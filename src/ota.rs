//! OTA firmware updates over MQTT chunked transfer.
//!
//! Protocol (all topics under `access/<device>/ota/`):
//! - `meta`  `{"size":N,"crc32":"XXXXXXXX"}` — begin; N must be 4-aligned
//!   (pad the image with 0xFF host-side). Selects the INACTIVE slot and
//!   erases the region for the incoming image.
//! - `data`  raw image bytes, streamed in order in <=512-byte chunks.
//! - `end`   `{}` — verify size + CRC32, flip the boot slot, reboot.
//!
//! Safety model: the RUNNING slot is never touched. The new image goes to
//! the inactive slot and the otadata entry with seq+1 marks it for boot;
//! the ESP-IDF bootloader verifies the image and falls back to the old slot
//! if it is invalid, so an aborted transfer degrades to "still running the
//! old build". `ota_state` is written as VALID (2) directly — this door
//! confirms itself, there is no esp_ota_ops agent to do it.
//!
//! otadata entry layout (32 bytes, decoded from live flash 2026-10-15):
//! `0..4` seq (LE u32, boots ota[(seq-1)%2]), `4..24` seq_label (0xFF),
//! `24..28` ota_state (2 = VALID), `28..32` CRC32 of the 4 seq bytes via
//! the ROM `crc32_le(0, bytes)` (LSB, poly 0x04c11db7, fin ~0) — verified
//! against live flash: seq=1 -> 0x4743989a.
use esp_println::println;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Instant, Timer};
use embedded_storage::nor_flash::NorFlash;
use embedded_storage::ReadStorage;
use esp_storage::FlashStorage;

use crate::ota_probation::{self, MarkerState};

/// Static buffer for 4KB otadata sector operations, avoiding stack allocation.
///
/// Safety / Concurrency: Access to flash operations and this buffer is serialized
/// by the caller holding `FLASH.lock().await` (or being inside single-threaded flash
/// operations). A `StaticCell` pattern or `AtomicBool` / mutex guards against concurrent use.
static OTADATA_SECTOR: Mutex<CriticalSectionRawMutex, [u8; 0x1000]> =
    Mutex::new([0xffu8; 0x1000]);

/// Partition geometry (partitions.csv, auto-placed offsets confirmed by
/// the second-stage boot log and a live otadata decode).
const OTADATA_OFF: u32 = 0xd000;
const OTA_SLOTS: [(u32, u32); 2] = [(0x1_0000, 0x1c_2000), (0x1e_0000, 0x1c_2000)];
const SECTOR: u32 = 0x1000;

/// Streaming transfer CRC32 — zlib-compatible so the host script's
/// `zlib.crc32` matches byte-for-byte.
fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut crc = !crc;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Parse the 8-hex-digit CRC from the meta payload.
fn hex8(s: &str) -> Option<u32> {
    if s.len() != 8 {
        return None;
    }
    u32::from_str_radix(s, 16).ok()
}

/// Metadata from the `ota/meta` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtaMeta {
    pub size: u32,
    pub crc32: u32,
}

/// Parse `{"size":N,"crc32":"XXXXXXXX"}` without heap allocation.
pub fn parse_meta(payload: &[u8]) -> Option<OtaMeta> {
    let s = core::str::from_utf8(payload).ok()?;
    let size_pos = s.find("\"size\"")?;
    let after_size = &s[size_pos + 6..];
    let colon_pos = after_size.find(':')?;
    let after_colon = &after_size[colon_pos + 1..];
    let size_end = after_colon.find([',', '}'])?;
    let size: u32 = after_colon[..size_end].trim().parse().ok()?;

    let crc_key_pos = s.find("\"crc32\"")?;
    let after_crc = &s[crc_key_pos + 7..];
    let colon_crc = after_crc.find(':')?;
    let after_colon_crc = after_crc[colon_crc + 1..].trim_start();
    let quote_start = after_colon_crc.find('"')?;
    let crc_hex = &after_colon_crc[quote_start + 1..];
    OtaMeta {
        size,
        crc32: hex8(crc_hex.get(..8)?)?,
    }
    .into()
}

/// Receive state; `None` = idle.
struct Rx {
    size: u32,
    crc_want: u32,
    crc_got: u32,
    written: u32,
    target_off: u32,
    erase_end: u32,
    erase_next: u32,
    erase_total_sectors: u32,
    last_progress_sectors: u32,
    erasing: bool,
    target_seq: u32,
    target_idx: usize,
    last_activity_ms: u64,
}

static RX: Mutex<CriticalSectionRawMutex, Option<Rx>> = Mutex::new(None);

/// Status messages for `access/<id>/ota/status` (drained by the MQTT task).
pub static STATUS_OUTBOUND: embassy_sync::channel::Channel<
    CriticalSectionRawMutex,
    heapless::String<128>,
    4,
> = embassy_sync::channel::Channel::new();

fn status(msg: &str) {
    println!("[ota] {}", msg);
    let mut s = heapless::String::<128>::new();
    use core::fmt::Write as _;
    let _ = write!(s, "{}", msg);
    let _ = STATUS_OUTBOUND.try_send(s);
}
static FLASH: Mutex<CriticalSectionRawMutex, Option<FlashStorage<'static>>> =
    Mutex::new(None);

/// Hand the flash peripheral to the OTA module (once, from `main`).
pub async fn init_flash(flash: FlashStorage<'static>) {
    *FLASH.lock().await = Some(flash);
}

/// Decode the otadata sector: highest valid (crc32_le-checked) entry across
/// both 4KB sectors (sector 0 at OTADATA_OFF, sector 1 at OTADATA_OFF + 0x1000).
/// Returns the boot seq of the RUNNING image (default 1 => ota_0).
fn current_seq(flash: &mut FlashStorage) -> u32 {
    let mut e0 = [0u8; 32];
    let mut e1 = [0u8; 32];
    let _ = flash.read(OTADATA_OFF, &mut e0);
    let _ = flash.read(OTADATA_OFF + 0x1000, &mut e1);
    use esp_hal::rom::crc::crc32_le;
    let mut best: Option<u32> = None;
    for e in [&e0, &e1] {
        let seq = u32::from_le_bytes(e[0..4].try_into().unwrap());
        let stored = u32::from_le_bytes(e[28..32].try_into().unwrap());
        if seq != u32::MAX && crc32_le(0, &e[0..4]) == stored {
            if best.map_or(true, |b| seq > b) {
                best = Some(seq);
            }
        }
    }
    best.unwrap_or(1)
}

/// `ota/meta`: validate, pick the inactive slot, erase it for the image.
pub async fn on_meta(payload: &[u8]) {
    let Some(meta) = parse_meta(payload) else {
        println!("[ota] meta: unparsable");
        crate::blog!("ota meta: unparsable");
        return;
    };
    if meta.size == 0 || meta.size % 4 != 0 || meta.size as usize > 0x1c2_000 {
        println!("[ota] meta: bad size {}", meta.size);
        crate::blog!("ota meta: bad size {}", meta.size);
        return;
    }
    let mut flash_guard = FLASH.lock().await;
    let Some(flash) = flash_guard.as_mut() else {
        println!("[ota] flash not initialized");
        crate::blog!("ota: flash not initialized");
        return;
    };
    let cur = current_seq(flash);
    let target_seq = cur + 1;
    let target_idx = ((target_seq - 1) % 2) as usize;
    let (target_off, target_len) = OTA_SLOTS[target_idx];
    let erase_end = target_off + meta.size.div_ceil(SECTOR) * SECTOR;
    let erase_total_sectors = (erase_end - target_off) / SECTOR;
    let _ = target_len;

    // Erase in small batches from the pump loop (erase_tick): a single
    // 175-sector blocking erase wedges the whole executor if the flash
    // chip hiccups — the watchdog then reboots and the OLD build keeps
    // guarding the door (otadata is only written after full verification).
    status("begin: erasing");

    *RX.lock().await = Some(Rx {
        size: meta.size,
        crc_want: meta.crc32,
        crc_got: 0,
        written: 0,
        target_off,
        erase_end,
        erase_next: target_off,
        erase_total_sectors,
        last_progress_sectors: 0,
        erasing: true,
        target_seq,
        target_idx,
        last_activity_ms: Instant::now().as_millis() as u64,
    });
}

/// `ota/data`: wire format `[u32 LE offset][bytes]`. The offset makes the
/// handler idempotent under QoS1 duplicate delivery: duplicates are
/// ignored, gaps abort the transfer.
pub async fn on_data(payload: &[u8]) {
    if payload.len() < 4 {
        return;
    }
    let off = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    let chunk = &payload[4..];
    let mut guard = FLASH.lock().await;
    let Some(flash) = guard.as_mut() else {
        return;
    };
    let mut state = RX.lock().await;
    let Some(rx) = state.as_mut() else {
        return;
    };
    if off != rx.written as usize {
        if off < rx.written as usize {
            return; // QoS1 duplicate — already written
        }
        crate::blog!("ota: gap at {} (expected {}) — aborting", off, rx.written);
        println!("[ota] gap at {} (expected {}) — aborting", off, rx.written);
        *state = None;
        return;
    }
    if rx.erasing {
        status("busy: still erasing (host should retry meta)");
        *state = None;
        return;
    }
    if rx.written + chunk.len() as u32 > rx.size {
        println!("[ota] overflow");
        crate::blog!("ota: overflow {} > {}", rx.written + chunk.len() as u32, rx.size);
        *state = None;
        return;
    }
    let pos = rx.target_off + rx.written;
    if flash.write(pos, chunk).is_err() {
        println!("[ota] write failed @{}", pos);
        crate::blog!("ota: write failed @{}", pos);
        *state = None;
        return;
    }
    rx.last_activity_ms = Instant::now().as_millis() as u64;
    rx.crc_got = crc32_update(rx.crc_got, chunk);
    rx.written += chunk.len() as u32;
    if rx.written % (128 * 1024) == 0 {
        println!("[ota] {}/{} bytes", rx.written, rx.size);
        crate::blog!("ota: {}/{} bytes", rx.written, rx.size);
    }
}

/// Erase up to `ERASE_BATCH` sectors per call; called every pump-loop pass
/// while a transfer is in the erasing phase. One sector per call = one
/// ~30-100 ms critical section, so the executor, Wi-Fi and the watchdog stay live.
const ERASE_BATCH: u32 = 1;

/// Returns true when no batched erase is pending.
pub async fn erase_tick() -> bool {
    let mut guard = FLASH.lock().await;
    let Some(flash) = guard.as_mut() else {
        return true;
    };
    let mut state = RX.lock().await;
    let Some(rx) = state.as_mut() else {
        return true;
    };
    if !rx.erasing {
        return true;
    }
    for _ in 0..ERASE_BATCH {
        if rx.erase_next >= rx.erase_end {
            rx.erasing = false;
            status("receiving: erase complete — send data");
            return true;
        }
        let r = flash.erase(rx.erase_next, rx.erase_next + SECTOR);
        if r.is_err() {
            status("erase failed — transfer aborted");
            println!("[ota] erase failed at {:#x}", rx.erase_next);
            *state = None;
            return true;
        }
        rx.erase_next += SECTOR;

        let sectors_done = (rx.erase_next - rx.target_off) / SECTOR;
        if sectors_done >= rx.last_progress_sectors + 32 || rx.erase_next >= rx.erase_end {
            rx.last_progress_sectors = sectors_done;
            let mut buf = heapless::String::<64>::new();
            use core::fmt::Write as _;
            let _ = write!(buf, "erase {}/{}", sectors_done, rx.erase_total_sectors);
            status(buf.as_str());
        }
    }
    false
}

/// `ota/end`: verify, write the otadata entries, reboot.
pub async fn on_end() {
    let mut guard = FLASH.lock().await;
    let Some(flash) = guard.as_mut() else {
        return;
    };
    let mut state = RX.lock().await;
    let Some(rx) = state.as_mut() else {
        println!("[ota] end: no transfer in progress");
        crate::blog!("ota end: no transfer in progress");
        return;
    };
    if rx.erasing {
        status("end: still erasing — ignored");
        return;
    }
    if rx.written != rx.size || rx.crc_got != rx.crc_want {
        println!(
            "[ota] verify FAILED ({} of {} bytes, crc {:08x} != {:08x})",
            rx.written, rx.size, rx.crc_got, rx.crc_want
        );
        crate::blog!(
            "ota: verify FAILED ({} of {} bytes, crc {:08x} != {:08x}) — keeping old build",
            rx.written,
            rx.size,
            rx.crc_got,
            rx.crc_want
        );
        *state = None;
        return;
    }

    use esp_hal::rom::crc::crc32_le;

    // The entry for the NEW slot: seq+1, VALID(2).
    // In ESP-IDF: otadata[0] lives in sector 0 (OTADATA_OFF = 0xd000),
    // and otadata[1] lives in sector 1 (OTADATA_OFF + 0x1000 = 0xe000).
    let new_idx = rx.target_idx;
    let new_seq = rx.target_seq;
    let new_entry = {
        let mut e = [0xffu8; 32];
        e[0..4].copy_from_slice(&new_seq.to_le_bytes());
        ota_probation::stamp_pending_marker(&mut e);
        e[24..28].copy_from_slice(&2u32.to_le_bytes()); // VALID
        let crc = crc32_le(0, &e[0..4]);
        e[28..32].copy_from_slice(&crc.to_le_bytes());
        e
    };

    let target_sector_off = OTADATA_OFF + (new_idx as u32 * 0x1000);
    let mut sector_guard = OTADATA_SECTOR.lock().await;
    sector_guard.fill(0xff);
    sector_guard[0..32].copy_from_slice(&new_entry);

    if flash.erase(target_sector_off, target_sector_off + 0x1000).is_err() {
        println!("[ota] otadata erase failed — old build keeps running");
        crate::blog!("ota: otadata erase failed — old build keeps running");
        return;
    }

    let mut write_failed = false;
    for i in 0..4 {
        let chunk_off = target_sector_off + (i as u32 * 1024);
        let chunk_data = &sector_guard[(i * 1024)..((i + 1) * 1024)];
        if flash.write(chunk_off, chunk_data).is_err() {
            write_failed = true;
            break;
        }
        if i < 3 {
            Timer::after(Duration::from_millis(10)).await;
        }
    }
    drop(sector_guard);

    if write_failed {
        println!("[ota] otadata write failed — old build keeps running");
        crate::blog!("ota: otadata write failed — old build keeps running");
        return;
    }

    println!(
        "[ota] verified {} bytes, slot{} seq{} ACTIVE — rebooting",
        rx.size, new_idx, new_seq
    );
    crate::blog!(
        "ota: verified {} bytes, slot{} seq{} ACTIVE — rebooting",
        rx.size,
        new_idx,
        new_seq
    );
    *state = None;
    drop(state);
    drop(guard);
    esp_hal::system::software_reset();
}

/// Boot information and marker status discovered from otadata sectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootInfo {
    pub state: MarkerState,
    pub max_seq: u32,
    pub booted_slot: usize,
}

/// Inspect both otadata entries to determine current booted slot and probation marker state.
pub async fn boot_check(flash: &mut FlashStorage<'static>) -> BootInfo {
    use esp_hal::rom::crc::crc32_le;
    let mut e0 = [0u8; 32];
    let mut e1 = [0u8; 32];
    let _ = flash.read(OTADATA_OFF, &mut e0);
    let _ = flash.read(OTADATA_OFF + 0x1000, &mut e1);

    let mut best_slot: Option<(usize, u32)> = None;
    for (slot_idx, e) in [(0usize, &e0), (1usize, &e1)] {
        let seq = u32::from_le_bytes(e[0..4].try_into().unwrap_or([0xFF; 4]));
        let stored = u32::from_le_bytes(e[28..32].try_into().unwrap_or([0xFF; 4]));
        if seq != u32::MAX && crc32_le(0, &e[0..4]) == stored {
            if best_slot.map_or(true, |(_, b_seq)| seq > b_seq) {
                best_slot = Some((slot_idx, seq));
            }
        }
    }

    match best_slot {
        Some((slot, seq)) => {
            let entry = if slot == 0 { &e0 } else { &e1 };
            let state = ota_probation::decode_marker(entry);
            BootInfo {
                state,
                max_seq: seq,
                booted_slot: slot,
            }
        }
        None => {
            // Fresh bench flash or all 0xFF
            BootInfo {
                state: MarkerState::Absent,
                max_seq: 1,
                booted_slot: 0,
            }
        }
    }
}

/// Record a boot attempt on the booted slot by advancing the bitmap word.
///
/// Modifies the 4-byte bitmap word at offset `OTADATA_OFF + slot * 0x1000 + 12`.
/// Returns Err(()) if attempt budget is exhausted (all slots already 0x00).
pub async fn record_attempt(flash: &mut FlashStorage<'static>) -> Result<(), ()> {
    let boot_info = boot_check(flash).await;
    let slot_off = OTADATA_OFF + (boot_info.booted_slot as u32 * 0x1000);
    let mut bitmap_word = [0u8; 4];
    if flash.read(slot_off + 12, &mut bitmap_word).is_err() {
        return Err(());
    }

    let Some(next) = ota_probation::next_bitmap(bitmap_word) else {
        return Err(());
    };

    // NOR flash allows changing bits 1 -> 0 without sector erase.
    flash.write(slot_off + 12, &next).map_err(|_| ())
}

/// Confirm the running firmware by setting status word to STATUS_CONFIRMED.
///
/// Idempotent: returns Ok(()) if already confirmed.
pub async fn confirm(flash: &mut FlashStorage<'static>) -> Result<(), ()> {
    let boot_info = boot_check(flash).await;
    let slot_off = OTADATA_OFF + (boot_info.booted_slot as u32 * 0x1000);
    let mut status_word = [0u8; 4];
    if flash.read(slot_off + 8, &mut status_word).is_err() {
        return Err(());
    }

    let next = ota_probation::confirm_transition(status_word);
    if next != status_word {
        flash.write(slot_off + 8, &next).map_err(|_| ())
    } else {
        Ok(())
    }
}

/// Write a rollback entry into the opposite (previous) slot's otadata sector.
///
/// Power loss during the old-sector erase destroys the last-known-good entry —
/// acceptable: the pending entry survives and the cycle retries (self-healing).
pub async fn write_rollback(
    flash: &mut FlashStorage<'static>,
    max_seq: u32,
    booted_slot: usize,
) -> Result<(), ()> {
    let other_slot = (booted_slot + 1) % 2;
    let target_sector_off = OTADATA_OFF + (other_slot as u32 * 0x1000);

    let rollback_entry = ota_probation::rollback_entry_32(max_seq);

    let mut sector_guard = OTADATA_SECTOR.lock().await;
    sector_guard.fill(0xff);
    sector_guard[0..32].copy_from_slice(&rollback_entry);

    if flash
        .erase(target_sector_off, target_sector_off + 0x1000)
        .is_err()
    {
        return Err(());
    }

    for i in 0..4 {
        let chunk_off = target_sector_off + (i as u32 * 1024);
        let chunk_data = &sector_guard[(i * 1024)..((i + 1) * 1024)];
        if flash.write(chunk_off, chunk_data).is_err() {
            return Err(());
        }
        if i < 3 {
            Timer::after(Duration::from_millis(10)).await;
        }
    }

    Ok(())
}

/// Check RX inactivity timeout.
///
/// If RX is active, not in erase phase, and inactivity exceeds RX_TIMEOUT_MS, aborts transfer.
/// Erase phase note: meta anchors the timer; a mid-erase disconnect at outer-loop 1 sector/s pace
/// exceeds 120s -> clean abort; host retries the whole push.
pub async fn rx_timeout_check(now_ms: u64) {
    let mut state = RX.lock().await;
    let Some(rx) = state.as_mut() else {
        return;
    };
    if !rx.erasing && now_ms.saturating_sub(rx.last_activity_ms) > ota_probation::RX_TIMEOUT_MS {
        status("idle: transfer timed out");
        println!("[ota] RX timeout ({} ms idle) — aborting", now_ms.saturating_sub(rx.last_activity_ms));
        crate::blog!("ota: RX timeout — aborting");
        *state = None;
    }
}
