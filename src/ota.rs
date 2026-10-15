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
use embedded_storage::nor_flash::NorFlash;
use embedded_storage::ReadStorage;
use esp_storage::FlashStorage;

/// Partition geometry (partitions.csv, auto-placed offsets confirmed by
/// the second-stage boot log and a live otadata decode).
const OTADATA_OFF: u32 = 0xd000;
const OTA_SLOTS: [(u32, u32); 2] = [(0x1000_0, 0x1c2_000), (0x1d2_000, 0x1c2_000)];
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
    let size_pos = s.find("\"size\":")?;
    let after = &s[size_pos + 7..];
    let size_end = after.find([',', '}'])?;
    let size: u32 = after[..size_end].trim().parse().ok()?;
    let crc_pos = s.find("\"crc32\":\"")?;
    let crc_hex = &s[crc_pos + 9..];
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
    erased_to: u32,
    target_seq: u32,
    target_idx: usize,
}

static RX: Mutex<CriticalSectionRawMutex, Option<Rx>> = Mutex::new(None);
static FLASH: Mutex<CriticalSectionRawMutex, Option<FlashStorage<'static>>> =
    Mutex::new(None);

/// Hand the flash peripheral to the OTA module (once, from `main`).
pub async fn init_flash(flash: FlashStorage<'static>) {
    *FLASH.lock().await = Some(flash);
}

/// Decode the otadata sector: highest valid (crc32_le-checked) entry.
/// Returns the boot seq of the RUNNING image (default 1 => ota_0).
fn current_seq(flash: &mut FlashStorage) -> u32 {
    let mut buf = [0u8; 64];
    if flash.read(OTADATA_OFF, &mut buf).is_err() {
        return 1;
    }
    use esp_hal::rom::crc::crc32_le;
    let mut best: Option<u32> = None;
    for i in 0..2 {
        let e = &buf[i * 32..(i + 1) * 32];
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
    let erase_to = target_off + meta.size.div_ceil(SECTOR) * SECTOR;
    let _ = erase_to.min(target_off + target_len);

    // Erase the region now (sector-stepped inside esp-storage, interrupts
    // disabled per sector by the driver's critical section).
    match flash.erase(target_off, erase_to) {
        Ok(()) => {}
        Err(e) => {
            println!("[ota] erase failed {:?}", e);
        crate::blog!("ota: erase failed {:?}", e);
            return;
        }
    }

    println!("[ota] begin {}B -> slot{} (seq {})", meta.size, target_idx, target_seq);
    crate::blog!(
        "ota: begin {}B -> slot{} (seq {}), erase ok",
        meta.size,
        target_idx,
        target_seq
    );
    *RX.lock().await = Some(Rx {
        size: meta.size,
        crc_want: meta.crc32,
        crc_got: 0,
        written: 0,
        target_off,
        erased_to: erase_to,
        target_seq,
        target_idx,
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
    rx.crc_got = crc32_update(rx.crc_got, chunk);
    rx.written += chunk.len() as u32;
    if rx.written % (128 * 1024) == 0 {
        println!("[ota] {}/{} bytes", rx.written, rx.size);
        crate::blog!("ota: {}/{} bytes", rx.written, rx.size);
    }
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

    // Re-read otadata, build both entries in RAM, erase, rewrite.
    let mut ot = [0u8; 64];
    if flash.read(OTADATA_OFF, &mut ot).is_err() {
        println!("[ota] otadata read failed");
        crate::blog!("ota: otadata read failed");
        return;
    }
    use esp_hal::rom::crc::crc32_le;

    // The entry for the NEW slot: seq+1, VALID(2).
    let new_idx = rx.target_idx;
    let new_seq = rx.target_seq;
    let new_entry = {
        let mut e = [0xffu8; 32];
        e[0..4].copy_from_slice(&new_seq.to_le_bytes());
        // e[4..24] stays 0xFF (seq_label)
        e[24..28].copy_from_slice(&2u32.to_le_bytes()); // VALID
        let crc = crc32_le(0, &e[0..4]);
        e[28..32].copy_from_slice(&crc.to_le_bytes());
        e
    };
    // The OTHER entry: preserve whatever is there (old build keeps its seq
    // so a fallback boot still works), minus nothing.
    let old_idx = 1 - new_idx;
    let mut old_entry = [0u8; 32];
    old_entry.copy_from_slice(&ot[old_idx * 32..(old_idx + 1) * 32]);

    let mut sector = [0xffu8; 0x1000];
    sector[new_idx * 32..(new_idx + 1) * 32].copy_from_slice(&new_entry);
    if old_entry != [0xffu8; 32] && old_entry[0..4] != [0xff; 4] {
        sector[old_idx * 32..(old_idx + 1) * 32].copy_from_slice(&old_entry);
    }

    if flash.erase(OTADATA_OFF, OTADATA_OFF + 0x1000).is_err()
        || flash.write(OTADATA_OFF, &sector).is_err()
    {
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
