//! PN532 NFC driver wrapper
//!
//! Thin wrapper around the `pn532` crate, providing tag detection
//! and identification for the XIAO-C6 NFC node.

use core::fmt;
use embassy_time::{Duration, Instant};
use pn532::{
    requests::{BorrowedRequest, Command, SAMMode},
    CountDown, Pn532, Request,
};

#[cfg(feature = "pn532-irq")]
use core::task::Poll;
#[cfg(feature = "pn532-irq")]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[cfg(feature = "pn532-irq")]
use embassy_sync::mutex::Mutex;
#[cfg(feature = "pn532-irq")]
use embassy_time::with_timeout;
#[cfg(feature = "pn532-irq")]
use esp_hal::gpio::Input;

/// Detected NFC tag information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagInfo {
    pub uid: [u8; 7],
    pub uid_len: u8,
    pub sak: u8,
}

impl TagInfo {
    /// Format UID as hex string for display
    pub fn uid_hex(&self) -> UidHex<'_> {
        UidHex(self)
    }

    /// Identify tag type from SAK byte
    pub fn tag_type(&self) -> &'static str {
        match self.sak {
            0x00 => "Mifare Ultralight",
            0x04 | 0x08 => "Mifare Classic 1K",
            0x18 => "Mifare Classic 4K",
            0x20 => "ISO 14443-4 (DESFire/NTAG424)",
            _ => "Unknown",
        }
    }
}

/// Display helper for UID hex formatting
pub struct UidHex<'a>(&'a TagInfo);

impl fmt::Display for UidHex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in 0..self.0.uid_len as usize {
            if i > 0 {
                write!(f, ":")?;
            }
            write!(f, "{:02X}", self.0.uid[i])?;
        }
        Ok(())
    }
}

/// Error type for NFC operations
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfcError {
    /// PN532 communication or protocol error
    Pn532,
    /// Timeout waiting for response
    Timeout,
    /// APDU payload too large for internal buffer
    ApduTooLarge,
    /// InDataExchange response was empty
    EmptyResponse,
    /// Target returned an RF error status byte
    RfError(u8),
}

// ---------------------------------------------------------------------------
// IRQ-driven readiness (feature `pn532-irq`, door board only)
// ---------------------------------------------------------------------------
// Architecture C: bypass the pn532 crate's internal `while
// wait_ready().is_pending()` busy loops by driving its public fine-grained
// API (`send` / `receive_ack` / `receive_response`, protocol.rs:229/281/313)
// ourselves. Each ready-wait is an embassy-bounded `Input::wait_for_low()` on
// GPIO4 (PN532 P70_IRQ idles HIGH, asserts LOW for BOTH the ACK and the
// response frame — UM0701-02 §6.2.5.2 Fig. 35), followed by ONE SPI STATREAD
// confirm through `pn532.interface.wait_ready()`.
//
// The confirm is mandatory, not a fallback: the PN532 releases IRQ on SPI
// DW/DR detection (§6.3.4.3/§6.3.4.4), so a stale LOW after our own reads is
// the EXPECTED spurious source (the phantom-low failure mode of the reverted
// 5f42f35 attempt, and the crate's own send/ack race, WMT-GmbH/pn532#4). A
// phantom LOW costs one paced STATREAD (~1 ms via the soft-SPI
// inter-transaction delay) and a re-wait bounded by the deadline — the loop
// below cannot spin line-rate.
//
// No custom `Interface` is implemented (a blocking `wait_ready` inside the
// crate's sync loop would park the embassy executor — dossier §2), and
// `process_async` is not used (its `WaitReadyFuture` self-wakes on Pending,
// a spin — WMT-GmbH/pn532#11). Never an unbounded or edge-only wait.

/// IRQ input installed by `board::setup` (door, feature-on) before
/// `init_pn532`. `None` until then; `irq_ready` fails closed on it.
#[cfg(feature = "pn532-irq")]
pub(crate) static IRQ_PIN: Mutex<CriticalSectionRawMutex, Option<Input<'static>>> =
    Mutex::new(None);

/// ACK wait budget. The PN532 ACKs a command frame immediately on this rig
/// (~1 status poll — PN532-SPI-NOTES "Timing measurements"); 30 ms is a 30x
/// margin that still fails fast on a dead reader instead of burning the full
/// command budget the way the blocking crate loop does.
#[cfg(feature = "pn532-irq")]
const IRQ_ACK_BUDGET: Duration = Duration::from_millis(30);

/// One IRQ ready-wait with STATREAD confirmation, deadline-bounded.
///
/// `Input::wait_for_low` is level-triggered (`Event::LowLevel`): an
/// already-low pin completes immediately (this is why edge variants are
/// forbidden — they would miss it), single-shot, and re-armed on every call.
/// esp-hal binds the default GPIO interrupt handler in `esp_hal::init()`, so
/// no manual handler registration is needed (and none may be added — a
/// direct-bound GPIO handler breaks the async GPIO API entirely).
#[cfg(feature = "pn532-irq")]
async fn irq_ready<I: pn532::Interface>(iface: &mut I, deadline: Instant) -> Result<(), NfcError> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(NfcError::Timeout);
        }
        let remaining = deadline - now;
        let pin_low = async {
            let mut pin = IRQ_PIN.lock().await;
            match pin.as_mut() {
                Some(irq) => {
                    irq.wait_for_low().await;
                    Ok(())
                }
                // Config bug: board::setup never installed GPIO4. Fail
                // closed rather than busy-poll.
                None => Err(NfcError::Pn532),
            }
        };
        match with_timeout(remaining, pin_low).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(NfcError::Timeout),
        }
        // IRQ asserted LOW — confirm with one STATREAD. Pending means a
        // stale/spurious low: loop (each iteration paces itself through the
        // soft-SPI inter-transaction delay inside the STATREAD).
        match iface.wait_ready() {
            Poll::Ready(Ok(())) => return Ok(()),
            Poll::Ready(Err(_)) => return Err(NfcError::Pn532),
            Poll::Pending => continue,
        }
    }
}

/// IRQ-driven mirror of the crate's `_process` (protocol.rs:152-173): send →
/// wait ready → `receive_ack` → wait ready → `receive_response`. On a
/// ready-wait failure the PN532 is aborted first (a host ACK frame forces it
/// to resync), matching the crate's error-path recovery contract.
#[cfg(feature = "pn532-irq")]
async fn irq_process<I: pn532::Interface, T, const N: usize>(
    pn: &mut Pn532<I, T, N>,
    request: impl Into<BorrowedRequest<'_>>,
    response_len: usize,
    ack_deadline: Instant,
    resp_deadline: Instant,
) -> Result<&[u8], NfcError> {
    let request = request.into();
    let sent_command = request.command;
    pn.send(request).map_err(|_| NfcError::Pn532)?;
    if let Err(e) = irq_ready(&mut pn.interface, ack_deadline).await {
        let _ = pn.abort();
        return Err(e);
    }
    pn.receive_ack().map_err(|_| NfcError::Pn532)?;
    if let Err(e) = irq_ready(&mut pn.interface, resp_deadline).await {
        let _ = pn.abort();
        return Err(e);
    }
    pn.receive_response(sent_command, response_len)
        .map_err(|_| NfcError::Pn532)
}

/// Non-blocking countdown timer wrapper implementing `pn532::CountDown` via `embassy_time::Instant`.
///
/// In `pn532 0.5`, wait loops in `_process` and `_process_no_response` iterate synchronously:
/// ```text
/// while self.interface.wait_ready()?.is_pending() {
///     if self.timer.wait().is_ok() {
///         return Err(Error::Timeout...);
///     }
/// }
/// ```
/// Because `CountDown::wait()` is a synchronous trait method (`fn wait(&mut self) -> nb::Result<(), Infallible>`),
/// it cannot `.await` on an Embassy timer internally. Each iteration performs an I2C read status check
/// (~100µs at 100kHz) and an `Instant::now()` deadline comparison without artificial blocking sleep.
/// If `wait_ready()` remains pending when no tag or ACK is present, the CPU executes this check loop
/// until the configured timeout expires (20ms for `init_pn532`, 30ms for `poll_tag`).
pub struct Pn532Delay {
    deadline: Option<Instant>,
}

impl Pn532Delay {
    pub const fn new() -> Self {
        Self { deadline: None }
    }
}

impl Default for Pn532Delay {
    fn default() -> Self {
        Self::new()
    }
}

impl CountDown for Pn532Delay {
    type Time = fugit::MillisDurationU32;

    fn start<T>(&mut self, count: T)
    where
        T: Into<Self::Time>,
    {
        let ms = count.into().ticks() as u64;
        self.deadline = Some(Instant::now() + Duration::from_millis(ms));
    }

    fn wait(&mut self) -> Result<(), nb::Error<core::convert::Infallible>> {
        if let Some(deadline) = self.deadline {
            if Instant::now() >= deadline {
                self.deadline = None;
                Ok(())
            } else {
                Err(nb::Error::WouldBlock)
            }
        } else {
            Ok(())
        }
    }
}

/// Initialize the PN532 in normal SAM mode over any supported interface.
///
/// Returns an initialized Pn532 instance ready for tag polling.
// Interface-agnostic: pass I2CInterface or SPIInterface; SPI builds rely on the crate's `msb-spi` feature (PN532 is LSB-first).
pub async fn init_pn532<I: pn532::Interface>(
    interface: I,
) -> Result<Pn532<I, Pn532Delay, 300>, NfcError> {
    let timer = Pn532Delay::new();
    let mut pn532 = Pn532::new(interface, timer);

    // SAMConfig on this module clone is per-boot flaky: identical firmware
    // boots have both passed and failed the first attempt (see AGENTS.md
    // "Expected timing" / PN532-SPI-NOTES.md). The reader must self-heal at
    // boot, not idle NFC-less until a manual reflash — retry with a resync
    // (ACK abort) and settle gap between attempts. All attempts share one
    // interface instance; nothing is lost on failure.
    let mut attempt = 0;
    loop {
        attempt += 1;
        // Progressive windows: the fast path still resolves in 500 ms; a
        // slow-processing module mood gets up to 3 s on the later attempts.
        let sam_timeout_ms = match attempt {
            1 => 500,
            2 => 1500,
            _ => 3000,
        };
        match soft_reinit(&mut pn532, sam_timeout_ms).await {
            Ok(()) => break,
            Err(e) if attempt < 3 => {
                #[cfg(target_arch = "xtensa")]
                esp_println::println!(
                    "[nfc] init attempt {} failed ({:?}) — resync + retry",
                    attempt,
                    e
                );
                let _ = pn532.abort(); // datasheet: ACK frame forces the PN532 to resync
                busy_wait_ms(200);
            }
            Err(e) => return Err(e),
        }
    }

    Ok(pn532)
}

/// Boot-only bounded settle delay (sync context, pre-executor).
fn busy_wait_ms(ms: u32) {
    let t0 = embassy_time::Instant::now();
    while (embassy_time::Instant::now() - t0).as_millis() < ms as u64 {
        core::hint::spin_loop();
    }
}

/// Re-initialize the PN532 SAM mode on an existing driver instance.
///
/// `sam_timeout_ms` bounds the SAMConfig wait. This module clone processes
/// commands 5-30x slower than Adafruit-class modules (see
/// PN532-SPI-NOTES.md "Timing measurements"): telemetry shows the status
/// byte driven-but-not-ready (0x00) for the entire window when the 500 ms
/// default is too short — the command is in flight, we just give up early.
///
/// Typically called after hardware RSTO pulse or when soft recovery is triggered.
pub async fn soft_reinit<I: pn532::Interface>(
    pn: &mut Pn532<I, Pn532Delay, 300>,
    sam_timeout_ms: u32,
) -> Result<(), NfcError> {
    // Configure SAM (Security Access Module) to normal mode.
    // PN532 SAMConfiguration typical response latency is <2ms; 20ms timeout is generous
    // while bounding worst-case unready spin duration.
    // `use_irq_pin = true` matches Adafruit's SAMConfig byte (0x01). Readiness is still
    // STATUS-polled over SPI; the byte only configures P70_IRQ signaling, but some
    // module firmwares treat 0x00 as a reduced mode.
    #[cfg(not(feature = "pn532-irq"))]
    pn.process(
        &Request::sam_configuration(SAMMode::Normal, true),
        0,
        fugit::MillisDurationU32::from_ticks(500),
    )
    .map_err(|_e| {
        // Symptom-based diagnostics from the 2026-10-10/11 bench session
        // (see docs/PN532-SPI-NOTES.md, "Symptom → diagnosis table").
        #[cfg(target_arch = "xtensa")]
        {
            let hint = match &_e {
                pn532::Error::TimeoutAck => "PN532 not ACKing. Check: DIP switches = 1:OFF 2:ON (SPI on this module family); power-cycle the MODULE after any DIP change (interface mode latches at power-on only, EN button does NOT relatch); SCK/MOSI/CS wiring; VCC.",
                pn532::Error::TimeoutResponse => "PN532 ACKed but never answered. Module-side stall — power-cycle the module; check supply stability.",
                pn532::Error::BadAck => "PN532 returned garbage for the ACK frame — mid-recovery/brownout signature. Power-cycle the module; check VCC current.",
                _ => "SPI interface error — check wiring.",
            };
            esp_println::println!("[nfc] SAMConfig failed ({:?}): {}", _e, hint);
        }
        NfcError::Pn532
    })?;
    #[cfg(feature = "pn532-irq")]
    {
        // Same command and effective 500 ms window as the blocking path
        // above (`sam_timeout_ms` is advisory there too — both paths run
        // the proven 500 ms SAMConfig budget).
        let t0 = Instant::now();
        let res = irq_process(
            pn,
            &Request::sam_configuration(SAMMode::Normal, true),
            0,
            t0 + IRQ_ACK_BUDGET,
            t0 + Duration::from_millis(500),
        )
        .await;
        if let Err(e) = res {
            #[cfg(target_arch = "xtensa")]
            esp_println::println!(
                "[nfc] SAMConfig (irq) failed ({:?}) — see docs/PN532-SPI-NOTES.md symptom table",
                e
            );
            return Err(NfcError::Pn532);
        }
    }

    // CfgItem 5: MaxRetries (MxRtyATR = 0xFF, MxRtyPSL = 0x01, MxRtyPassiveActivation = 0x0A)
    // Matches Adafruit setPassiveActivationRetries(0x0A): allows InListPassiveTarget
    // to cleanly return NbTg=0 when no tag is present in ~50ms instead of spinning indefinitely.
    let max_retries = Request::new(Command::RFConfiguration, [0x05, 0xFF, 0x01, 0x0A]);
    #[cfg(not(feature = "pn532-irq"))]
    let _ = pn.process(&max_retries, 0, fugit::MillisDurationU32::from_ticks(100));
    #[cfg(feature = "pn532-irq")]
    {
        let t0 = Instant::now();
        let _ = irq_process(
            pn,
            &max_retries,
            0,
            t0 + IRQ_ACK_BUDGET,
            t0 + Duration::from_millis(100),
        )
        .await;
    }

    Ok(())
}

/// Poll for a single NFC tag.
///
/// Returns:
/// - `Ok(Some(TagInfo))` if a tag is present in the RF field.
/// - `Ok(None)` if no tag is present (NbTg == 0).
/// - `Err(NfcError)` if communication or protocol failure occurs.
/// Periodic liveness probe: a real GetFirmwareVersion round-trip.
///
/// Detects the "fake-ready" wedge where STATUS polls report ready instantly
/// and every InListPassiveTarget returns a clean NbTg=0 while the RF core is
/// actually dead — a state the error-counting supervisor cannot see, because
/// nothing ever errors. A wedged reader fails this probe and lands in the
/// caller's recovery path (RSTO pulse + re-init).
pub async fn health_check<I: pn532::Interface, T: CountDown<Time = fugit::MillisDurationU32>, const N: usize>(
    pn: &mut Pn532<I, T, N>,
) -> Result<[u8; 4], NfcError> {
    #[cfg(not(feature = "pn532-irq"))]
    let res = pn
        .process(
            &Request::GET_FIRMWARE_VERSION,
            4,
        fugit::MillisDurationU32::from_ticks(500),
        )
        .map_err(|e| match e {
            pn532::Error::TimeoutAck | pn532::Error::TimeoutResponse => NfcError::Timeout,
            _ => NfcError::Pn532,
        })?;
    #[cfg(feature = "pn532-irq")]
    let res = {
        let t0 = Instant::now();
        irq_process(
            pn,
            &Request::GET_FIRMWARE_VERSION,
            4,
            t0 + IRQ_ACK_BUDGET,
            t0 + Duration::from_millis(500),
        )
        .await?
    };
    if res.len() < 4 || res[0] != 0x32 {
        return Err(NfcError::Pn532);
    }
    Ok([res[0], res[1], res[2], res[3]])
}

pub async fn poll_tag<I: pn532::Interface, T: CountDown<Time = fugit::MillisDurationU32>, const N: usize>(
    pn532: &mut Pn532<I, T, N>,
) -> Option<TagInfo> {
    // INLIST_ONE_ISO_A_TARGET: poll for 1 target at 106 kbps Type A.
    // 250ms matches the proven, smooth timing from the Waveshare C6 RFID reader.
    #[cfg(not(feature = "pn532-irq"))]
    let res = pn532.process(
        &Request::INLIST_ONE_ISO_A_TARGET,
        20,
        fugit::MillisDurationU32::from_ticks(600),
    );
    // IRQ path: identical total budget (both deadlines are absolute from the
    // same start instant, so the wall-clock bound stays 600 ms — poll cadence
    // and debounce/melody timing are unchanged), ACK fails fast at 30 ms.
    #[cfg(feature = "pn532-irq")]
    let res = {
        let t0 = Instant::now();
        irq_process(
            pn532,
            &Request::INLIST_ONE_ISO_A_TARGET,
            20,
            t0 + IRQ_ACK_BUDGET,
            t0 + Duration::from_millis(600),
        )
        .await
    };
    if let Ok(res) = res {
        if res.is_empty() || res[0] == 0 {
            return None;
        }

        let sak = res[4];
        let uid_len = res[5] as usize;

        if res.len() >= 6 + uid_len {
            let mut uid = [0u8; 7];
            let copy_len = uid_len.min(7);
            uid[..copy_len].copy_from_slice(&res[6..6 + copy_len]);
            return Some(TagInfo {
                uid,
                uid_len: copy_len as u8,
                sak,
            });
        }
    }
    None
}

/// Send an ISO-DEP (ISO 14443-4) APDU to a target via PN532 `InDataExchange`.
///
/// Prepares `[target, ...apdu]` payload and dispatches `Command::InDataExchange`.
/// Unwraps the PN532 response, checks the 1-byte status header (`0x00` indicates success),
/// strips the status byte, and returns the response slice containing card response bytes
/// including trailing SW1 and SW2 status words.
///
/// Returns `NfcError::EmptyResponse` if the response frame contains no data, or
/// `NfcError::RfError(status)` if the target status byte indicates an error.
pub async fn in_data_exchange<'a, I: pn532::Interface, T: CountDown<Time = fugit::MillisDurationU32>, const N: usize>(
    pn532: &'a mut Pn532<I, T, N>,
    target: u8,
    apdu: &[u8],
) -> Result<&'a [u8], NfcError> {
    // Maximum APDU payload supported by stack buffer in `no_std` without heap allocation.
    // 265 bytes accommodates standard ISO-DEP frame caps.
    let mut tx_buf = [0u8; 265];
    if 1 + apdu.len() > tx_buf.len() {
        return Err(NfcError::ApduTooLarge);
    }
    tx_buf[0] = target;
    tx_buf[1..1 + apdu.len()].copy_from_slice(apdu);

    let req = BorrowedRequest::new(Command::InDataExchange, &tx_buf[..1 + apdu.len()]);

    // PN532 buffer constraint: N - 9 >= max(response_len, M).
    // With N=300, max response_len can safely be up to 265 bytes (265 + 9 = 274 <= 300).
    // ISO-DEP card operations on NTAG 424 measured 1-2 status polls once the target
    // is activated, but this module's RF latencies run high — 500ms bounds worst case.
    #[cfg(not(feature = "pn532-irq"))]
    let resp = pn532
        .process(req, 265, fugit::MillisDurationU32::from_ticks(500))
        .map_err(|e| match e {
            pn532::Error::TimeoutAck | pn532::Error::TimeoutResponse => NfcError::Timeout,
            _ => NfcError::Pn532,
        })?;
    // IRQ path: 100 ms DataExchange response budget (NTAG 424 answers in
    // <15 ms; bench matrix E3 must watch for Transport errors on the moody
    // module — the fallback is the 500 ms bound of the blocking path).
    #[cfg(feature = "pn532-irq")]
    let resp = {
        let t0 = Instant::now();
        irq_process(
            pn532,
            req,
            265,
            t0 + IRQ_ACK_BUDGET,
            t0 + Duration::from_millis(100),
        )
        .await?
    };

    if resp.is_empty() {
        return Err(NfcError::EmptyResponse);
    }

    let status = resp[0];
    if status != 0x00 {
        return Err(NfcError::RfError(status));
    }

    // Strip the 1-byte PN532 status header, returning card response including SW1 SW2
    Ok(&resp[1..])
}

/// Check if an already-activated ISO-DEP target is still physically present
/// in the RF field by sending a standard Select NDEF Application APDU.
///
/// On any NTAG 424 DNA tag (blank from factory or provisioned), the tag answers
/// 90 00 in <15ms. If the tag was physically removed, the PN532 returns an RF error.
pub async fn is_target_present<I: pn532::Interface, T: CountDown<Time = fugit::MillisDurationU32>, const N: usize>(
    pn532: &mut Pn532<I, T, N>,
    target: u8,
) -> bool {
    const SELECT_APP: [u8; 13] = [
        0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
    ];
    let mut tx_buf = [0u8; 14];
    tx_buf[0] = target;
    tx_buf[1..14].copy_from_slice(&SELECT_APP);
    let req = BorrowedRequest::new(Command::InDataExchange, &tx_buf);
    #[cfg(not(feature = "pn532-irq"))]
    let res = pn532.process(req, 20, fugit::MillisDurationU32::from_ticks(150));
    #[cfg(feature = "pn532-irq")]
    let res = {
        let t0 = Instant::now();
        irq_process(
            pn532,
            req,
            20,
            t0 + IRQ_ACK_BUDGET,
            t0 + Duration::from_millis(150),
        )
        .await
    };
    match res {
        Ok(resp) => !resp.is_empty() && resp[0] == 0x00,
        Err(_) => false,
    }
}

/// Release a selected target in the PN532 (InRelease).
pub async fn release_target<I: pn532::Interface, T: CountDown<Time = fugit::MillisDurationU32>, const N: usize>(
    pn532: &mut Pn532<I, T, N>,
    target: u8,
) {
    let req = match target {
        1 => &Request::RELEASE_TAG_1,
        2 => &Request::RELEASE_TAG_2,
        _ => &Request::new(Command::InRelease, [0x00]),
    };
    #[cfg(not(feature = "pn532-irq"))]
    let _ = pn532.process(req, 1, fugit::MillisDurationU32::from_ticks(100));
    #[cfg(feature = "pn532-irq")]
    {
        let t0 = Instant::now();
        let _ = irq_process(
            pn532,
            req,
            1,
            t0 + IRQ_ACK_BUDGET,
            t0 + Duration::from_millis(100),
        )
        .await;
    }
}




