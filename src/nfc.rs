//! PN532 NFC driver wrapper
//!
//! Thin wrapper around the `pn532` crate, providing tag detection
//! and identification for the XIAO-C6 NFC node.

use core::fmt;
use embassy_time::{Duration, Instant};
use pn532::{
    i2c::I2CInterface,
    requests::{BorrowedRequest, Command, SAMMode},
    CountDown, Pn532, Request,
};

/// Detected NFC tag information
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

/// Initialize the PN532 in normal SAM mode over I2C.
///
/// Returns an initialized Pn532 instance ready for tag polling.
pub fn init_pn532<I2C, E>(
    i2c: I2C,
) -> Result<Pn532<I2CInterface<I2C>, Pn532Delay, 300>, NfcError>
where
    I2C: embedded_hal::i2c::I2c<Error = E>,
    E: core::fmt::Debug,
{
    let interface = I2CInterface { i2c };
    let timer = Pn532Delay::new();
    let mut pn532 = Pn532::new(interface, timer);

    // Configure SAM (Security Access Module) to normal mode.
    // PN532 SAMConfiguration typical response latency is <2ms; 20ms timeout is generous
    // while bounding worst-case unready spin duration.
    pn532
        .process(
            &Request::sam_configuration(SAMMode::Normal, false),
            0,
            fugit::MillisDurationU32::from_ticks(20),
        )
        .map_err(|_| NfcError::Pn532)?;

    Ok(pn532)
}

/// Poll for a single NFC tag. Returns `Some(TagInfo)` if a tag is present.
pub fn poll_tag<I2C, T, const N: usize>(
    pn532: &mut Pn532<I2CInterface<I2C>, T, N>,
) -> Option<TagInfo>
where
    I2C: embedded_hal::i2c::I2c,
    T: CountDown<Time = fugit::MillisDurationU32>,
{
    // INLIST_ONE_ISO_A_TARGET: poll for 1 target at 106 kbps Type A.
    // When no tag is in the RF field, PN532 responds with NbTg=0 in ~12-18ms.
    // A 30ms timeout accommodates valid target discovery while tightening the worst-case
    // pending spin loop bound (down from 100ms) to minimize executor impact.
    if let Ok(res) = pn532.process(
        &Request::INLIST_ONE_ISO_A_TARGET,
        20,
        fugit::MillisDurationU32::from_ticks(30),
    ) {
        if res.is_empty() || res[0] == 0 {
            return None;
        }

        // res[0] = NbTg (number of targets found, should be 1)
        // res[1] = Tg (target number, typically 1)
        // res[2..4] = SENS_RES (2 bytes ATQA)
        // res[4] = SEL_RES (1 byte SAK)
        // res[5] = NFCIDLength (UID length)
        // res[6..6+NFCIDLength] = NFCID1 (UID)
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
pub fn in_data_exchange<'a, I2C, T, const N: usize>(
    pn532: &'a mut Pn532<I2CInterface<I2C>, T, N>,
    target: u8,
    apdu: &[u8],
) -> Result<&'a [u8], NfcError>
where
    I2C: embedded_hal::i2c::I2c,
    T: CountDown<Time = fugit::MillisDurationU32>,
{
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
    // ISO-DEP card operations on NTAG 424 can take 10-30ms; 50ms timeout is safe and bounded.
    let resp = pn532
        .process(req, 265, fugit::MillisDurationU32::from_ticks(50))
        .map_err(|e| match e {
            pn532::Error::TimeoutAck | pn532::Error::TimeoutResponse => NfcError::Timeout,
            _ => NfcError::Pn532,
        })?;

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



