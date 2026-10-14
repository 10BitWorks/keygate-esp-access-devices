//! Buffered diagnostic log.
//!
//! Important node events (session deaths, supervisor recoveries, WiFi state,
//! NFC health) are mirrored into a bounded ring. Every successful MQTT
//! connect drains the ring to `access/{device_id}/log` (QoS0), so the
//! broker-side observer sees logs from *before* and *during* disconnects —
//! no serial required. The queue is drop-oldest: a diagnostic must never
//! block or grow unbounded.

/// Max characters per buffered line (silently truncated past this).
pub const LOG_LINE_MAX: usize = 160;
/// Ring capacity in lines. 64 × 160 B ≈ 10 KB static.
const QUEUE_CAP: usize = 64;

#[cfg(any(target_arch = "riscv32", target_arch = "xtensa"))]
pub(crate) mod imp {
    use super::{LOG_LINE_MAX, QUEUE_CAP};
    use core::fmt::Write as _;
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::channel::{Channel, TrySendError};

    pub static LOGQ: Channel<CriticalSectionRawMutex, heapless::String<LOG_LINE_MAX>, QUEUE_CAP> =
        Channel::new();

    pub fn log_fmt(args: core::fmt::Arguments<'_>) {
        let mut s = heapless::String::<LOG_LINE_MAX>::new();
        let _ = core::write!(s, "{} ", embassy_time::Instant::now().as_millis());
        let _ = core::write!(s, "{}", args);
        esp_println::println!("{}", s.as_str());
        match LOGQ.try_send(s) {
            Ok(()) => {}
            // Ring full: drop the OLDEST line to keep the newest.
            Err(TrySendError::Full(_)) => {
                let _ = LOGQ.try_receive();
                let _ = LOGQ.try_send(heapless::String::<LOG_LINE_MAX>::new());
            }
            Err(_) => {}
        }
    }

    /// Take the oldest buffered line, if any.
    pub fn pop() -> Option<heapless::String<LOG_LINE_MAX>> {
        LOGQ.try_receive().ok()
    }
}

#[cfg(not(any(target_arch = "riscv32", target_arch = "xtensa")))]
pub(crate) mod imp {
    pub fn log_fmt(_args: core::fmt::Arguments<'_>) {}
    pub fn pop() -> Option<heapless::String<{ super::LOG_LINE_MAX }>> {
        None
    }
}

/// Buffer a diagnostic line (also printed to UART).
#[macro_export]
macro_rules! blog {
    ($($arg:tt)*) => {
        $crate::diag::imp::log_fmt(format_args!($($arg)*))
    };
}
