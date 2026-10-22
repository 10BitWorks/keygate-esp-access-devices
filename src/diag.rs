//! Buffered diagnostic log.
//!
//! Important node events (session deaths, supervisor recoveries, WiFi state,
//! NFC health) are mirrored into a bounded ring. Every successful MQTT
//! connect drains the ring to `access/{device_id}/log` (QoS0), so the
//! broker-side observer sees logs from *before* and *during* disconnects —
//! no serial required. The queue is drop-oldest: a diagnostic must never
//! block or grow unbounded.
//!
//! While connected, the same lines ALSO stream live: `log_fmt` pushes the
//! formatted line into [`LOG_OUTBOUND`] and the MQTT pump publishes one
//! line per pump pass to the same topic (see node.rs). The live channel is
//! drop-on-full — the ring still holds every line for the next connect
//! flush, so a dropped live copy only costs immediacy, never the log.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;

/// Max characters per buffered line (silently truncated past that).
pub const LOG_LINE_MAX: usize = 160;
/// Ring capacity in lines. 64 × 160 B ≈ 10 KB static.
const QUEUE_CAP: usize = 64;
/// Live-stream channel capacity in lines (drained every MQTT pump pass,
/// which is bounded to ≥100 ms — bursts self-limit).
pub const LOG_OUTBOUND_CAPACITY: usize = 16;

/// Live diagnostic stream to the broker, drained by the MQTT pump loop.
///
/// Carries the exact `heapless::String<LOG_LINE_MAX>` that `log_fmt` built
/// for the ring (no re-formatting). `try_send` only: a full channel drops
/// the live copy silently; the ring keeps the line for the next connect.
pub static LOG_OUTBOUND: Channel<CriticalSectionRawMutex, heapless::String<LOG_LINE_MAX>, LOG_OUTBOUND_CAPACITY> =
    Channel::new();

#[cfg(any(target_arch = "riscv32", target_arch = "xtensa"))]
pub(crate) mod imp {
    use super::{LOG_LINE_MAX, LOG_OUTBOUND, QUEUE_CAP};
    use core::fmt::Write as _;
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::channel::{Channel, TrySendError};
    use embassy_time::Instant;

    pub static LOGQ: Channel<CriticalSectionRawMutex, heapless::String<LOG_LINE_MAX>, QUEUE_CAP> =
        Channel::new();

    pub fn log_fmt(args: core::fmt::Arguments<'_>) {
        let mut s = heapless::String::<LOG_LINE_MAX>::new();
        let _ = core::write!(s, "{} ", Instant::now().as_millis());
        let _ = core::write!(s, "{}", args);
        // Live stream first: try_send only, drop silently when full — the
        // ring below still holds the line for the next connect flush.
        let _ = LOG_OUTBOUND.try_send(s.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;
    use embassy_sync::channel::TrySendError;

    /// Mirrors piezo's `overflow_drops_ninth_event_on_full_channel`, against
    /// the REAL static: the live-stream channel must drop on full (never
    /// block the caller) and drain in FIFO order.
    #[test]
    fn log_outbound_drops_on_full_and_drains_fifo() {
        // Given the live channel with every slot filled...
        for slot in 0..LOG_OUTBOUND_CAPACITY {
            let mut s = heapless::String::<LOG_LINE_MAX>::new();
            let _ = write!(s, "line {slot}");
            LOG_OUTBOUND
                .try_send(s)
                .unwrap_or_else(|_| panic!("slot {slot} should accept"));
        }

        // ...the next try_send must drop with Full instead of blocking, and
        // must hand the value back so the caller could reclaim it.
        let mut extra = heapless::String::<LOG_LINE_MAX>::new();
        let _ = write!(extra, "overflow");
        let overflow = LOG_OUTBOUND.try_send(extra);
        assert!(
            matches!(&overflow, Err(TrySendError::Full(s)) if s.as_str() == "overflow"),
            "try_send past capacity must drop with Full, got {overflow:?}"
        );

        // Then draining yields exactly CAPACITY lines in FIFO order.
        for slot in 0..LOG_OUTBOUND_CAPACITY {
            let line = LOG_OUTBOUND.try_receive().expect("fifo drain");
            let mut expect = heapless::String::<LOG_LINE_MAX>::new();
            let _ = write!(expect, "line {slot}");
            assert_eq!(line.as_str(), expect.as_str());
        }
        assert!(
            LOG_OUTBOUND.try_receive().is_err(),
            "channel must be empty after the drain"
        );
    }
}
