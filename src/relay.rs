//! Asynchronous Door Relay Driver with Active-Low Default
//!
//! Provides `RELAY_CHANNEL` for receiving pulse requests (`pulse_ms: u32`)
//! and an async background task to pulse the door strike relay output pin.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Timer};
use esp_hal::gpio::{Level, Output};
use esp_println::println;

use crate::config;

/// Channel capacity for relay pulse requests.
pub const RELAY_CHANNEL_CAPACITY: usize = 4;

/// Asynchronous channel for requesting door relay pulses (duration in milliseconds).
///
/// Callers can enqueue pulse durations using `RELAY_CHANNEL.try_send(pulse_ms)`
/// or `RELAY_CHANNEL.send(pulse_ms).await` without blocking execution.
pub static RELAY_CHANNEL: Channel<CriticalSectionRawMutex, u32, RELAY_CHANNEL_CAPACITY> = Channel::new();

/// Background task to process relay pulses from `RELAY_CHANNEL`.
///
/// Receives the configured `esp_hal::gpio::Output` pin and actuates it
/// based on `config::RELAY_ACTIVE_LOW`.
///
/// Invariants:
/// - Polarity is determined once on startup.
/// - Relay starts and remains in the de-energized state while idle.
/// - `pulse_ms == 0` is ignored (door never unlocks on zero/bogus grant).
/// - Operates strictly one pulse at a time (awaits completion before receiving next).
#[embassy_executor::task]
pub async fn relay_task(mut pin: Output<'static>) -> ! {
    let active_low = parse_active_low(config::RELAY_ACTIVE_LOW);
    let (energized, deenergized) = if active_low {
        (Level::Low, Level::High)
    } else {
        (Level::High, Level::Low)
    };

    // Ensure idle/de-energized state at boot
    pin.set_level(deenergized);
    println!("Relay task initialized (active_low={})", active_low);

    loop {
        let pulse_ms = RELAY_CHANNEL.receive().await;

        // Guard: 0 ms pulse is ignored to prevent bogus unlock or glitches
        if pulse_ms == 0 {
            println!("Relay: ignoring 0ms pulse request");
            continue;
        }

        println!("Relay: energizing for {} ms", pulse_ms);
        pin.set_level(energized);
        Timer::after(Duration::from_millis(pulse_ms as u64)).await;
        pin.set_level(deenergized);
        println!("Relay: de-energized");
    }
}

/// Helper function to parse active-low polarity configuration.
/// Defaults to `true` (active-low) for any input other than explicitly "false" / "0".
fn parse_active_low(val: &str) -> bool {
    !matches!(val, "false" | "FALSE" | "0")
}
