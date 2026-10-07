//! Visual Status LED Driver for KeyGate ESP32-C6 Access Reader.
//!
//! # Hardware Adaptation Notice
//! The Seeed Studio XIAO ESP32-C6 onboard user indicator is a single mono amber LED
//! connected to GPIO15 with ACTIVE-LOW polarity (LOW = lit, HIGH = unlit).
//! Although the higher-level integration plan specifies "blink/color" states,
//! mono LED hardware cannot emit color (e.g. green for grant, red for denied).
//! Instead, states are distinguished strictly by temporal blink/pulse patterns:
//! - `WifiConnecting`: Slow blink (~800ms period, 400ms ON / 400ms OFF).
//! - `MqttConnected`: Solid lit (continuous ON).
//! - `TagReading`: Fast blink (~150ms period, 75ms ON / 75ms OFF).
//! - `Grant`: Single pulse (~300ms ON, 100ms OFF), then hold last steady state.
//! - `DeniedOrOffline`: Double blink (150ms ON / 150ms OFF x2), then hold last steady state.
//! - `Idle`: Off (continuous unlit).
//!
//! # Channel Semantics & Dropping Older Frames
//! `LED_CHANNEL` has a capacity of 1 to ensure low memory footprint.
//! In `embassy-sync 0.8.0`, calling `Channel::try_send` directly on a full channel
//! returns `Err(TrySendError::Full(val))`, which rejects/drops the *new* item.
//! To satisfy the requirement that a full channel drops the *older* frame gracefully
//! (so the latest visual status always takes precedence, e.g. a Grant pulse immediately
//! overrides a pending idle or blink state), this module provides [`set_state`].
//! [`set_state`] attempts `try_send`; if full, it drains the stale item via `try_receive()`
//! and enqueues the fresh state.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, TrySendError};
use embassy_time::{with_timeout, Duration};
use esp_hal::gpio::Output;

/// Visual states for the status LED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedState {
    /// Idle state (LED off).
    Idle,
    /// WiFi is attempting connection (slow blink, ~800ms period).
    WifiConnecting,
    /// MQTT connected and broker communication established (solid lit).
    MqttConnected,
    /// Active NFC tag polling / reading in progress (fast blink, ~150ms period).
    TagReading,
    /// Access granted (single ~300ms pulse, then reverts to prior steady state).
    Grant,
    /// Access denied or node is offline (double blink, then reverts to prior steady state).
    DeniedOrOffline,
}

impl Default for LedState {
    fn default() -> Self {
        Self::Idle
    }
}

/// Channel for dispatching visual status changes to the LED driver task.
///
/// Capacity is 1. Use [`set_state`] to ensure the freshest state replaces any
/// stale or unconsumed state.
pub static LED_CHANNEL: Channel<CriticalSectionRawMutex, LedState, 1> = Channel::new();

/// Send a status update to the LED driver task.
///
/// If `LED_CHANNEL` is full (holds an older unconsumed state), the older state is
/// drained via `try_receive` so the latest state takes precedence immediately.
pub fn set_state(state: LedState) {
    if let Err(TrySendError::Full(_)) = LED_CHANNEL.try_send(state) {
        let _ = LED_CHANNEL.try_receive();
        let _ = LED_CHANNEL.try_send(state);
    }
}

/// Spawns the async LED task. Accepts an already-constructed `esp_hal::gpio::Output` pin.
///
/// Full system wiring into `main` occurs in later integration tasks.
#[embassy_executor::task]
pub async fn status_led_task(mut pin: Output<'static>) -> ! {
    run_status_led(&mut pin).await
}

/// Core runner loop for the status LED.
///
/// Executes non-blocking blink/pulse patterns and listens for updates on `LED_CHANNEL`.
/// Polarity: Active-Low (pin.set_low() = lit, pin.set_high() = unlit).
pub async fn run_status_led(pin: &mut Output<'_>) -> ! {
    let mut current_state = LedState::Idle;
    let mut steady_state = LedState::Idle;

    loop {
        match current_state {
            LedState::Idle => {
                pin.set_high(); // Active-low OFF
                steady_state = LedState::Idle;
                // Wait indefinitely until the next command arrives
                current_state = LED_CHANNEL.receive().await;
            }
            LedState::MqttConnected => {
                pin.set_low(); // Active-low solid ON
                steady_state = LedState::MqttConnected;
                // Wait indefinitely until the next command arrives
                current_state = LED_CHANNEL.receive().await;
            }
            LedState::WifiConnecting => {
                // Slow blink: ~800ms period (400ms ON / 400ms OFF)
                pin.set_low();
                if let Ok(new_state) =
                    with_timeout(Duration::from_millis(400), LED_CHANNEL.receive()).await
                {
                    current_state = new_state;
                    continue;
                }
                pin.set_high();
                if let Ok(new_state) =
                    with_timeout(Duration::from_millis(400), LED_CHANNEL.receive()).await
                {
                    current_state = new_state;
                    continue;
                }
            }
            LedState::TagReading => {
                // Fast blink: ~150ms period (75ms ON / 75ms OFF)
                pin.set_low();
                if let Ok(new_state) =
                    with_timeout(Duration::from_millis(75), LED_CHANNEL.receive()).await
                {
                    current_state = new_state;
                    continue;
                }
                pin.set_high();
                if let Ok(new_state) =
                    with_timeout(Duration::from_millis(75), LED_CHANNEL.receive()).await
                {
                    current_state = new_state;
                    continue;
                }
            }
            LedState::Grant => {
                // Single ~300ms pulse (300ms ON, 100ms OFF), then hold prior steady state
                pin.set_low();
                if let Ok(new_state) =
                    with_timeout(Duration::from_millis(300), LED_CHANNEL.receive()).await
                {
                    current_state = new_state;
                    continue;
                }
                pin.set_high();
                if let Ok(new_state) =
                    with_timeout(Duration::from_millis(100), LED_CHANNEL.receive()).await
                {
                    current_state = new_state;
                    continue;
                }
                current_state = steady_state;
            }
            LedState::DeniedOrOffline => {
                // Double blink: ~150ms on/off x 2, then hold prior steady state
                // Pulse 1
                pin.set_low();
                if let Ok(new_state) =
                    with_timeout(Duration::from_millis(150), LED_CHANNEL.receive()).await
                {
                    current_state = new_state;
                    continue;
                }
                pin.set_high();
                if let Ok(new_state) =
                    with_timeout(Duration::from_millis(150), LED_CHANNEL.receive()).await
                {
                    current_state = new_state;
                    continue;
                }
                // Pulse 2
                pin.set_low();
                if let Ok(new_state) =
                    with_timeout(Duration::from_millis(150), LED_CHANNEL.receive()).await
                {
                    current_state = new_state;
                    continue;
                }
                pin.set_high();
                if let Ok(new_state) =
                    with_timeout(Duration::from_millis(150), LED_CHANNEL.receive()).await
                {
                    current_state = new_state;
                    continue;
                }
                current_state = steady_state;
            }
        }
    }
}
