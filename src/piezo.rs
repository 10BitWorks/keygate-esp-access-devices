//! Passive piezo feedback driver (bridge-driven, GPIO bit-bang).
//!
//! A 2-terminal passive piezo disc is driven differentially ("bridge" mode): leg A
//! high while leg B low, then swap, on every half-period. This doubles the voltage
//! swing across the disc versus a single-pin + GND drive and is polarity-free, so
//! either leg may land on either GPIO. An unwired disc simply stays silent — no
//! code path changes for that case.
//!
//! # Layout
//! The pattern table and the event→pattern lookup are deliberately free of HAL and
//! concurrency dependencies so they can be verified in host unit tests. The pins,
//! the event channel, and the async play loop are compiled only for the embedded
//! targets (`riscv32`/`xtensa`), where `esp-hal` and `embassy-sync` are available.

/// Fixed capacity of the feedback event channel.
///
/// Feedback is advisory: a full channel drops the newest event at the `try_send`
/// hook site rather than ever blocking the NFC/MQTT loop.
pub const PIEZO_CHANNEL_CAPACITY: usize = 8;

/// Discrete feedback events the rest of the firmware can request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeepEvent {
    /// A tag was sighted.
    TagDetected,
    /// An auth request was published to the broker.
    AuthSent,
    /// Access granted.
    Granted,
    /// Access denied.
    Denied,
    /// The strike relay was pulsed.
    RelayPulse,
    /// Provisioning mode is armed and waiting for a blank tag.
    ProvisionArmed,
    /// Provisioning of a tag succeeded.
    ProvisionOk,
    /// Provisioning of a tag failed.
    ProvisionFail,
    /// Node finished booting.
    Boot,
}

/// A single tone: `(frequency_hz, on_ms)`.
pub type Tone = (u32, u32);

/// Silence inserted between consecutive tones of a multi-tone pattern, so two
/// same-frequency beeps are heard as two and not one continuous tone.
pub const TONE_GAP_MS: u32 = 50;

/// Lowest accepted tone frequency (Hz).
pub const FREQ_MIN_HZ: u32 = 200;
/// Highest accepted tone frequency (Hz).
pub const FREQ_MAX_HZ: u32 = 5000;
/// Shortest accepted tone duration (ms).
pub const ON_MS_MIN: u32 = 10;
/// Longest accepted tone duration (ms).
pub const ON_MS_MAX: u32 = 1000;

/// Feedback pattern per event, per draft decision D5.

/// Connection progress states for the audible status beeps. Written by the
/// node via [`set_conn_state`] as the network stack comes up (or drops).
pub mod conn {
    /// Booting; nothing audible yet.
    pub const BOOT: u8 = 0;
    /// Joining Wi-Fi: one short beep per tick.
    pub const WAIT_WIFI: u8 = 1;
    /// Joining MQTT: double short beep per tick.
    pub const WAIT_MQTT: u8 = 2;
    /// Fully online: rising confirmation once, then silent.
    pub const ONLINE: u8 = 3;
    /// Lost the connection after having been online: one low beep every
    /// 15 s so an offline reader is noticed from across the room.
    pub const RECONNECT: u8 = 4;
    /// Provisioning window open: continuous low beacon until tag tapped or timeout.
    pub const PROV_ARMED: u8 = 5;
    /// Tag held & provisioning in progress: continuous higher tone.
    pub const PROV_WRITING: u8 = 6;
}

/// Current connection state (see [`conn`]).
pub static CONN_STATE: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(conn::BOOT);

/// Publish a new connection state for the audible progress beeps.
pub fn set_conn_state(state: u8) {
    CONN_STATE.store(state, core::sync::atomic::Ordering::Relaxed);
}

/// How often (in ticks) the reconnect beep plays while [`conn::RECONNECT`].
const RECONNECT_TICKS: u32 = 15;
///
/// Each entry maps an event to an ordered list of tones `(freq_hz, on_ms)`. The
/// first entry of each pattern is the leading beep; multi-tone patterns are
/// separated at play time by [`TONE_GAP_MS`].
pub const PATTERN_TABLE: &[(BeepEvent, &[Tone])] = &[
    (BeepEvent::TagDetected, &[(2600, 60)]),
    (BeepEvent::AuthSent, &[(2600, 40)]),
    (BeepEvent::Granted, &[(3200, 120), (3200, 120)]),
    (BeepEvent::Denied, &[(1300, 150), (1300, 150)]),
    (BeepEvent::RelayPulse, &[(2600, 400)]),
    (
        BeepEvent::ProvisionArmed,
        &[(2400, 60), (2700, 60), (3000, 60)],
    ),
    (
        BeepEvent::ProvisionOk,
        &[(2600, 120), (3200, 120), (4000, 120)],
    ),
    (
        BeepEvent::ProvisionFail,
        &[(3500, 150), (2600, 150), (2000, 150)],
    ),
    (BeepEvent::Boot, &[(2600, 60)]),
];

/// Look up the feedback pattern for `event`.
///
/// The unit tests pin coverage of every [`BeepEvent`] variant, so a miss returns
/// an empty slice only if the table and the enum ever drift apart.
pub fn pattern_for(event: BeepEvent) -> &'static [Tone] {
    for (ev, pattern) in PATTERN_TABLE {
        if *ev == event {
            return pattern;
        }
    }
    &[]
}

/// Hardware-facing section: pins, channel, and the async play loop.
///
/// Compiled only for the embedded targets. The host test build (x86_64) sees only
/// the pure table/lookup surface above.
#[cfg(any(target_arch = "riscv32", target_arch = "xtensa"))]
mod embedded {
    use super::*;

    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::channel::{Channel, Receiver, Sender};
    use embassy_time::{Duration, Timer, with_timeout};
    use esp_hal::gpio::{Level, Output};
    use esp_println::println;

    /// Approximate cost of one `spin_delay` iteration at 240 MHz.
    ///
    /// Matches the `spin_delay(ns / 12)` convention already used by the door
    /// soft-SPI driver in `board.rs` (~10-16 ns/iteration).
    const NS_PER_SPIN: u64 = 12;

    /// Channel delivering feedback events to the piezo task.
    ///
    /// Hook sites should use `PIEZO_CHANNEL.try_send(event)` (or `.sender()`),
    /// dropping the event when full so the NFC/MQTT loop never blocks.
    pub static PIEZO_CHANNEL: Channel<CriticalSectionRawMutex, BeepEvent, PIEZO_CHANNEL_CAPACITY> =
        Channel::new();

    /// Handle used by hook sites to enqueue events.
    pub type PiezoSender = Sender<'static, CriticalSectionRawMutex, BeepEvent, PIEZO_CHANNEL_CAPACITY>;
    /// Handle owned by the piezo task to drain events.
    pub type PiezoReceiver =
        Receiver<'static, CriticalSectionRawMutex, BeepEvent, PIEZO_CHANNEL_CAPACITY>;

    /// The two GPIO legs that drive the passive disc differentially.
    pub struct PiezoPins {
        /// Bridge leg A.
        pub a: Output<'static>,
        /// Bridge leg B.
        pub b: Output<'static>,
    }

    impl PiezoPins {
        /// Construct the pair from two already-owned output pins.
        pub fn new(a: Output<'static>, b: Output<'static>) -> Self {
            Self { a, b }
        }

        /// Leave the disc un-driven: both legs low, no DC across the disc.
        fn idle(&mut self) {
            self.a.set_level(Level::Low);
            self.b.set_level(Level::Low);
        }
    }

    /// Real-time busy-wait, materialized so the optimizer cannot delete it.
    ///
    /// Plain `core::hint::spin_loop()` loops are side-effect-free and LLVM
    /// collapses them entirely in release builds — every ms-scale delay in the
    /// door driver silently vanished before `black_box` was added per iteration.
    /// Copied verbatim from `board.rs` so the C6 board (which never had a copy)
    /// can share the proven helper. ~2-4 cycles/iteration at 240 MHz.
    #[inline(never)]
    fn spin_delay(iterations: u32) {
        for i in 0..iterations {
            core::hint::black_box(i);
        }
    }

    /// Bit-bang one tone on the bridge.
    ///
    /// Blocks for approximately `on_ms`. The play loop is the only caller, so this
    /// blocks its own task rather than any hook site. Both legs are returned to
    /// low on exit so the disc never sits under DC bias.
    fn play_tone(pins: &mut PiezoPins, freq_hz: u32, on_ms: u32) {
        if freq_hz == 0 || on_ms == 0 {
            return;
        }
        debug_assert!(
            (FREQ_MIN_HZ..=FREQ_MAX_HZ).contains(&freq_hz),
            "tone frequency {freq_hz} Hz out of bounds"
        );
        debug_assert!(
            (ON_MS_MIN..=ON_MS_MAX).contains(&on_ms),
            "tone duration {on_ms} ms out of bounds"
        );

        // Half-period of the square wave in nanoseconds.
        let half_ns = 1_000_000_000u64 / (2 * freq_hz as u64);
        let half_spins = ((half_ns / NS_PER_SPIN).max(1)) as u32;
        let half_count = (on_ms as u64 * 1_000_000) / half_ns;

        let mut leg_a_high = false;
        for _ in 0..half_count {
            if leg_a_high {
                pins.a.set_level(Level::High);
                pins.b.set_level(Level::Low);
            } else {
                pins.a.set_level(Level::Low);
                pins.b.set_level(Level::High);
            }
            leg_a_high = !leg_a_high;
            spin_delay(half_spins);
        }

        pins.idle();
    }

    /// Play a pattern with inter-tone gaps, returning the pins to idle.
    async fn play_pattern(pins: &mut PiezoPins, pattern: &[Tone]) {
        for (i, &(freq_hz, on_ms)) in pattern.iter().enumerate() {
            if i > 0 {
                pins.idle();
                Timer::after(Duration::from_millis(TONE_GAP_MS as u64)).await;
            }
            play_tone(pins, freq_hz, on_ms);
        }
        pins.idle();
    }

    fn conn_state() -> u8 {
        super::CONN_STATE.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Drain feedback events and play their patterns forever.
    ///
    /// Between events (1 s tick) the connection state drives audible progress:
    /// single beep while joining Wi-Fi, double beep while joining MQTT, a
    /// rising confirmation when online, and a slow beep every 15 s while
    /// reconnecting after a drop.
    pub async fn run(rx: PiezoReceiver, mut pins: PiezoPins) -> ! {
        pins.idle();
        println!("[piezo] bridge driver ready (idle both-low)");

        let mut tick: u32 = 0;
        let mut online_announced = false;
        loop {
            match with_timeout(Duration::from_millis(500), rx.receive()).await {
                Ok(event) => {
                    let pattern = pattern_for(event);
                    println!("[piezo] play {:?} ({} tone(s))", event, pattern.len());
                    play_pattern(&mut pins, &pattern).await;
                }
                Err(_) => {
                    tick = tick.saturating_add(1);
                    match conn_state() {
                        super::conn::WAIT_WIFI => {
                            if tick % 20 == 0 {
                                play_pattern(&mut pins, &[(2000, 80)]).await;
                            }
                        }
                        super::conn::WAIT_MQTT => {
                            if tick % 20 == 0 {
                                play_pattern(&mut pins, &[(2500, 50), (2500, 50)]).await;
                            }
                        }
                        super::conn::ONLINE => {
                            if !online_announced {
                                online_announced = true;
                                // Classic "Charge!" bugle fanfare (double-tempo): G - C - E - G ... E - G!
                                play_pattern(
                                    &mut pins,
                                    &[
                                        (1568, 40),
                                        (2093, 40),
                                        (2637, 40),
                                        (3136, 70),
                                        (2637, 40),
                                        (3136, 130),
                                    ],
                                )
                                .await;
                            }
                        }
                        super::conn::RECONNECT => {
                            if tick % 30 == 0 {
                                play_pattern(&mut pins, &[(1200, 150)]).await;
                            }
                        }
                        super::conn::PROV_ARMED => {
                            // Continuous low beep every 500ms while window is open
                            play_pattern(&mut pins, &[(1600, 60)]).await;
                        }
                        super::conn::PROV_WRITING => {
                            // Continuous higher tone while provisioning is in progress
                            play_pattern(&mut pins, &[(3000, 100)]).await;
                        }
                        _ => {}
                    }
                    pins.idle();
                }
            }
            if conn_state() != super::conn::ONLINE {
                online_announced = false;
            }
        }
    }

    /// Embassy task wrapper around [`run`].
    #[embassy_executor::task]
    pub async fn piezo_task(rx: PiezoReceiver, pins: PiezoPins) -> ! {
        run(rx, pins).await
    }
}

#[cfg(any(target_arch = "riscv32", target_arch = "xtensa"))]
// `run` and `PiezoReceiver` are the public API surface for the play loop; until
// the node hooks call through them they are referenced only inside `embedded`.
#[allow(unused_imports)]
pub use embedded::{PIEZO_CHANNEL, PiezoPins, PiezoReceiver, PiezoSender, piezo_task, run};

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_EVENTS: [BeepEvent; 9] = [
        BeepEvent::TagDetected,
        BeepEvent::AuthSent,
        BeepEvent::Granted,
        BeepEvent::Denied,
        BeepEvent::RelayPulse,
        BeepEvent::ProvisionArmed,
        BeepEvent::ProvisionOk,
        BeepEvent::ProvisionFail,
        BeepEvent::Boot,
    ];

    #[test]
    fn pattern_table_is_well_formed() {
        assert!(!PATTERN_TABLE.is_empty(), "pattern table must not be empty");
        for (event, tones) in PATTERN_TABLE {
            assert!(!tones.is_empty(), "{event:?} has an empty pattern");
            for &(freq_hz, on_ms) in *tones {
                assert!(
                    (FREQ_MIN_HZ..=FREQ_MAX_HZ).contains(&freq_hz),
                    "{event:?} frequency {freq_hz} Hz outside {FREQ_MIN_HZ}-{FREQ_MAX_HZ} Hz"
                );
                assert!(
                    (ON_MS_MIN..=ON_MS_MAX).contains(&on_ms),
                    "{event:?} duration {on_ms} ms outside {ON_MS_MIN}-{ON_MS_MAX} ms"
                );
            }
        }
    }

    #[test]
    fn lookup_covers_every_event() {
        assert_eq!(
            PATTERN_TABLE.len(),
            ALL_EVENTS.len(),
            "table has one entry per event"
        );
        for event in ALL_EVENTS {
            assert!(
                !pattern_for(event).is_empty(),
                "{event:?} has no pattern in the lookup"
            );
        }
    }

    #[test]
    fn overflow_drops_ninth_event_on_full_channel() {
        use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
        use embassy_sync::channel::{Channel, TrySendError};

        static CH: Channel<CriticalSectionRawMutex, BeepEvent, PIEZO_CHANNEL_CAPACITY> =
            Channel::new();

        // Given a channel with exactly `PIEZO_CHANNEL_CAPACITY` free slots,
        // when every slot is filled...
        for slot in 0..PIEZO_CHANNEL_CAPACITY {
            CH.try_send(BeepEvent::Boot)
                .unwrap_or_else(|_| panic!("slot {slot} should accept"));
        }

        // ...then the next try_send must drop the new event instead of blocking.
        let overflow = CH.try_send(BeepEvent::Granted);
        assert!(
            matches!(&overflow, Err(TrySendError::Full(BeepEvent::Granted))),
            "9th try_send must drop with Full, got {overflow:?}"
        );
    }
}
