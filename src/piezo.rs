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
    /// A tag was sighted. Wake-up event only — the audible announcement is
    /// the UID melody (see [`FIELD_UID`]/[`generate_melody`]); the pattern
    /// table maps this event to silence.
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
    /// PN532 failed to initialize — the reader is dead and the node is
    /// not guarding the door. Repeated periodically while absent.
    NfcDown,
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

/// ---- In-field identity melody -----------------------------------------
///
/// While a tag is physically in the RF field, the piezo plays a repeating
/// 4-beat measure derived from that card's UID (FNV-1a → base-10 digits;
/// each digit picks a pentatonic pitch and quarter-vs-short+rest rhythm).
/// The card audibly announces itself — and it works for every ISO14443-A
/// card, DNA or not.

/// Standard pentatonic frequencies in Hz (C6, D6, E6, G6, A6).
pub const PENTATONIC_FREQS: [u32; 5] = [1047, 1175, 1319, 1568, 1760];

/// One beat: a quarter note (200 ms tone) or a short note (100 ms) plus rest.
pub const BEAT_DURATION_MS: u32 = 250;

pub struct Beep {
    pub freq: u32,
    pub tone_duration_ms: u32,
    pub rest_duration_ms: u32,
}

/// The user's spec struct — derive the basics so beats compare in tests and
/// array-initialize in `melody_from_sequence`.
impl PartialEq for Beep {
    fn eq(&self, other: &Self) -> bool {
        self.freq == other.freq
            && self.tone_duration_ms == other.tone_duration_ms
            && self.rest_duration_ms == other.rest_duration_ms
    }
}
impl Eq for Beep {}
impl core::fmt::Debug for Beep {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Beep({} Hz, {} ms + {} ms rest)",
            self.freq, self.tone_duration_ms, self.rest_duration_ms
        )
    }
}
impl Clone for Beep {
    fn clone(&self) -> Self {
        *self
    }
}
impl Copy for Beep {}

/// FNV-1a 32-bit hash of the raw UID bytes.
fn hash_uid(uid: &[u8]) -> u32 {
    let mut hash: u32 = 2166136261;
    for &byte in uid {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(16777619);
    }
    hash
}

/// Map a base-10 digit sequence (LSB first, 10 combinations per beat:
/// digit % 5 = pentatonic pitch, digit >= 5 = eighth note + rest) to beats.
fn melody_from_sequence(mut sequence_val: u32) -> [Beep; 4] {
    let mut melody: [Beep; 4] = [Beep {
        freq: 0,
        tone_duration_ms: 0,
        rest_duration_ms: 0,
    }; 4];

    for beat in melody.iter_mut() {
        let digit = sequence_val % 10;
        sequence_val /= 10;

        let pitch_index = (digit % 5) as usize;
        let is_short = digit >= 5;

        let tone_duration = if is_short { 100 } else { 200 };

        *beat = Beep {
            freq: PENTATONIC_FREQS[pitch_index],
            tone_duration_ms: tone_duration,
            rest_duration_ms: BEAT_DURATION_MS - tone_duration,
        };
    }
    melody
}

/// A card's signature measure: 4 beats from its UID.
pub fn generate_melody(uid: &[u8]) -> [Beep; 4] {
    melody_from_sequence(hash_uid(uid) % 10_000)
}

/// UID of the tag currently in the RF field (empty = field clear).
pub static FIELD_UID: embassy_sync::mutex::Mutex<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    heapless::Vec<u8, 10>,
> = embassy_sync::mutex::Mutex::new(heapless::Vec::new());

/// Publish the in-field tag's UID (empty slice = tag left the field).
pub async fn set_field_uid(uid: &[u8]) {
    let mut guard = FIELD_UID.lock().await;
    guard.clear();
    for &b in uid {
        if guard.push(b).is_err() {
            break;
        }
    }
}

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
    // Sightings are announced by the UID melody (see FIELD_UID), not a
    // chirp — TagDetected remains as the wake-up event that pulls the piezo
    // task out of its idle wait the moment a card lands.
    (BeepEvent::TagDetected, &[]),
    (BeepEvent::AuthSent, &[(2600, 40)]),
    // Verdict: single short chirp. The relay click and the door itself are
    // the primary grant feedback; no fanfare after the tag has left.
    (BeepEvent::Granted, &[(3200, 100)]),
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
    // Reader-dead alarm: three low tones, unmistakable next to the connect
    // beeps (2000/2500 Hz) and the Denied double (1300 Hz).
    (
        BeepEvent::NfcDown,
        &[(900, 180), (900, 180), (900, 180)],
    ),
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
    /// While a card is in the field, its UID-derived measure (see
    /// [`generate_melody`]) repeats: the card audibly announces itself. The
    /// TagDetected event (empty pattern) wakes the idle wait instantly on a
    /// sighting so the melody starts without lag. Every beat awaits its
    /// rest — the executor always gets a slice (no starvation) — and each
    /// rest doubles as a checkpoint: field exit, card swap, or a queued
    /// event (verdict chirp) preempts the measure. Between events (1 s
    /// tick) the connection state drives audible progress: single beep
    /// while joining Wi-Fi, double beep while joining MQTT, a rising
    /// confirmation when online, and a slow beep every 15 s while
    /// reconnecting after a drop.
    pub async fn run(rx: PiezoReceiver, mut pins: PiezoPins) -> ! {
        pins.idle();
        println!("[piezo] bridge driver ready (idle both-low)");

        let mut tick: u32 = 0;
        let mut online_announced = false;
        loop {
            // In-field identity melody. Every beat awaits its rest — this
            // loop always yields, never starves the executor.
            loop {
                let field = FIELD_UID.lock().await.clone();
                if field.is_empty() {
                    break;
                }
                for beat in generate_melody(&field) {
                    if FIELD_UID.lock().await.as_slice() != field.as_slice() {
                        break; // card left or swapped mid-measure
                    }
                    if let Ok(event) = rx.try_receive() {
                        let pattern = pattern_for(event);
                        if !pattern.is_empty() {
                            println!("[piezo] play {:?} ({} tone(s))", event, pattern.len());
                            play_pattern(&mut pins, &pattern).await;
                        }
                    }
                    play_tone(&mut pins, beat.freq, beat.tone_duration_ms);
                    if beat.rest_duration_ms > 0 {
                        Timer::after(Duration::from_millis(beat.rest_duration_ms as u64)).await;
                    }
                }
            }
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
                                // Classic "Charge!" bugle fanfare: G - C - E - G^ - E - G^!
                                // 4th/5th notes halved vs the original dotted rhythm, whole
                                // thing at 0.8x duration (20% faster). Base was 40ms.
                                play_pattern(
                                    &mut pins,
                                    &[
                                        (1568, 32),
                                        (2093, 32),
                                        (2637, 32),
                                        (3136, 28),
                                        (2637, 16),
                                        (3136, 104),
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

    const ALL_EVENTS: [BeepEvent; 10] = [
        BeepEvent::TagDetected,
        BeepEvent::AuthSent,
        BeepEvent::Granted,
        BeepEvent::Denied,
        BeepEvent::RelayPulse,
        BeepEvent::ProvisionArmed,
        BeepEvent::ProvisionOk,
        BeepEvent::ProvisionFail,
        BeepEvent::Boot,
        BeepEvent::NfcDown,
    ];

    #[test]
    fn pattern_table_is_well_formed() {
        assert!(!PATTERN_TABLE.is_empty(), "pattern table must not be empty");
        for (event, tones) in PATTERN_TABLE {
            // TagDetected is the documented exception: wake-up event only —
            // sightings are announced by the UID melody, not a chirp.
            if *event == BeepEvent::TagDetected {
                assert!(tones.is_empty(), "TagDetected must stay a silent wake");
                continue;
            }
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
            if event == BeepEvent::TagDetected {
                continue; // silent wake — see pattern_table_is_well_formed
            }
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

    #[test]
    fn melody_beats_are_well_formed() {
        for uid in [
            &b""[..],
            b"\x04\x87\x53\x62\x1e\x18\x90",
            b"\x04\x5c\x64\x62\x1e\x18\x90",
            b"\x11\x22\x33\x44",
        ] {
            for beat in generate_melody(uid) {
                assert!(
                    PENTATONIC_FREQS.contains(&beat.freq),
                    "pitch {} Hz off the pentatonic scale",
                    beat.freq
                );
                assert!(
                    beat.tone_duration_ms == 100 || beat.tone_duration_ms == 200,
                    "tone {} ms is neither eighth nor quarter",
                    beat.tone_duration_ms
                );
                assert_eq!(
                    beat.tone_duration_ms + beat.rest_duration_ms,
                    BEAT_DURATION_MS,
                    "beat must fill exactly one measure slot"
                );
            }
        }
    }

    #[test]
    fn melody_is_deterministic_and_uid_sensitive() {
        let a = generate_melody(b"\x04\x87\x53\x62\x1e\x18\x90");
        assert_eq!(a, generate_melody(b"\x04\x87\x53\x62\x1e\x18\x90"));
        // Two real card UIDs: overwhelmingly unlikely to share a measure.
        let b = generate_melody(b"\x04\x5c\x64\x62\x1e\x18\x90");
        assert_ne!(a, b);
    }

    #[test]
    fn melody_digit_mapping_is_lsb_first_quarter_or_short() {
        // Sequence 0: digit 0 -> pitch 0, quarter note (200 ms + 50 ms rest).
        let m = melody_from_sequence(0);
        assert!(m.iter().all(|b| b.freq == 1047 && b.tone_duration_ms == 200));

        // Sequence 5: digit 5 -> pitch 0, eighth note + rest (100 + 150).
        let m = melody_from_sequence(5);
        assert_eq!(m[0].freq, 1047);
        assert_eq!(m[0].tone_duration_ms, 100);
        assert_eq!(m[0].rest_duration_ms, 150);

        // Sequence 1234: digits extracted LSB-first 4,3,2,1 -> all quarters,
        // pitches A6, G6, E6, D6 in that beat order.
        let m = melody_from_sequence(1234);
        let freqs: [u32; 4] = [m[0].freq, m[1].freq, m[2].freq, m[3].freq];
        assert_eq!(freqs, [1760, 1568, 1319, 1175]);
        assert!(m.iter().all(|b| b.tone_duration_ms == 200));

        // Sequence 9999: digit 9 -> pitch 4, short, every beat.
        let m = melody_from_sequence(9999);
        assert!(m.iter().all(|b| b.freq == 1760 && b.tone_duration_ms == 100));
    }
}
