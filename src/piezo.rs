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

/// One beat: a quarter note (400 ms tone) or a short note (160 ms) plus rest.
/// 400 ms (150 BPM) makes each note clearly audible and distinct.
pub const BEAT_DURATION_MS: u32 = 400;

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

/// Bugle fanfare played on connecting: Eb5 -> Ab5 -> C6 -> Eb6 -> (rest) -> C6 -> Eb6 (long).
/// Modeled from `sound/bugle.mid` at half-tempo / full-beat steps (272 ms per note):
/// the rising arpeggio takes ~1.08s, matching the LMMS project perception.
pub const BUGLE_CALL: &[Beep] = &[
    Beep { freq: 622, tone_duration_ms: 272, rest_duration_ms: 0 },
    Beep { freq: 831, tone_duration_ms: 272, rest_duration_ms: 0 },
    Beep { freq: 1047, tone_duration_ms: 272, rest_duration_ms: 0 },
    Beep { freq: 1245, tone_duration_ms: 272, rest_duration_ms: 180 },
    Beep { freq: 1047, tone_duration_ms: 272, rest_duration_ms: 0 },
    Beep { freq: 1245, tone_duration_ms: 545, rest_duration_ms: 0 },
];

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

        // Quarters touch: a quarter note fills the whole 400 ms beat
        // (no rest); eighths are 160 ms followed by a 240 ms rest.
        let tone_duration = if is_short { 160 } else { 400 };

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
    // Auth request: silent so it does not interrupt the card's melody.
    (BeepEvent::AuthSent, &[]),
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

/// A tone generator. `start` begins emitting `freq_hz` and returns — the
/// hardware (LEDC PWM) keeps the wave going with zero CPU; `stop` silences
/// the output. Split start/stop so the melody loop can `await` each note
/// duration while the sound runs entirely in hardware, in parallel with
/// every other task.
pub trait ToneDriver {
    fn start(&mut self, freq_hz: u32);
    fn stop(&mut self);
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
    use esp_println::println;

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

    /// Emit one tone through the tone driver, awaiting its duration. The
    /// hardware emits the waveform; this task just sleeps.
    async fn play_tone<T: ToneDriver>(tone: &mut T, freq_hz: u32, on_ms: u32) {
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
        tone.start(freq_hz);
        Timer::after(Duration::from_millis(on_ms as u64)).await;
        tone.stop();
    }

    /// Play a pattern with inter-tone gaps, leaving the output silent.
    async fn play_pattern<T: ToneDriver>(tone: &mut T, pattern: &[Tone]) {
        for (i, &(freq_hz, on_ms)) in pattern.iter().enumerate() {
            if i > 0 {
                tone.stop();
                Timer::after(Duration::from_millis(TONE_GAP_MS as u64)).await;
            }
            play_tone(tone, freq_hz, on_ms).await;
        }
        tone.stop();
    }

    /// Play an exact melody of notes and rests without synthetic gaps.
    async fn play_melody<T: ToneDriver>(tone: &mut T, melody: &[Beep]) {
        for beat in melody {
            play_tone(tone, beat.freq, beat.tone_duration_ms).await;
            if beat.rest_duration_ms > 0 {
                Timer::after(Duration::from_millis(beat.rest_duration_ms as u64)).await;
            }
        }
        tone.stop();
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
    pub async fn run<T: ToneDriver>(rx: PiezoReceiver, mut tone: T) -> ! {
        tone.stop();
        println!("[piezo] LEDC tone driver ready (hardware PWM)");

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
                            play_pattern(&mut tone, &pattern).await;
                        }
                    }
                    // Full-length notes: the hardware PWM emits the waveform
                    // while this task awaits — the NFC task keeps its slice.
                    play_tone(&mut tone, beat.freq, beat.tone_duration_ms).await;
                    if beat.rest_duration_ms > 0 {
                        Timer::after(Duration::from_millis(beat.rest_duration_ms as u64)).await;
                    }
                }
            }
            match with_timeout(Duration::from_millis(500), rx.receive()).await {
                Ok(event) => {
                    let pattern = pattern_for(event);
                    if !pattern.is_empty() {
                        println!("[piezo] play {:?} ({} tone(s))", event, pattern.len());
                        play_pattern(&mut tone, &pattern).await;
                    }
                }
                Err(_) => {
                    tick = tick.saturating_add(1);
                    match conn_state() {
                        super::conn::WAIT_WIFI => {
                            if tick % 20 == 0 {
                                play_pattern(&mut tone, &[(2000, 80)]).await;
                            }
                        }
                        super::conn::WAIT_MQTT => {
                            if tick % 20 == 0 {
                                play_pattern(&mut tone, &[(2500, 50), (2500, 50)]).await;
                            }
                        }
                        super::conn::ONLINE => {
                            if !online_announced {
                                online_announced = true;
                                play_melody(&mut tone, BUGLE_CALL).await;
                            }
                        }
                        super::conn::RECONNECT => {
                            if tick % 30 == 0 {
                                play_pattern(&mut tone, &[(1200, 150)]).await;
                            }
                        }
                        super::conn::PROV_ARMED => {
                            // Continuous low beep every 500ms while window is open
                            play_pattern(&mut tone, &[(1600, 60)]).await;
                        }
                        super::conn::PROV_WRITING => {
                            // Continuous higher tone while provisioning is in progress
                            play_pattern(&mut tone, &[(3000, 100)]).await;
                        }
                        _ => {}
                    }
                    tone.stop();
                }
            }
            if conn_state() != super::conn::ONLINE {
                online_announced = false;
            }
        }
    }

    // NOTE: no #[embassy_executor::task] here — the macro forbids generics.
    // Each board defines a concrete task wrapping [`run`] with its own
    // ToneDriver (see board.rs).
}

#[cfg(any(target_arch = "riscv32", target_arch = "xtensa"))]
// `run` and `PiezoReceiver` are the public API surface for the play loop; until
// the node hooks call through them they are referenced only inside `embedded`.
#[allow(unused_imports)]
pub use embedded::{PIEZO_CHANNEL, PiezoReceiver, PiezoSender, run};

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
            // TagDetected and AuthSent are silent so as not to interrupt
            // the in-field card melody.
            if *event == BeepEvent::TagDetected || *event == BeepEvent::AuthSent {
                assert!(tones.is_empty(), "{event:?} must stay silent");
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
            if event == BeepEvent::TagDetected || event == BeepEvent::AuthSent {
                continue; // silent wake / silent auth
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
                    beat.tone_duration_ms == 160 || beat.tone_duration_ms == 400,
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
        // Sequence 0: digit 0 -> pitch 0, quarter note — quarters touch:
        // full 400 ms beat, no rest.
        let m = melody_from_sequence(0);
        assert!(
            m.iter()
                .all(|b| b.freq == 1047 && b.tone_duration_ms == 400 && b.rest_duration_ms == 0)
        );

        // Sequence 5: digit 5 -> pitch 0, eighth note + rest (160 + 240).
        let m = melody_from_sequence(5);
        assert_eq!(m[0].freq, 1047);
        assert_eq!(m[0].tone_duration_ms, 160);
        assert_eq!(m[0].rest_duration_ms, 240);

        // Sequence 1234: digits extracted LSB-first 4,3,2,1 -> all quarters,
        // pitches A6, G6, E6, D6 in that beat order.
        let m = melody_from_sequence(1234);
        let freqs: [u32; 4] = [m[0].freq, m[1].freq, m[2].freq, m[3].freq];
        assert_eq!(freqs, [1760, 1568, 1319, 1175]);
        assert!(m.iter().all(|b| b.tone_duration_ms == 400));

        // Sequence 9999: digit 9 -> pitch 4, short, every beat.
        let m = melody_from_sequence(9999);
        assert!(m.iter().all(|b| b.freq == 1760 && b.tone_duration_ms == 160));
    }

    #[test]
    fn bugle_call_matches_midi_spec() {
        assert_eq!(BUGLE_CALL.len(), 6);
        let total_ms: u32 = BUGLE_CALL
            .iter()
            .map(|b| b.tone_duration_ms + b.rest_duration_ms)
            .sum();
        // 4 x 272 ms (rising arpeggio ~1.08s) + 180 ms rest + 272 ms + 545 ms = 2085 ms (~2.08s)
        assert_eq!(total_ms, 2085);
        assert_eq!(BUGLE_CALL[0].freq, 622); // Eb5
        assert_eq!(BUGLE_CALL[1].freq, 831); // Ab5
        assert_eq!(BUGLE_CALL[2].freq, 1047); // C6
        assert_eq!(BUGLE_CALL[3].freq, 1245); // Eb6
        assert_eq!(BUGLE_CALL[3].rest_duration_ms, 180); // breath rest
        assert_eq!(BUGLE_CALL[4].freq, 1047); // C6
        assert_eq!(BUGLE_CALL[5].freq, 1245); // Eb6
    }
}
