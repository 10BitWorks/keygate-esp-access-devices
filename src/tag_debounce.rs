//! NFC Tag Debounce and Presence State Machine
//!
//! Enforces physical removal of tags before allowing a subsequent tap event.
//! Prevents spamming authentication requests when a tag is left resting on the reader.
//!
//! # State Machine Overview
//! - `Idle`: No tag present, reader is armed.
//! - `Tapped`: Tag detected, single tap event emitted. Subsequent detections of
//!   the same or different tag while resting do not emit new tap events.
//! - `Removing`: Tag was lost / absent (`tag == None`). Must remain absent continuously
//!   for at least `REMOVAL_DEBOUNCE_MS` (500ms) before returning to `Idle` (re-arming).
//!   If a tag re-appears within 100ms (`BOUNCE_SUPPRESSION_MS`), it is treated as RF bounce / jitter
//!   and reverts back to `Tapped` without re-arming. If it re-appears between 100ms and 500ms,
//!   removal is interrupted and reset back to `Tapped` (strict removal-first policy).

use embassy_time::{Duration, Instant};

/// Continuous absence required to re-arm the reader for a new tap (500 ms).
pub const REMOVAL_DEBOUNCE: Duration = Duration::from_millis(500);

/// Bounce suppression window for RF jitter / brief contact loss (100 ms).
pub const BOUNCE_WINDOW: Duration = Duration::from_millis(100);

/// State of tag presence on the reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Reader is armed, waiting for a tag.
    Idle,
    /// Tag is present and has already emitted its tap event.
    /// Holding or resting on the reader produces no further events.
    Tapped {
        /// Active tag UID.
        uid: [u8; 7],
        /// Length of active tag UID (typically 4 or 7).
        uid_len: u8,
    },
    /// Tag disappeared; waiting for continuous absence to re-arm.
    Removing {
        /// Previous tag UID before absence.
        last_uid: [u8; 7],
        /// Previous UID length.
        last_uid_len: u8,
        /// Timestamp when tag was first observed absent.
        absent_since: Instant,
    },
}

/// An emitted tag tap event (edge-triggered).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TapEvent {
    /// Tag UID bytes.
    pub uid: [u8; 7],
    /// Length of the UID (e.g. 4 for Mifare Classic, 7 for Ultralight/NTAG).
    pub uid_len: u8,
    /// SAK (Select Acknowledge) byte from tag selection.
    pub sak: u8,
}

/// Tag observation input supplied per poll cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagObservation<'a> {
    pub uid: &'a [u8],
    pub sak: u8,
}

impl<'a> TagObservation<'a> {
    /// Construct from raw UID slice and SAK.
    pub const fn new(uid: &'a [u8], sak: u8) -> Self {
        Self { uid, sak }
    }

    /// Helper to construct from `nfc::TagInfo`.
    pub fn from_tag_info(tag: &'a crate::nfc::TagInfo) -> Self {
        let len = (tag.uid_len as usize).min(tag.uid.len());
        Self {
            uid: &tag.uid[..len],
            sak: tag.sak,
        }
    }
}

/// Tag presence and debounce state machine.
pub struct TagDebounce {
    state: State,
}

impl TagDebounce {
    /// Create a new debounce state machine in `Idle` (armed) state.
    pub const fn new() -> Self {
        Self { state: State::Idle }
    }

    /// Current internal state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Reset state machine back to `Idle` (armed).
    pub fn reset(&mut self) {
        self.state = State::Idle;
    }

    /// Observe current sensor reading at time `now`.
    ///
    /// Returns `Some(TapEvent)` ONLY on a valid new tap transition.
    ///
    /// # Behavior
    /// 1. `Idle` + `Some(tag)` -> transitions to `Tapped`, emits `Some(TapEvent)`.
    /// 2. `Tapped` + `Some(tag)` -> remains `Tapped`, emits `None` (no repeat / spam).
    /// 3. `Tapped` + `None` -> transitions to `Removing` with `absent_since = now`.
    /// 4. `Removing` + `None`:
    ///    - If `now - absent_since >= REMOVAL_DEBOUNCE` (500ms), transitions to `Idle`.
    ///    - Otherwise remains in `Removing`.
    /// 5. `Removing` + `Some(tag)`:
    ///    - Tag reappeared before 500ms continuous absence.
    ///    - Both RF bounce (< 100ms) and short absence (< 500ms) cancel removal
    ///      and revert to `Tapped` without re-arming or emitting a new event.
    ///    - Strict removal-first: switching tags without 500ms absence is also suppressed.
    pub fn observe(
        &mut self,
        now: Instant,
        tag: Option<TagObservation<'_>>,
    ) -> Option<TapEvent> {
        match (self.state, tag) {
            (State::Idle, Some(obs)) => {
                let mut uid = [0u8; 7];
                let len = obs.uid.len().min(7);
                uid[..len].copy_from_slice(&obs.uid[..len]);
                let uid_len = len as u8;

                self.state = State::Tapped { uid, uid_len };
                Some(TapEvent {
                    uid,
                    uid_len,
                    sak: obs.sak,
                })
            }
            (State::Idle, None) => None,
            (State::Tapped { .. }, Some(_obs)) => {
                // Resting card: tag remains present. Suppress duplicate emissions.
                None
            }
            (State::Tapped { uid, uid_len }, None) => {
                // Tag just vanished from RF field.
                self.state = State::Removing {
                    last_uid: uid,
                    last_uid_len: uid_len,
                    absent_since: now,
                };
                None
            }
            (
                State::Removing {
                    absent_since, ..
                },
                None,
            ) => {
                // Check if absent long enough (>= 500 ms) to re-arm.
                if now.checked_duration_since(absent_since).unwrap_or(Duration::from_ticks(0)) >= REMOVAL_DEBOUNCE {
                    self.state = State::Idle;
                }
                None
            }
            (
                State::Removing { .. },
                Some(obs),
            ) => {
                // Tag reappeared before the full 500ms absence elapsed.
                // Strict removal-first policy: revert to Tapped without re-arming.
                // If it's a new tag presented before the 500ms re-arm window,
                // update tracking UID to the new tag while staying Tapped (no event).
                let mut uid = [0u8; 7];
                let len = obs.uid.len().min(7);
                uid[..len].copy_from_slice(&obs.uid[..len]);
                let uid_len = len as u8;

                self.state = State::Tapped { uid, uid_len };
                None
            }
        }
    }
}

impl Default for TagDebounce {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tag(uid_byte: u8) -> TagObservation<'static> {
        // Leaked or static slice for test simplicity
        match uid_byte {
            1 => TagObservation {
                uid: &[0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
                sak: 0x20,
            },
            2 => TagObservation {
                uid: &[0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                sak: 0x20,
            },
            _ => TagObservation {
                uid: &[0x12, 0x34, 0x56, 0x78],
                sak: 0x08,
            },
        }
    }

    #[test]
    fn test_single_tap_emits_one_event() {
        let mut sm = TagDebounce::new();
        let t0 = Instant::from_millis(1000);
        let tag = dummy_tag(1);

        let event = sm.observe(t0, Some(tag));
        assert!(event.is_some());
        let ev = event.unwrap();
        assert_eq!(ev.uid_len, 7);
        assert_eq!(ev.uid[0], 0x04);
        assert_eq!(ev.sak, 0x20);
        assert!(matches!(sm.state(), State::Tapped { .. }));
    }

    #[test]
    fn test_held_tag_suppresses_repeat_events() {
        let mut sm = TagDebounce::new();
        let mut t = Instant::from_millis(1000);
        let tag = dummy_tag(1);

        // First tap emits
        assert!(sm.observe(t, Some(tag)).is_some());

        // Held tag over multiple seconds emits zero additional events
        for _ in 0..50 {
            t += Duration::from_millis(100);
            assert_eq!(sm.observe(t, Some(tag)), None);
        }
        assert!(matches!(sm.state(), State::Tapped { .. }));
    }

    #[test]
    fn test_removal_boundary_500ms_rearms() {
        let mut sm = TagDebounce::new();
        let tag = dummy_tag(1);

        // Tap
        let t0 = Instant::from_millis(1000);
        assert!(sm.observe(t0, Some(tag)).is_some());

        // Tag removed at t0 + 100ms
        let t1 = t0 + Duration::from_millis(100);
        assert_eq!(sm.observe(t1, None), None);
        assert!(matches!(sm.state(), State::Removing { .. }));

        // 499ms absent -> not yet rearmed
        let t_sub = t1 + Duration::from_millis(499);
        assert_eq!(sm.observe(t_sub, None), None);
        assert!(matches!(sm.state(), State::Removing { .. }));

        // 500ms absent -> rearmed to Idle
        let t_rearm = t1 + Duration::from_millis(500);
        assert_eq!(sm.observe(t_rearm, None), None);
        assert_eq!(sm.state(), State::Idle);

        // Subsequent tap is recognized
        let t_next = t_rearm + Duration::from_millis(50);
        let ev2 = sm.observe(t_next, Some(tag));
        assert!(ev2.is_some());
    }

    #[test]
    fn test_bounce_suppression_under_100ms() {
        let mut sm = TagDebounce::new();
        let tag = dummy_tag(1);

        // Initial tap
        let t0 = Instant::from_millis(1000);
        assert!(sm.observe(t0, Some(tag)).is_some());

        // Lost contact at 1100ms
        let t_loss = t0 + Duration::from_millis(100);
        assert_eq!(sm.observe(t_loss, None), None);

        // Reappears 50ms later (RF bounce within 100ms window)
        let t_bounce = t_loss + Duration::from_millis(50);
        let ev = sm.observe(t_bounce, Some(tag));
        assert_eq!(ev, None);
        assert!(matches!(sm.state(), State::Tapped { .. }));
    }

    #[test]
    fn test_different_tag_without_500ms_absence_suppressed() {
        let mut sm = TagDebounce::new();
        let tag1 = dummy_tag(1);
        let tag2 = dummy_tag(2);

        // Tap tag1
        let t0 = Instant::from_millis(1000);
        assert!(sm.observe(t0, Some(tag1)).is_some());

        // Absence at t0 + 100ms
        let t1 = t0 + Duration::from_millis(100);
        assert_eq!(sm.observe(t1, None), None);

        // Tag2 appears at t1 + 300ms (before 500ms absence)
        let t2 = t1 + Duration::from_millis(300);
        assert_eq!(sm.observe(t2, Some(tag2)), None);
        assert!(matches!(sm.state(), State::Tapped { .. }));

        // Now remove tag2 and wait full 500ms
        let t3 = t2 + Duration::from_millis(100);
        assert_eq!(sm.observe(t3, None), None);

        let t4 = t3 + Duration::from_millis(500);
        assert_eq!(sm.observe(t4, None), None);
        assert_eq!(sm.state(), State::Idle);

        // Now tag2 emits
        let t5 = t4 + Duration::from_millis(10);
        assert!(sm.observe(t5, Some(tag2)).is_some());
    }
}
