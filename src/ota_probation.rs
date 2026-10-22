//! OTA probation state machine and word-aligned otadata marker codec.
//!
//! Pure `no_std` module with no HAL or heap dependencies so it can be verified in host unit tests.
//!
//! # Alignment Constraint
//! All flash operations inside the otadata sector must be 4-byte (word) aligned:
//! `esp-storage` 0.8.1 rejects any write where `offset % 4 != 0` or `len % 4 != 0` with `NotAligned`.
//! Marker layout spans bytes `[4..24)` within the 32-byte otadata entry's `seq_label` scratch field.
//!
//! # Bootloader otadata CRC Rule & Rewrite-not-Mutate Pattern
//! The ESP-IDF second stage bootloader validates entries by computing `crc32_le(0, &entry[0..28])`
//! and checking it against `entry[28..32]` (`crc`).
//! Because `seq_label` [4..24) sits inside the 28-byte CRC span, any change to marker fields
//! (attempt count or confirmation status) renders the previous CRC stale and invalidates the entry
//! per the bootloader's rule.
//!
//! Therefore, all marker operations use a full rewrite-not-mutate pattern:
//! 1. Read current 4KB otadata sector into RAM.
//! 2. Mutate marker field(s) in the buffer.
//! 3. Recompute CRC over `entry[0..28]` with `crc32_le_compat(0, &entry[0..28])`.
//! 4. Erase the 4KB otadata sector.
//! 5. Rewrite the sector with fresh CRC.
//!
//! # Fail-Safe & Torn-Write Semantics
//! - A torn rewrite (power loss during sector erase or rewrite) leaves an invalid or blank entry.
//! - Per ESP-IDF bootloader logic, an invalid entry causes the bootloader to fall back to the other
//!   otadata sector (the previous slot's valid entry), resulting in a spontaneous rollback.
//!   This failure direction is fail-safe: it falls back to previously known-good firmware rather
//!   than booting unverified or corrupted state.
//! - Marker-free rollback: rollback entries explicitly wipe the `seq_label` field to all `0xFF`.
//!   A pending marker on the rollback entry would trigger probation on the known-good previous firmware,
//!   causing a boot ping-pong loop when the network or broker is unreachable.

pub const PROBATION_DEADLINE_MS: u64 = 90_000;
pub const ATTEMPT_THRESHOLD: u32 = 3;
pub const OFFLINE_RESET_MS: u64 = 180_000;
pub const RX_TIMEOUT_MS: u64 = 120_000;
pub const PRESENCE_REFRESH_MS: u64 = 60_000;

pub const MAGIC_KGOT: u32 = 0x544F_474B; // "KGOT" in Little-Endian
pub const STATUS_PENDING: u32 = 0xFFFF_FFFF;
pub const STATUS_CONFIRMED: u32 = 0x0000_0000;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MarkerState {
    Pending { attempts: u32 },
    Confirmed,
    Absent,
}

/// Host-safe ROM crc32_le reimplementation matching ESP-IDF bootloader and esp_hal::rom::crc::crc32_le.
///
/// Uses the IEEE 802.3 polynomial (reflected 0xEDB88320) with passed initial crc and ~0 final XOR.
/// Pinned test vector: `crc32_le_compat(0, &[0x01, 0x00, 0x00, 0x00]) == 0x4743989A`.
pub fn crc32_le_compat(crc: u32, data: &[u8]) -> u32 {
    let mut c = crc;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    c ^ 0xFFFF_FFFF
}

/// Count the number of consumed attempt slots in a 4-byte bitmap word.
///
/// Byte i is 0xFF until attempt i+1 clears it to 0x00.
pub fn attempts(bitmap_word: [u8; 4]) -> u32 {
    let mut count = 0;
    for &b in &bitmap_word {
        if b != 0xFF {
            count += 1;
        }
    }
    count
}

/// Compute the next attempt bitmap word by clearing the next available 0xFF slot to 0x00.
///
/// Returns None when all 4 attempt slots are consumed.
pub fn next_bitmap(bitmap_word: [u8; 4]) -> Option<[u8; 4]> {
    let mut next = bitmap_word;
    for b in &mut next {
        if *b == 0xFF {
            *b = 0x00;
            return Some(next);
        }
    }
    None
}

/// Decode the probation marker inside a 32-byte otadata entry.
///
/// - Bytes [4..8): Magic "KGOT" (LE 0x544F474B)
/// - Bytes [8..12): Status word (0xFFFFFFFF = pending, 0x00000000 = confirmed)
/// - Bytes [12..16): Attempt bitmap word (4 byte-slots)
/// - Bytes [16..24): Spare (stays 0xFF)
pub fn decode_marker(entry: &[u8; 32]) -> MarkerState {
    let magic = u32::from_le_bytes(entry[4..8].try_into().unwrap_or([0xFF; 4]));
    if magic != MAGIC_KGOT {
        return MarkerState::Absent;
    }

    let status = u32::from_le_bytes(entry[8..12].try_into().unwrap_or([0xFF; 4]));
    let bitmap: [u8; 4] = entry[12..16].try_into().unwrap_or([0xFF; 4]);

    if status == STATUS_CONFIRMED {
        MarkerState::Confirmed
    } else {
        MarkerState::Pending {
            attempts: attempts(bitmap),
        }
    }
}

/// Determine whether the current marker state requires an automatic rollback.
///
/// True if and only if state is Pending and attempt count >= ATTEMPT_THRESHOLD (3).
pub fn should_rollback(state: &MarkerState) -> bool {
    match state {
        MarkerState::Pending { attempts } => *attempts >= ATTEMPT_THRESHOLD,
        MarkerState::Confirmed | MarkerState::Absent => false,
    }
}

/// Check whether the probation deadline has expired since boot time.
///
/// Uses wall-clock `saturating_sub` to protect against clock anomalies.
pub fn deadline_expired(boot_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(boot_ms) >= PROBATION_DEADLINE_MS
}

/// Construct a 32-byte otadata entry for rolling back to the previous firmware slot.
///
/// - `seq` = current_max_seq + 2 (LE at [0..4])
/// - `seq_label` [4..24) ALL 0xFF (marker-free: prevents re-probating known-good old image)
/// - `ota_state` [24..28) = 2u32 LE (VALID)
/// - `crc` [28..32) = crc32_le_compat(0, entry[0..28]) LE
pub fn rollback_entry_32(current_max_seq: u32) -> [u8; 32] {
    let mut entry = [0xFFu8; 32];
    let next_seq = current_max_seq.wrapping_add(2);
    entry[0..4].copy_from_slice(&next_seq.to_le_bytes());
    // bytes [4..24) stay 0xFF (marker-free)
    entry[24..28].copy_from_slice(&2u32.to_le_bytes());
    let entry_crc = crc32_le_compat(0, &entry[0..28]);
    entry[28..32].copy_from_slice(&entry_crc.to_le_bytes());
    entry
}

/// Stamp the initial PENDING probation marker into the `seq_label` scratch area [4..24) of an otadata entry.
///
/// - [4..8): magic word `MAGIC_KGOT`
/// - [8..12): status word `STATUS_PENDING` (0xFFFFFFFF)
/// - [12..16): attempt bitmap word `[0xFF; 4]` (0 attempts)
/// - [16..24): spare `[0xFF; 8]`
pub fn stamp_pending_marker(entry: &mut [u8; 32]) {
    entry[4..8].copy_from_slice(&MAGIC_KGOT.to_le_bytes());
    entry[8..12].copy_from_slice(&STATUS_PENDING.to_le_bytes());
    entry[12..16].copy_from_slice(&[0xFFu8; 4]);
    entry[16..24].copy_from_slice(&[0xFFu8; 8]);
}

/// Transition marker status word from pending to confirmed.
///
/// Status word 0xFFFFFFFF -> 0x00000000. Idempotent: any other value is returned unchanged.
pub fn confirm_transition(status_word: [u8; 4]) -> [u8; 4] {
    let word = u32::from_le_bytes(status_word);
    if word == STATUS_PENDING {
        STATUS_CONFIRMED.to_le_bytes()
    } else {
        status_word
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_crc_vector() {
        assert_eq!(crc32_le_compat(0, &[0x01, 0x00, 0x00, 0x00]), 0x4743989A);
    }

    #[test]
    fn test_round_trip_encode_decode() {
        let mut entry = [0xFFu8; 32];
        entry[0..4].copy_from_slice(&2u32.to_le_bytes());
        stamp_pending_marker(&mut entry);
        entry[12..16].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF]);
        entry[24..28].copy_from_slice(&2u32.to_le_bytes());
        let entry_crc = crc32_le_compat(0, &entry[0..4]);
        entry[28..32].copy_from_slice(&entry_crc.to_le_bytes());

        let decoded = decode_marker(&entry);
        assert_eq!(decoded, MarkerState::Pending { attempts: 1 });

        let mut confirmed_entry = entry;
        confirmed_entry[8..12].copy_from_slice(&STATUS_CONFIRMED.to_le_bytes());
        assert_eq!(decode_marker(&confirmed_entry), MarkerState::Confirmed);
    }

    #[test]
    fn test_regression_stamp_confirm_transition_decodes_confirmed() {
        let mut entry = [0xFFu8; 32];
        stamp_pending_marker(&mut entry);
        assert_eq!(decode_marker(&entry), MarkerState::Pending { attempts: 0 });

        let status_word: [u8; 4] = entry[8..12].try_into().unwrap();
        let confirmed_status = confirm_transition(status_word);
        entry[8..12].copy_from_slice(&confirmed_status);
        assert_eq!(decode_marker(&entry), MarkerState::Confirmed);
    }

    #[test]
    fn test_regression_stamp_next_bitmap_decodes_pending_attempt_1() {
        let mut entry = [0xFFu8; 32];
        stamp_pending_marker(&mut entry);

        let bitmap_word: [u8; 4] = entry[12..16].try_into().unwrap();
        let next = next_bitmap(bitmap_word).expect("first attempt");
        entry[12..16].copy_from_slice(&next);
        assert_eq!(decode_marker(&entry), MarkerState::Pending { attempts: 1 });
    }

    #[test]
    fn test_partially_cleared_status_word_decodes_pending() {
        let mut entry = [0xFFu8; 32];
        stamp_pending_marker(&mut entry);
        // Partially cleared status word: has zero bits but != 0x00000000
        entry[8..12].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        assert_eq!(decode_marker(&entry), MarkerState::Pending { attempts: 0 });
    }

    #[test]
    fn test_torn_bitmap_byte_counts_as_consumed_attempt() {
        let mut entry = [0xFFu8; 32];
        stamp_pending_marker(&mut entry);
        // Torn bitmap byte e.g. [0x0F, 0xFF, 0xFF, 0xFF] -> 1 attempt consumed
        entry[12..16].copy_from_slice(&[0x0F, 0xFF, 0xFF, 0xFF]);
        assert_eq!(decode_marker(&entry), MarkerState::Pending { attempts: 1 });
    }

    #[test]
    fn test_magic_absent_returns_absent() {
        let entry = [0xFFu8; 32];
        assert_eq!(decode_marker(&entry), MarkerState::Absent);

        let mut corrupted = [0xAAu8; 32];
        corrupted[4..8].copy_from_slice(b"NOPE");
        assert_eq!(decode_marker(&corrupted), MarkerState::Absent);
    }

    #[test]
    fn test_attempts_counting() {
        assert_eq!(attempts([0xFF, 0xFF, 0xFF, 0xFF]), 0);
        assert_eq!(attempts([0x00, 0xFF, 0xFF, 0xFF]), 1);
        assert_eq!(attempts([0x00, 0x00, 0xFF, 0xFF]), 2);
        assert_eq!(attempts([0x00, 0x00, 0x00, 0xFF]), 3);
        assert_eq!(attempts([0x00, 0x00, 0x00, 0x00]), 4);
    }

    #[test]
    fn test_should_rollback_thresholds() {
        assert!(!should_rollback(&MarkerState::Absent));
        assert!(!should_rollback(&MarkerState::Confirmed));
        assert!(!should_rollback(&MarkerState::Pending { attempts: 0 }));
        assert!(!should_rollback(&MarkerState::Pending { attempts: 1 }));
        assert!(!should_rollback(&MarkerState::Pending { attempts: 2 }));
        assert!(should_rollback(&MarkerState::Pending { attempts: 3 }));
        assert!(should_rollback(&MarkerState::Pending { attempts: 4 }));
    }

    #[test]
    fn test_next_bitmap_progression_and_exhaustion() {
        let b0 = [0xFF, 0xFF, 0xFF, 0xFF];
        let b1 = next_bitmap(b0).expect("step 1");
        assert_eq!(b1, [0x00, 0xFF, 0xFF, 0xFF]);
        let b2 = next_bitmap(b1).expect("step 2");
        assert_eq!(b2, [0x00, 0x00, 0xFF, 0xFF]);
        let b3 = next_bitmap(b2).expect("step 3");
        assert_eq!(b3, [0x00, 0x00, 0x00, 0xFF]);
        let b4 = next_bitmap(b3).expect("step 4");
        assert_eq!(b4, [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(next_bitmap(b4), None);
    }

    #[test]
    fn test_bitmap_rmw_legality_only_clears_bits() {
        let mut cur = [0xFFu8; 4];
        for _ in 0..4 {
            let next = next_bitmap(cur).expect("next slot");
            for i in 0..4 {
                assert_eq!(
                    cur[i] & next[i],
                    next[i],
                    "NOR flash invariant violated: bits changed from 0 to 1"
                );
            }
            cur = next;
        }
    }

    #[test]
    fn test_rollback_entry_marker_free_and_crc_match() {
        let entry = rollback_entry_32(1);
        let seq = u32::from_le_bytes(entry[0..4].try_into().unwrap());
        assert_eq!(seq, 3);
        assert_eq!(&entry[4..24], &[0xFFu8; 20]);
        assert_eq!(decode_marker(&entry), MarkerState::Absent);
        let ota_state = u32::from_le_bytes(entry[24..28].try_into().unwrap());
        assert_eq!(ota_state, 2);
        let crc = u32::from_le_bytes(entry[28..32].try_into().unwrap());
        assert_eq!(crc, crc32_le_compat(0, &entry[0..28]));

        let seq0_entry = rollback_entry_32(0xFFFFFFFF);
        assert_eq!(
            &seq0_entry[0..4],
            &1u32.to_le_bytes(),
            "0xFFFFFFFF + 2 should wrap to 1"
        );
        let crc_seq1 = u32::from_le_bytes(seq0_entry[28..32].try_into().unwrap());
        assert_eq!(crc_seq1, crc32_le_compat(0, &seq0_entry[0..28]));
    }

    #[test]
    fn test_entry_with_28_byte_crc_passes_validation_and_mutation_requires_rewrite() {
        let mut entry = [0xFFu8; 32];
        entry[0..4].copy_from_slice(&2u32.to_le_bytes());
        stamp_pending_marker(&mut entry);
        entry[24..28].copy_from_slice(&2u32.to_le_bytes());
        let crc = crc32_le_compat(0, &entry[0..28]);
        entry[28..32].copy_from_slice(&crc.to_le_bytes());

        // Valid per 28-byte rule
        assert_eq!(
            u32::from_le_bytes(entry[28..32].try_into().unwrap()),
            crc32_le_compat(0, &entry[0..28])
        );

        // In-place mutation (e.g. advance bitmap) makes previous CRC stale!
        let bitmap_word: [u8; 4] = entry[12..16].try_into().unwrap();
        let next_bm = next_bitmap(bitmap_word).unwrap();
        entry[12..16].copy_from_slice(&next_bm);

        // Previous CRC is now STALE / invalid per bootloader rule
        assert_ne!(
            u32::from_le_bytes(entry[28..32].try_into().unwrap()),
            crc32_le_compat(0, &entry[0..28])
        );

        // Full rewrite pattern recomputes CRC over [0..28]
        let fresh_crc = crc32_le_compat(0, &entry[0..28]);
        entry[28..32].copy_from_slice(&fresh_crc.to_le_bytes());

        // Now valid again
        assert_eq!(
            u32::from_le_bytes(entry[28..32].try_into().unwrap()),
            crc32_le_compat(0, &entry[0..28])
        );
    }

    #[test]
    fn test_confirm_transition_and_idempotence() {
        let pending = STATUS_PENDING.to_le_bytes();
        let confirmed = confirm_transition(pending);
        assert_eq!(confirmed, STATUS_CONFIRMED.to_le_bytes());

        let confirmed_again = confirm_transition(confirmed);
        assert_eq!(confirmed_again, STATUS_CONFIRMED.to_le_bytes());

        let other = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(confirm_transition(other), other);
    }

    #[test]
    fn test_deadline_expired_math_and_saturating_wrap() {
        assert!(!deadline_expired(1000, 1000));
        assert!(!deadline_expired(1000, 1000 + PROBATION_DEADLINE_MS - 1));
        assert!(deadline_expired(1000, 1000 + PROBATION_DEADLINE_MS));
        assert!(deadline_expired(1000, 1000 + PROBATION_DEADLINE_MS + 5000));
        assert!(!deadline_expired(5000, 1000));
    }

    #[test]
    fn test_decode_garbage_buffers_never_panics() {
        let patterns: [&[u8]; 6] = [
            &[0x00; 32],
            &[0xFF; 32],
            &[0xAA; 32],
            &[0x55; 32],
            &[0x12; 32],
            &[0xEE; 32],
        ];

        for pattern in patterns {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(pattern);
            let _ = decode_marker(&buf);
        }

        for i in 0..255u8 {
            let mut buf = [i; 32];
            buf[4..8].copy_from_slice(&MAGIC_KGOT.to_le_bytes());
            let _ = decode_marker(&buf);
        }
    }

    #[test]
    fn test_stamp_pending_marker() {
        let mut entry = [0xFFu8; 32];
        entry[0..4].copy_from_slice(&123u32.to_le_bytes());
        stamp_pending_marker(&mut entry);

        // Seq remains intact
        assert_eq!(u32::from_le_bytes(entry[0..4].try_into().unwrap()), 123);

        // Marker decodes as Pending { attempts: 0 }
        assert_eq!(decode_marker(&entry), MarkerState::Pending { attempts: 0 });

        // Bits only cleared relative to 0xFF in seq_label [4..24)
        for i in 4..24 {
            assert_eq!(0xFF & entry[i], entry[i]);
        }
    }
}
