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
//!
//! The ESP-IDF second stage bootloader validates an otadata entry by CRC32-ing **only the 4-byte
//! little-endian `seq` word** at `entry[0..4)` with an initial value of `0xFFFFFFFF`, and comparing
//! the result against `entry[28..32]` (`crc`). In C:
//!
//! ```c
//! bootloader_common_ota_select_crc = esp_rom_crc32_le(UINT32_MAX, &s->ota_seq, 4);
//! ```
//!
//! The Rust crate `esp-bootloader-esp-idf` documents the same rule ("CRC32 of the `ota_seq` field
//! only", `ota.rs:130`). An entry is valid iff `seq != 0xFFFFFFFF` **and**
//! `entry[28..32] == entry_crc(seq)`.
//!
//! Use [`entry_crc`] for every site. Its CRC span is `entry[0..4)` only — the marker fields
//! `[4..28)` (`seq_label`, `ota_state`) are **OUTSIDE** the CRC.
//!
//! ## Correction (task 9, bench-disproven)
//! An earlier revision of this module (commit `327620e`) claimed the span was `entry[0..28)`.
//! **That claim was WRONG.** It was a misdiagnosis: the bootloader-written factory entry
//! (seq=1) is valid over `[0..4)` and invalid over `[0..28)`, so every 28-byte entry we wrote was
//! silently rejected by the bootloader and it fell back to `ota_0`. `f115fcd` (span 4, seed 0) had
//! the right span but the wrong seed; `327620e` had the wrong span *and* seed. Both were rejected.
//! The two pinned vectors below are the contract.
//!
//! ## Why rewrite-not-mutate is still required
//! Mutating the marker does **not** invalidate the CRC (the marker is outside the span), but NOR
//! flash cannot clear the attempt-bitmap bits `1 -> 0` in place: a program operation can only flip
//! bits `1 -> 0` without an erase. Confirming (`status [8..12)` -> `0x00000000`) and recording an
//! attempt (clearing a bitmap byte in `[12..16)`) therefore still require a full sector cycle. The
//! machinery is unchanged and bench-proven on the write path:
//! 1. Read current 4KB otadata sector into RAM.
//! 2. Mutate marker field(s) in the buffer.
//! 3. Recompute the CRC with [`entry_crc`] (constant here — `seq` is untouched — recomputed anyway
//!    so no site can drift from the pinned rule).
//! 4. Erase the 4KB otadata sector.
//! 5. Rewrite the sector.
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

/// Host-safe reflected CRC-32 (IEEE 802.3 polynomial `0xEDB88320`) with a raw initial register
/// value and a `~0` final XOR — the zlib/PKZIP convention.
///
/// `crc32_le_compat(init, data)` == `zlib.crc32(data, init ^ 0xFFFF_FFFF)`, i.e. a raw
/// initial value of `0xFFFF_FFFF` (the bootloader seed) is expressed as `init = 0` here.
///
/// Pinned test vectors: `crc32_le_compat(0, &[0x01, 0x00, 0x00, 0x00]) == 0x4743989A`,
/// `crc32_le_compat(0, &[0x02, 0x00, 0x00, 0x00]) == 0x55F63774`.
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

/// Bootloader-compatible CRC32 for a 32-byte otadata entry.
///
/// Reflected CRC-32 over the 4 little-endian `seq` bytes (`entry[0..4)`) seeded with `0xFFFFFFFF`.
///
/// This is the single source of truth for the entry CRC at `entry[28..32)`. Every construction site
/// (`on_end`, [`rollback_entry_32`]) and every rewrite path (`confirm`, `record_attempt`) plus both
/// validity decoders (`boot_check`, `current_seq`) MUST go through this helper so no site can drift
/// from the bootloader's rule.
///
/// Equivalent to `zlib.crc32(struct.pack('<I', seq), 0xFFFFFFFF)` and to the C bootloader's
/// `esp_rom_crc32_le(UINT32_MAX, &ota_seq, 4)`.
///
/// # Pinned vectors (bench-verified)
///
/// | `seq` | CRC32       | source                                    |
/// |-------|-------------|-------------------------------------------|
/// | `1`   | `0x4743989A`| bootloader-written factory otadata entry   |
/// | `2`   | `0x55F63774`| python brute-force cross-check            |
///
/// A stored CRC that does not match this value (or a `seq` of `0xFFFFFFFF`) means the bootloader
/// rejects the entry and falls back to the other otadata sector.
pub fn entry_crc(seq: u32) -> u32 {
    crc32_le_compat(0, &seq.to_le_bytes())
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
/// The ESP-IDF bootloader picks the slot from the entry sequence number alone:
/// `boot_index = (ota_seq - 1) % app_count`, and `app_count` is 2. **Which sector the entry lives
/// in is irrelevant** — the bootloader scans both otadata sectors, keeps the highest valid `seq`,
/// and derives the slot from that. A rollback therefore only works if the new `seq` lands on the
/// *opposite* parity from the one currently running:
///
/// ```text
/// seq = max + 1  ->  (seq - 1) % 2 =  max % 2  !=  (max - 1) % 2  = running slot
/// ```
///
/// A `+2` bump preserves parity and is therefore a NO-OP rollback.
///
/// # Why +2 was wrong (bench-proven, task-7 drill)
///
/// The old `max_seq + 2` preserved parity, so the "rollback" entry resolved to the same slot as
/// the broken image. Measured on the door board: after 3 probation attempts, `write_rollback`
/// wrote `seq = 6` (from `max_seq = 4`); `boot_index = (6 - 1) % 2 = 1` → `ota_1` — the same
/// `ota_1` that had just failed three times. The board re-booted the broken build marker-free, so
/// it came up as a plain Normal boot with no probation left to rescue it, and stayed permanently
/// offline. `+1` also matches ESP-IDF's own convention: `ota_seq` increments by exactly 1 per
/// otadata update.
///
/// - `seq` = current_max_seq + 1 (LE at [0..4)) — parity-flipping, see above
/// - `seq_label` [4..24) ALL 0xFF (marker-free: prevents re-probating known-good old image)
/// - `ota_state` [24..28) = 2u32 LE (VALID)
/// - `crc` [28..32) = [`entry_crc`] of the `seq` word, LE — CRC span is [0..4) ONLY
pub fn rollback_entry_32(current_max_seq: u32) -> [u8; 32] {
    let mut entry = [0xFFu8; 32];
    // +1 (never +2): the bootloader maps seq -> slot as (seq - 1) % 2, so an odd step flips the
    // slot and an even step re-selects the running one. See the doc comment for the bench proof.
    let next_seq = current_max_seq.wrapping_add(1);
    entry[0..4].copy_from_slice(&next_seq.to_le_bytes());
    // bytes [4..24) stay 0xFF (marker-free)
    entry[24..28].copy_from_slice(&2u32.to_le_bytes());
    let crc = entry_crc(next_seq);
    entry[28..32].copy_from_slice(&crc.to_le_bytes());
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

    /// Pinned benchmark vectors for the bootloader entry CRC (task 9).
    ///
    /// seq=1 -> 0x4743989A is the bootloader-written factory otadata entry, captured from
    /// live flash. seq=2 -> 0x55F63774 is the python brute-force cross-check.
    /// Both must be reproduced by the single shared `entry_crc` helper.
    #[test]
    fn test_entry_crc_pinned_vectors() {
        assert_eq!(
            entry_crc(1),
            0x4743_989A,
            "seq=1 (bootloader-written factory entry)"
        );
        assert_eq!(entry_crc(2), 0x55F6_3774, "seq=2 (python cross-check)");
    }

    /// Pins the `crc32_le_compat` convention: a raw initial register value of 0 with a
    /// `~0` final XOR, i.e. `zlib.crc32(data, 0xFFFFFFFF)`. The bootloader seed
    /// (`0xFFFFFFFF`) is expressed as `init = 0` on this API.
    #[test]
    fn test_crc32_le_compat_init_convention() {
        assert_eq!(crc32_le_compat(0, &[0x01, 0x00, 0x00, 0x00]), 0x4743_989A);
        assert_eq!(crc32_le_compat(0, &[0x02, 0x00, 0x00, 0x00]), 0x55F6_3774);
        // Seeding the raw register with 0xFFFFFFFF instead of 0 yields the complementary
        // (wrong) value — this is exactly the bug that f115fcd shipped and 327620e repeated.
        assert_ne!(
            crc32_le_compat(0xFFFF_FFFF, &[0x01, 0x00, 0x00, 0x00]),
            0x4743_989A
        );
    }

    /// The entry CRC depends on the seq word alone — marker and state fields must not
    /// perturb it. This is the span fix: the 28-byte rule was disproven on the bench.
    #[test]
    fn test_entry_crc_spans_only_seq_word() {
        let mut entry = [0xFFu8; 32];
        entry[0..4].copy_from_slice(&7u32.to_le_bytes());
        let before = entry_crc(7);

        stamp_pending_marker(&mut entry);
        assert_eq!(
            entry_crc(7),
            before,
            "marker stamp must not affect the entry CRC"
        );

        entry[24..28].copy_from_slice(&2u32.to_le_bytes()); // ota_state VALID
        assert_eq!(
            entry_crc(7),
            before,
            "ota_state must not affect the entry CRC (span is [0..4) only)"
        );

        entry[12..16].copy_from_slice(&next_bitmap([0xFF; 4]).unwrap()); // attempt 1
        assert_eq!(
            entry_crc(7),
            before,
            "attempt bitmap must not affect the entry CRC"
        );
    }

    #[test]
    fn test_entry_round_trip_validity_decode() {
        // Build exactly the way `on_end` builds the new-slot entry.
        let seq = 2u32;
        let mut entry = [0xFFu8; 32];
        entry[0..4].copy_from_slice(&seq.to_le_bytes());
        stamp_pending_marker(&mut entry);
        entry[24..28].copy_from_slice(&2u32.to_le_bytes()); // VALID
        entry[28..32].copy_from_slice(&entry_crc(seq).to_le_bytes());

        // Bootloader validity rule: seq != 0xFFFFFFFF && stored == entry_crc(seq).
        let stored = u32::from_le_bytes(entry[28..32].try_into().unwrap());
        let decoded_seq = u32::from_le_bytes(entry[0..4].try_into().unwrap());
        assert_ne!(decoded_seq, 0xFFFF_FFFF);
        assert_eq!(stored, entry_crc(decoded_seq));
        assert_eq!(stored, 0x55F6_3774);

        // Marker still decodes through the same entry.
        assert_eq!(decode_marker(&entry), MarkerState::Pending { attempts: 0 });

        // A 28-byte-span CRC (the 327620e bug) must NOT validate against this rule.
        let mut wrong = entry;
        wrong[28..32].copy_from_slice(&crc32_le_compat(0, &entry[0..28]).to_le_bytes());
        let wrong_stored = u32::from_le_bytes(wrong[28..32].try_into().unwrap());
        assert_ne!(
            wrong_stored,
            entry_crc(decoded_seq),
            "28-byte CRC must not pass seq-only bootloader validity"
        );
    }

    #[test]
    fn test_round_trip_encode_decode() {
        let mut entry = [0xFFu8; 32];
        entry[0..4].copy_from_slice(&2u32.to_le_bytes());
        stamp_pending_marker(&mut entry);
        entry[12..16].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF]);
        entry[24..28].copy_from_slice(&2u32.to_le_bytes());
        let crc = entry_crc(2);
        entry[28..32].copy_from_slice(&crc.to_le_bytes());

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
        assert_eq!(seq, 2, "seq is max+1 so the slot parity flips");
        assert_eq!(&entry[4..24], &[0xFFu8; 20]);
        assert_eq!(decode_marker(&entry), MarkerState::Absent);
        let ota_state = u32::from_le_bytes(entry[24..28].try_into().unwrap());
        assert_eq!(ota_state, 2);
        let crc = u32::from_le_bytes(entry[28..32].try_into().unwrap());
        assert_eq!(crc, entry_crc(seq));

        // The CRC must be derived from the WRAPPED seq, never from the pre-wrap input.
        let sentinel_entry = rollback_entry_32(0xFFFF_FFFE);
        assert_eq!(
            &sentinel_entry[0..4],
            &0xFFFF_FFFFu32.to_le_bytes(),
            "0xFFFFFFFE + 1 should wrap to the 0xFFFFFFFF sentinel"
        );
        let crc_sentinel = u32::from_le_bytes(sentinel_entry[28..32].try_into().unwrap());
        assert_eq!(crc_sentinel, entry_crc(0xFFFF_FFFF));

        // 0xFFFFFFFF is not a reachable input (validity requires seq != 0xFFFFFFFF), but the
        // helper must stay total and self-consistent across the wrap regardless.
        let wrap_entry = rollback_entry_32(0xFFFF_FFFF);
        assert_eq!(&wrap_entry[0..4], &0u32.to_le_bytes());
        let crc_wrap = u32::from_le_bytes(wrap_entry[28..32].try_into().unwrap());
        assert_eq!(crc_wrap, entry_crc(0), "CRC tracks the wrapped seq");
    }

    /// The whole point of `+1`: the bootloader maps `seq -> slot` as `(seq - 1) % 2`, so a
    /// rollback entry MUST land on the opposite parity from the slot that just failed.
    ///
    /// The old `+2` produced the SAME parity and therefore re-booted the broken image
    /// (bench-proven in the task-7 drill: `max_seq = 4` -> `seq = 6` -> `boot_index = 1` ->
    /// `ota_1`, the same broken slot, marker-free, permanently offline).
    #[test]
    fn test_rollback_entry_flips_slot_parity() {
        // Concrete vectors from the task-7 bench failure, plus the mirrored pair.
        for (max_seq, want_seq, want_slot) in [(4u32, 5u32, 0u32), (3u32, 4u32, 1u32)] {
            let entry = rollback_entry_32(max_seq);
            let seq = u32::from_le_bytes(entry[0..4].try_into().unwrap());
            assert_eq!(seq, want_seq, "max_seq={max_seq} must produce seq={want_seq}");

            // The rule the bootloader actually applies: boot_index = (ota_seq - 1) % 2.
            let boot_index = (seq - 1) % 2;
            let running_slot = (max_seq - 1) % 2;
            assert_eq!(boot_index, want_slot, "max_seq={max_seq} -> ota_{want_slot}");
            assert_ne!(
                boot_index,
                running_slot,
                "max_seq={max_seq}: rollback entry must select the OTHER slot"
            );

            // The old +2 behaviour must be impossible: it preserves parity.
            assert_eq!((max_seq.wrapping_add(2) - 1) % 2, running_slot);
        }

        // Sweep a wider range: the parity invariant holds for every reachable seq, not just
        // the two pinned vectors.
        for max_seq in 1u32..64 {
            let entry = rollback_entry_32(max_seq);
            let seq = u32::from_le_bytes(entry[0..4].try_into().unwrap());
            assert_ne!(
                (seq - 1) % 2,
                (max_seq - 1) % 2,
                "max_seq={max_seq} did not flip the slot parity"
            );
            // ...and the entry still satisfies bootloader validity, or it would be skipped.
            assert_ne!(seq, 0xFFFF_FFFF);
            assert_eq!(
                u32::from_le_bytes(entry[28..32].try_into().unwrap()),
                entry_crc(seq),
                "max_seq={max_seq}: CRC must cover the new seq so the bootloader accepts it"
            );
        }
    }

    /// Marker mutation sits OUTSIDE the CRC span, so it does not invalidate the entry —
    /// the 28-byte-span premise this test used to encode was disproven on the bench.
    /// The erase+rewrite cycle is still required (NOR cannot clear bitmap bits in place),
    /// but the recomputed CRC is byte-identical to the stored one.
    #[test]
    fn test_seq_only_crc_survives_marker_mutation() {
        let seq = 3u32;
        let mut entry = [0xFFu8; 32];
        entry[0..4].copy_from_slice(&seq.to_le_bytes());
        stamp_pending_marker(&mut entry);
        entry[24..28].copy_from_slice(&2u32.to_le_bytes());
        let crc = entry_crc(seq);
        entry[28..32].copy_from_slice(&crc.to_le_bytes());

        // Valid per the seq-only rule.
        assert_eq!(
            u32::from_le_bytes(entry[28..32].try_into().unwrap()),
            entry_crc(seq)
        );

        // Advance the attempt bitmap (in place, to model the buffer mutation).
        let bitmap_word: [u8; 4] = entry[12..16].try_into().unwrap();
        entry[12..16].copy_from_slice(&next_bitmap(bitmap_word).unwrap());

        // CRC is NOT stale: the marker lives outside the [0..4) span.
        assert_eq!(
            u32::from_le_bytes(entry[28..32].try_into().unwrap()),
            entry_crc(seq)
        );

        // A 28-byte-span CRC WOULD go stale — that was the bug fixed here.
        assert_ne!(
            u32::from_le_bytes(entry[28..32].try_into().unwrap()),
            crc32_le_compat(0, &entry[0..28])
        );

        // The rewrite path recomputes from seq and lands on the same bytes.
        let fresh_crc = entry_crc(u32::from_le_bytes(entry[0..4].try_into().unwrap()));
        entry[28..32].copy_from_slice(&fresh_crc.to_le_bytes());
        assert_eq!(
            u32::from_le_bytes(entry[28..32].try_into().unwrap()),
            entry_crc(seq)
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
