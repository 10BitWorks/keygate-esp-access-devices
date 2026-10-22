//! Authenticated secure-messaging session (`AuthenticateEV2First`).
//!
//! Establishes the §9.1 session (`TI`, `CmdCtr`, `KSesAuthENC`, `KSesAuthMAC`)
//! and verifies/advances the command counter on response MACs.

use crate::ntag424::{derive_session_keys, wrap_apdu, NdefError};
use crate::provision::crypto::{
    cbc_decrypt_inplace, cbc_encrypt_inplace, check_status, constant_time_eq, response_mac,
    rotate_left16, rotate_right16, NULL_IV,
};
use crate::provision::{ProvisionError, AUTH_EV2_FIRST_INS, ADDITIONAL_FRAME_INS};

/// An authenticated secure-messaging session (AuthenticateEV2First).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    /// Transaction identifier (4 bytes) returned by the tag.
    pub ti: [u8; 4],
    /// Command counter; advanced after every MACed/FULL command whose
    /// response MACt verified (§9.1.9).
    pub cmdctr: u16,
    /// Session encryption key (`KSesAuthENC`).
    pub k_enc: [u8; 16],
    /// Session MAC key (`KSesAuthMAC`).
    pub k_mac: [u8; 16],
}

/// Verify a response `MACt` and advance `CmdCtr` (§9.1.9).
///
/// `body` is the response data before `SW1SW2`. For `ChangeKey` (Case 1) and
/// `ChangeFileSettings` the PICC returns `MACt(8)` over empty response data
/// (AN12196 §5.16.1 Table 25 step 20), so `body` is exactly the 8-byte MACt.
/// The MAC input is `RC ‖ (CmdCtr+1)(LE) ‖ TI ‖ RespData` with `RC = 0x00`
/// (SW2 of the successful `91 00` status).
pub(crate) fn verify_response_mac(session: &mut Session, body: &[u8]) -> Result<(), ProvisionError> {
    if body.len() != 8 {
        return Err(ProvisionError::ShortResponse);
    }
    let expected = response_mac(session);
    if constant_time_eq(&expected, body) {
        session.cmdctr = session.cmdctr.wrapping_add(1);
        Ok(())
    } else {
        Err(ProvisionError::MacMismatch)
    }
}

/// Run `AuthenticateEV2First` (Part 1 + Part 2) and establish a session.
///
/// `rnda` is the 16-byte PCD nonce (the node supplies it from its RNG); it is a
/// parameter so the handshake is deterministic and host-testable. `exchange`
/// sends one APDU and returns `response ‖ SW1 SW2`. The transport is
/// `AsyncFnMut` so the node can drive it over an IRQ-waiting NFC transport;
/// on the default build the exchange closures never actually suspend.
pub(crate) async fn authenticate_ev2_first<F>(
    key: &[u8; 16],
    key_nr: u8,
    rnda: &[u8; 16],
    exchange: &mut F,
) -> Result<Session, ProvisionError>
where
    F: AsyncFnMut(&[u8], &mut [u8]) -> Result<usize, NdefError>,
{
    // --- Part 1: send key number (u16 LE), expect SW 91AF + E(RndB). ---
    let key_nr_le = (key_nr as u16).to_le_bytes();
    let (apdu, n) = wrap_apdu(AUTH_EV2_FIRST_INS, &key_nr_le);
    let mut resp = [0u8; 258];
    let rlen = exchange(&apdu[..n], &mut resp).await?;
    check_status(&resp[..rlen], 0x91, 0xAF)?;
    if rlen < 2 + 16 {
        return Err(ProvisionError::ShortResponse);
    }

    let mut rndb = [0u8; 16];
    rndb.copy_from_slice(&resp[..16]);
    cbc_decrypt_inplace(key, &NULL_IV, &mut rndb);

    // --- Part 2: send E(RndA ‖ RndB'), expect SW 9100 + E(TI ‖ RndA' ‖ caps). ---
    let mut plain = [0u8; 32];
    plain[..16].copy_from_slice(rnda);
    plain[16..].copy_from_slice(&rotate_left16(&rndb));
    cbc_encrypt_inplace(key, &NULL_IV, &mut plain);

    let (apdu, n) = wrap_apdu(ADDITIONAL_FRAME_INS, &plain);
    let rlen = exchange(&apdu[..n], &mut resp).await?;
    check_status(&resp[..rlen], 0x91, 0x00)?;
    if rlen < 2 + 32 {
        return Err(ProvisionError::ShortResponse);
    }

    let mut data = [0u8; 32];
    data.copy_from_slice(&resp[..32]);
    cbc_decrypt_inplace(key, &NULL_IV, &mut data);

    let mut ti = [0u8; 4];
    ti.copy_from_slice(&data[0..4]);

    let mut rnda_mirror = [0u8; 16];
    rnda_mirror.copy_from_slice(&data[4..20]);
    if rotate_right16(&rnda_mirror) != *rnda {
        return Err(ProvisionError::RndaMismatch);
    }

    let sk = derive_session_keys(key, rnda, &rndb);
    Ok(Session {
        ti,
        cmdctr: 0,
        k_enc: sk.enc,
        k_mac: sk.mac,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::block_on;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        let b = s.as_bytes();
        let mut o = [0u8; N];
        for (i, x) in o.iter_mut().enumerate() {
            let hi = (b[2 * i] as char).to_digit(16).expect("hex digit") as u8;
            let lo = (b[2 * i + 1] as char).to_digit(16).expect("hex digit") as u8;
            *x = (hi << 4) | lo;
        }
        o
    }

    // Golden fixtures pinned by tests/golden/gen_provision_goldens.py (pylibsdm).
    const KEY: &str = "000102030405060708090a0b0c0d0e0f";
    const RNDB: &str = "b9e2fc789b64bf237cccaa20ec7e6e48";
    const RNDA: &str = "13c5db8a5930439fc3def9a4c675360f";
    const TI: &str = "9d00c4df";
    const K_ENC: &str = "ed1b78dc9d39166756976e8563c76c20";
    const K_MAC: &str = "f5d34802bfb13df5468f98129fca002f";
    const PART2: &str =
        "c20c9babd6d89f66ed5a408ca16bfd9ed17e2194353efcae0c434b68e8602663";

    /// Card-side stub mirroring `CardStub` in the python generator.
    fn card(apdu: &[u8], out: &mut [u8]) -> Result<usize, NdefError> {
        let ins = apdu[1];
        let null = NULL_IV;
        match ins {
            0xA4 => {
                out[0] = 0x90;
                out[1] = 0x00;
                Ok(2)
            }
            0x71 => {
                let mut rndb: [u8; 16] = h(RNDB);
                cbc_encrypt_inplace(&h(KEY), &null, &mut rndb);
                out[..16].copy_from_slice(&rndb);
                out[16] = 0x91;
                out[17] = 0xAF;
                Ok(18)
            }
            0xAF => {
                let lc = apdu[4] as usize;
                let mut data = [0u8; 32];
                data.copy_from_slice(&apdu[5..5 + lc]);
                cbc_decrypt_inplace(&h(KEY), &null, &mut data);
                let mut rnda = [0u8; 16];
                rnda.copy_from_slice(&data[..16]);
                let mut rndb_p = [0u8; 16];
                rndb_p.copy_from_slice(&data[16..32]);
                assert_eq!(rndb_p, rotate_left16(&h(RNDB)), "RndB' mismatch");

                let mut resp = [0u8; 32];
                resp[0..4].copy_from_slice(&h::<4>(TI));
                resp[4..20].copy_from_slice(&rotate_left16(&rnda));
                cbc_encrypt_inplace(&h(KEY), &null, &mut resp);
                out[..32].copy_from_slice(&resp);
                out[32] = 0x91;
                out[33] = 0x00;
                Ok(34)
            }
            _ => Err(NdefError::Transport),
        }
    }

    #[test]
    fn test_authenticate_ev2_first_session_keys() {
        let key = h(KEY);
        let rnda = h(RNDA);
        let mut ex =
            async |apdu: &[u8], out: &mut [u8]| -> Result<usize, NdefError> { card(apdu, out) };
        let session = block_on(authenticate_ev2_first(&key, 0, &rnda, &mut ex)).expect("auth");
        assert_eq!(session.ti, h::<4>(TI));
        assert_eq!(session.k_enc, h::<16>(K_ENC));
        assert_eq!(session.k_mac, h::<16>(K_MAC));
        assert_eq!(session.cmdctr, 0);
    }

    #[test]
    fn test_authenticate_ev2_first_part2_payload() {
        let key = h(KEY);
        let rnda = h(RNDA);
        let mut part2 = [0u8; 32];
        let mut mock = async |apdu: &[u8], out: &mut [u8]| -> Result<usize, NdefError> {
            if apdu[1] == ADDITIONAL_FRAME_INS {
                let lc = apdu[4] as usize;
                part2.copy_from_slice(&apdu[5..5 + lc]);
            }
            card(apdu, out)
        };
        let _ = block_on(authenticate_ev2_first(&key, 0, &rnda, &mut mock)).expect("auth");
        drop(mock);
        assert_eq!(part2, h::<32>(PART2));
    }

    /// Response-MAC verification: correct MACt verifies and advances the
    /// counter; a tampered one fails and leaves the counter untouched.
    #[test]
    fn test_verify_response_mac_accepts_rejects_and_advances() {
        let mut session = Session {
            ti: [0x7A, 0x21, 0x08, 0x5E],
            cmdctr: 0,
            k_enc: [0u8; 16],
            k_mac: h("8248134A386E86EB7FAF54A52E536CB6"),
        };

        // Hand-compute the expected MACt over RC || (ctr+1) LE || TI.
        let expected = response_mac(&session);

        assert_eq!(verify_response_mac(&mut session, &expected), Ok(()));
        assert_eq!(session.cmdctr, 1);

        // Tampered MACt: rejected, counter stays put.
        let mut bad = expected;
        bad[0] ^= 0x01;
        assert_eq!(verify_response_mac(&mut session, &bad), Err(ProvisionError::MacMismatch));
        assert_eq!(session.cmdctr, 1);

        // Wrong length is a protocol error, not a MAC mismatch.
        assert_eq!(
            verify_response_mac(&mut session, &expected[..4]),
            Err(ProvisionError::ShortResponse)
        );
    }
}
