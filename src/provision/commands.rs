//! NTAG 424 DNA transport commands used by provisioning (host-testable).
//!
//! Instruction codes (NT4H2421Gx datasheet Table 22):
//!   AuthenticateEV2First  0x71 (Part 1 → SW 91AF)
//!   AdditionalFrame       0xAF (Part 2 → SW 9100)
//!   ChangeKey             0xC4 (CommMode.Full)
//!   ChangeFileSettings    0x5F (CommMode.MAC framing over the encrypted body)
//!
//! ISO/IEC 7816-4 mapped commands (§10.9):
//!   SELECT FILE    `00 A4` (DF name or file ID)
//!   READ BINARY   `00 B0` — **offset addressing only**; rejected with
//!                 `69 82` while an EV2 session is authenticated
//!   UPDATE BINARY `00 D6` — same constraints as READ BINARY
//!
//! The ISO commands are `CommMode.Plain` only: the chip rejects them with
//! `69 82` while an authenticated EV2 session is active, so the NDEF file
//! write runs BEFORE authentication (AN12196 §5.8.1 publishes exactly this
//! exchange: `00 D6 00 00 53 <83 bytes>`). SFI addressing (`P1[7]=1`) is NOT
//! used: the NTAG 424 DNA answers `6A 82` to it (observed on the bench card;
//! the `ntag424` crate reference sessions also always select the EF by file
//! ID and then address by offset).

use crate::ntag424::{wrap_apdu, NdefError, SELECT_NDEF_APP_APDU, SELECT_NDEF_FILE_02_APDU, READ_BINARY_INS};
use crate::provision::crypto::{check_status, command_mac, crc32_ieee, full_wrap};
use crate::provision::session::{verify_response_mac, Session};
use crate::provision::{ProvisionError, CHANGE_FILE_SETTINGS_INS, CHANGE_KEY_INS, UPDATE_BINARY_INS};

/// Max bytes per single ISO UPDATE BINARY APDU (`Lc` is one byte).
const ISO_UPDATE_CHUNK: usize = 255;

/// Select the NDEF application (DF name) and the NDEF file (file ID `E104`).
///
/// Runs unauthenticated. Re-selecting the application also **terminates an
/// active authenticated state** on the chip — callers rely on that to end
/// the session before the final ISO read-back.
///
/// The transport is `AsyncFnMut` so the node can drive InDataExchange over an
/// IRQ-waiting NFC transport; on the default build the exchange closures
/// never actually suspend.
pub(crate) async fn select_ndef<F>(exchange: &mut F) -> Result<(), ProvisionError>
where
    F: AsyncFnMut(&[u8], &mut [u8]) -> Result<usize, NdefError>,
{
    let mut resp = [0u8; 258];
    #[cfg(target_arch = "xtensa")]
    esp_println::println!("[prov-step] 1a: select NDEF app");
    let n = exchange(&SELECT_NDEF_APP_APDU, &mut resp).await?;
    #[cfg(target_arch = "xtensa")]
    esp_println::println!("[prov-step] 1a status: {:02x?}", &resp[..n]);
    check_status(&resp[..n], 0x90, 0x00)?;
    #[cfg(target_arch = "xtensa")]
    esp_println::println!("[prov-step] 1b: select NDEF file E104");
    let n = exchange(&SELECT_NDEF_FILE_02_APDU, &mut resp).await?;
    #[cfg(target_arch = "xtensa")]
    esp_println::println!("[prov-step] 1b status: {:02x?}", &resp[..n]);
    check_status(&resp[..n], 0x90, 0x00)?;
    Ok(())
}

/// ISO 7816-4 UPDATE BINARY, offset addressing (`00 D6 off_hi off_lo Lc data`).
///
/// `CommMode.Plain` only — the chip rejects the command with `69 82` while an
/// EV2 session is authenticated (§10.9.3), so this must run unauthenticated.
/// Splits at 255 bytes per APDU (`Lc` is one byte). Requires the NDEF file to
/// be selected and its write access to be free (factory default).
pub(crate) async fn iso_update_binary<F>(
    exchange: &mut F,
    offset: u16,
    data: &[u8],
) -> Result<(), ProvisionError>
where
    F: AsyncFnMut(&[u8], &mut [u8]) -> Result<usize, NdefError>,
{
    let mut resp = [0u8; 258];
    let mut written = 0;
    while written < data.len() {
        let chunk = (data.len() - written).min(ISO_UPDATE_CHUNK);
        let abs = offset as usize + written;
        if abs > 0x7FFF {
            return Err(ProvisionError::ShortResponse);
        }
        let mut apdu = [0u8; 5 + ISO_UPDATE_CHUNK];
        apdu[0] = 0x00;
        apdu[1] = UPDATE_BINARY_INS;
        apdu[2] = (abs >> 8) as u8;
        apdu[3] = (abs & 0xFF) as u8;
        apdu[4] = chunk as u8;
        apdu[5..5 + chunk].copy_from_slice(&data[written..written + chunk]);
        let rn = exchange(&apdu[..5 + chunk], &mut resp).await?;
        check_status(&resp[..rn], 0x90, 0x00)?;
        written += chunk;
    }
    Ok(())
}

/// Read the NDEF file (NLEN + message) into `file`; returns the NLEN value.
///
/// ISO READ BINARY with offset addressing on the selected EF — the same
/// proven path the idle reader uses. Must run unauthenticated (`69 82`
/// otherwise, §10.9.2).
pub(crate) async fn read_file<F>(
    exchange: &mut F,
    file: &mut [u8; 258],
) -> Result<usize, ProvisionError>
where
    F: AsyncFnMut(&[u8], &mut [u8]) -> Result<usize, NdefError>,
{
    let mut resp = [0u8; 258];
    // 1) Read the 2-byte NLEN at file offset 0.
    let n = exchange(&[0x00, READ_BINARY_INS, 0x00, 0x00, 0x02], &mut resp).await?;
    check_status(&resp[..n], 0x90, 0x00)?;
    if n < 4 {
        return Err(ProvisionError::ShortResponse);
    }
    let nlen = ((resp[0] as usize) << 8) | (resp[1] as usize);
    if nlen == 0 || 2 + nlen > file.len() {
        return Err(ProvisionError::ShortResponse);
    }
    // 2) Read the NDEF message body at file offset 2.
    let apdu = [0x00, READ_BINARY_INS, 0x00, 0x02, nlen as u8];
    let n = exchange(&apdu, &mut resp).await?;
    check_status(&resp[..n], 0x90, 0x00)?;
    let data = n.checked_sub(2).ok_or(ProvisionError::ShortResponse)?;
    if data < nlen {
        return Err(ProvisionError::ShortResponse);
    }
    // Reconstruct the full file view (NLEN ‖ message) so callers can index
    // with plain FILE offsets (byte 0 = first NLEN byte, per AN12196).
    file[0] = (nlen >> 8) as u8;
    file[1] = (nlen & 0xFF) as u8;
    file[2..2 + nlen].copy_from_slice(&resp[..nlen]);
    Ok(nlen)
}

/// Build the CommMode.Full data field for `ChangeKey` (Table 63):
/// - Key 0: `Hdr(KeyNr) ‖ FullEncrypt(NewKey ‖ KeyVersion)` (17 plaintext bytes).
/// - Key 1..=4: `Hdr(KeyNr) ‖ FullEncrypt((NewKey ⊕ OldKey) ‖ KeyVersion ‖
///   CRC32(NewKey))` (21 plaintext bytes).
///
/// Pure builder — does NOT advance `session.cmdctr`; the caller verifies the
/// response MACt (which advances) after the exchange succeeds.
pub(crate) fn change_key_frame(
    session: &Session,
    key_nr: u8,
    new_key: &[u8; 16],
    old_key: &[u8; 16],
    version: u8,
    out: &mut [u8],
) -> Result<usize, ProvisionError> {
    let mut plain = [0u8; 21];
    let plain_len = if key_nr == 0 {
        plain[..16].copy_from_slice(new_key);
        plain[16] = version;
        17
    } else {
        for i in 0..16 {
            plain[i] = new_key[i] ^ old_key[i];
        }
        plain[16] = version;
        let crc = crc32_ieee(new_key);
        plain[17..21].copy_from_slice(&crc.to_le_bytes());
        21
    };

    if out.len() < 1 + 32 + 8 {
        return Err(ProvisionError::BufferTooSmall);
    }
    let hdr = [key_nr];
    out[0] = key_nr;
    let enc_len = full_wrap(session, &plain[..plain_len], &mut out[1..])?;
    let mac = command_mac(session, CHANGE_KEY_INS, &hdr, &out[1..1 + enc_len]);
    out[1 + enc_len..1 + enc_len + 8].copy_from_slice(&mac);
    Ok(1 + enc_len + 8)
}

/// Build the CommMode.Full data field for `ChangeFileSettings`:
/// `Hdr(FileNr) ‖ FullEncrypt(SettingsBytes) ‖ CMAC` (§10.7.1).
///
/// Pure builder — does NOT advance `session.cmdctr` (see [`change_key_frame`]).
pub(crate) fn change_file_settings_frame(
    session: &Session,
    file_nr: u8,
    settings: &[u8],
    out: &mut [u8],
) -> Result<usize, ProvisionError> {
    if out.len() < 1 + 32 + 8 {
        return Err(ProvisionError::BufferTooSmall);
    }
    let hdr = [file_nr];
    out[0] = file_nr;
    let enc_len = full_wrap(session, settings, &mut out[1..])?;
    let mac = command_mac(session, CHANGE_FILE_SETTINGS_INS, &hdr, &out[1..1 + enc_len]);
    out[1 + enc_len..1 + enc_len + 8].copy_from_slice(&mac);
    Ok(1 + enc_len + 8)
}

/// Send a prepared CommMode.Full frame, check `91 00`, verify the trailing
/// response `MACt(8)` and advance `CmdCtr` (AN12196 §5.16.1 step 20).
pub(crate) async fn send_full_frame<F>(
    exchange: &mut F,
    session: &mut Session,
    ins: u8,
    frame: &[u8],
) -> Result<(), ProvisionError>
where
    F: AsyncFnMut(&[u8], &mut [u8]) -> Result<usize, NdefError>,
{
    let (apdu, len) = wrap_apdu(ins, frame);
    let mut resp = [0u8; 258];
    let rn = exchange(&apdu[..len], &mut resp).await?;
    check_status(&resp[..rn], 0x91, 0x00)?;
    // Response = MACt(8) ‖ SW1SW2 (no response data for ChangeKey Case 1 /
    // ChangeFileSettings).
    let body = rn.checked_sub(2).ok_or(ProvisionError::ShortResponse)?;
    verify_response_mac(session, &resp[..body])
}

/// `ChangeKey` end-to-end: build, send, verify response. Advances the
/// session counter only after the response MACt verifies.
pub(crate) async fn change_key<F>(
    exchange: &mut F,
    session: &mut Session,
    key_nr: u8,
    new_key: &[u8; 16],
    old_key: &[u8; 16],
    version: u8,
) -> Result<(), ProvisionError>
where
    F: AsyncFnMut(&[u8], &mut [u8]) -> Result<usize, NdefError>,
{
    let mut frame = [0u8; 64];
    let n = change_key_frame(session, key_nr, new_key, old_key, version, &mut frame)?;
    send_full_frame(exchange, session, CHANGE_KEY_INS, &frame[..n]).await
}

/// `ChangeFileSettings` end-to-end: build, send, verify response. Advances
/// the session counter only after the response MACt verifies.
pub(crate) async fn change_file_settings<F>(
    exchange: &mut F,
    session: &mut Session,
    file_nr: u8,
    settings: &[u8],
) -> Result<(), ProvisionError>
where
    F: AsyncFnMut(&[u8], &mut [u8]) -> Result<usize, NdefError>,
{
    let mut frame = [0u8; 64];
    let n = change_file_settings_frame(session, file_nr, settings, &mut frame)?;
    send_full_frame(exchange, session, CHANGE_FILE_SETTINGS_INS, &frame[..n]).await
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
    const TI: &str = "9d00c4df";
    const K_ENC: &str = "ed1b78dc9d39166756976e8563c76c20";
    const K_MAC: &str = "f5d34802bfb13df5468f98129fca002f";
    const NEWKEY: &str = "aabbccddeeff00112233445566778899";
    const SETTINGS: &str = "000102030405060708090a0b0c0d0e0f10111213";
    const CFS_FRAME: &str = "0231222f7c53531a2d9a4b32ad2805c020fba2b8c15dab3dd71fce2d7437b302c3c8544169fcf99161";

    fn golden_session() -> Session {
        Session {
            ti: h(TI),
            cmdctr: 0,
            k_enc: h(K_ENC),
            k_mac: h(K_MAC),
        }
    }

    #[test]
    fn test_change_key_frame() {
        let session = golden_session();
        let mut out = [0u8; 64];
        let n = change_key_frame(&session, 1, &h(NEWKEY), &[0u8; 16], 1, &mut out)
            .expect("change_key_frame");
        assert_eq!(n, 41); // hdr(1) ‖ ciphertext(32) ‖ MACt(8)
        // Hdr is the key number; the frame content (21-byte Case-1 plaintext
        // build, padding, IVc, command MAC) is pinned end-to-end by
        // `test_change_key_an12196_apdu_match` against AN12196 Table 25.
        assert_eq!(out[0], 1);
        // Pure builder: the counter advances only after response verification.
        assert_eq!(session.cmdctr, 0);
    }

    #[test]
    fn test_change_file_settings_frame() {
        // Advance the counter exactly as the reference sequence does (one
        // verified ChangeKey before ChangeFileSettings).
        let mut session = golden_session();
        session.cmdctr = 1;
        let mut out = [0u8; 64];
        let n = change_file_settings_frame(&session, 2, &h::<20>(SETTINGS), &mut out)
            .expect("change_file_settings_frame");
        assert_eq!(n, 41);
        assert_eq!(&out[..n], &h::<41>(CFS_FRAME)[..]);
        assert_eq!(session.cmdctr, 1);
    }

    /// AN12196 §5.16.1 Table 25: the full ChangeKey C-APDU at CmdCtr=2.
    #[test]
    fn test_change_key_an12196_apdu_match() {
        let session = Session {
            ti: h("7614281A"),
            cmdctr: 2, // CmdCtr starts at 2 in Step 14
            k_enc: h("4CF3CB41A22583A61E89B158D252FC53"),
            k_mac: h("5529860B2FC5FB6154B7F28361D30BF9"),
        };
        let new_key = h::<16>("F3847D627727ED3BC9C4CC050489B966");
        let old_key = [0u8; 16];
        let mut frame = [0u8; 64];
        let n = change_key_frame(&session, 2, &new_key, &old_key, 1, &mut frame)
            .expect("change_key_frame");
        assert_eq!(n, 41);
        let (apdu, len) = wrap_apdu(CHANGE_KEY_INS, &frame[..n]);
        let expected = h::<47>("90C4000029022CF362B7BF4311FF3BE1DAA295E8C68DE09050560D19B9E16C2393AE9CD1FAC75D0CE20BCD1D06E600");
        assert_eq!(&apdu[..len], &expected[..]);
    }

    /// `send_full_frame` verifies the response MACt and advances only on
    /// success; a bare `91 00` without the MACt is a protocol error.
    #[test]
    fn test_send_full_frame_verifies_response_mac() {
        use crate::provision::crypto::truncate_cmac;
        use crate::ntag424::aes_cmac;

        let mut session = golden_session();
        let frame = h::<41>(CFS_FRAME);

        // Correct response: MACt over RC || (ctr+1) LE || TI.
        let mut input = [0u8; 7];
        input[1..3].copy_from_slice(&1u16.to_le_bytes());
        input[3..7].copy_from_slice(&session.ti);
        let mact = truncate_cmac(&aes_cmac(&session.k_mac, &input));

        let mut good = async |apdu: &[u8], out: &mut [u8]| -> Result<usize, NdefError> {
            // 90 <INS> 00 00 29 <frame...> 00 — the frame's own hdr byte leads.
            assert_eq!(&apdu[..5], &[0x90, CHANGE_KEY_INS, 0x00, 0x00, 0x29]);
            assert_eq!(apdu[5], frame[0]);
            out[..8].copy_from_slice(&mact);
            out[8] = 0x91;
            out[9] = 0x00;
            Ok(10)
        };
        block_on(send_full_frame(
            &mut good,
            &mut session,
            CHANGE_KEY_INS,
            &frame,
        ))
        .expect("verified");
        assert_eq!(session.cmdctr, 1);

        // Bare 9100 (no MACt) is rejected.
        let mut bare = async |_apdu: &[u8], out: &mut [u8]| -> Result<usize, NdefError> {
            out[0] = 0x91;
            out[1] = 0x00;
            Ok(2)
        };
        let mut session2 = golden_session();
        assert_eq!(
            block_on(send_full_frame(
                &mut bare,
                &mut session2,
                CHANGE_KEY_INS,
                &frame
            )),
            Err(ProvisionError::ShortResponse)
        );
        assert_eq!(session2.cmdctr, 0);
    }

    /// `iso_update_binary` frames offset addressing exactly like the AN12196
    /// §5.8.1 Table 16 vector and chunks at 255 bytes.
    #[test]
    fn test_iso_update_binary_offset_addressing_and_chunking() {
        // 83-byte NDEF payload -> exactly the AN12196 example APDU.
        let data: [u8; 83] = core::array::from_fn(|i| i as u8);
        let mut first = async |apdu: &[u8], out: &mut [u8]| -> Result<usize, NdefError> {
            assert_eq!(apdu[..5], [0x00, UPDATE_BINARY_INS, 0x00, 0x00, 83]);
            assert_eq!(&apdu[5..], &data[..]);
            out[0] = 0x90;
            out[1] = 0x00;
            Ok(2)
        };
        block_on(iso_update_binary(&mut first, 0, &data)).expect("update ok");

        // 300 bytes -> chunks of 255 + 45 at offsets 0 and 255.
        let data: [u8; 300] = core::array::from_fn(|i| i as u8);
        let mut calls = 0usize;
        let mut chunked = async |apdu: &[u8], out: &mut [u8]| -> Result<usize, NdefError> {
            let (off, len) = match calls {
                0 => (0usize, 255usize),
                1 => (255usize, 45usize),
                _ => panic!("unexpected third call"),
            };
            assert_eq!(apdu[..5], [0x00, UPDATE_BINARY_INS, (off >> 8) as u8, off as u8, len as u8]);
            assert_eq!(&apdu[5..5 + len], &data[off..off + len]);
            calls += 1;
            out[0] = 0x90;
            out[1] = 0x00;
            Ok(2)
        };
        block_on(iso_update_binary(&mut chunked, 0, &data)).expect("chunked update ok");
        assert_eq!(calls, 2);
    }
}
