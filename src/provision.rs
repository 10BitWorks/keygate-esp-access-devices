//! NTAG 424 DNA provisioning primitives (host-testable).
//!
//! Pure secure-messaging building blocks for the provisioning sequence (todo 4):
//! AES-CBC helpers, `AuthenticateEV2First`, CommMode.MAC/FULL framing, and the
//! `ChangeKey` / `ChangeFileSettings` command builders. Transport is injected as
//! a closure (exactly like `ntag424::read_ndef_message`) so every routine is
//! unit-testable on the host with no `esp-hal` / `esp-radio` dependency.
//!
//! Algorithm reference: NXP NT4H2421Gx datasheet §9 (secure messaging) and the
//! pinned pylibsdm reference implementation
//! (`pylibsdm/tag/ntag424dna/tag.py`). Golden values are produced by
//! `tests/golden/gen_provision_goldens.py`, which drives pylibsdm's own
//! methods against a deterministic card stub.
//!
//! Command codes (datasheet Table 22 + pylibsdm const.py:10-20):
//!   AuthenticateEV2First  0x71 (Part 1 -> SW 91AF)
//!   AdditionalFrame       0xAF (Part 2 -> SW 9100)
//!   ChangeKey             0xC4 (CommMode.Full)
//!   ChangeFileSettings    0x5F (CommMode.Full)
//!
//! NOTE: the plan prose said "0x7A additional frame" and "change_file_settings
//! cmd 0x5C"; both are typos. The datasheet and the pinned pylibsdm reference
//! use 0xAF and 0x5F (0x5C is SetConfiguration). The golden tests enforce the
//! reference values.

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use heapless::Vec;

use crate::ntag424::{NdefError, aes_cmac, derive_session_keys, wrap_apdu};

/// AuthenticateEV2First Part 1 instruction (datasheet Table 22).
pub const AUTH_EV2_FIRST_INS: u8 = 0x71;
/// AuthenticateEV2First Part 2 / AdditionalFrame instruction (datasheet Table 22).
pub const ADDITIONAL_FRAME_INS: u8 = 0xAF;
/// ChangeKey instruction (datasheet Table 22, CommMode.Full).
pub const CHANGE_KEY_INS: u8 = 0xC4;
/// ChangeFileSettings instruction (datasheet Table 22, CommMode.Full).
pub const CHANGE_FILE_SETTINGS_INS: u8 = 0x5F;

const NULL_IV: [u8; 16] = [0u8; 16];

/// An authenticated secure-messaging session (AuthenticateEV2First).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    /// Transaction identifier (4 bytes) returned by the tag.
    pub ti: [u8; 4],
    /// Command counter; incremented after every MACed/FULL command.
    pub cmdctr: u16,
    /// Session encryption key (`KSesAuthENC`).
    pub k_enc: [u8; 16],
    /// Session MAC key (`KSesAuthMAC`).
    pub k_mac: [u8; 16],
}

/// Errors returned by the provisioning primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionError {
    /// The injected transport (exchange closure) failed.
    Transport(NdefError),
    /// The tag returned an unexpected ISO 7816 status word.
    Status(u8, u8),
    /// A response frame was shorter than the protocol requires.
    ShortResponse,
    /// The RndA mirrored back by the tag did not match the one we sent.
    RndaMismatch,
    /// A recomputed CMAC did not match the one presented.
    MacMismatch,
    /// A caller-provided output buffer was too small.
    BufferTooSmall,
}

impl From<NdefError> for ProvisionError {
    fn from(e: NdefError) -> Self {
        ProvisionError::Transport(e)
    }
}

// ---------------------------------------------------------------------------
// AES-128 CBC (single-block ECB for the IV derivation, CBC for payloads).
// ---------------------------------------------------------------------------

/// AES-128-CBC encrypt `buf` in place (length must be a multiple of 16).
fn cbc_encrypt_inplace(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    let cipher = Aes128::new_from_slice(key).expect("16-byte AES key");
    let mut prev = *iv;
    for chunk in buf.chunks_mut(16) {
        for i in 0..16 {
            chunk[i] ^= prev[i];
        }
        let mut block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(&mut block);
        prev.copy_from_slice(chunk);
    }
}

/// AES-128-CBC decrypt `buf` in place (length must be a multiple of 16).
fn cbc_decrypt_inplace(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    let cipher = Aes128::new_from_slice(key).expect("16-byte AES key");
    let mut prev = *iv;
    for chunk in buf.chunks_mut(16) {
        let mut ct = [0u8; 16];
        ct.copy_from_slice(chunk);
        let mut block = GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(&mut block);
        for i in 0..16 {
            chunk[i] ^= prev[i];
        }
        prev = ct;
    }
}

/// Encrypt a single 16-byte block (ECB); used for the IV derivation.
fn ecb_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let cipher = Aes128::new_from_slice(key).expect("16-byte AES key");
    let mut b = GenericArray::from_mut_slice(block);
    cipher.encrypt_block(&mut b);
}

fn rotate_left16(b: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[..15].copy_from_slice(&b[1..]);
    o[15] = b[0];
    o
}

fn rotate_right16(b: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[0] = b[15];
    o[1..].copy_from_slice(&b[..15]);
    o
}

fn truncate_cmac(full: &[u8; 16]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, o) in out.iter_mut().enumerate() {
        *o = full[2 * i + 1];
    }
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// ISO 7816-4 padding: append `0x80` then `0x00` up to the next 16-byte block.
fn iso7816_pad(data: &[u8], out: &mut [u8]) -> Result<usize, ProvisionError> {
    let padded = (data.len() / 16 + 1) * 16;
    if out.len() < padded {
        return Err(ProvisionError::BufferTooSmall);
    }
    out[..data.len()].copy_from_slice(data);
    out[data.len()] = 0x80;
    for b in out[data.len() + 1..padded].iter_mut() {
        *b = 0x00;
    }
    Ok(padded)
}

// ---------------------------------------------------------------------------
// Secure messaging primitives
// ---------------------------------------------------------------------------

/// Derive `IVc` (`0xA5 0x5A ‖ TI ‖ CmdCtr_le ‖ 8×00`, AES-ECB under `K_enc`).
pub fn iv_for_enc(session: &Session) -> [u8; 16] {
    iv_for(session, [0xA5, 0x5A])
}

/// Derive `IVr` (`0x5A 0xA5 ‖ TI ‖ CmdCtr_le ‖ 8×00`, AES-ECB under `K_enc`).
pub fn iv_for_dec(session: &Session) -> [u8; 16] {
    iv_for(session, [0x5A, 0xA5])
}

fn iv_for(session: &Session, prefix: [u8; 2]) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0] = prefix[0];
    buf[1] = prefix[1];
    buf[2..6].copy_from_slice(&session.ti);
    buf[6..8].copy_from_slice(&session.cmdctr.to_le_bytes());
    ecb_encrypt_block(&session.k_enc, &mut buf);
    buf
}

/// CommMode.MAC command MAC:
/// `CMAC(K_mac, Cmd ‖ CmdCtr_le ‖ TI ‖ Header ‖ Data)[1::2]`.
pub fn command_mac(session: &Session, cmd: u8, hdr: &[u8], data: &[u8]) -> [u8; 8] {
    let mut input = Vec::<u8, 160>::new();
    let _ = input.push(cmd);
    let _ = input.extend_from_slice(&session.cmdctr.to_le_bytes());
    let _ = input.extend_from_slice(&session.ti);
    let _ = input.extend_from_slice(hdr);
    let _ = input.extend_from_slice(data);
    truncate_cmac(&aes_cmac(&session.k_mac, &input))
}

/// CommMode.Full wrap: ISO 7816 pad then AES-CBC encrypt with `IVc`.
///
/// Returns the ciphertext length written into `out`.
pub fn full_wrap(session: &Session, data: &[u8], out: &mut [u8]) -> Result<usize, ProvisionError> {
    let n = iso7816_pad(data, out)?;
    let iv = iv_for_enc(session);
    cbc_encrypt_inplace(&session.k_enc, &iv, &mut out[..n]);
    Ok(n)
}

/// CommMode.Full unwrap: AES-CBC decrypt with `IVr`, then strip ISO 7816 padding.
///
/// Returns the plaintext length written into `out`.
pub fn full_unwrap(session: &Session, data: &[u8], out: &mut [u8]) -> Result<usize, ProvisionError> {
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(ProvisionError::ShortResponse);
    }
    if out.len() < data.len() {
        return Err(ProvisionError::BufferTooSmall);
    }
    out[..data.len()].copy_from_slice(data);
    let iv = iv_for_dec(session);
    cbc_decrypt_inplace(&session.k_enc, &iv, &mut out[..data.len()]);

    let mut end = data.len();
    while end > 0 && out[end - 1] == 0x00 {
        end -= 1;
    }
    if end == 0 || out[end - 1] != 0x80 {
        return Err(ProvisionError::ShortResponse);
    }
    Ok(end - 1)
}

/// Build the full CommMode.Full data field for `ChangeKey`:
/// `Hdr(KeyNr) ‖ FullEncrypt(NewKey ‖ KeyVersion) ‖ CMAC`. Advances
/// `session.cmdctr`.
///
/// The returned bytes are the exact APDU data field pylibsdm puts on the wire
/// (`send_command_full(command, hdr, data)` → `hdr ‖ encrypted ‖ cmac`), so the
/// caller can pass them straight to `ntag424::wrap_apdu(CHANGE_KEY_INS, …)`.
pub fn change_key(
    session: &mut Session,
    key_nr: u8,
    new_key: &[u8; 16],
    version: u8,
    out: &mut [u8],
) -> Result<usize, ProvisionError> {
    let mut plain = [0u8; 17];
    plain[..16].copy_from_slice(new_key);
    plain[16] = version;

    if out.len() < 1 + 16 + 8 {
        return Err(ProvisionError::BufferTooSmall);
    }
    let hdr = [key_nr];
    out[0] = key_nr;
    let enc_len = full_wrap(session, &plain, &mut out[1..])?;
    let mac = command_mac(session, CHANGE_KEY_INS, &hdr, &out[1..1 + enc_len]);
    out[1 + enc_len..1 + enc_len + 8].copy_from_slice(&mac);
    session.cmdctr = session.cmdctr.wrapping_add(1);
    Ok(1 + enc_len + 8)
}

/// Build the full CommMode.Full data field for `ChangeFileSettings`:
/// `Hdr(FileNr) ‖ FullEncrypt(SettingsBytes) ‖ CMAC`. Advances
/// `session.cmdctr`.
///
/// Same wire contract as [`change_key`] (matches pylibsdm `send_command_full`).
pub fn change_file_settings(
    session: &mut Session,
    file_nr: u8,
    settings: &[u8],
    out: &mut [u8],
) -> Result<usize, ProvisionError> {
    if out.len() < 1 + 16 + 8 {
        return Err(ProvisionError::BufferTooSmall);
    }
    let hdr = [file_nr];
    out[0] = file_nr;
    let enc_len = full_wrap(session, settings, &mut out[1..])?;
    let mac = command_mac(session, CHANGE_FILE_SETTINGS_INS, &hdr, &out[1..1 + enc_len]);
    out[1 + enc_len..1 + enc_len + 8].copy_from_slice(&mac);
    session.cmdctr = session.cmdctr.wrapping_add(1);
    Ok(1 + enc_len + 8)
}

/// Verify the trailing 8-byte CMAC of a CommMode.MAC frame against `session`.
///
/// The frame is `body ‖ CMAC`; the CMAC is recomputed over `body` and compared
/// in constant time.
pub fn verify_command_mac(
    session: &Session,
    ins: u8,
    hdr: &[u8],
    frame: &[u8],
) -> Result<(), ProvisionError> {
    if frame.len() < 8 {
        return Err(ProvisionError::ShortResponse);
    }
    let (body, received) = frame.split_at(frame.len() - 8);
    let expected = command_mac(session, ins, hdr, body);
    if constant_time_eq(&expected, received) {
        Ok(())
    } else {
        Err(ProvisionError::MacMismatch)
    }
}

/// Check an ISO 7816 status word against an expected `(SW1, SW2)`.
fn check_status(resp: &[u8], sw1: u8, sw2: u8) -> Result<(), ProvisionError> {
    if resp.len() < 2 {
        return Err(ProvisionError::ShortResponse);
    }
    let (a, b) = (resp[resp.len() - 2], resp[resp.len() - 1]);
    if a == sw1 && b == sw2 {
        Ok(())
    } else {
        Err(ProvisionError::Status(a, b))
    }
}

/// Run `AuthenticateEV2First` (Part 1 + Part 2) and establish a session.
///
/// `rnda` is the 16-byte PCD nonce (the node supplies it from its RNG); it is a
/// parameter so the handshake is deterministic and host-testable. `exchange`
/// sends one APDU and returns `response ‖ SW1 SW2`.
pub fn authenticate_ev2_first<F>(
    key: &[u8; 16],
    key_nr: u8,
    rnda: &[u8; 16],
    exchange: &mut F,
) -> Result<Session, ProvisionError>
where
    F: FnMut(&[u8], &mut [u8]) -> Result<usize, NdefError>,
{
    // --- Part 1: send key number (u16 LE), expect SW 91AF + E(RndB). ---
    let key_nr_le = (key_nr as u16).to_le_bytes();
    let (apdu, n) = wrap_apdu(AUTH_EV2_FIRST_INS, &key_nr_le);
    let mut resp = [0u8; 258];
    let rlen = exchange(&apdu[..n], &mut resp)?;
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
    let rlen = exchange(&apdu[..n], &mut resp)?;
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
mod provision_tests {
    use super::*;

    fn dec(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }

    fn h<const N: usize>(s: &str) -> [u8; N] {
        let b = s.as_bytes();
        let mut o = [0u8; N];
        for (i, x) in o.iter_mut().enumerate() {
            *x = (dec(b[2 * i]) << 4) | dec(b[2 * i + 1]);
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
    const IVC0: &str = "ba96939ab9daa41bc9910456ca41e501";
    const IVR0: &str = "c04984c676e20700328d78c4f2c82e0d";
    const NEWKEY: &str = "aabbccddeeff00112233445566778899";
    // Full CommMode.Full wire frames (what pylibsdm puts in the APDU data
    // field): Hdr ‖ FullEncrypt(...) ‖ CMAC, 41 bytes each.
    //   ChangeKey:         Hdr=0x01 (key nr 1)
    //   ChangeFileSettings: Hdr=0x02 (file nr 2)
    const CK_FRAME: &str = "01b101d4c46ba62a380b5068cac87a69bb269a880d1ef7576389b9c3b873a5ee6d28475dd56ed71d9a";
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
        let session = authenticate_ev2_first(&key, 0, &rnda, &mut card).expect("auth");
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
        let mut mock = |apdu: &[u8], out: &mut [u8]| -> Result<usize, NdefError> {
            if apdu[1] == ADDITIONAL_FRAME_INS {
                let lc = apdu[4] as usize;
                part2.copy_from_slice(&apdu[5..5 + lc]);
            }
            card(apdu, out)
        };
        let _ = authenticate_ev2_first(&key, 0, &rnda, &mut mock).expect("auth");
        drop(mock);
        assert_eq!(part2, h::<32>(PART2));
    }

    #[test]
    fn test_iv_for_enc_and_dec() {
        let session = golden_session();
        assert_eq!(iv_for_enc(&session), h::<16>(IVC0));
        assert_eq!(iv_for_dec(&session), h::<16>(IVR0));
    }

    #[test]
    fn test_full_wrap_matches_change_key_golden() {
        // The FIRST CommMode.Full frame of the golden sequence (ChangeKey,
        // cmdctr 0) pins full_wrap's ISO7816 pad + IVc encryption exactly.
        let session = golden_session();
        let mut plain = [0u8; 17];
        plain[..16].copy_from_slice(&h::<16>(NEWKEY));
        plain[16] = 1; // version
        let mut ct = [0u8; 48];
        let n = full_wrap(&session, &plain, &mut ct).expect("wrap");
        assert_eq!(n, 32);
        // CK_FRAME = Hdr(0x01) ‖ FullEncrypt(NewKey‖ver) ‖ CMAC.
        let frame = h::<41>(CK_FRAME);
        assert_eq!(&ct[..n], &frame[1..33]);
    }

    #[test]
    fn test_full_unwrap_roundtrip_with_ivr() {
        // Responses are encrypted with IVr (PICC->PCD direction, prefix
        // 5A A5) — NOT IVc (that prefix is PCD->PICC only). So the correct
        // round-trip pairs `full_unwrap` with an IVr-encrypted payload.
        let session = golden_session();
        let plain = b"keygate provision payload";
        let mut ct = [0u8; 48];
        let n = iso7816_pad(plain, &mut ct).expect("pad");
        let iv = iv_for_dec(&session);
        cbc_encrypt_inplace(&session.k_enc, &iv, &mut ct[..n]);
        let mut back = [0u8; 48];
        let m = full_unwrap(&session, &ct[..n], &mut back).expect("unwrap");
        assert_eq!(&back[..m], plain);
    }

    #[test]
    fn test_command_mac_matches_change_key_reference() {
        let session = golden_session();
        // CK_FRAME = Hdr(0x01) ‖ FullEncrypt(NewKey‖ver) ‖ CMAC.
        // The MAC covers INS ‖ cmdctr_le ‖ TI ‖ Hdr ‖ encrypted-body.
        let frame = h::<41>(CK_FRAME);
        let enc = &frame[1..33];
        let mac = command_mac(&session, CHANGE_KEY_INS, &[1u8], enc);
        assert_eq!(&mac[..], &frame[33..41]);
    }

    #[test]
    fn test_change_key_frame() {
        let mut session = golden_session();
        let mut out = [0u8; 64];
        let n = change_key(&mut session, 1, &h(NEWKEY), 1, &mut out).expect("change_key");
        assert_eq!(n, 41);
        assert_eq!(&out[..n], &h::<41>(CK_FRAME)[..]);
        assert_eq!(session.cmdctr, 1);
    }

    #[test]
    fn test_change_file_settings_frame() {
        let mut session = golden_session();
        let mut scratch = [0u8; 64];
        // Advance the counter exactly as the reference sequence does.
        let _ = change_key(&mut session, 1, &h(NEWKEY), 1, &mut scratch).expect("change_key");
        assert_eq!(session.cmdctr, 1);

        let mut out = [0u8; 64];
        let n = change_file_settings(&mut session, 2, &h::<20>(SETTINGS), &mut out)
            .expect("change_file_settings");
        assert_eq!(n, 41);
        assert_eq!(&out[..n], &h::<41>(CFS_FRAME)[..]);
        assert_eq!(session.cmdctr, 2);
    }

    #[test]
    fn test_verify_command_mac_accepts_and_rejects_tampered() {
        let session = golden_session();
        // CK_FRAME carries its Hdr byte up front; verify_command_mac expects
        // body ‖ CMAC with the header passed separately, so slice it off.
        let full = h::<41>(CK_FRAME);
        let frame = &full[1..]; // enc ‖ cmac (40 bytes)

        // Correct frame verifies.
        assert_eq!(
            verify_command_mac(&session, CHANGE_KEY_INS, &[1u8], frame),
            Ok(())
        );

        // Flip one bit of the trailing CMAC -> MacMismatch (tamper evidence).
        let mut tampered = [0u8; 40];
        tampered.copy_from_slice(frame);
        tampered[39] ^= 0x01;
        assert_eq!(
            verify_command_mac(&session, CHANGE_KEY_INS, &[1u8], &tampered),
            Err(ProvisionError::MacMismatch)
        );
    }
}
