//! AES secure-messaging primitives for NTAG 424 DNA (host-testable).
//!
//! Pure building blocks: AES-128-CBC, the §9.1.4 command/response IVs,
//! CommMode.MAC command MACs, CommMode.Full wrap/decrypt, ISO 7816-4 (ISO/IEC
//! 9797-1 method 2) padding, and the Table 63 footnote `CRC32NK`.
//!
//! Golden values are pinned by `tests/golden/gen_provision_goldens.py`
//! (drives pylibsdm's own reference code) and by AN12196 worked examples
//! (§5.4, §5.16.1). Semantics cross-checked against the `ntag424` crate
//! v0.1.1 (codeberg.org/jannschu/ntag424), whose own tests replay hardware
//! captures.
//!
//! MAC input layout (§9.1.9): `Cmd ‖ CmdCtr(LE) ‖ TI ‖ CmdHeader ‖ CmdData`.
//! Truncated MACt = the odd-index (0-based) bytes of the 16-byte CMAC.

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

use crate::ntag424::aes_cmac;
use crate::provision::{ProvisionError, Session};

pub(crate) const NULL_IV: [u8; 16] = [0u8; 16];

/// AES-128-CBC encrypt `buf` in place (length must be a multiple of 16).
pub(crate) fn cbc_encrypt_inplace(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    let cipher = Aes128::new_from_slice(key).expect("16-byte AES key");
    let mut prev = *iv;
    for chunk in buf.chunks_mut(16) {
        for i in 0..16 {
            chunk[i] ^= prev[i];
        }
        let mut block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
        prev.copy_from_slice(chunk);
    }
}

/// AES-128-CBC decrypt `buf` in place (length must be a multiple of 16).
pub(crate) fn cbc_decrypt_inplace(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    let cipher = Aes128::new_from_slice(key).expect("16-byte AES key");
    let mut prev = *iv;
    for chunk in buf.chunks_mut(16) {
        let mut ct = [0u8; 16];
        ct.copy_from_slice(chunk);
        let mut block = GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(block);
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
    cipher.encrypt_block(b);
}

pub(crate) fn rotate_left16(b: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[..15].copy_from_slice(&b[1..]);
    o[15] = b[0];
    o
}

pub(crate) fn rotate_right16(b: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[0] = b[15];
    o[1..].copy_from_slice(&b[..15]);
    o
}

/// Truncated MACt: odd-index (0-based) bytes of the full 16-byte CMAC (§9.1.3).
pub(crate) fn truncate_cmac(full: &[u8; 16]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, o) in out.iter_mut().enumerate() {
        *o = full[2 * i + 1];
    }
    out
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// ISO/IEC 9797-1 method 2 padding: append `0x80` then `0x00` up to the next
/// 16-byte block. Returns the padded length written into `out`.
pub(crate) fn iso7816_pad(data: &[u8], out: &mut [u8]) -> Result<usize, ProvisionError> {
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

/// Strip ISO/IEC 9797-1 method 2 padding from `buf[..n]`; returns the
/// plaintext length.
#[cfg(test)]
fn strip_iso7816_pad(buf: &[u8], n: usize) -> Result<usize, ProvisionError> {
    let mut end = n;
    while end > 0 && buf[end - 1] == 0x00 {
        end -= 1;
    }
    if end == 0 || buf[end - 1] != 0x80 {
        return Err(ProvisionError::ShortResponse);
    }
    Ok(end - 1)
}

/// `IVc` = `E(K_enc, A5 5A ‖ TI ‖ CmdCtr_le ‖ 8×00)` (§9.1.4, command direction).
pub(crate) fn iv_for_enc(session: &Session) -> [u8; 16] {
    iv_for(session, [0xA5, 0x5A])
}

/// `IVr` = `E(K_enc, 5A A5 ‖ TI ‖ CmdCtr_le ‖ 8×00)` (§9.1.4, response direction).
///
/// Test-only: our provisioning flow sends no FULL-mode commands whose
/// *response* carries encrypted data, so nothing decrypts with `IVr` outside
/// the golden tests and the mock.
#[cfg(test)]
pub(crate) fn iv_for_dec(session: &Session) -> [u8; 16] {
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

/// Largest MAC input our commands produce: `Cmd ‖ CmdCtr ‖ TI ‖ header(1) ‖
/// ciphertext(32)` — ChangeKey / ChangeFileSettings frames (§9.1.9).
const MAC_INPUT_MAX: usize = 1 + 2 + 4 + 1 + 32;

/// CommMode.MAC command MAC: `CMAC(K_mac, Cmd ‖ CmdCtr_le ‖ TI ‖ Header ‖
/// Data)[1::2]`.
pub(crate) fn command_mac(session: &Session, cmd: u8, hdr: &[u8], data: &[u8]) -> [u8; 8] {
    let len = 7 + hdr.len() + data.len();
    // Invariant: our frames bound header (1 byte key/file number) and
    // ciphertext (32 bytes) well under MAC_INPUT_MAX.
    assert!(len <= MAC_INPUT_MAX, "MAC input overflow: {len} > {MAC_INPUT_MAX}");
    let mut buf = [0u8; MAC_INPUT_MAX];
    buf[0] = cmd;
    buf[1..3].copy_from_slice(&session.cmdctr.to_le_bytes());
    buf[3..7].copy_from_slice(&session.ti);
    buf[7..7 + hdr.len()].copy_from_slice(hdr);
    buf[7 + hdr.len()..len].copy_from_slice(data);
    truncate_cmac(&aes_cmac(&session.k_mac, &buf[..len]))
}

/// Response MACt over `RC ‖ (CmdCtr+1)(LE) ‖ TI ‖ RespData` (§9.1.9) with
/// `RC = 0x00` (SW2 of the successful `91 00` status) and empty response
/// data — the shape `ChangeKey` Case 1 and `ChangeFileSettings` return
/// (AN12196 §5.16.1 Table 25 step 20).
pub(crate) fn response_mac(session: &Session) -> [u8; 8] {
    let mut input = [0u8; 7];
    input[1..3].copy_from_slice(&session.cmdctr.wrapping_add(1).to_le_bytes());
    input[3..7].copy_from_slice(&session.ti);
    truncate_cmac(&aes_cmac(&session.k_mac, &input))
}

/// CommMode.Full wrap: ISO 7816 pad then AES-CBC encrypt with `IVc`.
/// Returns the ciphertext length written into `out`.
pub(crate) fn full_wrap(session: &Session, data: &[u8], out: &mut [u8]) -> Result<usize, ProvisionError> {
    let n = iso7816_pad(data, out)?;
    let iv = iv_for_enc(session);
    cbc_encrypt_inplace(&session.k_enc, &iv, &mut out[..n]);
    Ok(n)
}

/// CommMode.Full command decrypt: AES-CBC decrypt with `IVc`, then strip the
/// ISO 7816 padding. Returns the plaintext length written into `out`.
///
/// Test-only: only the tag model (mock) receives FULL-mode commands.
#[cfg(test)]
pub(crate) fn decrypt_command(session: &Session, data: &[u8], out: &mut [u8]) -> Result<usize, ProvisionError> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return Err(ProvisionError::ShortResponse);
    }
    if out.len() < data.len() {
        return Err(ProvisionError::BufferTooSmall);
    }
    out[..data.len()].copy_from_slice(data);
    let iv = iv_for_enc(session);
    cbc_decrypt_inplace(&session.k_enc, &iv, &mut out[..data.len()]);
    strip_iso7816_pad(out, data.len())
}

/// Compute the `CRC32NK` value per NT4H2421Gx Table 63 footnote [1] and
/// AN12196 §5.16.1.
///
/// Standard IEEE 802.3 32-bit CRC (polynomial 0xEDB88320) initialized to 0xFFFFFFFF,
/// but NXP convention omits the final one's-complement (the raw residue is written little-endian).
pub(crate) fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = -(crc as i32 & 1) as u32;
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc
}

/// Verify a trailing 8-byte MACt of a CommMode.MAC/Full command frame
/// (`body ‖ MACt`) against `session`.
///
/// Test-only: only the tag model (mock) verifies incoming command MACs.
#[cfg(test)]
pub(crate) fn verify_command_mac(
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
pub(crate) fn check_status(resp: &[u8], sw1: u8, sw2: u8) -> Result<(), ProvisionError> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    const IVC0: &str = "ba96939ab9daa41bc9910456ca41e501";
    const IVR0: &str = "c04984c676e20700328d78c4f2c82e0d";
    const NEWKEY: &str = "aabbccddeeff00112233445566778899";
    // ChangeKey wire frame (hdr ‖ FullEncrypt(NewKey‖ver) ‖ CMAC, 41 bytes).
    const CK_FRAME: &str = "01b101d4c46ba62a380b5068cac87a69bb269a880d1ef7576389b9c3b873a5ee6d28475dd56ed71d9a";
    const CHANGE_KEY_INS: u8 = crate::provision::CHANGE_KEY_INS;

    fn golden_session() -> Session {
        Session {
            ti: h(TI),
            cmdctr: 0,
            k_enc: h(K_ENC),
            k_mac: h(K_MAC),
        }
    }

    #[test]
    fn test_iv_for_enc_and_dec() {
        let session = golden_session();
        assert_eq!(iv_for_enc(&session), h::<16>(IVC0));
        assert_eq!(iv_for_dec(&session), h::<16>(IVR0));
    }

    /// The FIRST CommMode.Full frame of the golden sequence (ChangeKey, cmdctr 0)
    /// pins full_wrap's ISO7816 pad + IVc encryption exactly.
    #[test]
    fn test_full_wrap_matches_change_key_golden() {
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

    /// Round-trip: full_wrap then decrypt_command must recover the plaintext
    /// (command-direction IVc on both sides).
    #[test]
    fn test_decrypt_command_roundtrip() {
        let session = golden_session();
        let plain = b"keygate provision payload";
        let mut ct = [0u8; 48];
        let n = full_wrap(&session, plain, &mut ct).expect("wrap");
        let mut back = [0u8; 48];
        let m = decrypt_command(&session, &ct[..n], &mut back).expect("decrypt");
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

    #[test]
    fn test_crc32nk_matches_an12196_case1_vector() {
        let new_key = h::<16>("F3847D627727ED3BC9C4CC050489B966");
        // AN12196 §5.16.1 Table 25 Step 7: CRC32(NewKey) = 789DFADC (little-endian bytes)
        assert_eq!(crc32_ieee(&new_key).to_le_bytes(), h::<4>("789DFADC"));
    }

    #[test]
    fn test_iso7816_pad_adds_a_full_block_when_aligned() {
        let mut out = [0u8; 48];
        let n = iso7816_pad(&[1u8; 16], &mut out).expect("pad");
        assert_eq!(n, 32);
        assert_eq!(&out[..16], &[1u8; 16]);
        assert_eq!(out[16], 0x80);
        assert_eq!(&out[17..32], &[0u8; 15]);
    }
}
