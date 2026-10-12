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
    /// The URL template is malformed (missing/extra mirrors, bad scheme,
    /// or too long for the 64-byte APDU carrier).
    BadTemplate,
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

// ---------------------------------------------------------------------------
// Full provisioning sequence (T4)
// ---------------------------------------------------------------------------

/// UPDATE BINARY instruction (ISO 7816-4): write the NDEF file.
pub const UPDATE_BINARY_INS: u8 = 0xD6;

/// URI prefix code written into the NDEF URI record payload.
const HTTPS_PREFIX: &str = "https://";

/// Max NDEF file size we will write (NTAG 424 NDEF file is 256 bytes; Lc is
/// one byte). The APDU carrier is the transport buffer (>=258 B), so a full
/// 255-byte file still fits one UPDATE BINARY.
const MAX_FILE_LEN: usize = 255;

/// Successful provisioning outcome: the tag identity as read back through the
/// active SUN mirrors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionReport {
    /// 7-byte card UID (from the UID mirror).
    pub uid: [u8; 7],
    /// SUN read counter value (from the counter mirror).
    pub counter: u32,
}

/// SDM mirror offsets within the NDEF file (byte 0 = first NLEN byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SunOffsets {
    /// First byte of the 14-ASCII-char UID mirror.
    uid: usize,
    /// First byte of the 6-ASCII-char read-counter mirror.
    read_ctr: usize,
    /// First byte of the CMAC input (= UID mirror start per AN12196 §3.4.4.2.2).
    mac_input: usize,
    /// First byte of the 16-ASCII-char CMAC mirror.
    mac: usize,
}

fn find_sub(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let mut i = from;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Build the NDEF file image (NLEN ‖ URI record) from a URL template and
/// compute the SDM mirror offsets.
///
/// The template must start with `https://` (encoded as URI prefix code 0x04,
/// stripped from the stored body), contain `uid=`, `c=` and `cmac=` in that
/// order with nothing between the `=` and the following separator. The empty
/// placeholders are expanded to the mirror widths (uid 14, counter 6, cmac 16
/// ASCII chars, per AN12196 §3.4) filled with `'0'` dummies — the chip
/// overwrites them with live values on every read.
fn ndef_file_from_template(
    template: &str,
    file: &mut [u8; 258],
) -> Result<(usize, SunOffsets), ProvisionError> {
    let body = template
        .strip_prefix(HTTPS_PREFIX)
        .ok_or(ProvisionError::BadTemplate)?;

    let b = body.as_bytes();
    // "?uid=" marks the UID mirror start; require it so a bare "uid=" in the
    // host name cannot pass.
    let i_uid = find_sub(b, b"?uid=", 0).ok_or(ProvisionError::BadTemplate)?;
    let i_c = find_sub(b, b"&c=", i_uid).ok_or(ProvisionError::BadTemplate)?;
    // `&c=` must not be the `&cmac=` prefix: the counter placeholder is empty,
    // so "&c=" is immediately followed by "&".
    if b.get(i_c + 3) != Some(&b'&') {
        return Err(ProvisionError::BadTemplate);
    }
    let i_mac = find_sub(b, b"&cmac=", i_c + 3).ok_or(ProvisionError::BadTemplate)?;
    // Placeholders must be empty: "&cmac=" directly follows "&c=".
    if i_mac != i_c + 3 {
        return Err(ProvisionError::BadTemplate);
    }

    // Expanded body: static parts + mirror-width dummy placeholders.
    const UID_W: usize = 14;
    const CTR_W: usize = 6;
    const MAC_W: usize = 16;
    let exp_len = b.len() + UID_W + CTR_W + MAC_W;
    // NLEN(2) + [D1,TL,PL,Type](4) + [Prefix](1) + expanded body
    let file_len = 7 + exp_len;
    if file_len > MAX_FILE_LEN {
        return Err(ProvisionError::BadTemplate);
    }

    // NLEN = NDEF message length after NLEN = 4 header bytes + payload
    // (prefix byte + expanded body).
    let nlen = 4 + 1 + exp_len;
    file[0] = (nlen >> 8) as u8;
    file[1] = (nlen & 0xFF) as u8;
    file[2] = 0xD1; // MB|ME|SR|TNF=1 (well-known)
    file[3] = 0x01; // type length
    file[4] = (1 + exp_len) as u8; // payload length (prefix byte + body)
    file[5] = b'U';
    file[6] = 0x04; // URI identifier code: "https://"

    // Splice: static-head + 14 dummies + "&c=" + 6 dummies + "&cmac=" + 16 dummies.
    let mut w = 7;
    file[w..w + i_uid + 5].copy_from_slice(&b[..i_uid + 5]);
    w += i_uid + 5;
    let o_uid = w;
    file[w..w + UID_W].fill(b'0');
    w += UID_W;
    file[w..w + (i_c + 3) - (i_uid + 5)].copy_from_slice(&b[i_uid + 5..i_c + 3]);
    w += (i_c + 3) - (i_uid + 5);
    let o_ctr = w;
    file[w..w + CTR_W].fill(b'0');
    w += CTR_W;
    file[w..w + (i_mac + 6) - (i_c + 3)].copy_from_slice(&b[i_c + 3..i_mac + 6]);
    w += (i_mac + 6) - (i_c + 3);
    let o_mac = w;
    file[w..w + MAC_W].fill(b'0');
    w += MAC_W;
    debug_assert_eq!(w, file_len);

    let offsets = SunOffsets {
        uid: o_uid,
        read_ctr: o_ctr,
        mac_input: o_uid,
        mac: o_mac,
    };
    // Mirror windows must not overlap and must end inside the file.
    if offsets.uid + UID_W > offsets.read_ctr
        || offsets.read_ctr + CTR_W > offsets.mac
        || offsets.mac + MAC_W > file_len
    {
        return Err(ProvisionError::BadTemplate);
    }
    Ok((file_len, offsets))
}

/// Serialize the 18-byte SDM ChangeFileSettings settings block.
///
/// Wire order per pylibsdm `structs.py FileSettings::to_bytes` (NTAG 424
/// datasheet table 73): file_option, access_rights(2), sdm_options,
/// sdm_access_rights(2), then the enabled 3-byte-LE offsets in the fixed
/// order uid, read_ctr, mac_input, mac.
fn sdm_settings_bytes(o: &SunOffsets) -> [u8; 18] {
    let mut s = [0u8; 18];
    s[0] = 0x40; // FileOption: SDM enabled (bit6) | CommMode.PLAIN (0)
    s[1] = 0xEF; // AccessRights: read=0xE (free), write=0xF (no access)
    s[2] = 0xF0; //               read_write=0xF, change=0x0 (key 0)
    s[3] = 0xC1; // SDMOptions: uid(128) | read_ctr(64) | ascii(1)
    s[4] = 0xFE; // SDMAccessRights b1: RFU(0xF) | ctr_ret=0xE (free)
    s[5] = 0xE1; //                   b2: meta_read=0xE (free) | file_read=0x1 (key 1)
    let le3 = |v: usize| [v as u8, (v >> 8) as u8, (v >> 16) as u8];
    s[6..9].copy_from_slice(&le3(o.uid));
    s[9..12].copy_from_slice(&le3(o.read_ctr));
    s[12..15].copy_from_slice(&le3(o.mac_input));
    s[15..18].copy_from_slice(&le3(o.mac));
    s
}

/// SUN SDM session key: `AES-CMAC(tag_key, SV2)` with
/// `SV2 = 3CC3 0001 0080 ‖ uid(7B) ‖ counter(3B LSB-first)` (AN12196 §3.3).
///
/// Distinct from the AUTH session SV2 (`0x5AA5 …`) in `ntag424`.
pub fn sun_session_key(
    tag_key: &[u8; 16],
    uid: &[u8; 7],
    counter: u32,
) -> [u8; 16] {
    let c = counter.to_le_bytes();
    let sv2: [u8; 16] = [
        0x3c, 0xc3, 0x00, 0x01, 0x00, 0x80, //
        uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], //
        c[0], c[1], c[2],
    ];
    aes_cmac(tag_key, &sv2)
}

/// MACt: SUN CMAC = odd-index bytes (`[1::2]`) of the full 16-byte digest.
fn sun_trunc_mac(full: &[u8; 16]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, o) in out.iter_mut().enumerate() {
        *o = full[2 * i + 1];
    }
    out
}

/// Compute the SUN CMAC the tag mirrors: odd-byte truncation of
/// `AES-CMAC(sun_session_key(tag_key, uid, ctr), mac_input)` where mac_input
/// is the exact ASCII the tag signs (`uid14&c=ctr6&cmac=`).
fn sun_tag_cmac(tag_key: &[u8; 16], uid: &[u8; 7], counter: u32, mac_input: &[u8]) -> [u8; 8] {
    let session = sun_session_key(tag_key, uid, counter);
    sun_trunc_mac(&aes_cmac(&session, mac_input))
}

/// Select NDEF app + file 02 (plain, expect SW 9000).
fn select_ndef<F>(exchange: &mut F) -> Result<(), ProvisionError>
where
    F: FnMut(&[u8], &mut [u8]) -> Result<usize, NdefError>,
{
    use crate::ntag424::{SELECT_NDEF_APP_APDU, SELECT_NDEF_FILE_02_APDU};
    let mut resp = [0u8; 258];
    let n = exchange(&SELECT_NDEF_APP_APDU, &mut resp)?;
    check_status(&resp[..n], 0x90, 0x00)?;
    let n = exchange(&SELECT_NDEF_FILE_02_APDU, &mut resp)?;
    check_status(&resp[..n], 0x90, 0x00)?;
    Ok(())
}

/// Read the NDEF file (NLEN + body) into `file`; returns the file length.
fn read_file<F>(exchange: &mut F, file: &mut [u8; 258]) -> Result<usize, ProvisionError>
where
    F: FnMut(&[u8], &mut [u8]) -> Result<usize, NdefError>,
{
    let mut resp = [0u8; 258];
    let n = exchange(&[0x00, crate::ntag424::READ_BINARY_INS, 0x00, 0x00, 0x02], &mut resp)?;
    check_status(&resp[..n], 0x90, 0x00)?;
    if n < 4 {
        return Err(ProvisionError::ShortResponse);
    }
    let nlen = ((resp[0] as usize) << 8) | (resp[1] as usize);
    if nlen == 0 || 2 + nlen > file.len() {
        return Err(ProvisionError::ShortResponse);
    }
    let apdu = [
        0x00,
        crate::ntag424::READ_BINARY_INS,
        0x00,
        0x02,
        nlen as u8,
    ];
    let n = exchange(&apdu, &mut resp)?;
    check_status(&resp[..n], 0x90, 0x00)?;
    let data = n.checked_sub(2).ok_or(ProvisionError::ShortResponse)?;
    if data < nlen {
        return Err(ProvisionError::ShortResponse);
    }
    // Reconstruct the full file view (NLEN ‖ message) so callers can index
    // with plain FILE offsets (byte 0 = first NLEN byte, per AN12196).
    if 2 + nlen > file.len() {
        return Err(ProvisionError::BufferTooSmall);
    }
    file[0] = (nlen >> 8) as u8;
    file[1] = (nlen & 0xFF) as u8;
    file[2..2 + nlen].copy_from_slice(&resp[..nlen]);
    Ok(nlen)
}

/// Run the full provisioning sequence against a blank (factory-keyed) tag.
///
/// Steps (AN12196 provisioning flow, restricted to what our verifier checks):
/// select NDEF → `AuthenticateEV2First` with factory key 0 → `ChangeKey` 1 to
/// the job key → write NDEF (template with empty placeholders + NLEN) via
/// UPDATE BINARY while the file is still open → `ChangeFileSettings` to enable
/// SDM mirroring under key 1 → read back through the live mirrors and verify
/// the mirrored CMAC locally. Fills `out` with the tag identity read back.
///
/// `rnda` seeds the auth handshake (deterministic, host-testable). The
/// transport `exchange` sends one APDU and returns `response ‖ SW1 SW2` —
/// same contract as `ntag424::read_ndef_message`.
pub fn provision_tag<F>(
    exchange: &mut F,
    rnda: &[u8; 16],
    job_key: &[u8; 16],
    url_template: &str,
    out: &mut ProvisionReport,
) -> Result<(), ProvisionError>
where
    F: FnMut(&[u8], &mut [u8]) -> Result<usize, NdefError>,
{
    let mut file = [0u8; 258];
    let (file_len, offsets) = ndef_file_from_template(url_template, &mut file)?;

    // 1) Select NDEF application + file.
    select_ndef(exchange)?;

    // 2) Authenticate with factory key 0 — NEVER change key 0.
    let factory = [0u8; 16];
    let mut session = authenticate_ev2_first(&factory, 0, rnda, exchange)?;

    // 3) ChangeKey 1 <- job key (CommMode.Full).
    let mut frame = [0u8; 64];
    let n = change_key(&mut session, 1, job_key, 1, &mut frame)?;
    let (apdu, len) = crate::ntag424::wrap_apdu(crate::provision::CHANGE_KEY_INS, &frame[..n]);
    let mut resp = [0u8; 258];
    let rn = exchange(&apdu[..len], &mut resp)?;
    check_status(&resp[..rn], 0x91, 0x00)?;

    // 4) Write NDEF (NLEN + record) while the file is still openly writable.
    let apdu = [
        0x00,
        UPDATE_BINARY_INS,
        0x00,
        0x00,
        file_len as u8,
    ];
    let mut update = [0u8; 260];
    update[..5].copy_from_slice(&apdu);
    update[5..5 + file_len].copy_from_slice(&file[..file_len]);
    let rn = exchange(&update[..5 + file_len], &mut resp)?;
    check_status(&resp[..rn], 0x90, 0x00)?;

    // 5) ChangeFileSettings on file 2: enable SDM mirrors (CommMode.Full).
    let settings = sdm_settings_bytes(&offsets);
    let n = change_file_settings(&mut session, 2, &settings, &mut frame)?;
    let (apdu, len) =
        crate::ntag424::wrap_apdu(crate::provision::CHANGE_FILE_SETTINGS_INS, &frame[..n]);
    let rn = exchange(&apdu[..len], &mut resp)?;
    check_status(&resp[..rn], 0x91, 0x00)?;

    // 6) Read back through the active mirrors and verify locally.
    select_ndef(exchange)?;
    let nlen = read_file(exchange, &mut resp)?;
    let uri = crate::ntag424::extract_ndef_uri(&resp[2..2 + nlen])
        .map_err(ProvisionError::Transport)?;
    let sun = crate::ntag424::parse_sun_url(uri).map_err(|_| ProvisionError::MacMismatch)?;

    // CMAC input is the exact raw ASCII the tag signed: uid mirror + separators.
    if offsets.uid + 14 > nlen || offsets.read_ctr + 6 > nlen {
        return Err(ProvisionError::ShortResponse);
    }
    let mut mac_input = [0u8; 29];
    mac_input[..14].copy_from_slice(&resp[offsets.uid..offsets.uid + 14]);
    mac_input[14..17].copy_from_slice(b"&c=");
    mac_input[17..23].copy_from_slice(&resp[offsets.read_ctr..offsets.read_ctr + 6]);
    mac_input[23..].copy_from_slice(b"&cmac=");

    let expected = sun_tag_cmac(job_key, &sun.uid, sun.counter, &mac_input);
    if !constant_time_eq(&expected, &sun.cmac) {
        return Err(ProvisionError::MacMismatch);
    }

    out.uid = sun.uid;
    out.counter = sun.counter;
    Ok(())
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

    // -----------------------------------------------------------------------
    // T4: provisioning sequence
    // -----------------------------------------------------------------------

    /// Uppercase ASCII hex encoder (matches NXP SUN mirrors + the verifier's
    /// `write_hex_upper`).
    fn enc_hex_upper(out: &mut [u8], src: &[u8]) {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for (i, b) in src.iter().enumerate() {
            out[2 * i] = HEX[(b >> 4) as usize];
            out[2 * i + 1] = HEX[(b & 0x0f) as usize];
        }
    }

    /// Cross-repo pin: the firmware SUN session/CMAC construction must
    /// reproduce the verifier's pylibsdm-generated golden vectors
    /// (access-control-verifier tests/crypto_vectors.rs, vector set 1).
    #[test]
    fn test_sun_cmac_matches_verifier_goldens() {
        // tag_key (diversified job key) and UID from the golden set.
        let tag_key: [u8; 16] = h("71A4EC87107F7FC71B2220E23D8CE93A");
        let uid: [u8; 7] = h("046522CABC5D80");
        // (counter, expected session key, expected cmac)
        let cases: &[(u32, &str, &str)] = &[
            (1, "C30319AC9B924D5D42F1DB871821E65B", "4BE403BA3E9B7BD0"),
            (8, "08D4380C34F41ED6506C6362AA43B287", "C894C366C5802E34"),
            (11, "C371C486F40250C4B46F27ED2BF9D64C", "2EBFCD8D2474E800"),
            (255, "3048E917D855466160E73E37E4622C94", "30A08B95BAAD09A4"),
        ];
        for &(ctr, ses, mac) in cases {
            assert_eq!(sun_session_key(&tag_key, &uid, ctr), h(ses));
            // mac_input per the pinned wire format: uid14&c=ctr6&cmac=
            let mut input = [0u8; 29];
            enc_hex_upper(&mut input[..14], &uid);
            input[14..17].copy_from_slice(b"&c=");
            let cb = ctr.to_be_bytes();
            enc_hex_upper(&mut input[17..23], &cb[1..4]);
            input[23..].copy_from_slice(b"&cmac=");
            assert_eq!(sun_tag_cmac(&tag_key, &uid, ctr, &input), h(mac));
        }
    }

    #[test]
    fn test_template_offsets_and_ndef_image() {
        let mut file = [0u8; 258];
        let (len, o) =
            ndef_file_from_template(TEMPLATE, &mut file)
                .expect("template parses");
        // Expanded body = 30 static + 36 mirror = 66 chars -> file 73 bytes.
        assert_eq!(len, 73);
        assert_eq!(o.uid, 28); // 7 + "?uid=" end in body (21)
        assert_eq!(o.read_ctr, o.uid + 14 + 3); // 14-char mirror + "&c="
        assert_eq!(o.mac, o.read_ctr + 6 + 6); // 6-char mirror + "&cmac="
        assert_eq!(o.mac_input, o.uid);
        assert_eq!(o.mac + 16, len); // CMAC mirror ends at EOF
        // Record image sanity.
        assert_eq!(file[0], 0x00);
        assert_eq!(file[1], 71); // NLEN = 4 hdr + 1 prefix + 66 body
        assert_eq!(&file[2..7], &[0xD1, 0x01, 67, b'U', 0x04]);
        assert_eq!(&file[7..12], b"10bit");
        assert_eq!(&file[24..28], b"uid=");
        assert_eq!(&file[28..42], b"00000000000000"); // uid dummy
        assert_eq!(&file[42..45], b"&c=");
        assert_eq!(&file[45..51], b"000000"); // counter dummy
        assert_eq!(&file[51..57], b"&cmac=");
        assert_eq!(&file[57..73], b"0000000000000000"); // cmac dummy
    }

    #[test]
    fn test_template_rejects_malformed() {
        let mut file = [0u8; 258];
        // Missing scheme.
        assert_eq!(
            ndef_file_from_template("http://x/k?uid=&c=&cmac=", &mut file),
            Err(ProvisionError::BadTemplate)
        );
        // Missing cmac.
        assert_eq!(
            ndef_file_from_template("https://x/k?uid=&c=", &mut file),
            Err(ProvisionError::BadTemplate)
        );
        // Non-empty counter placeholder (mirror overlap).
        assert_eq!(
            ndef_file_from_template("https://x/k?uid=&c=ZZZZZZ&cmac=", &mut file),
            Err(ProvisionError::BadTemplate)
        );
        // Bare uid= without query marker.
        assert_eq!(
            ndef_file_from_template("https://uid=&c=&cmac=", &mut file),
            Err(ProvisionError::BadTemplate)
        );
    }

    #[test]
    fn test_sdm_settings_wire_bytes() {
        let o = SunOffsets { uid: 28, read_ctr: 45, mac_input: 28, mac: 57 };
        let s = sdm_settings_bytes(&o);
        assert_eq!(
            s,
            [
                0x40, // file option: SDM on, PLAIN
                0xEF, 0xF0, // read=E, write=F, rw=F, change=0
                0xC1, // uid+read_ctr+ascii
                0xFE, 0xE1, // ctr_ret=E free, meta=E free, file_read=1
                28, 0, 0, // uid_offset LE24
                45, 0, 0, // read_ctr_offset
                28, 0, 0, // mac_input_offset
                57, 0, 0, // mac_offset
            ]
        );
    }

    // -----------------------------------------------------------------------
    // T4: full-sequence mock card
    // -----------------------------------------------------------------------

    /// Mirrors `TEMPLATE` (config is main-only:
    /// its `env!()` credentials cannot compile on the host test target).
    const TEMPLATE: &str = "https://10bitworks.org/k?uid=&c=&cmac=";

    const MOCK_UID_HEX: &str = "046522CABC5D80";
    const MOCK_JOB_KEY_HEX: &str = "aabbccddeeff00112233445566778899";
    const MOCK_RNDB: &str = "b9e2fc789b64bf237cccaa20ec7e6e48";
    const MOCK_CNTR: u32 = 1;

    /// Stateful card stub: factory key 0, EV2 auth, ChangeKey, file write,
    /// ChangeFileSettings, and SUN-mirrored reads computed with the REAL
    /// construction (so the read-back verify is genuinely end-to-end).
    struct MockCard {
        key1: [u8; 16],
        file: [u8; 258],
        file_len: usize,
        sdm: bool,
        fail_file_select: bool,
        // session state after auth
        sess: Option<Session>,
        cmdctr: u16,
        rndb: [u8; 16],
        recorded_settings: Option<[u8; 18]>,
    }

    impl MockCard {
        fn new() -> Self {
            Self {
                key1: [0u8; 16],
                file: [0u8; 258],
                file_len: 0,
                sdm: false,
                fail_file_select: false,
                sess: None,
                cmdctr: 0,
                rndb: h(MOCK_RNDB),
                recorded_settings: None,
            }
        }

        /// The SUN CMAC this card mirrors, computed with the real rules.
        fn sun_cmac_hex(&self, uid: &[u8; 7]) -> [u8; 16] {
            let mut out = [0u8; 16];
            let cmac = sun_tag_cmac(&self.key1, uid, MOCK_CNTR, &self.mac_input(uid));
            enc_hex_upper(&mut out, &cmac);
            out
        }

        fn mac_input(&self, uid: &[u8; 7]) -> [u8; 29] {
            let mut m = [0u8; 29];
            enc_hex_upper(&mut m[..14], uid);
            m[14..17].copy_from_slice(b"&c=");
            let cb = MOCK_CNTR.to_be_bytes();
            enc_hex_upper(&mut m[17..23], &cb[1..4]);
            m[23..].copy_from_slice(b"&cmac=");
            m
        }

        fn handle(&mut self, apdu: &[u8], out: &mut [u8]) -> Result<usize, NdefError> {
            let ins = apdu[1];
            match (apdu[0], ins) {
                // SELECT (ISO) — NDEF app AID or file 02.
                (0x00, 0xA4) => {
                    if apdu[2] == 0x04 {
                        out[0] = 0x90;
                        out[1] = 0x00;
                        return Ok(2);
                    }
                    // file 02 select
                    if self.fail_file_select {
                        out[0] = 0x6A;
                        out[1] = 0x82;
                        return Ok(2);
                    }
                    out[0] = 0x90;
                    out[1] = 0x00;
                    Ok(2)
                }
                // AuthenticateEV2First part 1 (native CLA 0x90).
                (0x90, 0x71) => {
                    let factory = [0u8; 16];
                    let mut e = self.rndb;
                    cbc_encrypt_inplace(&factory, &NULL_IV, &mut e);
                    out[..16].copy_from_slice(&e);
                    out[16] = 0x91;
                    out[17] = 0xAF;
                    Ok(18)
                }
                // Auth part 2.
                (0x90, 0xAF) => {
                    let factory = [0u8; 16];
                    let lc = apdu[4] as usize;
                    let mut data = [0u8; 32];
                    data.copy_from_slice(&apdu[5..5 + lc]);
                    cbc_decrypt_inplace(&factory, &NULL_IV, &mut data);
                    let mut rnda = [0u8; 16];
                    rnda.copy_from_slice(&data[..16]);
                    let sk = crate::ntag424::derive_session_keys(&factory, &rnda, &self.rndb);
                    self.sess = Some(Session {
                        ti: [0x11, 0x22, 0x33, 0x44],
                        cmdctr: 0,
                        k_enc: sk.enc,
                        k_mac: sk.mac,
                    });
                    self.cmdctr = 0;
                    let mut resp = [0u8; 32];
                    resp[0..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
                    resp[4..20].copy_from_slice(&rotate_left16(&rnda));
                    cbc_encrypt_inplace(&factory, &NULL_IV, &mut resp);
                    out[..32].copy_from_slice(&resp);
                    out[32] = 0x91;
                    out[33] = 0x00;
                    Ok(34)
                }
                // ChangeKey / ChangeFileSettings (CommMode.Full, native).
                (0x90, CHANGE_KEY_INS) | (0x90, CHANGE_FILE_SETTINGS_INS) => {
                    let s = self.sess.expect("auth first");
                    let lc = apdu[4] as usize;
                    let frame = &apdu[5..5 + lc];
                    // frame = hdr ‖ enc(32) ‖ cmac(8)
                    let mut plain = [0u8; 32];
                    plain.copy_from_slice(&frame[1..33]);
                    let iv = iv_for_enc(&Session {
                        ti: s.ti,
                        cmdctr: self.cmdctr,
                        k_enc: s.k_enc,
                        k_mac: s.k_mac,
                    });
                    cbc_decrypt_inplace(&s.k_enc, &iv, &mut plain);
                    if apdu[1] == CHANGE_KEY_INS {
                        // plain = new key ‖ version
                        self.key1.copy_from_slice(&plain[..16]);
                        assert_eq!(plain[16], 1, "key version");
                    } else {
                        let mut st = [0u8; 18];
                        st.copy_from_slice(&plain[..18]);
                        self.recorded_settings = Some(st);
                        self.sdm = true;
                    }
                    self.cmdctr = self.cmdctr.wrapping_add(1);
                    out[0] = 0x91;
                    out[1] = 0x00;
                    Ok(2)
                }
                // UPDATE BINARY (ISO).
                (0x00, UPDATE_BINARY_INS) => {
                    let off = ((apdu[2] as usize) << 8) | apdu[3] as usize;
                    let lc = apdu[4] as usize;
                    assert_eq!(off, 0, "whole-file write only");
                    self.file_len = lc;
                    self.file[..lc].copy_from_slice(&apdu[5..5 + lc]);
                    out[0] = 0x90;
                    out[1] = 0x00;
                    Ok(2)
                }
                // READ BINARY (ISO) — mirrors active after SDM enable.
                (0x00, 0xB0) => {
                    let off = ((apdu[2] as usize) << 8) | apdu[3] as usize;
                    let le = apdu[4] as usize;
                    let uid: [u8; 7] = h(MOCK_UID_HEX);
                    let mut view = [0u8; 258];
                    let n = self.file_len;
                    view[..n].copy_from_slice(&self.file[..n]);
                    if self.sdm {
                        // Fill mirrors at the recorded settings offsets.
                        let st = self.recorded_settings.expect("sdm settings");
                        let rd = |b: &[u8]| -> usize {
                            b[0] as usize | ((b[1] as usize) << 8) | ((b[2] as usize) << 16)
                        };
                        let uo = rd(&st[6..9]);
                        let co = rd(&st[9..12]);
                        let mo = rd(&st[15..18]);
                        enc_hex_upper(&mut view[uo..uo + 14], &uid);
                        let cb = MOCK_CNTR.to_be_bytes();
                        enc_hex_upper(&mut view[co..co + 6], &cb[1..4]);
                        view[mo..mo + 16].copy_from_slice(&self.sun_cmac_hex(&uid));
                    }
                    let end = (off + le).min(n);
                    let data = end.saturating_sub(off);
                    out[..data].copy_from_slice(&view[off..end]);
                    out[data] = 0x90;
                    out[data + 1] = 0x00;
                    Ok(data + 2)
                }
                _ => Err(NdefError::Transport),
            }
        }
    }

    #[test]
    fn test_provision_full_sequence_happy() {
        let job_key: [u8; 16] = h(MOCK_JOB_KEY_HEX);
        let rnda: [u8; 16] = h(RNDA);
        let mut card = MockCard::new();
        let mut report = ProvisionReport { uid: [0; 7], counter: 0 };
        let res = {
            let mut exchange = |apdu: &[u8], out: &mut [u8]| card.handle(apdu, out);
            provision_tag(
                &mut exchange,
                &rnda,
                &job_key,
                TEMPLATE,
                &mut report,
            )
        };
        res.expect("provisioning succeeds");
        // Report carries the identity read back through the mirrors.
        assert_eq!(report.uid, h(MOCK_UID_HEX));
        assert_eq!(report.counter, MOCK_CNTR);
        // Card actually took the job key.
        assert_eq!(card.key1, job_key);
        // Card recorded exactly the expected 18-byte SDM settings.
        let mut file = [0u8; 258];
        let (_, o) =
            ndef_file_from_template(TEMPLATE, &mut file).unwrap();
        assert_eq!(card.recorded_settings, Some(sdm_settings_bytes(&o)));
        // The written NDEF contains the expanded dummy placeholders.
        let written = &card.file[..card.file_len];
        let body = core::str::from_utf8(&written[7..]).unwrap();
        assert_eq!(body.len(), 66);
        assert_eq!(
            body,
            "10bitworks.org/k?uid=00000000000000&c=000000&cmac=0000000000000000"
        );
    }

    #[test]
    fn test_provision_file_select_failure_propagates() {
        let job_key: [u8; 16] = h(MOCK_JOB_KEY_HEX);
        let rnda: [u8; 16] = h(RNDA);
        let mut card = MockCard::new();
        card.fail_file_select = true;
        let mut report = ProvisionReport { uid: [0; 7], counter: 0 };
        let res = {
            let mut exchange = |apdu: &[u8], out: &mut [u8]| card.handle(apdu, out);
            provision_tag(
                &mut exchange,
                &rnda,
                &job_key,
                TEMPLATE,
                &mut report,
            )
        };
        assert_eq!(res, Err(ProvisionError::Status(0x6A, 0x82)));
    }

    #[test]
    fn test_config_template_constant() {
        // The template lives in config (not hardcoded in provision.rs) and
        // satisfies the parser's contract.
        let t = TEMPLATE;
        assert!(t.starts_with("https://"));
        assert!(t.contains("?uid="));
        assert!(t.contains("&c="));
        assert!(t.contains("&cmac="));
        let mut file = [0u8; 258];
        assert!(ndef_file_from_template(t, &mut file).is_ok());
    }

}

