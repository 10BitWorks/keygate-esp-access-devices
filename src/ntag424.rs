//! NTAG 424 DNA Authentication
//!
//! Implements the NXP NTAG 424 DNA mutual authentication protocol
//! (AuthenticateEV2First) and counter/file access commands.
//!
//! Uses pure-Rust AES and CMAC from the RustCrypto project —
//! no dependency on PSA Crypto or mbedtls.
//!
//! Protocol reference:
//!   - NXP AN12196: NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints
//!   - ISO 7816-4 APDU wrapping
//!   - ISO 14443-4 (ISO-DEP) transport via PN532 InDataExchange

#![allow(dead_code)]

use aes::Aes128;
use cmac::{Cmac, Mac};

/// AES-128 key size
const KEY_SIZE: usize = 16;

/// NTAG 424 DNA Application AID
const NDEF_APP_AID: [u8; 7] = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];

/// Session keys derived during AuthenticateEV2First
pub struct SessionKeys {
    pub enc: [u8; KEY_SIZE],
    pub mac: [u8; KEY_SIZE],
}

/// Authentication state
pub enum AuthState {
    /// Not authenticated
    None,
    /// AuthenticateEV2First completed, session keys established
    Authenticated(SessionKeys),
}

/// Compute AES-CMAC over the given data with the provided key.
///
/// Returns the full 16-byte MAC.
pub fn aes_cmac(key: &[u8; KEY_SIZE], data: &[u8]) -> [u8; KEY_SIZE] {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key).expect("valid key length");
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; KEY_SIZE];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// Derive session keys from RndA, RndB, and the shared AES key.
///
/// Per NXP AN12196 §3.4:
///   SV1 = 0xA55A || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] XOR RndB[15..10]) || RndB[9..0] || RndA[7..0]
///   SV2 = 0x5AA5 || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] XOR RndB[15..10]) || RndB[9..0] || RndA[7..0]
///   K_enc = CMAC(Key, SV1)
///   K_mac = CMAC(Key, SV2)
pub fn derive_session_keys(
    key: &[u8; KEY_SIZE],
    rnd_a: &[u8; KEY_SIZE],
    rnd_b: &[u8; KEY_SIZE],
) -> SessionKeys {
    let mut sv1 = [0u8; 32];
    let mut sv2 = [0u8; 32];

    // Header bytes
    sv1[0..2].copy_from_slice(&[0xA5, 0x5A]);
    sv2[0..2].copy_from_slice(&[0x5A, 0xA5]);

    // Common: 0x00 0x01 0x00 0x80
    let common = [0x00, 0x01, 0x00, 0x80];
    sv1[2..6].copy_from_slice(&common);
    sv2[2..6].copy_from_slice(&common);

    // RndA[15..14]
    sv1[6..8].copy_from_slice(&rnd_a[0..2]);
    sv2[6..8].copy_from_slice(&rnd_a[0..2]);

    // RndA[13..8] XOR RndB[15..10]
    for i in 0..6 {
        sv1[8 + i] = rnd_a[2 + i] ^ rnd_b[0 + i];
        sv2[8 + i] = rnd_a[2 + i] ^ rnd_b[0 + i];
    }

    // RndB[9..0]
    sv1[14..24].copy_from_slice(&rnd_b[6..16]);
    sv2[14..24].copy_from_slice(&rnd_b[6..16]);

    // RndA[7..0]
    sv1[24..32].copy_from_slice(&rnd_a[8..16]);
    sv2[24..32].copy_from_slice(&rnd_a[8..16]);

    SessionKeys {
        enc: aes_cmac(key, &sv1),
        mac: aes_cmac(key, &sv2),
    }
}

/// Wrap a native command into an ISO 7816-4 APDU for the NTAG 424.
///
/// Format: CLA=0x90, INS=cmd, P1=0x00, P2=0x00, Lc=data.len(), Data, Le=0x00
pub fn wrap_apdu(cmd: u8, data: &[u8]) -> ([u8; 64], usize) {
    let mut apdu = [0u8; 64];
    apdu[0] = 0x90; // CLA
    apdu[1] = cmd;  // INS
    apdu[2] = 0x00; // P1
    apdu[3] = 0x00; // P2

    let len = if data.is_empty() {
        apdu[4] = 0x00; // Le
        5
    } else {
        apdu[4] = data.len() as u8; // Lc
        apdu[5..5 + data.len()].copy_from_slice(data);
        apdu[5 + data.len()] = 0x00; // Le
        6 + data.len()
    };

    (apdu, len)
}

/// Select the NTAG 424 DNA NDEF application.
///
/// Issues: 90 5A 00 00 03 00 00 01 00  (Select Application, NDEF AID)
/// Uses ISO 7816-4 SELECT by DF name with the well-known NDEF AID.
pub fn select_application_apdu() -> ([u8; 64], usize) {
    // ISO SELECT by DF name: CLA=00, INS=A4, P1=04, P2=0C, Lc=07, AID
    let mut apdu = [0u8; 64];
    apdu[0] = 0x00; // CLA
    apdu[1] = 0xA4; // INS (SELECT)
    apdu[2] = 0x04; // P1 (Select by DF name)
    apdu[3] = 0x0C; // P2 (No response data)
    apdu[4] = NDEF_APP_AID.len() as u8;
    apdu[5..5 + NDEF_APP_AID.len()].copy_from_slice(&NDEF_APP_AID);
    (apdu, 5 + NDEF_APP_AID.len())
}

/// GetVersion command — first frame
pub fn get_version_apdu() -> ([u8; 64], usize) {
    wrap_apdu(0x60, &[])
}

/// Check if GetVersion Frame 1 response identifies an NTAG 424 DNA.
///
/// Byte[1]=0x04 (NTAG family), Byte[5]=0x11 (4KB), Byte[6]=0x05 (ISO-DEP)
pub fn is_ntag424_dna(version_frame1: &[u8]) -> bool {
    version_frame1.len() >= 7
        && version_frame1[1] == 0x04
        && version_frame1[5] == 0x11
        && version_frame1[6] == 0x05
}

/// Extracted SUN (Secure Unique NFC) mirror parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SunParams {
    /// 7-byte card UID.
    pub uid: [u8; 7],
    /// SUN read/tap counter.
    pub counter: u32,
    /// 16-byte AES-CMAC.
    pub cmac: [u8; 16],
}

/// Errors returned when parsing SUN URL query parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// No query string delimiter (`?`) found in URL.
    MissingQueryString,
    /// The `uid` parameter is missing.
    MissingUid,
    /// The `c` or `ctr` counter parameter is missing.
    MissingCounter,
    /// The `cmac` parameter is missing.
    MissingCmac,
    /// A parameter's hex representation contains an invalid character.
    InvalidHexChar,
    /// A hex parameter has an odd or invalid length.
    InvalidLength,
    /// A counter parameter could not be parsed as a decimal u32.
    InvalidCounter,
}

/// Helper function to convert a single ASCII hex character into its 4-bit nibble value.
fn hex_val(b: u8) -> Result<u8, ParseError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ParseError::InvalidHexChar),
    }
}

/// Decode exactly `N` hex bytes (from `2 * N` ASCII hex bytes) into `out`.
fn decode_hex_exact<const N: usize>(hex_str: &str, out: &mut [u8; N]) -> Result<(), ParseError> {
    let bytes = hex_str.as_bytes();
    if bytes.len() != N * 2 {
        return Err(ParseError::InvalidLength);
    }
    for i in 0..N {
        let hi = hex_val(bytes[i * 2])?;
        let lo = hex_val(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(())
}

/// Parse a decimal string into a `u32` without panic or overflow.
fn parse_decimal_u32(s: &str) -> Result<u32, ParseError> {
    if s.is_empty() {
        return Err(ParseError::InvalidCounter);
    }
    let mut val: u32 = 0;
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return Err(ParseError::InvalidCounter);
        }
        let digit = (b - b'0') as u32;
        val = val
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or(ParseError::InvalidCounter)?;
    }
    Ok(val)
}

/// Parse SUN mirror parameters (`uid`, `c`/`ctr`, `cmac`) from an NDEF URL.
///
/// Example: `https://access.10bit.works/?uid=04112233445566&c=000008&cmac=505C41A335A9B7DEF29D5959936FE7FE`
///
/// Features:
/// - Fixed-size, zero allocation (`no_std` compatible, no heap, no regex).
/// - Case-insensitive hex decoding (accepts upper/lowercase).
/// - Accepts either `c` or `ctr` for the tap counter.
/// - Validates UID length (14 hex chars -> 7 bytes) and CMAC length (32 hex chars -> 16 bytes).
pub fn parse_sun_url(url: &str) -> Result<SunParams, ParseError> {
    let query = match url.split_once('?') {
        Some((_, q)) => q,
        None => return Err(ParseError::MissingQueryString),
    };

    let mut uid_str: Option<&str> = None;
    let mut counter_str: Option<&str> = None;
    let mut cmac_str: Option<&str> = None;

    for param in query.split('&') {
        if param.is_empty() {
            continue;
        }
        let (key, val) = match param.split_once('=') {
            Some((k, v)) => (k, v),
            None => (param, ""),
        };

        if key == "uid" {
            uid_str = Some(val);
        } else if key == "c" || key == "ctr" {
            counter_str = Some(val);
        } else if key == "cmac" {
            cmac_str = Some(val);
        }
    }

    let uid_raw = uid_str.ok_or(ParseError::MissingUid)?;
    let counter_raw = counter_str.ok_or(ParseError::MissingCounter)?;
    let cmac_raw = cmac_str.ok_or(ParseError::MissingCmac)?;

    let mut uid = [0u8; 7];
    decode_hex_exact(uid_raw, &mut uid)?;

    let counter = parse_decimal_u32(counter_raw)?;

    let mut cmac = [0u8; 16];
    decode_hex_exact(cmac_raw, &mut cmac)?;

    Ok(SunParams { uid, counter, cmac })
}

// ---------------------------------------------------------------------------
// NDEF / SUN transport (T9): read the NDEF message over ISO-DEP and extract
// the URI, so the firmware can obtain the UID/counter/CMAC for authentication.
// ---------------------------------------------------------------------------

/// ISO 7816-4 SELECT by DF name for the NTAG 424 DNA NDEF application.
///
/// `00 A4 04 00 07 D2 76 00 00 85 01 01 00`
pub const SELECT_NDEF_APP_APDU: [u8; 13] = [
    0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
];

/// ISO 7816-4 SELECT by file ID for NDEF File 02.
///
/// `00 A4 00 0C 02 02 00`
pub const SELECT_NDEF_FILE_02_APDU: [u8; 7] = [0x00, 0xA4, 0x00, 0x0C, 0x02, 0x02, 0x00];

/// ISO 7816-4 READ BINARY instruction byte (INS=0xB0).
pub const READ_BINARY_INS: u8 = 0xB0;

/// Errors returned while reading or parsing an NTAG 424 DNA NDEF message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdefError {
    /// The ISO-DEP transport failed.
    Transport,
    /// The card returned an unexpected status word `(SW1, SW2)`.
    Status(u8, u8),
    /// A response frame was shorter than required.
    ShortRead,
    /// The NDEF length field was zero or otherwise inconsistent.
    InvalidLength,
    /// The caller-provided output buffer was too small.
    BufferTooSmall,
    /// The first NDEF record was not a URI (`U`) record.
    NotUriRecord,
    /// The URI payload was not valid UTF-8.
    InvalidUtf8,
}

/// Verify an ISO 7816-4 status word of `90 00` (success).
fn check_status(resp: &[u8]) -> Result<(), NdefError> {
    if resp.len() < 2 {
        return Err(NdefError::ShortRead);
    }
    let sw1 = resp[resp.len() - 2];
    let sw2 = resp[resp.len() - 1];
    if sw1 == 0x90 && sw2 == 0x00 {
        Ok(())
    } else {
        Err(NdefError::Status(sw1, sw2))
    }
}

/// Read the NDEF message off an NTAG 424 DNA tag.
///
/// Sequence (each step an ISO 7816-4 APDU):
/// 1. SELECT NDEF application (`D2 76 00 00 85 01 01`)
/// 2. SELECT NDEF File 02
/// 3. READ BINARY 2 bytes at offset 0 -> NLEN (big-endian)
/// 4. READ BINARY in <=255-byte chunks until `NLEN` bytes are read
///
/// `exchange` sends one APDU and writes the card response (data plus the
/// trailing SW1/SW2) into the supplied output slice, returning its length.
/// Keeping transport out of this routine makes it host-testable.
///
/// The decoded NDEF message is written into `buf`; the number of bytes written
/// is returned.
pub fn read_ndef_message<F>(exchange: &mut F, buf: &mut [u8]) -> Result<usize, NdefError>
where
    F: FnMut(&[u8], &mut [u8]) -> Result<usize, NdefError>,
{
    let mut resp = [0u8; 258];

    // 1) Select the NDEF application.
    let n = exchange(&SELECT_NDEF_APP_APDU, &mut resp)?;
    check_status(&resp[..n])?;

    // 2) Select NDEF File 02.
    let n = exchange(&SELECT_NDEF_FILE_02_APDU, &mut resp)?;
    check_status(&resp[..n])?;

    // 3) Read the 2-byte NLEN at file offset 0.
    let n = exchange(&[0x00, READ_BINARY_INS, 0x00, 0x00, 0x02], &mut resp)?;
    check_status(&resp[..n])?;
    let nlen_frame = n.checked_sub(2).ok_or(NdefError::ShortRead)?;
    if nlen_frame < 2 {
        return Err(NdefError::ShortRead);
    }
    let nlen = ((resp[0] as usize) << 8) | (resp[1] as usize);
    if nlen == 0 {
        return Err(NdefError::InvalidLength);
    }
    if nlen > buf.len() {
        return Err(NdefError::BufferTooSmall);
    }

    // 4) Read the NDEF body (file offset 2), in <=255-byte chunks.
    let mut offset = 2usize;
    let mut written = 0usize;
    while written < nlen {
        let chunk = (nlen - written).min(0xFF);
        let apdu = [
            0x00,
            READ_BINARY_INS,
            (offset >> 8) as u8,
            (offset & 0xFF) as u8,
            chunk as u8,
        ];
        let n = exchange(&apdu, &mut resp)?;
        check_status(&resp[..n])?;
        let data_len = n.checked_sub(2).ok_or(NdefError::ShortRead)?;
        if data_len < chunk {
            return Err(NdefError::ShortRead);
        }
        buf[written..written + chunk].copy_from_slice(&resp[..chunk]);
        written += chunk;
        offset += chunk;
    }

    Ok(written)
}

/// Extract the URI payload from a decoded NDEF message.
///
/// Supports a single Well-Known `U` (URI) record with either a short
/// (<=255-byte) or long payload, as produced by the NTAG 424 DNA SUN mirror
/// configuration. Only the first record is considered, and its TYPE field must
/// be `'U'`.
pub fn extract_ndef_uri(ndef: &[u8]) -> Result<&str, NdefError> {
    if ndef.len() < 3 {
        return Err(NdefError::ShortRead);
    }

    let header = ndef[0];
    let type_len = ndef[1] as usize;
    let short_record = header & 0x10 != 0;

    let (payload_len, mut idx) = if short_record {
        (ndef[2] as usize, 3usize)
    } else {
        if ndef.len() < 6 {
            return Err(NdefError::ShortRead);
        }
        (
            u32::from_be_bytes([ndef[2], ndef[3], ndef[4], ndef[5]]) as usize,
            6usize,
        )
    };

    // TYPE field (must be a single 'U' byte for a URI record).
    let type_end = idx.checked_add(type_len).ok_or(NdefError::ShortRead)?;
    if type_end > ndef.len() {
        return Err(NdefError::ShortRead);
    }
    if type_len != 1 || ndef[idx] != b'U' {
        return Err(NdefError::NotUriRecord);
    }
    idx = type_end;

    let payload_end = idx.checked_add(payload_len).ok_or(NdefError::ShortRead)?;
    if payload_end > ndef.len() {
        return Err(NdefError::ShortRead);
    }
    if payload_len < 1 {
        return Err(NdefError::InvalidLength);
    }

    // First payload byte is the URI identifier code prefix; skip it.
    let uri_body = &ndef[idx + 1..payload_end];
    core::str::from_utf8(uri_body).map_err(|_| NdefError::InvalidUtf8)
}

#[cfg(test)]
mod ndef_tests {
    use super::*;

    /// Canonical SUN URI matching the verifier test vectors.
    const URI: &[u8] =
        b"access.10bit.works/?uid=04112233445566&c=000008&cmac=505C41A335A9B7DEF29D5959936FE7FE";

    /// Build a minimal NTAG NDEF file image: `[NLEN_hi, NLEN_lo] || message`.
    fn build_ndef_file(uri: &[u8]) -> heapless::Vec<u8, 320> {
        let payload_len = 1 + uri.len();
        let msg_len = 4 + payload_len;
        let mut file: heapless::Vec<u8, 320> = heapless::Vec::new();
        file.push((msg_len >> 8) as u8).unwrap();
        file.push((msg_len & 0xFF) as u8).unwrap();
        file.extend_from_slice(&[0xD1, 0x01, payload_len as u8, b'U'])
            .unwrap();
        file.push(0x04).unwrap(); // URI identifier code: https://
        file.extend_from_slice(uri).unwrap();
        file
    }

    #[test]
    fn test_read_ndef_message_and_extract_uri() {
        let file = build_ndef_file(URI);

        let mut mock = |apdu: &[u8], out: &mut [u8]| -> Result<usize, NdefError> {
            if apdu == &SELECT_NDEF_APP_APDU[..] || apdu == &SELECT_NDEF_FILE_02_APDU[..] {
                out[0] = 0x90;
                out[1] = 0x00;
                return Ok(2);
            }
            if apdu.len() == 5 && apdu[0] == 0x00 && apdu[1] == READ_BINARY_INS {
                let off = ((apdu[2] as usize) << 8) | (apdu[3] as usize);
                let le = apdu[4] as usize;
                if off > file.len() {
                    out[0] = 0x6B;
                    out[1] = 0x00;
                    return Ok(2);
                }
                let end = (off + le).min(file.len());
                let data = &file[off..end];
                out[..data.len()].copy_from_slice(data);
                out[data.len()] = 0x90;
                out[data.len() + 1] = 0x00;
                return Ok(data.len() + 2);
            }
            Err(NdefError::Transport)
        };

        let mut buf = [0u8; 256];
        let n = read_ndef_message(&mut mock, &mut buf).expect("read NDEF");
        let uri = extract_ndef_uri(&buf[..n]).expect("extract URI");
        assert_eq!(uri, core::str::from_utf8(URI).unwrap());

        let sun = parse_sun_url(uri).expect("parse SUN");
        assert_eq!(sun.counter, 8);
        assert_eq!(sun.uid, [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn test_read_ndef_message_rejects_bad_status() {
        let mut mock = |_apdu: &[u8], out: &mut [u8]| -> Result<usize, NdefError> {
            out[0] = 0x6A;
            out[1] = 0x82;
            Ok(2)
        };
        let mut buf = [0u8; 64];
        assert_eq!(
            read_ndef_message(&mut mock, &mut buf),
            Err(NdefError::Status(0x6A, 0x82))
        );
    }

    #[test]
    fn test_extract_ndef_uri_rejects_non_uri() {
        // Well-known record of type 'T' (text) is not a URI.
        let ndef = [0xD1, 0x01, 0x03, b'T', 0x02, b'h', b'i'];
        assert_eq!(extract_ndef_uri(&ndef), Err(NdefError::NotUriRecord));
    }
}
