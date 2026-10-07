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
