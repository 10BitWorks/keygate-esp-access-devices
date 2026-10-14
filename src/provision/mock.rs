//! Contract-faithful NTAG 424 DNA tag model (test-only).
//!
//! Models the chip's actual behavior, NOT our implementation's assumptions —
//! every rule below is pinned to the `ntag424` crate v0.1.1 (whose tests replay
//! hardware captures), the NT4H2421Gx datasheet, AN12196, or directly-observed
//! bench-card behavior. The end-to-end provisioning tests run against this
//! model, so a flow regression fails on the host instead of at the bench.
//!
//! Modeled contracts:
//! - ISO SELECT AID (`00 A4 04 00`) terminates any authenticated state.
//! - ISO SELECT E104 (`00 A4 00 0C 02 E1 04`) requires the AID selected first.
//! - ISO READ/UPDATE BINARY use **offset addressing only**; SFI addressing
//!   (`P1[7]=1`) answers `6A 82` (observed on the bench card).
//! - ISO READ/UPDATE BINARY are `CommMode.Plain` only: while an EV2 session is
//!   authenticated they answer `69 82` (§10.9.2 / §10.9.3).
//! - UPDATE BINARY requires free write access (factory default); after
//!   provisioning sets write=NoAccess it answers `69 82`.
//! - Native `AuthenticateEV2First` requires the application selected.
//! - Native ChangeKey/ChangeFileSettings require an authenticated session
//!   (`91 AE` otherwise); their response is `MACt(8) ‖ 91 00`.
//! - Any command-MAC or CRC32NK failure answers `91 1E` **and drops the
//!   authenticated state** — subsequent secure commands answer `91 AE`
//!   (observed on the bench card).
//! - ChangeFileSettings applies the access rights with the real nibble
//!   layout (byte0 = (rw<<4)|change, byte1 = (read<<4)|write) and resets the
//!   SDM read counter.
//! - Reads of the NDEF file inject the SDM mirrors (uid, counter, SUN CMAC
//!   computed with the card's key 1) and advance the read counter per read.

use crate::ntag424::{derive_session_keys, NdefError};
use crate::provision::crypto::{
    cbc_decrypt_inplace, cbc_encrypt_inplace, crc32_ieee, decrypt_command, response_mac,
    rotate_left16, verify_command_mac, NULL_IV,
};
use crate::provision::sdm::{sun_tag_cmac, SunOffsets};
use crate::provision::session::Session;
use crate::provision::{CHANGE_FILE_SETTINGS_INS, CHANGE_KEY_INS};

/// NDEF application DF name (§8.2.2).
const NDEF_AID: [u8; 7] = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];

/// NDEF file size (§8.2.1: default 256 bytes).
const FILE_SIZE: usize = 256;

pub(crate) struct MockTag {
    /// The card's fixed identity.
    pub uid: [u8; 7],
    /// Application selected (DF name).
    app_selected: bool,
    /// NDEF file (E104) selected.
    ef_selected: bool,
    /// Active authenticated session, if any.
    auth: Option<Session>,
    /// Key 0 (factory zeros — our flow never changes it).
    pub key0: [u8; 16],
    /// Key 1 (what provisioning sets; the SUN CMAC key).
    pub key1: [u8; 16],
    /// NDEF file image (256 bytes).
    pub file: [u8; FILE_SIZE],
    /// Decoded access rights after ChangeFileSettings: (read, write, rw, change).
    pub recorded_ar: Option<(u8, u8, u8, u8)>,
    /// SDM mirror offsets after ChangeFileSettings.
    pub sdm: Option<SunOffsets>,
    /// SDM read counter (advances per unauthenticated read; reset by CFS).
    pub read_ctr: u32,
    /// Fixed RndB (deterministic auth handshake).
    rndb: [u8; 16],
}

impl MockTag {
    pub(crate) fn new(uid: [u8; 7], rndb: [u8; 16]) -> Self {
        Self {
            uid,
            app_selected: false,
            ef_selected: false,
            auth: None,
            key0: [0u8; 16],
            key1: [0u8; 16],
            file: [0u8; FILE_SIZE],
            recorded_ar: None,
            sdm: None,
            read_ctr: 0,
            rndb,
        }
    }

    /// Pre-provision the card exactly as a previous successful run leaves it
    /// (file image written, settings applied, key 1 set) — the "enrolled
    /// card" recovery scenario.
    pub(crate) fn pre_provisioned(
        &mut self,
        job_key: &[u8; 16],
        offsets: &SunOffsets,
        image: &[u8],
    ) {
        self.key1 = *job_key;
        self.file[..image.len()].copy_from_slice(image);
        self.recorded_ar = Some((0xE, 0xF, 0x0, 0x0)); // read, write, rw, change
        self.sdm = Some(*offsets);
        self.read_ctr = 0;
    }

    fn sess(&self) -> Session {
        self.auth.expect("caller must check auth state")
    }

    /// `91 1E` — integrity error; drops the authenticated state (observed on
    /// the bench card).
    fn integrity_error(&mut self, out: &mut [u8]) -> Result<usize, NdefError> {
        self.auth = None;
        out[0] = 0x91;
        out[1] = 0x1E;
        Ok(2)
    }

    /// `MACt(8) ‖ 91 00` — successful secure-command response; advances CmdCtr.
    fn secure_ok(&mut self, out: &mut [u8]) -> Result<usize, NdefError> {
        let s = self.sess();
        let mact = response_mac(&s);
        out[..8].copy_from_slice(&mact);
        out[8] = 0x91;
        out[9] = 0x00;
        self.auth = Some(Session {
            cmdctr: s.cmdctr.wrapping_add(1),
            ..s
        });
        Ok(10)
    }

    /// Verify the command MAC of a native secure command. The frame layout is
    /// `hdr(1) ‖ ciphertext(32) ‖ MACt(8)` with `Lc = 41` (§9.1.10 Figure 9).
    fn verify_secure(&self, ins: u8, apdu: &[u8]) -> bool {
        let Some(s) = self.auth.as_ref() else {
            return false;
        };
        let lc = apdu[4] as usize;
        if lc != 1 + 32 + 8 {
            return false;
        }
        let frame = &apdu[5..5 + lc];
        let (hdr, rest) = frame.split_first().expect("lc checked above");
        verify_command_mac(s, ins, &[*hdr], rest).is_ok()
    }

    /// Decrypt the 32-byte ciphertext of a secure command (command-direction
    /// IVc) and strip the ISO 7816 padding.
    fn decrypt_frame(&self, apdu: &[u8], out: &mut [u8; 32]) -> bool {
        let s = self.sess();
        let ct = &apdu[6..6 + 32]; // apdu[5] = hdr, then 32 bytes ciphertext
        decrypt_command(&s, ct, out).is_ok()
    }

    pub(crate) fn handle(&mut self, apdu: &[u8], out: &mut [u8]) -> Result<usize, NdefError> {
        let ins = apdu[1];
        match (apdu[0], ins) {
            // ---- ISO SELECT -------------------------------------------------
            (0x00, 0xA4) => {
                if apdu[2] == 0x04 {
                    // Select by DF name: must address the NDEF application.
                    if apdu[5..5 + 7] != NDEF_AID[..] {
                        out[0] = 0x6A;
                        out[1] = 0x82;
                        return Ok(2);
                    }
                    // Re-selecting the application terminates the
                    // authenticated state.
                    self.auth = None;
                    self.app_selected = true;
                    self.ef_selected = false;
                    out[0] = 0x90;
                    out[1] = 0x00;
                    return Ok(2);
                }
                // Select EF by file ID (E104).
                if !self.app_selected || apdu[5..7] != [0xE1, 0x04] {
                    out[0] = 0x6A;
                    out[1] = 0x82;
                    return Ok(2);
                }
                self.ef_selected = true;
                out[0] = 0x90;
                out[1] = 0x00;
                Ok(2)
            }
            // ---- ISO UPDATE BINARY (§10.9.3) --------------------------------
            (0x00, 0xD6) => {
                // SFI addressing is not supported (bench-observed 6A 82).
                if apdu[2] & 0x80 != 0 {
                    out[0] = 0x6A;
                    out[1] = 0x82;
                    return Ok(2);
                }
                if !self.app_selected || !self.ef_selected {
                    out[0] = 0x6A;
                    out[1] = 0x82;
                    return Ok(2);
                }
                // Plain CommMode only: rejected while authenticated.
                if self.auth.is_some() {
                    out[0] = 0x69;
                    out[1] = 0x82;
                    return Ok(2);
                }
                // Free write access only (factory default). After
                // provisioning (write=NoAccess) the chip refuses.
                let write_ar = self.recorded_ar.map(|(_, w, _, _)| w).unwrap_or(0xE);
                if write_ar != 0xE {
                    out[0] = 0x69;
                    out[1] = 0x82;
                    return Ok(2);
                }
                let off = ((apdu[2] as usize) << 8) | apdu[3] as usize;
                let lc = apdu[4] as usize;
                if off + lc > FILE_SIZE {
                    out[0] = 0x69;
                    out[1] = 0x85;
                    return Ok(2);
                }
                self.file[off..off + lc].copy_from_slice(&apdu[5..5 + lc]);
                out[0] = 0x90;
                out[1] = 0x00;
                Ok(2)
            }
            // ---- ISO READ BINARY (§10.9.2) ----------------------------------
            (0x00, 0xB0) => {
                if apdu[2] & 0x80 != 0 {
                    out[0] = 0x6A;
                    out[1] = 0x82;
                    return Ok(2);
                }
                if !self.app_selected || !self.ef_selected {
                    out[0] = 0x6A;
                    out[1] = 0x82;
                    return Ok(2);
                }
                // Plain CommMode only: rejected while authenticated.
                if self.auth.is_some() {
                    out[0] = 0x69;
                    out[1] = 0x82;
                    return Ok(2);
                }
                let read_ar = self.recorded_ar.map(|(r, _, _, _)| r).unwrap_or(0xE);
                if read_ar != 0xE {
                    out[0] = 0x69;
                    out[1] = 0x82;
                    return Ok(2);
                }
                let off = ((apdu[2] as usize) << 8) | apdu[3] as usize;
                let le = if apdu[4] == 0 { 256 } else { apdu[4] as usize };
                if off > FILE_SIZE {
                    out[0] = 0x6A;
                    out[1] = 0x86;
                    return Ok(2);
                }

                // Build the read view with the live SDM mirrors injected.
                let mut view = [0u8; FILE_SIZE];
                view.copy_from_slice(&self.file);
                if let Some(o) = self.sdm {
                    let used = self.read_ctr;
                    let uid_hex = hex_upper14(&self.uid);
                    view[o.uid..o.uid + 14].copy_from_slice(&uid_hex);
                    let ctr_hex = hex_upper6(used);
                    view[o.read_ctr..o.read_ctr + 6].copy_from_slice(&ctr_hex);
                    // SUN CMAC mirror computed with key 1 over the exact
                    // mac input the tag signs.
                    let mut mac_input = [0u8; 29];
                    mac_input[..14].copy_from_slice(&uid_hex);
                    mac_input[14..17].copy_from_slice(b"&c=");
                    mac_input[17..23].copy_from_slice(&ctr_hex);
                    mac_input[23..].copy_from_slice(b"&cmac=");
                    let cmac = sun_tag_cmac(&self.key1, &self.uid, used, &mac_input);
                    view[o.mac..o.mac + 16].copy_from_slice(&hex_upper16(&cmac));
                    // The read counter advances per read command.
                    self.read_ctr = used.wrapping_add(1) & 0xFF_FFFF;
                }

                let end = (off + le).min(FILE_SIZE);
                let data = end - off;
                out[..data].copy_from_slice(&view[off..end]);
                out[data] = 0x90;
                out[data + 1] = 0x00;
                Ok(data + 2)
            }
            // ---- AuthenticateEV2First Part 1 --------------------------------
            (0x90, 0x71) => {
                if !self.app_selected {
                    out[0] = 0x91;
                    out[1] = 0x40; // NO_SUCH_KEY (no application selected)
                    return Ok(2);
                }
                let mut e = self.rndb;
                cbc_encrypt_inplace(&self.key0, &NULL_IV, &mut e);
                out[..16].copy_from_slice(&e);
                out[16] = 0x91;
                out[17] = 0xAF;
                Ok(18)
            }
            // ---- AuthenticateEV2First Part 2 --------------------------------
            (0x90, 0xAF) => {
                let lc = apdu[4] as usize;
                if lc != 32 {
                    return Err(NdefError::Transport);
                }
                let mut data = [0u8; 32];
                data.copy_from_slice(&apdu[5..5 + 32]);
                cbc_decrypt_inplace(&self.key0, &NULL_IV, &mut data);
                let mut rnda = [0u8; 16];
                rnda.copy_from_slice(&data[..16]);
                let mut rndb_p = [0u8; 16];
                rndb_p.copy_from_slice(&data[16..32]);
                if rndb_p != rotate_left16(&self.rndb) {
                    return self.integrity_error(out);
                }
                let ti = [0x11, 0x22, 0x33, 0x44];
                let sk = derive_session_keys(&self.key0, &rnda, &self.rndb);
                self.auth = Some(Session {
                    ti,
                    cmdctr: 0,
                    k_enc: sk.enc,
                    k_mac: sk.mac,
                });
                let mut resp = [0u8; 32];
                resp[0..4].copy_from_slice(&ti);
                resp[4..20].copy_from_slice(&rotate_left16(&rnda));
                cbc_encrypt_inplace(&self.key0, &NULL_IV, &mut resp);
                out[..32].copy_from_slice(&resp);
                out[32] = 0x91;
                out[33] = 0x00;
                Ok(34)
            }
            // ---- ChangeFileSettings (§10.7.1, MAC framing) -----------------
            (0x90, CHANGE_FILE_SETTINGS_INS) => {
                if self.auth.is_none() {
                    out[0] = 0x91;
                    out[1] = 0xAE; // not authenticated
                    return Ok(2);
                }
                if !self.verify_secure(ins, apdu) {
                    return self.integrity_error(out);
                }
                let mut plain = [0u8; 32];
                if !self.decrypt_frame(apdu, &mut plain) {
                    return self.integrity_error(out);
                }
                // Decode the settings block (our shape: 18 bytes).
                // byte0 = (rw << 4) | change, byte1 = (read << 4) | write.
                self.recorded_ar =
                    Some((plain[2] >> 4, plain[2] & 0x0F, plain[1] >> 4, plain[1] & 0x0F));
                let rd24 = |b: &[u8]| -> usize {
                    b[0] as usize | ((b[1] as usize) << 8) | ((b[2] as usize) << 16)
                };
                self.sdm = Some(SunOffsets {
                    uid: rd24(&plain[6..9]),
                    read_ctr: rd24(&plain[9..12]),
                    mac_input: rd24(&plain[12..15]),
                    mac: rd24(&plain[15..18]),
                });
                // Enabling SDM resets the read counter.
                self.read_ctr = 0;
                self.secure_ok(out)
            }
            // ---- ChangeKey (§10.6.1, FULL framing) --------------------------
            (0x90, CHANGE_KEY_INS) => {
                if self.auth.is_none() {
                    out[0] = 0x91;
                    out[1] = 0xAE; // not authenticated
                    return Ok(2);
                }
                if apdu[5] != 1 {
                    // Our flow only ever changes key 1.
                    return Err(NdefError::Transport);
                }
                if !self.verify_secure(ins, apdu) {
                    return self.integrity_error(out);
                }
                let mut plain = [0u8; 32];
                if !self.decrypt_frame(apdu, &mut plain) {
                    return self.integrity_error(out);
                }
                // Table 63 Case 1: (NewKey ⊕ OldKey) ‖ KeyVer ‖ CRC32NK.
                let mut new_key = [0u8; 16];
                for i in 0..16 {
                    new_key[i] = plain[i] ^ self.key1[i];
                }
                let expected_crc = crc32_ieee(&new_key);
                let got_crc = u32::from_le_bytes([plain[17], plain[18], plain[19], plain[20]]);
                if expected_crc != got_crc {
                    // Wrong old-key XOR: integrity error + auth dropped.
                    return self.integrity_error(out);
                }
                self.key1 = new_key;
                self.secure_ok(out)
            }
            _ => Err(NdefError::Transport),
        }
    }
}

// Uppercase ASCII hex helpers with fixed-size outputs (no_std, NXP encoding).
fn hex_upper14(src: &[u8]) -> [u8; 14] {
    let mut out = [0u8; 14];
    hex_into(&mut out, src);
    out
}

fn hex_upper6(counter: u32) -> [u8; 6] {
    let b = counter.to_be_bytes();
    let mut out = [0u8; 6];
    hex_into(&mut out, &b[1..4]);
    out
}

fn hex_upper16(src: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    hex_into(&mut out, src);
    out
}

fn hex_into(out: &mut [u8], src: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (i, b) in src.iter().enumerate() {
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_helpers_match_nxp_encoding() {
        assert_eq!(&hex_upper14(&[0x04, 0x65, 0x22, 0xCA, 0xBC, 0x5D, 0x80]), b"046522CABC5D80");
        assert_eq!(&hex_upper6(1), b"000001");
        assert_eq!(&hex_upper6(0xFFFFFF), b"FFFFFF");
    }
}
