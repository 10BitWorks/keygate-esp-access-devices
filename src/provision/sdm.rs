//! SDM (Secure Dynamic Messaging) configuration for the NDEF file.
//!
//! Builds the NDEF file image from the URL template, computes the mirror
//! offsets, encodes the `ChangeFileSettings` SDM block, and computes/verifies
//! the SUN CMAC exactly as the tag does.
//!
//! Access-rights wire order (NT4H2421Gx Table 73 / `ntag424` crate v0.1.1
//! `AccessRights::to_le_bytes` / pylibsdm `structs.py`):
//!
//! ```text
//! byte 0 = (read_write << 4) | change
//! byte 1 = (read       << 4) | write
//! ```
//!
//! Verified against hardware factory captures: the factory NDEF file reports
//! `E0 EE` ⇒ read=Free, write=Free, read_write=Free, change=Key0.
//!
//! This provisioning sets: read=Free (phones + idle reads must work),
//! write=NoAccess, read_write=Key0 (authenticated native rewrite stays
//! possible for recovery), change=Key0.

use crate::ntag424::aes_cmac;
use crate::provision::ProvisionError;

/// URI prefix code written into the NDEF URI record payload.
const HTTPS_PREFIX: &str = "https://";

/// Max NDEF file image we write (NTAG 424 NDEF file is 256 bytes; a single
/// ISO UPDATE BINARY APDU carries at most 255).
const MAX_FILE_LEN: usize = 255;

/// SDM mirror widths in ASCII chars (AN12196 §3.4).
const UID_W: usize = 14;
const CTR_W: usize = 6;
const MAC_W: usize = 16;

/// SDM mirror offsets within the NDEF file (byte 0 = first NLEN byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SunOffsets {
    /// First byte of the 14-ASCII-char UID mirror.
    pub uid: usize,
    /// First byte of the 6-ASCII-char read-counter mirror.
    pub read_ctr: usize,
    /// First byte of the CMAC input (= UID mirror start per AN12196 §3.4.4.2.2).
    pub mac_input: usize,
    /// First byte of the 16-ASCII-char CMAC mirror.
    pub mac: usize,
}

/// Successful provisioning outcome: the tag identity as read back through the
/// active SUN mirrors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionReport {
    /// 7-byte card UID (from the UID mirror).
    pub uid: [u8; 7],
    /// SUN read counter value (from the counter mirror).
    pub counter: u32,
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
/// placeholders are expanded to the mirror widths filled with `'0'` dummies —
/// the chip overwrites them with live values on every read.
pub(crate) fn ndef_file_from_template(
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

/// Access nibbles (NT4H2421Gx Table 66).
pub(crate) const ACCESS_KEY0: u8 = 0x0;
pub(crate) const ACCESS_FREE: u8 = 0xE;
pub(crate) const ACCESS_NO_ACCESS: u8 = 0xF;

/// Serialize the 18-byte SDM `ChangeFileSettings` block.
///
/// Wire order (Table 73 / pylibsdm `FileSettings::to_bytes`): `FileOption`,
/// `AccessRights(2)`, `SDMOptions`, `SDMAccessRights(2)`, then the enabled
/// 3-byte-LE offsets in the fixed order uid, read_ctr, mac_input, mac.
pub(crate) fn sdm_settings_bytes(o: &SunOffsets) -> [u8; 18] {
    sdm_settings_bytes_with_write(o, ACCESS_NO_ACCESS)
}

/// Serialize the 18-byte SDM `ChangeFileSettings` block with custom write access.
pub(crate) fn sdm_settings_bytes_with_write(o: &SunOffsets, write_access: u8) -> [u8; 18] {
    let mut s = [0u8; 18];
    s[0] = 0x40; // FileOption: SDM enabled (bit 6) | CommMode.PLAIN (bits 1..0)
    // AccessRights: byte0 = (read_write << 4) | change, byte1 = (read << 4) | write.
    s[1] = (ACCESS_KEY0 << 4) | ACCESS_KEY0; // read_write=Key0, change=Key0
    s[2] = (ACCESS_FREE << 4) | (write_access & 0x0F);
    s[3] = 0xC1; // SDMOptions: uid mirror (0x80) | read_ctr mirror (0x40) | ASCII (0x01)
    // SDMAccessRights: byte0 = RFU(0xF0) | ctr_ret, byte1 = (meta_read << 4) | file_read.
    s[4] = 0xF0 | ACCESS_FREE; // ctr_ret=free
    s[5] = (ACCESS_FREE << 4) | 0x1; // meta_read=free/plain, file_read=key 1 (SUN CMAC key)
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
/// `tag_key` is the SDM File Read MAC key (key 1 on our tags). Distinct from
/// the AUTH session SV2 (`0x5AA5 …`) in `ntag424`.
pub fn sun_session_key(tag_key: &[u8; 16], uid: &[u8; 7], counter: u32) -> [u8; 16] {
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
/// `AES-CMAC(sun_session_key(tag_key, uid, ctr), mac_input)` where `mac_input`
/// is the exact ASCII the tag signs (`uid14&c=ctr6&cmac=`).
pub(crate) fn sun_tag_cmac(tag_key: &[u8; 16], uid: &[u8; 7], counter: u32, mac_input: &[u8]) -> [u8; 8] {
    let session = sun_session_key(tag_key, uid, counter);
    sun_trunc_mac(&aes_cmac(&session, mac_input))
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

    /// Uppercase ASCII hex encoder (matches NXP SUN mirrors + the verifier).
    fn enc_hex_upper(out: &mut [u8], src: &[u8]) {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for (i, b) in src.iter().enumerate() {
            out[2 * i] = HEX[(b >> 4) as usize];
            out[2 * i + 1] = HEX[(b & 0x0f) as usize];
        }
    }

    /// Mirrors `TEMPLATE` (config is main-only: its `env!()` credentials cannot
    /// compile on the host test target).
    const TEMPLATE: &str = "https://keys.10bitworks.org/?uid=&c=&cmac=";

    #[test]
    fn test_template_offsets_and_ndef_image() {
        let mut file = [0u8; 258];
        let (len, o) = ndef_file_from_template(TEMPLATE, &mut file).expect("template parses");
        // Expanded body = 34 static + 36 mirror = 70 chars -> file 77 bytes.
        assert_eq!(len, 77);
        assert_eq!(o.uid, 32); // 7 + "?uid=" end in body (25)
        assert_eq!(o.read_ctr, o.uid + 14 + 3); // 14-char mirror + "&c="
        assert_eq!(o.mac, o.read_ctr + 6 + 6); // 6-char mirror + "&cmac="
        assert_eq!(o.mac_input, o.uid);
        assert_eq!(o.mac + 16, len); // CMAC mirror ends at EOF
        // Record image sanity.
        assert_eq!(file[0], 0x00);
        assert_eq!(file[1], 75); // NLEN = 4 hdr + 1 prefix + 70 body
        assert_eq!(&file[2..7], &[0xD1, 0x01, 71, b'U', 0x04]);
        assert_eq!(&file[7..12], b"keys.");
        assert_eq!(&file[28..32], b"uid=");
        assert_eq!(&file[32..46], b"00000000000000"); // uid dummy
        assert_eq!(&file[46..49], b"&c=");
        assert_eq!(&file[49..55], b"000000"); // counter dummy
        assert_eq!(&file[55..61], b"&cmac=");
        assert_eq!(&file[61..77], b"0000000000000000"); // cmac dummy
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

    /// Pins the AccessRights byte order against the hardware-proven layout
    /// (`E0 EE` at factory ⇒ read=Free, write=Free): byte0 = (rw << 4) | change,
    /// byte1 = (read << 4) | write. A regression back to the swapped order
    /// ([0xEF, 0xF0]) would decode as read=NoAccess, change=NoAccess — a
    /// card no phone could ever read — and fail here.
    #[test]
    fn test_sdm_settings_wire_bytes_and_access_rights_decode() {
        let o = SunOffsets { uid: 28, read_ctr: 45, mac_input: 28, mac: 57 };
        let s = sdm_settings_bytes(&o);
        assert_eq!(
            s,
            [
                0x40, // file option: SDM on, PLAIN
                0x00, 0xEF, // rw=Key0, change=Key0 | read=Free, write=NoAccess
                0xC1, // uid+read_ctr+ascii
                0xFE, 0xE1, // ctr_ret=E free, meta=E free, file_read=1
                28, 0, 0, // uid_offset LE24
                45, 0, 0, // read_ctr_offset
                28, 0, 0, // mac_input_offset
                57, 0, 0, // mac_offset
            ]
        );

        // Decode the two AR bytes exactly like the chip does.
        let read = s[2] >> 4;
        let write = s[2] & 0x0F;
        let read_write = s[1] >> 4;
        let change = s[1] & 0x0F;
        assert_eq!(read, 0xE, "read must be free or phones cannot read the SUN URL");
        assert_eq!(write, 0xF, "write must be NoAccess");
        assert_eq!(read_write, 0x0, "read_write stays Key0 for recovery");
        assert_eq!(change, 0x0, "change stays Key0");

        // Factory capture cross-check: E0 EE decodes read=Free, write=Free,
        // rw=Free, change=Key0 — proving this nibble layout.
        assert_eq!((0xEE >> 4, 0xEE & 0xF, 0xE0 >> 4, 0xE0 & 0xF), (0xE, 0xE, 0xE, 0x0));
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
}
