#![no_std]

pub mod ntag424;
pub mod cmd;
pub mod auth_msg;
pub mod reader_supervisor;
pub mod piezo;

#[cfg(test)]
mod tests {
    use super::*;
    use ntag424::{parse_sun_url, SunParams};
    use auth_msg::build_auth_json;
    use cmd::parse_cmd;
    use heapless::String;

    // SUN goldens pinned by T1 from the pylibsdm reference oracle
    // (access-control-verifier/scripts/sun_golden.py, master
    // 000102030405060708090a0b0c0d0e0f). The mirror field is fixed-width,
    // zero-padded, case-insensitive hex:
    //   uid 04112233445566, ctr 000008 (8)  -> cmac 8A4E1B1A46979F04
    //   uid 04112233445566, ctr 00000B (11) -> cmac 408A4C5B0FB4711F
    // The earlier hand-computed naive-CMAC vectors were wrong and are gone.

    #[test]
    fn test_parse_sun_url_c_param() {
        let url =
            "https://access.10bit.works/k?uid=04112233445566&c=000008&cmac=8A4E1B1A46979F04";
        let res = parse_sun_url(url).expect("valid c URL");

        assert_eq!(res.uid, [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(res.counter, 8);
        assert_eq!(res.cmac, [0x8A, 0x4E, 0x1B, 0x1A, 0x46, 0x97, 0x9F, 0x04]);
        assert_eq!(&res.counter_mirror, b"000008");
    }

    #[test]
    fn test_parse_sun_url_ctr_param_mixed_case_hex() {
        // ctr 11 mirrors as fixed-width hex 00000B (not decimal 000011); the
        // hex field is case-insensitive and the raw bytes are kept verbatim.
        let url =
            "https://access.10bit.works/k?uid=04112233445566&ctr=00000b&cmac=408a4c5b0fb4711f";
        let res = parse_sun_url(url).expect("valid ctr URL with mixed case hex");

        assert_eq!(res.uid, [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(res.counter, 11);
        assert_eq!(res.cmac, [0x40, 0x8A, 0x4C, 0x5B, 0x0F, 0xB4, 0x71, 0x1F]);
        assert_eq!(&res.counter_mirror, b"00000b");
    }

    #[test]
    fn test_parse_sun_url_missing_cmac() {
        let url = "https://access.10bit.works/k?uid=04112233445566&c=000008";
        let res = parse_sun_url(url);
        assert_eq!(res, Err(ntag424::ParseError::MissingCmac));
    }

    #[test]
    fn test_parse_sun_url_bad_hex() {
        let url = "https://access.10bit.works/k?uid=041122334455XX&c=000008&cmac=8A4E1B1A46979F04";
        let res = parse_sun_url(url);
        assert_eq!(res, Err(ntag424::ParseError::InvalidHexChar));
    }

    #[test]
    fn test_parse_sun_url_corrupted_cmac_length() {
        // 15 hex chars: an odd/short CMAC mirror is rejected.
        let url = "https://access.10bit.works/k?uid=04112233445566&c=000008&cmac=8A4E1B1A46979F0";
        let res = parse_sun_url(url);
        assert_eq!(res, Err(ntag424::ParseError::InvalidLength));
    }

    #[test]
    fn test_parse_sun_url_rejects_legacy_32_hex_cmac() {
        // The old naive 16-byte CMAC mirror (32 hex) is no longer valid: the
        // real NTAG 424 SUN mirrors an 8-byte truncated CMAC (16 hex only).
        let url = "https://access.10bit.works/k?uid=04112233445566&c=000008&cmac=505C41A335A9B7DEF29D5959936FE7FE";
        let res = parse_sun_url(url);
        assert_eq!(res, Err(ntag424::ParseError::InvalidLength));
    }

    #[test]
    fn test_build_auth_json_exact_fields() {
        let sun = SunParams {
            uid: [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            counter: 8,
            cmac: [0x8A, 0x4E, 0x1B, 0x1A, 0x46, 0x97, 0x9F, 0x04],
            counter_mirror: *b"000008",
        };
        let mut buf = String::<256>::new();
        build_auth_json("keygate-test", &sun, &mut buf).unwrap();

        assert_eq!(
            buf.as_str(),
            r#"{"reader":"keygate-test","uid":"04112233445566","counter":8,"cmac":"8a4e1b1a46979f04"}"#
        );
    }

    #[test]
    fn test_parse_cmd_happy_grant() {
        let json = r#"{"grant":true,"reason":"Valid credential","pulse_ms":500}"#;
        let cmd = parse_cmd(json).expect("valid cmd json");
        assert_eq!(cmd.grant, true);
        assert_eq!(cmd.reason, "Valid credential");
        assert_eq!(cmd.pulse_ms, 500);
    }

    #[test]
    fn test_parse_cmd_happy_deny() {
        let json = r#"{"grant":false,"reason":"Unknown credential","pulse_ms":0}"#;
        let cmd = parse_cmd(json).expect("valid cmd json");
        assert_eq!(cmd.grant, false);
        assert_eq!(cmd.reason, "Unknown credential");
        assert_eq!(cmd.pulse_ms, 0);
    }

    #[test]
    fn test_parse_cmd_malformed_missing_field() {
        let json = r#"{"grant":true,"pulse_ms":500}"#; // missing reason
        let res = parse_cmd(json);
        assert!(res.is_err());
    }
}
