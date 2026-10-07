#![no_std]

pub mod ntag424;
pub mod cmd;
pub mod auth_msg;

#[cfg(test)]
mod tests {
    use super::*;
    use ntag424::{parse_sun_url, SunParams};
    use auth_msg::build_auth_json;
    use cmd::parse_cmd;
    use heapless::String;

    // From access-control-verifier src/crypto.rs test context
    // MASTER_KEY: 00112233445566778899aabbccddeeff
    //
    // Counter 7 vector generated manually following NXP AN12196 Diversification & CMAC rules
    // uid = 04112233445566, counter = 7
    //
    // TagKey = AES-CMAC(MASTER_KEY, 0x01 || uid) 
    //        = AES-CMAC(00112233445566778899aabbccddeeff, 0104112233445566)
    //        = 3e4b77c570b54fc178a25c1cbcf38435
    //
    // Counter 7 CMAC = AES-CMAC(TagKey, uid || counter_bytes)
    //                = AES-CMAC(3e4b77c570b54fc178a25c1cbcf38435, 04112233445566 || 000007)
    //                = e343397b4d690772fc61d0a7611d6c08

    // Counter 8 CMAC (from access-control-verifier tests)
    // uid = 04112233445566, counter = 8
    //                = AES-CMAC(3e4b77c570b54fc178a25c1cbcf38435, 04112233445566 || 000008)
    //                = 505c41a335a9b7def29d5959936fe7fe

    #[test]
    fn test_parse_sun_url_c7_c_param() {
        let url = "https://access.10bit.works/?uid=04112233445566&c=000007&cmac=e343397b4d690772fc61d0a7611d6c08";
        let res = parse_sun_url(url).expect("valid c7 URL");
        
        assert_eq!(res.uid, [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(res.counter, 7);
        assert_eq!(res.cmac, [0xe3, 0x43, 0x39, 0x7b, 0x4d, 0x69, 0x07, 0x72, 0xfc, 0x61, 0xd0, 0xa7, 0x61, 0x1d, 0x6c, 0x08]);
    }

    #[test]
    fn test_parse_sun_url_c8_ctr_param_mixed_case() {
        let url = "https://access.10bit.works/?uid=04112233445566&ctr=000008&cmac=505C41A335a9b7def29d5959936FE7FE";
        let res = parse_sun_url(url).expect("valid c8 URL with ctr and mixed case hex");
        
        assert_eq!(res.uid, [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(res.counter, 8);
        assert_eq!(res.cmac, [0x50, 0x5c, 0x41, 0xa3, 0x35, 0xa9, 0xb7, 0xde, 0xf2, 0x9d, 0x59, 0x59, 0x93, 0x6f, 0xe7, 0xfe]);
    }

    #[test]
    fn test_parse_sun_url_missing_cmac() {
        let url = "https://access.10bit.works/?uid=04112233445566&c=000008";
        let res = parse_sun_url(url);
        assert_eq!(res, Err(ntag424::ParseError::MissingCmac));
    }

    #[test]
    fn test_parse_sun_url_bad_hex() {
        let url = "https://access.10bit.works/?uid=041122334455XX&c=000008&cmac=505C41A335A9B7DEF29D5959936FE7FE";
        let res = parse_sun_url(url);
        assert_eq!(res, Err(ntag424::ParseError::InvalidHexChar));
    }

    #[test]
    fn test_parse_sun_url_corrupted_cmac_length() {
        // Missing one hex char in CMAC
        let url = "https://access.10bit.works/?uid=04112233445566&c=000008&cmac=505C41A335A9B7DEF29D5959936FE7F";
        let res = parse_sun_url(url);
        assert_eq!(res, Err(ntag424::ParseError::InvalidLength));
    }

    #[test]
    fn test_build_auth_json_exact_fields() {
        let sun = SunParams {
            uid: [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            counter: 8,
            cmac: [0x50, 0x5C, 0x41, 0xA3, 0x35, 0xA9, 0xB7, 0xDE, 0xF2, 0x9D, 0x59, 0x59, 0x93, 0x6F, 0xE7, 0xFE],
        };
        let mut buf = String::<256>::new();
        build_auth_json("keygate-test", &sun, &mut buf).unwrap();
        
        assert_eq!(
            buf.as_str(),
            r#"{"reader":"keygate-test","uid":"04112233445566","counter":8,"cmac":"505c41a335a9b7def29d5959936fe7fe"}"#
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
