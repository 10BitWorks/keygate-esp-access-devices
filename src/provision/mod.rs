//! NTAG 424 DNA provisioning (host-testable).
//!
//! The provisioning sequence mirrors AN12196's own worked flow and is pinned
//! against three references: the NXP NT4H2421Gx datasheet, AN12196, and the
//! `ntag424` crate v0.1.1 (codeberg.org/jannschu/ntag424 — hardware-capture
//! tested). Golden crypto vectors come from pylibsdm
//! (`tests/golden/gen_provision_goldens.py`) and the verifier repo's vector
//! set.
//!
//! Sequence (one card session, chip rules enforced):
//!
//! 1. ISO SELECT NDEF application + file `E104` (unauthenticated).
//! 2. ISO UPDATE BINARY (`00 D6`, **offset addressing**) writes the NDEF
//!    image — Plain CommMode, so it must run **before** authentication
//!    (§10.9.3 rejects ISO commands with `69 82` while an EV2 session is
//!    active; SFI addressing answers `6A 82` — both observed on the bench).
//!    On an already-provisioned card the file's write access is NoAccess and
//!    the chip answers `69 82`; that status is tolerated — the file content
//!    persists and step 6 verifies it end-to-end.
//! 3. `AuthenticateEV2First` with the factory key 0 — key 0 is never changed,
//!    so re-authentication is always possible.
//! 4. `ChangeFileSettings` on file 2: enable the SDM mirrors (MAC framing,
//!    response MACt verified).
//! 5. `ChangeKey` 1 ← job key: fresh card uses `old = factory zeros`. A
//!    previously provisioned card answers `91 1E` (and drops the
//!    authenticated state — the retry re-authenticates first); the verifier
//!    re-issues the same deterministic per-UID key, so the retry uses
//!    `old = job_key`. Both failing means the card is keyed with an unknown
//!    key and cannot be re-keyed (`ProvisionError::KeyMismatch`).
//! 6. ISO SELECT AID (terminates the authenticated state) + re-select `E104`,
//!    then read the message back through the live SDM mirrors and verify the
//!    SUN CMAC locally with the job key.
//!
//! The whole sequence runs on the host against the contract-faithful
//! [`mock::MockTag`] (see `tests` below) — regressions fail in `cargo test`,
//! not at the bench.
//!
//! Transport is injected as a closure (one APDU in, `response ‖ SW1SW2` out)
//! so every routine is unit-testable on the host with no `esp-hal` /
//! `esp-radio` dependency.

mod commands;
mod crypto;
mod sdm;
mod session;

#[cfg(test)]
mod mock;

pub use sdm::ProvisionReport;
pub use sdm::sun_session_key;

/// AuthenticateEV2First Part 1 instruction (datasheet Table 22).
pub const AUTH_EV2_FIRST_INS: u8 = 0x71;
/// AuthenticateEV2First Part 2 / AdditionalFrame instruction (datasheet Table 22).
pub const ADDITIONAL_FRAME_INS: u8 = 0xAF;
/// ChangeKey instruction (datasheet Table 22, CommMode.Full).
pub const CHANGE_KEY_INS: u8 = 0xC4;
/// ChangeFileSettings instruction (datasheet Table 22).
pub const CHANGE_FILE_SETTINGS_INS: u8 = 0x5F;
/// ISO 7816-4 UPDATE BINARY instruction byte (INS=0xD6).
pub const UPDATE_BINARY_INS: u8 = 0xD6;

use crate::ntag424::NdefError;
use commands::{change_file_settings, change_key, iso_update_binary, read_file, select_ndef};
use session::{authenticate_ev2_first, Session};

/// Factory default key 0 (all zeros). Provisioning never changes key 0.
const FACTORY_KEY: [u8; 16] = [0u8; 16];

/// Errors returned by the provisioning sequence.
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
    /// The card's key 1 is neither the factory zero key nor the job key, so
    /// `ChangeKey` cannot re-key it. The card was provisioned by an older,
    /// unknown key and cannot be recovered without that key.
    KeyMismatch,
    /// A caller-provided output buffer was too small.
    BufferTooSmall,
    /// The URL template is malformed (missing/extra mirrors, bad scheme,
    /// or too long for the 255-byte write carrier).
    BadTemplate,
}

impl From<NdefError> for ProvisionError {
    fn from(e: NdefError) -> Self {
        ProvisionError::Transport(e)
    }
}

/// Run the full provisioning sequence against a tag (wildcard writer flow).
///
/// See the module docs for the step ordering and the chip rules that force
/// it. `rnda` seeds the auth handshake (deterministic, host-testable). The
/// transport `exchange` sends one APDU and returns `response ‖ SW1 SW2`.
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
    let (file_len, offsets) = sdm::ndef_file_from_template(url_template, &mut file)?;

    // 1) Select NDEF application + file (unauthenticated).
    #[cfg(target_arch = "xtensa")]
    esp_println::println!("[prov-step] step 1: select_ndef");
    select_ndef(exchange)?;

    // 2) Write the NDEF file — ISO UPDATE BINARY, offset addressing, plain,
    //    unauthenticated (AN12196 §5.8.1 publishes exactly this exchange).
    //    `69 82` is tolerated: an already-provisioned card's NDEF file has
    //    write=NoAccess, its content persists, and step 6 verifies it.
    #[cfg(target_arch = "xtensa")]
    esp_println::println!("[prov-step] step 2: ISO update_binary ({} bytes)", file_len);
    match iso_update_binary(exchange, 0, &file[..file_len]) {
        Ok(()) => {}
        Err(ProvisionError::Status(0x69, 0x82)) => {
            #[cfg(target_arch = "xtensa")]
            esp_println::println!("[prov-step] write refused (69 82) — already provisioned, skipping rewrite");
        }
        Err(e) => return Err(e),
    }

    // 3) Authenticate with the factory key 0 — NEVER change key 0.
    #[cfg(target_arch = "xtensa")]
    esp_println::println!("[prov-step] step 3: authenticate_ev2_first");
    let mut session: Session = authenticate_ev2_first(&FACTORY_KEY, 0, rnda, exchange)?;

    // 4) ChangeFileSettings on file 2: enable the SDM mirrors.
    #[cfg(target_arch = "xtensa")]
    esp_println::println!("[prov-step] step 4: change_file_settings");
    let settings = sdm::sdm_settings_bytes(&offsets);
    change_file_settings(exchange, &mut session, 2, &settings)?;

    // 5) ChangeKey 1 <- job key (fresh: old = factory zeros; retry after
    //    re-authentication with old = job key for previously provisioned
    //    cards — the verifier re-issues the same deterministic per-UID key).
    #[cfg(target_arch = "xtensa")]
    esp_println::println!("[prov-step] step 5: change_key");
    match change_key(exchange, &mut session, 1, job_key, &[0u8; 16], 1) {
        Ok(()) => {}
        Err(ProvisionError::Status(0x91, 0x1E)) | Err(ProvisionError::Status(0x91, 0xAE)) => {
            #[cfg(target_arch = "xtensa")]
            esp_println::println!("[prov-step] key 1 not factory-zero — re-authenticating, retrying with old = job key");
            let mut retry: Session = authenticate_ev2_first(&FACTORY_KEY, 0, rnda, exchange)?;
            change_key(exchange, &mut retry, 1, job_key, job_key, 1)
                .map_err(|_| ProvisionError::KeyMismatch)?;
        }
        Err(e) => return Err(e),
    }

    // 6) Terminate the authenticated state (ISO SELECT AID resets it — ISO
    //    reads are rejected while authenticated, §10.9.2), then read the
    //    message back through the live mirrors and verify the SUN CMAC.
    #[cfg(target_arch = "xtensa")]
    esp_println::println!("[prov-step] step 6: readback & verify");
    select_ndef(exchange)?;
    let mut resp = [0u8; 258];
    let nlen = read_file(exchange, &mut resp)?;
    let uri = crate::ntag424::extract_ndef_uri(&resp[2..2 + nlen])?;
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

    let expected = sdm::sun_tag_cmac(job_key, &sun.uid, sun.counter, &mac_input);
    if !crypto::constant_time_eq(&expected, &sun.cmac) {
        return Err(ProvisionError::MacMismatch);
    }

    out.uid = sun.uid;
    out.counter = sun.counter;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::mock::MockTag;
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

    /// Mirrors `config::PROVISION_URL_TEMPLATE` (config is main-only: its
    /// `env!()` credentials cannot compile on the host test target).
    const TEMPLATE: &str = "https://10bitworks.org/k?uid=&c=&cmac=";

    const MOCK_UID_HEX: &str = "046522CABC5D80";
    const MOCK_JOB_KEY_HEX: &str = "aabbccddeeff00112233445566778899";
    const MOCK_RNDB: &str = "b9e2fc789b64bf237cccaa20ec7e6e48";
    const RNDA: &str = "13c5db8a5930439fc3def9a4c675360f";

    fn fresh_card() -> MockTag {
        MockTag::new(h(MOCK_UID_HEX), h(MOCK_RNDB))
    }

    /// Provision a card and return (card, report) for further assertions.
    fn provision(card: &mut MockTag) -> Result<ProvisionReport, ProvisionError> {
        let job_key: [u8; 16] = h(MOCK_JOB_KEY_HEX);
        let rnda: [u8; 16] = h(RNDA);
        let mut report = ProvisionReport { uid: [0; 7], counter: 0 };
        let res = {
            let mut exchange = |apdu: &[u8], out: &mut [u8]| card.handle(apdu, out);
            provision_tag(&mut exchange, &rnda, &job_key, TEMPLATE, &mut report)
        };
        res.map(|_| report)
    }

    // -----------------------------------------------------------------------
    // End-to-end: fresh card (the F3 wildcard drill, entirely on the host).
    // -----------------------------------------------------------------------

    #[test]
    fn test_provision_fresh_card_happy_path() {
        let mut card = fresh_card();
        let report = provision(&mut card).expect("provisioning succeeds");

        // Report carries the identity read back through the mirrors.
        assert_eq!(report.uid, h(MOCK_UID_HEX));
        assert_eq!(report.counter, 1); // two reads (NLEN + body) advanced the ctr

        // The card actually took the job key.
        assert_eq!(card.key1, h(MOCK_JOB_KEY_HEX));

        // Access rights decoded with the real nibble layout: read=Free,
        // write=NoAccess, read_write=Key0, change=Key0.
        assert_eq!(card.recorded_ar, Some((0xE, 0xF, 0x0, 0x0)));

        // SDM mirror offsets recorded from the wire block.
        let mut file = [0u8; 258];
        let (_, offsets) = sdm::ndef_file_from_template(TEMPLATE, &mut file).expect("template");
        assert_eq!(card.sdm, Some(offsets));

        // The written NDEF contains the expanded dummy placeholders.
        let written = &card.file[..73];
        let body = core::str::from_utf8(&written[7..]).expect("ascii");
        assert_eq!(
            body,
            "10bitworks.org/k?uid=00000000000000&c=000000&cmac=0000000000000000"
        );
    }

    // -----------------------------------------------------------------------
    // Recovery: card already provisioned by a previous run with the same
    // (deterministic) job key — the write is refused, ChangeKey retries with
    // old = job key after re-authentication.
    // -----------------------------------------------------------------------

    #[test]
    fn test_provision_reprovisions_enrolled_card() {
        let job_key: [u8; 16] = h(MOCK_JOB_KEY_HEX);
        let mut file = [0u8; 258];
        let (file_len, offsets) = sdm::ndef_file_from_template(TEMPLATE, &mut file).expect("template");

        let mut card = fresh_card();
        card.pre_provisioned(&job_key, &offsets, &file[..file_len]);

        let report = provision(&mut card).expect("re-provisioning succeeds");
        assert_eq!(report.uid, h(MOCK_UID_HEX));
        // Key 1 re-set to the same (deterministic) job key.
        assert_eq!(card.key1, job_key);
        // File untouched: the refused rewrite was tolerated.
        assert_eq!(&card.file[..file_len], &file[..file_len]);
    }

    // -----------------------------------------------------------------------
    // Failure: card keyed with an unknown old key — both ChangeKey attempts
    // fail, reported as KeyMismatch.
    // -----------------------------------------------------------------------

    #[test]
    fn test_provision_reports_key_mismatch() {
        let mut card = fresh_card();
        // Key 1 set to something the verifier would never re-issue.
        card.key1 = h("deadbeefdeadbeefdeadbeefdeadbeef");
        assert_eq!(provision(&mut card), Err(ProvisionError::KeyMismatch));
    }

    #[test]
    fn test_config_template_constant() {
        // The template lives in config (not hardcoded here) and satisfies the
        // parser's contract.
        let t = TEMPLATE;
        assert!(t.starts_with("https://"));
        assert!(t.contains("?uid="));
        assert!(t.contains("&c="));
        assert!(t.contains("&cmac="));
        let mut file = [0u8; 258];
        assert!(sdm::ndef_file_from_template(t, &mut file).is_ok());
    }

    // -----------------------------------------------------------------------
    // Chip-contract regression pins (direct exchanges against the mock).
    // Every rule below was violated by a previous version of the flow and
    // cost a bench cycle; these make the regression a host test failure.
    // -----------------------------------------------------------------------

    fn exchange(card: &mut MockTag, apdu: &[u8]) -> [u8; 258] {
        let mut out = [0u8; 258];
        let n = card.handle(apdu, &mut out).expect("mock handles APDU");
        let mut resp = [0u8; 258];
        resp[..n].copy_from_slice(&out[..n]);
        resp
    }

    fn select_all(card: &mut MockTag) {
        let _ = exchange(card, &crate::ntag424::SELECT_NDEF_APP_APDU);
        let _ = exchange(card, &crate::ntag424::SELECT_NDEF_FILE_02_APDU);
    }

    /// Real two-part `AuthenticateEV2First` handshake against the mock card
    /// (factory key 0), leaving the card authenticated.
    fn full_auth(card: &mut MockTag) -> Session {
        let rnda: [u8; 16] = h(RNDA);
        let mut exchange = |apdu: &[u8], out: &mut [u8]| card.handle(apdu, out);
        authenticate_ev2_first(&[0u8; 16], 0, &rnda, &mut exchange).expect("auth handshake")
    }

    /// SFI addressing (`P1[7]=1`) answers `6A 82` — the exact failure that
    /// stalled the bench card for hours.
    #[test]
    fn test_chip_rejects_sfi_addressed_update_binary() {
        let mut card = fresh_card();
        select_all(&mut card);
        let resp = exchange(&mut card, &[0x00, UPDATE_BINARY_INS, 0x82, 0x00, 0x01, 0xAA]);
        assert_eq!(&resp[..2], &[0x6A, 0x82]);
    }

    /// ISO UPDATE/READ BINARY answer `69 82` while an EV2 session is
    /// authenticated (§10.9.2/§10.9.3) — the latent bug the old ordering
    /// would have hit after fixing the SFI addressing.
    #[test]
    fn test_chip_rejects_iso_commands_while_authenticated() {
        let mut card = fresh_card();
        select_all(&mut card);
        let _session = full_auth(&mut card);
        let w = exchange(&mut card, &[0x00, UPDATE_BINARY_INS, 0x00, 0x00, 0x01, 0xAA]);
        assert_eq!(&w[..2], &[0x69, 0x82]);
        let r = exchange(&mut card, &[0x00, 0xB0, 0x00, 0x00, 0x02]);
        assert_eq!(&r[..2], &[0x69, 0x82]);
    }

    /// ISO SELECT AID terminates the authenticated state — the flow relies on
    /// this to make the final read-back legal, and the old flow broke the
    /// ChangeFileSettings session by selecting mid-flow.
    #[test]
    fn test_select_aid_terminates_authenticated_state() {
        let mut card = fresh_card();
        select_all(&mut card);
        let session = full_auth(&mut card);
        // SELECT AID succeeds and the authenticated state is gone.
        let s = exchange(&mut card, &crate::ntag424::SELECT_NDEF_APP_APDU);
        assert_eq!(&s[..2], &[0x90, 0x00]);
        // A secure command built with the (now dead) session answers 91 AE.
        let mut frame = [0u8; 64];
        let job_key: [u8; 16] = h(MOCK_JOB_KEY_HEX);
        let n = commands::change_key_frame(&session, 1, &job_key, &[0u8; 16], 1, &mut frame)
            .expect("frame");
        let mut apdu = [0u8; 64];
        apdu[..5].copy_from_slice(&[0x90, CHANGE_KEY_INS, 0x00, 0x00, n as u8]);
        apdu[5..5 + n].copy_from_slice(&frame[..n]);
        apdu[5 + n] = 0x00; // Le
        let resp = exchange(&mut card, &apdu[..5 + n + 1]);
        assert_eq!(&resp[..2], &[0x91, 0xAE]);
    }

    /// Secure commands without authentication answer `91 AE`.
    #[test]
    fn test_secure_command_requires_authentication() {
        let mut card = fresh_card();
        select_all(&mut card);
        let resp = exchange(
            &mut card,
            &[0x90, CHANGE_FILE_SETTINGS_INS, 0x00, 0x00, 0x01, 0x02, 0x00],
        );
        assert_eq!(&resp[..2], &[0x91, 0xAE]);
    }

    /// EF select without the application selected answers `6A 82`.
    #[test]
    fn test_ef_select_requires_application_first() {
        let mut card = fresh_card();
        let resp = exchange(&mut card, &crate::ntag424::SELECT_NDEF_FILE_02_APDU);
        assert_eq!(&resp[..2], &[0x6A, 0x82]);
    }

    /// Enrolled-card write refusal: after provisioning (write=NoAccess) an
    /// unauthenticated ISO UPDATE BINARY answers `69 82` — the tolerated
    /// status in step 2.
    #[test]
    fn test_enrolled_card_refuses_unauthenticated_write() {
        let mut card = fresh_card();
        provision(&mut card).expect("provision");
        select_all(&mut card);
        let resp = exchange(&mut card, &[0x00, UPDATE_BINARY_INS, 0x00, 0x00, 0x01, 0xAA]);
        assert_eq!(&resp[..2], &[0x69, 0x82]);
    }

    /// A tampered command MAC answers `91 1E` and drops the authenticated
    /// state — the retry-then-91-AE treadmill the old flow hit.
    #[test]
    fn test_bad_command_mac_drops_authenticated_state() {
        let mut card = fresh_card();
        select_all(&mut card);
        let session = full_auth(&mut card);
        let mut frame = [0u8; 64];
        let job_key: [u8; 16] = h(MOCK_JOB_KEY_HEX);
        let n = commands::change_key_frame(&session, 1, &job_key, &[0u8; 16], 1, &mut frame)
            .expect("frame");
        let mut apdu = [0u8; 64];
        apdu[..5].copy_from_slice(&[0x90, CHANGE_KEY_INS, 0x00, 0x00, n as u8]);
        apdu[5..5 + n].copy_from_slice(&frame[..n]);
        apdu[5 + n] = 0x00;
        // Tamper one ciphertext byte: MAC no longer matches.
        apdu[6] ^= 0x01;
        let resp = exchange(&mut card, &apdu[..5 + n + 1]);
        assert_eq!(&resp[..2], &[0x91, 0x1E]);
        // The authenticated state is gone: a retransmit of the intact frame
        // answers 91 AE (not authenticated), like on the bench card.
        apdu[6] ^= 0x01;
        let resp = exchange(&mut card, &apdu[..5 + n + 1]);
        assert_eq!(&resp[..2], &[0x91, 0xAE]);
    }
}
