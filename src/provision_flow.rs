//! Provisioning session state machine (host-testable, T7).
//!
//! Drives the tap-to-enroll flow on a writer-role node:
//!
//! ```text
//!        job msg                 tap (wildcard)              claim reply
//! Idle ────────────────▶ Armed ───────────────────▶ ClaimWait ────────────▶ Provisioning
//!  ▲                     │  ▲    tap (fixed-uid match)                    │
//!  │  timeout (silent)   │  └── tap rejected (uid mismatch, stays Armed)  │ ok / err (done)
//!  └─────────────────────┴────────────────────────────────────────────────┘
//! ```
//!
//! Pure logic only: the caller (node.rs) performs all side effects — MQTT
//! publishes, piezo events, the actual `provision::provision_tag` run — from
//! the returned [`ProvAction`]. Every decision is host-unit-testable.

use core::fmt::Write;
use heapless::String;
use serde::Deserialize;

/// Maximum job-id length (verifier sends 32 hex chars).
pub const JOB_ID_MAX: usize = 32;
/// Maximum uid length (14 hex chars).
pub const UID_HEX_MAX: usize = 14;
/// Maximum key length (32 hex chars = 16 bytes).
pub const KEY_HEX_MAX: usize = 32;

/// Inbound job payload from `writer/<device>/job`.
///
/// `key` is empty on a wildcard arming payload; the real diversified key
/// arrives with the claim reply. `expires_at` is informational — the node
/// enforces its own [`crate::config::PROVISION_WINDOW_SECS`] window.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct JobPayload<'a> {
    pub uid: &'a str,
    pub key: &'a str,
    pub job_id: &'a str,
    pub expires_at: &'a str,
}

/// A stored provisioning job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingJob {
    pub job_id: String<JOB_ID_MAX>,
    /// `None` = wildcard (bind on tap). `Some` = fixed-uid job.
    pub uid: Option<String<UID_HEX_MAX>>,
    /// Diversified key hex (empty until the claim reply for wildcards).
    pub key_hex: String<KEY_HEX_MAX>,
    /// Absolute node-time (ms) after which the job silently lapses.
    pub deadline_ms: u64,
}

/// Parse an inbound job payload into storage form.
///
/// Returns `None` on malformed JSON, over-long fields, or a key that is
/// neither empty nor exactly 32 hex chars.
pub fn parse_job(
    payload: &str,
    now_ms: u64,
    window_secs: u64,
) -> Option<PendingJob> {
    let (jp, _): (JobPayload, _) = serde_json_core::from_str(payload).ok()?;
    let mut job_id = String::new();
    job_id.push_str(jp.job_id).ok()?;
    let uid = if jp.uid.is_empty() {
        None
    } else {
        let mut u = String::new();
        u.push_str(jp.uid).ok()?;
        Some(u)
    };
    let mut key_hex = String::new();
    key_hex.push_str(jp.key).ok()?;
    if !key_hex.is_empty() && (key_hex.len() != 32 || key_hex.as_bytes().iter().any(|b| !b.is_ascii_hexdigit())) {
        return None;
    }
    if job_id.is_empty() || job_id.len() > JOB_ID_MAX {
        return None;
    }
    Some(PendingJob {
        job_id,
        uid,
        key_hex,
        deadline_ms: now_ms + window_secs * 1000,
    })
}

/// Inbound claim reply from `writer/<device>/job` while in ClaimWait.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ClaimPayload<'a> {
    pub uid: &'a str,
    pub key: &'a str,
    pub job_id: &'a str,
}

/// Provisioning state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvState {
    /// No job. Only here are new jobs accepted.
    Idle,
    /// Job armed; waiting for a tag tap.
    Armed(PendingJob),
    /// Wildcard claim published; waiting for the keyed re-publish.
    /// The third field is the absolute claim deadline (ms).
    ClaimWait(PendingJob, [u8; 7], u64),
    /// `provision_tag` running (the node drives it; the machine just holds
    /// the context so the completion path can report).
    Provisioning(PendingJob, [u8; 7]),
}

/// What the caller should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvAction {
    /// Nothing to do.
    None,
    /// A job was accepted: beep ProvisionArmed, switch LED.
    Arm,
    /// A second job arrived while busy: log + deny beep, keep current job.
    IgnoreSecond,
    /// A tap was rejected (fixed-uid mismatch): deny beep, stay Armed.
    TapRejected,
    /// Publish this claim JSON to `writer/<device>/claim` and wait.
    PublishClaim(String<{ CLAIM_JSON_MAX }>),
    /// Run `provision_tag` with the pending key.
    ProvisionStart,
    /// Job completed: publish done(ok, counter) + ProvisionOk beep.
    CompleteOk(String<JOB_ID_MAX>, u32),
    /// Job failed: publish done(ok:false, reason) + ProvisionFail beep.
    Fail(String<JOB_ID_MAX>, &'static str),
    /// Window lapsed: go Idle silently (no done publish — the server-side
    /// TTL lapses on its own).
    LapseSilent,
}

/// Upper bound for the claim JSON `{"job_id":"<32>","uid":"<14>"}`.
// 69 bytes for a real 32-hex job_id + 7-byte uid (was 64 — silently
/// truncated, and the verifier rejected the claim as malformed JSON).
const CLAIM_JSON_MAX: usize = 128;

impl ProvState {
    pub fn is_idle(&self) -> bool {
        matches!(self, ProvState::Idle)
    }
}

/// The machine.
#[derive(Debug, Clone)]
pub struct ProvMachine {
    pub state: ProvState,
}

impl ProvMachine {
    pub const fn new() -> Self {
        Self { state: ProvState::Idle }
    }

    /// Context of the in-flight provisioning run: `(job_id, key_hex)`.
    pub fn pending_context(&self) -> Option<(String<JOB_ID_MAX>, String<KEY_HEX_MAX>)> {
        match &self.state {
            ProvState::Provisioning(job, _) => Some((job.job_id.clone(), job.key_hex.clone())),
            _ => None,
        }
    }

    /// Feed an inbound job payload. Returns the parsed job alongside the
    /// action when a new job is accepted (the caller needs its fields).
    pub fn on_job(&mut self, payload: &str, now_ms: u64, window_secs: u64) -> (Option<PendingJob>, ProvAction) {
        if !self.state.is_idle() {
            return (None, ProvAction::IgnoreSecond);
        }
        match parse_job(payload, now_ms, window_secs) {
            Some(job) => {
                self.state = ProvState::Armed(job.clone());
                (Some(job), ProvAction::Arm)
            }
            None => (None, ProvAction::None),
        }
    }

    /// Feed a tag tap (7-byte uid) while a job is armed.
    pub fn on_tap(&mut self, uid: [u8; 7], now_ms: u64, claim_wait_secs: u64) -> ProvAction {
        let ProvState::Armed(job) = self.state.clone() else {
            return ProvAction::None;
        };
        // Window lapse takes precedence: an expired job never provisions.
        if now_ms >= job.deadline_ms {
            self.state = ProvState::Idle;
            return ProvAction::LapseSilent;
        }
        match &job.uid {
            Some(want) => {
                let mut hex = String::<UID_HEX_MAX>::new();
                for b in uid {
                    let _ = write_hex_byte(&mut hex, b);
                }
                if hex.as_str() != want.as_str() {
                    return ProvAction::TapRejected;
                }
                if job.key_hex.is_empty() {
                    // Fixed-uid jobs always carry their key; treat a missing
                    // one as a malformed job rather than provisioning with an
                    // empty key.
                    self.state = ProvState::Idle;
                    return ProvAction::Fail(job.job_id.clone(), "fixed-uid job had no key");
                }
                self.state = ProvState::Provisioning(job, uid);
                ProvAction::ProvisionStart
            }
            None => {
                let claim = build_claim_json(&job.job_id, &uid);
                let claim_deadline =
                    now_ms.saturating_add(claim_wait_secs.saturating_mul(1000));
                self.state = ProvState::ClaimWait(job, uid, claim_deadline);
                ProvAction::PublishClaim(claim)
            }
        }
    }

    /// Feed the keyed claim reply while waiting in ClaimWait.
    pub fn on_claim(&mut self, payload: &str, now_ms: u64) -> ProvAction {
        let ProvState::ClaimWait(job, uid, claim_deadline) = self.state.clone() else {
            return ProvAction::None;
        };
        if now_ms >= job.deadline_ms {
            self.state = ProvState::Idle;
            return ProvAction::LapseSilent;
        }
        if now_ms >= claim_deadline {
            self.state = ProvState::Idle;
            return ProvAction::Fail(job.job_id.clone(), "claim timeout");
        }
        let Ok((cp, _)) = serde_json_core::from_str::<ClaimPayload>(payload) else {
            return ProvAction::None; // not for us / malformed — keep waiting
        };
        if cp.job_id != job.job_id.as_str() {
            return ProvAction::None; // stale or foreign claim reply
        }
        let mut updated = job.clone();
        updated.key_hex.clear();
        if updated.key_hex.push_str(cp.key).is_err()
            || updated.key_hex.len() != 32
            || !updated.key_hex.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
        {
            self.state = ProvState::Idle;
            return ProvAction::Fail(job.job_id.clone(), "claim reply had bad key");
        }
        self.state = ProvState::Provisioning(updated, uid);
        ProvAction::ProvisionStart
    }

    /// Periodic tick: enforce window/claim deadlines.
    pub fn on_tick(&mut self, now_ms: u64) -> ProvAction {
        match self.state.clone() {
            ProvState::Idle => ProvAction::None,
            ProvState::Armed(job) => {
                if now_ms >= job.deadline_ms {
                    self.state = ProvState::Idle;
                    ProvAction::LapseSilent
                } else {
                    ProvAction::None
                }
            }
            ProvState::ClaimWait(job, _, claim_deadline) => {
                if now_ms >= claim_deadline {
                    // Claim window elapsed: fail the job explicitly so the
                    // server learns (unlike the silent arm-window lapse).
                    self.state = ProvState::Idle;
                    ProvAction::Fail(job.job_id.clone(), "claim timeout")
                } else if now_ms >= job.deadline_ms {
                    self.state = ProvState::Idle;
                    ProvAction::LapseSilent
                } else {
                    ProvAction::None
                }
            }
            ProvState::Provisioning(..) => ProvAction::None, // node drives it
        }
    }

    /// Node reports the provisioning run finished.
    pub fn on_provision_done(&mut self, ok: bool, counter: u32, reason: &'static str) -> ProvAction {
        let ProvState::Provisioning(job, _uid) = self.state.clone() else {
            return ProvAction::None;
        };
        self.state = ProvState::Idle;
        if ok {
            ProvAction::CompleteOk(job.job_id.clone(), counter)
        } else {
            ProvAction::Fail(job.job_id.clone(), reason)
        }
    }
}

/// `{"job_id":"…","uid":"…"}` for the wildcard claim.
pub fn build_claim_json(job_id: &str, uid: &[u8; 7]) -> String<CLAIM_JSON_MAX> {
    let mut out = String::new();
    let _ = out.push_str("{\"job_id\":\"");
    let _ = out.push_str(job_id);
    let _ = out.push_str("\",\"uid\":\"");
    for &b in uid.iter() {
        let _ = write_hex_byte(&mut out, b);
    }
    let _ = out.push_str("\"}");
    out
}

/// `{"job_id":"…","ok":true,"counter":N}` / `{"job_id":"…","ok":false,"error":"…"}`.
pub fn build_done_json(job_id: &str, ok: bool, counter: u32, error: &str) -> String<160> {
    let mut out = String::new();
    let _ = out.push_str("{\"job_id\":\"");
    let _ = out.push_str(job_id);
    if ok {
        let _ = out.push_str("\",\"ok\":true,\"counter\":");
        let _ = write!(out, "{}", counter);
        let _ = out.push('}');
    } else {
        let _ = out.push_str("\",\"ok\":false,\"error\":\"");
        let _ = out.push_str(error);
        let _ = out.push_str("\"}");
    }
    out
}

fn write_hex_byte<const N: usize>(out: &mut String<N>, b: u8) -> Result<(), ()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[(b >> 4) as usize] as char).map_err(|_| ())?;
    out.push(HEX[(b & 0x0f) as usize] as char).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_json_fits_real_job_id() {
        // Regression: a real verifier job_id is 32 hex chars; with
        // CLAIM_JSON_MAX = 64 the claim was silently truncated at column 64
        // and the verifier rejected it as malformed JSON.
        let job_id = "c53a1f82bbf3c919eeb889bb10b4020e";
        let uid: [u8; 7] = [0x04, 0x87, 0x53, 0x62, 0x1E, 0x18, 0x90];
        let claim = build_claim_json(job_id, &uid);
        let expected = "{\"job_id\":\"c53a1f82bbf3c919eeb889bb10b4020e\",\
                        \"uid\":\"048753621e1890\"}";
        assert_eq!(claim.as_str(), expected);
        assert_eq!(claim.len(), 68); // 11 + 32 (job_id) + 9 + 14 (uid) + 2 — overflows the old 64-byte buffer by 4
        // The done JSON must also survive a 32-hex job id.
        let done = build_done_json(job_id, true, 42, "");
        assert!(done.as_str().contains(job_id));
        assert!(done.as_str().ends_with("\"counter\":42}"));
    }

    const JOB_WILDCARD: &str =
        r#"{"uid":"","key":"","sun_config":{"key_version":1,"cmac_bytes":8},"job_id":"abc123","expires_at":"2026-10-11T00:00:00Z"}"#;
    const KEY_HEX: &str = "aabbccddeeff00112233445566778899";

    fn fixed_uid_job() -> String<160> {
        let mut s = String::<160>::new();
        let _ = write!(
            s,
            r#"{{"uid":"046522cabc5d80","key":"{}","job_id":"fix42","expires_at":"x"}}"#,
            KEY_HEX
        );
        s
    }

    #[test]
    fn wildcard_payload_arms() {
        let mut m = ProvMachine::new();
        let (job, action) = m.on_job(JOB_WILDCARD, 1000, 90);
        assert_eq!(action, ProvAction::Arm);
        let job = job.expect("job parsed");
        assert_eq!(job.uid, None);
        assert_eq!(job.key_hex, "");
        assert_eq!(job.job_id, "abc123");
        assert_eq!(job.deadline_ms, 1000 + 90 * 1000);
        assert!(matches!(m.state, ProvState::Armed(_)));
    }

    #[test]
    fn keyed_payload_captures_uid() {
        let mut m = ProvMachine::new();
        let (job, action) = m.on_job(fixed_uid_job().as_str(), 0, 90);
        assert_eq!(action, ProvAction::Arm);
        assert_eq!(job.expect("job").uid.as_deref(), Some("046522cabc5d80"));
    }

    #[test]
    fn second_job_while_armed_is_ignored() {
        let mut m = ProvMachine::new();
        let _ = m.on_job(JOB_WILDCARD, 0, 90);
        let (job, action) = m.on_job(fixed_uid_job().as_str(), 10, 90);
        assert_eq!(job, None);
        assert_eq!(action, ProvAction::IgnoreSecond);
        assert!(matches!(m.state, ProvState::Armed(_)));
    }

    #[test]
    fn wildcard_tap_publishes_claim_then_claim_reply_provisions() {
        let uid = [0x04, 0x65, 0x22, 0xca, 0xbc, 0x5d, 0x80];
        let mut m = ProvMachine::new();
        let _ = m.on_job(JOB_WILDCARD, 0, 90);
        let action = m.on_tap(uid, 500, 15);
        let ProvAction::PublishClaim(claim) = action else {
            panic!("expected claim, got {:?}", action);
        };
        assert_eq!(claim.as_str(), "{\"job_id\":\"abc123\",\"uid\":\"046522cabc5d80\"}");

        let mut reply = String::<160>::new();
        let _ = reply.push_str("{\"uid\":\"046522cabc5d80\",\"key\":\"");
        let _ = reply.push_str(KEY_HEX);
        let _ = reply.push_str("\",\"job_id\":\"abc123\"}");
        let action = m.on_claim(reply.as_str(), 600);
        assert_eq!(action, ProvAction::ProvisionStart);
        assert!(matches!(m.state, ProvState::Provisioning(_, _)));
    }

    #[test]
    fn foreign_claim_reply_is_ignored() {
        let uid = [0x04; 7];
        let mut m = ProvMachine::new();
        let _ = m.on_job(JOB_WILDCARD, 0, 90);
        let _ = m.on_tap(uid, 0, 15);
        let reply = r#"{"uid":"04040404040404","key":"aabb","job_id":"OTHER"}"#;
        assert_eq!(m.on_claim(reply, 100), ProvAction::None);
        assert!(matches!(m.state, ProvState::ClaimWait(_, _, _)));
    }

    #[test]
    fn fixed_uid_mismatch_rejects_and_stays_armed() {
        let mut m = ProvMachine::new();
        let _ = m.on_job(fixed_uid_job().as_str(), 0, 90);
        let other = [0x01; 7];
        assert_eq!(m.on_tap(other, 100, 15), ProvAction::TapRejected);
        assert!(matches!(m.state, ProvState::Armed(_)));
    }

    #[test]
    fn fixed_uid_match_starts_provisioning() {
        let mut m = ProvMachine::new();
        let _ = m.on_job(fixed_uid_job().as_str(), 0, 90);
        let uid = [0x04, 0x65, 0x22, 0xca, 0xbc, 0x5d, 0x80];
        assert_eq!(m.on_tap(uid, 100, 15), ProvAction::ProvisionStart);
        assert!(matches!(m.state, ProvState::Provisioning(_, _)));
    }

    #[test]
    fn claim_timeout_fails_job() {
        let uid = [0x04; 7];
        let mut m = ProvMachine::new();
        let _ = m.on_job(JOB_WILDCARD, 0, 90);
        let _ = m.on_tap(uid, 0, 15);
        // Claim deadline is tap + 15 s.
        assert_eq!(m.on_tick(14_999), ProvAction::None);
        assert!(matches!(m.on_tick(15_000), ProvAction::Fail(_, "claim timeout")));
        assert!(m.state.is_idle());
    }

    #[test]
    fn window_lapse_is_silent() {
        let mut m = ProvMachine::new();
        let _ = m.on_job(JOB_WILDCARD, 0, 90);
        assert_eq!(m.on_tick(90_000), ProvAction::LapseSilent);
        assert!(m.state.is_idle());
    }

    #[test]
    fn provision_completion_paths() {
        let mut m = ProvMachine::new();
        let _ = m.on_job(fixed_uid_job().as_str(), 0, 90);
        let uid = [0x04, 0x65, 0x22, 0xca, 0xbc, 0x5d, 0x80];
        let _ = m.on_tap(uid, 0, 15);
        assert!(matches!(m.on_provision_done(true, 7, ""), ProvAction::CompleteOk(_, 7)));
        assert!(m.state.is_idle());

        let _ = m.on_job(fixed_uid_job().as_str(), 1000, 90);
        let _ = m.on_tap(uid, 1000, 15);
        assert!(matches!(m.on_provision_done(false, 0, "sw"), ProvAction::Fail(_, "sw")));
        assert!(m.state.is_idle());
    }

    #[test]
    fn done_json_shapes() {
        assert_eq!(
            build_done_json("abc123", true, 42, "").as_str(),
            "{\"job_id\":\"abc123\",\"ok\":true,\"counter\":42}"
        );
        assert_eq!(
            build_done_json("abc123", false, 0, "boom").as_str(),
            "{\"job_id\":\"abc123\",\"ok\":false,\"error\":\"boom\"}"
        );
    }

    #[test]
    fn test_real_verifier_wildcard_job_arms() {
        let payload = r#"{"expires_at":"2026-10-14T16:25:02.236144627+00:00","job_id":"12fbcb7eff6ae9a9ba34a5300cd0fb07","key":"","sun_config":{"cmac_bytes":8,"key_version":1},"uid":""}"#;
        let mut m = ProvMachine::new();
        let (job, action) = m.on_job(payload, 1000, 90);
        assert_eq!(action, ProvAction::Arm);
        let job = job.expect("job parsed");
        assert_eq!(job.job_id.as_str(), "12fbcb7eff6ae9a9ba34a5300cd0fb07");
    }

    #[test]
    fn malformed_job_is_rejected() {
        let mut m = ProvMachine::new();
        assert_eq!(m.on_job("{not json", 0, 90), (None, ProvAction::None));
        assert_eq!(
            m.on_job(r#"{"uid":"","key":"xyz","job_id":"a"}"#, 0, 90),
            (None, ProvAction::None)
        );
        assert!(m.state.is_idle());
    }
}
