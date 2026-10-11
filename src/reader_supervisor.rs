//! PN532 lockup detection and reset policy supervisor.
//!
//! Pure `no_std` state machine that monitors consecutive reader poll failures
//! and determines when hardware or soft recovery should be triggered.
//!
//! Kept free of hardware/HAL dependencies so it can be verified in host unit tests.

/// Number of consecutive poll errors before triggering reader recovery.
pub const ERR_THRESHOLD: u32 = 8;

/// Minimum cooldown period in milliseconds between recovery attempts to prevent hammering.
pub const COOLDOWN_MS: u64 = 5_000;

/// Action prescribed by the reset policy supervisor.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Action {
    /// Comm healthy or error count below threshold / in cooldown.
    Continue,
    /// Recovery recommended (hardware RSTO pulse + soft reinit).
    Recover,
}

/// Reset policy supervisor tracking consecutive errors and cooldown periods.
#[derive(Debug, Default)]
pub struct ResetPolicy {
    consecutive_errs: u32,
    last_recover_ms: Option<u64>,
}

impl ResetPolicy {
    /// Create a new reset policy instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe the result of a reader poll.
    ///
    /// - `was_err`: true if the last poll returned Err.
    /// - `now_ms`: monotonic time in milliseconds.
    pub fn observe(&mut self, was_err: bool, now_ms: u64) -> Action {
        if !was_err {
            self.consecutive_errs = 0;
            return Action::Continue;
        }

        self.consecutive_errs += 1;
        if self.consecutive_errs >= ERR_THRESHOLD {
            let can_recover = match self.last_recover_ms {
                None => true,
                Some(last) => now_ms.saturating_sub(last) >= COOLDOWN_MS,
            };

            if can_recover {
                self.last_recover_ms = Some(now_ms);
                self.consecutive_errs = 0;
                return Action::Recover;
            }
        }

        Action::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_after_eight_consecutive_errors() {
        let mut policy = ResetPolicy::new();
        for _ in 0..7 {
            assert_eq!(policy.observe(true, 100), Action::Continue);
        }
        assert_eq!(policy.observe(true, 100), Action::Recover);
    }

    #[test]
    fn ok_resets_error_streak() {
        let mut policy = ResetPolicy::new();
        for _ in 0..7 {
            assert_eq!(policy.observe(true, 100), Action::Continue);
        }
        assert_eq!(policy.observe(false, 110), Action::Continue);
        for _ in 0..7 {
            assert_eq!(policy.observe(true, 120), Action::Continue);
        }
        assert_eq!(policy.observe(true, 130), Action::Recover);
    }

    #[test]
    fn alternating_glitch_never_recovers() {
        let mut policy = ResetPolicy::new();
        for i in 0..20 {
            assert_eq!(policy.observe(true, i * 10), Action::Continue);
            assert_eq!(policy.observe(false, i * 10 + 5), Action::Continue);
        }
    }

    #[test]
    fn cooldown_gates_second_recovery() {
        let mut policy = ResetPolicy::new();
        // Recover at t=0
        for _ in 0..7 {
            assert_eq!(policy.observe(true, 0), Action::Continue);
        }
        assert_eq!(policy.observe(true, 0), Action::Recover);

        // 8 errs at t=1000 -> Continue
        for _ in 0..8 {
            assert_eq!(policy.observe(true, 1_000), Action::Continue);
        }

        // at t=5000 -> Recover
        assert_eq!(policy.observe(true, 5_000), Action::Recover);
    }

    #[test]
    fn streak_resets_after_recovery() {
        let mut policy = ResetPolicy::new();
        for _ in 0..8 {
            policy.observe(true, 0);
        }
        // After Recover at t=0, consecutive_errs is reset to 0.
        // Needs 8 fresh errors (even after cooldown) to trigger next recovery.
        for _ in 0..7 {
            assert_eq!(policy.observe(true, 6_000), Action::Continue);
        }
        assert_eq!(policy.observe(true, 6_000), Action::Recover);
    }
}
