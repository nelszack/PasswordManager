//! Slows repeated wrong passwords for every client of this service (the CLI
//! and the desktop app). The first few failures cost nothing extra;
//! after that each failure doubles the wait, up to five minutes. A success
//! resets it. Refused attempts never run the key derivation.
use std::time::{Duration, Instant};

const FREE_FAILURES: u32 = 5;
const MAX_DELAY: Duration = Duration::from_secs(300);

#[derive(Debug, Default)]
pub(super) struct UnlockThrottle {
    failures: u32,
    retry_at: Option<Instant>,
}

impl UnlockThrottle {
    /// Seconds to wait before another attempt is allowed, if any.
    pub(super) fn wait(&self, now: Instant) -> Option<u64> {
        let remaining = self.retry_at?.checked_duration_since(now)?;
        (!remaining.is_zero()).then(|| remaining.as_millis().div_ceil(1000) as u64)
    }

    pub(super) fn failed(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        if self.failures > FREE_FAILURES {
            let exponent = (self.failures - FREE_FAILURES - 1).min(16);
            let delay = Duration::from_secs(1u64 << exponent).min(MAX_DELAY);
            self.retry_at = Some(now + delay);
        }
    }

    pub(super) fn succeeded(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_back_off_exponentially_and_success_resets() {
        let start = Instant::now();
        let mut throttle = UnlockThrottle::default();
        for _ in 0..FREE_FAILURES {
            assert_eq!(throttle.wait(start), None);
            throttle.failed(start);
        }
        assert_eq!(throttle.wait(start), None, "the first failures are free");
        throttle.failed(start);
        assert_eq!(throttle.wait(start), Some(1));
        throttle.failed(start);
        assert_eq!(throttle.wait(start), Some(2));
        for _ in 0..20 {
            throttle.failed(start);
        }
        assert_eq!(throttle.wait(start), Some(300), "capped at five minutes");
        assert_eq!(throttle.wait(start + MAX_DELAY), None);
        throttle.succeeded();
        throttle.failed(start);
        assert_eq!(throttle.wait(start), None);
    }
}
