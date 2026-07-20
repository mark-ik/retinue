//! Airtime accounting: the one duty-cycle gate every protocol shares.
//!
//! Tulle sits beneath every protocol on a radio, so this is the single place
//! transmit discipline is enforced: whatever rides the radio (Reticulum, a
//! mesh personality, a bearer tunnel) passes the same gate. Regulatory
//! regimes differ (EU 868 MHz has hard duty-cycle limits; US 915 MHz Part
//! 15.247 constrains dwell instead), so the budget is configuration, not
//! policy baked in here.
//!
//! Sans-io: the caller supplies time as milliseconds and asks before
//! transmitting. Nothing here sleeps, schedules, or touches a clock.

use std::collections::VecDeque;

/// Sliding-window airtime budget.
///
/// Tracks transmissions over a trailing window and answers "may I transmit
/// for `duration_ms` right now, and if not, when?". Permitted airtime is
/// `budget_permille` thousandths of the window (e.g. 10 = 1%, the strictest
/// EU sub-band; 100 = 10%).
pub struct AirtimeBudget {
    window_ms: u64,
    budget_permille: u64,
    /// (start_ms, duration_ms) of recorded transmissions, oldest first.
    sent: VecDeque<(u64, u64)>,
}

impl AirtimeBudget {
    pub fn new(window_ms: u64, budget_permille: u64) -> Self {
        AirtimeBudget {
            window_ms,
            budget_permille,
            sent: VecDeque::new(),
        }
    }

    /// Airtime allowed per window, in milliseconds.
    pub fn allowance_ms(&self) -> u64 {
        self.window_ms * self.budget_permille / 1000
    }

    fn prune(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        while let Some(&(start, dur)) = self.sent.front() {
            if start + dur <= cutoff {
                self.sent.pop_front();
            } else {
                break;
            }
        }
    }

    /// Airtime spent within the window ending at `now_ms`. Transmissions
    /// straddling the window edge count only their in-window part.
    pub fn spent_ms(&mut self, now_ms: u64) -> u64 {
        self.prune(now_ms);
        let cutoff = now_ms.saturating_sub(self.window_ms);
        self.sent
            .iter()
            .map(|&(start, dur)| {
                let end = start + dur;
                end - start.max(cutoff).min(end)
            })
            .sum()
    }

    /// Would a transmission of `duration_ms` starting now stay in budget?
    pub fn may_transmit(&mut self, now_ms: u64, duration_ms: u64) -> bool {
        duration_ms <= self.allowance_ms().saturating_sub(self.spent_ms(now_ms))
    }

    /// Record a transmission that was actually made.
    pub fn record(&mut self, start_ms: u64, duration_ms: u64) {
        self.sent.push_back((start_ms, duration_ms));
    }

    /// Earliest time a transmission of `duration_ms` could fit, at or after
    /// `now_ms`. Returns `None` if it can never fit (longer than the whole
    /// allowance).
    pub fn next_slot(&mut self, now_ms: u64, duration_ms: u64) -> Option<u64> {
        if duration_ms > self.allowance_ms() {
            return None;
        }
        // Step forward through recorded-transmission expiries until enough
        // budget has aged out. Bounded by the number of recorded sends.
        let mut t = now_ms;
        loop {
            if self.may_transmit(t, duration_ms) {
                return Some(t);
            }
            // The next point anything changes: the oldest send fully ages out.
            let &(start, dur) = self.sent.front()?;
            t = t.max(start + dur + self.window_ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1-hour window at 1% (the strict EU sub-band shape).
    fn one_percent() -> AirtimeBudget {
        AirtimeBudget::new(3_600_000, 10)
    }

    #[test]
    fn fresh_budget_allows() {
        let mut b = one_percent();
        assert_eq!(b.allowance_ms(), 36_000);
        assert!(b.may_transmit(0, 36_000));
        assert!(!b.may_transmit(0, 36_001));
    }

    #[test]
    fn spending_reduces_allowance() {
        let mut b = one_percent();
        b.record(0, 30_000);
        assert!(b.may_transmit(30_000, 6_000));
        assert!(!b.may_transmit(30_000, 6_001));
    }

    #[test]
    fn budget_ages_out() {
        let mut b = one_percent();
        b.record(0, 36_000);
        assert!(!b.may_transmit(36_000, 1));
        // Whole send outside the window: full budget again.
        assert!(b.may_transmit(3_636_000, 36_000));
    }

    #[test]
    fn straddling_send_counts_partially() {
        let mut b = one_percent();
        b.record(0, 20_000);
        // Window now covers [10_000+20_000-3_600_000.. ] — at t=3_610_000 the
        // cutoff is 10_000, so half the send (10_000ms) is still in-window.
        assert_eq!(b.spent_ms(3_610_000), 10_000);
        assert!(b.may_transmit(3_610_000, 26_000));
        assert!(!b.may_transmit(3_610_000, 26_001));
    }

    #[test]
    fn next_slot_now_when_budget_free() {
        let mut b = one_percent();
        assert_eq!(b.next_slot(500, 1_000), Some(500));
    }

    #[test]
    fn next_slot_waits_for_ageout() {
        let mut b = one_percent();
        b.record(0, 36_000); // budget exhausted at t=36_000
        let slot = b.next_slot(36_000, 36_000).unwrap();
        // The send fully ages out of the window at start+dur+window.
        assert_eq!(slot, 3_636_000);
        assert!(b.may_transmit(slot, 36_000));
    }

    #[test]
    fn next_slot_impossible_duration() {
        let mut b = one_percent();
        assert_eq!(b.next_slot(0, 36_001), None);
    }
}
