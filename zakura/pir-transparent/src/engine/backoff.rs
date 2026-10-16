//! Retry delays that spread out.
//!
//! Every wallet that meets the same refusal at the same moment computes the
//! same delay. Without jitter they all come back together and meet it again:
//! on the 2026-09-27 bench fleet, 128 wallets resubmitting in step kept a
//! saturated router refusing for minutes. A delay here is never shorter than
//! the one asked for, so a service's `retry-after` is still honoured.

use std::time::Duration;

/// `base` plus a uniformly random extra of up to half of it.
///
/// Never less than `base`: `base` is either what the service asked for or the
/// minimum the caller chose.
pub fn jittered(base: Duration) -> Duration {
    let spread = base / 2;
    if spread.is_zero() {
        return base;
    }
    let nanos = spread.as_nanos().min(u64::MAX as u128) as u64;
    base + Duration::from_nanos(random_u64() % (nanos + 1))
}

/// `initial` doubled per failure after the first, capped at `cap`, then
/// jittered: the wait before retry number `failures` (from 1).
pub fn exponential(initial: Duration, failures: u32, cap: Duration) -> Duration {
    let doubled = initial.saturating_mul(2u32.saturating_pow(failures.saturating_sub(1)));
    jittered(doubled.min(cap))
}

/// A random word from the standard library's per-process random hash keys,
/// which differ between calls; statistical quality is all a delay needs.
fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos() as u64),
    );
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delay_is_never_shorter_than_asked_and_spreads_up_to_half_again() {
        let base = Duration::from_secs(1);
        let delays: Vec<Duration> = (0..200).map(|_| jittered(base)).collect();
        assert!(delays.iter().all(|d| *d >= base && *d <= base * 3 / 2));
        let distinct: std::collections::BTreeSet<_> = delays.iter().collect();
        assert!(distinct.len() > 100, "{} distinct delays", distinct.len());
        assert_eq!(jittered(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn exponential_doubles_to_its_cap() {
        let initial = Duration::from_millis(250);
        let cap = Duration::from_secs(2);
        for (failures, base) in [
            (1, 250),
            (2, 500),
            (3, 1000),
            (4, 2000),
            (9, 2000),
            (40, 2000),
        ] {
            let delay = exponential(initial, failures, cap);
            let base = Duration::from_millis(base);
            assert!(
                delay >= base && delay <= base * 3 / 2,
                "{failures}: {delay:?}"
            );
        }
    }
}
