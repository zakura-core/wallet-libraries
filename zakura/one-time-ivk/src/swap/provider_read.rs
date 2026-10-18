//! When a provider's set of the receivers it was given is current enough to rule a
//! receiver out. A receiver directory publishes these sets from the provider's feed.

/// How long before the caller's clock a provider set's last complete read may have begun
/// and still rule a receiver out. A quote made after that read is missing from the set.
pub const PROVIDER_READ_MAX_AGE_SECS: i64 = 15 * 60;

/// How far after the caller's clock a provider set's last read may have begun, for a
/// provider clock slightly ahead of the caller's.
pub const PROVIDER_READ_CLOCK_SKEW_SECS: i64 = 60;

/// Whether a provider set whose last complete read began at `until` is current at `now`,
/// the caller's wall clock, both in Unix seconds: no older than
/// [`PROVIDER_READ_MAX_AGE_SECS`] and no more than [`PROVIDER_READ_CLOCK_SKEW_SECS`] ahead.
pub fn provider_read_is_current(until: i64, now: i64) -> bool {
    (now.saturating_sub(PROVIDER_READ_MAX_AGE_SECS)
        ..=now.saturating_add(PROVIDER_READ_CLOCK_SKEW_SECS))
        .contains(&until)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A read is current from the maximum age before `now` to the clock skew after it,
    /// inclusive, and the bounds saturate at the ends of the clock's range.
    #[test]
    fn a_read_is_current_only_within_its_bounds() {
        let now = 1_000_000;
        for (until, current) in [
            (now, true),
            (now - PROVIDER_READ_MAX_AGE_SECS, true),
            (now - PROVIDER_READ_MAX_AGE_SECS - 1, false),
            (now + PROVIDER_READ_CLOCK_SKEW_SECS, true),
            (now + PROVIDER_READ_CLOCK_SKEW_SECS + 1, false),
        ] {
            assert_eq!(provider_read_is_current(until, now), current, "{until}");
        }
        assert!(provider_read_is_current(i64::MAX, i64::MAX));
        assert!(!provider_read_is_current(i64::MIN, 0));
    }
}
