//! Ordered mirror attempts and last-good config retention.

use zakura_service_config::{
    AttemptFailure, CandidateRank, LastGoodConfig, MirrorAttempt, MirrorError, RefreshOutcome,
    resolve_from_mirrors,
};

/// Resolves bytes as UTF-8 text; empty text is usable but not preferred.
fn walk(
    attempts: Vec<MirrorAttempt>,
) -> Result<zakura_service_config::MirrorResolution<String>, MirrorError<String>> {
    resolve_from_mirrors(
        attempts,
        |_, bytes| String::from_utf8(bytes.to_vec()).map_err(|_| "not utf-8".to_string()),
        |text: &String| {
            if text.is_empty() {
                CandidateRank::Fallback {
                    reason: "empty document".to_string(),
                }
            } else {
                CandidateRank::Preferred
            }
        },
    )
}

#[test]
fn first_preferred_mirror_wins_and_earlier_failures_are_reported() {
    let resolution = walk(vec![
        MirrorAttempt::failed("https://a.example", "timed out after 30s"),
        MirrorAttempt::fetched("https://b.example", vec![0xff]),
        MirrorAttempt::fetched("https://c.example", b"config".to_vec()),
        MirrorAttempt::fetched("https://d.example", b"never read".to_vec()),
    ])
    .unwrap();
    assert_eq!(resolution.value, "config");
    assert_eq!(resolution.url, "https://c.example");
    let reasons: Vec<_> = resolution
        .passed_over
        .iter()
        .map(|f| f.reason.as_str())
        .collect();
    assert_eq!(reasons, ["fetch failed: timed out after 30s", "not utf-8"]);
}

#[test]
fn a_fallback_candidate_is_used_only_when_nothing_better_follows() {
    let resolution = walk(vec![
        MirrorAttempt::failed("https://a.example", "refused"),
        MirrorAttempt::fetched("https://b.example", Vec::new()),
        MirrorAttempt::failed("https://c.example", "refused"),
    ])
    .unwrap();
    assert_eq!(resolution.url, "https://b.example");
    // Mirrors after the fallback were not preferred to it.
    assert_eq!(resolution.passed_over.len(), 1);

    let better_later = walk(vec![
        MirrorAttempt::fetched("https://b.example", Vec::new()),
        MirrorAttempt::fetched("https://c.example", b"rounds".to_vec()),
    ])
    .unwrap();
    assert_eq!(better_later.url, "https://c.example");
    assert_eq!(better_later.passed_over[0].reason, "empty document");
}

#[test]
fn exhausted_mirrors_enumerate_every_failure_and_keep_the_last_cause() {
    let error = walk(vec![
        MirrorAttempt::failed("https://a.example", "dns"),
        MirrorAttempt::fetched("https://b.example", vec![0xff]),
    ])
    .unwrap_err();
    assert_eq!(
        error.summary(),
        "https://a.example: fetch failed: dns; https://b.example: not utf-8"
    );
    let MirrorError::Exhausted { last, failures } = error else {
        panic!("expected exhausted mirrors");
    };
    assert_eq!(failures.len(), 2);
    assert_eq!(last, AttemptFailure::Resolve("not utf-8".to_string()));

    assert_eq!(walk(Vec::new()).unwrap_err(), MirrorError::NoAttempts);
}

#[test]
fn failed_refreshes_never_replace_or_clear_the_accepted_config() {
    let mut config = LastGoodConfig::default();
    assert_eq!(
        config.refresh::<&str>(Err("offline")),
        RefreshOutcome::Unavailable { error: "offline" }
    );
    assert_eq!(config.refresh::<&str>(Ok(1)), RefreshOutcome::Accepted);
    assert_eq!(config.refresh::<&str>(Ok(1)), RefreshOutcome::Unchanged);
    assert_eq!(
        config.refresh(Err("invalid candidate")),
        RefreshOutcome::KeptPrevious {
            error: "invalid candidate"
        }
    );
    assert_eq!(config.accepted(), Some(&1));
    assert_eq!(config.refresh::<&str>(Ok(2)), RefreshOutcome::Accepted);
    assert_eq!(LastGoodConfig::new(Some(3)).into_accepted(), Some(3));
}
