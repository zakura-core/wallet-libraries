use super::*;

#[test]
fn progress_says_when_to_pass_again() {
    for (outcome, retry) in [
        (Outcome::Complete, Retry::Complete),
        (Outcome::More, Retry::More),
        (Outcome::Behind, Retry::After(Duration::from_secs(10))),
        (Outcome::Overloaded, Retry::After(Duration::from_secs(30))),
        (Outcome::Stalled, Retry::Stalled),
    ] {
        let progress = Progress {
            covered_through: 7,
            outcome,
        };
        assert_eq!(progress.retry(), retry, "{outcome:?}");
    }
    let progress = |covered_through| Progress {
        covered_through,
        outcome: Outcome::Behind,
    };
    assert_eq!(progress(100).behind(100), 0);
    assert_eq!(progress(93).behind(100), 7);
    // Coverage past the target never wraps.
    assert_eq!(progress(103).behind(100), 0);
    assert_eq!(progress(0).behind(u64::MAX), u64::MAX);
}

/// A withdrawn batch is never retried on a timer, whatever the sync
/// reported; any other batch follows its progress.
#[test]
fn a_withdrawn_batch_waits_for_new_work() {
    let batch = |state, outcome| RecoveryBatch::<()> {
        commits: Vec::new(),
        progress: Progress {
            covered_through: 7,
            outcome,
        },
        state,
        retired_revisions: Vec::new(),
        receipt: [0; 32],
    };
    for outcome in [
        Outcome::Complete,
        Outcome::More,
        Outcome::Behind,
        Outcome::Overloaded,
        Outcome::Stalled,
    ] {
        for cause in [
            WithdrawnCause::Regression,
            WithdrawnCause::Equivocation,
            WithdrawnCause::ChangedSealed,
            WithdrawnCause::Retired,
        ] {
            let withdrawn = batch(BatchState::Withdrawn(cause), outcome);
            assert_eq!(withdrawn.retry(), Retry::Stalled, "{cause:?} {outcome:?}");
        }
        for state in [BatchState::Ready, BatchState::Pending] {
            let progress = batch(state, outcome).progress();
            assert_eq!(batch(state, outcome).retry(), progress.retry());
        }
    }
}
