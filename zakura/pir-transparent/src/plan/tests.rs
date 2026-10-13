use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::transparent_ledger::{
    AccountLifecycle, ChainPoint, CommitRejection, StaleCommit, WatchOrigin, WatchedAddress,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

use super::*;
use crate::apply::{ApplyError, ApplyStats};
use crate::progress::{Outcome, Progress};

const OUTCOMES: [Outcome; 5] = [
    Outcome::Complete,
    Outcome::Behind,
    Outcome::More,
    Outcome::Overloaded,
    Outcome::Stalled,
];

const CAUSES: [WithdrawnCause; 4] = [
    WithdrawnCause::Regression,
    WithdrawnCause::Equivocation,
    WithdrawnCause::ChangedSealed,
    WithdrawnCause::Retired,
];

/// A watch set of `addresses` standalone addresses, with a target unless
/// `targetless`.
fn watch(addresses: u8, targetless: bool) -> TransparentAddressWatchSet<u32> {
    TransparentAddressWatchSet {
        account: 1,
        lifecycle: AccountLifecycle::Candidate,
        policy_generation: 0,
        target: (!targetless).then(|| ChainPoint {
            height: BlockHeight::from(100),
            hash: BlockHash([1; 32]),
        }),
        addresses: (0..addresses)
            .map(|tag| WatchedAddress {
                address: TransparentAddress::PublicKeyHash([tag; 20]),
                origin: WatchOrigin::Standalone,
                required_from: BlockHeight::from(1),
            })
            .collect(),
        pending_pages: vec![],
    }
}

fn new_plan() -> PassPlan<u32> {
    PassPlan::new(watch(1, false), PassLimits::default())
}

fn report(state: BatchState, outcome: Outcome) -> PassReport {
    PassReport {
        state,
        progress: Progress {
            covered_through: 90,
            outcome,
        },
        commits: usize::from(state == BatchState::Ready),
        retired: 0,
        publication_changed: false,
    }
}

fn progress(outcome: Outcome) -> Progress {
    Progress {
        covered_through: 90,
        outcome,
    }
}

fn applied(window_grew: bool) -> Result<Option<Applied>, ApplyFailure> {
    Ok(Some(Applied {
        stats: ApplyStats {
            applied: 1,
            qualified: 0,
            window_grew,
        },
        progress: progress(Outcome::Complete),
        retired: 0,
    }))
}

/// A settlement the wallet refused as stale for the pass's watch set.
fn stale() -> ApplyError {
    ApplyError::Rejected {
        index: 0,
        rejection: CommitRejection::Stale(StaleCommit::LifecycleChanged),
    }
}

fn failed(error: ApplyError) -> Result<Option<Applied>, ApplyFailure> {
    Err(ApplyFailure {
        error,
        stats: ApplyStats::default(),
        progress: progress(Outcome::Complete),
    })
}

/// A settlement failure of each action.
fn failures() -> Vec<(ApplyAction, ApplyError)> {
    vec![
        (ApplyAction::Refresh, stale()),
        (ApplyAction::Reconcile, ApplyError::Unreconciled),
        (ApplyAction::Skip, ApplyError::StaleReceipt),
        (ApplyAction::NotEnabled, ApplyError::NotEnabled),
        (ApplyAction::PolicyChanged, ApplyError::PolicyChanged),
        (ApplyAction::Fail, ApplyError::OuterTransaction),
        (ApplyAction::Interrupted, ApplyError::Interrupted),
    ]
}

const NOTHING: Result<Option<Applied>, ApplyFailure> = Ok(None);

#[test]
fn a_watch_set_without_a_target_needs_no_pass() {
    assert_eq!(new_plan().first(), Step::Pass);
    let targetless = PassPlan::new(watch(1, true), PassLimits::default());
    assert_eq!(targetless.first(), Step::Done(None));
    assert_eq!(targetless.watch().target, None);
}

/// A withdrawn pass holds the account whatever it covered: a timer would read the
/// same contradiction.
#[test]
fn a_withdrawn_pass_holds_the_account() {
    for cause in CAUSES {
        for outcome in OUTCOMES {
            let mut plan = new_plan();
            let step = plan.next(
                &report(BatchState::Withdrawn(cause), outcome),
                &NOTHING,
                watch(2, false),
            );
            assert_eq!(step, Step::Hold(HoldCause::Withdrawn(cause)), "{outcome:?}");
        }
    }
}

/// Every failed settlement says what the account does next; none counts as a pass.
#[test]
fn every_failed_settlement_has_its_step() {
    for (action, error) in failures() {
        let expected = match action {
            ApplyAction::Refresh => Step::Refresh,
            ApplyAction::Reconcile => Step::Hold(HoldCause::Unreconciled),
            ApplyAction::Skip => Step::Skip,
            ApplyAction::NotEnabled => Step::Stop(StopCause::NotEnabled),
            ApplyAction::PolicyChanged => Step::Stop(StopCause::PolicyChanged),
            ApplyAction::Fail => Step::Fail,
            ApplyAction::Interrupted => Step::Skip,
        };
        let settled = failed(error);
        assert_eq!(settled.as_ref().unwrap_err().action(), action);
        for outcome in OUTCOMES {
            let mut plan = new_plan();
            let step = plan.next(
                &report(BatchState::Ready, outcome),
                &settled,
                watch(1, false),
            );
            assert_eq!(step, expected, "{action:?} {outcome:?}");
        }
    }
}

/// A stale settlement passes again from the fresh watch set, uncounted, until the
/// refreshes run out.
#[test]
fn stale_settlements_refresh_a_bounded_number_of_times() {
    let ready = report(BatchState::Ready, Outcome::Complete);
    let stale = failed(stale());
    let mut plan = new_plan();
    for _ in 0..PassLimits::default().stale_refreshes {
        assert_eq!(plan.next(&ready, &stale, watch(1, false)), Step::Refresh);
    }
    assert_eq!(plan.next(&ready, &stale, watch(1, false)), Step::Skip);

    // A refresh that finds no target has nothing to pass.
    let mut plan = new_plan();
    assert_eq!(plan.next(&ready, &stale, watch(1, true)), Step::Done(None));

    // The refresh allowance is not reset when publication lag is reported.
    let limits = PassLimits { stale_refreshes: 1 };
    let mut plan = PassPlan::new(watch(1, false), limits);
    assert_eq!(plan.next(&ready, &stale, watch(1, false)), Step::Refresh);
    let behind = report(BatchState::Ready, Outcome::Behind);
    assert_eq!(
        plan.next(&behind, &applied(false), watch(1, false)),
        Step::Done(Some(Retry::After(Retry::BEHIND)))
    );
    assert_eq!(plan.next(&ready, &stale, watch(1, false)), Step::Skip);
    assert_eq!(PassLimits::default().stale_refreshes, 3);
}

/// A settlement the caller's gate interrupted skips only the account, never the run:
/// whichever budget ran out, the caller checks its own cancellation before the next
/// pass. It does not count as a pass, and the next run replays the rest.
#[test]
fn an_interrupted_settlement_skips_only_the_account() {
    let interrupted = failed(ApplyError::Interrupted);
    for outcome in OUTCOMES {
        let mut plan = new_plan();
        let step = plan.next(
            &report(BatchState::Ready, outcome),
            &interrupted,
            watch(2, false),
        );
        assert_eq!(step, Step::Skip, "{outcome:?}");
    }
}

/// A changed policy generation stops the run at once, never refreshes: the policy the
/// run captured may no longer permit private queries. It does not use up the stale
/// refreshes, which stale commits still take.
#[test]
fn a_changed_policy_stops_the_run() {
    let ready = report(BatchState::Ready, Outcome::Complete);
    let changed = failed(ApplyError::PolicyChanged);
    for targetless in [false, true] {
        let mut plan = new_plan();
        assert_eq!(
            plan.next(&ready, &changed, watch(1, targetless)),
            Step::Stop(StopCause::PolicyChanged)
        );
    }
    // After stale refreshes too.
    let mut plan = new_plan();
    assert_eq!(
        plan.next(&ready, &failed(stale()), watch(1, false)),
        Step::Refresh
    );
    assert_eq!(
        plan.next(&ready, &changed, watch(1, false)),
        Step::Stop(StopCause::PolicyChanged)
    );
    // Stale commits still refresh, up to the cap.
    let mut plan = new_plan();
    for _ in 0..PassLimits::default().stale_refreshes {
        assert_eq!(
            plan.next(&ready, &failed(stale()), watch(1, false)),
            Step::Refresh
        );
    }
    assert_eq!(
        plan.next(&ready, &failed(stale()), watch(1, false)),
        Step::Skip
    );
}

/// A ready batch nobody settled cannot be acknowledged by this plan.
#[test]
fn an_unsettled_ready_pass_is_skipped() {
    for outcome in OUTCOMES {
        let mut plan = new_plan();
        let step = plan.next(
            &report(BatchState::Ready, outcome),
            &NOTHING,
            watch(2, false),
        );
        assert_eq!(step, Step::Skip, "{outcome:?}");
    }
}

/// Settled or pending, every counted pass ends the sync with its retry, including
/// the delay after lag or overload. Neither window growth nor changed addresses
/// starts another pass in the current sync.
#[test]
fn a_counted_pass_follows_its_retry() {
    for state in [BatchState::Ready, BatchState::Pending] {
        let settlements = if state == BatchState::Ready {
            vec![(applied(false), false), (applied(true), true)]
        } else {
            vec![(NOTHING, false)]
        };
        for (settled, grew) in settlements {
            for addresses_changed in [false, true] {
                for outcome in OUTCOMES {
                    let mut plan = new_plan();
                    let fresh = watch(1 + u8::from(addresses_changed), false);
                    let step = plan.next(&report(state, outcome), &settled, fresh);
                    let expected = Step::Done(Some(pass_retry(outcome)));
                    assert_eq!(
                        step, expected,
                        "{state:?} grew={grew} changed={addresses_changed} {outcome:?}"
                    );
                    // The fresh set is saved, but this sync does not pass it again.
                    assert_eq!(
                        plan.watch().addresses.len(),
                        1 + usize::from(addresses_changed)
                    );
                }
            }
        }
    }
}

fn pass_retry(outcome: Outcome) -> Retry {
    match outcome {
        Outcome::Behind => Retry::After(Retry::BEHIND),
        Outcome::Overloaded => Retry::After(Retry::OVERLOADED),
        Outcome::More => Retry::More,
        Outcome::Complete => Retry::Complete,
        Outcome::Stalled => Retry::Stalled,
    }
}

/// A caller that continues until the plan ends must not loop forever on a
/// publication that stays behind or a service that keeps refusing capacity.
#[test]
fn persistent_lag_or_overload_does_not_keep_a_sync_running() {
    for state in [BatchState::Ready, BatchState::Pending] {
        for outcome in [Outcome::Behind, Outcome::Overloaded] {
            let settled = if state == BatchState::Ready {
                applied(false)
            } else {
                NOTHING
            };
            let mut plan = new_plan();
            let mut step = plan.first();
            let mut passes = 0;
            while !matches!(step, Step::Done(_)) {
                assert_eq!(passes, 0, "the sync must end after its counted pass");
                passes += 1;
                step = plan.next(&report(state, outcome), &settled, watch(1, false));
            }
            assert_eq!(passes, 1);
            assert_eq!(step, Step::Done(Some(pass_retry(outcome))));
        }
    }
}

#[test]
fn a_target_lost_after_a_pass_ends_the_passes() {
    for outcome in OUTCOMES {
        let mut plan = new_plan();
        let step = plan.next(
            &report(BatchState::Pending, outcome),
            &NOTHING,
            watch(1, true),
        );
        assert_eq!(step, Step::Done(None), "{outcome:?}");
    }
}

/// Over every input: a withdrawn pass never passes again, and every counted
/// pass, settled or pending, ends the sync with its retry.
#[test]
fn the_table_never_retries_what_it_must_not() {
    let mut states = vec![BatchState::Ready, BatchState::Pending];
    states.extend(CAUSES.map(BatchState::Withdrawn));
    let mut settlements = vec![NOTHING, applied(false), applied(true)];
    settlements.extend(failures().into_iter().map(|(_, error)| failed(error)));
    for state in states {
        for outcome in OUTCOMES {
            for settled in &settlements {
                for (addresses, targetless) in [(1, false), (2, false), (1, true)] {
                    let mut plan = new_plan();
                    let pass = report(state, outcome);
                    let step = plan.next(&pass, settled, watch(addresses, targetless));
                    let case = format!("{state:?} {outcome:?} {settled:?} {addresses}");
                    if matches!(state, BatchState::Withdrawn(_)) {
                        assert!(matches!(step, Step::Hold(_)), "{case}");
                    }
                    let withdrawn = matches!(state, BatchState::Withdrawn(_));
                    let counted = !withdrawn
                        && settled
                            .as_ref()
                            .is_ok_and(|settled| settled.is_some() || state == BatchState::Pending);
                    if counted {
                        assert_ne!(step, Step::Pass, "{case}");
                        assert!(matches!(step, Step::Done(_)), "{case}");
                    }
                    if targetless {
                        assert!(!matches!(step, Step::Pass | Step::Refresh), "{case}");
                    }
                }
            }
        }
    }
}
