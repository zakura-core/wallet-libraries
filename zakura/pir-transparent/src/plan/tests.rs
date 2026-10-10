use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::transparent_ledger::{
    AccountLifecycle, ChainPoint, WatchOrigin, WatchedAddress,
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
        (ApplyAction::Refresh, ApplyError::PolicyChanged),
        (ApplyAction::Reconcile, ApplyError::Unreconciled),
        (ApplyAction::Skip, ApplyError::StaleReceipt),
        (ApplyAction::NotEnabled, ApplyError::NotEnabled),
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
            assert_eq!(plan.passes(), 0);
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
            ApplyAction::Fail => Step::Fail,
            ApplyAction::Interrupted => Step::Stop(StopCause::Interrupted),
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
            assert_eq!(plan.passes(), 0);
        }
    }
}

/// A stale settlement passes again from the fresh watch set, uncounted, until the
/// refreshes run out.
#[test]
fn stale_settlements_refresh_a_bounded_number_of_times() {
    let ready = report(BatchState::Ready, Outcome::Complete);
    let stale = failed(ApplyError::PolicyChanged);
    let mut plan = new_plan();
    for _ in 0..PassLimits::default().stale_refreshes {
        assert_eq!(plan.next(&ready, &stale, watch(1, false)), Step::Refresh);
    }
    assert_eq!(plan.next(&ready, &stale, watch(1, false)), Step::Skip);
    assert_eq!(plan.passes(), 0);

    // A refresh that finds no target has nothing to pass.
    let mut plan = new_plan();
    assert_eq!(plan.next(&ready, &stale, watch(1, true)), Step::Done(None));

    // Refreshes do not reset between passes.
    let limits = PassLimits {
        passes: 8,
        stale_refreshes: 1,
    };
    let mut plan = PassPlan::new(watch(1, false), limits);
    assert_eq!(plan.next(&ready, &stale, watch(1, false)), Step::Refresh);
    let more = report(BatchState::Ready, Outcome::More);
    assert_eq!(
        plan.next(&more, &applied(false), watch(1, false)),
        Step::Pass
    );
    assert_eq!(plan.next(&ready, &stale, watch(1, false)), Step::Skip);
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

/// Settled or pending, a pass follows its retry: at once after `More`, after the
/// wait for `After`, and only for new work after `Complete` or `Stalled`.
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
                let new_work = grew || addresses_changed;
                for outcome in OUTCOMES {
                    let mut plan = new_plan();
                    let fresh = watch(1 + u8::from(addresses_changed), false);
                    let step = plan.next(&report(state, outcome), &settled, fresh);
                    let expected = match outcome {
                        Outcome::More => Step::Pass,
                        Outcome::Behind => Step::Wait(Retry::BEHIND),
                        Outcome::Overloaded => Step::Wait(Retry::OVERLOADED),
                        Outcome::Complete | Outcome::Stalled if new_work => Step::Pass,
                        Outcome::Complete => Step::Done(Some(Retry::Complete)),
                        Outcome::Stalled => Step::Done(Some(Retry::Stalled)),
                    };
                    assert_eq!(
                        step, expected,
                        "{state:?} grew={grew} changed={addresses_changed} {outcome:?}"
                    );
                    assert_eq!(plan.passes(), 1);
                }
            }
        }
    }
}

/// The plan compares each fresh watch set with the one the pass ran with, not the
/// first one it was given.
#[test]
fn new_work_is_measured_against_the_last_watch_set() {
    let complete = report(BatchState::Pending, Outcome::Complete);
    let mut plan = new_plan();
    assert_eq!(plan.next(&complete, &NOTHING, watch(3, false)), Step::Pass);
    assert_eq!(plan.watch().addresses.len(), 3);
    assert_eq!(
        plan.next(&complete, &NOTHING, watch(3, false)),
        Step::Done(Some(Retry::Complete))
    );
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

/// The pass limit ends a run that would otherwise go on, with the last retry.
#[test]
fn the_pass_limit_ends_the_passes() {
    let limits = PassLimits {
        passes: 3,
        stale_refreshes: 3,
    };
    for outcome in [Outcome::More, Outcome::Behind, Outcome::Complete] {
        let mut plan = PassPlan::new(watch(1, false), limits);
        let pass = report(BatchState::Ready, outcome);
        for _ in 1..limits.passes {
            assert_ne!(
                plan.next(&pass, &applied(true), watch(1, false)),
                Step::Done(Some(pass.retry()))
            );
        }
        assert_eq!(
            plan.next(&pass, &applied(true), watch(1, false)),
            Step::Done(Some(pass.retry())),
            "{outcome:?}"
        );
        assert_eq!(plan.passes(), limits.passes);
    }
    let defaults = PassLimits::default();
    assert_eq!((defaults.passes, defaults.stale_refreshes), (8, 3));
}

/// Over every input: a wait comes only from a retry that names one, a withdrawn
/// pass never passes again, and only settled or pending passes count.
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
                    if let Step::Wait(wait) = step {
                        assert_eq!(pass.retry(), Retry::After(wait), "{case}");
                    }
                    if matches!(state, BatchState::Withdrawn(_)) {
                        assert!(matches!(step, Step::Hold(_)), "{case}");
                    }
                    let withdrawn = matches!(state, BatchState::Withdrawn(_));
                    let counted = !withdrawn
                        && settled
                            .as_ref()
                            .is_ok_and(|settled| settled.is_some() || state == BatchState::Pending);
                    assert_eq!(plan.passes(), usize::from(counted), "{case}");
                    if targetless {
                        assert!(
                            !matches!(step, Step::Pass | Step::Refresh | Step::Wait(_)),
                            "{case}"
                        );
                    }
                }
            }
        }
    }
}
