//! Settling the batch a pass held, and the decision table that says what a wallet does
//! after each pass, with feature `sqlite`.
//!
//! [`PassPlan`] is pure: it makes no request, reads no clock and touches no database. The
//! wallet runs the passes, settles them, waits and stops; the plan only says which.

use std::time::Duration;

use rusqlite::Connection;
use zcash_client_backend::data_api::transparent_ledger::TransparentAddressWatchSet;
use zcash_client_sqlite::{AccountUuid, WalletDb};
use zcash_protocol::consensus;

#[cfg(doc)]
use crate::apply::ApplyError;
use crate::apply::{Applied, ApplyAction, ApplyFailure, Trust, WriteGate};
use crate::batch::{BatchState, WithdrawnCause};
use crate::pass::PassReport;
use crate::progress::Retry;
use crate::transparent_history_recovery::TransparentHistoryRecovery;

impl TransparentHistoryRecovery {
    /// Settles the ready batch the latest [`Self::pass`] held:
    /// [`Self::apply_and_acknowledge_gated`] with `trust` and `gate`.
    ///
    /// `Ok(None)` when no batch is held: the pass was pending or withdrawn, or its
    /// batch was already taken. Whatever the outcome, the batch is no longer held.
    /// [`Trust::Observed`] with retired revisions fails with
    /// [`ApplyError::Unreconciled`] before `gate` runs or the wallet is written, so
    /// a caller settles every pass and lets [`PassPlan::next`] hold the account.
    pub fn settle_latest<P: consensus::Parameters, CL, R>(
        &mut self,
        wallet: &mut WalletDb<Connection, P, CL, R>,
        trust: Trust,
        gate: &mut impl WriteGate,
    ) -> Result<Option<Applied>, ApplyFailure> {
        let Some(batch) = self.take_latest::<AccountUuid>() else {
            return Ok(None);
        };
        self.apply_and_acknowledge_gated(batch, wallet, trust, gate)
            .map(Some)
    }
}

/// The bounds of one account's passes in one run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassLimits {
    /// Passes a plan runs before [`Step::Done`]. A [`Step::Refresh`] does not count.
    pub passes: usize,
    /// [`Step::Refresh`]es a plan allows; the next stale settlement is [`Step::Skip`].
    pub stale_refreshes: usize,
}

impl Default for PassLimits {
    /// Eight passes and three refreshes, as Vizor runs an account.
    fn default() -> Self {
        Self {
            passes: 8,
            stale_refreshes: 3,
        }
    }
}

/// What a wallet does next with an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Pass again now, with [`PassPlan::watch`].
    Pass,
    /// Pass again now, with [`PassPlan::watch`]: a commit of the settlement was stale
    /// for the watch set the pass ran with. It does not count as a pass.
    Refresh,
    /// Pass again after the wait: the publication ends below the target, or the
    /// service refused for capacity.
    Wait(Duration),
    /// The account cannot progress until something outside recovery changes: skip
    /// it, without traffic, for longer than a run.
    Hold(HoldCause),
    /// This run cannot progress the account: the wallet refused a commit, the
    /// acknowledgment failed, a ready batch went unsettled, its commits stayed stale, or
    /// the caller's [`WriteGate`] stopped the settlement between wallet writes. What
    /// applied stays, and a later run passes the account again and replays the rest.
    ///
    /// A gate stops a settlement when the account's own time budget ran out as well as
    /// when the whole run is cancelled; the plan cannot tell which, so it skips only the
    /// account. A caller that checks its own cancellation before the next account's pass
    /// still stops a cancelled run.
    Skip,
    /// Stop the whole run.
    Stop(StopCause),
    /// The wallet failed or its connection was inside a transaction: report the
    /// [`ApplyFailure`] the settlement returned.
    Fail,
    /// The account's passes ended: the last pass's retry, or `None` when the watch
    /// set has no target, so there is nothing to pass. Offer the account for
    /// activation; the wallet rechecks everything itself.
    Done(Option<Retry>),
}

/// Why an account is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldCause {
    /// The publication contradicts the companion. Passing again on a timer reads the
    /// same contradiction; keep the companion and wait for the publication to change.
    Withdrawn(WithdrawnCause),
    /// The batch resolves retired revisions, which only [`Trust::Trusted`]
    /// settlement reconciles. Each observed pass would add one more.
    Unreconciled,
}

/// Why a run stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopCause {
    /// The handle or the durable policy does not permit this recovery.
    NotEnabled,
    /// The wallet's policy generation changed after the run read it, perhaps because
    /// private queries were turned off: no further private pass may run under the policy
    /// the run captured. The next run captures the policy again.
    PolicyChanged,
}

/// The decision table for one account's passes in one run: after each pass and its
/// settlement, the next [`Step`].
///
/// The plan owns the watch set every pass uses, so a pass can only run with the one
/// the plan last read; the chain view is built from its target. The sequence:
///
/// ```no_run
/// # use rusqlite::Connection;
/// # use zakura_pir_transparent::{
/// #     Companion, HttpExchange, PassLimits, PassPlan, Step, Trust, Ungated, WalletChain,
/// # };
/// # use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerRead as _;
/// # use zcash_client_sqlite::{AccountUuid, WalletDb};
/// # use zcash_protocol::consensus::Parameters;
/// # type Error = Box<dyn std::error::Error>;
/// fn recover_account<P: Parameters, CL, R>(
///     companion: &mut Companion,
///     wallet: &mut WalletDb<Connection, P, CL, R>,
///     account: AccountUuid,
///     exchange: &impl HttpExchange,
///     trust: Trust,
///     should_stop: &dyn Fn() -> bool,
/// ) -> Result<Option<Step>, Error> {
///     let mut plan = PassPlan::new(wallet.transparent_watch_set(account)?, PassLimits::default());
///     let mut step = plan.first();
///     loop {
///         match step {
///             Step::Pass | Step::Refresh => {}
///             // Bounded by the caller's own time budget.
///             Step::Wait(wait) => std::thread::sleep(wait),
///             step => return Ok(Some(step)),
///         }
///         if should_stop() {
///             return Ok(None);
///         }
///         let target = plan.watch().target.expect("a planned pass has a target");
///         let chain = WalletChain::new(&*wallet, target);
///         let report = companion.pass(plan.watch(), &chain, exchange, 8 << 20, should_stop)?;
///         let settled = companion.settle_latest(wallet, trust, &mut Ungated);
///         step = plan.next(&report, &settled, wallet.transparent_watch_set(account)?);
///         if step == Step::Fail {
///             return Err(settled.unwrap_err().into());
///         }
///     }
/// }
/// ```
///
/// Settle every pass, whatever it reported: [`TransparentHistoryRecovery::settle_latest`] does
/// nothing when the pass held nothing, and refuses an observed settlement of retired
/// revisions before writing anything. Read the fresh watch set after settling, since
/// applied commits can grow the window. A [`PassError`](crate::PassError) is the
/// caller's: an outage ends the run, anything else the account's passes.
pub struct PassPlan<A> {
    watch: TransparentAddressWatchSet<A>,
    limits: PassLimits,
    passes: usize,
    refreshes: usize,
}

impl<A> PassPlan<A> {
    /// A plan for the account whose watch set is `watch`, freshly read.
    pub fn new(watch: TransparentAddressWatchSet<A>, limits: PassLimits) -> Self {
        Self {
            watch,
            limits,
            passes: 0,
            refreshes: 0,
        }
    }

    /// The watch set the next pass runs with.
    pub fn watch(&self) -> &TransparentAddressWatchSet<A> {
        &self.watch
    }

    /// Passes counted so far.
    pub fn passes(&self) -> usize {
        self.passes
    }

    /// The first step: [`Step::Pass`], or [`Step::Done`] with no retry while the
    /// watch set has no target.
    pub fn first(&self) -> Step {
        if self.watch.target.is_none() {
            Step::Done(None)
        } else {
            Step::Pass
        }
    }

    /// The step after a pass that reported `report`, whose settlement returned
    /// `settled`, given `fresh`, the account's watch set read after settling, which
    /// the next pass runs with.
    ///
    /// The rules, in order:
    ///
    /// 1. A [`BatchState::Withdrawn`] pass is [`Step::Hold`]: the publication
    ///    contradicts the companion, and only a changed publication can resolve it.
    /// 2. A failed settlement follows [`ApplyFailure::action`]: `Refresh` is
    ///    [`Step::Refresh`] (or [`Step::Done`] with no retry when `fresh` has no
    ///    target), and [`Step::Skip`] once more than
    ///    [`PassLimits::stale_refreshes`] were needed, since a watch set that keeps
    ///    going stale will not settle this run; `Reconcile` is
    ///    [`HoldCause::Unreconciled`]; `Skip` and `Interrupted` are [`Step::Skip`];
    ///    `NotEnabled` and `PolicyChanged` stop the run; `Fail` is [`Step::Fail`].
    /// 3. A ready pass with nothing settled is [`Step::Skip`]: its batch was taken
    ///    elsewhere, and acknowledging it is not this plan's to know.
    /// 4. The pass counts. With no target in `fresh` there is nothing left to pass:
    ///    [`Step::Done`] with no retry.
    /// 5. After [`PassLimits::passes`] passes: [`Step::Done`] with the pass's retry.
    /// 6. By [`PassReport::retry`]: `More` passes again at once, since the companion
    ///    resumes; `After` is [`Step::Wait`]; `Complete` and `Stalled` pass again
    ///    only for new work, a settled commit that grew the window or a watch set
    ///    whose addresses changed, and are otherwise [`Step::Done`].
    pub fn next(
        &mut self,
        report: &PassReport,
        settled: &Result<Option<Applied>, ApplyFailure>,
        fresh: TransparentAddressWatchSet<A>,
    ) -> Step {
        let previous = std::mem::replace(&mut self.watch, fresh);
        if let BatchState::Withdrawn(cause) = report.state {
            return Step::Hold(HoldCause::Withdrawn(cause));
        }
        let window_grew = match settled {
            Ok(Some(applied)) => applied.stats.window_grew,
            Ok(None) if report.settleable() => return Step::Skip,
            Ok(None) => false,
            Err(failure) => return self.after_failure(failure.action()),
        };
        self.passes += 1;
        if self.watch.target.is_none() {
            return Step::Done(None);
        }
        let retry = report.retry();
        if self.passes >= self.limits.passes {
            return Step::Done(Some(retry));
        }
        let new_work = window_grew || self.watch.addresses != previous.addresses;
        match retry {
            Retry::More => Step::Pass,
            Retry::After(wait) => Step::Wait(wait),
            Retry::Complete | Retry::Stalled if new_work => Step::Pass,
            Retry::Complete | Retry::Stalled => Step::Done(Some(retry)),
        }
    }

    /// The step after a settlement that failed with `action`.
    fn after_failure(&mut self, action: ApplyAction) -> Step {
        match action {
            ApplyAction::Refresh => {
                self.refreshes += 1;
                if self.refreshes > self.limits.stale_refreshes {
                    Step::Skip
                } else if self.watch.target.is_none() {
                    Step::Done(None)
                } else {
                    Step::Refresh
                }
            }
            ApplyAction::Reconcile => Step::Hold(HoldCause::Unreconciled),
            // An account's budget, or the run's cancellation, which the caller checks
            // before the next pass.
            ApplyAction::Skip | ApplyAction::Interrupted => Step::Skip,
            ApplyAction::NotEnabled => Step::Stop(StopCause::NotEnabled),
            ApplyAction::PolicyChanged => Step::Stop(StopCause::PolicyChanged),
            ApplyAction::Fail => Step::Fail,
        }
    }
}

#[cfg(test)]
mod tests;
