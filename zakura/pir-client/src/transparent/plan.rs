//! Settling the batch a pass held, and the decision table that says what a wallet does
//! after each pass, with feature `sqlite`.
//!
//! [`PassPlan`] is pure: it makes no request, reads no clock and touches no database. The
//! wallet runs the passes, settles them and stops; the plan only says which.

use rusqlite::Connection;
use zakura_pir_protocol::transparent::recovery::TransparentAddressWatchSet;
use zcash_client_sqlite::{AccountUuid, WalletDb};
use zcash_protocol::consensus;

#[cfg(doc)]
use crate::transparent::apply::ApplyError;
use crate::transparent::apply::{Applied, ApplyAction, ApplyFailure, Trust, WriteGate};
use crate::transparent::batch::{BatchState, WithdrawnCause};
use crate::transparent::pass::PassReport;
use crate::transparent::progress::Retry;
use crate::transparent::transparent_history_recovery::TransparentHistoryRecovery;

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
    /// [`Step::Refresh`]es a plan allows; the next stale settlement is [`Step::Skip`].
    pub stale_refreshes: usize,
}

impl Default for PassLimits {
    /// Three refreshes, as Vizor runs an account.
    fn default() -> Self {
        Self { stale_refreshes: 3 }
    }
}

/// What a wallet does next with an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Pass now, with [`PassPlan::watch`]: only [`PassPlan::first`] returns it.
    Pass,
    /// Pass again now, with [`PassPlan::watch`]: a commit of the settlement was stale
    /// for the watch set the pass ran with. It does not count as a pass.
    Refresh,
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
    /// The account's passes ended for this sync: the counted pass's retry, or `None`
    /// when the watch set has no target, so there is nothing to pass. Offer the account
    /// for activation; the wallet rechecks everything itself. Whatever the retry, the
    /// next pass waits for the next sync, which reads the fresh watch set. A
    /// [`Retry::After`] delay belongs to scheduling that next sync.
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
    /// A directory entry of the account's failed on content three times, so it is no
    /// longer queried and the account cannot be covered. Each failure is something a
    /// service could aim at chosen rows; only a new companion asks the entry again.
    FailedEntries,
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
/// # use zakura_pir_client::transparent::{
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
/// applied commits can grow the window. A [`PassError`](crate::transparent::PassError) is the
/// caller's: an outage ends the run, anything else the account's passes.
pub struct PassPlan<A> {
    watch: TransparentAddressWatchSet<A>,
    limits: PassLimits,
    refreshes: usize,
}

impl<A> PassPlan<A> {
    /// A plan for the account whose watch set is `watch`, freshly read.
    pub fn new(
        watch: TransparentAddressWatchSet<A, impl crate::transparent::RecoveryHash>,
        limits: PassLimits,
    ) -> Self {
        let watch = watch.map_block_hash(crate::transparent::RecoveryHash::into_recovery_hash);
        Self {
            watch,
            limits,
            refreshes: 0,
        }
    }

    /// The watch set the next pass runs with.
    pub fn watch(&self) -> &TransparentAddressWatchSet<A> {
        &self.watch
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
    /// 4. The pass counts, and it is the sync's only one. With no target in `fresh`
    ///    there is nothing left to pass: [`Step::Done`] with no retry.
    /// 5. A pass with a directory entry at three content failures
    ///    ([`FailedEntries::held`](crate::transparent::FailedEntries::held)) is
    ///    [`HoldCause::FailedEntries`]: everything else it read was settled above, but the
    ///    entry is no longer queried, so the account cannot be covered.
    /// 6. Every retry is [`Step::Done`] with it, including `After`: a lagging or
    ///    overloaded pass may already have processed private replies. Its delay
    ///    schedules the next sync, so a settled commit that grew the window, a
    ///    changed watch set, or `More` cannot start another pass in this sync.
    ///    A pass with failed entries is [`Retry::Stalled`] whatever else stopped it.
    pub fn next(
        &mut self,
        report: &PassReport,
        settled: &Result<Option<Applied>, ApplyFailure>,
        fresh: TransparentAddressWatchSet<A, impl crate::transparent::RecoveryHash>,
    ) -> Step {
        self.watch = fresh.map_block_hash(crate::transparent::RecoveryHash::into_recovery_hash);
        if let BatchState::Withdrawn(cause) = report.state {
            return Step::Hold(HoldCause::Withdrawn(cause));
        }
        match settled {
            Ok(Some(_)) => {}
            Ok(None) if report.settleable() => return Step::Skip,
            Ok(None) => {}
            Err(failure) => return self.after_failure(failure.action()),
        }
        if self.watch.target.is_none() {
            return Step::Done(None);
        }
        if report.failed_entries.held > 0 {
            return Step::Hold(HoldCause::FailedEntries);
        }
        Step::Done(Some(report.retry()))
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
