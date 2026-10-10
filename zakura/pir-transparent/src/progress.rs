//! How far a pass covered its watch set, why it stopped, and when to pass again.

use std::time::Duration;

use transparent_wallet::{Completion, IncompleteReason, SyncReport};

/// Why a pass stopped. Only [`Outcome::Complete`] covers the whole target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every watched script is covered from its required height through the target.
    Complete,
    /// The publication ends below the target. The pass may still have covered
    /// through the publication's end; a later pass can finish once it catches up.
    Behind,
    /// A query, byte or pending-page budget stopped the pass. The companion keeps
    /// the continuation, so the next pass resumes.
    More,
    /// The service refused for capacity throughout its retry budget.
    Overloaded,
    /// Progress needs more than a retry: an unknown chain block, spends the
    /// watch set cannot resolve, or script discovery past its bound.
    Stalled,
}

/// How far a pass covered the watch set, independent of the commits it returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Height through which every watched script is covered from its required
    /// height, provisional tail coverage included.
    pub covered_through: u64,
    /// Why the pass stopped.
    pub outcome: Outcome,
}

/// When to pass an account again, from how its last pass stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    /// Every watched script is covered through the target. Pass again only
    /// for new work: a changed watch set or a grown window.
    Complete,
    /// A budget stopped the pass. Pass again at once; the companion resumes.
    More,
    /// The publication ends below the target, or the service refused for
    /// capacity. Pass again after the wait.
    After(Duration),
    /// Progress needs more than a retry. Pass again only for new work.
    Stalled,
}

impl Retry {
    /// The wait after a pass whose publication ends below the target.
    pub const BEHIND: Duration = Duration::from_secs(10);
    /// The wait after a pass the service refused for capacity.
    pub const OVERLOADED: Duration = Duration::from_secs(30);
}

impl Progress {
    /// When to pass the account again, from the outcome alone. A pass's
    /// [`RecoveryBatch::retry`](crate::RecoveryBatch::retry) also weighs its state; prefer it.
    pub fn retry(&self) -> Retry {
        match self.outcome {
            Outcome::Complete => Retry::Complete,
            Outcome::More => Retry::More,
            Outcome::Behind => Retry::After(Retry::BEHIND),
            Outcome::Overloaded => Retry::After(Retry::OVERLOADED),
            Outcome::Stalled => Retry::Stalled,
        }
    }

    /// Blocks between `target` and the height the pass covered through.
    pub fn behind(&self, target: u64) -> u64 {
        target.saturating_sub(self.covered_through)
    }
}

impl Progress {
    /// Maps the reference client's report onto the adapter's narrower contract.
    ///
    /// A `clamped` pass synced to the publication's end below the wallet's target,
    /// so even its completion is [`Outcome::Behind`].
    pub(crate) fn from_sync_report(report: &SyncReport, clamped: bool) -> Self {
        let outcome = match &report.completion {
            Completion::Complete if clamped => Outcome::Behind,
            Completion::Complete => Outcome::Complete,
            Completion::Incomplete { reason, .. } => match reason {
                IncompleteReason::QueryBudget
                | IncompleteReason::ByteBudget
                | IncompleteReason::PendingLimit => Outcome::More,
                IncompleteReason::PublicationBehind { .. } => Outcome::Behind,
                IncompleteReason::Overloaded { .. } => Outcome::Overloaded,
                IncompleteReason::ChainUnknown { .. }
                | IncompleteReason::UnresolvedSpends
                | IncompleteReason::DiscoveryUnbounded => Outcome::Stalled,
            },
        };
        Self {
            covered_through: report.covered_through,
            outcome,
        }
    }
}
