//! How far a pass covered its watch set, why it stopped, and when to pass again.

use std::time::Duration;

use transparent_wallet::{Completion, IncompleteReason, MAX_CONTENT_FAILURES, SyncReport};

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
    /// watch set cannot resolve, script discovery past its bound, or directory
    /// entries whose private replies failed on content ([`FailedEntries`]).
    Stalled,
}

/// Directory entries (one watched script in one shard) a pass could not read
/// because their private replies failed on content: a row whose content did not
/// decode or check out, or a record contradicting what the companion holds. A
/// reply failing its length, binding or epoch check fails its request instead,
/// and is not counted here. It carries counts only, so it may be logged whole.
///
/// The reference client counts each entry's content failures in the companion
/// and never resets them; at three an entry is no longer queried. Everything
/// else the pass read is settled, but the entry's script stays uncovered over
/// its shard, so the account cannot be activated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FailedEntries {
    /// Entries this pass failed on content, or left unqueried at three failures.
    pub entries: usize,
    /// Of those, the entries at three failures. Only a new companion queries them again.
    pub held: usize,
}

impl FailedEntries {
    /// Counts the reference client's report.
    pub(crate) fn of(report: &SyncReport) -> Self {
        Self {
            entries: report.failed_entries.len(),
            held: report
                .failed_entries
                .iter()
                .filter(|entry| entry.failures >= MAX_CONTENT_FAILURES)
                .count(),
        }
    }
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
    /// for new work, a changed watch set or a grown window, at the next sync.
    Complete,
    /// A budget stopped the pass. Pass again at the next sync; the companion
    /// resumes.
    More,
    /// The publication ends below the target, or the service refused for
    /// capacity. Schedule the next sync after the delay; do not pass again in
    /// the current sync, which may already have processed private replies.
    After(Duration),
    /// Progress needs more than a retry. Pass again only for new work, at the
    /// next sync.
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
                | IncompleteReason::DiscoveryUnbounded
                | IncompleteReason::ContentFailed => Outcome::Stalled,
            },
        };
        Self {
            covered_through: report.covered_through,
            outcome,
        }
    }
}
