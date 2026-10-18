//! What one pass returns: its candidate commits, its progress, and whether the commits
//! may reach the wallet.

use zakura_transparent_recovery_types::{RecoveryRevision, TransparentLedgerCommit};

use crate::progress::{FailedEntries, Outcome, Progress, Retry};
#[cfg(doc)]
use crate::{RecoveryError, TransparentHistoryRecovery};

/// Whether a pass's commits may reach the wallet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchState {
    /// The publication agrees with everything this companion recorded, and every
    /// revision it exported is still published, declared superseded by a
    /// re-cut, or has a successor at a higher lineage among the batch's
    /// commits. Apply the commits, then acknowledge.
    ///
    /// A successor withdraws its predecessor's provisional evidence only when
    /// the wallet qualifies it, so `Ready` assumes the commits are applied
    /// through the trusted operation. The predecessors are the batch's
    /// [`RecoveryBatch::retired_revisions`](crate::RecoveryBatch::retired_revisions),
    /// and such a batch is acknowledged only by applying its commits through
    /// the trusted operation with `TransparentHistoryRecovery::settle_latest`
    /// (feature `sqlite`).
    Ready,
    /// The publication or this companion's retrieval is behind what the
    /// companion recorded: a lagging replica (one serving a shard unsealed below
    /// a revision the companion saw, even a sealed one), a map ending below an
    /// exported revision, stored facts naming a revision the map neither
    /// publishes nor declares, a shard ending on a block the wallet's chain
    /// does not hold, or an exported tail whose successor is not retrieved yet,
    /// or a store a publication change reset that has not bound the new set
    /// again. A publication that diverged from what the sync read (a map
    /// refreshed mid-pass that does not continue the one the pass started
    /// from), a map under another set that ends below the height the store
    /// synced to, and a map the sync refuses as a rewrite of history the store
    /// holds but whose re-cut epoch is below the one this companion recorded,
    /// taken for a replica still serving the publication from before that
    /// re-cut, are also `Pending`, with
    /// [`Outcome::Behind`](crate::Outcome::Behind). The batch has no commits or
    /// retired revisions and cannot be acknowledged; a later pass can be
    /// `Ready`.
    Pending,
    /// The publication contradicts what this companion recorded. The batch has
    /// no commits or retired revisions and cannot be acknowledged, and passes
    /// stay withdrawn until the publication changes.
    ///
    /// Keep the companion meanwhile: hold and retry later, or stop recovering
    /// from this publication. A recreated companion has no record of what this
    /// one exported, so it cannot see the contradiction and may export
    /// revisions that collide with ones the wallet already holds. Not even
    /// [`RecoveryError::PublicationChanged`] calls for a new companion: the
    /// adapter resets the companion's store itself and keeps this catalog.
    Withdrawn(WithdrawnCause),
}

/// How a publication contradicts this companion's catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithdrawnCause {
    /// A sealed shard is published at a lower revision than this companion
    /// recorded for its source, or a shard is published below a revision the
    /// map declares a re-cut superseded in its source.
    Regression,
    /// One revision of a source is published or declared as two different
    /// shard revisions, or a re-cut declares a revision otherwise than this
    /// companion recorded it.
    Equivocation,
    /// A sealed revision a batch exported is neither published nor declared
    /// superseded by a re-cut, and its source is published at another revision
    /// that is not merely an older unsealed one; or the map rewrites sealed
    /// history the companion's store holds without declaring a re-cut, and the
    /// wallet's chain accepts both the stored range's end block and the end
    /// block of the sealed shard replacing it, which the sync refuses before
    /// reading anything. A declared re-cut never causes it.
    ChangedSealed,
    /// The heights of a revision a batch exported are published under another
    /// source, as after a geometry change or an undeclared re-cut. A declared
    /// re-cut never causes it.
    Retired,
}

/// Candidate observations and reference progress from one pass.
///
/// The batch is opaque: its commits can be read, never edited. With feature
/// `sqlite`, settling a [`BatchState::Ready`] batch consumes it, applies every
/// commit to a SQLite wallet and acknowledges it, reconciling its
/// [`RecoveryBatch::retired_revisions`] when the caller trusts the commits.
/// Without it, a batch can be read or discarded, never acknowledged, so the next
/// pass exports it again. Neither the batch nor a server withdrawal is
/// authority to change local facts or activate an account.
pub struct RecoveryBatch<AccountId> {
    /// The commits in the order they apply; empty unless `state` is ready.
    pub(crate) commits: Vec<TransparentLedgerCommit<AccountId>>,
    /// How far the pass covered its watch set, and why it stopped.
    pub(crate) progress: Progress,
    /// Whether the commits may reach the wallet.
    pub(crate) state: BatchState,
    /// The retired revisions this batch's commits resolve, as its pass recorded
    /// them. Acknowledging the batch forgets them.
    pub(crate) retired_revisions: Vec<RecoveryRevision>,
    /// What acknowledging the batch must present: the companion's
    /// outstanding receipt when the batch was issued. All zero for a batch that
    /// cannot be acknowledged.
    // Only settlement (feature `sqlite`) acknowledges a batch.
    #[cfg_attr(not(any(test, feature = "sqlite")), allow(dead_code))]
    pub(crate) receipt: [u8; 32],
    /// The directory entries the pass's sync failed on content or held at the cap.
    pub(crate) failed_entries: FailedEntries,
}

impl<A> RecoveryBatch<A> {
    /// Source-bound normalized commits, including unfinished page work, in the
    /// order they apply. Empty unless [`Self::state`] is [`BatchState::Ready`].
    pub fn commits(&self) -> &[TransparentLedgerCommit<A>] {
        &self.commits
    }

    /// How far this pass covered the watch set, and why it stopped. Anything but
    /// [`Outcome::Complete`] is never synchronized.
    pub fn progress(&self) -> Progress {
        self.progress
    }

    /// Whether the commits may be applied: only a [`BatchState::Ready`] batch
    /// has commits or can be acknowledged.
    pub fn state(&self) -> BatchState {
        self.state
    }

    /// The directory entries this pass could not read because their private replies
    /// failed on content, counted. The batch still holds everything else the pass read.
    pub fn failed_entries(&self) -> FailedEntries {
        self.failed_entries
    }

    /// When to pass the account again. A [`BatchState::Withdrawn`] batch is
    /// [`Retry::Stalled`] whatever its progress, which can even be
    /// [`Outcome::Complete`]: the publication contradicts the catalog, and
    /// passing again on a timer reads the same contradiction. Keep the
    /// companion and pass again for new work. So is a batch with
    /// [`Self::failed_entries`], whatever else stopped its pass: a pass again on
    /// a timer would ask a failed entry again in the same sync, a reaction a
    /// service could aim at chosen rows. Otherwise this is [`Progress::retry`].
    pub fn retry(&self) -> Retry {
        retry(self.state, self.progress, self.failed_entries)
    }

    /// Exactly the retired provisional revisions this batch resolves: each was
    /// exported by an earlier batch, is no longer published, and has a successor
    /// among [`Self::commits`] for the same source at a higher lineage. Empty
    /// unless [`Self::state`] is [`BatchState::Ready`].
    ///
    /// These are notifications, not authority to withdraw wallet evidence. The
    /// wallet resolves them when it applies every commit through its trusted
    /// operation, `TransparentLedgerWrite::qualify_and_apply_transparent_ledger_commit`,
    /// which qualifies each successor and withdraws its source's older
    /// provisional evidence in the same wallet transaction. Only settlement
    /// (feature `sqlite`) with trusted commits acknowledges such a batch. The
    /// trusted operation qualifies whatever it is given, so a
    /// caller that does not trust the batch's origin cannot use it and never
    /// acknowledges a batch with retirements.
    ///
    /// Until the batch is acknowledged the companion keeps them: the next pass
    /// lists them again, with any retirement found since, or is
    /// [`BatchState::Pending`] while it cannot export their successors. Only a
    /// publication change forgets them unacknowledged:
    /// [`RecoveryError::PublicationChanged`] drops those of sources the new map
    /// no longer names, which no successor can resolve, and the wallet keeps
    /// their provisional evidence.
    pub fn retired_revisions(&self) -> &[RecoveryRevision] {
        &self.retired_revisions
    }

    /// The commits and recorded retirements, for the adapter's own settlement.
    #[cfg(feature = "sqlite")]
    pub(crate) fn into_parts(self) -> (Vec<TransparentLedgerCommit<A>>, Vec<RecoveryRevision>) {
        (self.commits, self.retired_revisions)
    }

    /// A batch no companion issued, for [`crate::testing`].
    #[cfg(feature = "testing")]
    pub(crate) fn unissued(
        commits: Vec<TransparentLedgerCommit<A>>,
        progress: Progress,
        state: BatchState,
        retired_revisions: Vec<RecoveryRevision>,
    ) -> Self {
        Self {
            commits,
            progress,
            state,
            retired_revisions,
            receipt: [0; 32],
            failed_entries: FailedEntries::default(),
        }
    }
}

/// When to pass an account again after a pass in `state` with `progress` that failed
/// `failed` entries: never on a timer for a [`BatchState::Withdrawn`] one or one with
/// failed entries, otherwise as its progress says.
pub(crate) fn retry(state: BatchState, progress: Progress, failed: FailedEntries) -> Retry {
    match state {
        BatchState::Withdrawn(_) => Retry::Stalled,
        _ if failed.entries > 0 => Retry::Stalled,
        BatchState::Ready | BatchState::Pending => progress.retry(),
    }
}

/// A batch that is not [`BatchState::Ready`]: no commits, and nothing to
/// acknowledge.
pub(crate) fn unready_batch<A>(state: BatchState, progress: Progress) -> RecoveryBatch<A> {
    RecoveryBatch {
        commits: vec![],
        progress,
        state,
        retired_revisions: vec![],
        receipt: [0; 32],
        failed_entries: FailedEntries::default(),
    }
}

/// A [`BatchState::Pending`] batch for a pass that read nothing from a
/// publication it must wait for. Like the reference client stopping before it
/// reads anything, it claims no coverage.
pub(crate) fn behind_unread_batch<A>() -> RecoveryBatch<A> {
    unready_batch(
        BatchState::Pending,
        Progress {
            covered_through: 0,
            outcome: Outcome::Behind,
        },
    )
}
