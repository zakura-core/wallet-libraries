//! Continuous recovery of an account's one-time keys from a receiver directory's paid
//! buckets and cumulative snapshots.
//!
//! The account's receiver set is every registered key, whatever its state, and a window
//! of each purpose's indices from zero. A store that implements
//! [`OneTimeIvkCoverageWrite`] keeps which history of that set the directory has covered:
//!
//! - A frontier: every receiver in the set had no payment through it, apart from the hits
//!   whose lookups are recorded. It moves by consuming closed buckets tested against the
//!   whole set.
//! - Historical obligations: receivers that joined the set after the frontier passed part
//!   of their history. Each pins a cumulative snapshot, then bridges through the frontier
//!   it owes with buckets tested against its own receivers.
//! - Lookups: each hit's history read over PIR up to a target, with a generation that
//!   fences out walks a rewind or a history change made stale.
//!
//! Each write commits atomically, together with the work it creates, so a caller may stop
//! between any two. A write the store refuses changes nothing.

#[cfg(feature = "test-dependencies")]
use ambassador::delegatable_trait;
use zakura_one_time_ivk::{KeyId, Purpose};
use zcash_protocol::consensus::BlockHeight;

use super::{
    OneTimeIvkRead, OneTimeIvkWrite,
    restore::{DirectoryPayment, DiscoveryWork, LookupWork, PublicationEnd},
};
use crate::data_api::{WalletRead, transparent_ledger::ChainPoint};

/// Which directory history coverage follows. Steps from another history are refused (see
/// [`OneTimeIvkCoverageWrite::reset_one_time_history`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryHistory {
    /// The identity of the directory's catalog, the same in every publication of it.
    pub catalog: [u8; 32],
    /// The catalog's payment-history epoch, which every correction to published history
    /// raises.
    pub epoch: u64,
}

/// A cumulative snapshot of the paid set, through its cutoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The last block the snapshot covers.
    pub cutoff: ChainPoint,
    /// The snapshot object's digest.
    pub digest: [u8; 32],
}

/// One step of directory coverage: a closed bucket, or a cumulative snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverageStep {
    /// The block a bucket starts after, or `None` for a cumulative snapshot, which covers
    /// every block through `end`.
    pub start: Option<ChainPoint>,
    /// The last block the step covers.
    pub end: ChainPoint,
    /// The step object's digest.
    pub digest: [u8; 32],
    /// The history the step belongs to.
    pub history: DirectoryHistory,
}

/// What a coverage write applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageTarget {
    /// The account's frontier, tested against the receiver set of this generation (see
    /// [`ReceiverSet::generation`]).
    Frontier {
        /// The generation of the receiver set the step was tested against.
        generation: u64,
    },
    /// A historical obligation, tested against its own receivers.
    Obligation {
        /// The obligation's ID (see [`Obligation::id`]). IDs are never reused.
        id: u64,
        /// The account's receiver-set generation when the caller read the obligation
        /// (see [`CoverageState::generation`]), which fences out work a rewind or a
        /// history change made stale.
        generation: u64,
    },
}

/// What a coverage write did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageOutcome {
    /// The step and its hits' lookups were recorded.
    Recorded,
    /// The receiver set's generation changed since the caller read it, the obligation is
    /// gone, or the set's window receivers are not all derived yet: read again and test
    /// again.
    Stale,
    /// The wallet has not stored the step's last block, so it cannot check the step
    /// against its chain yet.
    Pending,
    /// The step's last block is not on the wallet's chain.
    OffChain,
    /// The step does not continue the target's coverage, or a cumulative step is not the
    /// snapshot pinned for it (see [`OneTimeIvkCoverageWrite::pin_one_time_snapshot`]).
    Discontinuous,
    /// The step comes from another history than the account follows.
    HistoryChanged,
}

/// The receivers of one purpose's window, indices `0..end`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    /// The keys' purpose.
    pub purpose: Purpose,
    /// The first index past the window.
    pub end: u64,
    /// The first index whose receiver is not derived yet. The window is complete once
    /// this reaches `end`.
    pub derived: u64,
}

/// The receivers an obligation owes history for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObligationReceivers {
    /// One registered key, outside its purpose's window when it registered.
    Key(KeyId),
    /// Window indices `start..end` of one purpose.
    Window {
        /// The keys' purpose.
        purpose: Purpose,
        /// The first index.
        start: u64,
        /// The first index past the range.
        end: u64,
    },
}

/// History that receivers which joined the set after the frontier passed it still need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Obligation {
    /// The obligation's ID.
    pub id: u64,
    /// The receivers it covers.
    pub receivers: ObligationReceivers,
    /// The first block whose payments the account recovers (its birthday).
    pub lower: BlockHeight,
    /// The last block it covers: the frontier when it was created.
    pub through: BlockHeight,
    /// The cumulative snapshot it pinned, if any. It never moves to a newer one.
    pub snapshot: Option<Snapshot>,
    /// How far it has covered once its snapshot was tested: the snapshot's cutoff, then
    /// each bridging bucket's end. It completes, and disappears, at `through`.
    pub bridged: Option<BlockHeight>,
}

/// An account's directory coverage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageState {
    /// The receiver set's generation, which every addition to it raises.
    pub generation: u64,
    /// The history coverage follows, once a frontier was first established.
    pub history: Option<DirectoryHistory>,
    /// The frontier and the receiver-set generation it was last tested against, if
    /// established.
    pub frontier: Option<(ChainPoint, u64)>,
    /// The cumulative snapshot pinned to establish the frontier, until it is.
    pub bootstrap: Option<Snapshot>,
    /// Both purposes' windows.
    pub windows: [Window; 2],
    /// The account's outstanding obligations.
    pub obligations: Vec<Obligation>,
}

/// The receivers coverage tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverSet {
    /// The set's generation (see [`CoverageTarget::Frontier`]).
    pub generation: u64,
    /// Every registered key and every derived window receiver, by purpose and index.
    pub receivers: Vec<DiscoveryWork>,
    /// Whether every window receiver is derived. A frontier step is refused until it is.
    pub complete: bool,
}

/// A lookup handed to a walk: its target and the generation it was dispatched at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupTicket {
    /// The key, its receiver, the target cutoff and where paging resumes.
    pub work: LookupWork,
    /// The lookup's generation, which a restart raises.
    pub generation: u64,
}

/// Reads of an account's directory coverage.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeIvkCoverageRead: OneTimeIvkRead {
    /// The account's coverage, or `None` if it has no one-time keys to recover: it has no
    /// Orchard viewing key, or Ironwood is not active. An unknown account is an error.
    fn one_time_coverage(
        &self,
        account: Self::AccountId,
    ) -> Result<Option<CoverageState>, Self::Error>;

    /// The account's receiver set, closed keys included.
    fn one_time_receiver_set(&self, account: Self::AccountId) -> Result<ReceiverSet, Self::Error>;
}

/// Writes of an account's directory coverage.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeIvkCoverageWrite: OneTimeIvkWrite + OneTimeIvkCoverageRead {
    /// Registers the refund keys of the account's stored funding memos, grows its windows
    /// to cover its keys, and derives at most `budget` window receivers. Returns whether
    /// every window receiver is derived. The next call resumes where this one stopped.
    fn prepare_one_time_coverage(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        budget: u32,
        now: i64,
    ) -> Result<bool, <Self as WalletRead>::Error>;

    /// Pins `snapshot` for `target` unless one is pinned already, and returns the pinned
    /// snapshot. The frontier takes one only until it is established, and an obligation
    /// only until its snapshot is tested. Otherwise, or if the target's generation is not
    /// current, this returns `None` and pins nothing.
    fn pin_one_time_snapshot(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        target: CoverageTarget,
        snapshot: Snapshot,
    ) -> Result<Option<Snapshot>, <Self as WalletRead>::Error>;

    /// Records that `step` was tested against `target`'s receivers, which matched only
    /// `hits`, and makes each hit's lookup due through the step's end. A hit outside the
    /// target's receivers is an error, and a hit's index never becomes allocated or
    /// issued. A cumulative step must be the snapshot pinned for the target, and the
    /// target's generation must be current. A frontier's first step is its pinned
    /// snapshot, which sets the history it follows. Each later one is a bucket starting at
    /// or below the frontier and ending above it, tested against the current, completely
    /// derived receiver set. An obligation tests its snapshot, then buckets that continue
    /// from it, and completes at its `through`. The step's last block must be on the
    /// wallet's chain, unless it precedes the account's birthday.
    fn record_one_time_coverage(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        target: CoverageTarget,
        step: CoverageStep,
        hits: &[KeyId],
        now: i64,
    ) -> Result<CoverageOutcome, <Self as WalletRead>::Error>;

    /// Follows `history` from now on, if it is another catalog or a newer epoch: the
    /// frontier, its pinned snapshot and every obligation are dropped, so the whole set is
    /// bootstrapped again, and every lookup restarts from page zero, including those that
    /// found payments. Returns whether anything changed.
    fn reset_one_time_history(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        history: DirectoryHistory,
    ) -> Result<bool, <Self as WalletRead>::Error>;

    /// Hands out the account's lookups due at `now`, recording each one's target and
    /// generation as dispatched, which supersedes an earlier ticket.
    fn dispatch_one_time_lookups(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        now: i64,
    ) -> Result<Vec<LookupTicket>, <Self as WalletRead>::Error>;

    /// Applies a page of `ticket`'s walk as
    /// [`OneTimeIvkRestoreWrite::record_one_time_lookup`] does, against the ticket's own
    /// target. Completing it marks the lookup done through that target alone: a target
    /// widened since stays due. Returns false, applying nothing, unless the ticket is the
    /// lookup's latest and its generation is current.
    ///
    /// [`OneTimeIvkRestoreWrite::record_one_time_lookup`]: super::restore::OneTimeIvkRestoreWrite::record_one_time_lookup
    #[allow(clippy::too_many_arguments)]
    fn record_one_time_lookup_page(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        ticket: &LookupTicket,
        revision: PublicationEnd,
        page: u32,
        records: &[DirectoryPayment],
        complete: bool,
        now: i64,
    ) -> Result<bool, <Self as WalletRead>::Error>;
}
