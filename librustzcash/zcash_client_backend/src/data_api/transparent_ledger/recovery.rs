//! Candidate recovery: watched addresses, normalized events, coverage, and resumable pages.
//!
//! A recovery run captures a [`TransparentWatchSet`], asks its source about the watched
//! addresses, and submits what it learned as one [`TransparentLedgerCommit`] per account.
//! A candidate account's state is isolated: it never changes balances, spend links, locks,
//! address use, or transaction history. Promoting the account projects its recovered events
//! into the wallet, and an active account's later commits project in the same transaction.

use transparent::{address::TransparentAddress, bundle::OutPoint, keys::TransparentKeyScope};
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use super::{CandidateBlocker, ChainPoint, TransactionMetadata};
use transparent::keys::NonHardenedChildIndex;

/// The longest source, revision, or page identifier a store accepts, in bytes.
pub const MAX_RECOVERY_IDENTIFIER_LEN: usize = 256;

/// Why an address is watched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchOrigin {
    /// Derived at `index` in `scope` and recorded in the wallet's address table.
    Derived {
        /// The derivation scope.
        scope: TransparentKeyScope,
        /// The child index within `scope`.
        index: NonHardenedChildIndex,
    },
    /// Derived beyond the wallet's own address window because candidate recovery found activity
    /// near its end. Such addresses are never added to the wallet's address table, marked
    /// used, or offered for receiving.
    CandidateWindow {
        /// The derivation scope.
        scope: TransparentKeyScope,
        /// The child index within `scope`.
        index: NonHardenedChildIndex,
    },
    /// An imported standalone key or script.
    Standalone,
}

/// A wallet-owned transparent address that recovery must cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchedAddress {
    /// The watched address; its script is what sources match.
    pub address: TransparentAddress,
    /// Why the address is watched.
    pub origin: WatchOrigin,
    /// Coverage must start at or below this height. It is the account's birthday and moves
    /// only earlier.
    pub required_from: BlockHeight,
}

/// Whether an account's ledger is isolated or authoritative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccountLifecycle {
    /// Recovery is isolated from the wallet's projection.
    Candidate,
    /// Promoted: commits also project into the wallet's outputs and spends.
    Active,
}

/// The context a recovery run captures before any source I/O, and that its commit must still
/// satisfy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransparentRecoveryContext<AccountId> {
    /// The account the run recovers.
    pub account: AccountId,
    /// The account's lifecycle when the run started.
    pub lifecycle: AccountLifecycle,
    /// The durable policy generation when the run started.
    pub policy_generation: u64,
    /// The highest contiguously scanned local block when the run started. Events and coverage
    /// cannot extend past it.
    pub target: ChainPoint,
}

/// One account's watched addresses, with the context a recovery run captures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentWatchSet<AccountId> {
    /// The account.
    pub account: AccountId,
    /// The account's lifecycle at the time of the read.
    pub lifecycle: AccountLifecycle,
    /// The durable policy generation at the time of the read.
    pub policy_generation: u64,
    /// The highest contiguously scanned local block; absent before any contiguous scan.
    pub target: Option<ChainPoint>,
    /// Every address recovery must cover, ordered by address. Receivers owned by another
    /// account in production are excluded even if this account can derive them in its
    /// candidate window; only an explicit production ownership transition transfers them.
    pub addresses: Vec<WatchedAddress>,
    /// Pages left open by earlier runs, which a new run should resume.
    pub pending_pages: Vec<PendingPage>,
}

impl<AccountId: Copy> TransparentWatchSet<AccountId> {
    /// The context to recover under, or `None` while no local target exists.
    pub fn context(&self) -> Option<TransparentRecoveryContext<AccountId>> {
        self.target.map(|target| TransparentRecoveryContext {
            account: self.account,
            lifecycle: self.lifecycle,
            policy_generation: self.policy_generation,
            target,
        })
    }
}

/// A publisher's asserted chain position. It is not local chain evidence and never substitutes
/// for a [`ChainPoint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationAnchor {
    /// The height the publisher claims to have indexed through.
    pub height: BlockHeight,
    /// The block hash the publisher claims for `height`.
    pub hash: BlockHash,
}

/// A source revision that supplied a commit's facts.
///
/// Identifiers are opaque and compared bytewise. Within a source, each replacement revision has
/// a strictly greater `lineage`. A provisional revision is superseded only by a trusted qualification transition
/// to a newer revision of the same source; observing a revision does not authorize replacement; a sealed revision never is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryRevision {
    /// The source identifier.
    pub source: Vec<u8>,
    /// The revision identifier within the source.
    pub revision: Vec<u8>,
    /// Replacement order within the source; at most `i64::MAX`.
    pub lineage: u64,
    /// Whether the revision is sealed.
    pub sealed: bool,
    /// The publisher's asserted position for this revision.
    pub publication: PublicationAnchor,
}

/// A recovered transparent output paying a watched address.
///
/// Its identity is the outpoint; the remaining fields are checked content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveEvent {
    /// Creating transaction facts; unavailable for legacy recovery sources.
    pub metadata: Option<TransactionMetadata>,
    /// The output's identity.
    pub outpoint: OutPoint,
    /// The watched address the output pays.
    pub address: TransparentAddress,
    /// The output's value.
    pub value: Zatoshis,
    /// Whether the output was created by a coinbase transaction.
    pub coinbase: bool,
    /// The height of the block that mined it.
    pub mined_height: BlockHeight,
}

/// A recovered transparent input spending an output of a watched address.
///
/// Its identity is the spending txid and input index. The spent outpoint is checked content,
/// not identity, so contradictory spends for the same input cannot hide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendEvent {
    /// Spending transaction facts; never the parent transaction metadata.
    pub metadata: Option<TransactionMetadata>,
    /// The spending transaction.
    pub spending_txid: TxId,
    /// The input's index in the spending transaction.
    pub input_index: u32,
    /// The output the input consumes.
    pub prevout: OutPoint,
    /// The watched address of the consumed output. It attributes a spend recovered before its
    /// output, and is checked against the output when that arrives.
    pub prevout_address: TransparentAddress,
    /// The height of the block that mined the spending transaction.
    pub mined_height: BlockHeight,
}

/// An inclusive height range for one watched address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRange {
    /// The watched address.
    pub address: TransparentAddress,
    /// The first height of the range.
    pub from: BlockHeight,
    /// The last height of the range.
    pub through: BlockHeight,
}

/// A page a commit opens: retrieval work that is started but not finished.
///
/// While open, it blocks coverage of its addresses over its range. A later commit completes it,
/// usually alongside the events and coverage it produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageRequest {
    /// The page identifier within its revision.
    pub page: Vec<u8>,
    /// The watched addresses the page answers for.
    pub addresses: Vec<TransparentAddress>,
    /// The first height the page covers.
    pub from: BlockHeight,
    /// The last height the page covers.
    pub through: BlockHeight,
}

/// An open page, as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPage {
    /// The page as opened.
    pub request: PageRequest,
    /// The revision it belongs to.
    pub revision: RecoveryRevision,
    /// The target of the run that opened it.
    pub target: ChainPoint,
}

/// What one recovery pass learned for one account, applied atomically.
///
/// `coverage` records ranges the source checked for each address, including ranges with no
/// events. `unsupported` records ranges the source cannot check; they block completeness until
/// another source covers them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentLedgerCommit<AccountId> {
    /// The context captured before source I/O.
    pub context: TransparentRecoveryContext<AccountId>,
    /// The revision that supplied these facts.
    pub revision: RecoveryRevision,
    /// The highest local block the source verified the revision agrees with. It must be
    /// locally accepted and at or below the target; nothing in the commit may extend past it.
    pub anchor: ChainPoint,
    /// Recovered receives.
    pub receives: Vec<ReceiveEvent>,
    /// Recovered spends.
    pub spends: Vec<SpendEvent>,
    /// Checked ranges.
    pub coverage: Vec<AddressRange>,
    /// Ranges the source cannot check.
    pub unsupported: Vec<AddressRange>,
    /// Pages this commit opens.
    pub opened_pages: Vec<PageRequest>,
    /// Pages of this revision that this commit completes.
    pub completed_pages: Vec<Vec<u8>>,
}

/// What [`TransparentLedgerWrite::forget_transparent_ledger`] removed.
///
/// [`TransparentLedgerWrite::forget_transparent_ledger`]: super::TransparentLedgerWrite::forget_transparent_ledger
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForgottenTransparentLedger {
    /// Spend links and pending spends that only the ledger supported.
    pub spends: usize,
    /// Outputs that only the ledger supported.
    pub outputs: usize,
    /// Outputs that only the ledger supports, kept without value or authority because they are
    /// locked or a spend from another origin refers to them. These stay and are counted by every
    /// call.
    pub retained_outputs: usize,
    /// Transactions left without wallet evidence.
    pub transactions: usize,
    /// Recovered receive and spend events.
    pub events: usize,
}

impl ForgottenTransparentLedger {
    /// Whether nothing was removed. Retained outputs are reported again by each call.
    pub fn removed_nothing(&self) -> bool {
        self.spends == 0 && self.outputs == 0 && self.transactions == 0 && self.events == 0
    }
}

/// The result of an applied commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitOutcome {
    /// Whether candidate activity near the end of a derived window extended it. The run should
    /// then read a fresh watch set and recover the new addresses at the same target.
    pub window_grew: bool,
}

/// Why a store refused a commit. None of a refused commit's facts are applied.
///
/// An integrity rejection additionally quarantines, in the same transaction, the commit's
/// source, its account, and every other account holding evidence from that source. Quarantined
/// sources and accounts accept no further commits and hold no private authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitRejection {
    /// The captured context no longer holds; retry from a fresh watch set.
    Stale(StaleCommit),
    /// The facts contradict stored evidence; stop trusting the session that produced them.
    Integrity(IntegrityFailure),
    /// The commit is malformed.
    Invalid(InvalidCommit),
    /// The store will not accept this commit; retrying cannot succeed.
    Refused(RefusedCommit),
}

/// A commit the store will not accept whatever its content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefusedCommit {
    /// The source is quarantined by an earlier integrity rejection.
    SourceQuarantined,
    /// The account is quarantined by an earlier integrity rejection.
    AccountQuarantined,
    /// The account is active and the revision is not qualified to support its authority.
    UnqualifiedRevision,
}

/// A context mismatch that a fresh watch set resolves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StaleCommit {
    /// The account no longer exists.
    AccountUnknown,
    /// The target is no longer a contiguously scanned local block.
    TargetNotAccepted,
    /// The anchor is no longer a local block.
    AnchorNotAccepted,
    /// The account no longer watches this address.
    AddressNotWatched(TransparentAddress),
    /// The page is not open for this account and revision.
    UnknownPage(Vec<u8>),
    /// The provisional revision was superseded by a newer revision of its source.
    SupersededRevision,
    /// The account was promoted or demoted since the run started.
    LifecycleChanged,
}

/// Facts that contradict stored evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntegrityFailure {
    /// Retained observations disagree about a transaction fact.
    TransactionMetadata(TxId),
    /// The revision identifier is known with different lineage, sealing, or publication, or
    /// another revision of the source has the same lineage.
    RevisionMismatch,
    /// A stored receive with this outpoint has different content.
    ReceiveContent(OutPoint),
    /// A stored receive with this outpoint is mined at a different height on the local chain.
    ReceivePlacement(OutPoint),
    /// A stored spend with this identity has different content.
    SpendContent {
        /// The spending transaction.
        spending_txid: TxId,
        /// The input index.
        input_index: u32,
    },
    /// A stored spend with this identity is mined at a different height on the local chain.
    SpendPlacement {
        /// The spending transaction.
        spending_txid: TxId,
        /// The input index.
        input_index: u32,
    },
    /// Two different mined spends consume this outpoint.
    ConflictingSpends(OutPoint),
    /// A spend names a different address than the output it consumes.
    SpendAddress(OutPoint),
    /// Events of this transaction are placed at different heights; a transaction is mined in
    /// one block.
    TransactionPlacement(TxId),
    /// Events of this transaction disagree on whether it is a coinbase transaction, or a coinbase
    /// transaction appears as a spender.
    TransactionCoinbase(TxId),
    /// A spend of this outpoint is mined below the output it consumes. A spend in the same
    /// block as its output is valid.
    SpendBeforeOutput(OutPoint),
    /// The wallet already holds this output with different content.
    ProjectionContent(OutPoint),
}

/// A malformed commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvalidCommit {
    /// Metadata disagrees with coinbase classification or the complete input count.
    TransactionMetadata,
    /// A source, revision, or page identifier is empty or longer than
    /// [`MAX_RECOVERY_IDENTIFIER_LEN`].
    Identifier,
    /// The lineage exceeds `i64::MAX`.
    Lineage,
    /// The anchor is above the target.
    AnchorAboveTarget,
    /// The anchor is above the revision's publication height, or at that height with a
    /// different hash: the revision cannot vouch for the chain at the anchor.
    AnchorOutsidePublication,
    /// A range starts after it ends.
    EmptyRange,
    /// An event, range, or page extends past the anchor.
    AboveAnchor,
    /// A page names no addresses, or a page identifier repeats.
    Page,
    /// Supported coverage and an open page of the same revision overlap for this address. A
    /// revision cannot claim a range complete while its own retrieval of that range is
    /// unfinished, in either order. Other revisions' coverage and pages are independent.
    PendingPageOverlap(TransparentAddress),
    /// One revision reports an overlapping range of this address as both checked and
    /// unsupported, in this commit or across its commits.
    SupportContradiction(TransparentAddress),
}

/// Development diagnostics for one account's candidate ledger.
///
/// Every field comes from one read. The amounts are unverified: until coverage is complete the
/// recovered net can be above or below the real balance, and it never authorizes a spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateRecovery<AccountId> {
    /// The account.
    pub account: AccountId,
    /// The highest contiguously scanned local block.
    pub target: Option<ChainPoint>,
    /// The highest height through which every watched address is continuously covered from its
    /// required start; absent when some address has no such coverage.
    pub covered_through: Option<BlockHeight>,
    /// Why recovery is incomplete; empty when complete through the target.
    pub blockers: Vec<CandidateBlocker>,
    /// The number of watched addresses.
    pub watched_addresses: usize,
    /// The number of open pages.
    pub pending_pages: usize,
    /// The number of mined spends whose outputs have not been recovered.
    pub unresolved_spends: usize,
    /// Mined receives, ordered by outpoint.
    pub receives: Vec<ReceiveEvent>,
    /// Mined spends, ordered by spending txid and input index.
    pub spends: Vec<SpendEvent>,
    /// Mined receives not consumed by a mined spend, ordered by outpoint.
    pub unspent: Vec<OutPoint>,
    /// The sum of `unspent`, or `None` when it exceeds `MAX_MONEY`. Until recovery is complete,
    /// unspent receives include outputs whose spends are not yet recovered, so the sum is
    /// unverified: neither authoritative nor a lower bound, and possibly above any real balance.
    pub recovered_unverified: Option<Zatoshis>,
}
