//! Storage-neutral APIs for privately enhancing compact Ironwood actions.
//!
//! Network lookups use tree positions; transaction/action identities stay local to
//! reject stale responses after reorgs. Note plaintext is authenticated, but schema
//! v11 transaction metadata (shape, fee, expiry) is trusted indexer data, not cryptographic evidence.

use incrementalmerkletree::Position;
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

use super::{PublicTransactionEnhancementRequest, WalletRead};
use crate::proto::compact_formats::{CompactBlock, CompactTx};

/// A compact block needed to rediscover outgoing actions after retroactive spend linkage.
///
/// Capture this identity before reading the cache or downloading the block. Prefer cached
/// blocks or normal batched downloads: a targeted download reveals interest in this height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IronwoodEnhanceDiscoveryRequest {
    /// Height of the previously scanned spending block.
    pub height: BlockHeight,
    /// Its locally scanned block hash, rechecked when reconstruction is applied.
    pub block_hash: BlockHash,
}

/// Why one transaction's outgoing discovery could not be completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IronwoodEnhanceDiscoveryFailureReason {
    /// No funding associations survive. Automatic discovery is suspended until new
    /// funding is linked; private protection and ordinary enhancement intent remain.
    NoFundingAccounts,
    /// The spending block or its predecessor lacks the tree-size metadata required
    /// to anchor reconstructed positions. The job becomes requestable when scanning
    /// supplies that metadata; private protection and ordinary intent remain.
    AnchorUnavailable,
    /// The supplied block does not contain the locally recorded transaction ID.
    /// The job remains retryable; remote omission is not evidence of completion.
    TransactionMissing,
    /// This transaction's locator, actions, or funding do not match local context.
    /// The job remains retryable without blocking independently valid transactions.
    ContextMismatch,
}

/// A local transaction identity and its discovery failure; never send this to the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IronwoodEnhanceDiscoveryFailure {
    /// The transaction whose discovery remains incomplete.
    pub txid: TxId,
    /// Why this transaction could not be reconstructed.
    pub reason: IronwoodEnhanceDiscoveryFailureReason,
}

/// One private enhancement obligation. Local identities must never be sent to the PIR service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnhancePirWork {
    /// Query the position, retaining the captured action identity locally.
    Query(EnhancePirRequest),
    /// Obtain a compact block through the normal cache/download path.
    Rediscover(IronwoodEnhanceDiscoveryRequest),
    /// Surface incomplete work without automatically retrying it.
    Suspended(EnhancePirSuspension),
}

/// One payload-retrieval obligation, routed to exactly one transport.
///
/// Returned by [`EnhancePirRead::transaction_enhancement_work`]. The route is decided by the
/// wallet from the configured [`EnhancementMode`] and durable transaction-wide routing state;
/// callers dispatch each variant to its transport and must not re-route it. In particular, a
/// failure servicing [`Self::Private`] work never authorizes a [`Self::Public`] request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionEnhancementWork {
    /// Retrieve the full transaction by ID over the ordinary (LWD) payload transport.
    Public(PublicTransactionEnhancementRequest),
    /// Service private Enhance PIR work; never disclose its transaction ID to a server.
    Private(EnhancePirWork),
}

/// Durable work waiting for new local context or user intervention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnhancePirSuspension {
    /// Missing funding associations or adjacent tree metadata.
    Discovery(IronwoodEnhanceDiscoveryFailure),
    /// Outgoing recovery failed; new funding/scanning may reactivate the action.
    OutgoingNotRecoverable(EnhancePirRequest),
}

/// Result of atomically applying independently validated discovery plans from a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IronwoodEnhanceDiscoveryResult {
    /// Number of transaction discovery jobs resolved, including mixed-pool routing decisions.
    Rebuilt(usize),
    /// Valid jobs were applied, but some transactions remain incomplete. This can report
    /// zero rebuilt jobs. These failures never cause LWD fallback or retire unresolved intent.
    Incomplete {
        /// Number of successfully resolved transaction discovery jobs.
        rebuilt: usize,
        /// Failed jobs and their individual reasons, in transaction-index order.
        unresolved: Vec<IronwoodEnhanceDiscoveryFailure>,
    },
    /// No matching active work remains, or the request belongs to an old chain branch.
    /// Suspended jobs may still exist in `transaction_enhancement_work()`.
    AlreadyResolved,
    /// Block-wide identity, ordering, or tree geometry is invalid. No state was changed.
    Rejected,
}

/// Tests provisional Ironwood-only eligibility using the complete compact transaction.
///
/// Empty transparent lists are not proof of absence; PIR record flags may still require LWD.
/// The compact source must include all shielded pools, not filter to Ironwood.
pub fn is_ironwood_pir_candidate(tx: &CompactTx) -> bool {
    !tx.ironwood_actions.is_empty()
        && tx.spends.is_empty()
        && tx.outputs.is_empty()
        && tx.actions.is_empty()
        && tx.vin.is_empty()
        && tx.vout.is_empty()
}

/// Selects how ordinary transaction enhancement interacts with private Ironwood enhancement.
///
/// Applications that expose a runtime PIR setting should always compile with
/// `zakura-pir-enhance`, and update this mode when the setting changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnhancementMode {
    /// Exposes ordinary transaction-ID enhancement requests, including for Ironwood transactions.
    Standard,
    /// Suppresses transaction-ID enhancement for transactions protected by Enhance PIR.
    ///
    /// Protection is transaction-wide, but only pure-Ironwood compact transactions are eligible.
    /// Mixed-pool transactions remain on standard transaction-ID enhancement. Status requests and
    /// enhancement of other, unprotected transactions remain available.
    /// Protection survives rewinds and private completion independently of pending work;
    /// removing transaction history must also remove its retrieval intents.
    ///
    /// A positive transparent-presence flag routes the whole transaction to LWD.
    /// Errors never trigger fallback. Disabling this mode exposes outstanding ordinary
    /// enhancement requests, including work suspended after outgoing non-recovery.
    PrivateIronwood,
}

/// A position-keyed lookup with a local identity that must not be sent to the PIR server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnhancePirRequest {
    position: Position,
    request_id: IronwoodEnhanceRequestId,
}

impl EnhancePirRequest {
    /// Captures the action identity when work is queued, before network I/O.
    pub fn new(position: Position, request_id: IronwoodEnhanceRequestId) -> Self {
        Self {
            position,
            request_id,
        }
    }

    /// Returns the local transaction/action identity.
    pub fn request_id(&self) -> IronwoodEnhanceRequestId {
        self.request_id
    }

    /// Returns the Ironwood commitment-tree position to query.
    pub fn position(&self) -> Position {
        self.position
    }
}

/// Stable chain identity for an Ironwood action queued for private enhancement.
///
/// Tree positions may be reused after a reorg, so completion must compare this
/// identity in addition to the queried position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IronwoodEnhanceRequestId {
    txid: TxId,
    output_index: u32,
}

impl IronwoodEnhanceRequestId {
    /// Constructs an action identity.
    pub fn new(txid: TxId, output_index: u32) -> Self {
        Self { txid, output_index }
    }

    /// Returns the transaction containing the action.
    pub fn txid(&self) -> TxId {
        self.txid
    }

    /// Returns the action index within the transaction's Ironwood bundle.
    pub fn output_index(&self) -> u32 {
        self.output_index
    }
}

pub use zakura_pir_enhance_types::{EnhanceRecord, EnhanceRecordParts, EnhanceTransactionMetadata};

/// Chain state to which a PIR snapshot is anchored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnhancePirSnapshotAnchor {
    /// Snapshot block height.
    pub height: BlockHeight,
    /// Snapshot block hash.
    pub block_hash: BlockHash,
    /// Ironwood tree size at the end of the anchor block.
    pub ironwood_tree_size: u64,
}

/// Whether a snapshot anchor is safe to use with the wallet's scanned chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnhancePirSnapshotStatus {
    /// Height and Ironwood tree size match locally scanned state.
    Accepted,
    /// The wallet has not scanned the anchor height yet.
    NotYetScanned,
    /// Local chain state disagrees with the snapshot.
    Mismatch,
}

/// Result of validating and atomically applying one response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnhancePirStoreResult {
    /// All requested incoming/outgoing data at this action was stored.
    Stored,
    /// The request no longer matches pending work; nothing was changed.
    AlreadyResolved,
    /// Outgoing recovery failed. The row is suspended, not completed; the
    /// ordinary fallback remains withheld until private mode is disabled.
    NotRecoverable,
    /// The whole transaction requires ordinary LWD enhancement.
    LwdRequired,
    /// Authentication or action binding failed; nothing was changed.
    Rejected,
}

/// Reason an atomic batch made no changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnhancePirBatchRejection {
    Empty,
    MixedTxid,
    ConflictingDuplicate,
    MetadataConflict,
    RecordRejected,
}

/// Atomic application outcome; committed results retain input order and duplicates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnhancePirBatchResult {
    Committed(Vec<EnhancePirStoreResult>),
    Rejected {
        index: Option<usize>,
        reason: EnhancePirBatchRejection,
    },
}

/// Application read interface for private enhancement.
pub trait EnhancePirRead: WalletRead {
    /// Returns every pending payload-retrieval obligation, each routed to a single transport,
    /// from one consistent wallet-state snapshot.
    ///
    /// - A transaction's payload obligation appears under at most one of
    ///   [`TransactionEnhancementWork::Public`] or [`TransactionEnhancementWork::Private`].
    /// - [`EnhancementMode::Standard`] yields only public work.
    /// - [`EnhancementMode::PrivateIronwood`] yields private work (including rediscovery and
    ///   suspensions) for privately protected transactions, and public work for unclassified
    ///   transactions or those with a sticky LWD decision. Private errors and suspensions never
    ///   produce public work.
    /// - Status observation and transparent-address history are not enhancement and are not
    ///   returned; obtain them from [`WalletRead::transaction_data_requests`].
    ///
    /// Rediscovery is grouped by block and ordered by height, followed by private queries by
    /// position, public requests, discovery suspensions by transaction location/identity, and
    /// outgoing suspensions by position/identity. Suspensions are incomplete obligations, not
    /// automatic retries. After applying any response, callers should reread this snapshot: for
    /// example, an authenticated positive transparent flag moves a transaction to public work.
    fn transaction_enhancement_work(&self) -> Result<Vec<TransactionEnhancementWork>, Self::Error>;

    /// Compares the snapshot anchor to locally scanned chain state.
    fn enhance_pir_snapshot_status(
        &self,
        anchor: EnhancePirSnapshotAnchor,
    ) -> Result<EnhancePirSnapshotStatus, Self::Error>;

    /// Returns whether an Ironwood transaction is covered by transaction-wide txid protection.
    ///
    /// This is an informational API. Storage implementations must enforce the configured
    /// [`EnhancementMode`] in their ordinary transaction-data request path so that callers cannot
    /// accidentally dispatch a protected enhancement request.
    fn is_ironwood_enhancement_protected(&self, txid: TxId) -> Result<bool, Self::Error>;
}

/// Application operations that validate and atomically apply network responses.
pub trait EnhancePirWrite: EnhancePirRead {
    /// Applies a nonempty, same-transaction batch, including batches spanning rows.
    /// Any live rejection or database error rolls back the entire batch. Stale
    /// requests are harmless no-ops. Server association and metadata are trusted
    /// where no incoming or outgoing decryption authenticates the action.
    fn apply_ironwood_enhance_records(
        &mut self,
        records: &[(EnhancePirRequest, EnhanceRecord)],
    ) -> Result<EnhancePirBatchResult, Self::Error>;

    /// Reconstructs pending outgoing candidates using a previously scanned compact block
    /// and the wallet's current durable funding associations, including already-spent notes.
    ///
    /// The caller obtains blocks using the same trusted compact source as scanning. Matching
    /// a block hash is a stale-branch check, not cryptographic authentication of its compact
    /// contents. Invalid block-wide context rejects the entire call without mutation.
    /// Otherwise, independently valid jobs commit together and transaction-local failures are
    /// reported individually. SQL failures roll back the whole call. Unresolved work is retained
    /// (suspended if its funding is gone), never publicly fetched because of an error.
    fn rebuild_ironwood_enhancement(
        &mut self,
        request: IronwoodEnhanceDiscoveryRequest,
        block: &CompactBlock,
    ) -> Result<IronwoodEnhanceDiscoveryResult, Self::Error>;

    /// Binds an encoding-validated record to the originally captured request, authenticates
    /// incoming note data, and attempts outgoing recovery. Context reads, identity rechecks,
    /// and all writes share one storage transaction. Validation failures never cause LWD fallback.
    ///
    /// Transparent flags are trusted server metadata, not authenticated by decryption.
    /// The request must match pending wallet identity before those flags can affect routing.
    /// Send-only association is trusted even when outgoing decryption cannot succeed.
    /// Positive transparent flags set a sticky transaction-wide LWD decision,
    /// clear private work, and preserve ordinary enhancement. False flags can
    /// never undo it. A stale response cannot change routing or note data.
    fn apply_ironwood_enhance_record(
        &mut self,
        request: EnhancePirRequest,
        record: &EnhanceRecord,
    ) -> Result<EnhancePirStoreResult, Self::Error>;
}

/// Contracts for storage implementers. Applications should use [`EnhancePirWrite`].
pub mod storage;
