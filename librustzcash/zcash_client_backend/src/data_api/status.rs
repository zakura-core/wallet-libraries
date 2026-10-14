//! Routed status obligations, independent of payload enhancement.
use super::WalletRead;
#[cfg(feature = "test-dependencies")]
use ambassador::delegatable_trait;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

/// Explicit disclosure policy for status work. This is independent of payload routing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionStatusMode {
    /// The application authorizes public transaction-ID status lookups.
    Public,
    /// Transaction IDs must remain private, including when coverage is incomplete.
    Private,
}

/// One status obligation routed to exactly one source. Callers must not reroute private work
/// after an error. An inconclusive observation leaves the obligation pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionStatusWork {
    /// Observe status using an authorized public transaction-ID transport.
    Public(PublicTransactionStatusRequest),
    /// Observe status privately; missing coverage never authorizes public fallback.
    Private(PrivateTransactionStatusRequest),
}
impl TransactionStatusWork {
    /// Returns the transaction to observe.
    pub fn txid(self) -> TxId {
        match self {
            Self::Public(r) => r.txid(),
            Self::Private(r) => r.txid(),
        }
    }
}

/// A transaction-ID lookup authorized by the configured public status policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicTransactionStatusRequest {
    txid: TxId,
}
impl PublicTransactionStatusRequest {
    /// Constructs work under an explicitly authorized public status policy.
    pub fn new(txid: TxId) -> Self {
        Self { txid }
    }
    /// Returns the transaction to observe.
    pub fn txid(self) -> TxId {
        self.txid
    }
}

/// A private observation with wallet-held inclusion evidence. Unknown evidence does not
/// authorize public lookup or a negative observation, but positive observations remain useful.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateTransactionStatusRequest {
    txid: TxId,
    earliest_possible_inclusion: Option<BlockHeight>,
}
impl PrivateTransactionStatusRequest {
    /// `earliest_possible_inclusion` must be a conservative inclusive lower bound established
    /// from trusted creation history, adjusted for rewinds. Observation/import heights are not
    /// sufficient evidence. Use `None` when provenance cannot establish a bound.
    pub fn new(txid: TxId, earliest_possible_inclusion: Option<BlockHeight>) -> Self {
        Self {
            txid,
            earliest_possible_inclusion,
        }
    }
    /// Returns the transaction to observe.
    pub fn txid(self) -> TxId {
        self.txid
    }
    /// Returns the inclusive lower bound, or `None` when creation provenance is unknown.
    pub fn earliest_possible_inclusion(self) -> Option<BlockHeight> {
        self.earliest_possible_inclusion
    }
}

/// Sole source of status work. Implementations require an explicit status policy, independent
/// of enhancement policy. A snapshot contains each actionable obligation at most once.
/// The caller supplies the height through which a particular absence decision needs coverage;
/// this decision horizon is not durable transaction evidence.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait TransactionStatusRead: WalletRead {
    /// Returns each currently actionable status obligation once, with its selected route.
    /// Stores may retain expired obligations as dormant work that becomes eligible after
    /// a rewind. Omission from this batch is not conclusive evidence of transaction absence.
    fn transaction_status_work(&self) -> Result<Vec<TransactionStatusWork>, Self::Error>;

    /// Routes an individual lookup without enqueueing it or requiring an actionable queue entry.
    /// Unknown transactions retain unknown inclusion evidence. This uses the same policy and
    /// provenance rules as batch enumeration.
    fn transaction_status_work_for(&self, txid: TxId)
    -> Result<TransactionStatusWork, Self::Error>;
}

/// Records evidence established by local transaction construction, independently of payload
/// ingestion. This is for durable outboxes that store signed bytes outside the wallet database.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait TransactionStatusWrite: TransactionStatusRead {
    /// Records a conservative earliest inclusion height for a transaction created locally.
    /// The caller must establish this from original construction context, never a later retry,
    /// schedule, import, or first observation. Implementations must preserve lower existing bounds
    /// and account for rewinds. Does not enqueue status work or complete enhancement work.
    /// Persist this in the same transaction as the outbox entry before broadcasting.
    /// SQLite returns `ChainHeightUnknown` when it cannot clamp the bound to a known tip.
    fn record_transaction_created(
        &mut self,
        txid: TxId,
        earliest_possible_inclusion: BlockHeight,
    ) -> Result<(), Self::Error>;
}
