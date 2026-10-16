//! A wallet's transparent recovery: birthday to balance.
//!
//! Given a birthday height, a script set and a published shard set, this
//! downloads every public filter in range, matches locally, privately
//! retrieves history only from the shards that matched, and replays the result
//! into a UTXO set and a history.
//!
//! It is deliberately split so the arithmetic can be checked without the
//! network: [`ledger`] takes events and produces state, and knows nothing about
//! where they came from. That is what lets the same replay be driven by private
//! retrieval and by an independent traversal of the chain, and their results
//! compared exactly.
//!
//! What this does not hide is which chain ranges the wallet queried. See
//! [`sync`] for the statement of that leak.

pub mod adapters;
pub mod backoff;
pub mod client;
pub mod facade;
#[cfg(feature = "reqwest")]
pub mod http;
pub mod init;
pub mod ledger;
pub mod memory_store;
mod progress;
pub mod store;
pub mod sync;
#[cfg(feature = "engine-conformance")]
pub mod testing;
pub mod transport;

pub use adapters::{Acceptance, ChainView, ScriptProvider, StaticChain, StaticScripts};
pub use facade::{FacadeError, LedgerSnapshot, SyncRequest, SyncStatus, TransparentSync};
pub use init::parse_init;
pub use ledger::{ConfirmedSpend, Ledger, LedgerError, TransactionSummary, UnresolvedSpend, Utxo};
pub use memory_store::MemoryStore;
pub use store::{
    Anchor, CoverageKind, CoverageRange, DummyQueries, PendingPages, ScriptEntry, ScriptOrigin,
    SetIdentity, SetupBlob, SetupKey, ShardCommit, StoreError, StoredEvent, WalletStore,
};
pub use sync::{
    Completion, FailedEntry, GeometryParams, IncompleteReason, MAX_CONTENT_FAILURES,
    ServiceGeometry, SyncError, SyncOutcome, SyncReport, WorkLimits, sync, sync_into,
};
pub use transport::{
    BudgetStop, ByteCharges, FilterSource, Overloaded, ShardReply, ShardRequest, ShardTransport,
    StaleRevision, TableCharges, refusal,
};
