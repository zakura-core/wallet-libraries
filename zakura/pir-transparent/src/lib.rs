//! Bounded transparent PIR retrieval. Candidate evidence never grants financial authority.
#[cfg(feature = "wallet")]
mod catalog;
#[cfg(feature = "wallet")]
mod chain;
#[cfg(feature = "wallet")]
mod display;
#[cfg(feature = "wallet")]
mod recovery;
#[cfg(feature = "wallet")]
pub use catalog::{BatchState, WithdrawnCause};
#[cfg(feature = "wallet")]
pub use chain::WalletChain;
#[cfg(feature = "wallet")]
pub use display::{deferral, display_facts, map_sha256};
// The txid display client: the caller supplies a synchronous transport.
#[cfg(feature = "wallet")]
pub use recovery::{
    Outcome, Progress, RecoveryBatch, RecoveryConfig, RecoveryError, ReferenceRecovery, SCHEMA,
};
#[cfg(feature = "wallet")]
pub use transparent_txid_client::{
    Address as EntryAddress, AddressKind, DisplayEntry, EntryOutput, Placement, ProfileCache,
    ProtocolKind, Provenance, Tier, TransportError, TxidDisplayClient, TxidError, TxidLookup,
    TxidReply, TxidRequest, TxidTransport,
};
// What a caller implements for `recover`: the chain view (or `WalletChain`), and
// transports that reach the companion's origin and map service refusals.
#[cfg(feature = "wallet")]
pub use transparent_wallet::ChainView;
#[cfg(feature = "wallet")]
pub use transparent_wallet::client::Table;
#[cfg(feature = "wallet")]
pub use transparent_wallet::transport::{
    BoxError, FilterSource, Overloaded, ShardRequest, ShardTransport, StaleRevision, refusal,
};
