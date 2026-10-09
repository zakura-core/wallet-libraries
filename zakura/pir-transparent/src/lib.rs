//! Bounded transparent PIR retrieval. Candidate evidence never grants financial authority.
#[cfg(feature = "sqlite")]
mod apply;
#[cfg(feature = "wallet")]
mod catalog;
#[cfg(feature = "wallet")]
mod chain;
#[cfg(feature = "wallet")]
mod companion;
#[cfg(feature = "wallet")]
mod display;
#[cfg(feature = "wallet")]
mod http;
#[cfg(feature = "wallet")]
mod recovery;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(feature = "wallet")]
mod txid;
#[cfg(feature = "sqlite")]
pub use apply::{Applied, ApplyAction, ApplyError, ApplyFailure, ApplyStats, Trust};
#[cfg(feature = "wallet")]
pub use catalog::{BatchState, WithdrawnCause};
#[cfg(feature = "wallet")]
pub use chain::WalletChain;
#[cfg(feature = "wallet")]
pub use companion::{Companion, CompanionDir, OpenError};
#[cfg(feature = "wallet")]
pub use display::{deferral, display_facts, map_sha256};
// Both services over the caller's raw HTTP exchange.
#[cfg(feature = "wallet")]
pub use http::{
    HttpExchange, HttpFailure, HttpMethod, HttpReply, HttpRequest, HttpStatus, PirFilters,
    PirShards, TransparentPirHttp, TxidHttp,
};
#[cfg(feature = "wallet")]
pub use recovery::{
    Outcome, Progress, RecoveryBatch, RecoveryConfig, RecoveryError, ReferenceRecovery, Retry,
    SCHEMA,
};
#[cfg(feature = "wallet")]
pub use transparent_txid_client::{
    Address as EntryAddress, AddressKind, DisplayEntry, EntryOutput, Placement, ProfileCache,
    ProtocolKind, Provenance, Tier, TransportError, TxidDisplayClient, TxidError, TxidLookup,
    TxidReply, TxidRequest, TxidTransport,
};
#[cfg(feature = "wallet")]
pub use txid::TxidDisplayService;
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
