//! Bounded transparent PIR retrieval. Candidate evidence never grants financial authority.
#[cfg(feature = "sqlite")]
mod apply;
#[cfg(feature = "recovery")]
mod batch;
#[cfg(feature = "recovery")]
mod catalog;
#[cfg(feature = "transparent-wallet")]
mod chain;
#[cfg(feature = "recovery")]
mod companion;
#[cfg(feature = "recovery")]
mod convert;
#[cfg(feature = "recovery")]
mod discover;
#[cfg(feature = "transparent")]
pub mod engine;
#[cfg(feature = "engine-store")]
pub mod engine_store;
#[cfg(feature = "recovery")]
mod error;
#[cfg(feature = "sqlite")]
mod forget;
#[cfg(feature = "recovery")]
mod http;
#[cfg(feature = "recovery")]
mod pass;
#[cfg(feature = "sqlite")]
mod plan;
#[cfg(feature = "recovery")]
mod progress;
#[cfg(all(test, feature = "recovery"))]
mod test_support;
#[cfg(all(feature = "testing", feature = "transparent-wallet"))]
pub mod testing;
#[cfg(feature = "recovery")]
mod transparent_history_recovery;
#[cfg(feature = "recovery")]
mod txid;
#[cfg(feature = "sqlite")]
pub use apply::{
    Applied, ApplyAction, ApplyError, ApplyFailure, ApplyStats, Interrupted, Trust, Ungated,
    WriteGate,
};
#[cfg(feature = "recovery")]
pub use batch::{BatchState, RecoveryBatch, WithdrawnCause};
#[cfg(feature = "transparent-wallet")]
pub use chain::WalletChain;
#[cfg(feature = "recovery")]
pub use companion::{Companion, CompanionDir, OpenError};
#[cfg(feature = "recovery")]
pub use discover::{Discovery, DiscoveryLimits, discover_active_addresses};
#[cfg(feature = "recovery")]
pub use error::RecoveryError;
#[cfg(feature = "sqlite")]
pub use forget::{ForgetError, forget_private_recovery};
// Both services over the caller's raw HTTP exchange.
#[cfg(feature = "recovery")]
pub use crate::transparent::txid_client::{
    Address as EntryAddress, AddressKind, DisplayEntry, EntryOutput, Placement, ProfileCache,
    ProtocolKind, Provenance, Tier, TransportError, TxidDisplayClient, TxidError, TxidLookup,
    TxidReply, TxidRequest, TxidTransport,
};
#[cfg(feature = "recovery")]
pub use http::{
    HttpExchange, HttpFailure, HttpMethod, HttpReply, HttpRequest, HttpStatus, PirFilters,
    PirShards, TransparentPirHttp, TxidHttp,
};
#[cfg(feature = "recovery")]
pub use pass::{PassError, PassReport};
#[cfg(feature = "sqlite")]
pub use plan::{HoldCause, PassLimits, PassPlan, Step, StopCause};
#[cfg(feature = "recovery")]
pub use progress::{FailedEntries, Outcome, Progress, Retry};
#[cfg(feature = "recovery")]
pub use transparent_history_recovery::{
    SCHEMA, TransparentHistoryRecovery, TransparentHistoryRecoveryConfig,
};
#[cfg(feature = "transparent-wallet")]
pub use txid::{
    DetailAnswer, DetailApplied, DetailRun, DetailStep, DetailWrite, MapCheck, MapChecked,
    deferral, display_facts,
};
#[cfg(feature = "recovery")]
pub use txid::{DisplayLookup, TxidDisplayService, map_sha256};
#[cfg(feature = "recovery")]
pub use zakura_pir_protocol::transparent::recovery as recovery_types;
#[cfg(feature = "recovery")]
mod wallet_boundary;
#[cfg(feature = "recovery")]
pub use wallet_boundary::RecoveryHash;
// What a caller implements for `pass` and `discover_active_addresses`: the chain view
// (or `WalletChain`), and transports that reach the service and map its refusals.
#[cfg(feature = "recovery")]
pub use crate::transparent::engine::ChainView;
#[cfg(feature = "recovery")]
pub use crate::transparent::engine::client::Table;
#[cfg(feature = "recovery")]
pub use crate::transparent::engine::transport::{
    BoxError, FilterSource, Overloaded, ShardRequest, ShardTransport, StaleRevision, refusal,
};

pub mod filter;
#[cfg(feature = "reqwest")]
mod http_client;
pub mod native;
mod routes;
pub mod txid_client;
