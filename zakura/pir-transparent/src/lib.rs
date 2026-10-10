//! Bounded transparent PIR retrieval. Candidate evidence never grants financial authority.
#[cfg(feature = "sqlite")]
mod apply;
#[cfg(feature = "wallet")]
mod batch;
#[cfg(feature = "wallet")]
mod catalog;
#[cfg(feature = "wallet")]
mod chain;
#[cfg(feature = "wallet")]
mod companion;
#[cfg(feature = "wallet")]
mod convert;
#[cfg(feature = "wallet")]
mod discover;
#[cfg(feature = "wallet")]
mod error;
#[cfg(feature = "sqlite")]
mod forget;
#[cfg(feature = "wallet")]
mod http;
#[cfg(feature = "wallet")]
mod pass;
#[cfg(feature = "sqlite")]
mod plan;
#[cfg(feature = "wallet")]
mod progress;
#[cfg(all(test, feature = "wallet"))]
mod test_support;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(feature = "wallet")]
mod transparent_history_recovery;
#[cfg(feature = "wallet")]
mod txid;
#[cfg(feature = "sqlite")]
pub use apply::{
    Applied, ApplyAction, ApplyError, ApplyFailure, ApplyStats, Interrupted, Trust, Ungated,
    WriteGate,
};
#[cfg(feature = "wallet")]
pub use batch::{BatchState, RecoveryBatch, WithdrawnCause};
#[cfg(feature = "wallet")]
pub use chain::WalletChain;
#[cfg(feature = "wallet")]
pub use companion::{Companion, CompanionDir, OpenError};
#[cfg(feature = "wallet")]
pub use discover::{Discovery, DiscoveryLimits, discover_active_addresses};
#[cfg(feature = "wallet")]
pub use error::RecoveryError;
#[cfg(feature = "sqlite")]
pub use forget::{ForgetError, forget_private_recovery};
// Both services over the caller's raw HTTP exchange.
#[cfg(feature = "wallet")]
pub use http::{
    HttpExchange, HttpFailure, HttpMethod, HttpReply, HttpRequest, HttpStatus, PirFilters,
    PirShards, TransparentPirHttp, TxidHttp,
};
#[cfg(feature = "wallet")]
pub use pass::{PassError, PassReport};
#[cfg(feature = "sqlite")]
pub use plan::{HoldCause, PassLimits, PassPlan, Step, StopCause};
#[cfg(feature = "wallet")]
pub use progress::{Outcome, Progress, Retry};
#[cfg(feature = "wallet")]
pub use transparent_history_recovery::{
    SCHEMA, TransparentHistoryRecovery, TransparentHistoryRecoveryConfig,
};
#[cfg(feature = "wallet")]
pub use transparent_txid_client::{
    Address as EntryAddress, AddressKind, DisplayEntry, EntryOutput, Placement, ProfileCache,
    ProtocolKind, Provenance, Tier, TransportError, TxidDisplayClient, TxidError, TxidLookup,
    TxidReply, TxidRequest, TxidTransport,
};
#[cfg(feature = "wallet")]
pub use txid::{
    DetailAnswer, DetailApplied, DetailRun, DetailStep, DetailWrite, DisplayLookup, MapCheck,
    MapChecked, TxidDisplayService, deferral, display_facts, map_sha256,
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
