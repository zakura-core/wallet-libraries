//! Wallet-bound v7 client for private Ironwood compact-action enhancement.

pub mod client;
pub mod transport;
pub mod types;

#[cfg(test)]
mod test_support;

pub use client::{
    AcceptedAnchor, ClientError, ClientResourceLimits, GenerationAcceptance, PreparedQuery,
    QuerySession,
};
#[cfg(feature = "https-client")]
pub use client::{EnhancePirClient, PendingEnhancePirClient};

pub use types::{
    Coverage, ENHANCE_SETUP_SEED, EnhanceRecord, EnhanceRecordParts, EnhanceTransactionMetadata,
    FLAG_HAS_TRANSPARENT_INPUTS, FLAG_HAS_TRANSPARENT_OUTPUTS, Geometry, HEADER_BYTES,
    ITEM_SIZE_BITS, InvalidEnhanceRecord, Manifest, MutableUnit, POOL, PROTOCOL_REVISION,
    QueryBinding, QueryShard, RECORD_BYTES, RECORDS_PER_ROW, ROW_BYTES, SCHEMA_VERSION, SessionRef,
    ShardSession, ShardState, UnitIdentity, parameter_id, parameters, setup_seed,
    unit_parameter_id,
};

#[cfg(feature = "wallet")]
pub mod wallet;
