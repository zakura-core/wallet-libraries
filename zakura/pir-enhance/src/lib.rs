//! Client and protocol types for privately enhancing Ironwood compact actions.

pub mod client;
pub mod types;
#[cfg(feature = "wallet-integration")]
pub mod wallet;

pub use client::{
    AcceptedAnchor, ClientError, ClientResourceLimits, GenerationAcceptance, PreparedQuery,
    QuerySession,
};
#[cfg(feature = "https-client")]
pub use client::{EnhancePirClient, PendingEnhancePirClient};
#[cfg(feature = "wallet-integration")]
pub use wallet::{ApplyRecordResult, apply_record, wallet_record};

pub use types::{
    ACTIVATION_HEIGHT, CONFIRMATIONS, ENHANCE_SETUP_SEED, EnhanceGeneration, EnhanceRecord,
    EnhanceRecordParts, EnhanceSession, ITEM_SIZE_BITS, NETWORK, POOL, PROTOCOL_REVISION,
    RECORD_BYTES, RECORDS_PER_ROW, ROW_BYTES, SCHEMA_VERSION, SHARD_POSITIONS, SHARD_ROWS,
    SHARDS_PER_GROUP, SHARDS_PER_WORKER, ShardDescriptor, checked_logical_rows_for,
    group_index_for_shard,
};
