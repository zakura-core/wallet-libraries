//! Client and protocol types for privately enhancing Ironwood compact actions.

pub mod client;
pub mod types;

pub use client::{
    AcceptedAnchor, ClientError, ClientResourceLimits, GenerationAcceptance, PreparedQuery,
    QuerySession,
};
#[cfg(feature = "https-client")]
pub use client::{EnhancePirClient, PendingEnhancePirClient};

pub use types::{
    ENHANCE_SETUP_SEED, EnhanceGeneration, EnhanceRecord, EnhanceRecordParts, EnhanceSession,
    EnhanceTransactionMetadata, FLAG_HAS_TRANSPARENT_INPUTS, FLAG_HAS_TRANSPARENT_OUTPUTS,
    ITEM_SIZE_BITS, InvalidEnhanceRecord, POOL, PROTOCOL_REVISION, RECORD_BYTES, RECORDS_PER_ROW,
    ROW_BYTES, SCHEMA_VERSION, SHARD_POSITIONS, SHARD_ROWS, SHARDS_PER_GROUP, ShardDescriptor,
    checked_logical_rows_for, group_index_for_shard,
};
