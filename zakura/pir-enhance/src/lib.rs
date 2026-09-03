//! Client and protocol types for privately enhancing Ironwood compact actions.

pub mod client;
pub mod types;

#[cfg(feature = "https-client")]
pub use client::EnhancePirClient;
pub use client::{ClientError, PreparedQuery, QuerySession};

pub use types::{
    ACTIVATION_HEIGHT, CONFIRMATIONS, ENHANCE_SETUP_SEED, EnhanceGeneration, EnhanceRecord,
    EnhanceRecordParts, EnhanceSession, ITEM_SIZE_BITS, NETWORK, POOL, PROTOCOL_REVISION,
    RECORD_BYTES, RECORDS_PER_ROW, ROW_BYTES, SCHEMA_VERSION, SHARD_POSITIONS, SHARD_ROWS,
    SHARDS_PER_GROUP, SHARDS_PER_WORKER, ShardDescriptor, group_index_for_shard,
};
