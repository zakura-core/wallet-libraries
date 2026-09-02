//! Private retrieval of complete Ironwood note ciphertexts by commitment-tree position.
//!
//! Query construction and response decoding are transport-neutral. The default
//! `https-client` feature supplies a small production HTTPS wrapper.

mod client;
mod types;

#[cfg(feature = "https-client")]
pub use client::HttpMemoPirClient;
pub use client::{ClientError, MemoPirSession, PreparedMemoQuery};
pub use types::{
    Coverage, ITEM_SIZE_BITS, MEMO_SETUP_SEED, MemoPirRow, MemoSnapshotMetadata, POOL,
    RECORD_BYTES, RECORDS_PER_ROW, ROW_BYTES, SCHEMA_VERSION, SHARD_ROWS, ShardDescriptor,
};
