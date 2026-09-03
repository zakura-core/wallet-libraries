//! Private retrieval of PIR table rows by commitment-tree position, starting
//! with complete Ironwood action records for memo completion.
//!
//! Query construction and response decoding are transport-neutral. The default
//! `https-client` feature supplies a small production HTTPS wrapper.

mod client;
mod types;

pub use client::{ClientError, PirSession, PreparedMemoQuery, PreparedQuery};
#[cfg(feature = "https-client")]
pub use client::{HttpMemoPirClient, HttpPirClient};
pub use types::{
    ACTION_EXPECTATION, DatabaseId, GenerationManifest, ITEM_SIZE_BITS, MANIFEST_SCHEMA_VERSION,
    MEMO_SETUP_SEED, MemoPirRecord, MemoPirRow, MemoPirSnapshotAnchor, POOL, PirRow, RECORD_BYTES,
    RECORDS_PER_ROW, ROW_BYTES, SHARD_ROWS, ShardDescriptor, TableExpectation, TableLayout,
    TableManifest,
};
