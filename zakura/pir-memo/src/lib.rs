//! Private retrieval of PIR table rows by commitment-tree position, plus the
//! witness, spend-check, and DAG-sync planning built on it.
//!
//! Query construction and response decoding are transport-neutral. The default
//! `https-client` feature supplies a small production HTTPS wrapper.

mod client;
pub mod dag;
pub mod spend;
mod types;
pub mod witness;

pub use client::{ClientError, PirSession, PreparedMemoQuery, PreparedQuery};
#[cfg(feature = "https-client")]
pub use client::{HttpMemoPirClient, HttpPirClient};
pub use types::{
    ACTION_EXPECTATION, DatabaseId, ENVELOPE_PROTOCOL_VERSION, Envelope, FrontierUpdate,
    GenerationManifest, ITEM_SIZE_BITS, MANIFEST_SCHEMA_VERSION, MEMO_SETUP_SEED, MemoPirRecord,
    MemoPirRow, MemoPirSnapshotAnchor, NULLIFIER_LAYOUT, POOL, PirRow, RECORD_BYTES,
    RECORDS_PER_ROW, ROW_BYTES, SHARD_ROWS, ShardDescriptor, TableExpectation, TableLayout,
    TableManifest, WITNESS_LAYOUT, WitnessCap, seed_from_domain,
};
