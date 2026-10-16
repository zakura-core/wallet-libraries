//! BIP 158 transparent activity filters for Zcash.
//!
//! This crate implements the `zcash-transparent-basic-v1` application profile:
//! one deterministic filter per accepted block, covering the transparent
//! scripts a block creates and spends, so a wallet can test its own scripts
//! locally without revealing them.
//!
//! What it does not do: it does not prove a filter is complete. Matching a
//! filter against the wallet's accepted block hash binds where the filter
//! claims to be, not what it claims to contain. Advancing coverage on a
//! negative result is only sound if the filter's author is trusted to have
//! built it over the whole block.

pub mod build_filter;
pub mod client;
pub mod digest;
pub mod envelope;
pub mod error;
pub mod experimental_parent;
pub mod hash;
#[cfg(feature = "client")]
pub mod http;
pub mod matching;
pub mod profile;
pub mod script;
pub mod transport;
pub mod validate;
pub mod wire;

pub use build_filter::{
    build_filter, build_range_filter, build_range_filter_for, build_range_filter_with,
    element_count, FilterBytes,
};
pub use client::{
    check_batch, check_range_batch, sync_range, sync_shards, AcceptedChain, BlockMatch, ChainMap,
    CheckedRecord, CheckedShard, ShardMatch, ShardSyncOutcome, SyncOutcome,
};
pub use digest::{filter_hash, filter_header, FilterHash, FilterHeader, GENESIS_PREDECESSOR};
pub use envelope::{
    FilterBatch, FilterRecord, RangeFilterBatch, RangeFilterRecord, ENVELOPE_VERSION,
    MAX_RANGE_RECORDS_PER_BATCH, MAX_RECORDS_PER_BATCH, RANGE_ENVELOPE_VERSION,
};
pub use error::FilterError;
pub use hash::{BlockHash, FilterKeys, ShardKey};
pub use matching::{
    map_wallet_scripts, map_wallet_scripts_keyed, match_keyed, match_mapped, match_range_scripts,
    match_scripts,
};
pub use profile::{
    range_profile, RangeProfile, MAINNET_GENESIS_DISPLAY, NETWORK, PROFILE, RANGE_PROFILE,
    RANGE_PROFILES, RANGE_PROFILE_V1, RANGE_PROFILE_V2, START_HEIGHT,
};
pub use script::ScriptBytes;
pub use transport::{
    ByteCharges, FileTransport, FilterTransport, RangeRequest, ShardFilterTransport,
    ShardRangeRequest,
};
pub use validate::{validate_filter, validate_range_filter, FilterLimits, ValidatedFilter};
pub use wire::{
    ChainEntry, FilterDigestEntry, FilterServiceHealth, FilterServiceInfo, Recut, SealParameters,
    ShardMap, ShardMapEntry, SupersededShard,
};
