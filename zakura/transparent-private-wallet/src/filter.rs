//! The wallet's side of activity filters: matching its scripts against them,
//! and fetching and checking filter batches. The profiles, encodings and
//! validation are [`zakura_transparent_private_shared::filter`].

pub mod client;
pub mod experimental_parent;
#[cfg(feature = "reqwest")]
pub mod http;
pub mod matching;
pub mod transport;

pub use client::{
    AcceptedChain, BlockMatch, ChainMap, CheckedRecord, CheckedShard, ShardMatch, ShardSyncOutcome,
    SyncOutcome, check_batch, check_range_batch, sync_range, sync_shards,
};
pub use matching::{
    map_wallet_scripts, map_wallet_scripts_keyed, match_keyed, match_mapped, match_range_scripts,
    match_scripts,
};
pub use transport::{
    ByteCharges, FileTransport, FilterTransport, RangeRequest, ShardFilterTransport,
    ShardRangeRequest,
};
