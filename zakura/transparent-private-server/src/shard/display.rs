//! Building txid display publications: placing entries in each bucket's
//! table, choosing where archives seal, writing manifests and splitting the
//! map. What a publication is, and how a wallet reads it, is
//! [`zakura_transparent_private_shared::shard::display`].

pub mod manifest;
pub mod seal;
pub mod split;
pub mod tables;

pub use manifest::DisplayManifestBuild;
pub use seal::{
    archive_boundary, height_counts, plan_seals, recent_start, window_start, HeightCounts,
};
pub use split::{index_file, DisplayMapSplit, SplitChunk, SplitMap, RECENT_MAP_FILE};
pub use tables::{
    build_shard, place_bucket, row_for, verify, verify_rows, BuiltBucket, BuiltDisplay, Placement,
};
