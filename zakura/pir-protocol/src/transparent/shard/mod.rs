//! Building the immutable shards a wallet privately retrieves history from.
//!
//! A shard is a chain range with a public activity filter, a private script
//! directory, and up to [`MAX_PAGE_CHILDREN`] private page shards holding the
//! history its scripts pushed out of the directory. Its boundaries are decided by what it
//! contains rather than by a fixed block width — see [`seal`] for why — and
//! every shard names a table geometry from a small closed registry, which is
//! what lets one set of PIR parameters serve every shard that names the same
//! one.
//!
//! A set may mix them: archive geometry for old, dense history and a narrower
//! recent geometry for the window wallets synchronise constantly. The registry
//! is closed rather than open so a wallet validates a handful of parameter sets
//! once instead of one per shard, and so a shard naming a shape this build does
//! not know is refused rather than decoded as the shape it does know.
//!
//! This crate decides boundaries and lays out tables. It does not fetch chain
//! data and it does not serve queries.

pub mod choice;
pub mod compact;
pub mod display;
pub mod layout;
pub mod manifest;
pub mod packing;
pub mod page_row;
pub mod records;
pub mod tag;
pub mod txid;
pub mod txid_v1;
pub mod txid_v2x;

pub use choice::{ChoiceError, ChoiceTable};
pub use layout::{
    DECOUPLED_2K_8K, DECOUPLED_32K_32K, DIRECTORY_ROW_BYTES, DIRECTORY_ROWS, EVENTS_PER_PAGE,
    Geometry, INLINE_EVENTS, MAX_ENTRIES_PER_ROW, MAX_PAGE_CHILDREN, PAGE_ENTRY_HEADER_BYTES,
    PAGE_ROW_BYTES, PAGE_ROW_HEADER_BYTES, PAGE_ROWS, PROFILES, PackedDemand,
    by_name as geometry_by_name,
};
pub use manifest::{
    ManifestLayout, ManifestOccupancy, ManifestSeal, PageChild, PageChildOccupancy, SCHEMA,
    ShardManifest, TableGeometry, pages_table, parse_pages_table, query_binding,
};
pub use page_row::{PageEntry, RunLink, decode_page_row, encode_page_row};
pub use records::{
    DIRECTORY_ENTRY_HEADER_BYTES, DIRECTORY_ROW_HEADER_BYTES, DIRECTORY_SLOTS, DirectoryEntry,
    MAX_DIRECTORY_ENTRY_BYTES, MAX_SCRIPT_BYTES, RecordError, decode_directory_row,
    encode_directory_row,
};
pub use tag::{SCRIPT_TAG_BYTES, page_tag_salt, resolve_tag_salt, script_tag, tag_salt};
