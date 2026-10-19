//! Transparent publication construction.
pub use zakura_pir_protocol::transparent::shard::*;
pub mod build;
pub mod display;
pub mod filter;
pub mod seal;
pub use build::{
    Block, BuildError, Built, BuiltChild, BuiltDirectory, DirectoryBuilder, Placement, ShardStream,
    build_directory_shard, candidate_rows, choice_table, place_scripts, placement_order,
    verify_choice,
};
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
pub use seal::{
    ChoiceMeasure, Closed, DecoupledPolicy, DisplacementSealer, Limit, Occupancy, SealError,
    SealPolicy, SealReason, SealedChild, SealedDirectory, SealedShard, Sealer,
};
pub use tag::{SCRIPT_TAG_BYTES, page_tag_salt, resolve_tag_salt, script_tag, tag_salt};

pub use zakura_pir_protocol::transparent::events;
