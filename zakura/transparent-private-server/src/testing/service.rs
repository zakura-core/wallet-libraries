//! A real transparent shard service for application tests: a publisher that
//! writes shards for a synthetic chain, and wallet-pir's shard server answering
//! requests in process, so a test reaches real filters and real PIR without a
//! network.
//!
//! Adapted from wallet-pir's shard-server test fixtures at fb90519b
//! (`transparent-shard-server/tests/common/{mod,prepared}.rs`), through the
//! crates' public APIs only. Unlike those, a test chooses every shard's range,
//! geometry, seal state, revision and page shards, and the re-cuts a map
//! declares, as a publisher would over time.
//!
//! Schema v12 publishes each shard as a directory shard with its own page
//! shards: consecutive block ranges inside it, each its own `pages-<j>` table.
//! An address keeps its two newest events in the directory; each older one is
//! pushed into whichever page shard is open when the event two places after it
//! arrives, so a long history is a chain of runs across page shards.

use std::path::Path;

use crate::shard::build::{build_directory_shard, Block};
use sha2::{Digest, Sha256};
use zakura_transparent_private_shared::events::TransparentEvent;
use zakura_transparent_private_shared::filter::{
    filter_hash, BlockHash, Recut, ScriptBytes, SealParameters, ShardMap, ShardMapEntry,
    SupersededShard,
};
use zakura_transparent_private_shared::shard::layout::{
    split_row, Geometry, DECOUPLED_2K_8K, DECOUPLED_32K_32K, MAX_PAGE_CHILDREN,
};
use zakura_transparent_private_shared::shard::manifest::{
    pages_table, ManifestLayout, ManifestOccupancy, ManifestSeal, ShardManifest, TableGeometry,
    SCHEMA,
};
use zakura_transparent_private_shared::shard::placement::candidate_rows;
use zakura_transparent_private_shared::shard::records::decode_directory_row;

/// A shard's usual geometry: the recent one, 2,048 directory rows and page
/// shards of 8,192 rows, which keeps the tables a pass sets up and queries small.
/// The range-filter profile the test service publishes under: production's.
const PROFILE: &str = zakura_transparent_private_shared::filter::RANGE_PROFILE_V2.name;

pub const GEOMETRY: &Geometry = &DECOUPLED_2K_8K;

/// The geometry a re-cut merges sealed shards into: the archive geometry.
pub const WIDE: &Geometry = &DECOUPLED_32K_32K;

/// The seal thresholds the publisher seals under.
pub const SEAL: SealParameters = SealParameters {
    max_scripts: 2_048,
    max_page_rows: 1_024,
    max_txids: 0,
};

/// A block hash for a height the wallet never scanned, distinct per height.
pub fn synthetic(height: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&height.to_le_bytes());
    bytes[31] = 0x5a;
    BlockHash::from_internal_bytes(bytes)
}

/// One shard of a publication: its range, geometry, whether it is sealed, its
/// published revision, the manifest digest that revision supersedes, its page
/// shards, and every event in it, keyed by the script it concerns.
pub struct ShardSpec {
    pub start: u64,
    pub end: u64,
    pub geometry: &'static Geometry,
    pub sealed: bool,
    pub revision: u32,
    /// Empty for a first revision. A republished tail names the digest it
    /// replaces, as a continuous publisher does; nothing in a pass reads it.
    pub supersedes: String,
    /// Blocks per page shard, counted from `start`; the last page shard ends
    /// at `end` and may be shorter. Zero lays out one page shard over the
    /// whole range. A growing tail republished with the same span keeps its
    /// earlier page shards, sealed and byte for byte, as a publisher does.
    pub page_span: u64,
    pub events: Vec<(ScriptBytes, TransparentEvent)>,
    /// Scripts whose directory entry is published malformed, as a service aiming
    /// bad content at chosen rows would: both rows the entry may occupy fail to
    /// decode, so a wallet's query for the script fails on content. Any other
    /// script sharing such a row fails with it. Empty for an honest shard.
    pub malformed_entries: Vec<ScriptBytes>,
}

impl ShardSpec {
    /// The first revision of a shard over `start..=end` in [`GEOMETRY`], with
    /// one page shard.
    pub fn first(
        start: u64,
        end: u64,
        sealed: bool,
        events: Vec<(ScriptBytes, TransparentEvent)>,
    ) -> Self {
        Self {
            start,
            end,
            geometry: GEOMETRY,
            sealed,
            revision: 0,
            supersedes: String::new(),
            page_span: 0,
            events,
            malformed_entries: Vec::new(),
        }
    }

    /// The heights its page shards end at, ascending, the last at `end`.
    pub fn page_ends(&self) -> Vec<u64> {
        if self.page_span == 0 {
            return vec![self.end];
        }
        let mut ends: Vec<u64> = (self.start + self.page_span - 1..self.end)
            .step_by(self.page_span as usize)
            .collect();
        ends.push(self.end);
        assert!(
            ends.len() <= MAX_PAGE_CHILDREN as usize,
            "a directory shard holds at most {MAX_PAGE_CHILDREN} page shards"
        );
        ends
    }
}

/// Writes a publishable shard set for `shards`, numbered from zero, to `dir`,
/// as the publisher would: one directory per manifest digest and the map in
/// `shards.json`, declaring `recuts`. `hash` gives each shard's parent and
/// terminal block, and each page shard's terminal block. Every geometry a shard
/// or a declaration names is sealed under `seal`. Returns the map.
pub fn publish(
    dir: &Path,
    shards: &[ShardSpec],
    seal: SealParameters,
    hash: impl Fn(u64) -> BlockHash,
    recuts: Vec<Recut>,
) -> ShardMap {
    let genesis = BlockHash::from_display_hex(
        zakura_transparent_private_shared::filter::MAINNET_GENESIS_DISPLAY,
    )
    .expect("mainnet's genesis hash");
    let mut entries = Vec::new();
    let mut parent_digest = String::new();
    for (shard_id, spec) in shards.iter().enumerate() {
        let shard_id = shard_id as u64;
        let geometry = spec.geometry;
        let blocks: Vec<Block> = (spec.start..=spec.end)
            .map(|height| {
                let events = spec
                    .events
                    .iter()
                    .filter(|(_, event)| u64::from(event.height()) == height)
                    .cloned()
                    .collect();
                (height, events)
            })
            .collect();
        let (mut built, children) = build_directory_shard(
            shard_id,
            geometry,
            genesis,
            PROFILE,
            blocks,
            &spec.page_ends(),
            &hash,
            spec.sealed,
        )
        .expect("a buildable shard");
        malform(
            &mut built.directory,
            shard_id,
            geometry,
            &spec.malformed_entries,
        );
        let page_children: Vec<_> = children
            .iter()
            .map(|child| child.describe(geometry))
            .collect();
        let directory_bytes = geometry.directory_bytes_per_segment();
        let manifest = ShardManifest {
            schema: SCHEMA.to_string(),
            profile: PROFILE.to_string(),
            geometry: geometry.name.to_string(),
            network: zakura_transparent_private_shared::filter::NETWORK.to_string(),
            genesis_hash: zakura_transparent_private_shared::filter::MAINNET_GENESIS_DISPLAY
                .to_string(),
            shard_id,
            start_height: spec.start,
            end_height: spec.end,
            parent_block_hash: hash(spec.start - 1).to_display_hex(),
            terminal_block_hash: hash(spec.end).to_display_hex(),
            tag_salt_counter: built.tag_salt_counter,
            parent_manifest_digest: parent_digest.clone(),
            sealed: spec.sealed,
            revision: spec.revision,
            supersedes: spec.supersedes.clone(),
            seal: ManifestSeal {
                scripts_target: seal.max_scripts,
                scripts_capacity: seal.max_scripts * 2,
                directory_bytes_target: directory_bytes - directory_bytes / 7,
                directory_bytes_capacity: directory_bytes,
                page_rows_target: seal.max_page_rows,
                page_rows_capacity: seal.max_page_rows * 2,
                max_page_children: MAX_PAGE_CHILDREN,
            },
            layout: ManifestLayout::current(),
            filter_hash: filter_hash(built.filter.as_slice()).to_display_hex(),
            directory_segments: built
                .directory
                .iter()
                .map(|segment| TableGeometry {
                    rows: geometry.directory_rows,
                    row_bytes: geometry.directory_row_bytes as u32,
                    sha256: hex::encode(Sha256::digest(segment)),
                })
                .collect(),
            occupancy: ManifestOccupancy {
                scripts: built.scripts,
                page_rows: page_children
                    .iter()
                    .map(|child| child.occupancy.page_rows)
                    .sum(),
                fragments: page_children
                    .iter()
                    .map(|child| child.occupancy.fragments)
                    .sum(),
                events: built.events,
                blocks: spec.end - spec.start + 1,
                txids: 0,
                excluded_scripts: built.excluded_scripts,
            },
            page_children,
            directory_choice: None,
        };
        manifest
            .check_children(geometry.page_rows, geometry.page_row_bytes as u32)
            .expect("well-formed page shards");
        let digest = manifest.digest();
        let shard_dir = dir.join(&digest);
        std::fs::create_dir_all(&shard_dir).expect("a shard directory");
        let write = |name: String, bytes: &[u8]| {
            std::fs::write(shard_dir.join(name), bytes).expect("a writable shard set");
        };
        write("manifest.json".into(), &manifest.canonical_bytes());
        write("filter.bin".into(), built.filter.as_slice());
        for (index, segment) in built.directory.iter().enumerate() {
            write(format!("directory.{index}.bin"), segment);
        }
        for child in &children {
            for segment in 0..child.segments {
                write(
                    format!("{}.{segment}.bin", pages_table(child.index)),
                    &child.segment(geometry, segment),
                );
            }
        }
        entries.push(ShardMapEntry {
            shard_id,
            geometry: geometry.name.to_string(),
            start_height: spec.start,
            end_height: spec.end,
            parent_block_hash: manifest.parent_block_hash.clone(),
            terminal_block_hash: manifest.terminal_block_hash.clone(),
            filter_hash: manifest.filter_hash.clone(),
            scripts: built.scripts,
            page_rows: manifest.occupancy.page_rows,
            txids: 0,
            directory_segments: built.directory_segments(),
            // Counts page shards in schema v12.
            page_segments: manifest.page_children.len() as u32,
            manifest_digest: digest.clone(),
            revision: spec.revision,
            sealed: spec.sealed,
        });
        parent_digest = digest;
    }
    let map = ShardMap {
        genesis_hash: zakura_transparent_private_shared::filter::MAINNET_GENESIS_DISPLAY
            .to_string(),
        network: zakura_transparent_private_shared::filter::NETWORK.to_string(),
        profile: PROFILE.to_string(),
        range_envelope_version: zakura_transparent_private_shared::filter::RANGE_ENVELOPE_VERSION,
        start_height: shards[0].start,
        seal: shards
            .iter()
            .map(|spec| spec.geometry.name.to_string())
            .chain(
                recuts
                    .iter()
                    .flat_map(|recut| &recut.superseded)
                    .map(|shard| shard.geometry.clone()),
            )
            .map(|geometry| (geometry, seal))
            .collect(),
        shards: entries,
        recuts,
    };
    map.check_shape().expect("a well-formed map");
    std::fs::write(
        dir.join("shards.json"),
        serde_json::to_vec(&map).expect("a serializable map"),
    )
    .expect("a writable shard set");
    map
}

/// Makes both candidate rows of each of `scripts` in shard `shard_id`'s `directory`
/// undecodable: a row's entry count is set past what a row holds. Done before the
/// manifest commits to the segments, so the service serves the rows as published.
fn malform(directory: &mut [Vec<u8>], shard_id: u64, geometry: &Geometry, scripts: &[ScriptBytes]) {
    let rows = geometry.directory_rows * directory.len() as u64;
    let row_bytes = geometry.directory_row_bytes;
    for script in scripts {
        for row in candidate_rows(shard_id, script.as_slice(), rows) {
            let (segment, within) = split_row(row, geometry.directory_rows);
            let at = within as usize * row_bytes;
            let row = &mut directory[segment as usize][at..at + row_bytes];
            row[..4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(decode_directory_row(row, MAX_PAGE_CHILDREN).is_err());
        }
    }
}

/// `entry` as a re-cut declares it superseded: exactly as it was published.
pub fn superseded(entry: &ShardMapEntry) -> SupersededShard {
    SupersededShard {
        shard_id: entry.shard_id,
        geometry: entry.geometry.clone(),
        start_height: entry.start_height,
        end_height: entry.end_height,
        terminal_block_hash: entry.terminal_block_hash.clone(),
        manifest_digest: entry.manifest_digest.clone(),
        revision: entry.revision,
        sealed: entry.sealed,
    }
}

pub use super::publication::InProcess;
