//! What a display shard publishes about itself, and the display map.
//!
//! Identity works as for history shards: a revision is named by the digest of
//! its canonical manifest. Sealed display manifests are content-pure (revision
//! 0, nothing superseded), so the same range rebuilt from the same journal
//! has the same digest however and whenever it was sealed. Only the recent
//! shard has a revision lineage.
//!
//! Archives are contiguous from the map's start. The recent shard follows
//! them by id but overlaps them by height: it starts at or before the first
//! height no archive holds, so a height at or below the last archive's end is
//! looked up in its archive and anything above in the recent shard.

use super::seal::DisplaySealParams;
use super::tables::BuiltDisplay;
use super::{
    display_by_name, DisplayTable, BUCKET_DOMAIN, DISPLAY_SCHEMA, MAX_BUCKETS, MAX_PLACEMENT_SEEDS,
    PLACEMENT_DOMAIN,
};
use crate::layout::Geometry;
use crate::manifest::TableGeometry;
use crate::txid::{slots_per_row, CODEC, ENTRY_BYTES, TAG_DOMAIN};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The fixed encoding parameters, restated so a consumer refuses a build that
/// changed one instead of misreading rows.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DisplayLayout {
    pub codec: String,
    pub entry_bytes: u32,
    pub row_bytes: u32,
    pub slots_per_row: u32,
    /// Rows an entry may occupy in its table: one.
    pub directory_choices: u32,
    pub placement_domain: String,
    pub max_placement_seeds: u32,
    pub bucket_domain: String,
    pub tag_domain: String,
}

impl DisplayLayout {
    /// The layout this build writes at `geometry`.
    pub fn of(geometry: &Geometry) -> Self {
        Self {
            codec: CODEC.to_string(),
            entry_bytes: ENTRY_BYTES as u32,
            row_bytes: geometry.directory_row_bytes as u32,
            slots_per_row: slots_per_row(geometry.directory_row_bytes) as u32,
            directory_choices: 1,
            placement_domain: String::from_utf8(PLACEMENT_DOMAIN.to_vec()).unwrap(),
            max_placement_seeds: MAX_PLACEMENT_SEEDS,
            bucket_domain: String::from_utf8(BUCKET_DOMAIN.to_vec()).unwrap(),
            tag_domain: String::from_utf8(TAG_DOMAIN.to_vec()).unwrap(),
        }
    }
}

/// One bucket's table and how many entries it holds: the anonymity set of a
/// lookup in this bucket.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DisplayBucket {
    pub bucket: u32,
    pub records: u64,
    /// The seed every entry's row in this bucket is derived under.
    pub placement_seed: u32,
    pub directory_segments: Vec<TableGeometry>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DisplayManifest {
    pub schema: String,
    pub network: String,
    pub genesis_hash: String,
    pub shard_id: u64,
    pub start_height: u64,
    pub end_height: u64,
    /// The block before `start_height`, in display hex.
    pub parent_block_hash: String,
    /// The block at `end_height`, in display hex.
    pub terminal_block_hash: String,
    /// The previous *sealed* display shard, or empty for the first one.
    pub parent_manifest_digest: String,
    pub sealed: bool,
    pub revision: u32,
    pub supersedes: String,
    pub geometry: String,
    pub n_buckets: u32,
    /// Per-bucket record target the seal rule applied; it decides where a
    /// sealed shard ends, so it is part of the shard's identity.
    pub archive_target: u64,
    pub layout: DisplayLayout,
    pub blocks: u64,
    pub records: u64,
    pub buckets: Vec<DisplayBucket>,
}

/// Identity and placement inputs of a manifest; the tables supply the rest.
#[derive(Clone, Debug)]
pub struct ManifestHeader {
    pub network: String,
    pub genesis_hash: String,
    pub shard_id: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub parent_block_hash: String,
    pub terminal_block_hash: String,
    pub parent_manifest_digest: String,
    pub sealed: bool,
    pub revision: u32,
    pub supersedes: String,
    pub archive_target: u64,
}

fn digest_tables(segments: &[Vec<u8>], geometry: &Geometry) -> Vec<TableGeometry> {
    segments
        .iter()
        .map(|segment| TableGeometry {
            rows: geometry.directory_rows,
            row_bytes: geometry.directory_row_bytes as u32,
            sha256: hex::encode(Sha256::digest(segment)),
        })
        .collect()
}

impl DisplayManifest {
    pub fn new(header: ManifestHeader, geometry: &Geometry, built: &BuiltDisplay) -> Self {
        Self {
            schema: DISPLAY_SCHEMA.to_string(),
            network: header.network,
            genesis_hash: header.genesis_hash,
            shard_id: header.shard_id,
            start_height: header.start_height,
            end_height: header.end_height,
            parent_block_hash: header.parent_block_hash,
            terminal_block_hash: header.terminal_block_hash,
            parent_manifest_digest: header.parent_manifest_digest,
            sealed: header.sealed,
            revision: header.revision,
            supersedes: header.supersedes,
            geometry: geometry.name.to_string(),
            n_buckets: built.buckets.len() as u32,
            archive_target: header.archive_target,
            layout: DisplayLayout::of(geometry),
            blocks: header.end_height - header.start_height + 1,
            records: built.records,
            buckets: built
                .buckets
                .iter()
                .enumerate()
                .map(|(b, bucket)| DisplayBucket {
                    bucket: b as u32,
                    records: bucket.records,
                    placement_seed: bucket.placement_seed,
                    directory_segments: digest_tables(&bucket.directory, geometry),
                })
                .collect(),
        }
    }

    /// Field order is declaration order, which serde preserves.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a display manifest serializes")
    }

    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_bytes()))
    }

    pub fn min_bucket_records(&self) -> u64 {
        self.buckets.iter().map(|b| b.records).min().unwrap_or(0)
    }

    /// Placement seeds, in bucket order.
    pub fn placement_seeds(&self) -> Vec<u32> {
        self.buckets.iter().map(|b| b.placement_seed).collect()
    }

    /// Segment geometries of `table`, if the shard has it.
    pub fn segments(&self, table: DisplayTable) -> Option<&[TableGeometry]> {
        self.buckets
            .get(table.bucket() as usize)
            .map(|b| b.directory_segments.as_slice())
    }

    /// Every table, in bucket order.
    pub fn tables(&self) -> Vec<DisplayTable> {
        (0..self.n_buckets).map(DisplayTable::Directory).collect()
    }

    pub fn display_geometry(&self) -> Option<&'static Geometry> {
        display_by_name(&self.geometry)
    }

    /// Internal consistency, checked before any table is opened.
    /// Rejects reversed or unrepresentable block spans and overflowing record totals.
    pub fn validate(&self) -> Result<&'static Geometry, String> {
        let geometry = self
            .display_geometry()
            .ok_or_else(|| format!("unknown display geometry {:?}", self.geometry))?;
        if self.schema != DISPLAY_SCHEMA {
            return Err(format!("unsupported display schema {:?}", self.schema));
        }
        if self.layout != DisplayLayout::of(geometry) {
            return Err("display layout differs from this build".into());
        }
        if self.n_buckets == 0 || self.n_buckets > MAX_BUCKETS {
            return Err(format!("{} buckets", self.n_buckets));
        }
        let blocks = self
            .end_height
            .checked_sub(self.start_height)
            .and_then(|span| span.checked_add(1))
            .ok_or("display shard range")?;
        if self.blocks != blocks {
            return Err("display shard range".into());
        }
        for hash in [
            &self.genesis_hash,
            &self.parent_block_hash,
            &self.terminal_block_hash,
        ] {
            if hash.len() != 64 {
                return Err("display shard block hash".into());
            }
        }
        if !self.parent_manifest_digest.is_empty() && self.parent_manifest_digest.len() != 64 {
            return Err("parent manifest digest".into());
        }
        if self.sealed && (self.revision != 0 || !self.supersedes.is_empty()) {
            return Err("a sealed display shard is content-pure: revision 0".into());
        }
        if self.buckets.len() != self.n_buckets as usize {
            return Err("bucket list length".into());
        }
        let mut total = 0u64;
        for (index, bucket) in self.buckets.iter().enumerate() {
            if bucket.bucket != index as u32 {
                return Err(format!("bucket {index} is labelled {}", bucket.bucket));
            }
            if bucket.placement_seed >= MAX_PLACEMENT_SEEDS {
                return Err(format!("bucket {index} placement seed"));
            }
            check_segments(&bucket.directory_segments, geometry)?;
            total = total.checked_add(bucket.records).ok_or("record total")?;
        }
        if total != self.records {
            return Err("record total".into());
        }
        Ok(geometry)
    }
}

fn check_segments(segments: &[TableGeometry], geometry: &Geometry) -> Result<(), String> {
    if segments.is_empty() {
        return Err("a display table has no segment".into());
    }
    if segments.iter().any(|s| {
        s.rows != geometry.directory_rows
            || s.row_bytes != geometry.directory_row_bytes as u32
            || s.sha256.len() != 64
    }) {
        return Err("display segment geometry".into());
    }
    Ok(())
}

/// One shard as the map lists it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DisplayMapEntry {
    pub shard_id: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub parent_block_hash: String,
    pub terminal_block_hash: String,
    pub geometry: String,
    pub n_buckets: u32,
    /// Segments per bucket table, in bucket order.
    pub directory_segments: Vec<u32>,
    /// Placement seed per bucket table, in bucket order.
    pub placement_seeds: Vec<u32>,
    pub records: u64,
    pub min_bucket_records: u64,
    pub manifest_digest: String,
    pub revision: u32,
    pub sealed: bool,
}

impl DisplayMapEntry {
    pub fn from_manifest(manifest: &DisplayManifest, digest: &str) -> Self {
        Self {
            shard_id: manifest.shard_id,
            start_height: manifest.start_height,
            end_height: manifest.end_height,
            parent_block_hash: manifest.parent_block_hash.clone(),
            terminal_block_hash: manifest.terminal_block_hash.clone(),
            geometry: manifest.geometry.clone(),
            n_buckets: manifest.n_buckets,
            directory_segments: manifest
                .buckets
                .iter()
                .map(|b| b.directory_segments.len() as u32)
                .collect(),
            placement_seeds: manifest.placement_seeds(),
            records: manifest.records,
            min_bucket_records: manifest.min_bucket_records(),
            manifest_digest: digest.to_string(),
            revision: manifest.revision,
            sealed: manifest.sealed,
        }
    }

    /// Whether this entry describes exactly `manifest` under `digest`.
    pub fn describes(&self, manifest: &DisplayManifest) -> bool {
        manifest.digest() == self.manifest_digest
            && *self == Self::from_manifest(manifest, &self.manifest_digest)
    }

    /// The tier a lookup in this shard names; the sealed flag, nothing more.
    pub fn tier(&self) -> &'static str {
        if self.sealed {
            "archive"
        } else {
            "recent"
        }
    }
}

/// `GET /v2/txid/shards`: the shards currently served, oldest first. Clients
/// read the [split map](super::split) instead; this full listing is kept for
/// clients built before it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DisplayMap {
    pub schema: String,
    pub network: String,
    pub genesis_hash: String,
    pub seal: DisplaySealParams,
    /// First height served; advances when the oldest archive leaves the window.
    pub start_height: u64,
    /// Id of the first listed shard. Ids are absolute and never renumbered.
    pub first_shard_id: u64,
    pub shards: Vec<DisplayMapEntry>,
}

impl DisplayMap {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("a display map serializes")
    }

    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(self.to_bytes()))
    }

    /// The listed archives, oldest first.
    pub fn archives(&self) -> &[DisplayMapEntry] {
        let count = self.shards.iter().take_while(|s| s.sealed).count();
        &self.shards[..count]
    }

    /// The unsealed recent shard, when listed.
    pub fn recent(&self) -> Option<&DisplayMapEntry> {
        self.shards.last().filter(|s| !s.sealed)
    }

    /// The first height no archive holds: the last archive's end plus one,
    /// or the start when none is listed. It and every later height are the
    /// recent shard's. Requires a map that passed [`Self::check_shape`].
    pub fn unsealed_start(&self) -> u64 {
        self.archives()
            .last()
            .map_or(self.start_height, |a| a.end_height + 1)
    }

    /// The shard a lookup at `height` names: its archive below
    /// [`Self::unsealed_start`], otherwise the recent shard.
    pub fn shard_for_height(&self, height: u64) -> Option<&DisplayMapEntry> {
        if height < self.unsealed_start() {
            return find_by_height(self.archives(), height);
        }
        self.recent().filter(|r| height <= r.end_height)
    }

    pub fn shard(&self, shard_id: u64) -> Option<&DisplayMapEntry> {
        let index = shard_id.checked_sub(self.first_shard_id)?;
        self.shards.get(usize::try_from(index).ok()?)
    }

    pub fn covered_through(&self) -> Option<u64> {
        self.shards.last().map(|s| s.end_height)
    }

    /// Checks the map is well formed before anything is fetched.
    pub fn check_shape(&self) -> Result<(), String> {
        if self.schema != DISPLAY_SCHEMA {
            return Err(format!("unsupported display map schema {:?}", self.schema));
        }
        self.seal.check()?;
        let Some(first) = self.shards.first() else {
            return Err("display map is empty".into());
        };
        if first.start_height != self.start_height || first.shard_id != self.first_shard_id {
            return Err("display map start".into());
        }
        for (index, shard) in self.shards.iter().enumerate() {
            if self.first_shard_id.checked_add(index as u64) != Some(shard.shard_id) {
                return Err(format!(
                    "display shard at position {index} claims id {}",
                    shard.shard_id
                ));
            }
            check_entry(&self.seal, shard)?;
            if !shard.sealed && index + 1 != self.shards.len() {
                return Err(format!(
                    "unsealed display shard {} is not last",
                    shard.shard_id
                ));
            }
        }
        let archives = self.archives();
        // Validate the exclusive end before unsealed_start is used, including
        // maps containing only sealed archives.
        if archives
            .last()
            .is_some_and(|last| last.end_height.checked_add(1).is_none())
        {
            return Err("display archive height range overflows".into());
        }
        for pair in archives.windows(2) {
            check_chain(&pair[0], &pair[1])?;
        }
        if let Some(recent) = self.recent() {
            check_recent(&self.seal, self.start_height, self.unsealed_start(), recent)?;
            for archive in archives {
                check_recent_parent(archive, recent)?;
            }
        }
        Ok(())
    }
}

/// Checks one listed shard on its own: range, geometry, tables, digest, and
/// for a sealed shard the bucket target and content purity.
pub(crate) fn check_entry(seal: &DisplaySealParams, shard: &DisplayMapEntry) -> Result<(), String> {
    if shard.end_height < shard.start_height {
        return Err(format!(
            "display shard {} ends before it starts",
            shard.shard_id
        ));
    }
    if display_by_name(&shard.geometry).is_none() {
        return Err(format!("display shard {} geometry", shard.shard_id));
    }
    let expected_buckets = if shard.sealed {
        seal.n_archive
    } else {
        seal.n_recent
    };
    if shard.n_buckets != expected_buckets
        || !(1..=MAX_BUCKETS).contains(&shard.n_buckets)
        || shard.directory_segments.len() != shard.n_buckets as usize
        || shard.directory_segments.contains(&0)
        || shard.placement_seeds.len() != shard.n_buckets as usize
        || shard
            .placement_seeds
            .iter()
            .any(|s| *s >= MAX_PLACEMENT_SEEDS)
    {
        return Err(format!("display shard {} tables", shard.shard_id));
    }
    if shard.manifest_digest.len() != 64 {
        return Err(format!("display shard {} digest", shard.shard_id));
    }
    if shard.sealed && (shard.revision != 0 || shard.min_bucket_records < seal.archive_target) {
        return Err(format!(
            "sealed display shard {} is below its bucket target or not content-pure",
            shard.shard_id
        ));
    }
    Ok(())
}

/// Checks the recent shard's range against the archives': it starts no lower
/// than the map, no higher than the first unsealed height, and reaches above
/// the last archive. It holds `recent_window` txids per bucket unless it
/// covers everything from the map's start.
pub(crate) fn check_recent(
    seal: &DisplaySealParams,
    start_height: u64,
    unsealed_start: u64,
    recent: &DisplayMapEntry,
) -> Result<(), String> {
    if recent.start_height < start_height
        || recent.start_height > unsealed_start
        || recent.end_height < unsealed_start
    {
        return Err(format!(
            "recent display shard {} does not cover the unsealed range",
            recent.shard_id
        ));
    }
    if recent.start_height != start_height && recent.min_bucket_records < seal.recent_window {
        return Err(format!(
            "recent display shard {} holds {} txids in a bucket, below the window of {}",
            recent.shard_id, recent.min_bucket_records, seal.recent_window
        ));
    }
    Ok(())
}

/// Checks the recent shard's parent block against `archive` wherever the
/// archive names that block: its terminal when the recent shard starts right
/// after it, its parent when both start at the same height.
pub(crate) fn check_recent_parent(
    archive: &DisplayMapEntry,
    recent: &DisplayMapEntry,
) -> Result<(), String> {
    let next_height = archive.end_height.checked_add(1).ok_or_else(|| {
        format!(
            "display archive {} height range overflows",
            archive.shard_id
        )
    })?;
    let parent = if recent.start_height == next_height {
        &archive.terminal_block_hash
    } else if recent.start_height == archive.start_height {
        &archive.parent_block_hash
    } else {
        return Ok(());
    };
    if recent.parent_block_hash != *parent {
        return Err(format!(
            "recent display shard {} does not chain to archive {}",
            recent.shard_id, archive.shard_id
        ));
    }
    Ok(())
}

/// Checks `shard` starts right after `previous`, at the next height and on
/// its terminal block.
pub(crate) fn check_chain(
    previous: &DisplayMapEntry,
    shard: &DisplayMapEntry,
) -> Result<(), String> {
    if previous.end_height.checked_add(1) != Some(shard.start_height)
        || shard.parent_block_hash != previous.terminal_block_hash
    {
        return Err(format!(
            "display shard {} does not chain to {}",
            shard.shard_id, previous.shard_id
        ));
    }
    Ok(())
}

/// The listed shard covering `height`, in a contiguous list ordered by height.
pub(crate) fn find_by_height(shards: &[DisplayMapEntry], height: u64) -> Option<&DisplayMapEntry> {
    let index = shards
        .binary_search_by(|shard| {
            if shard.end_height < height {
                std::cmp::Ordering::Less
            } else if shard.start_height > height {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .ok()?;
    shards.get(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display::{build_shard, TXID_2K8};
    use crate::txid::{DisplayFacts, DisplayOutput};
    use transparent_events::Txid;

    fn built() -> BuiltDisplay {
        let entries: Vec<_> = (0u8..20)
            .map(|i| {
                DisplayFacts {
                    txid: Txid([i; 32]),
                    coinbase: false,
                    fee: 1,
                    has_shielded_components: false,
                    spent: vec![DisplayOutput {
                        value: 2,
                        script: vec![0; 25],
                    }],
                    outputs: vec![DisplayOutput {
                        value: 1,
                        script: vec![0; 25],
                    }],
                }
                .entry()
                .unwrap()
            })
            .collect();
        build_shard(5, &TXID_2K8, 2, &entries).unwrap()
    }

    fn header(sealed: bool) -> ManifestHeader {
        ManifestHeader {
            network: "mainnet".into(),
            genesis_hash: "00".repeat(32),
            shard_id: 5,
            start_height: 100,
            end_height: 199,
            parent_block_hash: "11".repeat(32),
            terminal_block_hash: "22".repeat(32),
            parent_manifest_digest: "33".repeat(32),
            sealed,
            revision: 0,
            supersedes: String::new(),
            archive_target: 10,
        }
    }

    fn manifest() -> DisplayManifest {
        DisplayManifest::new(header(true), &TXID_2K8, &built())
    }

    #[test]
    fn manifest_block_count_rejects_overflow_and_keeps_representable_limits() {
        let mut m = manifest();
        m.start_height = 0;
        m.end_height = u64::MAX;
        m.blocks = 0; // The value unchecked arithmetic would wrap to.
        assert!(m.validate().is_err());
        m.start_height = u64::MAX;
        m.end_height = 0;
        m.blocks = 1;
        assert!(m.validate().is_err());
        for (start, end, blocks) in [(1, u64::MAX, u64::MAX), (u64::MAX, u64::MAX, 1), (0, 0, 1)] {
            m.start_height = start;
            m.end_height = end;
            m.blocks = blocks;
            m.validate().unwrap();
            m.blocks = blocks - 1;
            assert!(m.validate().is_err());
        }
    }

    #[test]
    fn manifest_record_total_rejects_overflow_and_keeps_representable_limits() {
        let mut m = manifest();
        assert_eq!(m.buckets.len(), 2);
        for (first, second, total) in [(u64::MAX, u64::MAX, u64::MAX - 1), (u64::MAX, 1, 0)] {
            m.buckets[0].records = first;
            m.buckets[1].records = second;
            m.records = total;
            assert!(m.validate().is_err());
        }
        for (first, second, total) in [
            (u64::MAX - 1, 1, u64::MAX),
            (u64::MAX, 0, u64::MAX),
            (0, 0, 0),
        ] {
            m.buckets[0].records = first;
            m.buckets[1].records = second;
            m.records = total;
            m.validate().unwrap();
            m.records = total ^ 1;
            assert!(m.validate().is_err());
        }
    }

    #[test]
    fn manifest_validates_and_every_field_reaches_the_digest() {
        let base = manifest();
        base.validate().unwrap();
        let digest = base.digest();
        type Mutation = Box<dyn Fn(&mut DisplayManifest)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|m| m.schema.push('x')),
            Box::new(|m| m.network.push('x')),
            Box::new(|m| m.genesis_hash = "99".repeat(32)),
            Box::new(|m| m.shard_id += 1),
            Box::new(|m| m.start_height += 1),
            Box::new(|m| m.end_height += 1),
            Box::new(|m| m.parent_block_hash = "99".repeat(32)),
            Box::new(|m| m.terminal_block_hash = "99".repeat(32)),
            Box::new(|m| m.parent_manifest_digest = "99".repeat(32)),
            Box::new(|m| m.sealed = false),
            Box::new(|m| m.revision += 1),
            Box::new(|m| m.supersedes = "99".repeat(32)),
            Box::new(|m| m.geometry = "txid-2k".into()),
            Box::new(|m| m.n_buckets += 1),
            Box::new(|m| m.archive_target += 1),
            Box::new(|m| m.layout.entry_bytes += 1),
            Box::new(|m| m.blocks += 1),
            Box::new(|m| m.records += 1),
            Box::new(|m| m.layout.directory_choices = 2),
            Box::new(|m| m.buckets[0].records += 1),
            Box::new(|m| m.buckets[1].placement_seed += 1),
            Box::new(|m| m.buckets[1].directory_segments[0].sha256 = "99".repeat(32)),
            Box::new(|m| {
                let extra = m.buckets[0].directory_segments[0].clone();
                m.buckets[0].directory_segments.push(extra);
            }),
        ];
        for mutate in mutations {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert_ne!(changed.digest(), digest);
        }
    }

    #[test]
    fn manifest_validation_refuses_inconsistent_content() {
        let mut m = manifest();
        m.revision = 1;
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.buckets[0].records += 1;
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.geometry = "decoupled-32k-32k".into();
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.buckets[1].directory_segments[0].rows = 4096;
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.buckets[1].directory_segments[0].row_bytes = 4096;
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.buckets[0].placement_seed = MAX_PLACEMENT_SEEDS;
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.layout.row_bytes = 4096;
        assert!(m.validate().is_err());
        let mut m = DisplayManifest::new(header(false), &TXID_2K8, &built());
        m.revision = 3;
        m.supersedes = "44".repeat(32);
        m.validate().unwrap();
    }

    fn map() -> DisplayMap {
        let seal = DisplaySealParams {
            n_archive: 2,
            n_recent: 2,
            archive_target: 5,
            recent_window: 5,
            reorg_margin: 100,
        };
        let mut shards = Vec::new();
        let mut parent = "11".repeat(32);
        for (i, sealed) in [true, true, false].into_iter().enumerate() {
            let mut h = header(sealed);
            h.shard_id = 7 + i as u64;
            h.start_height = 100 + i as u64 * 100;
            h.end_height = h.start_height + 99;
            h.parent_block_hash = parent.clone();
            h.terminal_block_hash = format!("{:064x}", i + 1);
            parent = h.terminal_block_hash.clone();
            let m = DisplayManifest::new(h, &TXID_2K8, &built());
            shards.push(DisplayMapEntry::from_manifest(&m, &m.digest()));
        }
        DisplayMap {
            schema: DISPLAY_SCHEMA.into(),
            network: "mainnet".into(),
            genesis_hash: "00".repeat(32),
            seal,
            start_height: 100,
            first_shard_id: 7,
            shards,
        }
    }

    #[test]
    fn full_map_rejects_overflowing_archive_heights_and_ids() {
        let original = map();
        for index in [0, 1] {
            let mut hostile = original.clone();
            hostile.shards[index].end_height = u64::MAX;
            assert!(hostile.check_shape().is_err());
            // The range must also be rejected when there is no recent shard.
            hostile.shards.pop();
            assert!(hostile.check_shape().is_err());
        }
        let mut hostile = original.clone();
        hostile.first_shard_id = u64::MAX;
        hostile.shards[0].shard_id = u64::MAX;
        hostile.shards[1].shard_id = 0;
        hostile.shards[2].shard_id = 1;
        assert!(hostile.check_shape().is_err());
        // The highest representable consecutive ids still describe a valid map.
        let mut valid = original;
        valid.first_shard_id = u64::MAX - 2;
        for (index, shard) in valid.shards.iter_mut().enumerate() {
            shard.shard_id = valid.first_shard_id + index as u64;
        }
        valid.check_shape().unwrap();
    }

    #[test]
    fn recent_parent_rejects_an_overflowing_archive_height() {
        let m = map();
        let mut archive = m.shards[0].clone();
        let mut recent = m.shards[2].clone();
        archive.end_height = u64::MAX;
        recent.start_height = 0;
        recent.parent_block_hash = archive.terminal_block_hash.clone();
        assert!(check_recent_parent(&archive, &recent).is_err());
        // Even a recent shard starting at the archive's start cannot give an
        // overflowing sealed range a representable next height.
        recent.start_height = archive.start_height;
        recent.parent_block_hash = archive.parent_block_hash.clone();
        assert!(check_recent_parent(&archive, &recent).is_err());
    }

    #[test]
    fn map_shape_and_lookup() {
        let m = map();
        m.check_shape().unwrap();
        assert_eq!(m.shard_for_height(250).unwrap().shard_id, 8);
        assert_eq!(m.shard(9).unwrap().tier(), "recent");
        assert!(m.shard(6).is_none() && m.shard_for_height(99).is_none());
        assert_eq!(m.covered_through(), Some(399));

        type Mutation = Box<dyn Fn(&mut DisplayMap)>;
        let broken: Vec<Mutation> = vec![
            Box::new(|m| m.first_shard_id = 0),
            Box::new(|m| m.shards[1].shard_id = 20),
            Box::new(|m| m.shards[1].start_height += 1),
            Box::new(|m| m.shards[1].parent_block_hash = "99".repeat(32)),
            Box::new(|m| m.shards[0].sealed = false),
            Box::new(|m| m.shards[0].min_bucket_records = 4),
            Box::new(|m| m.shards[0].revision = 1),
            Box::new(|m| m.shards[2].n_buckets = 1),
            Box::new(|m| m.shards[0].directory_segments[1] = 0),
            Box::new(|m| m.shards[0].placement_seeds.push(0)),
            Box::new(|m| m.shards[2].placement_seeds[0] = MAX_PLACEMENT_SEEDS),
            Box::new(|m| m.shards[0].geometry = "decoupled-2k-8k".into()),
            Box::new(|m| m.shards.clear()),
        ];
        for mutate in broken {
            let mut changed = map();
            mutate(&mut changed);
            assert!(changed.check_shape().is_err());
        }
        // A window that dropped its oldest shard is still well formed.
        let mut dropped = map();
        dropped.shards.remove(0);
        dropped.first_shard_id = 8;
        dropped.start_height = 200;
        dropped.check_shape().unwrap();
    }

    /// The recent shard 9 over `[start, 399]`, chained to the block before
    /// `start`, beside archives 7 over `[100, 199]` and 8 over `[200, 299]`.
    fn overlapping(start: u64, parent: String) -> DisplayMap {
        let mut m = map();
        let recent = &mut m.shards[2];
        recent.start_height = start;
        recent.parent_block_hash = parent;
        m
    }

    #[test]
    fn the_recent_shard_may_overlap_the_archives() {
        let terminal = |i: usize| format!("{i:064x}");
        // Inside the newest archive, at its start, inside an older one, at
        // the map's start, and right after the archives.
        for (start, parent) in [
            (250, "99".repeat(32)),
            (200, terminal(1)),
            (150, "99".repeat(32)),
            (100, "11".repeat(32)),
            (300, terminal(2)),
        ] {
            let m = overlapping(start, parent);
            m.check_shape().unwrap();
            // Heights the archives hold go to them, the rest to recent.
            assert_eq!(m.unsealed_start(), 300);
            assert_eq!(
                m.shard_for_height(start).unwrap().shard_id,
                7 + (start / 100 - 1)
            );
            assert_eq!(m.shard_for_height(299).unwrap().shard_id, 8);
            assert_eq!(m.shard_for_height(300).unwrap().shard_id, 9);
            assert!(m.shard_for_height(400).is_none());
            m.split().unwrap();
        }
        // A wrong parent where an archive names the block before the start.
        for (start, parent) in [(200, terminal(2)), (300, terminal(1)), (100, terminal(1))] {
            assert!(overlapping(start, parent).check_shape().is_err(), "{start}");
        }
        // Below the map, above the first unsealed height, or not above the
        // archives.
        assert!(overlapping(99, "99".repeat(32)).check_shape().is_err());
        assert!(overlapping(301, "99".repeat(32)).check_shape().is_err());
        let mut short = map();
        short.shards[2].end_height = 299;
        short.shards[2].start_height = 250;
        assert!(short.check_shape().is_err());
        // A recent shard below the window, unless it starts at the map's.
        let mut thin = overlapping(250, "99".repeat(32));
        thin.seal.recent_window = thin.shards[2].min_bucket_records + 1;
        assert!(thin.check_shape().is_err());
        let mut young = overlapping(100, "11".repeat(32));
        young.seal.recent_window = young.shards[2].min_bucket_records + 1;
        young.check_shape().unwrap();
    }
}
