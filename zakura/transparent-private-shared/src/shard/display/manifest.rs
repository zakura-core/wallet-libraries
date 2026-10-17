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
use super::{
    display_by_name, DisplayTable, BUCKET_DOMAIN, DISPLAY_SCHEMA, MAX_BUCKETS, MAX_PLACEMENT_SEEDS,
    PLACEMENT_DOMAIN,
};
use crate::shard::layout::Geometry;
use crate::shard::manifest::TableGeometry;
use crate::shard::txid::{slots_per_row, CODEC, ENTRY_BYTES, TAG_DOMAIN};
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

impl DisplayManifest {
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
    check_entry_structure(seal, shard)?;
    if display_by_name(&shard.geometry).is_none() {
        return Err(format!("display shard {} geometry", shard.shard_id));
    }
    Ok(())
}

/// Validates the wire fields shared by known and future geometries. A caller
/// must separately recognize the geometry before interpreting or querying it.
pub(crate) fn check_entry_structure(
    seal: &DisplaySealParams,
    shard: &DisplayMapEntry,
) -> Result<(), String> {
    if shard.end_height < shard.start_height {
        return Err(format!(
            "display shard {} ends before it starts",
            shard.shard_id
        ));
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
    if !is_digest(&shard.manifest_digest) {
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

pub(crate) fn is_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

    /// A map entry with only what chaining reads set meaningfully.
    fn entry(
        shard_id: u64,
        start: u64,
        end: u64,
        parent: String,
        terminal: String,
    ) -> DisplayMapEntry {
        DisplayMapEntry {
            shard_id,
            start_height: start,
            end_height: end,
            parent_block_hash: parent,
            terminal_block_hash: terminal,
            geometry: "txid-2k8".into(),
            n_buckets: 1,
            directory_segments: vec![1],
            placement_seeds: vec![0],
            records: 5,
            min_bucket_records: 5,
            manifest_digest: "ab".repeat(32),
            revision: 0,
            sealed: shard_id < 9,
        }
    }

    #[test]
    fn recent_parent_rejects_an_overflowing_archive_height() {
        let mut archive = entry(7, 100, 199, "11".repeat(32), format!("{:064x}", 1));
        let mut recent = entry(9, 300, 399, format!("{:064x}", 2), format!("{:064x}", 3));
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
}
