//! The split display map: a small recent map and immutable archive index
//! chunks.
//!
//! The full map lists every shard, so a client that refetches it after a 409
//! (the recent revision moves every block) pays for every archive each time.
//! The split publishes the same entries as two kinds of document:
//!
//! - **The recent map** (`GET /v2/txid/map`): the seal parameters, the start,
//!   the archive count, the last height an archive holds, one reference
//!   (start height and SHA-256) per index chunk, and the recent shard's entry.
//!   It changes every block and is what a client refetches after a 409.
//! - **Index chunks** (`GET /v2/txid/map/{base}/{sha256}`): the archive
//!   entries whose absolute shard ids lie in `[base, base + 32)`, where `base`
//!   is a multiple of [`INDEX_CHUNK_SHARDS`]. A chunk is addressed by its
//!   digest, so it is cacheable forever; only the newest chunk changes at a
//!   seal, and the oldest when the window drops an archive.
//!
//! A client fetches the recent map and only the chunk covering its height. A
//! chunk discloses a 32-archive range, coarser than the shard id a query
//! already names.
//!
//! Both documents are derived from the full [`DisplayMap`] by [`DisplayMap::split`],
//! so the full map and the split never disagree. Their canonical encoding is
//! compact JSON in declaration order.

use super::manifest::{
    check_chain, check_entry, check_recent, check_recent_parent, find_by_height,
};
use super::seal::DisplaySealParams;
use super::{DisplayMap, DisplayMapEntry, DISPLAY_SCHEMA};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Archives per index chunk. Chunks start at absolute shard ids that are
/// multiples of this, so a chunk's address never moves.
pub const INDEX_CHUNK_SHARDS: u64 = 32;

/// The recent map's file in a publication directory.
pub const RECENT_MAP_FILE: &str = "txid-map.json";

/// The file of the index chunk with this digest in a publication directory.
pub fn index_file(sha256: &str) -> String {
    format!("txid-index-{sha256}.json")
}

/// The base shard id of the index chunk holding `shard_id`.
pub fn chunk_base(shard_id: u64) -> u64 {
    shard_id - shard_id % INDEX_CHUNK_SHARDS
}

fn is_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// One index chunk as the recent map names it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DisplayChunkRef {
    /// The first height the chunk's first listed archive covers.
    pub start_height: u64,
    /// SHA-256 of the chunk's canonical bytes, hex.
    pub sha256: String,
}

/// `GET /v2/txid/map`: everything a lookup needs that changes every block.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DisplayRecentMap {
    pub schema: String,
    pub network: String,
    pub genesis_hash: String,
    pub seal: DisplaySealParams,
    /// First height served; advances when the oldest archive leaves the window.
    pub start_height: u64,
    /// Id of the first listed shard. Ids are absolute and never renumbered.
    pub first_shard_id: u64,
    /// Sealed archives listed, ids `first_shard_id..first_shard_id + archives`.
    pub archives: u64,
    /// The first height no archive holds: the last archive's end plus one,
    /// or `start_height` with none. It and every later height are the recent
    /// shard's, which may start lower.
    pub unsealed_start: u64,
    /// [`INDEX_CHUNK_SHARDS`], restated so a client refuses another chunking.
    pub chunk_shards: u64,
    /// One per index chunk holding a listed archive, oldest first.
    pub chunks: Vec<DisplayChunkRef>,
    /// The unsealed recent shard, after every archive.
    pub recent: Option<DisplayMapEntry>,
}

/// `GET /v2/txid/map/{base}/{sha256}`: the listed archives of one chunk.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DisplayIndexChunk {
    pub schema: String,
    /// The chunk's address: a multiple of [`INDEX_CHUNK_SHARDS`].
    pub base_shard_id: u64,
    /// Listed archives with ids in `[base, base + 32)`, oldest first. The
    /// oldest chunk starts at the window's first shard.
    pub shards: Vec<DisplayMapEntry>,
}

impl DisplayIndexChunk {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("an index chunk serializes")
    }

    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(self.to_bytes()))
    }

    /// The chunk's archive covering `height`.
    pub fn shard_for_height(&self, height: u64) -> Option<&DisplayMapEntry> {
        find_by_height(&self.shards, height)
    }
}

/// The two documents of a split map, each with its canonical bytes.
#[derive(Clone, Debug)]
pub struct SplitMap {
    pub recent: DisplayRecentMap,
    pub recent_bytes: Vec<u8>,
    pub recent_sha256: String,
    /// In the recent map's chunk order.
    pub chunks: Vec<SplitChunk>,
}

#[derive(Clone, Debug)]
pub struct SplitChunk {
    pub chunk: DisplayIndexChunk,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

impl SplitChunk {
    fn new(chunk: DisplayIndexChunk) -> Self {
        let bytes = chunk.to_bytes();
        let sha256 = hex::encode(Sha256::digest(&bytes));
        Self {
            chunk,
            bytes,
            sha256,
        }
    }
}

impl DisplayMap {
    /// The recent map and index chunks listing exactly this map's shards.
    /// The map must pass [`DisplayMap::check_shape`].
    pub fn split(&self) -> Result<SplitMap, String> {
        self.check_shape()?;
        let archives = self.shards.iter().take_while(|shard| shard.sealed).count();
        let recent = self.shards.get(archives).cloned();
        let mut chunks: Vec<SplitChunk> = Vec::new();
        for (base, group) in group_by_chunk(&self.shards[..archives]) {
            chunks.push(SplitChunk::new(DisplayIndexChunk {
                schema: DISPLAY_SCHEMA.to_string(),
                base_shard_id: base,
                shards: group.to_vec(),
            }));
        }
        let recent = DisplayRecentMap {
            schema: self.schema.clone(),
            network: self.network.clone(),
            genesis_hash: self.genesis_hash.clone(),
            seal: self.seal,
            start_height: self.start_height,
            first_shard_id: self.first_shard_id,
            archives: archives as u64,
            unsealed_start: self.unsealed_start(),
            chunk_shards: INDEX_CHUNK_SHARDS,
            chunks: chunks
                .iter()
                .map(|chunk| DisplayChunkRef {
                    start_height: chunk.chunk.shards[0].start_height,
                    sha256: chunk.sha256.clone(),
                })
                .collect(),
            recent,
        };
        recent.check_shape()?;
        for (index, chunk) in chunks.iter().enumerate() {
            recent.check_chunk(index, &chunk.chunk)?;
        }
        let recent_bytes = recent.to_bytes();
        Ok(SplitMap {
            recent_sha256: hex::encode(Sha256::digest(&recent_bytes)),
            recent_bytes,
            recent,
            chunks,
        })
    }
}

/// Consecutive runs of `archives` sharing a chunk base.
fn group_by_chunk(archives: &[DisplayMapEntry]) -> Vec<(u64, &[DisplayMapEntry])> {
    let mut groups = Vec::new();
    let mut rest = archives;
    while let Some(first) = rest.first() {
        let base = chunk_base(first.shard_id);
        let len = rest
            .iter()
            .take_while(|shard| chunk_base(shard.shard_id) == base)
            .count();
        groups.push((base, &rest[..len]));
        rest = &rest[len..];
    }
    groups
}

impl DisplayRecentMap {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a recent display map serializes")
    }

    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(self.to_bytes()))
    }

    /// The base shard id of chunk `index`.
    pub fn chunk_base_id(&self, index: usize) -> u64 {
        chunk_base(self.first_shard_id) + index as u64 * INDEX_CHUNK_SHARDS
    }

    /// The ids chunk `index` must list: from its base, or the window's first
    /// shard, to the next base or the last archive.
    pub fn chunk_ids(&self, index: usize) -> std::ops::Range<u64> {
        let base = self.chunk_base_id(index);
        base.max(self.first_shard_id)
            ..(base + INDEX_CHUNK_SHARDS).min(self.first_shard_id + self.archives)
    }

    /// The origin-relative path of chunk `index`.
    pub fn chunk_path(&self, index: usize) -> String {
        format!(
            "/v2/txid/map/{}/{}",
            self.chunk_base_id(index),
            self.chunks[index].sha256
        )
    }

    /// The chunk holding the archive covering `height`, if an archive does:
    /// heights from the start up to [`Self::unsealed_start`]. The shape
    /// check makes chunks contiguous, so the archive is in the last chunk
    /// starting at or below `height`.
    pub fn chunk_for_height(&self, height: u64) -> Option<usize> {
        if height < self.start_height || height >= self.unsealed_start {
            return None;
        }
        self.chunks
            .partition_point(|chunk| chunk.start_height <= height)
            .checked_sub(1)
    }

    /// The last height the recent shard covers, when there is one.
    pub fn covered_through(&self) -> Option<u64> {
        self.recent.as_ref().map(|recent| recent.end_height)
    }

    /// Checks the recent map is well formed before anything is fetched.
    pub fn check_shape(&self) -> Result<(), String> {
        if self.schema != DISPLAY_SCHEMA {
            return Err(format!(
                "unsupported recent display map schema {:?}",
                self.schema
            ));
        }
        if self.chunk_shards != INDEX_CHUNK_SHARDS {
            return Err(format!("{} archives per index chunk", self.chunk_shards));
        }
        self.seal.check()?;
        if self.archives == 0 && self.recent.is_none() {
            return Err("display map is empty".into());
        }
        let expected = match self.archives {
            0 => 0,
            n => {
                let last = self
                    .first_shard_id
                    .checked_add(n - 1)
                    .ok_or("archive count")?;
                (chunk_base(last) - chunk_base(self.first_shard_id)) / INDEX_CHUNK_SHARDS + 1
            }
        };
        if self.chunks.len() as u64 != expected {
            return Err(format!(
                "{} index chunks for {} archives from shard {}",
                self.chunks.len(),
                self.archives,
                self.first_shard_id
            ));
        }
        for (index, chunk) in self.chunks.iter().enumerate() {
            if !is_digest(&chunk.sha256) {
                return Err(format!("index chunk {index} digest"));
            }
            let floor = match index.checked_sub(1) {
                None => self.start_height,
                // Every archive covers at least one block.
                Some(before) => {
                    let ids = self.chunk_ids(before);
                    self.chunks[before].start_height + (ids.end - ids.start)
                }
            };
            if (index == 0 && chunk.start_height != floor) || chunk.start_height < floor {
                return Err(format!("index chunk {index} start"));
            }
        }
        let floor = match self.chunks.len().checked_sub(1) {
            None => self.start_height,
            Some(last) => {
                let ids = self.chunk_ids(last);
                self.chunks[last].start_height + (ids.end - ids.start)
            }
        };
        let unsealed = self.unsealed_start;
        if (self.archives == 0 && unsealed != self.start_height) || unsealed < floor {
            return Err("display map sealed height".into());
        }
        if let Some(recent) = &self.recent {
            check_entry(&self.seal, recent)?;
            if recent.sealed || recent.shard_id != self.first_shard_id + self.archives {
                return Err("recent display shard id or seal".into());
            }
            check_recent(&self.seal, self.start_height, self.unsealed_start, recent)?;
        }
        Ok(())
    }

    /// Checks chunk `index` is the one this map names: its address, its ids,
    /// every entry sealed and well formed, the chain inside it, and its edges
    /// against the neighbouring chunk starts and the recent shard. The digest
    /// is the caller's to compare.
    pub fn check_chunk(&self, index: usize, chunk: &DisplayIndexChunk) -> Result<(), String> {
        let reference = self
            .chunks
            .get(index)
            .ok_or_else(|| format!("no index chunk {index}"))?;
        if chunk.schema != DISPLAY_SCHEMA || chunk.base_shard_id != self.chunk_base_id(index) {
            return Err(format!("index chunk {index} schema or address"));
        }
        let ids = self.chunk_ids(index);
        if chunk.shards.len() as u64 != ids.end - ids.start {
            return Err(format!("index chunk {index} length"));
        }
        for (position, (shard, id)) in chunk.shards.iter().zip(ids).enumerate() {
            if shard.shard_id != id || !shard.sealed {
                return Err(format!(
                    "index chunk {index} lists shard {} where sealed shard {id} belongs",
                    shard.shard_id
                ));
            }
            check_entry(&self.seal, shard)?;
            if let Some(previous) = position.checked_sub(1).map(|p| &chunk.shards[p]) {
                check_chain(previous, shard)?;
            }
        }
        let (first, last) = (&chunk.shards[0], &chunk.shards[chunk.shards.len() - 1]);
        if first.start_height != reference.start_height {
            return Err(format!("index chunk {index} start"));
        }
        let next_start = match self.chunks.get(index + 1) {
            Some(next) => next.start_height,
            None => self.unsealed_start,
        };
        if last.end_height + 1 != next_start {
            return Err(format!("index chunk {index} does not reach the next start"));
        }
        if let Some(recent) = &self.recent {
            for shard in &chunk.shards {
                check_recent_parent(shard, recent)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(shard_id: u64, start: u64, end: u64, sealed: bool) -> DisplayMapEntry {
        DisplayMapEntry {
            shard_id,
            start_height: start,
            end_height: end,
            parent_block_hash: format!("{:064x}", start - 1),
            terminal_block_hash: format!("{end:064x}"),
            geometry: "txid-2k8".into(),
            n_buckets: 1,
            directory_segments: vec![1],
            placement_seeds: vec![0],
            records: 50,
            min_bucket_records: 50,
            manifest_digest: format!("{:064x}", 1_000_000 + shard_id),
            revision: if sealed { 0 } else { 4 },
            sealed,
        }
    }

    /// Shards `first..first + archives` of ten blocks each from height 101,
    /// then the recent shard.
    fn map(first: u64, archives: u64) -> DisplayMap {
        let shards: Vec<DisplayMapEntry> = (0..=archives)
            .map(|i| {
                let start = 101 + i * 10;
                entry(first + i, start, start + 9, i < archives)
            })
            .collect();
        DisplayMap {
            schema: DISPLAY_SCHEMA.into(),
            network: "mainnet".into(),
            genesis_hash: "00".repeat(32),
            seal: DisplaySealParams {
                n_archive: 1,
                n_recent: 1,
                archive_target: 50,
                recent_window: 1,
                reorg_margin: 1,
            },
            start_height: 101,
            first_shard_id: first,
            shards,
        }
    }

    #[test]
    fn chunks_sit_on_absolute_bases_and_cover_every_archive() {
        for (first, archives, bases) in [
            (0, 0, vec![]),
            (0, 1, vec![0]),
            (0, 32, vec![0]),
            (0, 33, vec![0, 32]),
            (5, 27, vec![0]),
            (5, 28, vec![0, 32]),
            (30, 70, vec![0, 32, 64, 96]),
        ] {
            let full = map(first, archives);
            let split = full.split().unwrap();
            let recent = &split.recent;
            recent.check_shape().unwrap();
            assert_eq!(recent.archives, archives);
            let listed: Vec<u64> = split.chunks.iter().map(|c| c.chunk.base_shard_id).collect();
            assert_eq!(listed, bases, "{first} {archives}");
            let mut ids = Vec::new();
            for (index, chunk) in split.chunks.iter().enumerate() {
                assert_eq!(recent.chunks[index].sha256, chunk.sha256);
                assert_eq!(chunk.sha256, chunk.chunk.sha256());
                assert!(chunk.chunk.shards.len() as u64 <= INDEX_CHUNK_SHARDS);
                assert_eq!(
                    recent.chunk_path(index),
                    format!("/v2/txid/map/{}/{}", bases[index], chunk.sha256)
                );
                ids.extend(chunk.chunk.shards.iter().map(|s| s.shard_id));
            }
            assert_eq!(ids, (first..first + archives).collect::<Vec<_>>());
            assert_eq!(recent.recent.as_ref(), full.shards.last());
            assert_eq!(recent.sha256(), split.recent_sha256);
            // Every height lands where the full map puts it.
            for height in 90..120 + archives * 10 {
                let expected = full.shard_for_height(height);
                let actual = match recent.chunk_for_height(height) {
                    Some(index) => split.chunks[index].chunk.shard_for_height(height),
                    None => recent
                        .recent
                        .as_ref()
                        .filter(|r| (r.start_height..=r.end_height).contains(&height)),
                };
                assert_eq!(actual, expected, "{first} {archives} {height}");
            }
        }
    }

    #[test]
    fn a_seal_changes_only_the_newest_chunk_and_a_drop_only_the_oldest() {
        let before = map(0, 40).split().unwrap();
        let sealed = map(0, 41).split().unwrap();
        assert_eq!(before.chunks[0].sha256, sealed.chunks[0].sha256);
        assert_ne!(before.chunks[1].sha256, sealed.chunks[1].sha256);
        let mut dropped = map(0, 41);
        dropped.shards.remove(0);
        dropped.first_shard_id = 1;
        dropped.start_height = 111;
        let dropped = dropped.split().unwrap();
        assert_ne!(dropped.chunks[0].sha256, sealed.chunks[0].sha256);
        assert_eq!(dropped.chunks[1].sha256, sealed.chunks[1].sha256);
        assert_eq!(dropped.recent.chunk_ids(0), 1..32);
    }

    #[test]
    fn malformed_recent_maps_and_chunks_are_refused() {
        let split = map(3, 70).split().unwrap();
        assert_eq!(split.chunks.len(), 3);
        type Mutation = Box<dyn Fn(&mut DisplayRecentMap)>;
        let broken: Vec<Mutation> = vec![
            Box::new(|m| m.schema.push('x')),
            Box::new(|m| m.chunk_shards = 16),
            Box::new(|m| m.archives += 32),
            Box::new(|m| m.archives -= 10),
            Box::new(|m| {
                m.chunks.pop();
            }),
            Box::new(|m| m.chunks[1].sha256 = "AB".repeat(32)),
            Box::new(|m| m.chunks[0].start_height += 1),
            Box::new(|m| m.chunks[1].start_height = m.chunks[0].start_height),
            Box::new(|m| m.recent.as_mut().unwrap().sealed = true),
            Box::new(|m| m.recent.as_mut().unwrap().shard_id += 1),
            Box::new(|m| m.recent.as_mut().unwrap().n_buckets = 2),
            // Above the first unsealed height, below the start, or not
            // reaching above the archives.
            Box::new(|m| m.recent.as_mut().unwrap().start_height = 802),
            Box::new(|m| m.recent.as_mut().unwrap().start_height = 100),
            Box::new(|m| m.recent.as_mut().unwrap().end_height = 800),
            Box::new(|m| m.recent.as_mut().unwrap().placement_seeds.clear()),
            Box::new(|m| m.unsealed_start -= 701),
            Box::new(|m| m.seal.recent_window = 51),
            // Bucket counts with no divisor or past every table label, the
            // recent entry agreeing with them.
            Box::new(|m| {
                m.seal.n_recent = 0;
                let recent = m.recent.as_mut().unwrap();
                recent.n_buckets = 0;
                recent.directory_segments.clear();
            }),
            Box::new(|m| {
                m.seal.n_recent = crate::display::MAX_BUCKETS + 1;
                let recent = m.recent.as_mut().unwrap();
                recent.n_buckets = m.seal.n_recent;
                recent.directory_segments = vec![1; m.seal.n_recent as usize];
            }),
            Box::new(|m| m.seal.n_archive = 0),
            Box::new(|m| {
                m.archives = 0;
                m.chunks.clear();
                m.recent = None;
            }),
        ];
        for (index, mutate) in broken.into_iter().enumerate() {
            let mut changed = split.recent.clone();
            mutate(&mut changed);
            assert!(changed.check_shape().is_err(), "mutation {index}");
        }

        let recent = &split.recent;
        for (index, chunk) in split.chunks.iter().enumerate() {
            recent.check_chunk(index, &chunk.chunk).unwrap();
        }
        type ChunkMutation = Box<dyn Fn(&mut DisplayIndexChunk)>;
        let broken: Vec<ChunkMutation> = vec![
            Box::new(|c| c.schema.push('x')),
            Box::new(|c| c.base_shard_id += 32),
            Box::new(|c| {
                c.shards.pop();
            }),
            Box::new(|c| c.shards[0].shard_id += 1),
            Box::new(|c| c.shards[2].sealed = false),
            Box::new(|c| c.shards[2].revision = 1),
            Box::new(|c| c.shards[2].min_bucket_records = 1),
            Box::new(|c| c.shards[2].parent_block_hash = "99".repeat(32)),
            Box::new(|c| c.shards[0].start_height -= 1),
            Box::new(|c| {
                let last = c.shards.len() - 1;
                c.shards[last].end_height += 1;
            }),
        ];
        // The middle chunk and the last, which meets the recent shard.
        for index in [1, 2] {
            for (number, mutate) in broken.iter().enumerate() {
                let mut changed = split.chunks[index].chunk.clone();
                mutate(&mut changed);
                assert!(
                    recent.check_chunk(index, &changed).is_err(),
                    "chunk {index} mutation {number}"
                );
            }
        }
        // Only the last chunk's end meets a hash the map holds.
        let mut changed = split.chunks[2].chunk.clone();
        let last = changed.shards.len() - 1;
        changed.shards[last].terminal_block_hash = "99".repeat(32);
        assert!(recent.check_chunk(2, &changed).is_err());
        // A sealed height the last chunk does not reach.
        let mut beyond = recent.clone();
        beyond.unsealed_start += 1;
        beyond.check_shape().unwrap();
        assert!(beyond.check_chunk(2, &split.chunks[2].chunk).is_err());
        // A chunk served at another chunk's position.
        assert!(recent.check_chunk(0, &split.chunks[1].chunk).is_err());
        assert!(recent.check_chunk(9, &split.chunks[1].chunk).is_err());
    }

    #[test]
    fn a_malformed_full_map_does_not_split() {
        let mut full = map(0, 3);
        full.shards[1].parent_block_hash = "99".repeat(32);
        assert!(full.split().is_err());
        // No bucket at all, with entries agreeing.
        let mut empty = map(0, 3);
        empty.seal.n_archive = 0;
        for shard in empty.shards.iter_mut().filter(|shard| shard.sealed) {
            shard.n_buckets = 0;
            shard.directory_segments.clear();
        }
        assert!(empty.check_shape().is_err());
        let mut sealed_only = map(0, 3);
        sealed_only.shards.pop();
        let split = sealed_only.split().unwrap();
        assert!(split.recent.recent.is_none());
        assert_eq!(split.recent.covered_through(), None);
        assert_eq!(split.recent.chunk_for_height(130), Some(0));
        assert_eq!(split.recent.chunk_for_height(131), None);
    }

    /// A recent shard starting inside the newest archive: heights the
    /// archives hold are routed to their chunk, the rest to the recent shard.
    #[test]
    fn an_overlapping_recent_shard_routes_by_the_sealed_height() {
        let mut full = map(30, 40);
        let last = full.shards[39].clone();
        let recent = full.shards.last_mut().unwrap();
        recent.start_height = last.start_height + 4;
        recent.parent_block_hash = "99".repeat(32);
        let split = full.split().unwrap();
        let map = &split.recent;
        assert_eq!(map.unsealed_start, last.end_height + 1);
        for height in last.start_height..=last.end_height {
            let index = map.chunk_for_height(height).unwrap();
            let chunk = &split.chunks[index].chunk;
            assert_eq!(chunk.shard_for_height(height), Some(&last));
            map.check_chunk(index, chunk).unwrap();
        }
        assert_eq!(map.chunk_for_height(last.end_height + 1), None);
        assert_eq!(
            full.shard_for_height(last.end_height + 1),
            full.shards.last()
        );
        // Starting where the last archive starts, the parent is that
        // archive's parent; a wrong one is refused with that chunk.
        let mut full = map_at_archive_start(&last, "98".repeat(32));
        assert!(full.split().is_err());
        full.shards.last_mut().unwrap().parent_block_hash = last.parent_block_hash.clone();
        full.split().unwrap();
    }

    fn map_at_archive_start(last: &DisplayMapEntry, parent: String) -> DisplayMap {
        let mut full = map(30, 40);
        let recent = full.shards.last_mut().unwrap();
        recent.start_height = last.start_height;
        recent.parent_block_hash = parent;
        full
    }
}
