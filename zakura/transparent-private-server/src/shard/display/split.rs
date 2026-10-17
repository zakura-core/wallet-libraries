//! Splitting a display map into the recent map and index chunks the publisher
//! serves; the documents themselves are
//! [`zakura_transparent_private_shared::shard::display::split`].

use sha2::{Digest, Sha256};
use zakura_transparent_private_shared::shard::display::split::{
    chunk_base, DisplayChunkRef, DisplayIndexChunk, DisplayRecentMap, INDEX_CHUNK_SHARDS,
};
use zakura_transparent_private_shared::shard::display::{
    DisplayMap, DisplayMapEntry, DISPLAY_SCHEMA,
};

/// The recent map's file in a publication directory.
pub const RECENT_MAP_FILE: &str = "txid-map.json";

/// The file of the index chunk with this digest in a publication directory.
pub fn index_file(sha256: &str) -> String {
    format!("txid-index-{sha256}.json")
}

/// Splitting a [`DisplayMap`].
pub trait DisplayMapSplit {
    /// The recent map and index chunks listing exactly this map's shards.
    /// The map must pass [`DisplayMap::check_shape`].
    fn split(&self) -> Result<SplitMap, String>;
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

impl DisplayMapSplit for DisplayMap {
    fn split(&self) -> Result<SplitMap, String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_transparent_private_shared::shard::display::*;

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

    fn map_at_archive_start(last: &DisplayMapEntry, parent: String) -> DisplayMap {
        let mut full = map(30, 40);
        let recent = full.shards.last_mut().unwrap();
        recent.start_height = last.start_height;
        recent.parent_block_hash = parent;
        full
    }

    #[test]
    fn archive_id_and_chunk_limits_are_checked() {
        let template = map(0, 1).split().unwrap().recent;
        for (first, archives) in [(u64::MAX, 1), (u64::MAX - 1, 2), (u64::MAX - 31, 32)] {
            let mut invalid = template.clone();
            invalid.first_shard_id = first;
            invalid.archives = archives;
            invalid.recent = None;
            assert!(invalid.check_shape().is_err(), "{first} {archives}");
        }
        // The exclusive end is representable even though the final absolute
        // chunk boundary is not. Partial and crossing-chunk windows remain valid.
        for (first, archives) in [(u64::MAX - 1, 1), (u64::MAX - 31, 31), (u64::MAX - 32, 32)] {
            let mut valid = template.clone();
            valid.first_shard_id = first;
            valid.archives = archives;
            valid.recent = None;
            valid.unsealed_start = valid.start_height + archives;
            let count = (chunk_base(u64::MAX - 1) - chunk_base(first)) / INDEX_CHUNK_SHARDS + 1;
            valid.chunks = (0..count)
                .map(|index| DisplayChunkRef {
                    start_height: valid.start_height
                        + if index == 0 {
                            0
                        } else {
                            INDEX_CHUNK_SHARDS - first % INDEX_CHUNK_SHARDS
                        },
                    sha256: "aa".repeat(32),
                })
                .collect();
            valid.check_shape().unwrap();
            let ids: Vec<_> = (0..valid.chunks.len())
                .flat_map(|index| valid.chunk_ids(index))
                .collect();
            assert_eq!(ids, (first..u64::MAX).collect::<Vec<_>>());
        }
    }

    #[test]
    fn chunk_height_overflow_is_rejected() {
        let mut recent = map(0, 33).split().unwrap().recent;
        recent.start_height = u64::MAX - 1;
        recent.chunks[0].start_height = recent.start_height;
        assert!(recent.check_shape().is_err());
        let mut recent = map(0, 1).split().unwrap().recent;
        recent.start_height = u64::MAX;
        recent.chunks[0].start_height = u64::MAX;
        assert!(recent.check_shape().is_err());
    }

    #[test]
    fn chunk_chain_rejects_an_overflowing_predecessor_height() {
        let mut split = map(0, 2).split().unwrap();
        split.recent.recent = None;
        split.recent.check_shape().unwrap();
        let mut chunk = split.chunks[0].chunk.clone();
        chunk.shards[0].end_height = u64::MAX;
        assert!(split.recent.check_chunk(0, &chunk).is_err());
        // In a wrapping build, MAX + 1 would equal this hostile successor's
        // start. Matching block hashes must not allow that backwards chain.
        chunk.shards[1].start_height = 0;
        assert!(split.recent.check_chunk(0, &chunk).is_err());
    }

    #[test]
    fn chunk_terminal_height_overflow_is_rejected() {
        let split = map(0, 1).split().unwrap();
        let mut chunk = split.chunks[0].chunk.clone();
        chunk.shards[0].end_height = u64::MAX;
        assert!(split.recent.check_chunk(0, &chunk).is_err());
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
                m.seal.n_recent =
                    zakura_transparent_private_shared::shard::display::MAX_BUCKETS + 1;
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
}
