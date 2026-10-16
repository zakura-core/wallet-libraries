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
//! Both documents are derived from the full [`DisplayMap`](super::DisplayMap) by the publisher's split,
//! so the full map and the split never disagree. Their canonical encoding is
//! compact JSON in declaration order.

use super::manifest::{
    check_chain, check_entry, check_entry_structure, check_recent, check_recent_parent,
    find_by_height, is_digest,
};
use super::seal::DisplaySealParams;
use super::{DisplayMapEntry, DISPLAY_SCHEMA};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Archives per index chunk. Chunks start at absolute shard ids that are
/// multiples of this, so a chunk's address never moves.
pub const INDEX_CHUNK_SHARDS: u64 = 32;

/// The base shard id of the index chunk holding `shard_id`.
pub fn chunk_base(shard_id: u64) -> u64 {
    shard_id - shard_id % INDEX_CHUNK_SHARDS
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

impl DisplayRecentMap {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a recent display map serializes")
    }

    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(self.to_bytes()))
    }

    /// The base shard id of chunk `index`.
    /// Requires a map that passed [`Self::check_shape`] and an existing index.
    pub fn chunk_base_id(&self, index: usize) -> u64 {
        chunk_base(self.first_shard_id) + index as u64 * INDEX_CHUNK_SHARDS
    }

    /// The ids chunk `index` must list: from its base, or the window's first
    /// shard, to the next base or the last archive.
    /// Requires a map that passed [`Self::check_shape`] and an existing index.
    pub fn chunk_ids(&self, index: usize) -> std::ops::Range<u64> {
        let base = self.chunk_base_id(index);
        let end = self.first_shard_id + self.archives;
        // Bound the addition by the validated exclusive archive end before
        // adding: the final chunk's next absolute base may exceed u64::MAX.
        base.max(self.first_shard_id)..base + (end - base).min(INDEX_CHUNK_SHARDS)
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
        self.check_structure()?;
        if let Some(recent) = &self.recent {
            check_entry(&self.seal, recent)?;
        }
        Ok(())
    }

    /// Checks the known schema's ranges, identities, bounds and revision
    /// digests, without requiring a recognized recent geometry. Clients may
    /// then report a future geometry as unsupported, but must not query it.
    /// Unknown schemas and malformed fields are errors.
    pub fn check_structure(&self) -> Result<(), String> {
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
        let archive_end = self
            .first_shard_id
            .checked_add(self.archives)
            .ok_or("archive id range")?;
        let expected = match self.archives {
            0 => 0,
            _ => {
                let last = archive_end - 1;
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
                    self.chunks[before]
                        .start_height
                        .checked_add(ids.end - ids.start)
                        .ok_or("index chunk height range")?
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
                self.chunks[last]
                    .start_height
                    .checked_add(ids.end - ids.start)
                    .ok_or("index chunk height range")?
            }
        };
        let unsealed = self.unsealed_start;
        if (self.archives == 0 && unsealed != self.start_height) || unsealed < floor {
            return Err("display map sealed height".into());
        }
        if let Some(recent) = &self.recent {
            check_entry_structure(&self.seal, recent)?;
            if recent.sealed || recent.shard_id != archive_end {
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
        self.check_chunk_structure(index, chunk)?;
        for shard in &chunk.shards {
            check_entry(&self.seal, shard)?;
        }
        Ok(())
    }

    /// Checks every chunk identity, entry, range and chain link as
    /// [`Self::check_chunk`] does, while allowing unknown geometry names.
    /// Call only after [`Self::check_structure`]; the caller must still check
    /// canonical bytes and their digest, and recognize the selected entry's
    /// geometry before requesting its manifest, setup or table rows.
    pub fn check_chunk_structure(
        &self,
        index: usize,
        chunk: &DisplayIndexChunk,
    ) -> Result<(), String> {
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
            check_entry_structure(&self.seal, shard)?;
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
        if last.end_height.checked_add(1) != Some(next_start) {
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
