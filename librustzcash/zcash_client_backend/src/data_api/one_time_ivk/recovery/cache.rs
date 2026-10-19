//! Optional in-memory replay storage owned by the application. Entries retain the
//! predecessor trees as well as compact bytes, and never keep more than three blocks.
use crate::{
    data_api::{chain::ChainState, transparent_ledger::ChainPoint},
    proto::compact_formats::CompactBlock,
};
use prost::Message;
use std::{io, mem::size_of};
use zcash_primitives::{
    block::BlockHash,
    merkle_tree::{read_frontier_v1, write_frontier_v1},
};
use zcash_protocol::consensus::BlockHeight;

/// Hard ceiling for retained serialized blocks, tree context and cache bookkeeping.
pub const MAX_CACHE_BYTES: usize = 16 * 1024 * 1024;

/// Compact bytes and predecessor trees needed for one local replay. Constructed only
/// from data already scanned by the wallet, not from a filter response.
struct Entry {
    point: ChainPoint,
    parent: BlockHash,
    block: Box<[u8]>,
    trees: Box<[u8]>,
}

/// A wallet/network's shared three-block cache. All accounts use the same instance.
/// It has no persistence, network fetch or eviction pinning. Applications discard it
/// when discovery is disabled and call `rewind` when their connected chain rewinds.
pub struct RecentBlocks {
    entries: [Option<Entry>; 3],
    latest: Option<BlockHeight>,
    limit: usize,
}

/// Decoded transient replay input. The caller processes one entry at a time and drops
/// it after scanning. It must not accumulate replay copies in a pending work queue.
pub struct ReplayBlock {
    pub block: CompactBlock,
    pub predecessor: ChainState,
}

impl crate::data_api::chain::BlockSource for ReplayBlock {
    type Error = std::convert::Infallible;

    /// Replays only this immutable local block through the ordinary multi-pass scanner.
    fn with_blocks<F, E>(
        &self,
        from: Option<BlockHeight>,
        limit: Option<usize>,
        mut visit: F,
    ) -> Result<(), crate::data_api::chain::error::Error<E, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), crate::data_api::chain::error::Error<E, Self::Error>>,
    {
        if limit != Some(0) && from.is_none_or(|from| from == self.block.height()) {
            visit(self.block.clone())?;
        }
        Ok(())
    }
}

impl RecentBlocks {
    /// Starts empty, with a caller budget capped at the hard ceiling. A budget smaller
    /// than the cache's fixed bookkeeping makes every insertion a cache miss.
    pub fn new(byte_budget: usize) -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
            latest: None,
            limit: byte_budget.min(MAX_CACHE_BYTES),
        }
    }

    /// Reports retained bytes, including exact boxed payload lengths and fixed metadata.
    pub fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            + self
                .entries
                .iter()
                .flatten()
                .map(|e| e.block.len() + e.trees.len())
                .sum::<usize>()
    }

    /// Returns retained identities in oldest-first order for scheduling and diagnostics.
    pub fn blocks(&self) -> impl Iterator<Item = ChainPoint> + '_ {
        self.entries.iter().flatten().map(|e| e.point)
    }

    /// Clears only the optimization, leaving the wallet's durable discovery work intact.
    pub fn clear(&mut self) {
        self.entries = std::array::from_fn(|_| None);
        self.latest = None;
    }

    /// Removes forked entries without discarding valid entries below the common ancestor.
    pub fn rewind(&mut self, ancestor: BlockHeight) {
        for entry in &mut self.entries {
            if entry.as_ref().is_some_and(|e| e.point.height > ancestor) {
                *entry = None;
            }
        }
        self.latest = self.latest.map(|h| h.min(ancestor));
        self.compact();
    }

    /// Retains a newly scanned block only with matching predecessor context. Height or
    /// byte eviction never waits for a filter. Even an oversized block advances the
    /// three-height retention window. Older historical rescans cannot enlarge it.
    pub fn insert(&mut self, block: &CompactBlock, prior: &ChainState) -> io::Result<bool> {
        let height = u32::try_from(block.height)
            .map(BlockHeight::from)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "cache block height"))?;
        if block.hash.len() != 32
            || block.prev_hash.len() != 32
            || u64::from(u32::from(prior.block_height())) + 1 != block.height
            || block.prev_hash() != prior.block_hash()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cache predecessor mismatch",
            ));
        }
        if self.latest.is_some_and(|latest| height < latest) {
            return Ok(false);
        }
        let point = ChainPoint {
            height,
            hash: block.hash(),
        };
        self.latest = Some(height);
        for entry in &mut self.entries {
            if entry.as_ref().is_some_and(|e| {
                u64::from(u32::from(e.point.height)) + 3 <= block.height || e.point.height == height
            }) {
                *entry = None;
            }
        }
        self.compact();
        let mut trees = Vec::new();
        write_frontier_v1(&mut trees, prior.final_sapling_tree())?;
        write_frontier_v1(&mut trees, prior.final_orchard_tree())?;
        write_frontier_v1(&mut trees, prior.final_ironwood_tree())?;
        let payload = block
            .encoded_len()
            .checked_add(trees.len())
            .and_then(|n| n.checked_add(size_of::<Self>()));
        if payload.is_none_or(|bytes| bytes > self.limit) {
            return Ok(false);
        }
        let entry = Entry {
            point,
            parent: prior.block_hash(),
            block: block.encode_to_vec().into_boxed_slice(),
            trees: trees.into_boxed_slice(),
        };
        while self.entries.iter().all(Option::is_some)
            || self.retained_bytes() + entry.block.len() + entry.trees.len() > self.limit
        {
            self.entries[0] = None;
            self.compact();
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|e| e.is_none())
            .expect("evicted room");
        *slot = Some(entry);
        Ok(true)
    }

    /// Decodes only an exact canonical match. Missing context, eviction and restart
    /// return a miss so callers leave work due for PIR instead of refetching this block.
    pub fn get(&self, point: ChainPoint) -> io::Result<Option<ReplayBlock>> {
        let Some(entry) = self.entries.iter().flatten().find(|e| e.point == point) else {
            return Ok(None);
        };
        let block = CompactBlock::decode(entry.block.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut bytes = entry.trees.as_ref();
        let sapling = read_frontier_v1(&mut bytes)?;
        let orchard = read_frontier_v1(&mut bytes)?;
        let ironwood = read_frontier_v1(&mut bytes)?;
        if !bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing cache context",
            ));
        }
        let predecessor =
            ChainState::new(point.height - 1, entry.parent, sapling, orchard, ironwood);
        Ok(Some(ReplayBlock { block, predecessor }))
    }

    /// Keeps populated entries in height order without allocating an auxiliary buffer.
    fn compact(&mut self) {
        self.entries.sort_by_key(|entry| {
            entry
                .as_ref()
                .map(|e| u64::from(u32::from(e.point.height)))
                .unwrap_or(u64::MAX)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A compact block with a matching empty predecessor and controllable payload size.
    fn fixture(height: u32, payload: usize) -> (CompactBlock, ChainState) {
        let parent = BlockHash([(height - 1) as u8; 32]);
        let block = CompactBlock {
            height: u64::from(height),
            hash: vec![height as u8; 32],
            prev_hash: parent.0.to_vec(),
            vtx: vec![crate::proto::compact_formats::CompactTx {
                txid: vec![1; 32],
                vout: vec![crate::proto::compact_formats::TxOut {
                    value: 0,
                    script_pub_key: vec![0; payload],
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        (
            block,
            ChainState::empty(BlockHeight::from(height - 1), parent),
        )
    }
    /// Five rapidly scanned blocks retain only the latest three, independent of filter timing.
    #[test]
    fn oldest_retained_and_first_evicted_are_exact() {
        let mut cache = RecentBlocks::new(MAX_CACHE_BYTES);
        for height in 101..=105 {
            let (block, prior) = fixture(height, 0);
            assert!(cache.insert(&block, &prior).unwrap());
        }
        assert_eq!(
            cache
                .blocks()
                .map(|b| u32::from(b.height))
                .collect::<Vec<_>>(),
            [103, 104, 105]
        );
        assert!(
            cache
                .get(ChainPoint {
                    height: 102.into(),
                    hash: BlockHash([102; 32])
                })
                .unwrap()
                .is_none()
        );
        let recovered = cache
            .get(ChainPoint {
                height: 103.into(),
                hash: BlockHash([103; 32]),
            })
            .unwrap()
            .unwrap();
        assert_eq!((recovered.block, recovered.predecessor), fixture(103, 0));
        assert!(
            cache
                .get(ChainPoint {
                    height: 103.into(),
                    hash: BlockHash([0; 32])
                })
                .unwrap()
                .is_none()
        );
        cache.clear();
        assert_eq!(cache.blocks().count(), 0);
    }
    /// Replay preserves all three pool frontiers, including nontrivial sibling paths.
    #[test]
    fn cached_replay_restores_nonempty_predecessor_trees() {
        use incrementalmerkletree::{Hashable, frontier::Frontier};
        let (block, empty) = fixture(10, 0);
        let mut sapling = Frontier::empty();
        let mut orchard = Frontier::empty();
        let mut ironwood = Frontier::empty();
        for _ in 0..17 {
            assert!(sapling.append(sapling::Node::empty_leaf()));
        }
        for _ in 0..9 {
            assert!(orchard.append(orchard::tree::MerkleHashOrchard::empty_leaf()));
        }
        for _ in 0..31 {
            assert!(ironwood.append(orchard::tree::MerkleHashOrchard::empty_leaf()));
        }
        let prior = ChainState::new(
            empty.block_height(),
            empty.block_hash(),
            sapling,
            orchard,
            ironwood,
        );
        let mut cache = RecentBlocks::new(MAX_CACHE_BYTES);
        assert!(cache.insert(&block, &prior).unwrap());
        let replay = cache
            .get(ChainPoint {
                height: 10.into(),
                hash: block.hash(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(replay.predecessor, prior);
        assert_eq!(replay.block, block);
        assert!(cache.retained_bytes() <= MAX_CACHE_BYTES);
    }

    /// Byte eviction accounts for actual compact encoding and all predecessor tree bytes.
    #[test]
    fn byte_budget_can_evict_before_three_blocks() {
        let mut cache = RecentBlocks::new(4096);
        for height in 1..=3 {
            let (block, prior) = fixture(height, 1800);
            assert!(cache.insert(&block, &prior).unwrap());
            assert!(cache.retained_bytes() <= 4096);
        }
        assert!(cache.blocks().count() < 3);
        let (huge, prior) = fixture(4, 5000);
        assert!(!cache.insert(&huge, &prior).unwrap());
        assert!(cache.blocks().all(|point| u32::from(point.height) >= 2));
        assert!(cache.retained_bytes() <= 4096);
        let mut tiny = RecentBlocks::new(0);
        let (block, prior) = fixture(1, 0);
        assert!(!tiny.insert(&block, &prior).unwrap());
    }
    /// Rewinds remove only the fork suffix, and stale scan batches cannot repin older history.
    #[test]
    fn fork_and_old_batch_do_not_expand_retention() {
        let mut cache = RecentBlocks::new(MAX_CACHE_BYTES);
        for height in 1..=4 {
            let (block, prior) = fixture(height, 0);
            cache.insert(&block, &prior).unwrap();
        }
        let (old, prior) = fixture(1, 0);
        assert!(!cache.insert(&old, &prior).unwrap());
        cache.rewind(3.into());
        assert_eq!(
            cache
                .blocks()
                .map(|b| u32::from(b.height))
                .collect::<Vec<_>>(),
            [2, 3]
        );
        let (mut replacement, prior) = fixture(4, 0);
        replacement.hash = vec![99; 32];
        assert!(cache.insert(&replacement, &prior).unwrap());
        assert!(
            cache
                .get(ChainPoint {
                    height: 4.into(),
                    hash: BlockHash([4; 32])
                })
                .unwrap()
                .is_none()
        );
        let (block, _) = fixture(5, 0);
        let invalid = ChainState::empty(4.into(), BlockHash([0; 32]));
        assert!(cache.insert(&block, &invalid).is_err());
    }
}
