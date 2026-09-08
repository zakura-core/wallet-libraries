//! Binding a published shard set to the chain this wallet accepted.
//!
//! A shard names two block hashes: the block before its first height, and the
//! block at its last. A recovered event names a height and no hash at all —
//! deliberately, because an event carrying a server-supplied block hash could
//! be placed on a branch the wallet never accepted, and there would be nothing
//! in the event to notice it with.
//!
//! The snapshot includes the fixed accepted target, published endpoints and
//! every anchor retained by coverage or pending pages. Missing hashes remain
//! unknown. Publication refresh cannot advance this snapshot's target.

use std::collections::BTreeMap;

use transparent_filter::{BlockHash, ShardMap};
use transparent_wallet::{Acceptance, Anchor, ChainView};
use zakura_wallet_store::WalletDb;
use zcash_protocol::consensus::BlockHeight;

use crate::Error;

/// The wallet's view of the chain, for checking a shard map against.
pub trait AcceptedBlocks {
    /// The hash the wallet accepted at `height`, if it has scanned it.
    fn accepted(&self, height: u64) -> Result<Option<[u8; 32]>, Error>;
}

impl AcceptedBlocks for WalletDb {
    fn accepted(&self, height: u64) -> Result<Option<[u8; 32]>, Error> {
        let Ok(height) = u32::try_from(height) else {
            return Ok(None);
        };
        Ok(self
            .accepted_block_hash(BlockHeight::from_u32(height))?
            .map(|hash| hash.0))
    }
}

/// The wallet's accepted chain at the heights one sync will ask about.
///
/// A snapshot rather than a live view, because the sync holds the wallet as
/// its store for the whole run and a second borrow of it is not available. The
/// heights are knowable in advance: every shard boundary in the map, every
/// block the ledger's coverage rests on, and the anchor. Anything else is
/// `Unknown`, which the library turns into an incomplete sync rather than a
/// guess.
#[derive(Debug, Clone)]
pub struct ChainSnapshot {
    hashes: BTreeMap<u64, String>,
    target: Anchor,
}

impl ChainSnapshot {
    /// Reads the wallet's hashes at every height `map` and the ledger name.
    fn load(db: &WalletDb, map: &ShardMap, target: &Anchor) -> Result<Self, Error> {
        let mut heights: Vec<u64> = Vec::new();
        for shard in &map.shards {
            heights.push(shard.start_height.saturating_sub(1));
            heights.push(shard.end_height);
        }
        for (height, _) in db.transparent_coverage_terminals()? {
            heights.push(u64::from(u32::from(height)));
        }
        if let Some(anchor) = db.transparent_anchor()? {
            heights.push(u64::from(u32::from(anchor.height)));
        }
        let mut hashes = BTreeMap::new();
        for height in heights {
            if let Some(bytes) = db.accepted(height)? {
                hashes.insert(
                    height,
                    BlockHash::from_internal_bytes(bytes).to_display_hex(),
                );
            }
        }
        Ok(Self {
            hashes,
            target: target.clone(),
        })
    }

    /// Binds one run to an explicit wallet-accepted target, independently of publication.
    pub fn load_at(db: &WalletDb, map: &ShardMap, target: &Anchor) -> Result<Self, Error> {
        let mut snapshot = Self::load(db, map, target)?;
        let mut anchors = vec![target.clone()];
        for range in db
            .transparent_scripts()?
            .iter()
            .map(|s| db.transparent_coverage_of(&s.script))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
        {
            if let Some(anchor) = range.source_anchor {
                anchors.push(Anchor {
                    height: u64::from(u32::from(anchor.height)),
                    hash: anchor.hash,
                });
            }
        }
        for pending in db.transparent_pending()? {
            if let Some(anchor) = pending.target_anchor {
                anchors.push(Anchor {
                    height: u64::from(u32::from(anchor.height)),
                    hash: anchor.hash,
                });
            }
        }
        for anchor in anchors {
            if let Some(bytes) = db.accepted(anchor.height)? {
                snapshot.hashes.insert(
                    anchor.height,
                    BlockHash::from_internal_bytes(bytes).to_display_hex(),
                );
            }
        }
        snapshot.target = target.clone();
        Ok(snapshot)
    }

    /// The heights the snapshot can answer for.
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Whether the snapshot can answer for nothing at all.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }
}

impl ChainView for ChainSnapshot {
    fn is_accepted(&self, height: u64, hash: &str) -> Acceptance {
        match self.hashes.get(&height) {
            Some(known) if known == hash => Acceptance::Accepted,
            Some(_) => Acceptance::Rejected,
            None => Acceptance::Unknown,
        }
    }

    fn tip(&self) -> Option<Anchor> {
        Some(self.target.clone())
    }
}
