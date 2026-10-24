//! Settled shard descriptors a wallet keeps between inventory captures.
use super::{
    Hash,
    inventory::{CHUNK_SHARDS, Head, Inventory, Shard},
    session::Error,
};
use serde::{Deserialize, Serialize};

/// The format of a saved descriptor cache (see [`DescriptorCache`]).
const CACHE_FORMAT: &str = "ironwood-receiver-inventory-cache-v1";

/// Settled shard descriptors (see [`Shard::settled`]) saved between captures, bound to the
/// network, inventory protocol and correction generation they were verified under. A
/// capture reuses them only for whole chunks, and only the complete inventory's identity
/// proves them current: a descriptor a reorg replaced fails that check, so the capture
/// downloads every chunk again and replaces the cache.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DescriptorCache {
    format: String,
    protocol: String,
    genesis: Hash,
    history_revision: u64,
    /// Ordered by index.
    shards: Vec<Shard>,
}

impl DescriptorCache {
    /// The settled shards of a verified inventory.
    pub(crate) fn of(inventory: &Inventory) -> Self {
        let head = inventory.head();
        Self {
            format: CACHE_FORMAT.into(),
            protocol: head.protocol.clone(),
            genesis: head.genesis,
            history_revision: head.history_revision,
            shards: inventory
                .shards()
                .iter()
                .filter(|shard| shard.settled())
                .cloned()
                .collect(),
        }
    }

    /// The saved form.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parses `bytes` for `head`'s inventory: `None` when they do not parse, or were saved
    /// in another format or under another protocol, network or correction generation.
    pub(crate) fn decode(bytes: &[u8], head: &Head) -> Option<Self> {
        let cache: Self = serde_json::from_slice(bytes).ok()?;
        (cache.format == CACHE_FORMAT
            && cache.protocol == head.protocol
            && cache.genesis == head.genesis
            && cache.history_revision == head.history_revision
            && cache.shards.windows(2).all(|w| w[0].index < w[1].index))
        .then_some(cache)
    }

    /// The cached shards of chunk `index` of `head`'s inventory, if every one is cached.
    pub(crate) fn chunk(&self, head: &Head, index: u32) -> Option<Vec<Shard>> {
        let start = index.checked_mul(CHUNK_SHARDS as u32)?;
        let end = start.checked_add(CHUNK_SHARDS as u32)?.min(head.shards);
        let first = self.shards.binary_search_by_key(&start, |s| s.index).ok()?;
        let shards = self
            .shards
            .get(first..first + (end.checked_sub(start)? as usize))?;
        (shards.last()?.index == end - 1).then(|| shards.to_vec())
    }
}
