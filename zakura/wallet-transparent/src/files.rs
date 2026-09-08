//! Reading a published shard set from a directory.
//!
//! What `shard-publish` writes: one directory per shard, named by its manifest
//! digest, holding `manifest.json`, `filter.bin` and the private tables. This
//! reads the public half of that.
//!
//! It is a local file reader. It is evidence about the arithmetic — the same
//! ledger, from the same shards, without a network in the way — and evidence
//! about nothing else. In particular it says nothing about any transport's
//! behaviour or privacy.

use std::collections::BTreeMap;
use std::path::Path;

use transparent_shard::ShardManifest;
use transparent_wallet::transport::{BoxError, FilterSource};

/// A published shard set on disk.
pub struct PublishedFilters {
    filters: BTreeMap<u64, Vec<u8>>,
    map: Vec<u8>,
}

impl PublishedFilters {
    /// Loads every shard's filter from `dir`, with `map` as the shard map.
    ///
    /// The map is supplied rather than read from the directory because it is
    /// the publisher's statement about the set as a whole, and the wallet
    /// checks each filter against it.
    pub fn load(dir: &Path, map: &transparent_filter::ShardMap) -> Result<Self, BoxError> {
        let mut filters = BTreeMap::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if !path.is_dir() {
                continue;
            }
            let manifest: ShardManifest = serde_json::from_slice(&std::fs::read(
                path.join("manifest.json"),
            )?)?;
            filters.insert(manifest.shard_id, std::fs::read(path.join("filter.bin"))?);
        }
        Ok(Self {
            filters,
            map: serde_json::to_vec(map)?,
        })
    }
}

impl FilterSource for PublishedFilters {
    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        Ok((self.map.clone(), self.map.len() as u64))
    }

    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        let bytes = self
            .filters
            .get(&shard_id)
            .ok_or_else(|| format!("the published set has no shard {shard_id}"))?
            .clone();
        let len = bytes.len() as u64;
        Ok((bytes, len))
    }
}
