//! Isolated opt-in traversal. All invalid/missing parent evidence falls back to
//! ordinary child retrieval; only a fully validated negative can skip a child.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use transparent_filter::{
    experimental_parent::{Manifest, SCHEMA},
    ShardMap, ValidatedFilter,
};

// WalletStore filter caches may key by revision alone: every artifact gets
// its own revision key, as well as a checked content digest.
pub(super) struct ParentExperiment {
    url: String,
    geometry: String,
    manifest: Option<Manifest>,
    attempted: bool,
    eligible: BTreeSet<String>,
    decoded: BTreeMap<String, ValidatedFilter>,
    failed: BTreeSet<String>,
}
impl ParentExperiment {
    pub fn new(url: String, geometry: String) -> Self {
        Self {
            url,
            geometry,
            manifest: None,
            attempted: false,
            eligible: BTreeSet::new(),
            decoded: BTreeMap::new(),
            failed: BTreeSet::new(),
        }
    }
    fn fetch(
        source: &HttpFilterSource,
        url: &str,
        stage: &'static str,
    ) -> Result<Vec<u8>, BoxError> {
        execute(
            source.client.get(url),
            stage,
            0,
            None,
            &source.observer,
            source.retry,
        )
    }
    pub fn prepare(
        &mut self,
        source: &HttpFilterSource,
        map: &ShardMap,
        uncached: &[u64],
        store: &mut dyn crate::WalletStore,
    ) -> Result<u64, BoxError> {
        self.eligible.clear();
        if !map.shards.iter().any(|c| {
            c.sealed
                && (self.geometry == "both" || c.geometry == self.geometry)
                && uncached.contains(&c.shard_id)
        }) {
            return Ok(0);
        }
        let mut cost = 0;
        if !self.attempted {
            self.attempted = true;
            let cache_key = transparent_filter::experimental_parent::sha(
                format!(
                    "{}:{}",
                    self.url,
                    transparent_filter::experimental_parent::sha(&serde_json::to_vec(map)?)
                )
                .as_bytes(),
            );
            let cached = store.filter(&format!("parent-manifest-v1:{cache_key}"), &cache_key)?;
            let bytes = if let Some(bytes) = cached {
                Some(bytes)
            } else {
                Self::fetch(source, &self.url, "parent_manifest")
                    .ok()
                    .inspect(|b| cost = b.len() as u64)
            };
            if let Some(bytes) = bytes {
                if bytes.len() <= 2 * 1024 * 1024 {
                    self.manifest = serde_json::from_slice(&bytes).ok();
                    if self.manifest.as_ref().is_some_and(|m| {
                        m.schema == SCHEMA && m.parents.iter().all(|p| p.agrees(map))
                    }) {
                        store.put_filter(
                            &format!("parent-manifest-v1:{cache_key}"),
                            &cache_key,
                            true,
                            &bytes,
                        )?;
                    }
                }
            }
        }
        let Some(m) = &self.manifest else {
            return Ok(cost);
        };
        if m.schema != SCHEMA {
            self.manifest = None;
            return Ok(cost);
        }
        let mut seen = BTreeSet::new();
        if m.parents.iter().any(|p| {
            !p.agrees(map)
                || p.children.iter().any(|c| {
                    (self.geometry != "both" && c.geometry != self.geometry)
                        || !seen.insert(c.shard_id)
                })
        }) {
            self.manifest = None;
            return Ok(cost);
        }
        let sizes: BTreeMap<_, _> = m.child_bytes.iter().cloned().collect();
        for p in &m.parents {
            let relevant: Vec<_> = p
                .children
                .iter()
                .filter(|c| uncached.contains(&c.shard_id))
                .collect();
            let Some(total) = relevant.iter().try_fold(0u64, |sum, c| {
                sum.checked_add(*sizes.get(&c.manifest_digest)?)
            }) else {
                continue;
            };
            if p.bytes < total
                && p.bytes <= transparent_filter::experimental_parent::LIMITS.max_bytes as u64
            {
                self.eligible.insert(p.filter_hash.clone());
            }
        }
        Ok(cost)
    }
    pub fn negative(
        &mut self,
        source: &HttpFilterSource,
        map: &ShardMap,
        id: u64,
        scripts: &[Vec<u8>],
        store: &mut dyn crate::WalletStore,
    ) -> Result<(bool, u64), BoxError> {
        let Some(p) = self
            .manifest
            .as_ref()
            .and_then(|m| {
                m.parents
                    .iter()
                    .find(|p| p.children.iter().any(|c| c.shard_id == id))
            })
            .cloned()
        else {
            return Ok((false, 0));
        };
        if !p.agrees(map) || self.failed.contains(&p.filter_hash) {
            return Ok((false, 0));
        }
        // Identical bytes can decode differently under different precisions.
        let decoded_key = format!("{}:{}:{}", p.filter_hash, p.m, p.p);
        if !self.eligible.contains(&p.filter_hash)
            && !self.decoded.contains_key(&decoded_key)
            && store
                .filter(&format!("{SCHEMA}:{}", p.filter_hash), &p.filter_hash)?
                .is_none()
        {
            return Ok((false, 0));
        }
        let mut cost = 0;
        if !self.decoded.contains_key(&decoded_key) {
            let cached = store.filter(&format!("{SCHEMA}:{}", p.filter_hash), &p.filter_hash)?;
            let bytes = if let Some(bytes) = cached {
                bytes
            } else {
                if p.filter_hash.len() != 64
                    || !p.filter_hash.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Ok((false, 0));
                }
                let Some((root, _)) = self.url.rsplit_once('/') else {
                    return Ok((false, 0));
                };
                match Self::fetch(
                    source,
                    &format!("{root}/artifacts/{}.bin", p.filter_hash),
                    "parent_filters",
                ) {
                    Ok(bytes) => {
                        cost = bytes.len() as u64;
                        bytes
                    }
                    Err(_) => {
                        self.failed.insert(p.filter_hash.clone());
                        return Ok((false, 0));
                    }
                }
            };
            match p.validate(&bytes) {
                Ok(v) => {
                    store.put_filter(
                        &format!("{SCHEMA}:{}", p.filter_hash),
                        &p.filter_hash,
                        true,
                        &bytes,
                    )?;
                    self.decoded.insert(decoded_key.clone(), v);
                }
                Err(_) => {
                    self.failed.insert(p.filter_hash.clone());
                    return Ok((false, cost));
                }
            }
        }
        let decoded = &self.decoded[&decoded_key];
        if decoded.element_count() as u64 != p.elements || decoded.bytes().len() as u64 != p.bytes {
            return Ok((false, cost));
        }
        let matched = p.matches(decoded, scripts)?;
        Ok((!matched, cost))
    }
}
