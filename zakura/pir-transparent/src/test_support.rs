//! Transports for unit tests that count every call and serve as little as a
//! check needs, so a test can assert what a refusal sent before it stopped.

use std::cell::Cell;

use transparent_wallet::client::Table;
use transparent_wallet::transport::{BoxError, FilterSource, ShardTransport};

/// A mainnet shard map with two shards, a sealed one and the tail.
pub(crate) const MAP: &[u8] = include_bytes!("../tests/fixtures/shard-map.json");

/// A public filter source that counts every call and serves only a shard map,
/// the fixture's by default.
pub(crate) struct CountingFilters {
    pub(crate) map: Vec<u8>,
    pub(crate) parents: bool,
    pub(crate) parent_checks: Cell<usize>,
    pub(crate) maps: usize,
    pub(crate) filters: usize,
}
impl Default for CountingFilters {
    fn default() -> Self {
        Self::serving(MAP.to_vec())
    }
}
impl CountingFilters {
    pub(crate) fn serving(map: Vec<u8>) -> Self {
        Self {
            map,
            parents: false,
            parent_checks: Cell::new(0),
            maps: 0,
            filters: 0,
        }
    }
    pub(crate) fn calls(&self) -> usize {
        self.parent_checks.get() + self.maps + self.filters
    }
}
impl FilterSource for CountingFilters {
    fn uses_parents(&self) -> bool {
        self.parent_checks.set(self.parent_checks.get() + 1);
        self.parents
    }
    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.maps += 1;
        Ok((self.map.clone(), self.map.len() as u64))
    }
    fn filter(&mut self, _shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        self.filters += 1;
        Err("the counting source serves no filters".into())
    }
}

/// A private shard transport that counts every call and serves only an init.
#[derive(Default)]
pub(crate) struct CountingShards {
    pub(crate) schema: &'static str,
    pub(crate) inits: usize,
    pub(crate) manifests: usize,
    pub(crate) setups: usize,
    pub(crate) queries: usize,
}
impl CountingShards {
    pub(crate) fn serving(schema: &'static str) -> Self {
        Self {
            schema,
            ..Default::default()
        }
    }
    pub(crate) fn calls(&self) -> usize {
        self.inits + self.manifests + self.setups + self.queries
    }
}
impl ShardTransport for CountingShards {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.inits += 1;
        let init = serde_json::to_vec(&serde_json::json!({
            "schema": self.schema,
            "geometries": [],
        }))?;
        let cost = init.len() as u64;
        Ok((init, cost))
    }
    fn manifest(&mut self, _shard_id: u64, _revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        self.manifests += 1;
        Err("the counting transport serves no manifests".into())
    }
    fn setup(
        &mut self,
        _shard_id: u64,
        _revision: &str,
        _table: Table,
        _segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        self.setups += 1;
        Err("the counting transport serves no setup".into())
    }
    fn query(
        &mut self,
        _shard_id: u64,
        _revision: &str,
        _table: Table,
        _body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        self.queries += 1;
        Err("the counting transport answers no queries".into())
    }
}
