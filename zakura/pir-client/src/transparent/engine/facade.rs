//! A boundary a wallet application can bind to.
//!
//! Everything a host needs in plain data: a store path, two base URLs, the
//! wallet's scripts with their required heights, the block hashes the host
//! accepts, work limits. No callbacks cross this boundary and nothing here has
//! a lifetime or a generic, so a binding generator (flutter_rust_bridge for
//! the first integration, UniFFI for another) can take it as it is. The
//! host's own rules stay the host's: gap-limit advance is "call `sync_once`
//! again with the scripts you now have", and the chain view is the list of
//! headers the host has accepted.
//!
//! What this establishes is the [contract](../../docs/contract.md)'s
//! trusted-indexer profile, not more. A host must not present the balance as
//! synchronized while `completion` is not `complete` or `unresolved` is
//! nonzero, and should run this beside its existing sync until it accepts
//! that profile.

use crate::transparent::engine::adapters::{Acceptance, ChainView, ScriptProvider};
use crate::transparent::engine::ledger::{
    ConfirmedSpend, TransactionSummary, UnresolvedSpend, Utxo,
};
use crate::transparent::engine::store::{Anchor, ScriptEntry, WalletStore};
use crate::transparent::engine::sync::{
    Completion, FailedEntry, IncompleteReason, ServiceGeometry, WorkLimits, sync_into_tracking,
};
use crate::transparent::engine::transport::{FilterSource, ShardTransport};
use std::collections::BTreeMap;
use zakura_pir_protocol::transparent::filter::ShardMap;

/// What a host passes to one sync call.
#[derive(Clone, Debug, Default)]
pub struct SyncRequest {
    pub target_anchor: Anchor,
    /// Every script the host is responsible for right now.
    pub scripts: Vec<ScriptEntry>,
    /// Block hashes the host's chain accepts, by height. Coverage resting on a
    /// height listed here with another hash is rolled back; a height not
    /// listed is unknown and leaves the sync incomplete rather than guessed.
    pub accepted_headers: Vec<(u64, String)>,
    pub limits: WorkLimits,
}

/// The host-facing state after a call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncStatus {
    pub anchor: Option<Anchor>,
    pub settled_through: u64,
    pub covered_through: u64,
    /// Pending page retrievals left in the store.
    pub pending: usize,
    /// Spends whose receive the ledger has never seen.
    pub unresolved: usize,
    /// Confirmed, not spendable.
    pub confirmed_balance: u64,
    /// `complete`, or the reason the sync stopped short.
    pub completion: String,
    pub rolled_back_to: Option<u64>,
    pub scripts_added: usize,
    pub map_refreshes: u32,
    /// Directory entries whose replies failed on content, with the failure
    /// count each now has; an entry at three is no longer queried.
    pub failed_entries: Vec<FailedEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerSnapshot {
    pub utxos: Vec<Utxo>,
    pub spends: Vec<ConfirmedSpend>,
    pub unresolved: Vec<UnresolvedSpend>,
    pub history: Vec<TransactionSummary>,
}

#[derive(Debug, thiserror::Error)]
pub enum FacadeError {
    #[error("{0}")]
    Sync(#[from] crate::transparent::engine::sync::SyncError),
    #[error("{0}")]
    Store(#[from] crate::transparent::engine::store::StoreError),
    #[error("{0}")]
    Transport(String),
    #[error("call refresh_map before sync_once")]
    NoMap,
}

/// A host's chain view as a header list.
struct AcceptedHeaders(BTreeMap<u64, String>);

impl ChainView for AcceptedHeaders {
    fn hash_at(&self, height: u64) -> Option<String> {
        self.0.get(&height).cloned()
    }
    fn is_accepted(&self, height: u64, hash: &str) -> Acceptance {
        match self.0.get(&height) {
            Some(known) if known == hash => Acceptance::Accepted,
            Some(_) => Acceptance::Rejected,
            None => Acceptance::Unknown,
        }
    }
    fn tip(&self) -> Option<Anchor> {
        self.0.iter().next_back().map(|(height, hash)| Anchor {
            height: *height,
            hash: hash.clone(),
        })
    }
}

/// A host's script set, passed as data; no gap-limit callback.
struct GivenScripts(Vec<ScriptEntry>);

impl ScriptProvider for GivenScripts {
    fn scripts(&mut self) -> Vec<ScriptEntry> {
        self.0.clone()
    }
    fn on_activity(&mut self, _: &[Vec<u8>]) -> Vec<ScriptEntry> {
        Vec::new()
    }
}

/// One wallet's transparent sync, over whatever store and transports the
/// host chose.
pub struct TransparentSync {
    store: Box<dyn WalletStore + Send>,
    transport: Box<dyn ShardTransport + Send>,
    filters: Box<dyn FilterSource + Send>,
    geometry: Option<ServiceGeometry>,
    map: Option<(ShardMap, u64)>,
}

impl TransparentSync {
    pub fn new(
        store: Box<dyn WalletStore + Send>,
        transport: Box<dyn ShardTransport + Send>,
        filters: Box<dyn FilterSource + Send>,
    ) -> Self {
        Self {
            store,
            transport,
            filters,
            geometry: None,
            map: None,
        }
    }

    /// Fetches the map and the service's parameters. Returns the map's tip,
    /// which the host validates against its own chain before syncing.
    pub fn refresh_map(&mut self) -> Result<Anchor, FacadeError> {
        let (raw, len) = self
            .filters
            .shard_map()
            .map_err(|error| FacadeError::Transport(error.to_string()))?;
        let map: ShardMap = serde_json::from_slice(&raw)
            .map_err(|error| FacadeError::Transport(error.to_string()))?;
        map.validate_supported().map_err(FacadeError::Transport)?;
        let (init, _) = self
            .transport
            .init()
            .map_err(|error| FacadeError::Transport(error.to_string()))?;
        self.geometry = Some(
            crate::transparent::engine::init::parse_init(&init)
                .map_err(|error| FacadeError::Transport(error.to_string()))?,
        );
        let tip = map
            .shards
            .last()
            .map(|entry| Anchor {
                height: entry.end_height,
                hash: entry.terminal_block_hash.clone(),
            })
            .ok_or_else(|| FacadeError::Transport("the map names no shards".into()))?;
        self.map = Some((map, len));
        Ok(tip)
    }

    /// One bounded sync against the last refreshed or adopted map. A saved
    /// map's transfer receipt is consumed once; a revision refresh remains
    /// current even if later work stops short or returns an error.
    pub fn sync_once(&mut self, request: SyncRequest) -> Result<SyncStatus, FacadeError> {
        let (map, map_bytes) = self.map.as_mut().ok_or(FacadeError::NoMap)?;
        let geometry = self.geometry.as_ref().ok_or(FacadeError::NoMap)?;
        let chain = AcceptedHeaders(request.accepted_headers.iter().cloned().collect());
        let mut scripts = GivenScripts(request.scripts);
        let mut adopted_map = None;
        let report = sync_into_tracking(
            &mut self.store,
            map,
            std::mem::take(map_bytes),
            geometry,
            &chain,
            &mut scripts,
            &mut self.filters,
            &mut self.transport,
            &request.limits,
            &request.target_anchor,
            &mut adopted_map,
        );
        if let Some(map) = adopted_map {
            // Its receipt was charged by the sync that fetched it.
            self.map = Some((map, 0));
        }
        let report = report?;
        let completion = match report.completion {
            Completion::Complete => "complete".to_string(),
            Completion::Incomplete { reason, .. } => match reason {
                IncompleteReason::QueryBudget => "query-budget".into(),
                IncompleteReason::ByteBudget => "byte-budget".into(),
                IncompleteReason::PendingLimit => "pending-limit".into(),
                IncompleteReason::Overloaded { shard_id } => format!("overloaded:{shard_id}"),
                IncompleteReason::ChainUnknown { height } => format!("chain-unknown:{height}"),
                IncompleteReason::PublicationBehind { height } => {
                    format!("publication-behind:{height}")
                }
                IncompleteReason::UnresolvedSpends => "unresolved-spends".into(),
                IncompleteReason::DiscoveryUnbounded => "discovery-unbounded".into(),
                IncompleteReason::ContentFailed => "content-failed".into(),
            },
        };
        Ok(SyncStatus {
            anchor: self.store.anchor()?,
            settled_through: report.settled_through,
            covered_through: report.covered_through,
            pending: self.store.pending()?.len(),
            unresolved: report.ledger.unresolved().len(),
            confirmed_balance: report.ledger.confirmed_balance(),
            completion,
            rolled_back_to: report.rolled_back_to,
            scripts_added: report.scripts_added,
            map_refreshes: report.map_refreshes,
            failed_entries: report.failed_entries,
        })
    }

    /// The store's state without syncing.
    pub fn status(&self) -> Result<SyncStatus, FacadeError> {
        let ledger = self.store.ledger()?;
        let progress = crate::transparent::engine::progress::summary(self.store.as_ref())?;
        Ok(SyncStatus {
            anchor: self.store.anchor()?,
            settled_through: progress.settled_through,
            covered_through: progress.covered_through,
            pending: self.store.pending()?.len(),
            unresolved: ledger.unresolved().len(),
            confirmed_balance: ledger.confirmed_balance(),
            completion: if self.store.pending()?.is_empty() {
                "idle".into()
            } else {
                "pending".into()
            },
            rolled_back_to: None,
            scripts_added: 0,
            map_refreshes: 0,
            failed_entries: Vec::new(),
        })
    }

    pub fn snapshot(&self) -> Result<LedgerSnapshot, FacadeError> {
        let ledger = self.store.ledger()?;
        Ok(LedgerSnapshot {
            utxos: ledger.utxos().cloned().collect(),
            spends: ledger.spends().to_vec(),
            unresolved: ledger.unresolved().to_vec(),
            history: ledger.history(),
        })
    }

    /// A host-driven rollback, for a reorg the host learned of itself.
    pub fn rollback_to(&mut self, anchor: Anchor) -> Result<SyncStatus, FacadeError> {
        self.store.rollback_above(&anchor, "host rollback")?;
        self.status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparent::engine::client::Table;
    use crate::transparent::engine::transport::BoxError;
    use crate::transparent::engine::{MemoryStore, ScriptOrigin};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    struct Filters {
        fresh: ShardMap,
        calls: Arc<AtomicUsize>,
        negative: Arc<AtomicBool>,
    }
    impl FilterSource for Filters {
        fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let bytes = serde_json::to_vec(&self.fresh)?;
            let len = bytes.len() as u64;
            Ok((bytes, len))
        }
        fn filter(&mut self, _: u64) -> Result<(Vec<u8>, u64), BoxError> {
            Ok((b"new".to_vec(), 3))
        }
        fn parent_negative(
            &mut self,
            _: &ShardMap,
            _: u64,
            _: &[Vec<u8>],
            _: &mut dyn WalletStore,
        ) -> Result<(bool, u64), BoxError> {
            Ok((self.negative.load(Ordering::Relaxed), 0))
        }
    }
    struct Offline;
    impl ShardTransport for Offline {
        fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
            Err("offline".into())
        }
        fn manifest(&mut self, _: u64, _: &str) -> Result<(Vec<u8>, u64), BoxError> {
            Err("offline".into())
        }
        fn setup(&mut self, _: u64, _: &str, _: Table, _: u32) -> Result<(Vec<u8>, u64), BoxError> {
            Err("offline".into())
        }
        fn query(&mut self, _: u64, _: &str, _: Table, _: &[u8]) -> Result<Vec<u8>, BoxError> {
            Err("offline".into())
        }
    }
    fn map() -> ShardMap {
        serde_json::from_value(serde_json::json!({
            "genesis_hash": "01".repeat(32), "network":"main",
            "profile":"zcash-transparent-range-v1", "range_envelope_version":1,
            "start_height":100, "seal":{"decoupled-2k-8k":{"max_scripts":1,"max_page_rows":1,"max_txids":0}},
            "shards":[{"shard_id":0,"geometry":"decoupled-2k-8k","start_height":100,"end_height":199,
                "parent_block_hash":"02".repeat(32),"terminal_block_hash":"03".repeat(32),
                "filter_hash":"00".repeat(32),"scripts":1,"page_rows":1,"txids":1,
                "directory_segments":1,"page_segments":1,"manifest_digest":"04".repeat(32),
                "revision":0,"sealed":false}], "recuts":[]
        })).unwrap()
    }
    fn request(scripts: bool) -> SyncRequest {
        SyncRequest {
            target_anchor: Anchor {
                height: 199,
                hash: "03".repeat(32),
            },
            accepted_headers: vec![(99, "02".repeat(32)), (199, "03".repeat(32))],
            scripts: if scripts {
                vec![ScriptEntry {
                    script: vec![1],
                    origin: ScriptOrigin::Imported,
                    required_from: 100,
                }]
            } else {
                vec![]
            },
            limits: WorkLimits::UNLIMITED,
        }
    }
    fn facade(
        fresh: ShardMap,
        calls: Arc<AtomicUsize>,
        negative: Arc<AtomicBool>,
    ) -> TransparentSync {
        let mut sync = TransparentSync::new(
            Box::new(MemoryStore::new()),
            Box::new(Offline),
            Box::new(Filters {
                fresh,
                calls,
                negative,
            }),
        );
        sync.map = Some((map(), 17));
        sync.geometry = Some(ServiceGeometry {
            schema: zakura_pir_protocol::transparent::shard::SCHEMA.into(),
            geometries: vec![],
        });
        sync
    }
    #[test]
    fn cached_map_receipt_is_consumed_once_across_bounded_calls() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut sync = facade(map(), calls.clone(), Arc::new(AtomicBool::new(false)));
        sync.sync_once(request(false)).unwrap();
        assert_eq!(sync.map.as_ref().unwrap().1, 0);
        sync.sync_once(request(false)).unwrap();
        assert_eq!(sync.map.as_ref().unwrap().1, 0);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn adopted_map_survives_an_error_and_the_next_bounded_call() {
        let mut fresh = map();
        fresh.shards[0].revision = 1;
        fresh.shards[0].manifest_digest = "05".repeat(32);
        fresh.shards[0].filter_hash =
            zakura_pir_protocol::transparent::filter::filter_hash(b"new").to_display_hex();
        let calls = Arc::new(AtomicUsize::new(0));
        let negative = Arc::new(AtomicBool::new(false));
        let mut sync = facade(fresh.clone(), calls.clone(), negative.clone());
        // The replacement filter is delivered under the old URL, causing a
        // validated map refresh. Its malformed contents then stop this call.
        assert!(sync.sync_once(request(true)).is_err());
        assert_eq!(
            sync.map.as_ref().unwrap().0.shards[0].manifest_digest,
            fresh.shards[0].manifest_digest
        );
        assert_eq!(sync.map.as_ref().unwrap().1, 0);
        negative.store(true, Ordering::Relaxed);
        // The invalid filter is still rejected on retry; the facade must
        // nevertheless keep the adopted revision rather than refresh again.
        assert!(sync.sync_once(request(true)).is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
