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

use crate::adapters::{Acceptance, ChainView, ScriptProvider};
use crate::ledger::{ConfirmedSpend, TransactionSummary, UnresolvedSpend, Utxo};
use crate::store::{Anchor, ScriptEntry, WalletStore};
use crate::sync::{
    sync_into, Completion, FailedEntry, IncompleteReason, ServiceGeometry, WorkLimits,
};
use crate::transport::{FilterSource, ShardTransport};
use std::collections::BTreeMap;
use transparent_filter::ShardMap;

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
    Sync(#[from] crate::sync::SyncError),
    #[error("{0}")]
    Store(#[from] crate::store::StoreError),
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
        map.check_shape().map_err(FacadeError::Transport)?;
        let (init, _) = self
            .transport
            .init()
            .map_err(|error| FacadeError::Transport(error.to_string()))?;
        self.geometry = Some(
            crate::init::parse_init(&init)
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

    /// One bounded sync against the last refreshed map.
    pub fn sync_once(&mut self, request: SyncRequest) -> Result<SyncStatus, FacadeError> {
        let (map, map_bytes) = self.map.as_ref().ok_or(FacadeError::NoMap)?;
        let geometry = self.geometry.as_ref().ok_or(FacadeError::NoMap)?;
        let chain = AcceptedHeaders(request.accepted_headers.iter().cloned().collect());
        let mut scripts = GivenScripts(request.scripts);
        let report = sync_into(
            &mut self.store,
            map,
            *map_bytes,
            geometry,
            &chain,
            &mut scripts,
            &mut self.filters,
            &mut self.transport,
            &request.limits,
            &request.target_anchor,
        )?;
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
        Ok(SyncStatus {
            anchor: self.store.anchor()?,
            settled_through: 0,
            covered_through: 0,
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
