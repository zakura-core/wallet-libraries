//! Recovery passes for one wallet account: a bounded sync through the reference
//! client into the companion's store, then normalization of what the store holds into a
//! batch of candidate commits.
//!
//! The caller supplies a watch set of already-derived addresses. The same
//! recovery pass retrieves history during wallet restoration and ongoing sync.

mod commit_builder;
mod normalize;
mod page_completion;
mod page_cover;
mod preflight;
mod publication_gate;
mod receipt;
mod sync_inputs;
#[cfg(test)]
mod tests;

use crate::engine::transport::{FilterSource, ShardTransport};
use crate::engine::{ChainView, SetIdentity, SyncError, WorkLimits};
use crate::engine_store::SqliteStore;
use rusqlite::Connection;
use std::{any::Any, path::Path, time::Duration};
use transparent_filter::ShardMap;
use zcash_client_backend::data_api::transparent_ledger::TransparentAddressWatchSet;

pub(crate) use preflight::{
    check_publication_limits, ensure_mainnet_publication, refuse_parent_filters, service_geometry,
};

#[cfg(doc)]
use crate::batch::{BatchState, WithdrawnCause};
use crate::batch::{RecoveryBatch, behind_unread_batch};
use crate::catalog::{self, Published};
use crate::error::{RecoveryError, ensure_valid, failure};
use crate::progress::{FailedEntries, Outcome, Progress};
use preflight::{accepted_target, watch_floor};
use sync_inputs::{FloorAcceptingChain, RecordingFilterSource, watched_scripts};

/// The only shard schema this adapter reads.
///
/// Every companion is bound to it, and a pass refuses a service whose init
/// names another schema before requesting any manifest or private query.
pub const SCHEMA: &str = "transparent-shard-v12";

/// Identity and finite resource bounds for one account's recovery passes.
///
/// The caller supplies the transports for each pass; nothing here is dialed.
/// Account keys and mnemonic derivation stay with the caller.
#[derive(Clone, Debug)]
pub struct TransparentHistoryRecoveryConfig {
    /// Caller-chosen source identity, independent of a server's assertions.
    pub source: Vec<u8>,
    /// Stable wallet/account identity; use a different companion store per account.
    pub account_binding: Vec<u8>,
    /// Identity label bound into the companion: the origin whose publication the
    /// caller's transports retrieve. Transports are the caller's; this is not dialed.
    pub origin: String,
    /// Maximum watched scripts and retained companion scripts.
    pub scripts: usize,
    /// Maximum shard-map entries per pass.
    pub shards: usize,
    /// Maximum candidate event records exported per pass.
    pub events: usize,
    /// Private query budget. Exhaustion retains continuation and reports [`Outcome::More`].
    pub queries: u64,
    /// Private payload budget, including setup. One atomic response may cross it.
    pub private_bytes: u64,
}

/// Durable reference retrieval and normalization for one wallet/account.
///
/// Recover transparent history for addresses the caller has already derived,
/// both during mnemonic restoration and during subsequent synchronization.
///
/// The companion store retains cache and page continuation. It is deliberately
/// separate from wallet financial state, whose writer independently validates each
/// normalized commit. No method here changes qualification, activation or spending.
pub struct TransparentHistoryRecovery {
    /// The identity and bounds every pass of this companion uses.
    config: TransparentHistoryRecoveryConfig,
    /// The companion binding every derived source includes.
    binding: [u8; 32],
    /// The reference client's store: scripts, coverage, events, page work and
    /// caches, in the companion file.
    store: SqliteStore,
    /// A second connection to the companion file, for the catalog's own tables.
    pub(crate) catalog: Connection,
    /// The receipt of the latest ready batch, until it is acknowledged or applied or
    /// a new pass starts. Only the batch carrying it can be acknowledged.
    outstanding_receipt: Option<[u8; 32]>,
    /// The ready batch [`Self::pass`] returned last, a `RecoveryBatch<A>` for the
    /// pass's account type, until it is taken or a new pass starts.
    pub(crate) latest: Option<Box<dyn Any + Send>>,
}

impl TransparentHistoryRecovery {
    /// Open a compatible companion store and fence its account, origin and schema binding.
    ///
    /// A new companion is created in format `transparent-reference-companion-v3`.
    /// A v2 companion, whose sources bound shard ids, has its catalog rebuilt
    /// empty in place and keeps its store, so the next pass exports its stored
    /// facts again under v3 sources without retrieving them. One in the v1
    /// format, whose lineage was a local counter no recreated companion can
    /// reproduce, is refused with `Invalid("companion format v1; recreate")`.
    pub fn open(
        path: impl AsRef<Path>,
        config: TransparentHistoryRecoveryConfig,
    ) -> Result<Self, RecoveryError> {
        ensure_valid(
            !config.source.is_empty()
                && config.source.len() <= 256
                && !config.account_binding.is_empty()
                && config.account_binding.len() <= 256,
            "source/account binding must be nonempty and at most 256 bytes",
        )?;
        ensure_valid(
            config.scripts > 0
                && config.shards > 0
                && config.events > 0
                && config.queries > 0
                && config.private_bytes > 0,
            "recovery bounds must be positive",
        )?;
        let url = url::Url::parse(&config.origin).map_err(failure)?;
        ensure_valid(
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid explicit HTTP origin",
        )?;
        let store = SqliteStore::open(&path).map_err(failure)?;
        let mut catalog = Connection::open(path).map_err(failure)?;
        catalog
            .busy_timeout(Duration::from_secs(5))
            .map_err(failure)?;
        let binding = catalog::companion_binding([
            &config.source,
            &config.account_binding,
            config.origin.as_bytes(),
            SCHEMA.as_bytes(),
        ]);
        catalog::prepare(&mut catalog, &binding)?;
        Ok(Self {
            config,
            binding,
            store,
            catalog,
            outstanding_receipt: None,
            latest: None,
        })
    }

    /// Test support: draws page cover from `seed` from now on. Page cover is not
    /// built yet, so this does nothing. Never call it in a production build.
    #[cfg(feature = "testing")]
    pub fn seed_page_cover(&mut self, _seed: u64) {}

    /// One attempt of [`Self::pass`] through `filters` and `transport`, returning its
    /// batch rather than holding it. A new attempt makes the batch of every earlier one
    /// unacknowledgeable. When the publication set changed it resets the store, keeps the
    /// catalog and fails with [`RecoveryError::PublicationChanged`], which `pass` retries
    /// once.
    pub(crate) fn recover<A, C, F, T>(
        &mut self,
        watch: &TransparentAddressWatchSet<A>,
        chain: &C,
        filters: &mut F,
        transport: &mut T,
    ) -> Result<RecoveryBatch<A>, RecoveryError>
    where
        A: Copy + std::fmt::Debug,
        C: ChainView,
        F: FilterSource,
        T: ShardTransport,
    {
        self.outstanding_receipt = None;
        self.latest = None;
        let target = accepted_target(watch, chain)?;
        if watch.addresses.is_empty() {
            // Every watched script is covered, vacuously. A sync would need the
            // wallet's hash for every shard from the map's start, since nothing
            // raises the floor, and the reference client reports a sync with no
            // scripts as unbounded discovery.
            return self.issue_ready_batch(
                vec![],
                vec![],
                Progress {
                    covered_through: target.height,
                    outcome: Outcome::Complete,
                },
            );
        }

        // Refusals before any filter or private retrieval, in the documented order.
        self.check_watch_set(watch)?;
        refuse_parent_filters(filters)?;
        let (mut filters, map_fetch_bytes) =
            RecordingFilterSource::fetch(filters).map_err(failure)?;
        let map: ShardMap = serde_json::from_slice(filters.map()).map_err(failure)?;
        let floor = watch_floor(watch, target.height);
        self.check_limits(&map, floor)?;
        ensure_mainnet_publication(&map)?;
        let geometry = service_geometry(transport)?;
        if let Some(lagging_replica) = self.gate_publication_set(&map, chain)? {
            return Ok(lagging_replica);
        }

        // The sync into the companion's store.
        let sync_target = self.store_sync_target(&map, &target, floor, chain)?;
        let floor_accepting_chain = FloorAcceptingChain {
            chain,
            floor,
            genesis_hash: &map.genesis_hash,
        };
        let mut scripts = watched_scripts(watch);
        let limits = WorkLimits {
            max_queries: Some(self.config.queries),
            max_private_bytes: Some(self.config.private_bytes),
        };
        let synced = match crate::engine::sync_into(
            &mut self.store,
            &map,
            map_fetch_bytes,
            &geometry,
            &floor_accepting_chain,
            &mut scripts,
            &mut filters,
            transport,
            &limits,
            &sync_target.anchor,
        ) {
            Ok(report) => Some(report),
            Err(SyncError::SealedRewrite { .. }) => return self.refused_rewrite_batch(&map),
            // Not a set change, which was checked above: a map refreshed
            // mid-pass does not continue the first (another re-cut epoch, or a
            // resumed shard id moved to another start). A later pass starts
            // from the publication it then finds.
            Err(SyncError::MapDiverged(_)) => return Ok(behind_unread_batch()),
            // A reply's content failed where the client could not fail one
            // directory entry for it: a contradiction no single entry carried.
            // Like a failed entry, it is the reply's, not the companion's, so
            // the pass is not a failure a caller would pass again for: what the
            // sync committed before it settles, and the pass is stalled.
            Err(SyncError::Content(_)) => None,
            Err(other) => return Err(failure(other)),
        };
        let (progress, failed_entries) = match &synced {
            Some(report) => (
                Progress::from_sync_report(report, sync_target.clamped),
                FailedEntries::of(report),
            ),
            None => (
                Progress {
                    covered_through: 0,
                    outcome: Outcome::Stalled,
                }
                .with_publication_wait(sync_target.clamped),
                FailedEntries::default(),
            ),
        };

        // A stale revision may have refreshed the map mid-sync. The stored facts
        // are the ones that map described.
        let synced_map: ShardMap = serde_json::from_slice(filters.map()).map_err(failure)?;
        self.check_limits(&synced_map, floor)?;
        let mut batch = self.normalize(watch, synced_map, progress, chain)?;
        batch.failed_entries = failed_entries;
        Ok(batch)
    }

    /// Every revision `map`, under `set`, publishes, and every one its re-cuts
    /// declare superseded, the superseded tails included.
    fn map_revisions(
        &self,
        map: &ShardMap,
        set: &SetIdentity,
    ) -> Result<(Vec<Published>, Vec<Published>), RecoveryError> {
        let published = map
            .shards
            .iter()
            .map(|entry| Published::of(&self.binding, set, entry))
            .collect::<Result<Vec<_>, _>>()?;
        let declarations = map
            .recuts
            .iter()
            .flat_map(|recut| &recut.superseded)
            .map(|shard| Published::declared(&self.binding, set, shard))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((published, declarations))
    }

    /// Acknowledges the latest batch, when it lists no retired revision, as if a
    /// wallet applied its commits: drives the companion in tests without a wallet.
    ///
    /// Only a [`BatchState::Ready`] batch from this companion's latest pass, with
    /// no [`RecoveryBatch::retired_revisions`], is acknowledged. A
    /// [`BatchState::Pending`] or [`BatchState::Withdrawn`] batch, or the receipt
    /// of an earlier pass, is refused too.
    #[cfg(test)]
    pub(crate) fn acknowledge_applied<A>(
        &mut self,
        batch: &RecoveryBatch<A>,
    ) -> Result<(), RecoveryError> {
        ensure_valid(
            batch.retired_revisions().is_empty(),
            "retired revisions require trusted wallet reconciliation",
        )?;
        self.acknowledge(batch)
    }
}
