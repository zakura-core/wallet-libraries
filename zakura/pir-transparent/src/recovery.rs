//! Recovery passes for one wallet account: a bounded sync through the reference
//! client into the companion's store, then normalization of what the store holds into a
//! batch of candidate commits.

mod commit_builder;
mod normalize;
mod page_completion;
mod preflight;
mod publication_gate;
mod receipt;
mod sync_inputs;
#[cfg(test)]
mod tests;

use rusqlite::Connection;
use std::{path::Path, time::Duration};
use transparent_filter::ShardMap;
use transparent_wallet::transport::{FilterSource, ShardTransport};
use transparent_wallet::{ChainView, SetIdentity, SyncError, WorkLimits};
use transparent_wallet_store::SqliteStore;
use zcash_client_backend::data_api::transparent_ledger::TransparentWatchSet;

pub(crate) use preflight::{
    check_publication_limits, ensure_mainnet_publication, refuse_parent_filters, service_geometry,
};

#[cfg(doc)]
use crate::batch::{BatchState, WithdrawnCause};
use crate::batch::{RecoveryBatch, behind_unread_batch};
use crate::catalog::{self, Published};
use crate::error::{RecoveryError, ensure_valid, failure};
use crate::progress::{Outcome, Progress};
use preflight::{accepted_target, watch_floor};
use sync_inputs::{FloorAcceptingChain, RecordingFilterSource, watched_scripts};

/// The only shard schema this adapter reads.
///
/// Every companion is bound to it, and a pass refuses a service whose init
/// names another schema before requesting any manifest or private query.
pub const SCHEMA: &str = "transparent-shard-v11";

/// Identity and finite resource bounds for one account's recovery passes.
///
/// The caller supplies the transports for each pass; nothing here is dialed.
#[derive(Clone, Debug)]
pub struct RecoveryConfig {
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
/// The companion store retains cache and page continuation. It is deliberately
/// separate from wallet financial state, whose writer independently validates each
/// normalized commit. No method here changes qualification, activation or spending.
pub struct ReferenceRecovery {
    config: RecoveryConfig,
    /// The companion binding every derived source includes.
    binding: [u8; 32],
    store: SqliteStore,
    pub(crate) catalog: Connection,
    outstanding_receipt: Option<[u8; 32]>,
}

impl ReferenceRecovery {
    /// Open a compatible companion store and fence its account, origin and schema binding.
    ///
    /// A new companion is created in format `transparent-reference-companion-v3`.
    /// A v2 companion, whose sources bound shard ids, has its catalog rebuilt
    /// empty in place and keeps its store, so the next pass exports its stored
    /// facts again under v3 sources without retrieving them. One in the v1
    /// format, whose lineage was a local counter no recreated companion can
    /// reproduce, is refused with `Invalid("companion format v1; recreate")`.
    pub fn open(path: impl AsRef<Path>, config: RecoveryConfig) -> Result<Self, RecoveryError> {
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
        })
    }

    /// Recover a finite pass through the caller's transports and independently
    /// accepted chain.
    ///
    /// `filters` and `transport` must reach the origin bound into this companion.
    /// Before any filter or private retrieval, in order: the watch set's target
    /// must be accepted by `chain`; the watch set and the companion's retained
    /// scripts must be within the script limit; `filters` must not use the parent
    /// filter experiment; the shard map, its shards and the revisions its re-cuts
    /// declare superseded at or above the watch set's floor counted together,
    /// must be within the shard limit, its declarations at any height within
    /// [`MAX_SUPERSEDED`], and it must name Zcash mainnet's network and
    /// genesis block; and the service's init must name
    /// [`SCHEMA`]. A failed check returns [`RecoveryError::Invalid`] without
    /// further requests. A watch set with no addresses needs nothing retrieved:
    /// once its target is accepted, the pass sends no request and returns a batch
    /// with no commits, [`Outcome::Complete`] at the target.
    ///
    /// `chain` answers for every block at or above the watch set's floor, its
    /// lowest required height; below it the pass needs no wallet hashes and
    /// exports nothing. When the publication ends below the target, the pass
    /// syncs to the publication's end if `chain` accepts it and the companion
    /// holds nothing above it; completing there reports [`Outcome::Behind`].
    /// Otherwise the pass is [`Outcome::Behind`] at once. Commits keep the watch
    /// set's context either way.
    ///
    /// The batch is built from the shard map the sync finished with, which is the
    /// first one fetched unless the sync refreshed it; no further map is fetched.
    /// Its [`BatchState`] says whether the commits may be applied.
    ///
    /// When the first map's set identity no longer continues the one the
    /// companion's store is bound to, the pass resets the store, keeps the
    /// catalog, and fails with [`RecoveryError::PublicationChanged`] before the
    /// sync; retry once with the same companion. If that map ends below the
    /// store's anchor while `chain` still accepts the anchor, the pass instead
    /// keeps the store and waits for the map to catch up. That, and any
    /// divergence the sync itself finds (a map refreshed mid-pass that does not
    /// continue the first), is a [`BatchState::Pending`] batch with
    /// [`Outcome::Behind`] that claims no coverage, keeping companion and
    /// catalog. A map that rewrites sealed history the store holds without
    /// declaring a re-cut, where `chain` accepts both the stored range's end
    /// block and the end block of the map's sealed shard now covering it, is
    /// refused by the sync before anything is read, after it rolled back any
    /// reorg the chain alone shows. The pass returns a [`BatchState::Withdrawn`]
    /// batch with [`WithdrawnCause::ChangedSealed`], claiming no coverage,
    /// unless the map declares fewer re-cuts (a lower epoch) than one this
    /// companion recorded: such a map is taken for a replica still serving the
    /// publication from before that re-cut, and the batch is `Pending` and
    /// behind.
    ///
    /// A re-cut the map declares keeps the wallet's history: facts the store
    /// read under a sealed revision the re-cut superseded are exported under
    /// that revision's own identity, which the wallet holds, and the renumbered
    /// shards and tail keep their sources. An undeclared change of sealed
    /// content never reaches the wallet: the sync refuses it, or the catalog
    /// withdraws it, either way as [`BatchState::Withdrawn`]. A ready pass over
    /// a re-cut map records its re-cut epoch once the store holds a fact under
    /// a revision any of its re-cuts superseded, or under one the map publishes
    /// at or above its newest re-cut's first height. The epoch never stops a
    /// sync: a map at a lower epoch that rewrites nothing the store has
    /// finished reading is synced normally, and only a refused `SealedRewrite`
    /// is classified by the epoch. It tells a lagging replica's refused map
    /// from a contradiction, so a forged epoch can at most soften a real
    /// contradiction to `Pending`, and an honest map that rewrites nothing the
    /// store holds is never held back.
    pub fn recover<A, C, F, T>(
        &mut self,
        watch: &TransparentWatchSet<A>,
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
        let report = match transparent_wallet::sync_into(
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
            Ok(report) => report,
            Err(SyncError::SealedRewrite { .. }) => return self.refused_rewrite_batch(&map),
            // Not a set change, which was checked above: a map refreshed
            // mid-pass does not continue the first (another re-cut epoch, or a
            // resumed shard id moved to another start). A later pass starts
            // from the publication it then finds.
            Err(SyncError::MapDiverged(_)) => return Ok(behind_unread_batch()),
            Err(other) => return Err(failure(other)),
        };

        // A stale revision may have refreshed the map mid-sync. The stored facts
        // are the ones that map described.
        let synced_map: ShardMap = serde_json::from_slice(filters.map()).map_err(failure)?;
        self.check_limits(&synced_map, floor)?;
        self.normalize(
            watch,
            synced_map,
            Progress::from_sync_report(&report, sync_target.clamped),
            chain,
        )
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

    /// Acknowledge the latest batch after every wallet commit succeeded, when it
    /// lists no retired revision.
    ///
    /// Only a [`BatchState::Ready`] batch from this companion's latest pass, with
    /// no [`RecoveryBatch::retired_revisions`], is acknowledged. A batch with
    /// retirements is refused, even when its commits applied, and its durable
    /// notifications are left unchanged: only
    /// [`Self::apply_and_acknowledge`] with trusted commits reconciles them. A
    /// [`BatchState::Pending`] or [`BatchState::Withdrawn`] batch, or the receipt
    /// of an earlier pass, is refused too.
    ///
    /// The batch's own revisions were recorded as exported before it was
    /// returned, so a crash before this acknowledgment replays the same candidate
    /// facts. It never advances a wallet's qualification, coverage or financial
    /// authority.
    pub fn acknowledge_applied<A>(
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
