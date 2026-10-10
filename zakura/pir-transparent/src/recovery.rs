//! Recovery passes for one wallet account: a bounded sync through the reference
//! client into the companion's store, then normalization of what the store holds into a
//! batch of candidate commits.

mod commit_builder;
mod normalize;
mod page_completion;
mod preflight;
mod receipt;
mod sync_inputs;
#[cfg(test)]
mod tests;

use rusqlite::Connection;
use std::{collections::BTreeMap, path::Path, time::Duration};
use transparent_filter::{MAINNET_GENESIS_DISPLAY, NETWORK, ShardMap};
use transparent_wallet::transport::{FilterSource, ShardTransport};
use transparent_wallet::{
    Acceptance, Anchor, ChainView, ScriptEntry, ScriptOrigin, SetIdentity, StaticScripts,
    SyncError, WalletStore, WorkLimits,
};
use transparent_wallet_store::SqliteStore;
use zcash_client_backend::data_api::transparent_ledger::TransparentWatchSet;

pub(crate) use preflight::{check_publication_limits, service_geometry};

use crate::batch::{BatchState, RecoveryBatch, WithdrawnCause, behind_unread, unready};
use crate::catalog::{self, Published};
use crate::convert::address_script;
use crate::error::{RecoveryError, failure, require};
use crate::progress::{Outcome, Progress, progress};
use preflight::required_floor;
use sync_inputs::{BelowFloor, Recorded, sync_target};

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
    pending_export: Option<[u8; 32]>,
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
        require(
            !config.source.is_empty()
                && config.source.len() <= 256
                && !config.account_binding.is_empty()
                && config.account_binding.len() <= 256,
            "source/account binding must be nonempty and at most 256 bytes",
        )?;
        require(
            config.scripts > 0
                && config.shards > 0
                && config.events > 0
                && config.queries > 0
                && config.private_bytes > 0,
            "recovery bounds must be positive",
        )?;
        let url = url::Url::parse(&config.origin).map_err(failure)?;
        require(
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
        let binding = catalog::binding([
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
            pending_export: None,
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
        self.pending_export = None;
        let context = watch
            .context()
            .ok_or_else(|| RecoveryError::Invalid("no locally accepted recovery target".into()))?;
        let target = Anchor {
            height: u64::from(u32::from(context.target.height)),
            hash: context.target.hash.to_string(),
        };
        require(
            chain.is_accepted(target.height, &target.hash) == Acceptance::Accepted,
            "target is not independently accepted",
        )?;
        if watch.addresses.is_empty() {
            // Every watched script is covered, vacuously. A sync would need the
            // wallet's hash for every shard from the map's start, since nothing
            // raises the floor, and the reference client reports a sync with no
            // scripts as unbounded discovery.
            return self.ready(
                vec![],
                vec![],
                Progress {
                    covered_through: target.height,
                    outcome: Outcome::Complete,
                },
            );
        }
        require(
            watch.addresses.len() <= self.config.scripts
                && self.store.scripts().map_err(failure)?.len() <= self.config.scripts,
            "script limit exceeded",
        )?;
        let addresses: BTreeMap<Vec<u8>, _> = watch
            .addresses
            .iter()
            .map(|entry| (address_script(entry.address), entry))
            .collect();
        require(
            addresses.len() == watch.addresses.len(),
            "duplicate watch address",
        )?;
        // The parent experiment's selective child requests leak coarse activity.
        require(
            !filters.uses_parents(),
            "parent filter sources are not supported",
        )?;
        let (mut filters, map_bytes) = Recorded::fetch(filters).map_err(failure)?;
        let map: ShardMap = serde_json::from_slice(filters.map()).map_err(failure)?;
        let floor = required_floor(watch, target.height);
        self.check_limits(&map, floor)?;
        // The wallet's chain is mainnet's; another chain's map cannot cover it.
        require(
            map.network == NETWORK && map.genesis_hash == MAINNET_GENESIS_DISPLAY,
            "publication is not for Zcash mainnet",
        )?;
        let geometry = service_geometry(transport)?;
        // The set check the sync would make when binding, made here so that a
        // changed publication restarts the store rather than stopping the sync.
        let set = SetIdentity::of_schema(&map, SCHEMA);
        if self
            .store
            .set_identity()
            .map_err(failure)?
            .is_some_and(|bound| !bound.continues(&set))
        {
            map.check_shape().map_err(failure)?;
            // As the reference client refuses a map ending below the anchor the
            // wallet's chain still accepts, a map under another set ending there
            // is a replica that has not caught up, perhaps still serving the
            // previous set. Wait for it: a reset would empty the store again
            // each time such replicas alternate.
            if let Some(anchor) = self.store.anchor().map_err(failure)?
                && map
                    .shards
                    .last()
                    .is_none_or(|last| last.end_height < anchor.height)
                && chain.is_accepted(anchor.height, &anchor.hash) == Acceptance::Accepted
            {
                return Ok(behind_unread());
            }
            let (published, declarations) = self.revisions(&map, &set)?;
            let named: Vec<_> = published.into_iter().chain(declarations).collect();
            catalog::reset(&mut self.catalog, &named)?;
            return Err(RecoveryError::PublicationChanged);
        }
        let stored = self.store.anchor().map_err(failure)?;
        let retained = self
            .store
            .events()
            .map_err(failure)?
            .iter()
            .map(|held| u64::from(held.event.height()))
            .max()
            .unwrap_or(0);
        let (sync_anchor, clamped) =
            sync_target(&map, &target, floor, stored.as_ref(), retained, chain);
        let below_floor = BelowFloor {
            chain,
            below: floor,
            genesis: &map.genesis_hash,
        };
        let mut scripts = StaticScripts(
            watch
                .addresses
                .iter()
                .map(|entry| ScriptEntry {
                    script: address_script(entry.address),
                    origin: ScriptOrigin::Derived,
                    required_from: u64::from(u32::from(entry.required_from)),
                })
                .collect(),
        );
        let limits = WorkLimits {
            max_queries: Some(self.config.queries),
            max_private_bytes: Some(self.config.private_bytes),
        };
        let report = match transparent_wallet::sync_into(
            &mut self.store,
            &map,
            map_bytes,
            &geometry,
            &below_floor,
            &mut scripts,
            &mut filters,
            transport,
            &limits,
            &sync_anchor,
        ) {
            Ok(report) => report,
            // The map rewrites sealed history the store holds without declaring
            // a re-cut, and the wallet's chain accepts both the block the stored
            // range ends on and the block the map's sealed shard now covering
            // its start ends on, at or below the target. The sync judges that
            // only after rolling back any reorg the chain alone shows, and only
            // for the ranges the rollback kept, and refuses it before reading
            // anything; anything the chain cannot settle yet stops it as
            // `ChainUnknown`.
            //
            // The sync keeps no re-cut epoch, so a replica still serving a map
            // from before a re-cut the store followed looks the same to it. A
            // map below the epoch this companion recorded is taken for one:
            // `Pending`, behind, and a later pass syncs again. Otherwise the
            // publisher contradicts the wallet's own chain, which no later pass
            // over this history repairs: `Withdrawn(ChangedSealed)`. Either way
            // nothing was read: the store keeps what it held, less any reorg the
            // sync rolled back first, and the catalog is unchanged.
            Err(SyncError::SealedRewrite { .. }) => {
                if map.recut_epoch() < catalog::recut_epoch(&self.catalog)? {
                    return Ok(behind_unread());
                }
                return Ok(unready(
                    BatchState::Withdrawn(WithdrawnCause::ChangedSealed),
                    Progress {
                        covered_through: 0,
                        outcome: Outcome::Behind,
                    },
                ));
            }
            // Not a set change, which was checked above: a map refreshed
            // mid-pass does not continue the first (another re-cut epoch, or a
            // resumed shard id moved to another start). A later pass starts
            // from the publication it then finds.
            Err(SyncError::MapDiverged(_)) => return Ok(behind_unread()),
            Err(other) => return Err(failure(other)),
        };
        // A stale revision may have refreshed the map mid-sync. The stored facts
        // are the ones that map described.
        let map: ShardMap = serde_json::from_slice(filters.map()).map_err(failure)?;
        self.check_limits(&map, floor)?;
        self.normalize(watch, map, progress(&report, clamped), chain)
    }

    /// Refuses a map with more shards and declarations at or above `floor`
    /// than the shard limit, or more declarations in all than
    /// [`MAX_SUPERSEDED`].
    fn check_limits(&self, map: &ShardMap, floor: u64) -> Result<(), RecoveryError> {
        check_publication_limits(map, floor, self.config.shards)
    }

    /// Every revision `map`, under `set`, publishes, and every one its re-cuts
    /// declare superseded, the superseded tails included.
    fn revisions(
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
        require(
            batch.retired_revisions().is_empty(),
            "retired revisions require trusted wallet reconciliation",
        )?;
        self.acknowledge(batch)
    }
}
