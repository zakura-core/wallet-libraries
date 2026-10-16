//! Birthday to balance: the join between public filters and private retrieval.
//!
//! This is the path the whole design exists to make cheap:
//!
//! 1. fetch the published shard map and binary-search it for the birthday;
//! 2. download **every** filter from that shard forward and match locally;
//! 3. for each matched script and directory shard, privately retrieve its
//!    directory row, then walk the chain of runs its entry points to, newest
//!    first, through the shard's page shards (see `walk_chains`);
//! 4. replay the events into a UTXO set.
//!
//! Step 2 downloads every filter in range, not only the ones that will match.
//! Which filters a wallet asks for must not be a function of its scripts.
//!
//! Step 3 addresses a row over the shard's whole logical row space, which is
//! its segments concatenated. Every segment answers, and the row is identified
//! by its exact script bytes rather than by which segment returned it: asking
//! only the segment that holds the script would disclose part of the script.
//! Coverage advances for a shard only once every segment has been processed.
//!
//! # Settled and provisional coverage
//!
//! The last shard in the map may be a provisional tail revision, which will be
//! superseded as the chain advances. Coverage taken from one is reported
//! separately from settled coverage, with the revision's digest, so a caller
//! can re-derive that range instead of merging a later revision into it.
//!
//! # What the checks here establish
//!
//! The first profile trusts the publisher and the retrieval service to provide
//! correct, complete, mutually consistent data for the declared anchor. What
//! this code checks — filter digests against the map, exact script bytes
//! against the row, a page header against the entry that located it, the event
//! total against what the pages yielded — detects corruption, stale data and
//! accidentally mixed shards. None of it establishes that the index matches the
//! chain: a service that returns a consistent lie passes every one of them.
//!
//! # What this leaks, stated plainly
//!
//! Step 3 queries only the shards that matched, so the service learns which
//! chain ranges the wallet had probable activity in. That is the leak the
//! design accepts, and it is real: with content-sealed shards a busy period is
//! covered by a narrower shard, so the localization is sharper during busy
//! periods than quiet ones. This code does not hide it and must not be
//! described as if it did.

use crate::engine::adapters::{Acceptance, ChainView, ScriptProvider, StaticScripts};
use crate::engine::client::{ClientError, Table, TableClient};
use crate::engine::ledger::{Ledger, LedgerError};
use crate::engine::memory_store::MemoryStore;
use crate::engine::store::{
    Anchor, CoverageKind, CoverageRange, PendingPages, ScriptEntry, ScriptOrigin, SetIdentity,
    ShardCommit, StoreError, StoredEvent, WalletStore, uncovered,
};
use crate::engine::transport::{ByteCharges, FilterSource, ShardTransport, StaleRevision};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use transparent_filter::{BlockHash, ScriptBytes, ShardMap};

mod ahead;
mod failures;
mod manifest;
mod rows;
mod shard;
mod walk;

use failures::{
    Failure, Failures, accepted_at, budget_stopped, chain_unknown, event_height, held, hold,
    incomplete_at, record_failure,
};
use manifest::{
    Rewrite, check_resume, directory_choice, fetch_manifest, judge_rewrite, refresh_map,
    tag_salt_of, verify_manifest, vouches_for,
};
use rows::{PirRows, Reply, RowRequest, RowSource, open_table};
use shard::{ShardRead, endpoint_of, finish_pages, match_filter, read_shard_into, with_refusals};
use walk::{check_target_hash, commit_bounded, locate, walk_chains};

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("client: {0}")]
    Client(#[from] ClientError),
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
    #[error("filter: {0}")]
    Filter(#[from] transparent_filter::FilterError),
    #[error("record: {0}")]
    Record(#[from] transparent_shard::records::RecordError),
    #[error("transport: {0}")]
    Transport(String),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// The store's accepted anchor lies above the offered map's end, and the
    /// wallet's chain still accepts it. A lower anchor is never accepted
    /// silently.
    #[error(
        "the store's anchor {stored} is above the map's end {offered}, which the chain still accepts"
    )]
    AnchorRegressed { stored: u64, offered: u64 },
    #[error("{0}")]
    Invalid(String),
    /// A row in a private reply failed on content: it did not decode, a
    /// record or link in it was not what the shard declares, or it
    /// contradicts what the store holds. A reply failing as a whole (its
    /// length, revision binding or parameter epoch) is a request failure
    /// instead, [`SyncError::Client`]: the service makes those without
    /// knowing the row.
    ///
    /// A sync does not stop for one: it fails the directory entry the reply
    /// was for, finishes everything else, counts the failure in the store
    /// and reports [`IncompleteReason::ContentFailed`]; see
    /// [`retrieve_shard_into`](shard::retrieve_shard_into) and [`walk_chains`].
    /// It reaches a caller from the one-shot [`sync`], which has no store to
    /// count it in, and when a contradiction cannot be laid at one entry's door.
    #[error("content: {0}")]
    Content(String),
    #[error("service serves schema {served}, this build reads {expected}")]
    Schema {
        served: String,
        expected: &'static str,
    },
    /// A shard names a geometry this build has no parameters for.
    ///
    /// Fatal for the whole sync rather than a reason to skip the shard. Skipping
    /// would advance coverage past a range whose history was never retrieved,
    /// and the wallet would report a synchronised balance it has not earned.
    #[error(
        "shard set uses geometry {0}, which this build does not know; upgrade before syncing this \
         range"
    )]
    UnknownGeometry(String),
    /// The map names a range-filter profile this build does not know.
    ///
    /// Its filters would be decoded under the wrong Golomb-Rice parameters,
    /// which neither fails reliably nor matches correctly, so the sync stops
    /// before matching anything.
    #[error(
        "shard set uses range-filter profile {0}, which this build does not know; upgrade \
         before syncing this range"
    )]
    UnknownProfile(String),
    /// A revision this sync needed was withdrawn, and refreshing the map did
    /// not offer one that is served.
    ///
    /// Terminal, and coverage stopped where it was. Distinct from a transport
    /// failure so a caller can re-validate a map against its accepted chain and
    /// come back, rather than treating a routine republication as a broken set.
    #[error(
        "shard {shard_id}: {stale}; the map was refreshed {refreshes} time(s) without offering a \
         live revision"
    )]
    StaleRevision {
        shard_id: u64,
        stale: StaleRevision,
        refreshes: u32,
    },
    /// The service stayed at its capacity limit for the whole retry budget.
    #[error("shard {shard_id}: the service had no free cache capacity after {attempts} attempts")]
    Overloaded { shard_id: u64, attempts: u32 },
    /// A shard's manifest does not describe the shard the map named.
    ///
    /// Terminal for the sync, and coverage stops where it was. Every field a
    /// retrieval relies on — geometry, range, segment shape, chain link — is
    /// checked against the map before a single private request, so a
    /// publication that is internally inconsistent is refused rather than read
    /// under whichever of its two stories the wallet happened to see first.
    #[error("shard {shard_id}: manifest {field} does not agree with the map")]
    ManifestMismatch { shard_id: u64, field: &'static str },
    /// A refreshed map is not the same shard set, continued.
    ///
    /// The caller validated the map this sync started from against the wallet's
    /// accepted chain. A map fetched mid-sync inherits that validation only over
    /// the range the two agree on, so a disagreement about already-covered
    /// history is a different set rather than a longer one, and the caller has
    /// to re-validate before retrying.
    #[error("the refreshed shard map is not a continuation of the one this sync started from: {0}")]
    MapDiverged(String),
    /// The map contradicts sealed history the store holds on the wallet's own
    /// chain, and declares no re-cut of it.
    ///
    /// Sealed content is immutable. A sealed range described differently is a
    /// reorg when the chain has moved, and is rolled back as one. This is the
    /// other case: the chain accepts the block the stored range rests on and
    /// also the block the map's sealed shard now covering its start ends on,
    /// at or below the target. Both are on the chain the wallet follows, so
    /// nothing explains the change but the publisher, and retrying does not
    /// resolve it while the publisher serves this history. When the chain
    /// does not yet accept the replacement's end block, as when the publisher
    /// followed a shallow reorg through a shard it had just sealed before the
    /// wallet's chain did, the sync stops with
    /// [`IncompleteReason::ChainUnknown`] instead and becomes an ordinary reorg
    /// once the chain moves. Refused before anything is read, and after
    /// rolling back only a reorg the wallet's chain itself shows, which runs
    /// first so that no map can hold it back. Distinct from
    /// [`MapDiverged`](Self::MapDiverged), which a re-cut published mid-sync
    /// also produces and which the next sync resolves.
    ///
    /// A replica still serving a map from before a re-cut the store has
    /// already followed looks the same from here, since the store keeps no
    /// re-cut epoch: an embedding that records the epoch it last synced at
    /// can tell the two apart before calling the sync.
    #[error(
        "the map replaces the sealed shard the store holds from height {start_height} (revision \
         {revision_digest}) with another the wallet's chain also accepts, and declares no re-cut \
         of it"
    )]
    SealedRewrite {
        start_height: u64,
        revision_digest: String,
    },
}

/// Map refreshes one sync will spend recovering a withdrawn revision.
///
/// A tail is republished on a block cadence, so a wallet lapped this many times
/// while reading is not converging on the tip, and saying so beats re-reading a
/// moving target indefinitely. Every refresh must also *change* the refused
/// revision, so this bounds genuine republication rather than a loop.
const MAX_MAP_REFRESHES: u32 = 4;

/// Attempts one shard gets against a service that is out of cache capacity.
const MAX_OVERLOAD_ATTEMPTS: u32 = 4;

/// Wait before a second attempt when the service names no delay, doubled per
/// attempt after that.
const OVERLOAD_BACKOFF: Duration = Duration::from_millis(250);

/// Ceiling on any single wait before jitter, so a service asking for an
/// implausible delay cannot park a sync inside it.
const OVERLOAD_BACKOFF_CAP: Duration = Duration::from_secs(2);

/// Passes a sync makes while the wallet's rules keep adding scripts. A
/// gap-limit advance that never converges is a wallet fault; this stops it
/// from becoming an unbounded sync.
const MAX_DISCOVERY_PASSES: u32 = 16;

/// Content failures after which a directory entry is no longer queried.
///
/// A service can aim a bad reply at chosen rows and watch what the wallet
/// does next. Each failure changes later traffic once (the entry is asked
/// again, then not), so this is how many such observations a revision gives
/// away; a service could deny the entry service anyway by corrupting it.
pub const MAX_CONTENT_FAILURES: u32 = 3;

/// One geometry's parameters, as a service declares them.
///
/// The dimensions come with the schemes so a wallet can check the pair rather
/// than adopt either. A service naming a registry geometry but publishing other
/// row counts under it is refused; so is one publishing the registry's row
/// counts with a scheme they do not derive.
pub struct GeometryParams {
    pub name: String,
    pub directory_rows: u64,
    pub directory_row_bytes: u32,
    pub directory_scheme: transparent_native::NativeScheme,
    /// The 44-bit dithered directory scheme, when the service advertises one.
    pub directory_scheme_dq44: Option<transparent_native::NativeScheme>,
    pub directory_setup_seed: u64,
    pub page_rows: u64,
    pub page_row_bytes: u32,
    pub pages_scheme: transparent_native::NativeScheme,
    /// The 44-bit dithered page scheme, when the service advertises one.
    pub pages_scheme_dq44: Option<transparent_native::NativeScheme>,
    pub pages_setup_seed: u64,
}

/// The geometries a service declares, checked against this build's registry.
pub struct ServiceGeometry {
    /// The schema the service serves, from its init response.
    ///
    /// A row's meaning is entirely a function of its schema, and the bytes
    /// carry no version of their own — a fixed-width row has nowhere to put
    /// one without spending space on every row. So a wallet that decoded
    /// whatever it was handed would read a newer layout as the one it knows
    /// and reconstruct a plausible, wrong history. This is where that stops.
    pub schema: String,
    /// One entry per geometry the service holds. A set spanning an archive tier
    /// and a recent tier declares two.
    pub geometries: Vec<GeometryParams>,
}

/// The prepared clients for one geometry: one per table.
struct GeometryClients {
    directory: TableClient,
    pages: TableClient,
}

/// Every geometry a sync has prepared, by registry name.
///
/// Prepared on first use rather than up front, so a wallet syncing only recent
/// history never pays to derive archive parameters. Once prepared, a geometry's
/// clients are reused for every shard naming it — which is the saving that
/// naming geometries from a closed registry exists to buy.
struct Clients {
    schema: String,
    prepared: HashMap<String, GeometryClients>,
}

impl Clients {
    /// Prepares the clients for `name`, checking the service's declaration
    /// against this build's registry and re-deriving the scheme.
    ///
    /// Three things have to agree: the name must be one this build knows, the
    /// dimensions the service published under it must be the registry's, and
    /// the scheme must be what those dimensions derive. A service that could
    /// move any one of them independently could choose a geometry for the
    /// wallet, and choosing the geometry is choosing what the response reveals.
    fn prepare(
        &mut self,
        name: &str,
        declared: &[GeometryParams],
    ) -> Result<&mut GeometryClients, SyncError> {
        if !self.prepared.contains_key(name) {
            let geometry = transparent_shard::layout::by_name(name)
                .ok_or_else(|| SyncError::UnknownGeometry(name.to_string()))?;
            let params = declared
                .iter()
                .find(|params| params.name == name)
                .ok_or_else(|| {
                    SyncError::Invalid(format!(
                        "the map uses geometry {name} but the service declares no parameters for it"
                    ))
                })?;
            if params.directory_rows != geometry.directory_rows
                || params.directory_row_bytes != geometry.directory_row_bytes as u32
                || params.page_rows != geometry.page_rows
                || params.page_row_bytes != geometry.page_row_bytes as u32
            {
                return Err(SyncError::Invalid(format!(
                    "the service declares geometry {name} with dimensions this build does not \
                     know it by"
                )));
            }
            let clients = GeometryClients {
                directory: TableClient::new_with_schema(
                    &self.schema,
                    Table::Directory,
                    name,
                    geometry.directory_rows,
                    geometry.directory_row_bytes as u32,
                    &params.directory_scheme,
                    params.directory_scheme_dq44.as_ref(),
                )?,
                pages: TableClient::new_with_schema(
                    &self.schema,
                    Table::Pages(0),
                    name,
                    geometry.page_rows,
                    geometry.page_row_bytes as u32,
                    &params.pages_scheme,
                    params.pages_scheme_dq44.as_ref(),
                )?,
            };
            self.prepared.insert(name.to_string(), clients);
        }
        Ok(self.prepared.get_mut(name).expect("just prepared"))
    }
}

/// What one sync recovered.
pub struct SyncOutcome {
    pub ledger: Ledger,
    pub charges: ByteCharges,
    /// Shards where at least one script matched. Ascending.
    pub matched_shards: Vec<u64>,
    /// Matches that turned out to hold no directory entry: the filter's false
    /// positives, plus any script outside the private tables' coverage.
    pub unproductive_matches: u64,
    /// Height through which coverage is complete, including any provisional
    /// tail revision this sync used.
    pub covered_through: u64,
    /// Height through which coverage came from sealed shards alone.
    ///
    /// Equal to `covered_through` when the sync used no provisional revision.
    /// A balance beyond this height is current but not settled.
    pub settled_through: u64,
    /// The provisional revisions this sync took coverage from: shard id,
    /// revision number and the manifest digest that identifies the revision.
    ///
    /// A caller records these with the coverage. When a later revision or the
    /// sealed shard appears, the range they covered is re-derived rather than
    /// extended, because a revision replaces its predecessor.
    pub provisional: Vec<ProvisionalCoverage>,
    /// Times this sync refetched the map to recover a withdrawn revision.
    ///
    /// Non-zero means part of the range was re-derived under a later revision.
    /// The abandoned attempt's bytes are still counted in `charges`, so a
    /// recovered sync legitimately reports more filter and setup bytes than a
    /// clean one over the same range.
    pub map_refreshes: u32,
}

/// One provisional revision a sync took coverage from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionalCoverage {
    pub shard_id: u64,
    pub revision: u32,
    pub manifest_digest: String,
    pub end_height: u64,
}

/// Bounds on one call to [`sync_into`]. `None` is unbounded.
///
/// Reaching a bound is not an error: the sync commits what it has, records
/// the page work still owed, and reports `Incomplete`. The next call resumes
/// from the durable pending work.
/// Soft limits checked before starting private setup or a whole query group.
/// A started group completes every candidate row and table segment, even on
/// a hit or failure, so the last indivisible group can exceed either limit.
/// A zero limit starts no private work. Checked progress is committed before
/// returning an incomplete report.
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkLimits {
    /// Private queries, directory and pages together.
    pub max_queries: Option<u64>,
    /// Private bytes: setup, query uploads and responses.
    pub max_private_bytes: Option<u64>,
}

impl WorkLimits {
    pub const UNLIMITED: Self = Self {
        max_queries: None,
        max_private_bytes: None,
    };
}

/// Why a sync stopped short.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IncompleteReason {
    QueryBudget,
    ByteBudget,
    /// The store would not hold more pending page work.
    PendingLimit,
    /// The service stayed at capacity for the whole retry budget on this shard.
    Overloaded {
        shard_id: u64,
    },
    /// The wallet's chain view could not confirm a block its coverage rests
    /// on, so neither a reorg nor its absence could be established.
    ChainUnknown {
        height: u64,
    },
    /// The wallet's rules kept adding scripts past the pass bound.
    DiscoveryUnbounded,
    /// Coverage stops short at directory entries whose replies failed on
    /// content; [`SyncReport::failed_entries`] lists them. Everything else
    /// was read and committed.
    ContentFailed,
    PublicationBehind {
        height: u64,
    },
    UnresolvedSpends,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Completion {
    Complete,
    Incomplete {
        reason: IncompleteReason,
        /// Pending page retrievals left in the store.
        pending: usize,
    },
}

/// What one [`sync_into`] call did.
pub struct SyncReport {
    /// The store's whole ledger after this sync, not only what it added.
    pub ledger: Ledger,
    pub charges: ByteCharges,
    pub matched_shards: Vec<u64>,
    pub unproductive_matches: u64,
    /// Height through which every script in scope is covered from its
    /// required height, provisional coverage included.
    pub covered_through: u64,
    /// The same counting settled coverage only.
    pub settled_through: u64,
    pub provisional: Vec<ProvisionalCoverage>,
    pub map_refreshes: u32,
    pub completion: Completion,
    /// The height everything above was rolled back to, if this sync found a
    /// reorg or a replaced provisional tail.
    pub rolled_back_to: Option<u64>,
    /// Provisional revision digests whose coverage was truncated and
    /// re-derived.
    pub replaced_revisions: Vec<String>,
    /// Scripts the wallet's rules added during this sync.
    pub scripts_added: usize,
    /// Store commits this sync made.
    pub commits: u64,
    /// Directory entries this sync failed on content or held back because
    /// they had failed [`MAX_CONTENT_FAILURES`] times, by shard revision and script.
    pub failed_entries: Vec<FailedEntry>,
}

/// One script's directory entry in one shard that failed on content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedEntry {
    pub shard_id: u64,
    /// The exact manifest whose content failed.
    pub revision_digest: String,
    pub script: Vec<u8>,
    /// Content failures the store holds for the entry, this sync's included.
    /// At [`MAX_CONTENT_FAILURES`] the entry is no longer queried.
    pub failures: u32,
}

/// Runs one sync from `birthday` to the explicit wallet-accepted target.
///
/// `scripts` is the wallet's derived script set. It never leaves the machine:
/// matching is local, and a private query names a row, not a script.
///
/// One-shot: a fresh in-memory store, every script required from `birthday`,
/// no work limits, using the caller's accepted chain view. A returning
/// wallet uses [`sync_into`] with its own store.
#[allow(clippy::too_many_arguments)]
pub fn sync(
    map: &ShardMap,
    map_bytes: u64,
    geometry: &ServiceGeometry,
    filters: &mut impl FilterSource,
    transport: &mut impl ShardTransport,
    scripts: &[ScriptBytes],
    birthday: u64,
    chain: &impl ChainView,
    target_anchor: &Anchor,
) -> Result<SyncOutcome, SyncError> {
    let mut store = MemoryStore::new();
    let mut provider = StaticScripts(
        scripts
            .iter()
            .map(|script| ScriptEntry {
                script: script.as_slice().to_vec(),
                origin: ScriptOrigin::Derived,
                required_from: birthday,
            })
            .collect(),
    );
    let report = sync_into(
        &mut store,
        map,
        map_bytes,
        geometry,
        chain,
        &mut provider,
        filters,
        transport,
        &WorkLimits::UNLIMITED,
        target_anchor,
    )?;
    match report.completion {
        Completion::Complete => Ok(SyncOutcome {
            ledger: report.ledger,
            charges: report.charges,
            matched_shards: report.matched_shards,
            unproductive_matches: report.unproductive_matches,
            covered_through: report.covered_through,
            settled_through: report.settled_through,
            provisional: report.provisional,
            map_refreshes: report.map_refreshes,
        }),
        // Without a store to keep it, incomplete work is a failure.
        Completion::Incomplete {
            reason: IncompleteReason::Overloaded { shard_id },
            ..
        } => Err(SyncError::Overloaded {
            shard_id,
            attempts: MAX_OVERLOAD_ATTEMPTS,
        }),
        Completion::Incomplete {
            reason: IncompleteReason::ContentFailed,
            ..
        } => Err(SyncError::Content(format!(
            "replies failed for {} directory entries",
            report.failed_entries.len()
        ))),
        Completion::Incomplete { reason, .. } => Err(SyncError::Invalid(format!(
            "the sync stopped short: {reason:?}"
        ))),
    }
}

/// Syncs a wallet's store to its accepted target, independently of publication tip.
///
/// See the module documentation for the shape of a sync. The store is the
/// wallet's memory: what it holds decides what is fetched, and what is
/// fetched is committed to it shard by shard. On return the store is
/// consistent whether the sync completed or not.
#[allow(clippy::too_many_arguments)]
pub fn sync_into<S: WalletStore>(
    store: &mut S,
    map: &ShardMap,
    map_bytes: u64,
    geometry: &ServiceGeometry,
    chain: &impl ChainView,
    scripts: &mut impl ScriptProvider,
    filters: &mut impl FilterSource,
    transport: &mut impl ShardTransport,
    limits: &WorkLimits,
    target_anchor: &Anchor,
) -> Result<SyncReport, SyncError> {
    sync_into_tracking(
        store,
        map,
        map_bytes,
        geometry,
        chain,
        scripts,
        filters,
        transport,
        limits,
        target_anchor,
        &mut None,
    )
}

/// Retains an adopted map even when a later request ends this call in error.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sync_into_tracking<S: WalletStore>(
    store: &mut S,
    map: &ShardMap,
    map_bytes: u64,
    geometry: &ServiceGeometry,
    chain: &impl ChainView,
    scripts: &mut impl ScriptProvider,
    filters: &mut impl FilterSource,
    transport: &mut impl ShardTransport,
    limits: &WorkLimits,
    target_anchor: &Anchor,
    adopted_map: &mut Option<ShardMap>,
) -> Result<SyncReport, SyncError> {
    if !transparent_shard::manifest::supported_schema(&geometry.schema) {
        return Err(SyncError::Schema {
            served: geometry.schema.clone(),
            expected: transparent_shard::SCHEMA,
        });
    }
    map.validate_supported().map_err(|error| {
        if transparent_filter::range_profile(&map.profile).is_none() {
            SyncError::UnknownProfile(map.profile.clone())
        } else {
            SyncError::Invalid(format!("shard map is unsupported: {error}"))
        }
    })?;
    let genesis = BlockHash::from_display_hex(&map.genesis_hash)?;
    BlockHash::from_display_hex(&target_anchor.hash)?;
    if target_anchor.height < map.start_height {
        return Err(SyncError::Invalid(
            "target precedes publication start".into(),
        ));
    }
    match chain.is_accepted(target_anchor.height, &target_anchor.hash) {
        Acceptance::Rejected => {
            return Err(SyncError::Invalid(
                "target anchor rejected by wallet chain".into(),
            ));
        }
        Acceptance::Unknown => {
            store.add_scripts(&scripts.scripts())?;
            return incomplete_at(
                store,
                IncompleteReason::ChainUnknown {
                    height: target_anchor.height,
                },
            );
        }
        Acceptance::Accepted => {}
    }
    if map
        .shards
        .last()
        .is_none_or(|s| s.end_height < target_anchor.height)
    {
        store.add_scripts(&scripts.scripts())?;
        return incomplete_at(
            store,
            IncompleteReason::PublicationBehind {
                height: target_anchor.height,
            },
        );
    }
    check_target_hash(map, target_anchor)?;
    let retained = store
        .events()?
        .iter()
        .map(|e| event_height(&e.event))
        .max()
        .unwrap_or(0);
    if let Some(a) = store.anchor()? {
        if a.height > target_anchor.height
            && chain.is_accepted(a.height, &a.hash) == Acceptance::Accepted
        {
            return Err(SyncError::AnchorRegressed {
                stored: a.height,
                offered: target_anchor.height,
            });
        }
    }
    if retained > target_anchor.height {
        return Err(SyncError::Invalid(
            "target below retained events; explicitly roll back to an accepted anchor first".into(),
        ));
    }

    // The store is bound to a publication lineage. A map from another
    // lineage is refused before anything is read from it.
    let identity = SetIdentity::of_schema(map, &geometry.schema);
    store.bind_set(&identity).map_err(|error| match error {
        StoreError::SetMismatch { stored, offered } => SyncError::MapDiverged(format!(
            "the store is bound to set {stored}, this map is {offered}"
        )),
        other => SyncError::Store(other),
    })?;
    let first_commit = store.last_commit()?;

    let Some(tip_entry) = map.shards.last() else {
        return Err(SyncError::Invalid("the map names no shards".into()));
    };
    let through = target_anchor.height;
    let _ = tip_entry;

    // A map that ends below the anchor the wallet accepted is not a newer
    // publication; if the wallet's chain still accepts that anchor, the
    // map is refused rather than silently rewound.
    if let Some(anchor) = store.anchor()? {
        if anchor.height > through
            && chain.is_accepted(anchor.height, &anchor.hash) == Acceptance::Accepted
        {
            return Err(SyncError::AnchorRegressed {
                stored: anchor.height,
                offered: through,
            });
        }
    }

    let mut charges = ByteCharges {
        map_bytes,
        ..Default::default()
    };
    let mut rolled_back_to: Option<u64> = None;
    let mut replaced_revisions: Vec<String> = Vec::new();

    // Every revision the map's re-cuts declare, by digest, looked up once.
    let declared = map.superseded_index();

    // Reorg detection over what the store holds. Every distinct block the
    // coverage rests on is asked of the wallet's chain, newest first; the
    // first rejected one rolls everything above the highest accepted block
    // below it back.
    let mut rests_on: BTreeMap<u64, String> = BTreeMap::new();
    // Settled ranges the map neither still publishes nor declares superseded.
    let mut rewritten: Vec<CoverageRange> = Vec::new();
    for entry in store.scripts()? {
        for range in store.coverage(&entry.script)? {
            rests_on
                .entry(range.end_height)
                .or_insert(range.terminal_block_hash.clone());
            if range.kind == CoverageKind::Settled && !vouches_for(map, &declared, &range) {
                rewritten.push(range);
            }
        }
    }
    let mut ancestor: Option<u64> = None;
    let mut unknown: Option<u64> = None;
    for (height, hash) in rests_on.iter().rev() {
        match chain.is_accepted(*height, hash) {
            Acceptance::Rejected => {
                // Roll back to the highest accepted block below this one.
                let mut below = map.start_height.saturating_sub(1);
                for (candidate, candidate_hash) in rests_on.range(..height).rev() {
                    if chain.is_accepted(*candidate, candidate_hash) == Acceptance::Accepted {
                        below = *candidate;
                        break;
                    }
                }
                ancestor = Some(below);
                break;
            }
            Acceptance::Accepted => break,
            Acceptance::Unknown => {
                unknown = Some(*height);
            }
        }
    }
    if let Some(height) = ancestor {
        store.rollback_above(&accepted_at(chain, map, height)?, "reorg")?;
        rolled_back_to = Some(height);
    } else if let Some(height) = unknown {
        if !rests_on.is_empty() {
            // Nothing could be confirmed. Reading on would either accept a
            // branch the wallet has not seen or roll back on a guess.
            return chain_unknown(
                store,
                map,
                target_anchor,
                charges,
                height,
                rolled_back_to,
                replaced_revisions,
                first_commit,
            );
        }
    }

    // Sealed content is immutable, so a sealed range the map now describes
    // differently, without declaring a re-cut of it, is judged by what the
    // wallet's chain says; see `judge_rewrite`. Only after the scan above,
    // which depends on the chain alone, has rolled back any reorg the chain
    // shows, and only for the ranges that rollback kept: a map cannot hold
    // back a reorg by changing history below it. A contradiction on the
    // wallet's own chain is refused before anything else is rolled back or
    // read; anything the chain cannot settle yet stops the sync as an
    // unknown block does.
    let mut contradiction: Option<&CoverageRange> = None;
    let mut unplaced: Option<u64> = None;
    let mut rederive_from: Option<u64> = None;
    let mut rederived: Vec<String> = Vec::new();
    for range in rewritten
        .iter()
        .filter(|range| ancestor.is_none_or(|kept| range.end_height <= kept))
    {
        match judge_rewrite(map, range, target_anchor, chain) {
            Rewrite::Reorg => {}
            Rewrite::Rederive => {
                rederive_from = Some(
                    rederive_from.map_or(range.start_height, |held| held.min(range.start_height)),
                );
                if !rederived.contains(&range.revision_digest) {
                    rederived.push(range.revision_digest.clone());
                }
            }
            Rewrite::Contradiction => {
                if contradiction.is_none_or(|held| held.start_height > range.start_height) {
                    contradiction = Some(range);
                }
            }
            Rewrite::Unsettled(height) => {
                unplaced = Some(unplaced.map_or(height, |held| held.max(height)));
            }
        }
    }
    if let Some(range) = contradiction {
        return Err(SyncError::SealedRewrite {
            start_height: range.start_height,
            revision_digest: range.revision_digest.clone(),
        });
    }
    if let Some(height) = unplaced {
        return chain_unknown(
            store,
            map,
            target_anchor,
            charges,
            height,
            rolled_back_to,
            replaced_revisions,
            first_commit,
        );
    }

    // Provisional reconciliation. A tail revision the map has moved past is
    // truncated and re-derived; one the map has sealed is promoted. A settled
    // range whose publication the chain left above its coverage is re-derived
    // the same way.
    let mut truncate_from: Option<u64> = rederive_from;
    for revision in rederived {
        if !replaced_revisions.contains(&revision) {
            replaced_revisions.push(revision);
        }
    }
    let mut promote: Vec<(u64, String)> = Vec::new();
    // A partially retrieved revision may have events and pending pages but no
    // completed coverage yet. Unfinished work under a revision the map no
    // longer publishes is dropped, and what it saved is rolled back from
    // where the revision began, never from wherever the map now puts its
    // shard id: a re-cut gives that id to another range.
    let mut dropped: Vec<u64> = Vec::new();
    let mut saved: Option<Vec<StoredEvent>> = None;
    for pending in store.pending()? {
        if map
            .shards
            .get(pending.shard_id as usize)
            .is_some_and(|published| published.manifest_digest == pending.revision_digest)
        {
            continue;
        }
        if saved.is_none() {
            saved = Some(store.events()?);
        }
        let lowest_saved = saved
            .iter()
            .flatten()
            .filter(|stored| stored.revision_digest == pending.revision_digest)
            .map(|stored| event_height(&stored.event))
            .min();
        let declared = declared.get(pending.revision_digest.as_str()).copied();
        match unfinished(&pending, declared, lowest_saved, chain) {
            Unfinished::Rewind(height) => {
                truncate_from = Some(truncate_from.map_or(height, |held| held.min(height)));
            }
            Unfinished::Drop => dropped.extend(pending.id),
        }
        if !replaced_revisions.contains(&pending.revision_digest) {
            replaced_revisions.push(pending.revision_digest);
        }
    }
    for range in store.provisional()? {
        match map.shards.get(range.shard_id as usize) {
            Some(published) if published.manifest_digest == range.revision_digest => {
                if published.sealed {
                    fetch_manifest(
                        published,
                        &previous_digest_of(map, published.shard_id),
                        map,
                        transport,
                        &mut charges,
                    )?;
                    promote.push((range.shard_id, range.revision_digest.clone()));
                }
            }
            _ => {
                truncate_from = Some(
                    truncate_from
                        .map_or(range.start_height, |held: u64| held.min(range.start_height)),
                );
                if !replaced_revisions.contains(&range.revision_digest) {
                    replaced_revisions.push(range.revision_digest.clone());
                }
            }
        }
    }
    if let Some(start) = truncate_from {
        // From the start of the shard now covering that height: at or below
        // everything the replaced revision saved, and a boundary the map names
        // a block for, so the rollback never depends on the wallet's chain
        // holding a hash inside a shard.
        let start = map
            .shard_for_height(start)
            .map_or(start, |entry| entry.start_height.min(start));
        let below = start.saturating_sub(1);
        if rolled_back_to.is_none_or(|held| held > below) {
            store.rollback_above(&accepted_at(chain, map, below)?, "replaced revision")?;
            rolled_back_to = Some(below);
        }
    }
    for (shard_id, digest) in promote {
        store.promote_provisional(shard_id, &digest)?;
    }

    let discard: Vec<u64> = store
        .pending()?
        .iter()
        .filter(|p| {
            p.target_anchor.as_ref() != Some(target_anchor)
                || p.id.is_some_and(|id| dropped.contains(&id))
        })
        .filter_map(|p| p.id)
        .collect();
    if !discard.is_empty() {
        store.commit_shard(ShardCommit {
            pending_complete: discard,
            ..Default::default()
        })?;
    }
    // Replies a lookahead sends early are held here until the walk asks for
    // them; see `ahead`. With nothing stashed both pass straight through.
    let transport = &mut ahead::Staged::new(transport);
    let filters = &mut ahead::StagedFilters::new(filters);
    // A budgeted sync walks in sequence: whether a later shard's queries are
    // sent at all depends on page work the walk discovers on the way.
    let look_ahead = transport.concurrency() > 1
        && store.pending_limit() > 0
        && limits.max_queries.is_none()
        && limits.max_private_bytes.is_none();

    // The wallet's script set, with its own required heights.
    store.add_scripts(&scripts.scripts())?;
    let mut scripts_added = 0usize;
    let mut clients = Clients {
        schema: geometry.schema.clone(),
        prepared: HashMap::new(),
    };
    let mut matched_shards: Vec<u64> = Vec::new();
    let mut unproductive = 0u64;
    let mut refreshes = 0u32;
    let mut held_map_digest: Option<String> = None;
    let mut active: Cow<'_, ShardMap> = Cow::Borrowed(map);
    let mut completion = Completion::Complete;
    let mut failures = Failures::default();
    // The map is adopted: from here on a failing sync must not leave the
    // filters and setups of revisions it no longer publishes behind.
    prune_to(store, &active)?;

    'passes: for pass in 0..=MAX_DISCOVERY_PASSES {
        if pass == MAX_DISCOVERY_PASSES {
            completion = Completion::Incomplete {
                reason: IncompleteReason::DiscoveryUnbounded,
                pending: store.pending()?.len(),
            };
            break;
        }
        let entries = store.scripts()?;
        let mut active_scripts: Vec<Vec<u8>> = Vec::new();

        // Pending page work first: it is already located, and finishing it
        // is the cheapest coverage available.
        let pending = store.pending()?;
        let mut by_revision: BTreeMap<(u64, String), Vec<PendingPages>> = BTreeMap::new();
        for item in pending {
            by_revision
                .entry((item.shard_id, item.revision_digest.clone()))
                .or_default()
                .push(item);
        }
        for ((shard_id, digest), mut items) in by_revision {
            // An entry that failed earlier in this sync, or too often, is
            // not walked again; one still owing dummies sends them.
            let mut kept = Vec::with_capacity(items.len());
            for item in items {
                if !hold(
                    store,
                    &mut failures.entries,
                    shard_id,
                    &digest,
                    &item.script,
                )? || failures.owes(shard_id, &digest, &item.script).is_some()
                {
                    kept.push(item);
                }
            }
            items = kept;
            if items.is_empty() {
                continue;
            }
            let Some(entry) = active.shards.get(shard_id as usize) else {
                continue;
            };
            if entry.manifest_digest != digest {
                // Its revision is gone, here only after a refresh mid-sync;
                // the ordinary planning re-derives the range.
                continue;
            }
            let entry = entry.clone();
            let previous_digest = previous_digest_of(&active, shard_id);
            let outcome = with_refusals(
                store,
                &active,
                &entry,
                &previous_digest,
                geometry,
                &mut clients,
                transport,
                &mut charges,
                limits,
                |store, prepared, transport, charges, manifest| {
                    finish_pages(
                        store,
                        &entry,
                        manifest,
                        &items,
                        prepared,
                        transport,
                        charges,
                        limits,
                        target_anchor,
                        chain,
                        &mut failures,
                    )
                },
            );
            match outcome {
                Ok(Some(stopped)) => {
                    completion = stopped;
                    break 'passes;
                }
                Ok(None) => {
                    if !matched_shards.contains(&shard_id) {
                        matched_shards.push(shard_id);
                    }
                    let events = store.events()?;
                    for item in &items {
                        if holds_history(&events, &item.script, &entry, target_anchor.height)
                            && !active_scripts.contains(&item.script)
                        {
                            active_scripts.push(item.script.clone());
                        }
                    }
                }
                Err(SyncError::StaleRevision { .. }) => {
                    // Handled by the ordinary planning below on the next map.
                }
                Err(other) => return Err(other),
            }
        }

        // Plan: which shards each script still needs.
        let through = target_anchor.height;
        let mut work: BTreeMap<usize, Vec<Vec<u8>>> = BTreeMap::new();
        for entry in &entries {
            let from = entry.required_from.max(active.start_height);
            if from > through {
                continue;
            }
            let coverage = store.coverage(&entry.script)?;
            for (gap_start, gap_end) in uncovered(&coverage, from, through) {
                for (index, shard) in active.shards.iter().enumerate() {
                    if shard.end_height < gap_start {
                        continue;
                    }
                    if shard.start_height > gap_end {
                        break;
                    }
                    let scripts = work.entry(index).or_default();
                    if !scripts.contains(&entry.script) {
                        scripts.push(entry.script.clone());
                    }
                }
            }
        }

        let mut uncached = Vec::new();
        for index in work.keys() {
            let entry = &active.shards[*index];
            if store
                .filter(&entry.manifest_digest, &entry.filter_hash)?
                .is_none()
            {
                uncached.push(entry.shard_id);
            }
        }
        if filters.uses_parents() {
            charges.filter_bytes += filters
                .prepare_parents(&active, &uncached, store)
                .map_err(|e| SyncError::Transport(e.to_string()))?;
        } else {
            // Every uncached filter in the walk is downloaded anyway; overlap
            // them rather than paying one round trip each.
            charges.filter_bytes += filters.prefetch_charged(&uncached);
        }
        let mut index_iter: Vec<usize> = work.keys().copied().collect();
        if look_ahead && !filters.uses_parents() {
            ahead::look_ahead(
                store,
                &active,
                genesis,
                &index_iter,
                &work,
                geometry,
                &mut clients,
                filters,
                transport,
                target_anchor,
                chain,
                &failures.entries,
                &mut charges,
            )?;
        }
        let mut position = 0usize;
        while position < index_iter.len() {
            let index = index_iter[position];
            let Some(entry) = active.shards.get(index).cloned() else {
                break;
            };
            let scripts_here = work.get(&index).cloned().unwrap_or_default();
            let previous_digest = previous_digest_of(&active, entry.shard_id);
            let result = read_shard_into(
                store,
                &active,
                &entry,
                &previous_digest,
                genesis,
                &scripts_here,
                geometry,
                &mut clients,
                filters,
                transport,
                &mut charges,
                limits,
                target_anchor,
                chain,
                &mut failures,
            );
            match result {
                Ok(ShardRead::Done {
                    matched,
                    unproductive: count,
                }) => {
                    unproductive += count;
                    if !matched.is_empty() {
                        if !matched_shards.contains(&entry.shard_id) {
                            matched_shards.push(entry.shard_id);
                        }
                        for script in matched {
                            if !active_scripts.contains(&script) {
                                active_scripts.push(script);
                            }
                        }
                    }
                    position += 1;
                }
                Ok(ShardRead::Unproductive { count }) => {
                    unproductive += count;
                    position += 1;
                }
                Ok(ShardRead::Stopped(stopped)) => {
                    completion = stopped;
                    break 'passes;
                }
                Err(SyncError::StaleRevision { stale, .. }) => {
                    // The service withdrew this revision while the sync was
                    // reading it. Refresh the map, check it is the same set
                    // continued, roll this shard's provisional coverage back,
                    // and re-derive from whatever replaced it.
                    //
                    // Nothing read ahead survives a refresh: the rest of this
                    // pass is walked in sequence.
                    ahead::clear(transport, filters, &mut clients);
                    if refreshes >= MAX_MAP_REFRESHES
                        || (stale.map_sha256.is_some()
                            && stale.map_sha256.as_deref() == held_map_digest.as_deref())
                    {
                        return Err(SyncError::StaleRevision {
                            shard_id: entry.shard_id,
                            stale,
                            refreshes,
                        });
                    }
                    let (covered, _) = coverage_summary(store, target_anchor.height)?;
                    let (fresh, digest) = refresh_map(&active, covered, filters, &mut charges)?;
                    check_target_hash(&fresh, target_anchor)?;
                    if fresh
                        .shards
                        .last()
                        .is_none_or(|s| s.end_height < target_anchor.height)
                    {
                        completion = Completion::Incomplete {
                            reason: IncompleteReason::PublicationBehind {
                                height: target_anchor.height,
                            },
                            pending: store.pending()?.len(),
                        };
                        *adopted_map = Some(fresh.clone());
                        active = Cow::Owned(fresh);
                        prune_to(store, &active)?;
                        break 'passes;
                    }
                    refreshes += 1;
                    held_map_digest = Some(digest);
                    let Some(resume) = fresh
                        .shards
                        .iter()
                        .position(|candidate| candidate.shard_id == entry.shard_id)
                    else {
                        // The refreshed map no longer advertises this range.
                        *adopted_map = Some(fresh.clone());
                        active = Cow::Owned(fresh);
                        prune_to(store, &active)?;
                        break;
                    };
                    if fresh.shards[resume].manifest_digest == stale.revision {
                        return Err(SyncError::StaleRevision {
                            shard_id: entry.shard_id,
                            stale,
                            refreshes,
                        });
                    }
                    check_resume(&fresh.shards[resume], &entry).map_err(SyncError::MapDiverged)?;
                    let resume_start = fresh.shards[resume].start_height;
                    let below = resume_start.saturating_sub(1);
                    store.rollback_above(
                        &accepted_at(chain, &active, below)?,
                        "revision withdrawn mid-sync",
                    )?;
                    if rolled_back_to.is_none_or(|held| held > below) {
                        rolled_back_to = Some(below);
                    }
                    if !replaced_revisions.contains(&stale.revision) {
                        replaced_revisions.push(stale.revision.clone());
                    }
                    *adopted_map = Some(fresh.clone());
                    active = Cow::Owned(fresh);
                    prune_to(store, &active)?;
                    // Re-plan against the new map from this shard on.
                    let mut rest: Vec<usize> = (resume..active.shards.len())
                        .take_while(|i| active.shards[*i].start_height <= through)
                        .collect();
                    index_iter.truncate(position);
                    index_iter.append(&mut rest);
                    for later in resume..active.shards.len() {
                        work.entry(later).or_insert_with(|| scripts_here.clone());
                    }
                }
                Err(other) => return Err(other),
            }
        }
        // Anything read ahead and not consumed belongs to this pass only.
        ahead::clear(transport, filters, &mut clients);

        if pass == 0 {
            // A call that stopped for its budget, or failed, after saving a
            // script's history never reported that activity, and coverage now
            // keeps the history from being read again. Report what the store
            // holds, as a completed read of it would have.
            for script in saved_activity(store, &failures.entries, target_anchor.height)? {
                if !active_scripts.contains(&script) {
                    active_scripts.push(script);
                }
            }
        }
        let added = scripts.on_activity(&active_scripts);
        if added.is_empty() {
            break;
        }
        scripts_added += store.add_scripts(&added)?;
    }

    // Prune against the map this pass ended on: a revision withdrawn during
    // the walk must leave no cached filter or setup either.
    prune_to(store, &active)?;

    let (covered_through, settled_through) = coverage_summary(store, target_anchor.height)?;
    if completion == Completion::Complete {
        if covered_through < target_anchor.height {
            // A failed entry leaves its script uncovered over its shard.
            completion = Completion::Incomplete {
                reason: if failures.entries.is_empty() {
                    IncompleteReason::DiscoveryUnbounded
                } else {
                    IncompleteReason::ContentFailed
                },
                pending: store.pending()?.len(),
            };
        } else if !store.pending()?.is_empty() {
            completion = Completion::Incomplete {
                reason: IncompleteReason::PendingLimit,
                pending: store.pending()?.len(),
            };
        } else if !store.ledger()?.unresolved().is_empty() {
            completion = Completion::Incomplete {
                reason: IncompleteReason::UnresolvedSpends,
                pending: 0,
            };
        } else {
            store.commit_anchor(target_anchor, settled_through, covered_through)?;
        }
    }
    matched_shards.sort_unstable();
    let mut failed = failures.entries;
    failed.sort_by(|a, b| (a.shard_id, &a.script).cmp(&(b.shard_id, &b.script)));
    Ok(SyncReport {
        ledger: store.ledger()?,
        charges,
        matched_shards,
        unproductive_matches: unproductive,
        covered_through,
        settled_through,
        provisional: provisional_of(store, &active)?,
        map_refreshes: refreshes,
        completion,
        rolled_back_to,
        replaced_revisions,
        scripts_added,
        commits: store.last_commit()? - first_commit,
        failed_entries: failed,
    })
}

/// What becomes of unfinished page work under a revision the map no longer
/// publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unfinished {
    /// Dropped, and what the revision saved stays.
    Drop,
    /// Dropped, and the store rolls back from this height.
    Rewind(u64),
}

/// Decides [`Unfinished`] for one item, from what the wallet itself stored.
///
/// Every event an item saved lies at or below the target it was read for,
/// which the store keeps with it. So when a declared re-cut replaced the
/// sealed revision and the wallet's chain still accepts that target block,
/// what was saved is history on the chain the wallet follows, which a re-cut
/// does not change: it stays, the script's gap is read again under the shard
/// now covering it, and events are kept once per outpoint. The declaration
/// only says this is a re-cut; nothing it claims about heights or blocks is
/// relied on.
///
/// Otherwise what the revision saved is rolled back from the lowest height it
/// saved anything at, or the declared start if that is lower; never from the
/// declared start alone, which the wallet has not checked. A revision that
/// saved nothing leaves nothing to roll back.
fn unfinished(
    pending: &PendingPages,
    declared: Option<&transparent_filter::SupersededShard>,
    lowest_saved: Option<u64>,
    chain: &impl ChainView,
) -> Unfinished {
    let declared = declared.filter(|declared| declared.shard_id == pending.shard_id);
    let target_held = pending.target_anchor.as_ref().is_some_and(|target| {
        chain.is_accepted(target.height, &target.hash) == Acceptance::Accepted
    });
    if declared.is_some_and(|declared| declared.sealed) && target_held {
        return Unfinished::Drop;
    }
    match lowest_saved {
        Some(lowest) => Unfinished::Rewind(
            declared.map_or(lowest, |declared| declared.start_height.min(lowest)),
        ),
        None => Unfinished::Drop,
    }
}

/// Whether `script` has stored history inside `entry`'s range, up to the
/// target.
///
/// By height rather than by the revision that recorded it: an event is kept
/// once per outpoint, so history first read under a revision a re-cut has
/// since replaced keeps that revision's name when the new shard is read.
fn holds_history(
    events: &[StoredEvent],
    script: &[u8],
    entry: &transparent_filter::ShardMapEntry,
    through: u64,
) -> bool {
    let range = entry.start_height..=entry.end_height.min(through);
    events
        .iter()
        .any(|stored| stored.script == script && range.contains(&event_height(&stored.event)))
}

/// Deletes the cached filters and setups of every revision `map` does not
/// publish. Called once a map is adopted, before anything is read under it.
fn prune_to<S: WalletStore>(store: &mut S, map: &ShardMap) -> Result<(), SyncError> {
    let queryable: Vec<&str> = map
        .shards
        .iter()
        .map(|entry| entry.manifest_digest.as_str())
        .collect();
    Ok(store.prune_caches(&queryable)?)
}

/// The scripts with saved history through `through`, in the store's order,
/// leaving out history saved under an entry [`held`] out of this sync. Each
/// event is judged under the revision it was saved by, so history a re-cut
/// kept, already checked when read, is still reported.
fn saved_activity<S: WalletStore>(
    store: &S,
    failed: &[FailedEntry],
    through: u64,
) -> Result<Vec<Vec<u8>>, SyncError> {
    let mut active: Vec<Vec<u8>> = Vec::new();
    let mut judged: BTreeMap<(u64, String, Vec<u8>), bool> = BTreeMap::new();
    for stored in store.events()? {
        if event_height(&stored.event) > through || active.contains(&stored.script) {
            continue;
        }
        let key = (stored.shard_id, stored.revision_digest, stored.script);
        let excluded = match judged.get(&key) {
            Some(&excluded) => excluded,
            None => {
                let excluded = held(store, failed, key.0, &key.1, &key.2)?;
                judged.insert(key.clone(), excluded);
                excluded
            }
        };
        if !excluded {
            active.push(key.2);
        }
    }
    Ok(active)
}

fn previous_digest_of(map: &ShardMap, shard_id: u64) -> String {
    shard_id
        .checked_sub(1)
        .and_then(|before| map.shards.get(before as usize))
        .map(|entry| entry.manifest_digest.clone())
        .unwrap_or_default()
}

/// Heights through which every script is covered from its required height:
/// provisional coverage included, then settled only. The minimum over
/// scripts, so one script's gap holds the whole wallet's figure down.
fn coverage_summary<S: WalletStore>(store: &S, through: u64) -> Result<(u64, u64), SyncError> {
    Ok(crate::engine::progress::coverage(store, Some(through))?)
}

fn provisional_of<S: WalletStore>(
    store: &S,
    map: &ShardMap,
) -> Result<Vec<ProvisionalCoverage>, SyncError> {
    let mut provisional = crate::engine::progress::provisional(store)?;
    for held in &mut provisional {
        held.revision = map
            .shards
            .get(held.shard_id as usize)
            .filter(|entry| entry.manifest_digest == held.manifest_digest)
            .map_or(0, |entry| entry.revision);
    }
    Ok(provisional)
}

#[cfg(test)]
mod tests;

/// The chain walk over real built tables, read directly: every check a walk
/// makes, and the run cache stopping it.
#[cfg(test)]
mod walk_tests;
