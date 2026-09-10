//! Driving one run of the private transparent ledger.
//!
//! The order of what follows is load-bearing, so it is stated once here.
//!
//! 1. Capture the wallet's accepted scanned target independently of the map.
//!    Keep it fixed throughout the run. A larger published shard can be read
//!    whole while only its accepted prefix is committed.
//! 2. Take the service's declared geometry and refuse it if it is not the
//!    schema this build reads, or not the chain the map describes.
//! 3. Keep every account's window of unused addresses full, read every derived
//!    script with the height it needs, and sync the ledger — the library
//!    continues whatever the store already holds, detects a reorg against the
//!    wallet's own chain, and stops at the work limits.
//! 4. If the sync found activity, the gap limit may have moved: widen again,
//!    and if that produced new scripts, sync again so they are read over their
//!    whole required range. Bounded, so a wallet whose every new address is
//!    used cannot loop forever inside one run.
//!
//! Everything a shard yields is committed by the store as it is retrieved, so
//! a failure anywhere leaves coverage exactly where the last commit put it. A
//! sync that stops short says why, and that reason is kept beside the balance
//! so the interface can show it.

use std::collections::BTreeSet;

use transparent_wallet::{
    Completion, IncompleteReason, ServiceGeometry, StaticScripts, SyncReport, WorkLimits,
    sync_into,
    transport::{FilterSource, ShardTransport},
};
use zakura_wallet_store::WalletDb;
use zakura_wallet_sync::{
    TransparentCompletion, TransparentProgress, TransparentSource, transparent::BoxError,
};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::{
    ChainSnapshot, Endpoints, Error, PirStore, scripts,
    stop::{StopSignal, Stoppable},
};

/// How many times one run will widen the address window and sync again.
///
/// Each pass exists because the one before it found activity at the edge of
/// the window. Sixteen is more than any ordinary wallet needs and small enough
/// that a wallet paid at every fresh address in turn still returns.
const MAX_PASSES: usize = 16;

/// The wallet's transparent ledger, over a pair of services.
///
/// Generic over the network parameters because an account's birthday and its
/// keys are read through them, and over nothing else: the transports are
/// constructed per run, so a failed run leaves no connection state behind for
/// the next one to inherit.
pub struct TransparentPir<P> {
    endpoints: Endpoints,
    params: P,
    limits: WorkLimits,
    stop: StopSignal,
}

impl<P: Parameters + Send + Sync + 'static> TransparentPir<P> {
    /// Points the ledger at a filter service and a shard service, with the
    /// mobile work limits.
    pub fn new(endpoints: Endpoints, params: P) -> Self {
        Self {
            endpoints,
            params,
            limits: crate::MOBILE_LIMITS,
            stop: StopSignal::new(),
        }
    }

    /// Lets `signal` end a run between requests.
    ///
    /// A run that is stopped keeps every shard it committed and records
    /// `stopped` as the reason it fell short; the next run continues from
    /// there. Without a signal a run ends only when it finishes or fails,
    /// and the wallet's own stop waits for it.
    pub fn with_stop(mut self, signal: StopSignal) -> Self {
        self.stop = signal;
        self
    }

    /// Bounds the private work one run may do.
    pub fn with_limits(mut self, limits: WorkLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The services this reads from.
    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// The limits one run works under.
    pub fn limits(&self) -> &WorkLimits {
        &self.limits
    }

    /// Runs one recovery against caller-supplied transports.
    ///
    /// Exposed so a test — or a wallet with its own HTTP stack — can drive the
    /// whole thing without this crate's transports. Everything above the
    /// transports is the same code either way, which is the point.
    pub fn recover_with(
        &self,
        db: &mut WalletDb,
        filters: &mut impl FilterSource,
        transport: &mut impl ShardTransport,
    ) -> Result<TransparentProgress, Error> {
        let mut filters = Stoppable::new(filters, self.stop.clone());
        let mut transport = Stoppable::new(transport, self.stop.clone());
        let result = self.run(db, &mut filters, &mut transport);
        if result.is_err() {
            // A run that did not finish must not leave `sync-in-progress`
            // beside the balance, which would read as a sync still running.
            // The reason is a fixed word rather than the error: the error
            // names hosts, and this is kept in the wallet and shown.
            let reason = if self.stop.is_stopped() {
                "stopped"
            } else {
                "failed"
            };
            db.put_transparent_completion(reason)?;
        }
        result
    }

    fn run(
        &self,
        db: &mut WalletDb,
        filters: &mut impl FilterSource,
        transport: &mut impl ShardTransport,
    ) -> Result<TransparentProgress, Error> {
        db.put_transparent_completion("sync-in-progress")?;
        let (map_bytes, map_cost) = filters
            .shard_map()
            .map_err(|e| Error::Transport(format!("shard map: {e}")))?;
        let map: transparent_filter::ShardMap = serde_json::from_slice(&map_bytes)
            .map_err(|e| Error::Invalid(format!("shard map: {e}")))?;

        map.check_shape()
            .map_err(|e| Error::Invalid(format!("shard map: {e}")))?;
        check_map_chain(&map, &self.params)?;
        let Some((_, scanned)) = db.block_height_extrema()? else {
            let reason = format!(
                "chain-unknown:{}",
                map.shards
                    .first()
                    .map_or(map.start_height, |s| s.end_height)
            );
            db.put_transparent_completion(&reason)?;
            return Ok(TransparentProgress {
                completion: TransparentCompletion::Incomplete(reason),
                ..TransparentProgress::default()
            });
        };
        let target_height = u64::from(u32::from(scanned));
        let target_hash = db
            .accepted_block_hash(scanned)?
            .ok_or_else(|| Error::Invalid("accepted scan tip has no hash".into()))?;
        let target = transparent_wallet::Anchor {
            height: target_height,
            hash: transparent_filter::BlockHash::from_internal_bytes(target_hash.0)
                .to_display_hex(),
        };

        let (init_bytes, _) = transport
            .init()
            .map_err(|e| Error::Transport(format!("shard service init: {e}")))?;
        let geometry = geometry_of(&init_bytes, &map)?;

        let (receives_before, spends_before) = db.transparent_event_counts()?;
        let mut last: Option<SyncReport> = None;
        let mut rolled_back_to: Option<BlockHeight> = None;
        let mut outside_coverage = 0;
        let mut asked: BTreeSet<Vec<u8>> = BTreeSet::new();
        // Set when the window was still moving after the last allowed pass:
        // scripts exist that no sync has read, and the run must say so.
        let mut unbounded = false;

        for pass in 0..=MAX_PASSES {
            if self.stop.is_stopped() {
                return Err(Error::Transport(crate::stop::STOPPED.into()));
            }
            widen_windows(db, &self.params)?;
            let watched = scripts::watched_scripts(db, &self.params, map.start_height)?;
            outside_coverage = watched.outside_coverage;
            if watched.is_empty() {
                break;
            }
            let now: BTreeSet<Vec<u8>> = watched.entries.iter().map(|e| e.script.clone()).collect();
            if now == asked {
                // The last sync moved no gap limit: nothing new to read.
                break;
            }
            if pass == MAX_PASSES {
                unbounded = true;
                break;
            }
            asked = now;

            // The snapshot is taken before the store borrows the wallet, and
            // covers exactly the heights the sync can ask about.
            let snapshot = ChainSnapshot::load_at(db, &map, &target)?;
            let report = {
                let mut store = PirStore::new(db, watched.owners);
                let mut provider = StaticScripts(watched.entries);
                sync_into(
                    &mut store,
                    &map,
                    map_cost,
                    &geometry,
                    &snapshot,
                    &mut provider,
                    filters,
                    transport,
                    &self.limits,
                    &target,
                )?
            };
            if let Some(height) = report.rolled_back_to {
                let height = self::height(height)?;
                rolled_back_to = Some(rolled_back_to.map_or(height, |held| held.min(height)));
            }
            // Discovery continues while coverage is complete. A spend whose
            // receive lies below the wallet's floor leaves the balance
            // unresolved, and says so, but every script in scope has been
            // read over its whole range: the window can still move, and a
            // receive at its edge is money the wallet should know about now
            // rather than after another run. Any other stop is short
            // coverage, and widening over it would read the new scripts
            // over less than they need.
            // The library reports unresolved spends only once every script
            // in scope is covered to the target; that is what makes widening
            // safe. Checked here rather than trusted, so a library that ever
            // reported them early would end the run short rather than read
            // the new scripts over less than they need.
            let coverage_complete = match report.completion {
                Completion::Complete => true,
                Completion::Incomplete {
                    reason: IncompleteReason::UnresolvedSpends,
                    ..
                } => report.covered_through >= target_height,
                Completion::Incomplete { .. } => false,
            };
            last = Some(report);
            if !coverage_complete {
                break;
            }
        }

        let (receives_after, spends_after) = db.transparent_event_counts()?;
        let completion = if unbounded {
            TransparentCompletion::Incomplete("discovery-unbounded".into())
        } else {
            match &last {
                Some(report) => completion_of(&report.completion),
                None => TransparentCompletion::Complete,
            }
        };
        db.put_transparent_completion(&completion.to_string())?;

        Ok(TransparentProgress {
            // Net of any rollback the run made: a replaced tail or a reorg can
            // leave the ledger holding fewer events than it started with.
            outputs: receives_after.saturating_sub(receives_before) as usize,
            spends: spends_after.saturating_sub(spends_before) as usize,
            unresolved: last.as_ref().map_or(0, |r| r.ledger.unresolved().len()),
            settled_through: last
                .as_ref()
                .map(|r| height(r.settled_through))
                .transpose()?,
            covered_through: last
                .as_ref()
                .map(|r| height(r.covered_through))
                .transpose()?,
            completion,
            pending: db.transparent_pending()?.len(),
            rolled_back_to,
            outside_coverage,
        })
    }
}

#[cfg(feature = "https-client")]
impl<P: Parameters + Send + Sync + 'static> TransparentSource for TransparentPir<P> {
    fn recover(&self, db: &mut WalletDb) -> Result<TransparentProgress, BoxError> {
        use transparent_wallet::http::{HttpFilterSource, HttpOptions, HttpShardTransport};
        // Generous, because a private query is evaluated over a whole table
        // and a mobile connection is not fast. A wallet that timed out mid-run
        // keeps what it committed, but pays for the request again.
        let options = HttpOptions {
            timeout: std::time::Duration::from_secs(120),
            ..HttpOptions::default()
        };
        let mut filters = HttpFilterSource::new(&self.endpoints.filters_url, &options)?;
        let mut shards = HttpShardTransport::new(&self.endpoints.shards_url, &options)?;
        Ok(self.recover_with(db, &mut filters, &mut shards)?)
    }
}

/// Keeps every account's window of unused transparent addresses full.
///
/// Cheap when nothing moved: the gap query finds the window already wide
/// enough and derives nothing. Here rather than in the engine, because the
/// window moves *during* a run — a recovered receive marks its address used —
/// and the scripts that produces have to be read in the same run.
fn widen_windows<P: Parameters>(db: &mut WalletDb, params: &P) -> Result<(), Error> {
    let limits = zakura_wallet_store::GapLimits::default();
    for account in db.accounts(params)? {
        db.maintain_transparent_addresses(params, account.id, &limits)?;
    }
    Ok(())
}

/// Refuses a map that describes a chain other than the wallet's.
///
/// The service and the map are checked against each other further down; this
/// checks both against the wallet. Without it a mainnet wallet handed a
/// testnet set would find every boundary hash unknown and stop short with
/// `chain-unknown`, which is true and useless: the configuration is wrong, and
/// the wallet should say so rather than wait for a chain it will never scan.
fn check_map_chain<P: Parameters>(
    map: &transparent_filter::ShardMap,
    params: &P,
) -> Result<(), Error> {
    use zcash_protocol::consensus::NetworkType;
    let expected = match params.network_type() {
        NetworkType::Main => "main",
        NetworkType::Test => "test",
        NetworkType::Regtest => "regtest",
    };
    if map.network != expected {
        return Err(Error::Invalid(format!(
            "the shard map describes the {} chain and this wallet is on {expected}",
            map.network
        )));
    }
    if params.network_type() == NetworkType::Main
        && map.genesis_hash != transparent_filter::MAINNET_GENESIS_DISPLAY
    {
        return Err(Error::Invalid(
            "the shard map names a genesis block that is not mainnet's".into(),
        ));
    }
    Ok(())
}

/// Reads the service's geometry, and refuses one that does not match the map.
///
/// The chain identity, the range profile and the schema are all checked before
/// a query is prepared. Two services that disagreed about any of them would
/// still each answer, and the answers would be rows from different partitions
/// of different chains, decoded as though they were one. The library checks
/// the schema again and every geometry against its registry; what it cannot
/// check is that the map came from the same chain, because it only ever sees
/// the two documents together.
fn geometry_of(bytes: &[u8], map: &transparent_filter::ShardMap) -> Result<ServiceGeometry, Error> {
    let geometry =
        transparent_wallet::parse_init(bytes).map_err(|e| Error::Invalid(format!("init: {e}")))?;
    if geometry.schema != crate::SCHEMA {
        return Err(Error::Schema {
            served: geometry.schema,
            expected: crate::SCHEMA,
        });
    }
    let init: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| Error::Invalid(format!("init: {e}")))?;
    let field = |name: &str| init[name].as_str().unwrap_or_default().to_owned();
    if field("genesis_hash") != map.genesis_hash {
        return Err(Error::Invalid(
            "the shard service and the shard map describe different chains".into(),
        ));
    }
    if field("network") != map.network || field("profile") != map.profile {
        return Err(Error::Invalid(format!(
            "the shard service serves {}/{} and the map is {}/{}",
            field("network"),
            field("profile"),
            map.network,
            map.profile
        )));
    }
    Ok(geometry)
}

/// The library's completion, in the words the interface shows.
fn completion_of(completion: &Completion) -> TransparentCompletion {
    match completion {
        Completion::Complete => TransparentCompletion::Complete,
        Completion::Incomplete { reason, .. } => TransparentCompletion::Incomplete(match reason {
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
        }),
    }
}

/// Reject heights the wallet cannot represent.
fn height(value: u64) -> Result<BlockHeight, Error> {
    u32::try_from(value)
        .map(BlockHeight::from_u32)
        .map_err(|_| Error::Invalid("height exceeds chain range".into()))
}
