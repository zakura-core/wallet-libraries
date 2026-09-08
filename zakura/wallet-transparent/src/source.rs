//! Driving one run of the private transparent ledger.
//!
//! The order of what follows is load-bearing, so it is stated once here.
//!
//! 1. Take the shard map and cut it down to the shards whose boundaries this
//!    wallet has accepted. Anything past that is unverifiable, and a map is
//!    gapless, so an unverifiable shard makes every later one unreachable.
//! 2. Take the service's declared geometry and refuse it if it is not the
//!    schema this build reads.
//! 3. Group the account's scripts by where each has already been read to, and
//!    run once per group.
//! 4. Commit each run's events and the coverage that explains them together.
//!
//! Step 4 is the one that is easy to get subtly wrong. Committing events
//! without coverage means paying to re-derive them; committing coverage without
//! events means never looking at that range again. Coverage advances only for a
//! run that completed, so a failure anywhere above leaves the range unread
//! rather than recorded as empty.

use serde::Deserialize;

use transparent_wallet::sync::ServiceGeometry;
use transparent_wallet::transport::{FilterSource, ShardTransport};
use zakura_wallet_store::WalletDb;
use zakura_wallet_sync::{TransparentProgress, TransparentSource, transparent::BoxError};
use zcash_protocol::consensus::Parameters;

use crate::{Endpoints, Error, chain, ledger, scripts};

/// The wallet's transparent ledger, over a pair of services.
///
/// Generic over the network parameters because an account's birthday and its
/// keys are read through them, and over nothing else: the transports are
/// constructed per run, so a failed run leaves no connection state behind for
/// the next one to inherit.
pub struct TransparentPir<P> {
    endpoints: Endpoints,
    params: P,
}

impl<P: Parameters + Send + Sync + 'static> TransparentPir<P> {
    /// Points the ledger at a filter service and a shard service.
    pub fn new(endpoints: Endpoints, params: P) -> Self {
        Self { endpoints, params }
    }

    /// The services this reads from.
    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
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
        let (map_bytes, map_cost) = filters
            .shard_map()
            .map_err(|e| Error::Transport(format!("shard map: {e}")))?;
        let mut map: transparent_filter::ShardMap = serde_json::from_slice(&map_bytes)
            .map_err(|e| Error::Invalid(format!("shard map: {e}")))?;

        let kept = chain::accepted_prefix(&mut map, db)?;
        if kept == 0 {
            // Not an error, and not an empty balance either. The wallet has not
            // scanned down to the range the shards cover, so there is nothing
            // it could yet check an answer against.
            return Ok(TransparentProgress::default());
        }

        let (init_bytes, _) = transport
            .init()
            .map_err(|e| Error::Transport(format!("shard service init: {e}")))?;
        let geometry = geometry_of(&init_bytes, &map)?;

        let accounts = db.accounts(&self.params)?;
        let mut progress = TransparentProgress::default();

        for account in accounts {
            let watched = scripts::watched_scripts(db, account.id, account.birthday)?;
            if watched.is_empty() {
                continue;
            }

            for (start, group) in &watched.groups {
                let outcome = transparent_wallet::sync(
                    &map,
                    map_cost,
                    &geometry,
                    filters,
                    transport,
                    group,
                    *start,
                )
                .map_err(|e| Error::Sync(e.to_string()))?;

                let recovered = ledger::into_ledger(&outcome, account.id, group);
                progress.outputs += recovered.outputs.len();
                progress.spends += recovered.spends.len();
                db.apply_transparent_ledger(&recovered)?;
            }

            let state = db.transparent_state(account.id, account.birthday)?;
            progress.unresolved += state.unresolved_spends as usize;
            progress.settled_through = min_option(progress.settled_through, state.settled_through);
            progress.covered_through = min_option(progress.covered_through, state.covered_through);
        }

        Ok(progress)
    }
}

#[cfg(feature = "https-client")]
impl<P: Parameters + Send + Sync + 'static> TransparentSource for TransparentPir<P> {
    fn recover(&self, db: &mut WalletDb) -> Result<TransparentProgress, BoxError> {
        let mut filters = crate::http::HttpFilters::new(&self.endpoints.filters_url)?;
        let mut shards = crate::http::HttpShards::new(&self.endpoints.shards_url)?;
        Ok(self.recover_with(db, &mut filters, &mut shards)?)
    }
}

/// What the shard service says about itself.
///
/// Only the fields a wallet has to check or re-derive from. The scheme
/// parameters are here because they are checked against the pinned geometry,
/// not because they are adopted.
#[derive(Deserialize)]
struct Init {
    schema: String,
    profile: String,
    network: String,
    genesis_hash: String,
    directory_scheme: ipir_sp::YpirSchemeParams,
    directory_setup_seed: u64,
    pages_scheme: ipir_sp::YpirSchemeParams,
    pages_setup_seed: u64,
}

/// Reads the service's geometry, and refuses one that does not match the map.
///
/// The chain identity, the range profile and the schema are all checked before
/// a query is prepared. Two services that disagreed about any of them would
/// still each answer, and the answers would be rows from different partitions
/// of different chains, decoded as though they were one.
fn geometry_of(bytes: &[u8], map: &transparent_filter::ShardMap) -> Result<ServiceGeometry, Error> {
    let init: Init =
        serde_json::from_slice(bytes).map_err(|e| Error::Invalid(format!("init: {e}")))?;

    if init.schema != crate::SCHEMA {
        return Err(Error::Schema {
            served: init.schema,
            expected: crate::SCHEMA,
        });
    }
    if init.genesis_hash != map.genesis_hash {
        return Err(Error::Invalid(
            "the shard service and the shard map describe different chains".into(),
        ));
    }
    if init.network != map.network || init.profile != map.profile {
        return Err(Error::Invalid(format!(
            "the shard service serves {}/{} and the map is {}/{}",
            init.network, init.profile, map.network, map.profile
        )));
    }

    Ok(ServiceGeometry {
        schema: init.schema,
        directory_scheme: init.directory_scheme,
        directory_setup_seed: init.directory_setup_seed,
        pages_scheme: init.pages_scheme,
        pages_setup_seed: init.pages_setup_seed,
    })
}

/// The lower of two coverages, treating absence as "no constraint".
///
/// A balance is only as current as its least current part, so coverage across
/// accounts is a minimum rather than a maximum or an average.
fn min_option<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, b) => b,
    }
}
