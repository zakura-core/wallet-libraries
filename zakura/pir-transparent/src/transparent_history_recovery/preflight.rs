//! Checks a pass makes before any filter or private retrieval.

use std::collections::BTreeMap;

use transparent_filter::{MAINNET_GENESIS_DISPLAY, NETWORK, ShardMap, wire::MAX_SUPERSEDED};
use transparent_wallet::transport::{FilterSource, ShardTransport};
use transparent_wallet::{Acceptance, Anchor, ChainView, ServiceGeometry, WalletStore};
use zcash_client_backend::data_api::transparent_ledger::TransparentAddressWatchSet;

use super::{SCHEMA, TransparentHistoryRecovery};
use crate::convert::{address_script, height_u64};
use crate::error::{RecoveryError, ensure_valid, failure};

/// The watch set's target as the reference client names it, refusing a watch set
/// without one or a target `chain` does not accept.
pub(super) fn accepted_target<A: Copy>(
    watch: &TransparentAddressWatchSet<A>,
    chain: &impl ChainView,
) -> Result<Anchor, RecoveryError> {
    let context = watch
        .context()
        .ok_or_else(|| RecoveryError::Invalid("no locally accepted recovery target".into()))?;
    let target = Anchor {
        height: height_u64(context.target.height),
        hash: context.target.hash.to_string(),
    };
    ensure_valid(
        chain.is_accepted(target.height, &target.hash) == Acceptance::Accepted,
        "target is not independently accepted",
    )?;
    Ok(target)
}

/// Refuses a filter source using the parent filter experiment, whose selective child
/// requests leak coarse activity.
pub(crate) fn refuse_parent_filters(filters: &impl FilterSource) -> Result<(), RecoveryError> {
    ensure_valid(
        !filters.uses_parents(),
        "parent filter sources are not supported",
    )
}

/// Refuses a map for another network or genesis block: the wallet's chain is
/// mainnet's, and another chain's map cannot cover it.
pub(crate) fn ensure_mainnet_publication(map: &ShardMap) -> Result<(), RecoveryError> {
    ensure_valid(
        map.network == NETWORK && map.genesis_hash == MAINNET_GENESIS_DISPLAY,
        "publication is not for Zcash mainnet",
    )
}

impl TransparentHistoryRecovery {
    /// Refuses a watch set with more addresses than the script limit, a companion
    /// retaining more scripts than it, or a watch set naming an address twice.
    pub(super) fn check_watch_set<A>(
        &self,
        watch: &TransparentAddressWatchSet<A>,
    ) -> Result<(), RecoveryError> {
        ensure_valid(
            watch.addresses.len() <= self.config.scripts
                && self.store.scripts().map_err(failure)?.len() <= self.config.scripts,
            "script limit exceeded",
        )?;
        let addresses: BTreeMap<Vec<u8>, _> = watch
            .addresses
            .iter()
            .map(|entry| (address_script(entry.address), entry))
            .collect();
        ensure_valid(
            addresses.len() == watch.addresses.len(),
            "duplicate watch address",
        )
    }

    /// Refuses a map with more shards and declarations at or above `floor`
    /// than the shard limit, or more declarations in all than
    /// [`MAX_SUPERSEDED`].
    pub(super) fn check_limits(&self, map: &ShardMap, floor: u64) -> Result<(), RecoveryError> {
        check_publication_limits(map, floor, self.config.shards)
    }
}

/// The lowest height a pass needs the wallet's chain for: the lowest required
/// height in `watch`, capped at `target`, or 0 when nothing is watched.
pub(super) fn watch_floor<A>(watch: &TransparentAddressWatchSet<A>, target: u64) -> u64 {
    watch
        .addresses
        .iter()
        .map(|entry| height_u64(entry.required_from))
        .min()
        .map_or(0, |lowest| lowest.min(target))
}

/// The map entries a pass over a watch set with `floor` handles: every shard
/// the map publishes, and every revision its re-cuts declare superseded that
/// ends at or above the floor. Declarations are never dropped, so those wholly
/// below every watched script's required height, which no stored fact can
/// name, do not count against the limit; [`declaration_count`] bounds them.
pub(super) fn limited_map_entries(map: &ShardMap, floor: u64) -> usize {
    map.shards.len()
        + map
            .recuts
            .iter()
            .flat_map(|recut| &recut.superseded)
            .filter(|shard| shard.end_height >= floor)
            .count()
}

/// Every revision `map`'s re-cuts declare superseded, at any height.
///
/// A pass checks each declaration against the map and the others, and marks
/// those the catalog holds current, whatever the floor: the floor is the
/// current watch set's, and the wallet may hold a declared revision from an
/// earlier pass whose floor was lower. So the floor does not bound this work;
/// the total is held to [`MAX_SUPERSEDED`], the most the map's own shape check
/// accepts, before anything is retrieved.
fn declaration_count(map: &ShardMap) -> usize {
    map.recuts.iter().map(|recut| recut.superseded.len()).sum()
}

/// Refuses a map with more shards and declarations at or above `floor` than
/// `shards`, or more declarations in all than [`MAX_SUPERSEDED`].
pub(crate) fn check_publication_limits(
    map: &ShardMap,
    floor: u64,
    shards: usize,
) -> Result<(), RecoveryError> {
    ensure_valid(
        limited_map_entries(map, floor) <= shards,
        "publication shard limit exceeded",
    )?;
    ensure_valid(
        declaration_count(map) <= MAX_SUPERSEDED,
        "publication declaration limit exceeded",
    )
}

/// The service's geometry from its init, refusing a service whose init names a
/// schema other than [`SCHEMA`].
pub(crate) fn service_geometry(
    transport: &mut impl ShardTransport,
) -> Result<ServiceGeometry, RecoveryError> {
    let (raw_init, _) = transport.init().map_err(failure)?;
    let geometry = transparent_wallet::parse_init(&raw_init).map_err(failure)?;
    ensure_valid(
        geometry.schema == SCHEMA,
        "service serves an unsupported shard schema",
    )?;
    Ok(geometry)
}
