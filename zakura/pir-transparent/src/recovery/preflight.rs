//! Checks a pass makes before any filter or private retrieval.

use transparent_filter::{ShardMap, wire::MAX_SUPERSEDED};
use transparent_wallet::ServiceGeometry;
use transparent_wallet::transport::ShardTransport;
use zcash_client_backend::data_api::transparent_ledger::TransparentWatchSet;

use super::SCHEMA;
use crate::error::{RecoveryError, ensure_valid, failure};

/// The lowest height a pass needs the wallet's chain for: the lowest required
/// height in `watch`, capped at `target`, or 0 when nothing is watched.
pub(super) fn watch_floor<A>(watch: &TransparentWatchSet<A>, target: u64) -> u64 {
    watch
        .addresses
        .iter()
        .map(|entry| u64::from(u32::from(entry.required_from)))
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
