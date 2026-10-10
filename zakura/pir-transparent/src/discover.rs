//! Import-time account discovery: which of a few candidate addresses hold
//! transparent history from a birthday on, before any wallet exists.
//!
//! A wallet importing a recovery phrase checks the first address of each
//! higher account for history, so that accounts another wallet used are not
//! left out. Asking an indexer about each address discloses them. Here the
//! candidates are checked as a private pass checks a watch set: every filter
//! from the floor's shard to the publication's end is downloaded, whatever
//! matches, and each filter match is confirmed by private retrieval, so a
//! filter's false positive never reports an address as used.
//!
//! Nothing is stored: the pass runs over a fresh in-memory store that is
//! dropped on return, and no companion, catalog or wallet is touched.

use std::collections::BTreeSet;

use transparent::address::TransparentAddress;
use transparent_filter::{MAINNET_GENESIS_DISPLAY, NETWORK, ShardMap};
use transparent_wallet::transport::{FilterSource, ShardTransport};
use transparent_wallet::{
    Acceptance, Anchor, ChainView, Completion, IncompleteReason, MemoryStore, ScriptEntry,
    ScriptOrigin, StaticChain, StaticScripts, SyncError, WalletStore, WorkLimits,
};

use crate::recovery::{
    Outcome, Progress, RecoveryError, address_script, check_publication_limits, failure, progress,
    require, service_geometry,
};

/// Finite bounds for one discovery.
#[derive(Clone, Copy, Debug)]
pub struct DiscoveryLimits {
    /// Maximum candidate addresses.
    pub scripts: usize,
    /// Maximum shard-map entries.
    pub shards: usize,
    /// Private query budget.
    pub queries: u64,
    /// Private payload budget, including setup.
    pub private_bytes: u64,
}

/// What a discovery found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovery {
    /// Ascending indices into the candidates of those holding a receive or a
    /// spend at a height from the floor through the publication's end, each
    /// confirmed by private retrieval. Unless the outcome is
    /// [`Outcome::Complete`], the others may hold history this pass did not
    /// reach.
    pub active: Vec<usize>,
    /// How far the candidates were covered, and why the pass stopped.
    pub progress: Progress,
}

/// Finds which of `addresses` hold transparent history at or above `floor`,
/// through the caller's transports, with no wallet.
///
/// Before any filter or private retrieval, in order: the candidates must be
/// nonempty, within the script limit and distinct; the bounds positive;
/// `filters` must not use the parent filter experiment; the shard map must be
/// well formed, within the shard limit, name Zcash mainnet's network and
/// genesis block, and start at or below `floor`; and the service's init must
/// name [`crate::SCHEMA`]. A failed check returns [`RecoveryError::Invalid`]
/// without further requests. A floor above the publication's end is
/// [`Outcome::Behind`] with nothing found, after only the map was fetched.
///
/// The requests depend on the floor and the publication, never on which
/// candidate a filter matched, except for the private retrieval that confirms
/// a match, which reveals the matched shard as a recovery pass does, and, from
/// how many queries it takes, roughly how much history that shard holds for
/// the candidates. The pass
/// covers through the end of the publication's tail, and so misses history in
/// blocks published after its map.
///
/// A spend counts as history: an address paid below the floor and spent at or
/// above it is active. The first shard may start below the floor; history
/// there below the floor is not.
///
/// The publication is its own chain view here (see [`PublicationChain`]),
/// which is sound only because nothing a discovery finds is evidence or
/// authority: an address it reports leads the caller to import an account,
/// whose own recovery is then checked against the wallet's chain. A dishonest
/// publication can hide an address's history or invent it, as an indexer
/// answering per address can.
///
/// Never returns [`RecoveryError::PublicationChanged`].
pub fn discover_active_addresses<F: FilterSource, T: ShardTransport>(
    addresses: &[TransparentAddress],
    floor: u64,
    limits: &DiscoveryLimits,
    filters: &mut F,
    transport: &mut T,
) -> Result<Discovery, RecoveryError> {
    require(
        !addresses.is_empty() && addresses.len() <= limits.scripts,
        "candidate count outside the script limit",
    )?;
    let scripts: Vec<Vec<u8>> = addresses
        .iter()
        .map(|address| address_script(*address))
        .collect();
    require(
        scripts.iter().collect::<BTreeSet<_>>().len() == scripts.len(),
        "duplicate candidate address",
    )?;
    require(
        limits.shards > 0 && limits.queries > 0 && limits.private_bytes > 0,
        "discovery bounds must be positive",
    )?;
    // The parent experiment's selective child requests leak coarse activity.
    require(
        !filters.uses_parents(),
        "parent filter sources are not supported",
    )?;
    let (raw_map, map_bytes) = filters.shard_map().map_err(failure)?;
    let map: ShardMap = serde_json::from_slice(&raw_map).map_err(failure)?;
    map.check_shape().map_err(failure)?;
    check_publication_limits(&map, floor, limits.shards)?;
    require(
        map.network == NETWORK && map.genesis_hash == MAINNET_GENESIS_DISPLAY,
        "publication is not for Zcash mainnet",
    )?;
    // The sync plans each script from the map's start when that is above its
    // required height, which would skip history between the two unseen.
    require(
        map.start_height <= floor,
        "publication starts above the discovery floor",
    )?;
    let last = map
        .shards
        .last()
        .ok_or_else(|| RecoveryError::Invalid("publication has no shards".into()))?;
    if floor > last.end_height {
        return Ok(Discovery {
            active: Vec::new(),
            progress: Progress {
                covered_through: last.end_height,
                outcome: Outcome::Behind,
            },
        });
    }
    let target = Anchor {
        height: last.end_height,
        hash: last.terminal_block_hash.clone(),
    };
    let geometry = service_geometry(transport)?;
    let chain = PublicationChain::of(&map);
    let mut store = MemoryStore::new();
    let mut candidates = StaticScripts(
        scripts
            .iter()
            .map(|script| ScriptEntry {
                script: script.clone(),
                origin: ScriptOrigin::Derived,
                required_from: floor,
            })
            .collect(),
    );
    let work = WorkLimits {
        max_queries: Some(limits.queries),
        max_private_bytes: Some(limits.private_bytes),
    };
    let report = match transparent_wallet::sync_into(
        &mut store,
        &map,
        map_bytes,
        &geometry,
        &chain,
        &mut candidates,
        filters,
        transport,
        &work,
        &target,
    ) {
        Ok(report) => report,
        // A map refreshed mid-pass that does not continue the first: a later
        // discovery starts from the publication it then finds.
        Err(SyncError::MapDiverged(_)) => {
            return Ok(Discovery {
                active: Vec::new(),
                progress: Progress {
                    covered_through: 0,
                    outcome: Outcome::Behind,
                },
            });
        }
        Err(other) => return Err(failure(other)),
    };
    let progress = match report.completion {
        // Reported only once every candidate is covered through the target with
        // no page left: a spend of an output paid below the floor, which no
        // candidate's history from the floor on can resolve. Its spend is the
        // history discovery asks about.
        Completion::Incomplete {
            reason: IncompleteReason::UnresolvedSpends,
            ..
        } => Progress {
            covered_through: report.covered_through,
            outcome: Outcome::Complete,
        },
        _ => progress(&report, false),
    };
    let range = floor..=target.height;
    let events = store.events().map_err(failure)?;
    let active = scripts
        .iter()
        .enumerate()
        .filter(|(_, script)| {
            events.iter().any(|stored| {
                stored.script == **script && range.contains(&u64::from(stored.event.height()))
            })
        })
        .map(|(index, _)| index)
        .collect();
    Ok(Discovery { active, progress })
}

/// The publication as its own chain view: accepts exactly the blocks its map
/// names, each shard's terminal block and the parent before its start, and the
/// genesis block. Passed to `sync_into` only.
///
/// `sync_into` checks the target and every shard endpoint against the chain
/// view, so that a wallet's independently accepted chain catches a reorg the
/// publication has not followed. Before a wallet exists there is no such chain,
/// so this view vouches for nothing and catches nothing; it lets a one-shot
/// pass run, and it is sound only for [`discover_active_addresses`], whose
/// answer grants no authority. At wallet-pir 06a972db the view is asked:
///
/// - for the target, the map's last end (`sync.rs:554`), and for each planned
///   shard's endpoint, its own end or the target (`sync.rs:1471`,
///   `endpoint_of`), all named by the map the pass started from. A map
///   refreshed mid-pass keeps the target, so a tail republished since clamps
///   to it; a shard sealed since, ending below the target at a height the
///   first map did not name, is unknown and stops the pass as
///   `ChainUnknown`.
/// - for rollback anchors (`accepted_at`, `sync.rs:2661`), which fall back to
///   the map's own hashes; only block 0 has no map entry, so
///   [`Self::hash_at`] answers it with the genesis hash.
///
/// Re-verify these call sites on every wallet-pir pin bump.
struct PublicationChain {
    chain: StaticChain,
}

impl PublicationChain {
    fn of(map: &ShardMap) -> Self {
        let mut chain = StaticChain::from_map(map);
        chain.hashes.insert(0, map.genesis_hash.clone());
        Self { chain }
    }
}

impl ChainView for PublicationChain {
    fn is_accepted(&self, height: u64, hash_display_hex: &str) -> Acceptance {
        self.chain.is_accepted(height, hash_display_hex)
    }

    fn tip(&self) -> Option<Anchor> {
        self.chain.tip()
    }

    fn hash_at(&self, height: u64) -> Option<String> {
        self.chain.hash_at(height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SCHEMA;
    use crate::test_support::{CountingFilters, CountingShards, MAP};

    const LIMITS: DiscoveryLimits = DiscoveryLimits {
        scripts: 20,
        shards: 1_024,
        queries: 256,
        private_bytes: 96 << 20,
    };

    fn map() -> ShardMap {
        serde_json::from_slice(MAP).unwrap()
    }

    fn candidates(count: u8) -> Vec<TransparentAddress> {
        (0..count)
            .map(|n| TransparentAddress::PublicKeyHash([n; 20]))
            .collect()
    }

    /// The fixture map's start: every check passes at this floor.
    fn floor() -> u64 {
        map().start_height
    }

    fn discover(
        addresses: &[TransparentAddress],
        floor: u64,
        limits: &DiscoveryLimits,
        filters: &mut CountingFilters,
        shards: &mut CountingShards,
    ) -> Result<Discovery, RecoveryError> {
        discover_active_addresses(addresses, floor, limits, filters, shards)
    }

    #[test]
    fn candidate_sets_and_bounds_are_checked_before_any_request() {
        let mut filters = CountingFilters::default();
        let mut shards = CountingShards::serving(SCHEMA);
        let duplicate = [candidates(1), candidates(1)].concat();
        let oversized = candidates(21);
        let unbounded = DiscoveryLimits {
            queries: 0,
            ..LIMITS
        };
        for (addresses, limits) in [
            (&[][..], &LIMITS),
            (&duplicate[..], &LIMITS),
            (&oversized[..], &LIMITS),
            (&candidates(2)[..], &unbounded),
        ] {
            assert!(matches!(
                discover(addresses, floor(), limits, &mut filters, &mut shards),
                Err(RecoveryError::Invalid(_))
            ));
        }
        assert_eq!(filters.calls() + shards.calls(), 0);
    }

    #[test]
    fn parent_filter_sources_are_refused_before_the_map() {
        let mut filters = CountingFilters {
            parents: true,
            ..Default::default()
        };
        let mut shards = CountingShards::serving(SCHEMA);
        assert!(matches!(
            discover(&candidates(2), floor(), &LIMITS, &mut filters, &mut shards),
            Err(RecoveryError::Invalid(_))
        ));
        assert_eq!((filters.maps, filters.filters, shards.calls()), (0, 0, 0));
    }

    #[test]
    fn publications_that_cannot_cover_the_floor_are_refused_before_init() {
        let mut other_network = map();
        other_network.network = "test".into();
        let mut other_genesis = map();
        other_genesis.genesis_hash = "11".repeat(32);
        for (published, floor, limits) in [
            (other_network, floor(), LIMITS),
            (other_genesis, floor(), LIMITS),
            // History between the floor and the map's start would go unseen.
            (map(), floor() - 1, LIMITS),
            (
                map(),
                floor(),
                DiscoveryLimits {
                    shards: 1,
                    ..LIMITS
                },
            ),
        ] {
            let mut filters = CountingFilters::serving(serde_json::to_vec(&published).unwrap());
            let mut shards = CountingShards::serving(SCHEMA);
            assert!(matches!(
                discover(&candidates(2), floor, &limits, &mut filters, &mut shards),
                Err(RecoveryError::Invalid(_))
            ));
            assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 0));
        }
    }

    #[test]
    fn a_floor_above_the_publication_is_behind_with_only_the_map_fetched() {
        let end = map().shards.last().unwrap().end_height;
        let mut filters = CountingFilters::default();
        let mut shards = CountingShards::serving(SCHEMA);
        let discovery =
            discover(&candidates(2), end + 1, &LIMITS, &mut filters, &mut shards).unwrap();
        assert_eq!(
            discovery,
            Discovery {
                active: vec![],
                progress: Progress {
                    covered_through: end,
                    outcome: Outcome::Behind,
                },
            }
        );
        assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 0));
    }

    #[test]
    fn another_schema_is_refused_before_any_filter() {
        let mut filters = CountingFilters::default();
        let mut shards = CountingShards::serving("transparent-shard-v10");
        assert!(matches!(
            discover(&candidates(2), floor(), &LIMITS, &mut filters, &mut shards),
            Err(RecoveryError::Invalid(_))
        ));
        assert_eq!((filters.maps, filters.filters), (1, 0));
        assert_eq!((shards.inits, shards.calls()), (1, 1));
    }

    #[test]
    fn the_publication_vouches_only_for_blocks_its_map_names() {
        let map = map();
        let chain = PublicationChain::of(&map);
        let last = map.shards.last().unwrap();
        assert_eq!(
            chain.is_accepted(last.end_height, &last.terminal_block_hash),
            Acceptance::Accepted
        );
        assert_eq!(
            chain.is_accepted(last.start_height - 1, &last.parent_block_hash),
            Acceptance::Accepted
        );
        assert_eq!(chain.hash_at(0), Some(map.genesis_hash.clone()));
        assert_eq!(
            chain.is_accepted(last.end_height, &"00".repeat(32)),
            Acceptance::Rejected
        );
        assert_eq!(
            chain.is_accepted(last.end_height - 1, &last.terminal_block_hash),
            Acceptance::Unknown
        );
    }
}
