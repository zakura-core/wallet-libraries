use super::commit_builder::CommitBuilder;
use super::page_completion::{page_continuation_id, ranges_cover};
use super::preflight::{limited_map_entries, watch_floor};
use super::sync_inputs::{FloorAcceptingChain, SyncTarget, sync_target};
use super::*;
use crate::transparent::batch::{BatchState, WithdrawnCause};
use crate::transparent::convert::address_script;
use crate::transparent::convert::{block_hash_from_display, block_height, ledger_metadata};
use crate::transparent::engine::client::Table;
use crate::transparent::engine::store::RunCursor;
use crate::transparent::engine::transport::BoxError;
use crate::transparent::engine::{Acceptance, Anchor, ScriptEntry, ScriptOrigin};
use crate::transparent::engine::{Completion, IncompleteReason, SyncReport, WalletStore};
use crate::transparent::engine::{
    Ledger, PendingPages, SetupBlob, SetupKey, StaticChain, StoredEvent,
};
use crate::transparent::progress::Retry;
use crate::transparent::test_support::{CountingFilters, CountingShards, MAP};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use transparent::address::TransparentAddress;
use zakura_pir_protocol::transparent::events::{FeeState, TransparentEvent};
use zakura_pir_protocol::transparent::filter::MAINNET_GENESIS_DISPLAY;
use zakura_pir_protocol::transparent::filter::wire::MAX_SUPERSEDED;
use zakura_pir_protocol::transparent::filter::{
    Recut, SealParameters, ShardMapEntry, SupersededShard,
};
use zakura_pir_protocol::transparent::recovery::RecoveryBlockHash as BlockHash;
use zakura_pir_protocol::transparent::recovery::{
    AccountLifecycle, PendingPage, WatchOrigin, WatchedAddress,
};
use zakura_pir_protocol::transparent::recovery::{
    AddressRange, ChainPoint, PageRequest, TransparentLedgerCommit, WholeTransactionFee,
};
use zakura_pir_protocol::transparent::recovery::{PublicationAnchor, RecoveryRevision};
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};
const MORE: Progress = Progress {
    covered_through: 0,
    outcome: Outcome::More,
};

fn config() -> TransparentHistoryRecoveryConfig {
    TransparentHistoryRecoveryConfig {
        source: b"explicit-fixture-source".to_vec(),
        account_binding: vec![1],
        origin: "http://127.0.0.1:1".into(),
        scripts: 40,
        shards: 2000,
        events: 100_000,
        queries: 64,
        private_bytes: 64 * 1024 * 1024,
    }
}

#[test]
fn invalid_endpoint_is_rejected_before_creating_the_companion() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("companion.sqlite");
    for origin in [
        "https://user@example.org/",
        "https://example.org/?",
        "https://example.org/#",
        "https://bücher.example/",
        "https:example.org",
        "http://127.1/",
        "https://example.org/\\@other.example/",
    ] {
        let mut config = config();
        config.origin = origin.into();
        assert!(
            TransparentHistoryRecovery::open(&path, config).is_err(),
            "{origin}"
        );
        assert!(
            !path.exists(),
            "invalid endpoint created a companion: {origin}"
        );
    }
}

#[test]
fn endpoint_validation_keeps_the_original_companion_binding() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("companion.sqlite");
    let mut original = config();
    original.origin = "http://EXAMPLE.ORG:80/base/".into();
    // Transparent recovery still accepts non-loopback HTTP. The original
    // configured bytes remain its identity even when endpoint parsing normalizes.
    drop(TransparentHistoryRecovery::open(&path, original.clone()).unwrap());
    drop(TransparentHistoryRecovery::open(&path, original).unwrap());
    let mut canonical = config();
    canonical.origin = "http://example.org/base/".into();
    assert!(TransparentHistoryRecovery::open(&path, canonical).is_err());
}

fn map() -> ShardMap {
    serde_json::from_slice(MAP).unwrap()
}

fn watch() -> TransparentAddressWatchSet<u32> {
    let map = map();
    let last = map.shards.last().unwrap();
    TransparentAddressWatchSet {
        account: 1,
        lifecycle: AccountLifecycle::Candidate,
        policy_generation: 0,
        target: Some(ChainPoint {
            height: block_height(last.end_height).unwrap(),
            hash: block_hash_from_display(&last.terminal_block_hash).unwrap(),
        }),
        addresses: vec![WatchedAddress {
            address: TransparentAddress::PublicKeyHash([7; 20]),
            origin: WatchOrigin::Standalone,
            required_from: block_height(map.start_height).unwrap(),
        }],
        pending_pages: vec![],
    }
}

fn report(completion: Completion) -> SyncReport {
    SyncReport {
        ledger: Ledger::new(),
        charges: Default::default(),
        matched_shards: vec![],
        unproductive_matches: 0,
        covered_through: 0,
        settled_through: 0,
        provisional: vec![],
        map_refreshes: 0,
        completion,
        rolled_back_to: None,
        replaced_revisions: vec![],
        scripts_added: 0,
        commits: 0,
        failed_entries: vec![],
    }
}

/// A companion bound to the fixture map that retains `script` from `required_from`.
fn seeded(
    dir: &tempfile::TempDir,
    script: &[u8],
    required_from: u64,
) -> TransparentHistoryRecovery {
    let mut adapter =
        TransparentHistoryRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
    adapter.store.bind_set(&SetIdentity::of(&map())).unwrap();
    adapter
        .store
        .add_scripts(&[ScriptEntry {
            script: script.to_vec(),
            origin: ScriptOrigin::Imported,
            required_from,
        }])
        .unwrap();
    adapter
}

/// What a pass reading `entry` under `digest` through `end` commits for `script`.
fn covered(
    entry: &ShardMapEntry,
    digest: &str,
    (end, terminal): (u64, &str),
    script: &[u8],
    events: Vec<TransparentEvent>,
) -> crate::transparent::engine::ShardCommit {
    crate::transparent::engine::ShardCommit {
        source_anchor: None,
        shard_id: entry.shard_id,
        revision_digest: digest.into(),
        sealed: entry.sealed,
        start_height: entry.start_height,
        end_height: end,
        terminal_block_hash: terminal.into(),
        events: events
            .into_iter()
            .map(|event| StoredEvent {
                script: script.to_vec(),
                event,
                shard_id: entry.shard_id,
                revision_digest: digest.into(),
            })
            .collect(),
        covered_scripts: vec![script.to_vec()],
        pending_upsert: vec![],
        pending_complete: vec![],
        cached_runs: vec![],
        failed_entries: vec![],
    }
}

/// A companion at `path` opened under `config` and bound to `map`, covering
/// the watched script on every shard under the revision `map` publishes.
fn covering_as(
    path: &Path,
    config: TransparentHistoryRecoveryConfig,
    map: &ShardMap,
) -> TransparentHistoryRecovery {
    let mut adapter = TransparentHistoryRecovery::open(path, config).unwrap();
    cover(&mut adapter, map);
    adapter
}

/// Binds the companion's store to `map` and covers the watched script on
/// every shard under the revision `map` publishes, as a sync would.
fn cover(adapter: &mut TransparentHistoryRecovery, map: &ShardMap) {
    let script = address_script(watch().addresses[0].address);
    adapter.store.bind_set(&SetIdentity::of(map)).unwrap();
    adapter
        .store
        .add_scripts(&[ScriptEntry {
            script: script.clone(),
            origin: ScriptOrigin::Imported,
            required_from: map.start_height,
        }])
        .unwrap();
    for entry in &map.shards {
        let end = (entry.end_height, entry.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(entry, &entry.manifest_digest, end, &script, vec![]))
            .unwrap();
    }
}

/// Starts a pass from `map`, which must stop at the set check: before any
/// filter or private request, with the store reset.
fn publication_change(adapter: &mut TransparentHistoryRecovery, map: &ShardMap) {
    let mut filters = CountingFilters::serving(serde_json::to_vec(map).unwrap());
    let mut shards = CountingShards::serving(SCHEMA);
    assert!(matches!(
        adapter.recover(
            &watch(),
            &StaticChain::from_map(map),
            &mut filters,
            &mut shards
        ),
        Err(RecoveryError::PublicationChanged)
    ));
    assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 1));
    assert_eq!(adapter.store.set_identity().unwrap(), None);
}

/// `(table, rows)` for every table of the companion's store, the catalog's
/// excluded, by name.
fn store_rows(adapter: &TransparentHistoryRecovery) -> Vec<(String, u64)> {
    let mut statement = adapter
        .catalog
        .prepare(
            "SELECT name FROM sqlite_master WHERE type='table'
             AND name NOT LIKE 'pir_bridge_%' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .unwrap();
    let tables: Vec<String> = statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let rows = adapter
                .catalog
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            (table, rows)
        })
        .collect()
}

fn covering(path: &Path, map: &ShardMap) -> TransparentHistoryRecovery {
    covering_as(path, config(), map)
}

/// Normalizes the fixture watch set against `map`, accepted as the chain.
fn pass(adapter: &mut TransparentHistoryRecovery, map: &ShardMap) -> RecoveryBatch<u32> {
    adapter
        .normalize(&watch(), map.clone(), MORE, &StaticChain::from_map(map))
        .unwrap()
}

/// `map` with shard `index` republished as `revision` under `digest`.
fn republished(map: &ShardMap, index: usize, revision: u32, digest: String) -> ShardMap {
    let mut map = map.clone();
    map.shards[index].revision = revision;
    map.shards[index].manifest_digest = digest;
    map
}

/// Rolls the companion's tail facts back, as a sync does when the tail it
/// covered is replaced.
fn withdraw_tail(adapter: &mut TransparentHistoryRecovery, map: &ShardMap) {
    let tail = map.shards.last().unwrap();
    adapter
        .store
        .rollback_above(
            &Anchor {
                height: tail.start_height - 1,
                hash: tail.parent_block_hash.clone(),
            },
            "replaced tail",
        )
        .unwrap();
}

/// Replaces the companion's tail facts with coverage under `map`'s tail.
fn retrieve_tail(adapter: &mut TransparentHistoryRecovery, map: &ShardMap) {
    withdraw_tail(adapter, map);
    let tail = map.shards.last().unwrap();
    let script = address_script(watch().addresses[0].address);
    let end = (tail.end_height, tail.terminal_block_hash.as_str());
    adapter
        .store
        .commit_shard(covered(tail, &tail.manifest_digest, end, &script, vec![]))
        .unwrap();
}

/// The fixture map's start heights: its archive shard's and its tail's.
const ARCHIVE: u64 = 3_499_739;

const TAIL: u64 = 3_500_239;

/// `(start_height, lineage)` of every catalog row recorded as exported.
fn exported(adapter: &TransparentHistoryRecovery) -> Vec<(u64, u64)> {
    let mut statement = adapter
        .catalog
        .prepare(
            "SELECT start_height, lineage FROM pir_bridge_catalog WHERE exported=1
             ORDER BY start_height, lineage",
        )
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Every catalog row as `(source, start_height, lineage, exported, current)`,
/// so a test can tell that a call recorded nothing.
fn catalog_rows(adapter: &TransparentHistoryRecovery) -> Vec<(Vec<u8>, u64, u64, bool, bool)> {
    let mut statement = adapter
        .catalog
        .prepare(
            "SELECT source, start_height, lineage, exported, current FROM pir_bridge_catalog
             ORDER BY source, lineage",
        )
        .unwrap();
    statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn cataloged(adapter: &TransparentHistoryRecovery) -> u64 {
    adapter
        .catalog
        .query_row("SELECT COUNT(*) FROM pir_bridge_catalog", [], |r| r.get(0))
        .unwrap()
}

fn revisions(batch: &RecoveryBatch<u32>) -> Vec<RecoveryRevision> {
    batch
        .commits
        .iter()
        .map(|commit| commit.revision.clone())
        .collect()
}

/// Page work the store still owes for `script` on `entry`: the chain walk
/// from the newest run, at `row` of the first page shard.
fn store_page(entry: &ShardMapEntry, script: &[u8], row: u32) -> PendingPages {
    PendingPages {
        dummy_queries: None,
        id: None,
        shard_id: entry.shard_id,
        revision_digest: entry.manifest_digest.clone(),
        script: script.to_vec(),
        cursor: RunCursor {
            child: 0,
            row,
            older_runs: None,
        },
        carried: vec![],
        fragments: vec![],
        attempts: 0,
        target_anchor: None,
    }
}

/// `map` with the seal parameters of `shard`'s geometry changed.
fn resealing(map: &ShardMap, shard: usize) -> ShardMap {
    let mut resealed = map.clone();
    resealed
        .seal
        .get_mut(&map.shards[shard].geometry)
        .unwrap()
        .max_scripts += 1;
    resealed
}

/// The recent geometry the re-cut fixture's sealed shards and tail use.
const NARROW: &str = "decoupled-2k-8k";

/// The geometry the re-cut fixture merges into, standing in for an
/// archive geometry.
const WIDE: &str = "decoupled-32k-32k";

/// The re-cut fixture's block at `height`: the fixture map's own at its
/// archive shard's end, a synthetic one elsewhere.
fn recut_hash(height: u64) -> String {
    let archive = &map().shards[0];
    if height == archive.end_height {
        archive.terminal_block_hash.clone()
    } else {
        format!("{height:064x}")
    }
}

/// A map entry over `[start, end]` whose manifest digest is `tag`.
fn recut_entry(
    shard_id: u64,
    geometry: &str,
    (start, end): (u64, u64),
    (revision, sealed): (u32, bool),
    tag: u64,
) -> ShardMapEntry {
    ShardMapEntry {
        shard_id,
        geometry: geometry.into(),
        start_height: start,
        end_height: end,
        parent_block_hash: recut_hash(start - 1),
        terminal_block_hash: recut_hash(end),
        manifest_digest: format!("{tag:064x}"),
        revision,
        sealed,
        ..map().shards[1].clone()
    }
}

/// `entry` as a re-cut declares it superseded.
fn superseded(entry: &ShardMapEntry) -> SupersededShard {
    SupersededShard {
        shard_id: entry.shard_id,
        geometry: entry.geometry.clone(),
        start_height: entry.start_height,
        end_height: entry.end_height,
        terminal_block_hash: entry.terminal_block_hash.clone(),
        manifest_digest: entry.manifest_digest.clone(),
        revision: entry.revision,
        sealed: entry.sealed,
    }
}

/// `shards` published under the fixture map's identity, with seal
/// parameters for both re-cut geometries, declaring `recuts`. The fixture map
/// already seals both, and keeps its parameters: changing them would change
/// the publication set.
fn recut_map(shards: Vec<ShardMapEntry>, recuts: Vec<Recut>) -> ShardMap {
    let mut map = map();
    for geometry in [NARROW, WIDE] {
        map.seal.entry(geometry.into()).or_insert(SealParameters {
            max_scripts: 100,
            max_page_rows: 10,
            max_txids: 0,
        });
    }
    map.shards = shards;
    map.recuts = recuts;
    map.check_shape().unwrap();
    map
}

/// A publication before and after a declared re-cut.
///
/// Before: the fixture's archive shard S0, sealed shards S1–S3 and the tail
/// T, all [`NARROW`]. After: S0 unchanged, S1–S2 re-cut into one [`WIDE`]
/// shard W, and S3′ and T′ renumbered at the same heights one revision
/// higher, declared at epoch 1.
fn recut_pair() -> (ShardMap, ShardMap) {
    let s0 = map().shards[0].clone();
    let at = s0.end_height + 1;
    let span = |index: u64| (at + 100 * index, at + 100 * index + 99);
    let before = vec![
        s0.clone(),
        recut_entry(1, NARROW, span(0), (0, true), 0x11),
        recut_entry(2, NARROW, span(1), (0, true), 0x12),
        recut_entry(3, NARROW, span(2), (0, true), 0x13),
        recut_entry(4, NARROW, (at + 300, at + 340), (6, false), 0x14),
    ];
    let after = vec![
        s0,
        recut_entry(1, WIDE, (at, at + 199), (0, true), 0x21),
        recut_entry(2, NARROW, span(2), (1, true), 0x23),
        recut_entry(3, NARROW, (at + 300, at + 350), (7, false), 0x24),
    ];
    let recut = Recut {
        epoch: 1,
        from_height: at,
        superseded: before[1..].iter().map(superseded).collect(),
    };
    (recut_map(before, vec![]), recut_map(after, vec![recut]))
}

/// The fixture watch set, targeting the end of `map`.
fn watching(map: &ShardMap) -> TransparentAddressWatchSet<u32> {
    let last = map.shards.last().unwrap();
    TransparentAddressWatchSet {
        target: Some(ChainPoint {
            height: block_height(last.end_height).unwrap(),
            hash: block_hash_from_display(&last.terminal_block_hash).unwrap(),
        }),
        ..watch()
    }
}

/// A chain accepting every block either map names.
fn accepting(maps: &[&ShardMap]) -> StaticChain {
    let mut chain = StaticChain::default();
    for map in maps {
        chain.hashes.extend(StaticChain::from_map(map).hashes);
    }
    chain
}

/// A companion at `path` that covered `before` and exported every shard of
/// it to the wallet, then followed the declared re-cut to `after` as the
/// sync leaves the store: sealed coverage kept under the revisions it was
/// read under, the tail retrieved again. Returns the first batch.
fn recut_companion(
    path: &Path,
    before: &ShardMap,
    after: &ShardMap,
) -> (TransparentHistoryRecovery, RecoveryBatch<u32>) {
    let (watch, chain) = (watching(after), accepting(&[before, after]));
    let mut adapter = covering(path, before);
    let first = adapter
        .normalize(&watch, before.clone(), MORE, &chain)
        .unwrap();
    assert_eq!(first.state, BatchState::Ready);
    assert_eq!(first.commits.len(), before.shards.len());
    adapter.acknowledge_applied(&first).unwrap();
    retrieve_tail(&mut adapter, after);
    (adapter, first)
}

fn recut_pass(
    adapter: &mut TransparentHistoryRecovery,
    watch: &TransparentAddressWatchSet<u32>,
    map: &ShardMap,
    chain: &StaticChain,
) -> RecoveryBatch<u32> {
    adapter.normalize(watch, map.clone(), MORE, chain).unwrap()
}

/// The re-cut fixture's `after`, with a forged re-cut before its own that
/// declares sealed one-block revisions from height 0, far below the
/// fixture map and any floor, bringing the map's declarations to `total`.
fn forged(total: usize) -> ShardMap {
    let (_, mut after) = recut_pair();
    let mut own = after.recuts.pop().unwrap();
    own.epoch = 2;
    let count = (total - own.superseded.len()) as u64;
    let forged = Recut {
        epoch: 1,
        from_height: 0,
        superseded: (0..count)
            .map(|height| SupersededShard {
                shard_id: height,
                geometry: NARROW.into(),
                start_height: height,
                end_height: height,
                terminal_block_hash: format!("{height:064x}"),
                manifest_digest: format!("{:064x}", (1u64 << 40) + height),
                revision: 0,
                sealed: true,
            })
            .collect(),
    };
    after.recuts = vec![forged, own];
    after
}

// The tests, grouped by the behavior they check.
#[cfg(feature = "sqlite")]
mod apply;
mod conversions;
mod declaration_limits;
mod divergence;
mod export_durability;
mod floor_and_target;
mod page_coverage;
mod preflight;
mod publication_change;
mod recut;
mod retired_revisions;
mod retry_contract;
mod settle;
mod source_identity;
mod stale_facts;
mod stranded_pages;
mod withdrawal;
