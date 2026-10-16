//! A tail republished under a new manifest digest, synced through the public
//! engine API against a shard service running in process over loopback HTTP
//! and real PIR: the store's filter and setup caches keep only the revisions
//! the current map publishes, while content failure counts and cached runs,
//! which are not keyed by a map revision, survive.

// Shared with the recovery tests, which use helpers this file does not.
#[allow(dead_code, unused_imports)]
mod fixture;

use std::collections::BTreeSet;
use std::path::Path;

use fixture::{GEOMETRY, SEAL, Server, ShardSpec, synthetic};
use transparent_events::{ReceiveEvent, TransparentEvent, Txid};
use transparent_filter::{ScriptBytes, ShardMap, ShardMapEntry};
use zakura_pir_transparent::engine::client::Table;
use zakura_pir_transparent::engine::http::{HttpFilterSource, HttpOptions, HttpShardTransport};
use zakura_pir_transparent::engine::store::{CachedRun, SetupKey, ShardCommit};
use zakura_pir_transparent::engine::testing::cached_run;
use zakura_pir_transparent::engine::transport::{BoxError, ShardTransport};
use zakura_pir_transparent::engine::{
    Anchor, Completion, MemoryStore, ScriptEntry, ScriptOrigin, StaticChain, StaticScripts,
    WalletStore, WorkLimits, parse_init, sync_into,
};
use zakura_pir_transparent::engine_store::SqliteStore;

/// The first height the fixture publishes, a mainnet height.
const H0: u64 = 3_428_143;

/// The wallet's one script: paid in the sealed shard and again in the tail.
fn watched() -> ScriptBytes {
    ScriptBytes::new([&[0x76, 0xa9, 20][..], &[0x31; 20], &[0x88, 0xac]].concat())
}

fn receive(height: u64, tag: u8) -> TransparentEvent {
    let mut txid = [0u8; 32];
    txid[0] = tag;
    txid[31] = 0x77;
    TransparentEvent::Receive(ReceiveEvent {
        metadata: None,
        height: height as u32,
        txid: Txid(txid),
        transaction_index: 1,
        output_index: 0,
        value: 50_000,
        coinbase: false,
    })
}

/// A sealed shard over `[H0, H0 + 299]` and a tail from `H0 + 300` that grows
/// by 100 blocks with each `revision`, so each republication has a new digest.
fn shards(revision: u32) -> Vec<ShardSpec> {
    let shard = |start, end, sealed, revision, events| ShardSpec {
        start,
        end,
        geometry: GEOMETRY,
        sealed,
        revision,
        supersedes: String::new(),
        page_span: 0,
        events,
        malformed_entries: Vec::new(),
    };
    vec![
        shard(
            H0,
            H0 + 299,
            true,
            0,
            vec![(watched(), receive(H0 + 100, 1))],
        ),
        shard(
            H0 + 300,
            H0 + 399 + 100 * u64::from(revision),
            false,
            revision,
            vec![(watched(), receive(H0 + 350, 2))],
        ),
    ]
}

/// One publication, served until the next replaces it.
struct Served {
    url: String,
    map: ShardMap,
}

fn publish(server: &mut Server, root: &Path, revision: u32) -> Served {
    let dir = root.join(format!("publication-{revision}"));
    let map = fixture::publish(&dir, &shards(revision), SEAL, synthetic, vec![]);
    Served {
        url: server.serve(&dir),
        map,
    }
}

/// Syncs `store` to the publication's tail. `chain` accepts every block any
/// publication so far named, as the wallet's own chain does.
fn sync<S: WalletStore>(store: &mut S, served: &Served, chain: &mut StaticChain) {
    let options = HttpOptions::default();
    let mut filters = HttpFilterSource::new(&served.url, &options).unwrap();
    let mut transport = HttpShardTransport::new(&served.url, &options).unwrap();
    let geometry = parse_init(&transport.init().unwrap().0).unwrap();
    chain
        .hashes
        .extend(StaticChain::from_map(&served.map).hashes);
    let tail = served.map.shards.last().unwrap();
    let report = sync_into(
        store,
        &served.map,
        0,
        &geometry,
        chain,
        &mut StaticScripts(vec![ScriptEntry {
            script: watched().as_slice().to_vec(),
            origin: ScriptOrigin::Derived,
            required_from: H0,
        }]),
        &mut filters,
        &mut transport,
        &WorkLimits::UNLIMITED,
        &Anchor {
            height: tail.end_height,
            hash: tail.terminal_block_hash.clone(),
        },
    )
    .unwrap();
    assert_eq!(report.completion, Completion::Complete);
    assert_eq!(report.ledger.confirmed_balance(), 100_000);
}

/// A cached run in a page shard no publication here names, and a content
/// failure counted for an unwatched script under the sealed shard's revision.
fn unrevisioned(sealed: &ShardMapEntry) -> (CachedRun, ShardCommit) {
    let run = CachedRun {
        shard_id: 99,
        ..cached_run("reusable-page-shard", 9, &[10, 20])
    };
    let commit = ShardCommit {
        shard_id: sealed.shard_id,
        revision_digest: sealed.manifest_digest.clone(),
        cached_runs: vec![run.clone()],
        failed_entries: vec![run.script.clone()],
        ..Default::default()
    };
    (run, commit)
}

fn directory_setup(store: &dyn WalletStore, revision: &ShardMapEntry) -> SetupKey {
    SetupKey {
        set_digest: store.set_identity().unwrap().unwrap().digest(),
        revision_digest: revision.manifest_digest.clone(),
        table: Table::Directory,
        segment: 0,
    }
}

/// The store holds the filter and directory setup of every revision in
/// `held` and of none in `pruned`, and still holds `run` and its failure.
fn assert_caches(
    store: &dyn WalletStore,
    held: &[&ShardMapEntry],
    pruned: &[&ShardMapEntry],
    run: &CachedRun,
    sealed: &ShardMapEntry,
) {
    for entry in held {
        assert!(
            store
                .filter(&entry.manifest_digest, &entry.filter_hash)
                .unwrap()
                .is_some(),
            "the filter of revision {} is kept",
            entry.revision
        );
        assert!(
            store
                .setup(&directory_setup(store, entry))
                .unwrap()
                .is_some(),
            "the setup of revision {} is kept",
            entry.revision
        );
    }
    for entry in pruned {
        assert!(
            store
                .filter(&entry.manifest_digest, &entry.filter_hash)
                .unwrap()
                .is_none(),
            "the filter of replaced revision {} is pruned",
            entry.revision
        );
        assert!(
            store
                .setup(&directory_setup(store, entry))
                .unwrap()
                .is_none(),
            "the setup of replaced revision {} is pruned",
            entry.revision
        );
    }
    assert_eq!(
        store.cached_run(&run.child_digest, &run.script).unwrap(),
        Some(run.clone())
    );
    assert_eq!(
        store
            .entry_failures(sealed.shard_id, &sealed.manifest_digest, &run.script)
            .unwrap(),
        1
    );
}

/// The revisions the SQLite file's filter and setup caches hold any row under.
fn cached_revisions(path: &Path) -> [BTreeSet<String>; 2] {
    let db = rusqlite::Connection::open(path).unwrap();
    ["filter_cache", "setup_cache"].map(|table| {
        db.prepare(&format!("SELECT DISTINCT revision_digest FROM {table}"))
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    })
}

#[test]
fn republished_tails_leave_only_the_current_revisions_cached() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("store.sqlite");
    let mut server = Server::start();
    let mut chain = StaticChain::default();

    let mut served = vec![publish(&mut server, root.path(), 0)];
    let sealed = served[0].map.shards[0].clone();
    let (run, seeded) = unrevisioned(&sealed);
    let mut sqlite = SqliteStore::open(&path).unwrap();
    let mut memory = MemoryStore::new();
    sqlite.commit_shard(seeded.clone()).unwrap();
    memory.commit_shard(seeded).unwrap();

    for revision in 0..3u32 {
        if revision > 0 {
            served.push(publish(&mut server, root.path(), revision));
        }
        let current = served.last().unwrap();
        sync(&mut sqlite, current, &mut chain);
        sync(&mut memory, current, &mut chain);
        let tail = &current.map.shards[1];
        let replaced: Vec<&ShardMapEntry> = served[..served.len() - 1]
            .iter()
            .map(|earlier| &earlier.map.shards[1])
            .collect();
        for store in [&sqlite as &dyn WalletStore, &memory] {
            assert_caches(store, &[&sealed, tail], &replaced, &run, &sealed);
        }
        let current_revisions: BTreeSet<String> = [&sealed, tail]
            .map(|entry| entry.manifest_digest.clone())
            .into();
        assert_eq!(
            cached_revisions(&path),
            [current_revisions.clone(), current_revisions]
        );
    }

    // The pruned file reopens and follows the next republication.
    drop(sqlite);
    served.push(publish(&mut server, root.path(), 3));
    let mut sqlite = SqliteStore::open(&path).unwrap();
    let current = served.last().unwrap();
    sync(&mut sqlite, current, &mut chain);
    let tail = &current.map.shards[1];
    let replaced: Vec<&ShardMapEntry> = served[..3].iter().map(|e| &e.map.shards[1]).collect();
    assert_caches(&sqlite, &[&sealed, tail], &replaced, &run, &sealed);
    let current_revisions: BTreeSet<String> = [&sealed, tail]
        .map(|entry| entry.manifest_digest.clone())
        .into();
    assert_eq!(
        cached_revisions(&path),
        [current_revisions.clone(), current_revisions]
    );
}

/// The service, except that every private query fails as an outage would:
/// filters and setups are fetched and verified, and then the sync fails.
struct QueriesFail(HttpShardTransport);

impl ShardTransport for QueriesFail {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.0.init()
    }
    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        self.0.manifest(shard_id, revision)
    }
    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        self.0.setup(shard_id, revision, table, segment)
    }
    fn query(&mut self, _: u64, _: &str, _: Table, _: &[u8]) -> Result<Vec<u8>, BoxError> {
        Err("the service is unavailable".into())
    }
}

/// Syncs `store` to the publication's tail through `QueriesFail`, which
/// fails the sync with the transport's error.
fn failing_sync<S: WalletStore>(store: &mut S, served: &Served, chain: &mut StaticChain) {
    let options = HttpOptions::default();
    let mut filters = HttpFilterSource::new(&served.url, &options).unwrap();
    let mut transport = QueriesFail(HttpShardTransport::new(&served.url, &options).unwrap());
    let geometry = parse_init(&transport.init().unwrap().0).unwrap();
    chain
        .hashes
        .extend(StaticChain::from_map(&served.map).hashes);
    let tail = served.map.shards.last().unwrap();
    let error = sync_into(
        store,
        &served.map,
        0,
        &geometry,
        chain,
        &mut StaticScripts(vec![ScriptEntry {
            script: watched().as_slice().to_vec(),
            origin: ScriptOrigin::Derived,
            required_from: H0,
        }]),
        &mut filters,
        &mut transport,
        &WorkLimits::UNLIMITED,
        &Anchor {
            height: tail.end_height,
            hash: tail.terminal_block_hash.clone(),
        },
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("the service is unavailable"),
        "the transport's own error is returned: {error}"
    );
}

#[test]
fn failed_syncs_leave_only_the_adopted_maps_revisions_cached() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("store.sqlite");
    let mut server = Server::start();
    let mut chain = StaticChain::default();

    let mut served = vec![publish(&mut server, root.path(), 0)];
    let sealed = served[0].map.shards[0].clone();
    let (run, seeded) = unrevisioned(&sealed);
    let mut sqlite = SqliteStore::open(&path).unwrap();
    let mut memory = MemoryStore::new();
    sqlite.commit_shard(seeded.clone()).unwrap();
    memory.commit_shard(seeded).unwrap();
    sync(&mut sqlite, &served[0], &mut chain);
    sync(&mut memory, &served[0], &mut chain);

    // Each growing tail's filter and setup are verified and cached before
    // its query fails; the tails replaced before it must not stay behind.
    for revision in 1..4u32 {
        served.push(publish(&mut server, root.path(), revision));
        let current = served.last().unwrap();
        if revision == 3 {
            drop(sqlite);
            sqlite = SqliteStore::open(&path).unwrap();
        }
        failing_sync(&mut sqlite, current, &mut chain);
        failing_sync(&mut memory, current, &mut chain);
        let tail = &current.map.shards[1];
        let replaced: Vec<&ShardMapEntry> = served[..served.len() - 1]
            .iter()
            .map(|earlier| &earlier.map.shards[1])
            .collect();
        for store in [&sqlite as &dyn WalletStore, &memory] {
            assert_caches(store, &[&sealed, tail], &replaced, &run, &sealed);
        }
        let current_revisions: BTreeSet<String> = [&sealed, tail]
            .map(|entry| entry.manifest_digest.clone())
            .into();
        assert_eq!(
            cached_revisions(&path),
            [current_revisions.clone(), current_revisions]
        );
    }

    // A map the sync refuses before adopting it changes nothing cached.
    let current = served.last().unwrap();
    let tail = &current.map.shards[1];
    let before = cached_revisions(&path);
    refused_sync(&mut sqlite, current, &chain);
    refused_sync(&mut memory, current, &chain);
    for store in [&sqlite as &dyn WalletStore, &memory] {
        assert_caches(store, &[&sealed, tail], &[], &run, &sealed);
    }
    assert_eq!(cached_revisions(&path), before);
}

/// Syncs to a target the publication's tail does not end on, which the sync
/// refuses before it adopts the map.
fn refused_sync<S: WalletStore>(store: &mut S, served: &Served, chain: &StaticChain) {
    let options = HttpOptions::default();
    let mut filters = HttpFilterSource::new(&served.url, &options).unwrap();
    let mut transport = HttpShardTransport::new(&served.url, &options).unwrap();
    let geometry = parse_init(&transport.init().unwrap().0).unwrap();
    let (sealed, tail) = (&served.map.shards[0], &served.map.shards[1]);
    sync_into(
        store,
        &served.map,
        0,
        &geometry,
        chain,
        &mut StaticScripts(Vec::new()),
        &mut filters,
        &mut transport,
        &WorkLimits::UNLIMITED,
        &Anchor {
            height: tail.end_height,
            hash: sealed.terminal_block_hash.clone(),
        },
    )
    .unwrap_err();
}
