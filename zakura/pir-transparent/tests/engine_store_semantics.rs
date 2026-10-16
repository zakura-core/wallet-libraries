//! The store contract, run against both reference implementations.
//!
//! The suite itself lives in `zakura_pir_transparent::engine::testing` so a wallet that
//! brings its own store can run the same one; what is here is only the three
//! constructors and the reopen check.

use zakura_pir_transparent::engine::MemoryStore;
use zakura_pir_transparent::engine::store::{Anchor, WalletStore};
use zakura_pir_transparent::engine::testing::{commit, identity, receive, script, suite};
use zakura_pir_transparent::engine_store::SqliteStore;

#[test]
fn metadata_survives_reopen_and_cross_script_contradictions_are_atomic() {
    use transparent_events::{FeeState, TransactionMetadata};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("metadata.sqlite");
    let metadata = TransactionMetadata {
        fee: FeeState::Exact(1000),
        transparent_input_count: 2,
        has_shielded_components: true,
    };
    let mut event = receive(1, 0, 5000, 10);
    event.event = event.event.with_metadata(Some(metadata));
    let mut store = SqliteStore::open(&path).unwrap();
    store.bind_set(&identity()).unwrap();
    store
        .commit_shard(commit(
            0,
            "r0",
            true,
            (0, 99),
            vec![event.clone()],
            vec![script(1)],
        ))
        .unwrap();
    drop(store);
    let mut store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.events().unwrap(), vec![event.clone()]);
    let before = store.last_commit().unwrap();
    let mut conflict = event.clone();
    conflict.script = script(2);
    conflict.event = match conflict.event {
        transparent_events::TransparentEvent::Receive(mut r) => {
            r.output_index = 1;
            transparent_events::TransparentEvent::Receive(r)
        }
        _ => unreachable!(),
    }
    .with_metadata(Some(TransactionMetadata {
        fee: FeeState::Exact(1001),
        ..metadata
    }));
    assert!(
        store
            .commit_shard(commit(
                1,
                "r1",
                true,
                (0, 99),
                vec![conflict],
                vec![script(2)]
            ))
            .is_err()
    );
    assert_eq!(store.events().unwrap(), vec![event]);
    assert_eq!(store.last_commit().unwrap(), before);
    assert!(store.coverage(&script(2)).unwrap().is_empty());
    let mut incompatible = identity();
    incompatible.shard_schema = "transparent-shard-v11".into();
    assert!(store.bind_set(&incompatible).is_err());
}

#[test]
fn the_memory_store_meets_the_contract() {
    suite(|| MemoryStore::with_pending_limit(8));
}

#[test]
fn the_sqlite_store_meets_the_contract_in_memory() {
    suite(|| SqliteStore::open_in_memory().unwrap().with_pending_limit(8));
}

#[test]
fn the_sqlite_store_meets_the_contract_on_disk_and_survives_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    suite(|| {
        // Each run starts from a fresh file.
        let _ = std::fs::remove_file(&path);
        SqliteStore::open(&path).unwrap().with_pending_limit(8)
    });

    // What was committed is there after the process forgets everything.
    let _ = std::fs::remove_file(&path);
    let mut store = SqliteStore::open(&path).unwrap();
    store.bind_set(&identity()).unwrap();
    store
        .commit_shard(commit(
            0,
            "r0",
            true,
            (0, 99),
            vec![receive(1, 0, 5_000, 10)],
            vec![script(1)],
        ))
        .unwrap();
    store
        .commit_anchor(
            &Anchor {
                height: 99,
                hash: "h".into(),
            },
            99,
            99,
        )
        .unwrap();
    drop(store);
    let store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.set_identity().unwrap(), Some(identity()));
    assert_eq!(store.anchor().unwrap().unwrap().height, 99);
    assert_eq!(store.ledger().unwrap().confirmed_balance(), 5_000);
    assert_eq!(store.coverage(&script(1)).unwrap().len(), 1);
    assert_eq!(store.last_commit().unwrap(), 2);
}

/// Versions before schema 6 hold walks or coverage this build cannot read.
#[test]
fn a_store_from_an_unsupported_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v5.sqlite");
    let mut store = SqliteStore::open(&path).unwrap();
    store.bind_set(&identity()).unwrap();
    drop(store);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("UPDATE wallet_meta SET value = '5' WHERE key = 'schema_version';")
        .unwrap();
    drop(db);
    assert!(SqliteStore::open(&path).is_err());
}

/// A content-failure count is on disk once its commit returns, and keeps
/// counting after a reopen.
#[test]
fn entry_failures_survive_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("failures.sqlite");
    let mut store = SqliteStore::open(&path).unwrap();
    store.bind_set(&identity()).unwrap();
    let mut failed = commit(4, "r0", true, (0, 99), vec![], vec![]);
    failed.failed_entries = vec![script(1)];
    store.commit_shard(failed.clone()).unwrap();
    drop(store);
    let mut store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.entry_failures(4, &script(1)).unwrap(), 1);
    store.commit_shard(failed).unwrap();
    drop(store);
    let store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.entry_failures(4, &script(1)).unwrap(), 2);
    assert_eq!(store.entry_failures(4, &script(2)).unwrap(), 0);
}

/// A walk's cursor and carried events, and the run cache, are on disk once
/// their commit returns.
#[test]
fn a_walk_cursor_and_the_run_cache_survive_reopening() {
    use zakura_pir_transparent::engine::store::RunCursor;
    use zakura_pir_transparent::engine::testing::{cached_run, pending};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("walk.sqlite");
    let mut store = SqliteStore::open(&path).unwrap();
    store.bind_set(&identity()).unwrap();
    let mut c = commit(1, "r0", true, (0, 99), vec![], vec![]);
    c.pending_upsert.push(pending(1, "r0"));
    let run = zakura_pir_transparent::engine::store::CachedRun {
        shard_id: 1,
        older: Some("older-child".into()),
        ..cached_run("child", 1, &[10, 20])
    };
    c.cached_runs.push(run.clone());
    store.commit_shard(c).unwrap();
    drop(store);
    let mut store = SqliteStore::open(&path).unwrap();
    let mut restored = store.pending().unwrap().remove(0);
    assert_eq!(
        restored,
        zakura_pir_transparent::engine::PendingPages {
            id: restored.id,
            ..pending(1, "r0")
        }
    );
    assert_eq!(
        store.cached_run("child", &script(1)).unwrap(),
        Some(run.clone())
    );
    restored.cursor = RunCursor {
        child: 2,
        row: 70_000,
        older_runs: Some(4),
    };
    restored.carried.reverse();
    restored.fragments = vec![
        transparent_shard::page_row::encode_page_row(&[
            transparent_shard::page_row::PageEntry::new([1; 14], 0, 2, run.events.clone()).unwrap(),
        ])
        .unwrap(),
    ];
    let mut c = commit(1, "r0", true, (0, 99), vec![], vec![]);
    c.pending_upsert.push(restored.clone());
    store.commit_shard(c).unwrap();
    drop(store);
    assert_eq!(
        SqliteStore::open(&path).unwrap().pending().unwrap(),
        vec![restored]
    );
}

mod durable_progress_reports {
    use super::*;
    use zakura_pir_transparent::engine::client::Table;
    use zakura_pir_transparent::engine::transport::{BoxError, FilterSource, ShardTransport};
    use zakura_pir_transparent::engine::{
        Completion, IncompleteReason, ScriptEntry, ScriptOrigin, ServiceGeometry, SetIdentity,
        StaticChain, StaticScripts, TransparentSync, WorkLimits, sync_into,
    };

    struct Never;
    impl FilterSource for Never {
        fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
            panic!("progress must not fetch maps")
        }
        fn filter(&mut self, _: u64) -> Result<(Vec<u8>, u64), BoxError> {
            panic!("progress must not fetch filters")
        }
    }
    impl ShardTransport for Never {
        fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
            panic!("progress must not fetch init")
        }
        fn manifest(&mut self, _: u64, _: &str) -> Result<(Vec<u8>, u64), BoxError> {
            panic!("progress must not fetch manifests")
        }
        fn setup(&mut self, _: u64, _: &str, _: Table, _: u32) -> Result<(Vec<u8>, u64), BoxError> {
            panic!("progress must not fetch setup")
        }
        fn query(&mut self, _: u64, _: &str, _: Table, _: &[u8]) -> Result<Vec<u8>, BoxError> {
            panic!("progress must not send queries")
        }
    }
    fn watched(tag: u8, from: u64) -> ScriptEntry {
        ScriptEntry {
            script: script(tag),
            origin: ScriptOrigin::Imported,
            required_from: from,
        }
    }
    fn facade(path: &std::path::Path) -> TransparentSync {
        TransparentSync::new(
            Box::new(SqliteStore::open(path).unwrap()),
            Box::new(Never),
            Box::new(Never),
        )
    }
    fn seed(path: &std::path::Path) -> transparent_filter::ShardMap {
        let map: transparent_filter::ShardMap =
            serde_json::from_slice(include_bytes!("fixtures/shard-map.json")).unwrap();
        let mut store = SqliteStore::open(path).unwrap();
        store
            .bind_set(&SetIdentity::of_schema(&map, transparent_shard::SCHEMA))
            .unwrap();
        store.add_scripts(&[watched(1, map.start_height)]).unwrap();
        for entry in &map.shards {
            let mut event = receive(
                entry.shard_id as u8 + 1,
                0,
                5000,
                entry.start_height as u32 + 10,
            );
            event.script = script(1);
            let mut saved = commit(
                entry.shard_id,
                &entry.manifest_digest,
                entry.sealed,
                (entry.start_height, entry.end_height),
                vec![event],
                vec![script(1)],
            );
            saved.terminal_block_hash = entry.terminal_block_hash.clone();
            store.commit_shard(saved).unwrap();
            if entry.sealed {
                store
                    .commit_anchor(
                        &Anchor {
                            height: entry.end_height,
                            hash: entry.terminal_block_hash.clone(),
                        },
                        entry.end_height,
                        entry.end_height,
                    )
                    .unwrap();
            }
        }
        map
    }

    #[test]
    fn reopened_progress_survives_unknown_targets_and_lagging_publications() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("progress.sqlite");
        let map = seed(&path);
        let sealed = &map.shards[0];
        let tail = map.shards.last().unwrap();
        // The tail was committed after the last anchor checkpoint.
        let status = facade(&path).status().unwrap();
        assert_eq!(
            (status.covered_through, status.settled_through),
            (tail.end_height, sealed.end_height)
        );
        let mut store = SqliteStore::open(&path).unwrap();
        let target = Anchor {
            height: tail.end_height,
            hash: tail.terminal_block_hash.clone(),
        };
        let geometry = ServiceGeometry {
            schema: transparent_shard::SCHEMA.into(),
            geometries: vec![],
        };
        let ordinary = sync_into(
            &mut store,
            &map,
            0,
            &geometry,
            &StaticChain::from_map(&map),
            &mut StaticScripts(vec![watched(1, map.start_height)]),
            &mut Never,
            &mut Never,
            &WorkLimits::UNLIMITED,
            &target,
        )
        .unwrap();
        assert_eq!(ordinary.completion, Completion::Complete);
        assert_eq!(
            (ordinary.covered_through, ordinary.settled_through),
            (tail.end_height, sealed.end_height)
        );
        let before = (
            store.last_commit().unwrap(),
            store.events().unwrap(),
            store.coverage(&script(1)).unwrap(),
            store.pending().unwrap(),
        );
        let unknown = sync_into(
            &mut store,
            &map,
            0,
            &geometry,
            &StaticChain::default(),
            &mut StaticScripts(vec![]),
            &mut Never,
            &mut Never,
            &WorkLimits::UNLIMITED,
            &target,
        )
        .unwrap();
        assert!(matches!(
            unknown.completion,
            Completion::Incomplete {
                reason: IncompleteReason::ChainUnknown { .. },
                ..
            }
        ));
        let mut behind = map.clone();
        behind.shards.pop();
        let lagging = sync_into(
            &mut store,
            &behind,
            0,
            &geometry,
            &StaticChain::from_map(&map),
            &mut StaticScripts(vec![]),
            &mut Never,
            &mut Never,
            &WorkLimits::UNLIMITED,
            &target,
        )
        .unwrap();
        assert!(matches!(
            lagging.completion,
            Completion::Incomplete {
                reason: IncompleteReason::PublicationBehind { .. },
                ..
            }
        ));
        for report in [unknown, lagging] {
            assert_eq!(
                (report.covered_through, report.settled_through),
                (ordinary.covered_through, ordinary.settled_through)
            );
            assert_eq!(report.provisional, ordinary.provisional);
        }
        assert_eq!(
            (
                store.last_commit().unwrap(),
                store.events().unwrap(),
                store.coverage(&script(1)).unwrap(),
                store.pending().unwrap()
            ),
            before
        );
    }

    #[test]
    fn status_recomputes_for_added_scripts_partial_progress_and_host_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rollback.sqlite");
        let map = seed(&path);
        let sealed = &map.shards[0];
        let tail = map.shards.last().unwrap();
        let mut host = facade(&path);
        assert_eq!(host.status().unwrap().covered_through, tail.end_height);
        let mut store = SqliteStore::open(&path).unwrap();
        // Even a stale successful checkpoint must not cover a newly added script.
        store
            .commit_anchor(
                &Anchor {
                    height: tail.end_height,
                    hash: tail.terminal_block_hash.clone(),
                },
                sealed.end_height,
                tail.end_height,
            )
            .unwrap();
        store.add_scripts(&[watched(2, map.start_height)]).unwrap();
        let status = host.status().unwrap();
        assert_eq!(
            (status.covered_through, status.settled_through),
            (map.start_height - 1, map.start_height - 1)
        );
        let mut partial = commit(
            0,
            &sealed.manifest_digest,
            true,
            (sealed.start_height, sealed.end_height),
            vec![],
            vec![script(2)],
        );
        partial.terminal_block_hash = sealed.terminal_block_hash.clone();
        store.commit_shard(partial).unwrap();
        drop(store);
        let status = host.status().unwrap();
        assert_eq!(
            (status.covered_through, status.settled_through),
            (sealed.end_height, sealed.end_height)
        );
        let rollback = map.start_height + 100;
        let status = host
            .rollback_to(Anchor {
                height: rollback,
                hash: "11".repeat(32),
            })
            .unwrap();
        assert_eq!(
            (status.covered_through, status.settled_through),
            (rollback, rollback)
        );
        drop(host);
        let status = facade(&path).status().unwrap();
        assert_eq!(
            (status.covered_through, status.settled_through),
            (rollback, rollback)
        );
    }
}
