//! The store contract, run against both reference implementations.
//!
//! The suite itself lives in `zakura_pir_client::transparent::engine::testing` so a wallet that
//! brings its own store can run the same one; what is here is only the three
//! constructors and the reopen check.

use zakura_pir_client::transparent::engine::MemoryStore;
use zakura_pir_client::transparent::engine::store::{Anchor, WalletStore};
use zakura_pir_client::transparent::engine::testing::{commit, identity, receive, script, suite};
use zakura_pir_client::transparent::engine_store::SqliteStore;

#[test]
fn metadata_survives_reopen_and_cross_script_contradictions_are_atomic() {
    use zakura_pir_protocol::transparent::events::{FeeState, TransactionMetadata};
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
        zakura_pir_protocol::transparent::events::TransparentEvent::Receive(mut r) => {
            r.output_index = 1;
            zakura_pir_protocol::transparent::events::TransparentEvent::Receive(r)
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
    assert_eq!(store.entry_failures(4, "r0", &script(1)).unwrap(), 1);
    store.commit_shard(failed).unwrap();
    drop(store);
    let store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.entry_failures(4, "r0", &script(1)).unwrap(), 2);
    assert_eq!(store.entry_failures(4, "r0", &script(2)).unwrap(), 0);
}

/// A walk's cursor and carried events, and the run cache, are on disk once
/// their commit returns.
#[test]
fn a_walk_cursor_and_the_run_cache_survive_reopening() {
    use zakura_pir_client::transparent::engine::store::RunCursor;
    use zakura_pir_client::transparent::engine::testing::{cached_run, pending};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("walk.sqlite");
    let mut store = SqliteStore::open(&path).unwrap();
    store.bind_set(&identity()).unwrap();
    let mut c = commit(1, "r0", true, (0, 99), vec![], vec![]);
    c.pending_upsert.push(pending(1, "r0"));
    let run = zakura_pir_client::transparent::engine::store::CachedRun {
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
        zakura_pir_client::transparent::engine::PendingPages {
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
        zakura_pir_publisher::transparent::page_row::encode_page_row(&[
            zakura_pir_publisher::transparent::page_row::PageEntry::new(
                [1; 14],
                0,
                2,
                run.events.clone(),
            )
            .unwrap(),
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
    use zakura_pir_client::transparent::engine::client::Table;
    use zakura_pir_client::transparent::engine::transport::{
        BoxError, FilterSource, ShardTransport,
    };
    use zakura_pir_client::transparent::engine::{
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
    fn seed(path: &std::path::Path) -> zakura_pir_client::transparent::filter::ShardMap {
        let map: zakura_pir_client::transparent::filter::ShardMap =
            serde_json::from_slice(include_bytes!("fixtures/shard-map.json")).unwrap();
        let mut store = SqliteStore::open(path).unwrap();
        store
            .bind_set(&SetIdentity::of_schema(
                &map,
                zakura_pir_publisher::transparent::SCHEMA,
            ))
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
            schema: zakura_pir_publisher::transparent::SCHEMA.into(),
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

/// Compare every persisted value, including identity, checkpoints, coverage,
/// unfinished walks, cached runs and the commit sequence.
fn database_rows(path: &std::path::Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let connection = rusqlite::Connection::open(path).unwrap();
    let tables = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let name = table.replace('"', "\"\"");
            let mut query = connection
                .prepare(&format!("SELECT * FROM \"{name}\" ORDER BY rowid"))
                .unwrap();
            let columns = query.column_count();
            let rows = query
                .query_map([], |row| {
                    (0..columns)
                        .map(|index| row.get(index))
                        .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (table, rows)
        })
        .collect()
}

#[test]
fn invalid_saved_events_leave_every_table_unchanged_and_allow_a_valid_retry() {
    use zakura_pir_client::transparent::engine::testing::{cached_run, pending};
    use zakura_pir_protocol::transparent::events::{
        FeeState, MAX_MONEY, ReceiveEvent, TransactionMetadata, TransparentEvent, Txid,
    };

    #[derive(Clone, Copy)]
    enum InvalidAt {
        Ledger,
        NewPending,
        ExistingPending,
        CachedRun,
        EmptyRecord,
    }
    for location in [
        InvalidAt::Ledger,
        InvalidAt::NewPending,
        InvalidAt::ExistingPending,
        InvalidAt::CachedRun,
        InvalidAt::EmptyRecord,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.sqlite");
        let mut store = SqliteStore::open(&path).unwrap();
        store.bind_set(&identity()).unwrap();
        let mut initial = commit(
            0,
            "r0",
            false,
            (0, 99),
            vec![receive(1, 0, 5000, 10)],
            vec![script(1)],
        );
        initial.pending_upsert.push(pending(1, "r0"));
        initial.cached_runs.push(cached_run("held-child", 1, &[20]));
        let mut memory = MemoryStore::new();
        memory.bind_set(&identity()).unwrap();
        memory.commit_shard(initial.clone()).unwrap();
        store.commit_shard(initial).unwrap();
        store
            .commit_anchor(
                &Anchor {
                    height: 99,
                    hash: format!("{:064x}", 99),
                },
                0,
                99,
            )
            .unwrap();
        let held = store.pending().unwrap().remove(0);
        let mut valid = commit(
            1,
            "r1",
            false,
            (100, 199),
            vec![receive(2, 0, 7000, 110)],
            vec![script(2)],
        );
        valid.pending_complete.push(held.id.unwrap());
        valid.pending_upsert.push(pending(2, "r1"));
        valid.cached_runs.push(cached_run("next-child", 2, &[120]));
        if matches!(location, InvalidAt::ExistingPending) {
            valid.pending_complete.clear();
            valid.pending_upsert = vec![held.clone()];
            valid.pending_upsert[0].cursor.row += 1;
        }
        let mut invalid = valid.clone();
        let metadata = Some(TransactionMetadata {
            fee: FeeState::Exact(MAX_MONEY + 1),
            transparent_input_count: 1,
            has_shielded_components: false,
        });
        match location {
            InvalidAt::Ledger => {
                invalid.events[0].event = invalid.events[0].event.with_metadata(metadata)
            }
            InvalidAt::NewPending | InvalidAt::ExistingPending => {
                invalid.pending_upsert[0].carried[0] =
                    invalid.pending_upsert[0].carried[0].with_metadata(metadata);
            }
            InvalidAt::CachedRun => {
                invalid.cached_runs[0].events[0] =
                    invalid.cached_runs[0].events[0].with_metadata(metadata)
            }
            InvalidAt::EmptyRecord => {
                invalid.events[0].event = TransparentEvent::Receive(ReceiveEvent {
                    metadata: None,
                    height: 0,
                    txid: Txid([0; 32]),
                    transaction_index: 0,
                    output_index: 0,
                    value: 0,
                    coinbase: false,
                })
            }
        }
        let before_memory = format!("{memory:?}");
        let before = database_rows(&path);
        let before_events = store.events().unwrap();
        let before_pending = store.pending().unwrap();
        let memory_error = memory.commit_shard(invalid.clone()).unwrap_err();
        let sqlite_error = store.commit_shard(invalid).unwrap_err();
        assert_eq!(memory_error.to_string(), sqlite_error.to_string());
        assert_eq!(format!("{memory:?}"), before_memory);
        assert_eq!(database_rows(&path), before);
        assert_eq!(store.events().unwrap(), before_events);
        assert_eq!(store.pending().unwrap(), before_pending);
        drop(store);
        let mut store = SqliteStore::open(&path).unwrap();
        assert_eq!(database_rows(&path), before);
        assert_eq!(store.events().unwrap(), before_events);
        assert_eq!(store.pending().unwrap(), before_pending);
        memory.commit_shard(valid.clone()).unwrap();
        store.commit_shard(valid.clone()).unwrap();
        assert_eq!(store.events().unwrap(), memory.events().unwrap());
        assert_eq!(store.pending().unwrap(), memory.pending().unwrap());
        assert_ne!(database_rows(&path), before);
        assert_eq!(store.events().unwrap().len(), 2);
        assert_eq!(
            store.pending().unwrap()[0].carried,
            valid.pending_upsert[0].carried
        );
        assert_eq!(
            store.cached_run("next-child", &script(2)).unwrap(),
            Some(valid.cached_runs[0].clone())
        );
        assert_eq!(store.coverage(&script(2)).unwrap()[0].end_height, 199);
    }
}

#[test]
fn conflicting_events_in_one_commit_are_atomic_and_exact_duplicates_are_retryable() {
    use zakura_pir_client::transparent::engine::ledger::LedgerError;
    use zakura_pir_client::transparent::engine::store::StoreError;
    use zakura_pir_client::transparent::engine::testing::spend;
    use zakura_pir_protocol::transparent::events::{
        FeeState, TransactionMetadata, TransparentEvent,
    };

    #[derive(Clone, Copy)]
    enum Conflict {
        ReceiveValue,
        ReceiveScript,
        SpendingTransaction,
        SpendingInput,
        SpendScript,
    }
    for metadata in [
        None,
        Some(TransactionMetadata {
            fee: FeeState::Exact(1000),
            transparent_input_count: 2,
            has_shielded_components: true,
        }),
    ] {
        for conflict in [
            Conflict::ReceiveValue,
            Conflict::ReceiveScript,
            Conflict::SpendingTransaction,
            Conflict::SpendingInput,
            Conflict::SpendScript,
        ] {
            let is_receive = matches!(conflict, Conflict::ReceiveValue | Conflict::ReceiveScript);
            let first = if is_receive {
                receive(1, 0, 5000, 110)
            } else {
                spend(1, 4, 0, 5, 110)
            };
            let mut second = first.clone();
            match conflict {
                Conflict::ReceiveValue => {
                    if let TransparentEvent::Receive(ref mut event) = second.event {
                        event.value += 1;
                    }
                }
                Conflict::ReceiveScript | Conflict::SpendScript => second.script = script(9),
                Conflict::SpendingTransaction => second = spend(1, 4, 0, 6, 110),
                Conflict::SpendingInput => {
                    if let TransparentEvent::Spend(ref mut event) = second.event {
                        event.input_index = 1;
                    }
                }
            }
            let first = {
                let mut event = first;
                event.event = event.event.with_metadata(metadata);
                event
            };
            second.event = second.event.with_metadata(metadata);
            for reversed in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("conflicts.sqlite");
                let mut store = SqliteStore::open(&path).unwrap();
                store.bind_set(&identity()).unwrap();
                let initial = commit(
                    0,
                    "r0",
                    true,
                    (0, 99),
                    vec![receive(8, 0, 3000, 10)],
                    vec![script(8)],
                );
                let mut memory = MemoryStore::new();
                memory.bind_set(&identity()).unwrap();
                memory.commit_shard(initial.clone()).unwrap();
                store.commit_shard(initial).unwrap();
                store
                    .commit_anchor(
                        &Anchor {
                            height: 99,
                            hash: format!("{:064x}", 99),
                        },
                        99,
                        99,
                    )
                    .unwrap();
                let mut events = vec![first.clone(), second.clone()];
                if reversed {
                    events.reverse();
                }
                let offered = commit(
                    1,
                    "r1",
                    true,
                    (100, 199),
                    events,
                    vec![script(1), script(9)],
                );
                let before = database_rows(&path);
                let before_memory = format!("{memory:?}");
                let memory_error = memory.commit_shard(offered.clone()).unwrap_err();
                let error = store.commit_shard(offered.clone()).unwrap_err();
                assert_eq!(memory_error.to_string(), error.to_string());
                assert_eq!(format!("{memory:?}"), before_memory);
                let mut observations = offered
                    .events
                    .iter()
                    .map(|stored| (stored.script.clone(), stored.event))
                    .collect::<Vec<_>>();
                let mut ledger = zakura_pir_client::transparent::engine::Ledger::new();
                let ledger_error = ledger.replay(&mut observations).unwrap_err();
                assert_eq!(
                    ledger_error.to_string(),
                    match &error {
                        StoreError::Contradiction(error) => error.to_string(),
                        _ => panic!("expected contradiction"),
                    }
                );
                assert!(matches!(
                    (is_receive, error),
                    (
                        true,
                        StoreError::Contradiction(LedgerError::ConflictingReceive(_, 0))
                    ) | (
                        false,
                        StoreError::Contradiction(LedgerError::DoubleSpend(_, 0))
                    )
                ));
                assert_eq!(database_rows(&path), before);
                drop(store);
                let mut store = SqliteStore::open(&path).unwrap();
                assert_eq!(database_rows(&path), before);
                let retry = commit(
                    1,
                    "r1",
                    true,
                    (100, 199),
                    vec![first.clone(), first.clone()],
                    vec![script(1)],
                );
                memory.commit_shard(retry.clone()).unwrap();
                store.commit_shard(retry.clone()).unwrap();
                assert_eq!(store.events().unwrap(), memory.events().unwrap());
                let retained = store.events().unwrap();
                assert_eq!(retained.len(), 2);
                store.commit_shard(retry).unwrap();
                assert_eq!(store.events().unwrap(), retained);
                drop(store);
                let store = SqliteStore::open(&path).unwrap();
                assert_eq!(store.events().unwrap(), retained);
                store.ledger().unwrap();
            }
        }
    }
}

#[test]
fn a_known_outpoint_cannot_be_spent_by_two_inputs_of_one_transaction() {
    use zakura_pir_client::transparent::engine::testing::spend;
    use zakura_pir_client::transparent::engine::{Ledger, LedgerError};
    use zakura_pir_protocol::transparent::events::TransparentEvent;
    let first = spend(4, 4, 0, 5, 110);
    let mut second = first.clone();
    if let TransparentEvent::Spend(ref mut event) = second.event {
        event.input_index = 1;
    }
    let mut ledger = Ledger::new();
    let received = receive(4, 0, 5000, 10);
    ledger
        .replay(&mut [
            (received.script, received.event),
            (first.script, first.event),
        ])
        .unwrap();
    assert!(matches!(
        ledger.extend(&mut [(second.script, second.event)]),
        Err(LedgerError::DoubleSpend(_, 0))
    ));
}

#[test]
fn unresolved_outpoint_conflicts_are_rejected_when_a_later_batch_arrives() {
    use zakura_pir_client::transparent::engine::testing::spend;
    use zakura_pir_client::transparent::engine::{Ledger, LedgerError};
    use zakura_pir_protocol::transparent::events::TransparentEvent;
    let first = spend(4, 4, 0, 5, 110);
    let mut second = first.clone();
    if let TransparentEvent::Spend(ref mut event) = second.event {
        event.input_index = 1;
    }
    let mut ledger = Ledger::new();
    ledger.replay(&mut [(first.script, first.event)]).unwrap();
    assert!(matches!(
        ledger.extend(&mut [(second.script, second.event)]),
        Err(LedgerError::DoubleSpend(_, 0))
    ));
    assert_eq!(ledger.unresolved().len(), 1);
}

#[test]
fn a_recut_reusing_a_failed_shard_id_starts_a_new_persisted_count() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recut-failures.sqlite");
    let mut store = SqliteStore::open(&path).unwrap();
    store.bind_set(&identity()).unwrap();
    let mut failed = commit(7, "old", true, (0, 99), vec![], vec![]);
    failed.failed_entries = vec![script(1)];
    for _ in 0..3 {
        store.commit_shard(failed.clone()).unwrap();
    }
    drop(store);
    let mut store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.entry_failures(7, "old", &script(1)).unwrap(), 3);
    assert_eq!(store.entry_failures(7, "recut", &script(1)).unwrap(), 0);
    let mut recut = commit(7, "recut", true, (200, 299), vec![], vec![]);
    recut.failed_entries = vec![script(1)];
    store.commit_shard(recut).unwrap();
    drop(store);
    let store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.entry_failures(7, "recut", &script(1)).unwrap(), 1);
    assert_eq!(store.entry_failures(7, "old", &script(1)).unwrap(), 0);
}

#[test]
fn legacy_failure_counts_without_a_revision_binding_do_not_hold_the_latest_revision() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy-failures.sqlite");
    let mut store = SqliteStore::open(&path).unwrap();
    store
        .commit_shard(commit(7, "old", true, (0, 99), vec![], vec![]))
        .unwrap();
    store
        .commit_shard(commit(7, "new", true, (0, 199), vec![], vec![]))
        .unwrap();
    drop(store);
    // An older writer retained old failures after a successful new revision,
    // and wrote neither a revision column nor an explicit metadata binding.
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "DELETE FROM wallet_meta WHERE key = 'failure_revision:7'",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO failed_entries (shard_id, script, failures) VALUES (7, ?1, 3)",
        [&script(1)],
    )
    .unwrap();
    drop(db);
    let mut store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.entry_failures(7, "new", &script(1)).unwrap(), 0);
    assert_eq!(store.entry_failures(7, "old", &script(1)).unwrap(), 0);
    let mut failed = commit(7, "new", true, (0, 199), vec![], vec![]);
    failed.failed_entries = vec![script(1)];
    store.commit_shard(failed).unwrap();
    drop(store);
    let store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.entry_failures(7, "new", &script(1)).unwrap(), 1);
}

#[test]
fn aggregate_overflow_does_not_poison_a_reopened_sqlite_store() {
    use zakura_pir_client::transparent::engine::{LedgerError, StoreError};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("overflow.sqlite");
    let mut store = SqliteStore::open(&path).unwrap();
    store.bind_set(&identity()).unwrap();
    store
        .commit_shard(commit(
            0,
            "r0",
            true,
            (0, 99),
            vec![receive(1, 0, u64::MAX, 10)],
            vec![script(1)],
        ))
        .unwrap();
    let before = store.events().unwrap();
    let before_id = store.last_commit().unwrap();
    assert!(matches!(
        store.commit_shard(commit(
            1,
            "r1",
            true,
            (100, 199),
            vec![receive(2, 0, 1, 110)],
            vec![script(2)]
        )),
        Err(StoreError::Contradiction(LedgerError::ValueOverflow))
    ));
    drop(store);
    let mut store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.events().unwrap(), before);
    assert_eq!(store.last_commit().unwrap(), before_id);
    assert!(store.coverage(&script(2)).unwrap().is_empty());
    assert_eq!(store.ledger().unwrap().confirmed_balance(), u64::MAX);
    // Removing the uncommitted output makes the same range safely retryable.
    store
        .commit_shard(commit(1, "r1", true, (100, 199), vec![], vec![script(2)]))
        .unwrap();
    assert_eq!(store.ledger().unwrap().confirmed_balance(), u64::MAX);
}
