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
    use transparent_events::{
        FeeState, MAX_MONEY, ReceiveEvent, TransactionMetadata, TransparentEvent, Txid,
    };
    use zakura_pir_transparent::engine::testing::{cached_run, pending};

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
        let before = database_rows(&path);
        let before_events = store.events().unwrap();
        let before_pending = store.pending().unwrap();
        assert!(store.commit_shard(invalid).is_err());
        assert_eq!(database_rows(&path), before);
        assert_eq!(store.events().unwrap(), before_events);
        assert_eq!(store.pending().unwrap(), before_pending);
        drop(store);
        let mut store = SqliteStore::open(&path).unwrap();
        assert_eq!(database_rows(&path), before);
        assert_eq!(store.events().unwrap(), before_events);
        assert_eq!(store.pending().unwrap(), before_pending);
        store.commit_shard(valid.clone()).unwrap();
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
