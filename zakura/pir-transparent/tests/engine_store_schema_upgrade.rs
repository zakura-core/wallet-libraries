//! Opening a published-format cache preserves recovery state and upgrades atomically.

use rusqlite::{Connection, params, types::Value};
use std::{collections::BTreeMap, path::Path};
use zakura_pir_transparent::engine::{
    store::{Anchor, StoreError, WalletStore},
    testing::{commit, identity, receive, script, spend},
};
use zakura_pir_transparent::engine_store::SqliteStore;

fn populated_cache6(path: &Path) -> Connection {
    let db = Connection::open(path).unwrap();
    db.execute_batch(include_str!("fixtures/schema6.sql"))
        .unwrap();
    for (key, value) in [
        ("set_identity", serde_json::to_string(&identity()).unwrap()),
        (
            "anchor",
            serde_json::to_string(&Anchor {
                height: 99,
                hash: "h".into(),
            })
            .unwrap(),
        ),
        ("covered_through", "99".into()),
        ("settled_through", "99".into()),
    ] {
        db.execute(
            "INSERT INTO wallet_meta VALUES (?1, ?2)",
            params![key, value],
        )
        .unwrap();
    }
    let script = script(1);
    let received = receive(1, 0, 5_000, 10).event.to_bytes().unwrap();
    let spent = spend(1, 1, 0, 3, 20).event.to_bytes().unwrap();
    let mut framed = b"EV3\0".to_vec();
    framed.extend_from_slice(&(received.len() as u16).to_le_bytes());
    framed.extend_from_slice(&received);
    db.execute("INSERT INTO scripts VALUES (?1, 'derived', 0)", [&script])
        .unwrap();
    db.execute(
        "INSERT INTO coverage VALUES (?1, 0, 99, 'settled', 0, 'r0', 'h', NULL)",
        [&script],
    )
    .unwrap();
    db.execute(
        "INSERT INTO receives VALUES (?1, 0, ?2, 10, ?3, 0, 'r0')",
        params![vec![1u8; 32], script, received.as_slice()],
    )
    .unwrap();
    db.execute(
        "INSERT INTO spends VALUES (?1, 0, ?2, 0, ?3, 20, ?4, 0, 'r0')",
        params![vec![3u8; 32], vec![1u8; 32], script, spent.as_slice()],
    )
    .unwrap();
    let fragment = transparent_shard::page_row::encode_page_row(&[
        transparent_shard::page_row::PageEntry::new(
            [1; 14],
            0,
            2,
            vec![receive(1, 0, 5_000, 10).event],
        )
        .unwrap(),
    ])
    .unwrap();
    db.execute(
        "INSERT INTO pending_work VALUES (7, 1, 'r1', ?1, 3, 4, 2, ?2, ?3, NULL, 1)",
        params![script, framed, fragment],
    )
    .unwrap();
    db.execute(
        "INSERT INTO run_cache VALUES ('child', ?1, 0, ?2, 'older')",
        params![script, framed],
    )
    .unwrap();
    db.execute_batch(
        "INSERT INTO setup_cache VALUES ('set', 'r0', 'directory', 0, 'AQ==', 'digest');
         INSERT INTO filter_cache VALUES ('r0', 'hash', 1, X'010203');
         INSERT INTO commits VALUES (21, 'shard', '0:r0');
         CREATE TABLE pir_bridge_catalog (source BLOB PRIMARY KEY, lineage INTEGER, exported INTEGER);
         INSERT INTO pir_bridge_catalog VALUES (X'0102', 4, 1);",
    ).unwrap();
    db
}

/// Compare every saved row, including catalog data and SQLite sequence values.
fn saved_rows(db: &Connection) -> BTreeMap<String, Vec<Vec<Value>>> {
    let tables: Vec<String> = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name != 'failed_entries' ORDER BY name")
        .unwrap().query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
    tables
        .into_iter()
        .map(|table| {
            let filter = if table == "wallet_meta" {
                " WHERE key != 'schema_version'"
            } else {
                ""
            };
            let mut stmt = db
                .prepare(&format!("SELECT * FROM \"{table}\"{filter} ORDER BY rowid"))
                .unwrap();
            let columns = stmt.column_count();
            let rows = stmt
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<Result<Vec<Value>, _>>()
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            (table, rows)
        })
        .collect()
}

fn version(db: &Connection) -> String {
    db.query_row(
        "SELECT value FROM wallet_meta WHERE key = 'schema_version'",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn a_published_cache_upgrades_without_losing_recovery_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.sqlite");
    let db = populated_cache6(&path);
    let before = saved_rows(&db);
    assert_eq!(version(&db), "6");
    drop(db);

    let mut store = SqliteStore::open(&path).unwrap();
    let db = Connection::open(&path).unwrap();
    assert_eq!(version(&db), "7");
    assert_eq!(saved_rows(&db), before);
    assert_eq!(store.set_identity().unwrap(), Some(identity()));
    assert_eq!(store.anchor().unwrap().unwrap().height, 99);
    assert_eq!(store.ledger().unwrap().confirmed_balance(), 0);
    assert_eq!(store.coverage(&script(1)).unwrap().len(), 1);
    assert_eq!(store.pending().unwrap()[0].fragments.len(), 1);
    assert!(store.cached_run("child", &script(1)).unwrap().is_some());
    assert_eq!(store.last_commit().unwrap(), 21);
    assert_eq!(store.entry_failures(1, "r1", &script(1)).unwrap(), 0);
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM failed_entries", [], |row| row
            .get::<_, u64>(0))
            .unwrap(),
        0
    );

    let mut failed = commit(1, "r1", true, (0, 99), vec![], vec![]);
    failed.failed_entries = vec![script(1)];
    store.commit_shard(failed).unwrap();
    drop(store);
    let before_reopen = saved_rows(&db);
    drop(db);
    let store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.entry_failures(1, "r1", &script(1)).unwrap(), 1);
    assert_eq!(saved_rows(&Connection::open(&path).unwrap()), before_reopen);
}

#[test]
fn a_failed_upgrade_rolls_back_the_new_table_and_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.sqlite");
    let db = populated_cache6(&path);
    let before = saved_rows(&db);
    db.execute_batch(
        "CREATE TRIGGER refuse_upgrade BEFORE UPDATE OF value ON wallet_meta
        WHEN OLD.key = 'schema_version' AND NEW.value = '7'
        BEGIN SELECT RAISE(ABORT, 'injected upgrade failure'); END;",
    )
    .unwrap();
    assert!(SqliteStore::open(&path).is_err());
    assert_eq!(version(&db), "6");
    assert_eq!(saved_rows(&db), before);
    assert!(
        !db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'failed_entries')",
            [],
            |row| row.get::<_, bool>(0)
        )
        .unwrap()
    );
    db.execute_batch("DROP TRIGGER refuse_upgrade").unwrap();
    SqliteStore::open(&path).unwrap();
    assert_eq!(version(&db), "7");
    assert_eq!(saved_rows(&db), before);
}

#[test]
fn unsupported_versions_are_refused_without_modification() {
    for incompatible in ["5", "8", "invalid"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.sqlite");
        let db = populated_cache6(&path);
        db.execute(
            "UPDATE wallet_meta SET value = ?1 WHERE key = 'schema_version'",
            [incompatible],
        )
        .unwrap();
        let before = saved_rows(&db);
        assert!(SqliteStore::open(&path).is_err());
        assert_eq!(version(&db), incompatible);
        assert_eq!(saved_rows(&db), before);
        assert!(
            !db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'failed_entries')",
                [],
                |row| row.get::<_, bool>(0)
            )
            .unwrap()
        );
    }
}

/// Everything a refused open must leave as it was: the persistent journal mode,
/// every schema object's SQL and every row, the version marker included.
type FileState = (
    String,
    Vec<(String, String, Option<String>)>,
    BTreeMap<String, Vec<Vec<Value>>>,
);

fn file_state(path: &Path) -> FileState {
    let db = Connection::open(path).unwrap();
    let journal = db
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    let schema = db
        .prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let rows = tables
        .into_iter()
        .map(|table| {
            let mut stmt = db
                .prepare(&format!("SELECT * FROM \"{table}\" ORDER BY rowid"))
                .unwrap();
            let columns = stmt.column_count();
            let rows = stmt
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<Result<Vec<Value>, _>>()
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            (table, rows)
        })
        .collect();
    (journal, schema, rows)
}

/// Opening the file at `path` is refused as incompatible and changes nothing.
fn assert_refused_unchanged(path: &Path) {
    let before = file_state(path);
    assert_eq!(
        before.0, "delete",
        "the fixture starts in rollback journal mode"
    );
    match SqliteStore::open(path) {
        Err(StoreError::Corrupt(_)) => {}
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(_) => panic!("an incompatible file was opened"),
    }
    assert_eq!(file_state(path), before);
}

#[test]
fn a_metadata_table_without_its_version_is_refused_without_modification() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.sqlite");
    let db = populated_cache6(&path);
    db.execute("DELETE FROM wallet_meta WHERE key = 'schema_version'", [])
        .unwrap();
    // An incompatible layout the store would otherwise keep and stamp.
    db.execute_batch("DROP TABLE filter_cache; CREATE TABLE filter_cache (other TEXT);")
        .unwrap();
    drop(db);
    assert_refused_unchanged(&path);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE wallet_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         INSERT INTO wallet_meta VALUES ('anchor', 'kept');",
    )
    .unwrap();
    drop(db);
    assert_refused_unchanged(&path);
}

#[test]
fn unknown_versions_are_refused_without_changing_schema_or_journal_mode() {
    for incompatible in ["5", "8", "invalid", ""] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.sqlite");
        let db = populated_cache6(&path);
        db.execute(
            "UPDATE wallet_meta SET value = ?1 WHERE key = 'schema_version'",
            [incompatible],
        )
        .unwrap();
        drop(db);
        assert_refused_unchanged(&path);
    }
}

#[test]
fn orphaned_store_tables_without_metadata_are_refused_without_modification() {
    // A cache whose metadata table is gone keeps its other tables and rows.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.sqlite");
    let db = populated_cache6(&path);
    db.execute_batch("DROP TABLE wallet_meta").unwrap();
    drop(db);
    assert_refused_unchanged(&path);

    // One table under a store name, in a layout this build does not write.
    for table in ["coverage", "run_cache", "filter_cache", "commits"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(&format!(
            "CREATE TABLE {table} (other TEXT); INSERT INTO {table} VALUES ('kept');"
        ))
        .unwrap();
        drop(db);
        assert_refused_unchanged(&path);
    }
}

#[test]
fn store_names_in_another_case_are_refused_without_modification() {
    // SQLite resolves names case-insensitively, so the schema's `IF NOT
    // EXISTS` and every later query would reach these objects as the store's.
    for batch in [
        "CREATE TABLE SCRIPTS (other TEXT); INSERT INTO SCRIPTS VALUES ('kept');",
        "CREATE TABLE Run_Cache (other TEXT); INSERT INTO Run_Cache VALUES ('kept');",
        "CREATE TABLE application (x TEXT); INSERT INTO application VALUES ('kept');
         CREATE INDEX Spends_By_Transaction ON application(x);",
        "CREATE TABLE WALLET_META (key TEXT PRIMARY KEY, value TEXT);
         INSERT INTO WALLET_META VALUES ('anchor', 'kept');",
        "CREATE TABLE Wallet_Meta (key TEXT PRIMARY KEY, value TEXT);
         INSERT INTO Wallet_Meta VALUES ('schema_version', '5');",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(batch).unwrap();
        drop(db);
        assert_refused_unchanged(&path);
    }
}

#[test]
fn unrelated_tables_in_the_file_still_open_as_a_fresh_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE pir_bridge_catalog (source BLOB PRIMARY KEY, lineage INTEGER);
         INSERT INTO pir_bridge_catalog VALUES (X'0102', 4);
         CREATE TABLE application_settings (name TEXT PRIMARY KEY, value TEXT);
         INSERT INTO application_settings VALUES ('theme', 'dark');
         CREATE TABLE counters (id INTEGER PRIMARY KEY AUTOINCREMENT, n INTEGER);
         INSERT INTO counters (n) VALUES (1);",
    )
    .unwrap();
    drop(db);
    let (_, _, foreign) = file_state(&path);

    let store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.set_identity().unwrap(), None);
    assert_eq!(store.last_commit().unwrap(), 0);
    drop(store);
    assert_eq!(version(&Connection::open(&path).unwrap()), "7");
    let (journal, _, rows) = file_state(&path);
    assert_eq!(journal, "wal");
    for (table, held) in &foreign {
        assert_eq!(rows.get(table), Some(held), "{table} changed");
    }
    // The version 7 store, unrelated tables and all, reopens.
    let store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.last_commit().unwrap(), 0);
}
