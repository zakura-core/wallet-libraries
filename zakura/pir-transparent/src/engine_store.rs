//! A durable [`WalletStore`] on SQLite.
//!
//! The reference persistence for a returning wallet, and the one the tests
//! run crash and restart cases against. One SQLite file, one transaction per
//! shard commit, write-ahead logging with synchronous commits, so a commit
//! that returned is on disk and a commit that did not is not there at all.
//!
//! Every table's primary key is the identity the wallet library keys on: a
//! receive by outpoint, a spend by its spending input and the outpoint it
//! consumes, coverage by script and start height. A retry inserts nothing
//! new; a retry that differs is caught by comparing the row it collides with
//! and refused as a contradiction before anything is written.
//!
//! Kept behind its own feature so the engine stays pure Rust: a wallet that
//! brings its own storage does not compile SQLite to use the library.

use crate::engine::ledger::{LedgerError, check_event_identities};
use crate::engine::store::{
    Anchor, CachedRun, CoverageKind, CoverageRange, PendingPages, RunCursor, ScriptEntry,
    ScriptOrigin, SetIdentity, SetupBlob, SetupKey, ShardCommit, StoreError, StoredEvent,
    WalletStore, merge_coverage,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::{Path, PathBuf};
use transparent_events::{EVENT_BYTES, ReceiveEvent, SpendEvent, TransparentEvent, Txid};

/// Versioned persistence. Schema 7 holds schema-v12 chain walks, saved run
/// fragments, the run cache and per-entry content failures. Schema 6 upgrades
/// in place by adding the failure counts; other versions are refused.
pub const SCHEMA_VERSION: u32 = 7;

/// Default bound on pending page retrievals a commit may leave.
pub const DEFAULT_PENDING_LIMIT: usize = 4_096;

struct SpendRow {
    spending_txid: Vec<u8>,
    input_index: i64,
    event: Vec<u8>,
    script: Vec<u8>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS wallet_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scripts (
    script BLOB PRIMARY KEY,
    origin TEXT NOT NULL,
    required_from INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS coverage (
    script BLOB NOT NULL,
    start_height INTEGER NOT NULL,
    end_height INTEGER NOT NULL,
    kind TEXT NOT NULL,
    shard_id INTEGER NOT NULL,
    revision_digest TEXT NOT NULL,
    terminal_block_hash TEXT NOT NULL,
    source_anchor TEXT,
    PRIMARY KEY (script, start_height)
);
CREATE TABLE IF NOT EXISTS receives (
    txid BLOB NOT NULL,
    output_index INTEGER NOT NULL,
    script BLOB NOT NULL,
    height INTEGER NOT NULL,
    event BLOB NOT NULL,
    shard_id INTEGER NOT NULL,
    revision_digest TEXT NOT NULL,
    PRIMARY KEY (txid, output_index)
);
CREATE TABLE IF NOT EXISTS spends (
    spending_txid BLOB NOT NULL,
    input_index INTEGER NOT NULL,
    spent_txid BLOB NOT NULL,
    spent_output_index INTEGER NOT NULL,
    script BLOB NOT NULL,
    height INTEGER NOT NULL,
    event BLOB NOT NULL,
    shard_id INTEGER NOT NULL,
    revision_digest TEXT NOT NULL,
    PRIMARY KEY (spending_txid, input_index, spent_txid, spent_output_index),
    UNIQUE (spent_txid, spent_output_index)
);
CREATE INDEX IF NOT EXISTS spends_by_transaction ON spends(spending_txid);
CREATE TABLE IF NOT EXISTS pending_work (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shard_id INTEGER NOT NULL,
    revision_digest TEXT NOT NULL,
    script BLOB NOT NULL,
    cursor_child INTEGER NOT NULL,
    cursor_row INTEGER NOT NULL,
    cursor_older_runs INTEGER,
    carried BLOB NOT NULL,
    fragments BLOB NOT NULL,
    target_anchor TEXT,
    attempts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS run_cache (
    child_digest TEXT NOT NULL,
    script BLOB NOT NULL,
    shard_id INTEGER NOT NULL,
    events BLOB NOT NULL,
    older TEXT,
    PRIMARY KEY (child_digest, script)
);
CREATE INDEX IF NOT EXISTS run_cache_by_shard ON run_cache(shard_id, script);
CREATE TABLE IF NOT EXISTS setup_cache (
    set_digest TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    tbl TEXT NOT NULL,
    segment INTEGER NOT NULL,
    public_params_base64 TEXT NOT NULL,
    public_params_sha256 TEXT NOT NULL,
    PRIMARY KEY (set_digest, revision_digest, tbl, segment)
);
CREATE TABLE IF NOT EXISTS filter_cache (
    revision_digest TEXT PRIMARY KEY,
    filter_hash TEXT NOT NULL,
    sealed INTEGER NOT NULL,
    bytes BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS failed_entries (
    shard_id INTEGER NOT NULL,
    script BLOB NOT NULL,
    failures INTEGER NOT NULL,
    PRIMARY KEY (shard_id, script)
);
CREATE TABLE IF NOT EXISTS commits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL
);
"#;

pub struct SqliteStore {
    conn: Connection,
    path: Option<PathBuf>,
    pending_limit: usize,
}

fn io(error: rusqlite::Error) -> StoreError {
    StoreError::Io(error.to_string())
}

impl SqliteStore {
    /// Opens or creates the store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open(&path).map_err(io)?;
        let mut store = Self {
            conn,
            path: Some(path),
            pending_limit: DEFAULT_PENDING_LIMIT,
        };
        store.prepare()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(io)?;
        let mut store = Self {
            conn,
            path: None,
            pending_limit: DEFAULT_PENDING_LIMIT,
        };
        store.prepare()?;
        Ok(store)
    }

    pub fn with_pending_limit(mut self, limit: usize) -> Self {
        self.pending_limit = limit;
        self
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    fn prepare(&mut self) -> Result<(), StoreError> {
        let target_version = SCHEMA_VERSION.to_string();
        // Fence unknown readers before changing journal mode or creating indexes.
        admit(&self.conn)?;
        // Durable on every commit: a commit that returned is on disk.
        self.conn
            .execute_batch(
                "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;",
            )
            .map_err(io)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io)?;
        // Admit again under the write lock: another opener may have created
        // or upgraded the store after the initial compatibility check.
        let version = admit(&tx)?;
        // Existing tables and their rows are untouched. For schema 6 this
        // creates only the empty failure-count table. Its creation and the
        // version update either both commit or both roll back.
        tx.execute_batch(SCHEMA).map_err(io)?;
        if version.as_deref() != Some(target_version.as_str()) {
            tx.execute(
                "INSERT INTO wallet_meta (key, value) VALUES ('schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [target_version],
            )
            .map_err(io)?;
        }
        tx.commit().map_err(io)?;
        Ok(())
    }

    fn failure_revision(conn: &Connection, shard_id: u64) -> Result<Option<String>, StoreError> {
        // Historic aggregate counts can span multiple revisions. The latest
        // commit cannot establish which revision caused those failures; only
        // an explicit binding identifies counts safe to apply to a revision.
        conn.query_row(
            "SELECT value FROM wallet_meta WHERE key = ?1",
            [format!("failure_revision:{shard_id}")],
            |row| row.get(0),
        )
        .optional()
        .map_err(io)
    }

    fn meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        self.conn
            .query_row(
                "SELECT value FROM wallet_meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(io)
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO wallet_meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map(|_| ())
            .map_err(io)
    }

    fn record_commit(conn: &Connection, kind: &str, detail: &str) -> Result<u64, StoreError> {
        conn.execute(
            "INSERT INTO commits (kind, detail) VALUES (?1, ?2)",
            params![kind, detail],
        )
        .map_err(io)?;
        Ok(conn.last_insert_rowid() as u64)
    }

    fn cached_run_in(
        conn: &Connection,
        child_digest: &str,
        script: &[u8],
    ) -> Result<Option<CachedRun>, StoreError> {
        let held: Option<(i64, Vec<u8>, Option<String>)> = conn
            .query_row(
                "SELECT shard_id, events, older FROM run_cache WHERE child_digest = ?1 AND script = ?2",
                params![child_digest, script],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(io)?;
        held.map(|(shard_id, events, older)| {
            Ok(CachedRun {
                child_digest: child_digest.to_string(),
                script: script.to_vec(),
                shard_id: u64::try_from(shard_id).map_err(|_| {
                    StoreError::Corrupt("a cached run's shard id is negative".into())
                })?,
                events: decode_events(&events, usize::MAX)?,
                older,
            })
        })
        .transpose()
    }

    fn coverage_of(conn: &Connection, script: &[u8]) -> Result<Vec<CoverageRange>, StoreError> {
        let mut statement = conn
            .prepare(
                "SELECT start_height, end_height, kind, shard_id, revision_digest, terminal_block_hash, source_anchor \
                 FROM coverage WHERE script = ?1 ORDER BY start_height",
            )
            .map_err(io)?;
        let rows = statement
            .query_map(params![script], |row| {
                Ok(CoverageRange {
                    source_anchor: decode_anchor(row.get(6)?)?,
                    script: script.to_vec(),
                    start_height: row.get::<_, i64>(0)? as u64,
                    end_height: row.get::<_, i64>(1)? as u64,
                    kind: if row.get::<_, String>(2)? == "settled" {
                        CoverageKind::Settled
                    } else {
                        CoverageKind::Provisional
                    },
                    shard_id: row.get::<_, i64>(3)? as u64,
                    revision_digest: row.get(4)?,
                    terminal_block_hash: row.get(5)?,
                })
            })
            .map_err(io)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(io)
    }

    fn write_coverage(
        conn: &Connection,
        script: &[u8],
        ranges: &[CoverageRange],
    ) -> Result<(), StoreError> {
        conn.execute("DELETE FROM coverage WHERE script = ?1", params![script])
            .map_err(io)?;
        for range in ranges {
            Self::insert_coverage(conn, script, range)?;
        }
        Ok(())
    }

    fn insert_coverage(
        conn: &Connection,
        script: &[u8],
        range: &CoverageRange,
    ) -> Result<(), StoreError> {
        conn.execute(
            "INSERT INTO coverage (script, start_height, end_height, kind, shard_id, revision_digest, terminal_block_hash, source_anchor) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                script,
                range.start_height as i64,
                range.end_height as i64,
                kind_str(range.kind),
                range.shard_id as i64,
                range.revision_digest,
                range.terminal_block_hash,
                range.source_anchor.as_ref().map(|a| serde_json::to_string(a).unwrap()),
            ],
        )
        .map_err(io)?;
        Ok(())
    }
}

/// Deletes the filter and setup cache rows under any revision but those in
/// `queryable`. The engine's sync and the catalog's pass both prune with it.
pub(crate) fn prune_revision_caches(conn: &Connection, queryable: &[&str]) -> rusqlite::Result<()> {
    let named = serde_json::to_string(queryable)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    for table in ["filter_cache", "setup_cache"] {
        conn.execute(
            &format!(
                "DELETE FROM {table} WHERE revision_digest NOT IN (SELECT value FROM json_each(?1))"
            ),
            [&named],
        )?;
    }
    Ok(())
}

/// The names of the tables and indexes [`SCHEMA`] creates.
fn owned_names() -> impl Iterator<Item = &'static str> {
    SCHEMA.lines().filter_map(|line| {
        line.strip_prefix("CREATE TABLE IF NOT EXISTS ")
            .or_else(|| line.strip_prefix("CREATE INDEX IF NOT EXISTS "))
            .and_then(|rest| rest.split([' ', '(']).next())
    })
}

/// Admits the file's store before anything in it changes, returning the
/// schema version it records, or `None` for a file holding no store.
///
/// Only a file with none of the store's tables is fresh: other tables, such as
/// a catalog sharing the file, are left alone. A metadata table without its
/// version marker, store tables without a metadata table, or a version this
/// build does not read is refused. Creating the missing tables beside those
/// and stamping the current version would pass a layout of unknown origin off
/// as this one.
fn admit(conn: &Connection) -> Result<Option<String>, StoreError> {
    let held: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type IN ('table', 'index') ORDER BY name")
        .map_err(io)?
        .query_map([], |row| row.get(0))
        .map_err(io)?
        .collect::<Result<_, _>>()
        .map_err(io)?;
    if !held.iter().any(|name| name == "wallet_meta") {
        return match held
            .iter()
            .find(|name| owned_names().any(|owned| owned == name.as_str()))
        {
            Some(orphan) => Err(StoreError::Corrupt(format!(
                "store table {orphan} without the store's metadata"
            ))),
            None => Ok(None),
        };
    }
    let found: String = conn
        .query_row(
            "SELECT value FROM wallet_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(io)?
        .ok_or_else(|| StoreError::Corrupt("store metadata without a schema version".into()))?;
    // Schema 6 has the same history and walk representation. Older stores
    // lack saved fragments or use another shard schema.
    if found != "6" && found != SCHEMA_VERSION.to_string() {
        return Err(StoreError::Corrupt(format!(
            "store schema {found}, this build reads {SCHEMA_VERSION}"
        )));
    }
    Ok(Some(found))
}

fn kind_str(kind: CoverageKind) -> &'static str {
    match kind {
        CoverageKind::Settled => "settled",
        CoverageKind::Provisional => "provisional",
    }
}

/// Decodes version-tagged event lists, refusing more than `limit` events.
fn decode_events(bytes: &[u8], limit: usize) -> Result<Vec<TransparentEvent>, StoreError> {
    let mut remaining = bytes
        .strip_prefix(b"EV3\0")
        .ok_or_else(|| StoreError::Corrupt("unknown event framing".into()))?;
    let mut events = Vec::new();
    while !remaining.is_empty() {
        let header = remaining
            .get(..2)
            .ok_or_else(|| StoreError::Corrupt("truncated event framing".into()))?;
        let length = usize::from(u16::from_le_bytes(header.try_into().unwrap()));
        let raw = remaining
            .get(2..2 + length)
            .ok_or_else(|| StoreError::Corrupt("truncated event".into()))?;
        events.push(decode_event(raw)?);
        if events.len() > limit {
            return Err(StoreError::Corrupt("too many events".into()));
        }
        remaining = &remaining[2 + length..];
    }
    Ok(events)
}

fn decode_event(bytes: &[u8]) -> Result<TransparentEvent, StoreError> {
    if !(EVENT_BYTES..=transparent_events::MAX_EVENT_BYTES).contains(&bytes.len()) {
        return Err(StoreError::Corrupt(
            "event record has the wrong length".into(),
        ));
    }
    TransparentEvent::from_bytes(bytes).map_err(|error| StoreError::Corrupt(error.to_string()))
}

impl WalletStore for SqliteStore {
    fn set_identity(&self) -> Result<Option<SetIdentity>, StoreError> {
        match self.meta("set_identity")? {
            None => Ok(None),
            Some(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|error| StoreError::Corrupt(error.to_string())),
        }
    }

    fn bind_set(&mut self, identity: &SetIdentity) -> Result<(), StoreError> {
        match self.set_identity()? {
            None => {}
            Some(stored) if stored.continues(identity) => {}
            Some(stored) => {
                return Err(StoreError::SetMismatch {
                    stored: stored.digest(),
                    offered: identity.digest(),
                });
            }
        }
        let json =
            serde_json::to_string(identity).map_err(|error| StoreError::Io(error.to_string()))?;
        self.set_meta("set_identity", &json)
    }

    fn anchor(&self) -> Result<Option<Anchor>, StoreError> {
        match self.meta("anchor")? {
            None => Ok(None),
            Some(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|error| StoreError::Corrupt(error.to_string())),
        }
    }

    fn scripts(&self) -> Result<Vec<ScriptEntry>, StoreError> {
        let mut statement = self
            .conn
            .prepare("SELECT script, origin, required_from FROM scripts ORDER BY script")
            .map_err(io)?;
        let rows = statement
            .query_map([], |row| {
                Ok(ScriptEntry {
                    script: row.get(0)?,
                    origin: if row.get::<_, String>(1)? == "imported" {
                        ScriptOrigin::Imported
                    } else {
                        ScriptOrigin::Derived
                    },
                    required_from: row.get::<_, i64>(2)? as u64,
                })
            })
            .map_err(io)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(io)
    }

    fn add_scripts(&mut self, entries: &[ScriptEntry]) -> Result<usize, StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io)?;
        let mut added = 0;
        for entry in entries {
            // An upsert reports a change either way, so whether the script
            // is new is asked first.
            let known: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM scripts WHERE script = ?1",
                    params![entry.script],
                    |row| row.get(0),
                )
                .map_err(io)?;
            tx.execute(
                "INSERT INTO scripts (script, origin, required_from) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(script) DO UPDATE SET required_from = MIN(required_from, excluded.required_from)",
                params![
                    entry.script,
                    match entry.origin {
                        ScriptOrigin::Derived => "derived",
                        ScriptOrigin::Imported => "imported",
                    },
                    entry.required_from as i64
                ],
            )
            .map_err(io)?;
            if known == 0 {
                added += 1;
            }
        }
        tx.commit().map_err(io)?;
        Ok(added)
    }

    fn coverage(&self, script: &[u8]) -> Result<Vec<CoverageRange>, StoreError> {
        Self::coverage_of(&self.conn, script)
    }

    fn provisional(&self) -> Result<Vec<CoverageRange>, StoreError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT script, start_height, end_height, shard_id, revision_digest, terminal_block_hash, source_anchor \
                 FROM coverage WHERE kind = 'provisional' ORDER BY script, start_height",
            )
            .map_err(io)?;
        let rows = statement
            .query_map([], |row| {
                Ok(CoverageRange {
                    source_anchor: decode_anchor(row.get(6)?)?,
                    script: row.get(0)?,
                    start_height: row.get::<_, i64>(1)? as u64,
                    end_height: row.get::<_, i64>(2)? as u64,
                    kind: CoverageKind::Provisional,
                    shard_id: row.get::<_, i64>(3)? as u64,
                    revision_digest: row.get(4)?,
                    terminal_block_hash: row.get(5)?,
                })
            })
            .map_err(io)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(io)
    }

    fn events(&self) -> Result<Vec<StoredEvent>, StoreError> {
        let mut events = Vec::new();
        let mut receives = self
            .conn
            .prepare("SELECT script, event, shard_id, revision_digest FROM receives")
            .map_err(io)?;
        let rows = receives
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(io)?;
        for row in rows {
            let (script, raw, shard_id, revision_digest) = row.map_err(io)?;
            events.push(StoredEvent {
                script,
                event: decode_event(&raw)?,
                shard_id,
                revision_digest,
            });
        }
        let mut spends = self
            .conn
            .prepare("SELECT script, event, shard_id, revision_digest FROM spends")
            .map_err(io)?;
        let rows = spends
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(io)?;
        for row in rows {
            let (script, raw, shard_id, revision_digest) = row.map_err(io)?;
            events.push(StoredEvent {
                script,
                event: decode_event(&raw)?,
                shard_id,
                revision_digest,
            });
        }
        events.sort_by_key(|entry| entry.event.sort_key());
        Ok(events)
    }

    fn commit_shard(&mut self, commit: ShardCommit) -> Result<u64, StoreError> {
        let (encoded_events, encoded_pending, encoded_runs) = commit.encode_events()?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io)?;
        let mut assertions = commit
            .events
            .iter()
            .map(|stored| stored.event)
            .collect::<Vec<_>>();
        let txids = assertions
            .iter()
            .map(TransparentEvent::txid)
            .collect::<std::collections::BTreeSet<_>>();
        for txid in txids {
            let mut query = tx.prepare_cached("SELECT event FROM receives WHERE txid = ?1 UNION ALL SELECT event FROM spends WHERE spending_txid = ?1").map_err(io)?;
            let rows = query
                .query_map([txid.0.as_slice()], |row| row.get::<_, Vec<u8>>(0))
                .map_err(io)?;
            for row in rows {
                assertions.push(decode_event(&row.map_err(io)?)?);
            }
        }
        transparent_events::check_transaction_consistency(&assertions)
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        // Contradictions first, before any write, so a refused commit rolls
        // back to exactly the prior state.
        check_event_identities(
            commit
                .events
                .iter()
                .map(|stored| (stored.script.as_slice(), &stored.event)),
        )?;
        for (stored, encoded) in commit.events.iter().zip(&encoded_events) {
            match &stored.event {
                TransparentEvent::Receive(receive) => {
                    let existing: Option<(Vec<u8>, Vec<u8>)> = tx
                        .query_row(
                            "SELECT script, event FROM receives WHERE txid = ?1 AND output_index = ?2",
                            params![receive.txid.0.as_slice(), receive.output_index as i64],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()
                        .map_err(io)?;
                    if let Some((script, raw)) = existing {
                        if script != stored.script || raw != *encoded {
                            return Err(LedgerError::ConflictingReceive(
                                receive.txid.to_display_hex(),
                                receive.output_index,
                            )
                            .into());
                        }
                    }
                }
                TransparentEvent::Spend(spend) => {
                    let existing: Option<SpendRow> = tx
                        .query_row(
                            "SELECT spending_txid, input_index, event, script FROM spends WHERE spent_txid = ?1 AND spent_output_index = ?2",
                            params![spend.spent_txid.0.as_slice(), spend.spent_output_index as i64],
                            |row| Ok(SpendRow { spending_txid: row.get(0)?, input_index: row.get(1)?, event: row.get(2)?, script: row.get(3)? }),
                        )
                        .optional()
                        .map_err(io)?;
                    if let Some(existing) = existing {
                        if existing.spending_txid != spend.spending_txid.0.as_slice()
                            || existing.input_index as u32 != spend.input_index
                            || existing.event != *encoded
                            || existing.script != stored.script
                        {
                            return Err(LedgerError::DoubleSpend(
                                spend.spent_txid.to_display_hex(),
                                spend.spent_output_index,
                            )
                            .into());
                        }
                    }
                }
            }
        }
        let pending_now: i64 = tx
            .query_row("SELECT COUNT(*) FROM pending_work", [], |row| row.get(0))
            .map_err(io)?;
        let new_items = commit
            .pending_upsert
            .iter()
            .filter(|p| p.id.is_none())
            .count() as i64;
        let finished = commit.pending_complete.len() as i64;
        if pending_now + new_items - finished > self.pending_limit as i64 {
            return Err(StoreError::PendingLimit {
                limit: self.pending_limit,
            });
        }
        for run in &commit.cached_runs {
            let held = Self::cached_run_in(&tx, &run.child_digest, &run.script)?;
            if held.is_some_and(|held| held != *run) {
                return Err(StoreError::Corrupt(format!(
                    "page shard {} holds two histories for one script",
                    run.child_digest
                )));
            }
        }

        for (stored, encoded) in commit.events.iter().zip(&encoded_events) {
            match &stored.event {
                TransparentEvent::Receive(receive) => {
                    tx.execute(
                        "INSERT OR IGNORE INTO receives (txid, output_index, script, height, event, shard_id, revision_digest) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            receive.txid.0.as_slice(),
                            receive.output_index as i64,
                            stored.script,
                            receive.height as i64,
                            encoded.as_slice(),
                            stored.shard_id as i64,
                            stored.revision_digest,
                        ],
                    )
                    .map_err(io)?;
                }
                TransparentEvent::Spend(spend) => {
                    tx.execute(
                        "INSERT OR IGNORE INTO spends (spending_txid, input_index, spent_txid, spent_output_index, script, height, event, shard_id, revision_digest) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        params![
                            spend.spending_txid.0.as_slice(),
                            spend.input_index as i64,
                            spend.spent_txid.0.as_slice(),
                            spend.spent_output_index as i64,
                            stored.script,
                            spend.height as i64,
                            encoded.as_slice(),
                            stored.shard_id as i64,
                            stored.revision_digest,
                        ],
                    )
                    .map_err(io)?;
                }
            }
        }
        let kind = if commit.sealed {
            CoverageKind::Settled
        } else {
            CoverageKind::Provisional
        };
        for script in &commit.covered_scripts {
            let range = CoverageRange {
                source_anchor: commit.source_anchor.clone(),
                script: script.clone(),
                start_height: commit.start_height,
                end_height: commit.end_height,
                kind,
                shard_id: commit.shard_id,
                revision_digest: commit.revision_digest.clone(),
                terminal_block_hash: commit.terminal_block_hash.clone(),
            };
            // A range strictly inside the one starting nearest at or below it
            // is already covered: nothing changes. Otherwise it replaces every
            // range of this script it contains, whatever shard they came
            // from: a repeat, a longer revision at the same start, and the
            // narrower shards a re-cut merged into this one. Both lookups seek
            // the script-and-start key, so appending past the covered history
            // reads one row and rewrites none. The memory store keeps the
            // same rule.
            let holder: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT start_height, end_height FROM coverage WHERE script = ?1 AND start_height <= ?2 \
                     ORDER BY start_height DESC LIMIT 1",
                    params![script, range.start_height as i64],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(io)?;
            if holder.is_some_and(|(start, end)| {
                end as u64 >= range.end_height
                    && (start as u64, end as u64) != (range.start_height, range.end_height)
            }) {
                continue;
            }
            tx.execute(
                "DELETE FROM coverage WHERE script = ?1 AND start_height >= ?2 AND end_height <= ?3",
                params![
                    script,
                    range.start_height as i64,
                    range.end_height as i64
                ],
            )
            .map_err(io)?;
            Self::insert_coverage(&tx, script, &range)?;
        }
        for id in &commit.pending_complete {
            tx.execute(
                "DELETE FROM pending_work WHERE id = ?1",
                params![*id as i64],
            )
            .map_err(io)?;
        }
        for (pending, encoded) in commit.pending_upsert.iter().zip(&encoded_pending) {
            let cursor = pending.cursor;
            match pending.id {
                Some(id) => {
                    tx.execute(
                        "UPDATE pending_work SET cursor_child = ?2, cursor_row = ?3, cursor_older_runs = ?4, carried = ?5, attempts = ?6, fragments = ?7 WHERE id = ?1",
                        params![
                            id as i64,
                            i64::from(cursor.child),
                            i64::from(cursor.row),
                            cursor.older_runs.map(i64::from),
                            encoded,
                            pending.attempts as i64,
                            pending.fragments.concat(),
                        ],
                    )
                    .map_err(io)?;
                }
                None => {
                    tx.execute(
                        "INSERT INTO pending_work (shard_id, revision_digest, script, cursor_child, cursor_row, cursor_older_runs, carried, target_anchor, attempts, fragments) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![
                            pending.shard_id as i64,
                            pending.revision_digest,
                            pending.script,
                            i64::from(cursor.child),
                            i64::from(cursor.row),
                            cursor.older_runs.map(i64::from),
                            encoded,
                            pending.target_anchor.as_ref().map(|a| serde_json::to_string(a).unwrap()),
                            pending.attempts as i64,
                            pending.fragments.concat(),
                        ],
                    )
                    .map_err(io)?;
                }
            }
        }
        for (run, encoded) in commit.cached_runs.iter().zip(&encoded_runs) {
            tx.execute(
                "INSERT OR IGNORE INTO run_cache (child_digest, script, shard_id, events, older) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    run.child_digest,
                    run.script,
                    run.shard_id as i64,
                    encoded,
                    run.older,
                ],
            )
            .map_err(io)?;
        }
        if commit.finishes_shard() {
            for script in &commit.covered_scripts {
                tx.execute(
                    "DELETE FROM run_cache WHERE shard_id = ?1 AND script = ?2",
                    params![commit.shard_id as i64, script],
                )
                .map_err(io)?;
            }
        }
        // The numeric id may now name another shard after a re-cut. Keep the
        // revision binding and its counters in the same transaction as the commit.
        if !commit.revision_digest.is_empty() {
            let failure_key = format!("failure_revision:{}", commit.shard_id);
            let held_revision = Self::failure_revision(&tx, commit.shard_id)?;
            if held_revision.as_deref() != Some(commit.revision_digest.as_str()) {
                tx.execute(
                    "DELETE FROM failed_entries WHERE shard_id = ?1",
                    [commit.shard_id as i64],
                )
                .map_err(io)?;
            }
            tx.execute(
            "INSERT INTO wallet_meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![failure_key, commit.revision_digest],
        ).map_err(io)?;
        }
        for script in &commit.failed_entries {
            tx.execute(
                "INSERT INTO failed_entries (shard_id, script, failures) VALUES (?1, ?2, 1) \
                 ON CONFLICT(shard_id, script) DO UPDATE SET failures = failures + 1",
                params![commit.shard_id as i64, script],
            )
            .map_err(io)?;
        }
        let id = Self::record_commit(
            &tx,
            "shard",
            &format!("{}:{}", commit.shard_id, commit.revision_digest),
        )?;
        tx.commit().map_err(io)?;
        Ok(id)
    }

    fn commit_anchor(
        &mut self,
        anchor: &Anchor,
        settled_through: u64,
        covered_through: u64,
    ) -> Result<u64, StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io)?;
        let json =
            serde_json::to_string(anchor).map_err(|error| StoreError::Io(error.to_string()))?;
        for (key, value) in [
            ("anchor", json),
            ("settled_through", settled_through.to_string()),
            ("covered_through", covered_through.to_string()),
        ] {
            tx.execute(
                "INSERT INTO wallet_meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(io)?;
        }
        let id = Self::record_commit(&tx, "anchor", &anchor.height.to_string())?;
        tx.commit().map_err(io)?;
        Ok(id)
    }

    fn rollback_above(&mut self, accepted: &Anchor, reason: &str) -> Result<u64, StoreError> {
        let height = accepted.height;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io)?;
        let h = height as i64;
        tx.execute("DELETE FROM receives WHERE height > ?1", params![h])
            .map_err(io)?;
        tx.execute("DELETE FROM spends WHERE height > ?1", params![h])
            .map_err(io)?;
        tx.execute("DELETE FROM coverage WHERE start_height > ?1", params![h])
            .map_err(io)?;
        tx.execute(
            "UPDATE coverage SET end_height = ?1, terminal_block_hash = ?2 WHERE end_height > ?1",
            params![h, accepted.hash],
        )
        .map_err(io)?;
        // Pending work belongs to a revision; one whose coverage is gone is
        // gone with it.
        tx.execute("DELETE FROM pending_work", []).map_err(io)?;
        // Cached runs survive: each is keyed by its page shard's chained
        // identity, which commits to the chain it was published on, so a walk
        // reaches one only through a manifest on the accepted chain.
        let anchor: Option<String> = tx
            .query_row(
                "SELECT value FROM wallet_meta WHERE key = 'anchor'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(io)?;
        if let Some(json) = anchor {
            let mut anchor: Anchor = serde_json::from_str(&json)
                .map_err(|error| StoreError::Corrupt(error.to_string()))?;
            if anchor.height > height {
                anchor.height = height;
                anchor.hash = accepted.hash.clone();
                tx.execute(
                    "UPDATE wallet_meta SET value = ?1 WHERE key = 'anchor'",
                    params![serde_json::to_string(&anchor).unwrap()],
                )
                .map_err(io)?;
            }
        }
        for key in ["settled_through", "covered_through"] {
            let value: Option<String> = tx
                .query_row(
                    "SELECT value FROM wallet_meta WHERE key = ?1",
                    params![key],
                    |row| row.get(0),
                )
                .optional()
                .map_err(io)?;
            if let Some(current) = value.and_then(|v| v.parse::<u64>().ok()) {
                if current > height {
                    tx.execute(
                        "UPDATE wallet_meta SET value = ?2 WHERE key = ?1",
                        params![key, height.to_string()],
                    )
                    .map_err(io)?;
                }
            }
        }
        let id = Self::record_commit(&tx, "rollback", &format!("{height}: {reason}"))?;
        tx.commit().map_err(io)?;
        Ok(id)
    }

    fn promote_provisional(
        &mut self,
        shard_id: u64,
        revision_digest: &str,
    ) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io)?;
        tx.execute(
            "UPDATE coverage SET kind = 'settled' WHERE shard_id = ?1 AND revision_digest = ?2 AND kind = 'provisional'",
            params![shard_id as i64, revision_digest],
        )
        .map_err(io)?;
        // Re-merge every script's ranges now that adjacent settled ones may join.
        let scripts: Vec<Vec<u8>> = {
            let mut statement = tx
                .prepare("SELECT DISTINCT script FROM coverage")
                .map_err(io)?;
            let rows = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(io)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(io)?
        };
        for script in scripts {
            let ranges = Self::coverage_of(&tx, &script)?;
            let merged = merge_coverage(ranges);
            Self::write_coverage(&tx, &script, &merged)?;
        }
        tx.commit().map_err(io)?;
        Ok(())
    }

    fn pending(&self) -> Result<Vec<PendingPages>, StoreError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, shard_id, revision_digest, script, cursor_child, cursor_row, cursor_older_runs, carried, attempts, target_anchor, fragments \
                 FROM pending_work ORDER BY id",
            )
            .map_err(io)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)? as u32,
                    decode_anchor(row.get(9)?)?,
                    row.get::<_, Vec<u8>>(10)?,
                ))
            })
            .map_err(io)?;
        let mut pending = Vec::new();
        for row in rows {
            let (
                id,
                shard_id,
                revision_digest,
                script,
                child,
                cursor_row,
                older_runs,
                carried,
                attempts,
                target_anchor,
                fragments,
            ) = row.map_err(io)?;
            let width = transparent_shard::PAGE_ROW_BYTES;
            if fragments.len() % width != 0 {
                return Err(StoreError::Corrupt(
                    "saved run fragment has the wrong width".into(),
                ));
            }
            let corrupt = |_| StoreError::Corrupt("pending walk cursor out of range".into());
            pending.push(PendingPages {
                id: Some(id),
                shard_id,
                revision_digest,
                script,
                cursor: RunCursor {
                    child: u8::try_from(child).map_err(corrupt)?,
                    row: u32::try_from(cursor_row).map_err(corrupt)?,
                    older_runs: older_runs.map(u8::try_from).transpose().map_err(corrupt)?,
                },
                carried: decode_events(&carried, transparent_shard::INLINE_EVENTS as usize)?,
                fragments: fragments.chunks_exact(width).map(<[u8]>::to_vec).collect(),
                attempts,
                target_anchor,
            });
        }
        Ok(pending)
    }

    fn cached_run(
        &self,
        child_digest: &str,
        script: &[u8],
    ) -> Result<Option<CachedRun>, StoreError> {
        Self::cached_run_in(&self.conn, child_digest, script)
    }

    fn pending_limit(&self) -> usize {
        self.pending_limit
    }

    fn setup(&self, key: &SetupKey) -> Result<Option<SetupBlob>, StoreError> {
        self.conn
            .query_row(
                "SELECT public_params_base64, public_params_sha256 FROM setup_cache \
                 WHERE set_digest = ?1 AND revision_digest = ?2 AND tbl = ?3 AND segment = ?4",
                params![
                    key.set_digest,
                    key.revision_digest,
                    key.table.name(),
                    key.segment as i64
                ],
                |row| {
                    Ok(SetupBlob {
                        public_params_base64: row.get(0)?,
                        public_params_sha256: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(io)
    }

    fn put_setup(&mut self, key: &SetupKey, blob: &SetupBlob) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO setup_cache (set_digest, revision_digest, tbl, segment, public_params_base64, public_params_sha256) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    key.set_digest,
                    key.revision_digest,
                    key.table.name(),
                    key.segment as i64,
                    blob.public_params_base64,
                    blob.public_params_sha256
                ],
            )
            .map(|_| ())
            .map_err(io)
    }

    fn drop_setup(&mut self, key: &SetupKey) -> Result<(), StoreError> {
        self.conn
            .execute(
                "DELETE FROM setup_cache WHERE set_digest = ?1 AND revision_digest = ?2 \
                 AND tbl = ?3 AND segment = ?4",
                params![
                    key.set_digest,
                    key.revision_digest,
                    key.table.name(),
                    key.segment as i64
                ],
            )
            .map(|_| ())
            .map_err(io)
    }

    fn filter(
        &self,
        revision_digest: &str,
        filter_hash: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.conn
            .query_row(
                "SELECT bytes FROM filter_cache WHERE revision_digest = ?1 AND filter_hash = ?2",
                params![revision_digest, filter_hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(io)
    }

    fn put_filter(
        &mut self,
        revision_digest: &str,
        filter_hash: &str,
        sealed: bool,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO filter_cache (revision_digest, filter_hash, sealed, bytes) VALUES (?1, ?2, ?3, ?4)",
                params![revision_digest, filter_hash, sealed as i64, bytes],
            )
            .map(|_| ())
            .map_err(io)
    }

    fn prune_caches(&mut self, queryable: &[&str]) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io)?;
        prune_revision_caches(&tx, queryable).map_err(io)?;
        tx.commit().map_err(io)
    }

    fn last_commit(&self) -> Result<u64, StoreError> {
        self.conn
            .query_row("SELECT COALESCE(MAX(id), 0) FROM commits", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|id| id as u64)
            .map_err(io)
    }

    fn entry_failures(
        &self,
        shard_id: u64,
        revision: &str,
        script: &[u8],
    ) -> Result<u32, StoreError> {
        if Self::failure_revision(&self.conn, shard_id)?.as_deref() != Some(revision) {
            return Ok(0);
        }
        self.conn
            .query_row(
                "SELECT failures FROM failed_entries WHERE shard_id = ?1 AND script = ?2",
                params![shard_id as i64, script],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map(|failures| failures.unwrap_or(0) as u32)
            .map_err(io)
    }
}

// Keep the event types referenced for readers of this file.
#[allow(dead_code)]
fn _types(_: &ReceiveEvent, _: &SpendEvent, _: &Txid) {}

fn decode_anchor(raw: Option<String>) -> rusqlite::Result<Option<Anchor>> {
    raw.map(|s| {
        serde_json::from_str(&s).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })
    })
    .transpose()
}

#[cfg(test)]
mod coverage_append_tests {
    use super::*;

    /// Admission recognizes exactly the tables and indexes the schema creates.
    #[test]
    fn owned_names_are_every_object_the_schema_creates() {
        let store = SqliteStore::open_in_memory().unwrap();
        let created: Vec<String> = store
            .conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type IN ('table', 'index') \
                 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let mut owned: Vec<&str> = owned_names().collect();
        owned.sort_unstable();
        assert_eq!(created, owned);
    }

    #[test]
    fn appending_checkpoints_does_not_rewrite_prior_coverage() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let script = vec![0x51];
        let commit = |height| ShardCommit {
            shard_id: height,
            revision_digest: "dataset".into(),
            sealed: true,
            start_height: height,
            end_height: height,
            terminal_block_hash: format!("{height:064x}"),
            covered_scripts: vec![script.clone()],
            ..Default::default()
        };
        for height in 0..100 {
            store.commit_shard(commit(height)).unwrap();
        }
        let before: u64 = store
            .conn
            .query_row("SELECT total_changes()", [], |r| r.get(0))
            .unwrap();
        store.commit_shard(commit(100)).unwrap();
        let after: u64 = store
            .conn
            .query_row("SELECT total_changes()", [], |r| r.get(0))
            .unwrap();
        assert!(
            after - before <= 3,
            "append rewrote prior rows: {} changes",
            after - before
        );
        let ranges = store.coverage(&script).unwrap();
        assert_eq!(ranges.len(), 101);
        assert_eq!(ranges.first().unwrap().start_height, 0);
        assert_eq!(ranges.last().unwrap().end_height, 100);
        store.commit_shard(commit(100)).unwrap();
        assert_eq!(store.coverage(&script).unwrap(), ranges);
    }
}
