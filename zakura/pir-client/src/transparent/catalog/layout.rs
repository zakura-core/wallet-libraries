//! The companion's catalog tables, and opening a companion of this format or the one
//! before it.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::recut::record_epoch;
use crate::transparent::error::{RecoveryError, ensure_valid, failure};

/// The companion layout this build creates and reads.
const FORMAT: &str = "transparent-reference-companion-v3";

/// The previous layout, whose catalog [`prepare`] rebuilds in place.
const FORMAT_V2: &str = "transparent-reference-companion-v2";

/// The companion's key-value settings: its `format`, its `account-source`
/// binding, and the `recut-epoch` its store last followed.
const BINDING: &str =
    "CREATE TABLE pir_bridge_binding (key TEXT PRIMARY KEY, value BLOB NOT NULL);";

/// One row per shard revision this companion has seen, by source and manifest
/// digest. `lineage` is the publisher's revision number plus one, `revision` the
/// derived revision identity, and `height`/`hash` the publication anchor. `current`
/// marks rows the latest pass's map publishes, or declares superseded while sealed;
/// `exported` marks rows a batch may have handed to the wallet whose export intent
/// no acknowledgment or reset has cleared.
const CATALOG: &str = "CREATE TABLE pir_bridge_catalog (
        source BLOB NOT NULL CHECK(length(source)=32),
        start_height INTEGER NOT NULL CHECK(start_height>=0),
        digest TEXT NOT NULL,
        sealed INTEGER NOT NULL CHECK(sealed IN (0,1)),
        lineage INTEGER NOT NULL CHECK(lineage>0),
        revision BLOB NOT NULL CHECK(length(revision)=32),
        height INTEGER NOT NULL CHECK(height>=0 AND height<=4294967295),
        hash BLOB NOT NULL CHECK(length(hash)=32),
        exported INTEGER NOT NULL DEFAULT 0 CHECK(exported IN (0,1)),
        current INTEGER NOT NULL DEFAULT 0 CHECK(current IN (0,1)),
        PRIMARY KEY(source,digest,sealed), UNIQUE(source,lineage), UNIQUE(source,revision));";

/// Every revision a batch handed to the wallet, never pruned. The wallet keeps
/// every revision it registered for good, so no later revision may reach it at
/// the source and lineage of one it holds under another identity, even once
/// the catalog pruned that row.
const EXPORTS: &str = "CREATE TABLE IF NOT EXISTS pir_bridge_exports (
        source BLOB NOT NULL CHECK(length(source)=32),
        lineage INTEGER NOT NULL CHECK(lineage>0),
        revision BLOB NOT NULL CHECK(length(revision)=32),
        sealed INTEGER NOT NULL CHECK(sealed IN (0,1)),
        height INTEGER NOT NULL CHECK(height>=0 AND height<=4294967295),
        hash BLOB NOT NULL CHECK(length(hash)=32),
        PRIMARY KEY(source,lineage), UNIQUE(source,revision));";

/// Creates this format's tables in a new companion, or checks that an existing
/// one is bound to `binding` and brings a v2 companion to this format.
///
/// The catalog keeps, never pruned, every revision a batch exported
/// (`pir_bridge_exports`): the wallet keeps every revision it registered.
///
/// A v1 companion counted lineage per companion, which no recreated companion
/// can reproduce, so it is refused rather than migrated. A v2 catalog derived
/// its sources from shard ids, which a re-cut renumbers. Its catalog is rebuilt
/// empty in place, and its store is kept: the next pass exports the stored facts
/// again under v3 sources without retrieving anything. The application keys
/// companion files by origin and schema only, so a new file is no option.
pub(crate) fn prepare(conn: &mut Connection, binding: &[u8; 32]) -> Result<(), RecoveryError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failure)?;
    let has = |table: &str| -> Result<bool, RecoveryError> {
        tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )
        .map_err(failure)
    };
    let bound = has("pir_bridge_binding")?;
    let format: Option<String> = if bound {
        tx.query_row(
            "SELECT value FROM pir_bridge_binding WHERE key='format'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(failure)?
    } else {
        None
    };
    ensure_valid(
        !has("pir_bridge_revisions")? && (!bound || format.is_some()),
        "companion format v1; recreate",
    )?;
    ensure_valid(
        format
            .as_deref()
            .is_none_or(|format| format == FORMAT || format == FORMAT_V2),
        "unsupported companion format",
    )?;
    if !bound {
        tx.execute_batch(BINDING).map_err(failure)?;
        tx.execute_batch(CATALOG).map_err(failure)?;
        tx.execute(
            "INSERT INTO pir_bridge_binding (key, value) VALUES ('format', ?1), ('account-source', ?2)",
            params![FORMAT, binding.as_slice()],
        )
        .map_err(failure)?;
        record_epoch(&tx, 0)?;
    }
    let prior: Option<Vec<u8>> = tx
        .query_row(
            "SELECT value FROM pir_bridge_binding WHERE key='account-source'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(failure)?;
    ensure_valid(
        prior.as_deref() == Some(binding.as_slice()),
        "companion account/source/origin/schema binding mismatch",
    )?;
    if format.as_deref() == Some(FORMAT_V2) {
        tx.execute_batch("DROP TABLE pir_bridge_catalog;")
            .map_err(failure)?;
        tx.execute_batch(CATALOG).map_err(failure)?;
        tx.execute(
            "UPDATE pir_bridge_binding SET value=?1 WHERE key='format'",
            [FORMAT],
        )
        .map_err(failure)?;
        record_epoch(&tx, 0)?;
    }
    if !has("pir_bridge_exports")? {
        tx.execute_batch(EXPORTS).map_err(failure)?;
        // A companion of this format from before the record began.
        tx.execute(
            "INSERT OR IGNORE INTO pir_bridge_exports (source, lineage, revision, sealed, height, hash)
             SELECT source, lineage, revision, sealed, height, hash FROM pir_bridge_catalog
             WHERE exported=1",
            [],
        )
        .map_err(failure)?;
    }
    tx.commit().map_err(failure)
}
