//! The reference store's own tables, which the catalog shares a file with, and the reset
//! of a store whose publication changed.

use std::collections::BTreeSet;

use rusqlite::{Connection, Transaction, TransactionBehavior};

use super::identity::Published;
use super::recut::record_epoch;
use crate::error::{RecoveryError, failure};

// Pruning names the reference store's cache and commit tables, and a reset names
// every store table. Re-verify those names, that `wallet_meta` keeps the schema
// version under `schema_version`, and that `last_commit` reads only the highest
// commit id, before accepting another store schema.
//
// Schema 7 holds saved run fragments and per-entry content failures. The store upgrades
// schema 6 in place, preserving its history and catalog, and refuses other versions.
// A companion's file name commits to the shard
// schema (see `companion`), so a schema-v12 companion never opens a file a schema-v11
// build wrote.
const _: () = assert!(crate::engine_store::SCHEMA_VERSION == 7);

/// The reference store's tables at schema version 7 that a reset empties, besides
/// `wallet_meta`.
///
/// `run_cache` holds verified run histories keyed by page shard identity. The
/// store keeps it across a rollback, and pruning leaves it alone: a superseded
/// tail's sealed page shards are the replacement's too. Only a reset empties it.
///
/// `failed_entries`, the content failures counted per shard revision and script, is not
/// listed: a reset keeps it. A service that changes its publication set would
/// otherwise earn every held entry three more attempts.
const STORE_TABLES: [&str; 9] = [
    "scripts",
    "coverage",
    "receives",
    "spends",
    "pending_work",
    "run_cache",
    "setup_cache",
    "filter_cache",
    "commits",
];

/// Restarts the companion's store for a publication whose set identity no
/// longer continues the one the store is bound to, in one transaction.
///
/// Every store table, the run cache included, is emptied but for the content
/// failure counts, and `wallet_meta` keeps the schema version and failure revision bindings, so the next
/// sync binds the new set and retrieves from the floor.
/// The recorded re-cut epoch is cleared with it: the empty store follows no
/// map. The catalog stays: each source keeps its highest lineage, so a source
/// the new set leaves unchanged still recognizes a restarted revision number.
/// Rows of sources that none of `named`, the map's published and declared
/// revisions, names lose their export mark, because no commit can succeed
/// them, so no batch reports them as retired revisions, even those a batch
/// already listed and nobody acknowledged; the wallet keeps their evidence as
/// it is, and a later batch completes its pages under them once it covers
/// their ranges.
pub(crate) fn reset_store_keep_catalog(
    conn: &mut Connection,
    named: &[Published],
) -> Result<(), RecoveryError> {
    let named: BTreeSet<&[u8]> = named
        .iter()
        .map(|entry| entry.revision.source.as_slice())
        .collect();
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failure)?;
    tx.execute(
        "DELETE FROM wallet_meta WHERE key<>'schema_version' AND key NOT GLOB 'failure_revision:*'",
        [],
    )
    .map_err(failure)?;
    for table in STORE_TABLES {
        tx.execute(&format!("DELETE FROM {table}"), [])
            .map_err(failure)?;
    }
    record_epoch(&tx, 0)?;
    let exported = tx
        .prepare("SELECT DISTINCT source FROM pir_bridge_catalog WHERE exported=1")
        .map_err(failure)?
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(failure)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(failure)?;
    for source in exported {
        if !named.contains(source.as_slice()) {
            tx.execute(
                "UPDATE pir_bridge_catalog SET exported=0 WHERE source=?1",
                [&source],
            )
            .map_err(failure)?;
        }
    }
    tx.commit().map_err(failure)
}

/// Prunes the store's filter and setup caches to the revisions `digests` names, and
/// its commit log to the last commit, within a pass's transaction `tx`. The store
/// reads only the last commit id. The run cache is not keyed by revision and is
/// kept: a later revision of a tail reaches the runs its sealed page shards hold.
pub(super) fn prune_store_caches(
    tx: &Transaction<'_>,
    digests: &[&str],
) -> Result<(), RecoveryError> {
    crate::engine_store::prune_revision_caches(tx, digests).map_err(failure)?;
    tx.execute(
        "DELETE FROM commits WHERE id < (SELECT MAX(id) FROM commits)",
        [],
    )
    .map_err(failure)?;
    Ok(())
}
