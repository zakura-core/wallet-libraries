//! The reference store's own tables, which the catalog shares a file with, and the reset
//! of a store whose publication changed.

use std::collections::BTreeSet;

use rusqlite::{Connection, Transaction, TransactionBehavior, named_params};

use super::identity::Published;
use super::recut::record_epoch;
use crate::error::{RecoveryError, failure};

// Pruning names the reference store's cache and commit tables, and a reset names
// every store table. Re-verify those names, that `wallet_meta` keeps the schema
// version under `schema_version`, and that `last_commit` reads only the highest
// commit id, before accepting another store schema.
const _: () = assert!(transparent_wallet_store::SCHEMA_VERSION == 4);

/// The reference store's tables at schema version 4, besides `wallet_meta`.
const STORE_TABLES: [&str; 8] = [
    "scripts",
    "coverage",
    "receives",
    "spends",
    "pending_work",
    "setup_cache",
    "filter_cache",
    "commits",
];

/// Restarts the companion's store for a publication whose set identity no
/// longer continues the one the store is bound to, in one transaction.
///
/// Every store table is emptied, and `wallet_meta` keeps only the schema
/// version, so the next sync binds the new set and retrieves from the floor.
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
    tx.execute("DELETE FROM wallet_meta WHERE key<>'schema_version'", [])
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
/// reads only the last commit id.
pub(super) fn prune_store_caches(
    tx: &Transaction<'_>,
    digests: &[&str],
) -> Result<(), RecoveryError> {
    let named = serde_json::to_string(digests).map_err(failure)?;
    for table in ["filter_cache", "setup_cache"] {
        tx.execute(
            &format!(
                "DELETE FROM {table} WHERE revision_digest NOT IN (SELECT value FROM json_each(:named))"
            ),
            named_params![":named": named],
        )
        .map_err(failure)?;
    }
    tx.execute(
        "DELETE FROM commits WHERE id < (SELECT MAX(id) FROM commits)",
        [],
    )
    .map_err(failure)?;
    Ok(())
}
