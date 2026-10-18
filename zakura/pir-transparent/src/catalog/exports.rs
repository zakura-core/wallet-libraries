//! Export intents: acknowledging the revisions a batch handed to the wallet, and pruning
//! rows no batch can need.

use rusqlite::{Connection, Transaction};
#[cfg(any(test, feature = "sqlite"))]
use rusqlite::{TransactionBehavior, params};
#[cfg(any(test, feature = "sqlite"))]
use zakura_transparent_recovery_types::RecoveryRevision;

use crate::error::{RecoveryError, failure};

/// Clears the export intent of `replaced` rows, whose successors the wallet
/// applied after reconciling them, and prunes the catalog. The batch's own
/// revisions were recorded as exported by its pass.
#[cfg(test)]
pub(crate) fn acknowledge(
    conn: &mut Connection,
    replaced: &[RecoveryRevision],
) -> Result<(), RecoveryError> {
    let tx = acknowledgment_transaction(conn)?;
    acknowledge_in_transaction(&tx, replaced)?;
    tx.commit().map_err(failure)
}

/// The immediate catalog transaction an acknowledgment runs in. Applying takes it
/// before the wallet's read transaction, so waiting for the companion's lock holds
/// no wallet reservation.
#[cfg(any(test, feature = "sqlite"))]
pub(crate) fn acknowledgment_transaction(
    conn: &mut Connection,
) -> Result<Transaction<'_>, RecoveryError> {
    conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failure)
}

/// Clears the export intent of `replaced` rows and prunes the catalog within `tx`, which the
/// caller commits.
#[cfg(any(test, feature = "sqlite"))]
pub(crate) fn acknowledge_in_transaction(
    tx: &Transaction<'_>,
    replaced: &[RecoveryRevision],
) -> Result<(), RecoveryError> {
    for row in replaced {
        tx.execute(
            "UPDATE pir_bridge_catalog SET exported=0 WHERE source=?1 AND revision=?2 AND current=0",
            params![row.source, row.revision],
        )
        .map_err(failure)?;
    }
    prune_catalog(tx)
}

/// Whether any batch may have handed a revision to the wallet.
pub(crate) fn exported_any(conn: &Connection) -> Result<bool, RecoveryError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pir_bridge_catalog WHERE exported=1)",
        [],
        |row| row.get(0),
    )
    .map_err(failure)
}

/// Forgets rows that are neither current nor exported. Each source's newest
/// row stays, so a later regression or lagging replica is still recognized,
/// and `pir_bridge_exports` keeps every exported revision, so a pruned one
/// still refuses a revision that would collide with it in the wallet.
pub(super) fn prune_catalog(tx: &Transaction<'_>) -> Result<(), RecoveryError> {
    tx.execute(
        "DELETE FROM pir_bridge_catalog WHERE current=0 AND exported=0
         AND lineage < (SELECT MAX(m.lineage) FROM pir_bridge_catalog m WHERE m.source=pir_bridge_catalog.source)",
        [],
    )
    .map(|_| ())
    .map_err(failure)
}
