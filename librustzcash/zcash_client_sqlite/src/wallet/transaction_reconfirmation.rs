//! Historical inclusion receipts for transactions compact scanning cannot rediscover.
//!
//! A receipt has no current-chain authority. Only a successful scan batch that re-observes
//! its exact block may restore the prior inclusion. A changed block exposes ordinary status
//! work; incomplete network coverage leaves both the receipt and its obligation intact.

use rusqlite::{Connection, named_params};
#[cfg(feature = "transparent-inputs")]
use zcash_keys::keys::transparent::gap_limits::GapLimits;
use zcash_primitives::block::BlockHash;
use zcash_protocol::{
    TxId,
    consensus::{self, BlockHeight},
};

use super::TxQueryType;
use crate::error::SqliteClientError;

/// Predicate over transaction alias `t`: no wallet-owned shielded note or spend can rediscover it.
pub(super) const UNOBSERVABLE_TRANSACTION: &str = "
    NOT EXISTS (SELECT 1 FROM sapling_received_notes n WHERE n.transaction_id = t.id_tx)
    AND NOT EXISTS (SELECT 1 FROM sapling_received_note_spends s WHERE s.transaction_id = t.id_tx)
    AND NOT EXISTS (SELECT 1 FROM orchard_received_notes n WHERE n.transaction_id = t.id_tx)
    AND NOT EXISTS (SELECT 1 FROM orchard_received_note_spends s WHERE s.transaction_id = t.id_tx)
    AND NOT EXISTS (SELECT 1 FROM ironwood_received_notes n WHERE n.transaction_id = t.id_tx)
    AND NOT EXISTS (SELECT 1 FROM ironwood_received_note_spends s WHERE s.transaction_id = t.id_tx)";

/// Pending evidence is independent of `blocks`, which truncation deletes. It cascades only
/// with its transaction. `replacement_observed = 0` waits for an accepted scan at this height;
/// `1` permits status fallback. Neither value grants mining or spending authority.
pub(crate) const RECEIPT_SCHEMA: &str = "
    CREATE TABLE tx_reconfirmation_receipts (
        transaction_id INTEGER PRIMARY KEY REFERENCES transactions(id_tx) ON DELETE CASCADE,
        mined_height INTEGER NOT NULL CHECK (typeof(mined_height) = 'integer' AND mined_height BETWEEN 0 AND 4294967295),
        block_hash BLOB NOT NULL CHECK (typeof(block_hash) = 'blob' AND length(block_hash) = 32),
        tx_index INTEGER CHECK (tx_index IS NULL OR (typeof(tx_index) = 'integer' AND tx_index BETWEEN 0 AND 65535)),
        replacement_observed INTEGER NOT NULL DEFAULT 0 CHECK (replacement_observed IN (0, 1))
    );
    CREATE INDEX idx_tx_reconfirmation_receipts_height ON tx_reconfirmation_receipts(mined_height);";

/// Saves available old block identities before the caller un-mines transactions. Replaces
/// stale receipts only for transactions currently mined above the truncation height, including
/// dropping an old receipt when a newer inclusion has no available block hash. Unmined receipts
/// survive. All mutations participate in the caller's rewind transaction.
pub(super) fn capture_before_rewind(
    conn: &rusqlite::Transaction<'_>,
    truncation_height: BlockHeight,
    rescan_floor: BlockHeight,
) -> Result<(), SqliteClientError> {
    conn.execute(
        &format!(
            "DELETE FROM tx_reconfirmation_receipts
                  WHERE transaction_id IN (SELECT t.id_tx FROM transactions t
                      WHERE t.mined_height > :height AND {UNOBSERVABLE_TRANSACTION})"
        ),
        named_params![":height": u32::from(truncation_height)],
    )?;
    conn.execute(
        &format!(
            "INSERT INTO tx_reconfirmation_receipts
                     (transaction_id, mined_height, block_hash, tx_index)
                  SELECT t.id_tx, t.mined_height, b.hash, t.tx_index
                  FROM transactions t JOIN blocks b ON b.height = t.mined_height
                  WHERE t.mined_height > :height AND {UNOBSERVABLE_TRANSACTION}"
        ),
        named_params![":height": u32::from(truncation_height)],
    )?;
    reset_validation_after_rewind(conn, rescan_floor)?;
    Ok(())
}

/// Rewinding an unscanned suffix can change the branch without un-mining any additional rows.
/// Require a fresh accepted scan for receipts above that rescan floor as well.
pub(super) fn reset_validation_after_rewind(
    conn: &rusqlite::Transaction<'_>,
    rescan_floor: BlockHeight,
) -> Result<(), SqliteClientError> {
    // Receipts cascade with their transactions: an empty wallet has no classification to reset.
    // This also keeps first-account setup independent of receipt schema installation.
    if !conn.query_row("SELECT EXISTS(SELECT 1 FROM transactions)", [], |row| {
        row.get::<_, bool>(0)
    })? {
        return Ok(());
    }
    conn.execute(
        "UPDATE tx_reconfirmation_receipts SET replacement_observed = 0
         WHERE mined_height > :floor",
        named_params![":floor": u32::from(rescan_floor)],
    )?;
    Ok(())
}

/// A completed observation supersedes pending historical evidence, without touching payload
/// work. Errors are not observations and must never call this transition.
pub(super) fn complete_observation(conn: &Connection, txid: TxId) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE tx_retrieval_queue SET reconfirm_mined = 0
         WHERE txid = :txid AND query_type = :status_type",
        named_params![":txid": txid.as_ref(), ":status_type": TxQueryType::Status.code()],
    )?;
    conn.execute(
        "DELETE FROM tx_reconfirmation_receipts
         WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = :txid)",
        named_params![":txid": txid.as_ref()],
    )?;
    Ok(())
}

/// Restores inclusion only against identities supplied by a successfully accepted scan batch.
/// Run after all scan validations, in the same transaction. A cached block at a different
/// height, a high scan frontier, or a rejected batch cannot authorize restoration. This does
/// not establish unspentness, transparent recovery coverage, or private spending authority.
pub(crate) fn reconcile_scanned_blocks<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    #[cfg(feature = "transparent-inputs")] gap_limits: &GapLimits,
    scanned_blocks: &[(BlockHeight, BlockHash)],
) -> Result<(), SqliteClientError> {
    for &(height, hash) in scanned_blocks {
        let receipts = conn
            .prepare_cached(
                "SELECT t.txid, r.block_hash, r.tx_index, t.mined_height IS NOT NULL
             FROM tx_reconfirmation_receipts r
             JOIN transactions t ON t.id_tx = r.transaction_id
             WHERE r.mined_height = :height",
            )?
            .query_map(named_params![":height": u32::from(height)], |row| {
                Ok((
                    TxId::from_bytes(row.get(0)?),
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<u16>>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (txid, previous_hash, tx_index, already_mined) in receipts {
            if already_mined {
                // A newer payload or shielded scan already established inclusion. Never overwrite it.
                complete_observation(conn, txid)?;
            } else if previous_hash.as_slice() == hash.0 {
                super::record_mined_transaction(
                    conn,
                    params,
                    #[cfg(feature = "transparent-inputs")]
                    gap_limits,
                    txid,
                    height,
                )?;
                conn.execute(
                    "UPDATE transactions SET tx_index = :index WHERE txid = :txid",
                    named_params![":index": tx_index, ":txid": txid.as_ref()],
                )?;
                complete_observation(conn, txid)?;
            } else {
                conn.execute(
                    "UPDATE tx_reconfirmation_receipts SET replacement_observed = 1
                     WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = :txid)",
                    named_params![":txid": txid.as_ref()],
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
