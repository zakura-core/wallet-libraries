//! Restore sweep steps around an app's directory lookups (see `OneTimeIvkRestoreWrite`).
use rusqlite::{Connection, OptionalExtension, params};
use zcash_client_backend::data_api::{
    one_time_ivk::restore::{
        DirectoryPayment, MAX_PUBLICATION_LAG, SweepDeferral, recovery::EncryptedNote,
    },
    transparent_ledger::ChainPoint,
};
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::{
    PendingPayment,
    payments::pending_payments,
    planner::{anchor, canonical, queue_lookup},
};
use crate::wallet::one_time_ivk::{KeyId, activate, corrupt, invalid, key_ref};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// Implements `OneTimeIvkRestoreRead::directory_publication_anchor`.
pub(crate) fn publication_anchor(
    conn: &Connection,
    height: BlockHeight,
    through: ChainPoint,
) -> Result<Result<ChainPoint, SweepDeferral>, SqliteClientError> {
    let hash = match wallet::get_block_hash(conn, height)? {
        Some(hash) if height <= through.height => hash,
        _ => return Ok(Err(SweepDeferral::UnknownAnchor)),
    };
    if u32::from(through.height) - u32::from(height) > MAX_PUBLICATION_LAG {
        return Ok(Err(SweepDeferral::StalePublication));
    }
    Ok(Ok(ChainPoint { height, hash }))
}

/// Splits `payments` into the queued candidates they repeat and the rest, with positions,
/// skipping imported ones and failing on one that contradicts its import.
#[allow(clippy::type_complexity)]
fn sort_directory_payments<'a>(
    conn: &Connection,
    account: AccountUuid,
    key: KeyId,
    payments: &'a [DirectoryPayment],
) -> Result<(Vec<PendingPayment>, Vec<(&'a DirectoryPayment, u32)>), SqliteClientError> {
    let id = key_ref(conn, account, key)?;
    let queued = pending_payments(conn, account, key)?;
    let mut kept = Vec::new();
    let mut missing = Vec::new();
    for payment in payments {
        let position = u32::try_from(payment.position)
            .map_err(|_| invalid("directory payment position out of range"))?;
        let txid = TxId::from_bytes(payment.txid);
        let block_hash = BlockHash(payment.block_hash);
        let height = BlockHeight::from(payment.height);
        let imported: Option<(Option<i64>, u32, u32)> = conn
            .query_row(
                "SELECT n.one_time_key_id, t.mined_height, n.commitment_tree_position
                 FROM ironwood_received_notes n
                 JOIN transactions t ON t.id_tx = n.transaction_id
                 WHERE t.txid = ?1 AND n.action_index = ?2 AND t.mined_height IS NOT NULL
                   AND n.commitment_tree_position IS NOT NULL",
                params![txid.as_ref(), payment.action_index],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((owner, mined, imported_at)) = imported {
            if owner != Some(id)
                || mined != payment.height
                || imported_at != position
                || wallet::get_block_hash(conn, height)? != Some(block_hash)
            {
                return Err(invalid("directory payment contradicts a stored note"));
            }
            continue;
        }
        match queued
            .iter()
            .find(|p| p.txid == txid && p.action_index == payment.action_index)
        {
            Some(old)
                if old.position == position
                    && old.height == height
                    && old.block_hash == block_hash
                    && u32::from(old.tx_index) == payment.tx_index
                    && old.encrypted_note.matches_compact(
                        payment.action_nullifier,
                        payment.cmx,
                        payment.ephemeral_key,
                        payment.ciphertext_prefix,
                    ) =>
            {
                kept.push(old.clone())
            }
            // A corrected answer replaces the candidate it contradicts when queued.
            _ => missing.push((payment, position)),
        }
    }
    Ok((kept, missing))
}

/// Implements `OneTimeIvkRestoreWrite::queue_directory_lookup`.
pub(crate) fn queue_directory_lookup<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    anchor: ChainPoint,
    payments: &[DirectoryPayment],
) -> Result<Result<(), SweepDeferral>, SqliteClientError> {
    // A deferral changes nothing, so check before replacing queued candidates.
    if canonical(conn, Some(anchor))?.is_none() {
        return Ok(Err(SweepDeferral::UnknownAnchor));
    }
    let (kept, missing) = sort_directory_payments(conn, account, key, payments)?;
    for old in pending_payments(conn, account, key)? {
        if !kept.contains(&old) {
            conn.execute(
                "DELETE FROM ironwood_one_time_payment_recovery
                 WHERE txid = ?1 AND action_index = ?2",
                params![old.txid.as_ref(), old.action_index],
            )?;
        }
    }
    let fresh = missing
        .into_iter()
        .map(|(payment, position)| {
            Ok(PendingPayment {
                txid: TxId::from_bytes(payment.txid),
                action_index: payment.action_index,
                height: payment.height.into(),
                block_hash: BlockHash(payment.block_hash),
                tx_index: payment
                    .tx_index
                    .try_into()
                    .map_err(|_| invalid("directory payment index out of range"))?,
                position,
                encrypted_note: EncryptedNote::from_parts(
                    payment.action_nullifier,
                    payment.cmx,
                    payment.ephemeral_key,
                    payment.ciphertext_prefix,
                ),
            })
        })
        .collect::<Result<Vec<_>, SqliteClientError>>()?;
    queue_lookup(conn, params, account, key, anchor, &fresh)
}

/// Finishes `key`'s sweep at its lookup's anchor once its candidates are applied (see
/// `OneTimeIvkRestoreWrite::apply_one_time_sweep`).
pub(in crate::wallet::one_time_ivk) fn finish(
    conn: &rusqlite::Transaction<'_>,
    account: AccountUuid,
    key: KeyId,
    recent: bool,
) -> Result<Result<(), SweepDeferral>, SqliteClientError> {
    let id = key_ref(conn, account, key)?;
    let (pending, lookup): (bool, Option<ChainPoint>) = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery
                WHERE one_time_key_id = ?1),
            lookup_height, lookup_hash
         FROM ironwood_one_time_sweeps WHERE one_time_key_id = ?1",
        [id],
        |r| Ok((r.get(0)?, anchor(r.get(1)?, r.get(2)?))),
    )?;
    if pending {
        return Err(corrupt("sweep has unapplied candidates"));
    }
    let Some(lookup) = canonical(conn, lookup)? else {
        return Ok(Err(SweepDeferral::UnknownAnchor));
    };
    conn.execute(
        "UPDATE ironwood_one_time_sweeps SET done_height = ?2 WHERE one_time_key_id = ?1",
        params![id, u32::from(lookup.height)],
    )?;
    // A refund owed while the sweep was pending deferred an unstarted key's start to here
    // (see `swap::reservations::record_status`). Expectations 2 and 3 are a receipt or an
    // inconclusive end (see `swap::lifecycle::record`).
    let (scanning, refund_owed): (bool, bool) = conn.query_row(
        "SELECT k.active_from IS NOT NULL AND k.closed_at IS NULL,
            k.purpose = 0 AND k.active_from IS NULL AND k.closed_at IS NULL
              AND EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                WHERE o.one_time_key_id = k.id AND o.expectation IN (2, 3))
         FROM ironwood_one_time_keys k WHERE k.id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if recent || scanning || refund_owed {
        activate(conn, id, lookup.height + 1)?;
    } else {
        conn.execute(
            "UPDATE ironwood_one_time_keys SET closed_at = COALESCE(closed_at,
                (SELECT time FROM blocks WHERE height = ?2))
             WHERE id = ?1",
            params![id, u32::from(lookup.height)],
        )?;
    }
    Ok(Ok(()))
}
