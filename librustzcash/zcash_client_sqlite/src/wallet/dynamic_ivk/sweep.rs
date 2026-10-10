//! Restore sweep steps around an app's directory lookups (see `DynamicIvkWrite`).
use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension, params};
use zakura_dynamic_ivk::recovery::EncryptedNote;
use zcash_client_backend::data_api::{
    dynamic_ivk::{DirectoryPayment, MAX_PUBLICATION_LAG, SweepDeferral},
    transparent_ledger::ChainPoint,
};
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::{
    KeyId, PendingPayment, activate, corrupt, invalid, key_ref,
    payments::pending_payments,
    planner::{anchor, canonical, queue_lookup},
};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// Implements `DynamicIvkRead::directory_publication_anchor`.
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

/// Implements `DynamicIvkRead::directory_note_data_needed`.
pub(crate) fn note_data_needed(
    conn: &Connection,
    account: AccountUuid,
    key: KeyId,
    payments: &[DirectoryPayment],
) -> Result<Vec<u64>, SqliteClientError> {
    let (_, missing) = sort_directory_payments(conn, account, key, payments)?;
    Ok(missing.iter().map(|(p, _)| p.position).collect())
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
                "SELECT n.receiving_key_id, t.mined_height, n.commitment_tree_position
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

/// Implements `DynamicIvkWrite::queue_directory_lookup`.
pub(crate) fn queue_directory_lookup<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    anchor: ChainPoint,
    payments: &[DirectoryPayment],
    note_data: &BTreeMap<u64, [u8; 528]>,
) -> Result<Result<bool, SweepDeferral>, SqliteClientError> {
    // A deferral changes nothing, so check before replacing queued candidates.
    if canonical(conn, Some(anchor))?.is_none() {
        return Ok(Err(SweepDeferral::UnknownAnchor));
    }
    let (kept, missing) = sort_directory_payments(conn, account, key, payments)?;
    for old in pending_payments(conn, account, key)? {
        if !kept.contains(&old) {
            conn.execute(
                "DELETE FROM ironwood_dynamic_payment_recovery
                 WHERE txid = ?1 AND action_index = ?2",
                params![old.txid.as_ref(), old.action_index],
            )?;
        }
    }
    let mut fresh = Vec::new();
    let mut done = true;
    for (payment, position) in missing {
        let Some(suffix) = note_data.get(&payment.position) else {
            done = false;
            continue;
        };
        fresh.push(PendingPayment {
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
                suffix,
            ),
        });
    }
    Ok(queue_lookup(conn, params, account, key, anchor, &fresh, done)?.map(|()| done))
}

/// Finishes `key`'s sweep at its lookup's anchor once its candidates are applied, and
/// scans the key from the next block (see `DynamicIvkWrite::apply_dynamic_sweep`).
pub(super) fn finish(
    conn: &rusqlite::Transaction<'_>,
    account: AccountUuid,
    key: KeyId,
    seen: bool,
) -> Result<Result<(), SweepDeferral>, SqliteClientError> {
    let id = key_ref(conn, account, key)?;
    let (pending, lookup): (bool, Option<ChainPoint>) = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_dynamic_payment_recovery
                WHERE receiving_key_id = ?1),
            lookup_height, lookup_hash
         FROM ironwood_dynamic_sweeps WHERE receiving_key_id = ?1",
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
        "UPDATE ironwood_dynamic_sweeps SET done_height = ?2 WHERE receiving_key_id = ?1",
        params![id, u32::from(lookup.height)],
    )?;
    // Never issued again, so like a paid key it extends the restore walk and the gap
    // (see `recovery_end`).
    if seen {
        conn.execute(
            "UPDATE ironwood_receiving_keys
             SET provider_seen = 1, advances_allocation = 1 WHERE id = ?1",
            [id],
        )?;
    }
    activate(conn, id, lookup.height + 1)?;
    Ok(Ok(()))
}
