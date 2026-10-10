//! Durable ownership-checked candidates. These rows never contribute to balance.
use rusqlite::{Connection, OptionalExtension, params};
use zakura_dynamic_ivk::recovery::{EncryptedNote, RecoveredNote};
use zcash_client_backend::data_api::{dynamic_ivk::SweepDeferral, transparent_ledger::ChainPoint};
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::{
    PoolType,
    consensus::{BlockHeight, Parameters},
};

use super::{KeyId, account_key, invalid, key_ref};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// A directory payment awaiting inclusion and spend checks; its metadata is unchecked.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct PendingPayment {
    /// Transaction hash in protocol byte order.
    pub txid: TxId,
    /// Original Action index.
    pub action_index: u32,
    /// Claimed mined height.
    pub height: BlockHeight,
    /// Claimed canonical block hash.
    pub block_hash: BlockHash,
    /// Original transaction index in that block.
    pub tx_index: u16,
    /// Global Ironwood commitment position.
    pub position: u32,
    /// Full incoming encrypted-note context, without service fee or expiry assertions.
    pub encrypted_note: EncryptedNote,
}

/// Local spend evidence as of one independently checked scan anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SpendStatus {
    /// Scan coverage is missing, pruned, or the requested anchor is not yet scanned.
    Unknown,
    /// Every block retains its unlinked nullifiers, and no recorded wallet spend matches.
    Unspent,
    /// A retained canonical transaction with this ID reveals the nullifier.
    Spent(TxId),
}

/// Authenticates `candidate` with `key` against its registered receiver, returning the
/// key's registry ID and the note.
pub(super) fn authenticate<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
) -> Result<(i64, RecoveredNote), SqliteClientError> {
    let id = key_ref(conn, account, key)?;
    let (_, parent) = account_key(conn, params, account)?;
    let note = candidate
        .encrypted_note
        .decrypt(&parent, key)
        .ok_or_else(|| invalid("directory note authentication failed"))?;
    let receiver: Vec<u8> = conn.query_row(
        "SELECT receiver FROM ironwood_receiving_keys WHERE id = ?1",
        [id],
        |r| r.get(0),
    )?;
    if receiver != note.note().recipient().to_raw_address_bytes() {
        return Err(invalid("directory note does not pay its key's receiver"));
    }
    Ok((id, note))
}

/// A queued candidate from a row selecting its columns in declaration order.
fn payment(row: &rusqlite::Row<'_>) -> rusqlite::Result<PendingPayment> {
    let bytes: Vec<u8> = row.get(6)?;
    let bytes = bytes
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(PendingPayment {
        txid: TxId::from_bytes(row.get(0)?),
        action_index: row.get(1)?,
        height: BlockHeight::from(row.get::<_, u32>(2)?),
        block_hash: BlockHash(row.get(3)?),
        tx_index: row.get(4)?,
        position: row.get(5)?,
        encrypted_note: EncryptedNote::from_bytes(bytes),
    })
}

/// Checks retained nullifiers through `through` for `nullifier`, authenticated
/// `candidate`'s, without accepting a service's claim of absence.
pub(super) fn spend_status(
    conn: &Connection,
    candidate: &PendingPayment,
    nullifier: &orchard::note::Nullifier,
    through: ChainPoint,
) -> Result<Result<SpendStatus, SweepDeferral>, SqliteClientError> {
    if through.height < candidate.height
        || wallet::fully_scanned_height(conn)?.is_none_or(|h| h < through.height)
    {
        return Ok(Ok(SpendStatus::Unknown));
    }
    if wallet::get_block_hash(conn, through.height)? != Some(through.hash)
        || wallet::get_block_hash(conn, candidate.height)? != Some(candidate.block_hash)
    {
        return Ok(Err(SweepDeferral::UnknownAnchor));
    }
    let spent = conn
        .query_row(
            // The scanner removes known wallet spends from the unlinked nullifier map.
            // Both stores must be checked before interpreting absence as unspent.
            "SELECT t.txid FROM nullifier_map n
             JOIN tx_locator_map t USING (block_height, tx_index)
             WHERE n.spend_pool = ?1 AND n.nf = ?2 AND t.block_height BETWEEN ?3 AND ?4
             UNION ALL
             SELECT t.txid FROM ironwood_received_notes n
             JOIN ironwood_received_note_spends s ON s.ironwood_received_note_id = n.id
             JOIN transactions t ON t.id_tx = s.transaction_id
             JOIN blocks b ON b.height = t.block AND b.height = t.mined_height
             WHERE n.nf = ?2 AND t.mined_height BETWEEN ?3 AND ?4
             LIMIT 1",
            params![
                wallet::encoding::pool_code(PoolType::IRONWOOD),
                nullifier.to_bytes(),
                u32::from(candidate.height),
                u32::from(through.height)
            ],
            |r| Ok(SpendStatus::Spent(TxId::from_bytes(r.get(0)?))),
        )
        .optional()?;
    if let Some(spent) = spent {
        return Ok(Ok(spent));
    }
    let covered: u64 = conn.query_row(
        "SELECT COUNT(*) FROM ironwood_nullifier_scan_blocks WHERE height BETWEEN ?1 AND ?2",
        params![u32::from(candidate.height), u32::from(through.height)],
        |r| r.get(0),
    )?;
    let blocks = u64::from(u32::from(through.height) - u32::from(candidate.height)) + 1;
    Ok(Ok(if covered == blocks {
        SpendStatus::Unspent
    } else {
        SpendStatus::Unknown
    }))
}

/// `account`'s queued candidates for `key`. Loading does not credit or complete them.
pub(super) fn pending_payments(
    conn: &Connection,
    account: AccountUuid,
    key: KeyId,
) -> Result<Vec<PendingPayment>, SqliteClientError> {
    let id = key_ref(conn, account, key)?;
    let mut stmt = conn.prepare(
        "SELECT txid, action_index, height, block_hash, tx_index, position, encrypted_note
         FROM ironwood_dynamic_payment_recovery WHERE receiving_key_id = ?1 ORDER BY position",
    )?;
    Ok(stmt.query_map([id], payment)?.collect::<Result<_, _>>()?)
}

/// Authenticates and queues one candidate, idempotently, without crediting it.
pub(super) fn queue_payment<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
) -> Result<(), SqliteClientError> {
    let (id, _) = authenticate(conn, params, account, key, candidate)?;
    if wallet::get_block_hash(conn, candidate.height)?
        .is_some_and(|hash| hash != candidate.block_hash)
    {
        return Err(invalid(
            "directory payment block is not on the wallet's chain",
        ));
    }
    let old = conn
        .query_row(
            "SELECT txid, action_index, height, block_hash, tx_index, position,
                encrypted_note, receiving_key_id
             FROM ironwood_dynamic_payment_recovery WHERE txid = ?1 AND action_index = ?2",
            params![candidate.txid.as_ref(), candidate.action_index],
            |r| Ok((payment(r)?, r.get::<_, i64>(7)?)),
        )
        .optional()?;
    if let Some((old, owner)) = old {
        return if old == *candidate && owner == id {
            Ok(())
        } else {
            Err(invalid("conflicting directory payment identity"))
        };
    }
    conn.execute(
        "INSERT INTO ironwood_dynamic_payment_recovery (
            receiving_key_id, txid, action_index, height, block_hash,
            tx_index, position, encrypted_note
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            id,
            candidate.txid.as_ref(),
            candidate.action_index,
            u32::from(candidate.height),
            candidate.block_hash.0,
            candidate.tx_index,
            candidate.position,
            candidate.encrypted_note.to_bytes().as_slice()
        ],
    )?;
    Ok(())
}
