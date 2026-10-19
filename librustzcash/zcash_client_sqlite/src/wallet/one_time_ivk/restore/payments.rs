//! Durable ownership-checked candidates. These rows never contribute to balance.
use rusqlite::{Connection, OptionalExtension, params};
use zcash_client_backend::data_api::one_time_ivk::restore::{
    DirectoryPayment, PublicationEnd,
    recovery::{EncryptedNote, RecoveredNote},
};
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::wallet::one_time_ivk::{KeyId, account_key, block_issuance, invalid, key_ref};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// A directory payment awaiting inclusion and spend checks; its metadata is unchecked.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::wallet::one_time_ivk) struct PendingPayment {
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

/// `payment` as a candidate, or `None` if its position or transaction index is out of
/// range.
pub(in crate::wallet::one_time_ivk) fn directory_candidate(
    payment: &DirectoryPayment,
) -> Option<PendingPayment> {
    Some(PendingPayment {
        txid: TxId::from_bytes(payment.txid),
        action_index: payment.action_index,
        height: payment.height.into(),
        block_hash: BlockHash(payment.block_hash),
        tx_index: payment.tx_index.try_into().ok()?,
        position: payment.position.try_into().ok()?,
        encrypted_note: EncryptedNote::from_parts(
            payment.action_nullifier,
            payment.cmx,
            payment.ephemeral_key,
            payment.ciphertext_prefix,
        ),
    })
}

/// Authenticates `candidate` with `key` against its registered receiver, returning the
/// key's registry ID and the note.
pub(in crate::wallet::one_time_ivk) fn authenticate<P: Parameters>(
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
        "SELECT receiver FROM ironwood_one_time_keys WHERE id = ?1",
        [id],
        |r| r.get(0),
    )?;
    if receiver != note.note().recipient().to_raw_address_bytes() {
        return Err(invalid("directory note does not pay its key's receiver"));
    }
    Ok((id, note))
}

/// A queued candidate from a row selecting its columns in declaration order.
pub(in crate::wallet::one_time_ivk) fn payment(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PendingPayment> {
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

/// The queued candidate for output `action` of `txid`, if any.
pub(in crate::wallet::one_time_ivk) fn pending_payment(
    conn: &Connection,
    txid: TxId,
    action: u32,
) -> Result<Option<PendingPayment>, SqliteClientError> {
    Ok(conn
        .query_row(
            "SELECT txid, action_index, height, block_hash, tx_index, position, encrypted_note
             FROM ironwood_one_time_payment_recovery WHERE txid = ?1 AND action_index = ?2",
            params![txid.as_ref(), action],
            payment,
        )
        .optional()?)
}

/// Authenticates and queues one candidate from the directory revision ending at
/// `publication`, idempotently and without crediting it: a scan hint if `hint`, else a
/// late candidate. Its key is never issued again.
pub(in crate::wallet::one_time_ivk) fn queue_payment<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
    publication: PublicationEnd,
    hint: bool,
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
                encrypted_note, one_time_key_id
             FROM ironwood_one_time_payment_recovery WHERE txid = ?1 AND action_index = ?2",
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
    block_issuance(conn, id)?;
    conn.execute(
        "INSERT INTO ironwood_one_time_payment_recovery (
            one_time_key_id, txid, action_index, height, block_hash, tx_index, position,
            encrypted_note, publication_height, publication_hash, scan_hint
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            id,
            candidate.txid.as_ref(),
            candidate.action_index,
            u32::from(candidate.height),
            candidate.block_hash.0,
            candidate.tx_index,
            candidate.position,
            candidate.encrypted_note.to_bytes().as_slice(),
            u32::from(publication.height),
            publication.hash,
            hint
        ],
    )?;
    Ok(())
}
