//! Durable ownership-checked candidates. These rows never contribute to balance.
use rusqlite::{Connection, OptionalExtension, params};
use zcash_client_backend::data_api::one_time_ivk::restore::{
    DirectoryPayment, SegmentRef, WITNESS_PAYLOAD_BYTES,
    recovery::{EncryptedNote, RecoveredNote},
};
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::wallet::one_time_ivk::{KeyId, account_key, corrupt, invalid, key_ref};
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

/// Authenticates and queues one candidate idempotently without crediting it, with the
/// segment and ordinal it was read under and its witness `payload` at that segment's
/// companion tree. A candidate read again takes the latest binding and payload. A new
/// candidate sets the account's use marker (see `queue::mark_used`). Lookups never store
/// one before the birthday.
pub(in crate::wallet::one_time_ivk) fn queue_payment<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
    (segment, ordinal): (SegmentRef, u32),
    payload: &[u8; WITNESS_PAYLOAD_BYTES],
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
    if let Some((old, owner)) = &old
        && (old != candidate || *owner != id)
    {
        return Err(invalid("conflicting directory payment identity"));
    }
    let tree = segment.tree;
    conn.execute(
        "INSERT INTO ironwood_one_time_payment_recovery (
            one_time_key_id, txid, action_index, height, block_hash, tx_index, position,
            encrypted_note, directory, companion, ordinal, witness, witness_height,
            witness_hash, witness_size
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
         ON CONFLICT (txid, action_index) DO UPDATE SET directory = excluded.directory,
             companion = excluded.companion, ordinal = excluded.ordinal,
             witness = excluded.witness, witness_height = excluded.witness_height,
             witness_hash = excluded.witness_hash, witness_size = excluded.witness_size",
        params![
            id,
            candidate.txid.as_ref(),
            candidate.action_index,
            u32::from(candidate.height),
            candidate.block_hash.0,
            candidate.tx_index,
            candidate.position,
            candidate.encrypted_note.to_bytes().as_slice(),
            segment.directory,
            segment.companion,
            ordinal,
            payload.as_slice(),
            u32::from(tree.height),
            tree.hash,
            tree.tree_size,
        ],
    )?;
    if old.is_none() {
        super::queue::mark_used(conn, wallet::get_account_ref(conn, account)?.0)?;
    }
    Ok(())
}

/// Whether `tx`'s action `action_index` is exactly the action `note` describes: the same
/// action nullifier, note commitment, ephemeral key and ciphertext prefix. A directory
/// authenticates a note and its position but not the transaction or action it names, so
/// every check of that claim against raw bytes uses this, whether the raw transaction
/// arrives before admission or after it.
pub(in crate::wallet::one_time_ivk) fn action_holds(
    tx: &zcash_primitives::transaction::Transaction,
    action_index: u32,
    note: &EncryptedNote,
) -> bool {
    tx.ironwood_bundle()
        .and_then(|b| b.actions().get(usize::try_from(action_index).ok()?))
        .is_some_and(|a| {
            note.matches_compact(
                a.nullifier().to_bytes(),
                a.cmx().to_bytes(),
                a.encrypted_note().epk_bytes,
                a.encrypted_note().enc_ciphertext[..52]
                    .try_into()
                    .expect("52-byte prefix"),
            )
        })
}

/// The action index and compact action of stored private receipt `note`, rebuilt from the
/// stored note itself so its commitment is the one admission authenticated, or `None` for
/// a receipt stored without its compact ciphertext.
pub(in crate::wallet::one_time_ivk) fn stored_action(
    conn: &Connection,
    note: i64,
) -> Result<Option<(u32, EncryptedNote)>, SqliteClientError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(
        u32,
        [u8; 32],
        [u8; 32],
        i64,
        i64,
        [u8; 32],
        Vec<u8>,
        Vec<u8>,
    )> = conn
        .query_row(
            "SELECT n.action_index, n.rho, n.rseed, n.value, n.note_version, n.ephemeral_key,
                 n.compact_ciphertext, k.receiver
             FROM ironwood_received_notes n
             JOIN ironwood_one_time_keys k ON k.id = n.one_time_key_id
             WHERE n.id = ?1 AND n.compact_ciphertext IS NOT NULL",
            [note],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((action, rho, rseed, value, version, epk, prefix, receiver)) = row else {
        return Ok(None);
    };
    let bad = || corrupt("invalid stored one-time-key note");
    let receiver: [u8; 43] = receiver.try_into().map_err(|_| bad())?;
    let recipient =
        Option::from(orchard::Address::from_raw_address_bytes(&receiver)).ok_or_else(bad)?;
    let rho = Option::from(orchard::note::Rho::from_bytes(&rho)).ok_or_else(bad)?;
    let rseed = Option::from(orchard::note::RandomSeed::from_bytes(rseed, &rho)).ok_or_else(bad)?;
    let version = wallet::orchard::parse_note_version(version).ok_or_else(bad)?;
    let value = u64::try_from(value).map_err(|_| bad())?;
    let note: orchard::Note = Option::from(orchard::Note::from_parts(
        recipient,
        orchard::value::NoteValue::from_raw(value),
        rho,
        rseed,
        version,
    ))
    .ok_or_else(bad)?;
    let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes();
    Ok(Some((
        action,
        EncryptedNote::from_parts(
            rho.to_bytes(),
            cmx,
            epk,
            prefix.try_into().map_err(|_| bad())?,
        ),
    )))
}
