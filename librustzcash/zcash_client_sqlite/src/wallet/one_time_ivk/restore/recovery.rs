//! Refund identities recovered from authenticated ordinary wallet history.
use rusqlite::{Connection, OptionalExtension, params};
use zakura_one_time_ivk::swap::{REFUND_MEMO_MAGIC, RefundMemo};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::wallet::one_time_ivk::{KeyId, Purpose, decode_index, register};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// Whether a mined internal note of this account still lacks its retrieved memo, which may
/// be a refund memo [`recover_refund_memos`] has not registered yet. Refund issuance waits.
pub(in crate::wallet::one_time_ivk) fn refund_memos_pending(
    conn: &Connection,
    account: AccountUuid,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes n
         JOIN transactions t ON t.id_tx = n.transaction_id
         JOIN accounts a ON a.id = n.account_id
         WHERE a.uuid = ?1 AND n.recipient_key_scope = 1
           AND n.one_time_key_id IS NULL AND t.mined_height IS NOT NULL
           AND n.memo IS NULL)",
        [account.0],
        |r| r.get(0),
    )?)
}

/// How far above the account's highest known refund index a memo may register one without
/// proof that this wallet spent in its transaction. Indexes are reserved in order, and 100
/// unused in a row is the gap seed discovery already assumes.
const REFUND_MEMO_GAP: u64 = 100;

/// Queues the refund memos on internal notes of transaction `tx_ref` that no key holds
/// yet, as storing a decrypted, sent or privately enhanced transaction does, then retries
/// every memo of that transaction still queued for each enabled account, including one
/// queued earlier, since storing it may have just established its block or its spends (see
/// [`recover_refund_memos`]).
pub(crate) fn memos_stored<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    tx_ref: i64,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT OR IGNORE INTO ironwood_one_time_pending_memos (note_id)
         SELECT id FROM ironwood_received_notes
         WHERE transaction_id = ?1 AND recipient_key_scope = 1 AND one_time_key_id IS NULL
           AND substr(memo, 1, 5) = ?2",
        params![tx_ref, REFUND_MEMO_MAGIC],
    )?;
    let accounts: Vec<AccountUuid> = conn
        .prepare(
            "SELECT DISTINCT a.uuid FROM ironwood_received_notes n
             JOIN ironwood_one_time_pending_memos q ON q.note_id = n.id
             JOIN accounts a ON a.id = n.account_id
             JOIN ironwood_one_time_recovery r ON r.account_id = a.id
             WHERE n.transaction_id = ?1 AND r.enabled = 1",
        )?
        .query_map([tx_ref], |r| Ok(AccountUuid(r.get(0)?)))?
        .collect::<Result<_, _>>()?;
    for account in accounts {
        recover_refund_memos(conn, params, account)?;
    }
    Ok(())
}

/// [`memos_stored`] for the transaction with ID `txid`, if the wallet stored it.
pub(crate) fn memos_stored_by_txid<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    txid: &[u8],
) -> Result<(), SqliteClientError> {
    let tx_ref: Option<i64> = conn
        .query_row(
            "SELECT id_tx FROM transactions WHERE txid = ?1",
            [txid],
            |r| r.get(0),
        )
        .optional()?;
    tx_ref.map_or(Ok(()), |tx_ref| memos_stored(conn, params, tx_ref))
}

/// Queues every refund memo on `account`'s internal notes that no key holds yet, as
/// enabling recovery does, since memos stored while it was off were not processed.
pub(in crate::wallet::one_time_ivk) fn queue_all_refund_memos(
    conn: &Connection,
    owner: i64,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT OR IGNORE INTO ironwood_one_time_pending_memos (note_id)
         SELECT id FROM ironwood_received_notes
         WHERE account_id = ?1 AND recipient_key_scope = 1 AND one_time_key_id IS NULL
           AND substr(memo, 1, 5) = ?2",
        params![owner, REFUND_MEMO_MAGIC],
    )?;
    Ok(())
}

/// Registers the refund key named by each queued refund memo on this account's mined
/// internal notes, zero-value and spent ones included, and removes it from the queue. Only
/// this wallet's keys can create an output its internal key decrypts, so the memo needs no
/// known funding input, such as one-time notes not recovered yet or notes before its
/// birthday. Memos are queued when their transaction is stored (see [`memos_stored`]), so
/// a block batch reads only the few still waiting, not every historical memo.
///
/// A viewing key can also derive internal addresses, so an index is accepted only within
/// [`REFUND_MEMO_GAP`] of the highest known refund index, or when the transaction spends a
/// note this account owns, which a viewing key cannot forge. A forged memo can at most mark
/// a nearby index used, and one beyond the gap without that proof stays queued until the
/// gap closes or ownership of a spent note is learned. An unmined memo waits for its block.
/// Memos are taken in mined order, and passes repeat until none is newly accepted, so a run
/// of memos from another device raises the bound step by step in whatever order they were
/// mined. Issuance runs this first, and each issued index raises the bound, so an index
/// another device funded is accepted before issuance could reach it.
pub(in crate::wallet::one_time_ivk) fn recover_refund_memos<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let owner = wallet::get_account_ref(conn, account)?;
    let records = conn
        .prepare_cached(PENDING_MEMOS)?
        .query_map([owner.0], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<Vec<u8>>>(1)?,
                r.get::<_, Option<u32>>(2)?,
                r.get::<_, bool>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut memos = vec![];
    for (note, bytes, height, own_send) in records {
        let memo = bytes
            .and_then(|bytes| zcash_protocol::memo::MemoBytes::from_bytes(&bytes).ok())
            .and_then(|bytes| RefundMemo::decode(bytes.as_array()));
        match (memo, height) {
            (Some(memo), Some(height)) => memos.push((height, memo.index(), own_send, note)),
            (Some(_), None) => {}
            (None, _) => drop_memo(conn, note)?,
        }
    }
    memos.sort_unstable();
    let highest: Option<Vec<u8>> = conn.query_row(
        "SELECT MAX(key_index) FROM ironwood_one_time_keys WHERE account_id = ?1 AND purpose = 0",
        [owner.0],
        |r| r.get(0),
    )?;
    let mut highest = highest.map(decode_index).transpose()?.unwrap_or(0);
    loop {
        let mut deferred = vec![];
        for (height, index, own_send, note) in memos {
            if !own_send && index > highest.saturating_add(REFUND_MEMO_GAP) {
                deferred.push((height, index, own_send, note));
                continue;
            }
            let (id, _) = register(conn, params, account, KeyId::new(Purpose::Refund, index))?;
            super::queue::funded(conn, params, id, BlockHeight::from(height))?;
            drop_memo(conn, note)?;
            highest = highest.max(index);
        }
        if deferred.is_empty()
            || deferred
                .iter()
                .all(|(_, i, _, _)| *i > highest.saturating_add(REFUND_MEMO_GAP))
        {
            return Ok(());
        }
        memos = deferred;
    }
}

/// `?1`'s queued memos with their note, block and own-spend evidence. Every block batch
/// runs this, so the queue, almost always nearly empty, drives the joins rather than the
/// account's whole note history.
pub(in crate::wallet::one_time_ivk) const PENDING_MEMOS: &str = "SELECT q.note_id, n.memo,
     t.mined_height, EXISTS(SELECT 1 FROM v_received_output_spends s
         WHERE s.transaction_id = n.transaction_id AND s.account_id = n.account_id)
     FROM ironwood_one_time_pending_memos q
     CROSS JOIN ironwood_received_notes n ON n.id = q.note_id
     CROSS JOIN transactions t ON t.id_tx = n.transaction_id
     WHERE n.account_id = ?1";

/// Removes note `note`'s memo from the queue, once accepted or when it is not a refund memo.
fn drop_memo(conn: &Connection, note: i64) -> Result<(), SqliteClientError> {
    conn.execute(
        "DELETE FROM ironwood_one_time_pending_memos WHERE note_id = ?1",
        [note],
    )?;
    Ok(())
}
