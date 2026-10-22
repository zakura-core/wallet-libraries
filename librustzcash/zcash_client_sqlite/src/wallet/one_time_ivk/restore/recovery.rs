//! Refund identities recovered from authenticated ordinary wallet history.
use rusqlite::{Connection, params};
use zakura_one_time_ivk::swap::{REFUND_MEMO_MAGIC, RefundMemo};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::wallet::one_time_ivk::{KeyId, Purpose, register};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// Whether an internal funding record may still hold an unregistered refund index after
/// [`recover_refund_memos`]: its memo is not retrieved yet, or it lacks own-send evidence
/// while scanning has not reached its block. Refund issuance waits.
pub(in crate::wallet::one_time_ivk) fn refund_memos_pending(
    conn: &Connection,
    account: AccountUuid,
) -> Result<bool, SqliteClientError> {
    let scanned = wallet::fully_scanned_height(conn)?.map(u32::from);
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes n
         JOIN transactions t ON t.id_tx = n.transaction_id
         JOIN accounts a ON a.id = n.account_id
         WHERE a.uuid = ?1 AND n.recipient_key_scope = 1
           AND n.one_time_key_id IS NULL AND t.mined_height IS NOT NULL
           AND (n.memo IS NULL OR (substr(n.memo, 1, 5) = ?3
             AND NOT EXISTS(SELECT 1 FROM v_received_output_spends s
               WHERE s.transaction_id = n.transaction_id
                 AND s.account_id = n.account_id)
             AND (?2 IS NULL OR t.mined_height > ?2))))",
        params![account.0, scanned, REFUND_MEMO_MAGIC],
        |r| r.get(0),
    )?)
}

/// Recovers refund identities only from internal funding memos with an input owned by
/// this account. Zero-value and already-spent memo outputs remain eligible.
pub(in crate::wallet::one_time_ivk) fn recover_refund_memos<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let owner = wallet::get_account_ref(conn, account)?;
    let records = conn
        .prepare_cached(
            "SELECT n.memo, t.mined_height FROM ironwood_received_notes n
         JOIN transactions t ON t.id_tx = n.transaction_id
         WHERE n.account_id = ?1 AND n.recipient_key_scope = 1
           AND n.one_time_key_id IS NULL AND t.mined_height IS NOT NULL
           AND substr(n.memo, 1, 5) = ?2 AND EXISTS(SELECT 1 FROM v_received_output_spends s
               WHERE s.transaction_id = n.transaction_id AND s.account_id = n.account_id)",
        )?
        .query_map(params![owner.0, REFUND_MEMO_MAGIC], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, u32>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (bytes, height) in records {
        let Some(memo) = zcash_protocol::memo::MemoBytes::from_bytes(&bytes)
            .ok()
            .and_then(|bytes| RefundMemo::decode(bytes.as_array()))
        else {
            continue;
        };
        let (id, _) = register(
            conn,
            params,
            account,
            KeyId::new(Purpose::Refund, memo.index()),
        )?;
        super::queue::funded(conn, id, BlockHeight::from(height))?;
    }
    Ok(())
}
