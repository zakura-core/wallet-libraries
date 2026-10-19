//! Recovery from authenticated wallet data, independent of the directory transport.
use rusqlite::{Connection, OptionalExtension, params};
use zakura_one_time_ivk::swap::{REFUND_MEMO_MAGIC, RefundMemo};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::wallet::one_time_ivk::{
    Discovery, KeyId, Purpose, account_key, authenticate_key, block_issuance, recovering_accounts,
    register,
};
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

/// Runs [`recover_refund_memos`] for every account whose one-time keys are recovered, as
/// storing a block, a full transaction or a retrieved memo does.
pub(crate) fn recover_all<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    now: i64,
) -> Result<(), SqliteClientError> {
    for account in recovering_accounts(conn, params)? {
        recover_refund_memos(conn, params, account, now)?;
    }
    Ok(())
}

/// Registers, for a lookup, the refund key of each confirmed internal funding memo, spent
/// and zero-value ones included, whose own-send evidence (an input of the same account)
/// authenticates it, unless a key already covers its block. A marked memo that does not
/// decode is ignored. Every memo's key is blocked from issuance, and one that is
/// authenticated is promoted (see `one_time_ivk::coverage`), whether or not its history
/// was already covered.
///
/// A marker still lacking that evidence once scanning passed its block was funded before
/// the birthday or is not this wallet's: its key is looked up without advancing
/// allocation, so a forged record cannot exhaust the index space. It is sparse: it joins
/// the receiver set alone and never widens a window.
pub(in crate::wallet::one_time_ivk) fn recover_refund_memos<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<(), SqliteClientError> {
    let (account_ref, _) = account_key(conn, params, account)?;
    let scanned = wallet::fully_scanned_height(conn)?.map(u32::from);
    let records = conn
        .prepare_cached(
            "SELECT n.memo, t.mined_height, EXISTS (SELECT 1 FROM v_received_output_spends s
                 WHERE s.transaction_id = n.transaction_id AND s.account_id = n.account_id)
             FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             WHERE n.account_id = ?1 AND n.recipient_key_scope = 1
               AND n.one_time_key_id IS NULL AND t.mined_height IS NOT NULL
               AND substr(n.memo, 1, 5) = ?2",
        )?
        .query_map(params![account_ref.0, REFUND_MEMO_MAGIC], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, bool>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (bytes, height, authenticated) in records {
        // SQLite omits trailing zero padding when storing MemoBytes.
        let memo = zcash_protocol::memo::MemoBytes::from_bytes(&bytes)
            .ok()
            .and_then(|bytes| RefundMemo::decode(bytes.as_array()));
        let (memo, authenticated) = match memo {
            Some(memo) if authenticated => (memo, true),
            Some(memo) if scanned.is_some_and(|scanned| height <= scanned) => (memo, false),
            _ => continue,
        };
        let key_id = KeyId::new(Purpose::Refund, memo.index());
        // Storing the funding transaction already started a key scanned here (see
        // `start_funded_refund_keys`), and an earlier call queued any other.
        let covered: Option<i64> = conn
            .query_row(
                "SELECT k.id FROM ironwood_one_time_keys k
                 WHERE k.account_id = ?1 AND k.purpose = 0 AND k.key_index = ?2
                   AND k.scan_from <= ?3 AND (k.active_from <= ?3 OR EXISTS(
                     SELECT 1 FROM ironwood_one_time_lookups l WHERE l.one_time_key_id = k.id))",
                params![account_ref.0, key_id.index().to_be_bytes(), height],
                |row| row.get(0),
            )
            .optional()?;
        let id = match covered {
            Some(id) => id,
            None => {
                let from = BlockHeight::from(height);
                let lookup = Discovery::Lookup;
                register(
                    conn,
                    params,
                    account,
                    key_id,
                    from,
                    authenticated,
                    lookup,
                    now,
                )?
                .0
            }
        };
        block_issuance(conn, id)?;
        if authenticated {
            authenticate_key(conn, id)?;
        }
    }
    Ok(())
}
