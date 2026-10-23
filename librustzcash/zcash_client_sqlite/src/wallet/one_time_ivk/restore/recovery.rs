//! Refund identities recovered from authenticated ordinary wallet history.
use rusqlite::{Connection, params};
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

/// How far above the account's highest known refund index a memo may register one. Indexes
/// are reserved in order, and 100 unused in a row is the gap seed discovery already assumes.
const REFUND_MEMO_GAP: u64 = 100;

/// Registers the refund key named by each refund memo on this account's mined internal
/// notes, zero-value and spent ones included. Only this wallet's keys can create an output
/// its internal key decrypts, so the memo needs no known funding input, such as one-time
/// notes not recovered yet or notes before its birthday.
///
/// A viewing key can also derive internal addresses, so an index is accepted only within
/// [`REFUND_MEMO_GAP`] of the highest known refund index, and a forged memo can at most
/// mark a nearby index used. Memos are taken in mined order, and passes repeat until none
/// is newly accepted, so a run of memos from another device raises the bound step by step
/// in whatever order they were mined. Issuance runs this first, and each issued index
/// raises the bound, so an index another device funded is accepted before issuance could
/// reach it.
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
           AND substr(n.memo, 1, 5) = ?2",
        )?
        .query_map(params![owner.0, REFUND_MEMO_MAGIC], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, u32>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut memos: Vec<(u32, u64)> = records
        .into_iter()
        .filter_map(|(bytes, height)| {
            zcash_protocol::memo::MemoBytes::from_bytes(&bytes)
                .ok()
                .and_then(|bytes| RefundMemo::decode(bytes.as_array()))
                .map(|memo| (height, memo.index()))
        })
        .collect();
    memos.sort_unstable();
    let highest: Option<Vec<u8>> = conn.query_row(
        "SELECT MAX(key_index) FROM ironwood_one_time_keys WHERE account_id = ?1 AND purpose = 0",
        [owner.0],
        |r| r.get(0),
    )?;
    let mut highest = highest.map(decode_index).transpose()?.unwrap_or(0);
    loop {
        let mut deferred = vec![];
        for (height, index) in memos {
            if index > highest.saturating_add(REFUND_MEMO_GAP) {
                deferred.push((height, index));
                continue;
            }
            let (id, _) = register(conn, params, account, KeyId::new(Purpose::Refund, index))?;
            super::queue::funded(conn, params, id, BlockHeight::from(height))?;
            highest = highest.max(index);
        }
        if deferred.is_empty()
            || deferred
                .iter()
                .all(|(_, i)| *i > highest.saturating_add(REFUND_MEMO_GAP))
        {
            return Ok(());
        }
        memos = deferred;
    }
}
