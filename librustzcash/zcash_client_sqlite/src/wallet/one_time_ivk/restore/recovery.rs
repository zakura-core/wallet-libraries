//! Refund identities recovered from authenticated ordinary wallet history.
use rusqlite::{Connection, params};
use zakura_one_time_ivk::swap::{REFUND_MEMO_MAGIC, RefundMemo};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::wallet::one_time_ivk::{KeyId, Purpose, decode_index, one_time_account, register};
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

/// SQL over note alias `n`, joined to its transaction `t`: a stored refund memo, on a mined
/// internal note of the account that no one-time key holds. `?2` is [`REFUND_MEMO_MAGIC`].
const STORED_MEMO: &str = "n.recipient_key_scope = 1 AND n.one_time_key_id IS NULL
    AND t.mined_height IS NOT NULL AND substr(n.memo, 1, 5) = ?2";

/// Decodes stored memo bytes as a refund memo. A memo that doesn't decode is ignored.
fn decode_memo(bytes: &[u8]) -> Option<RefundMemo> {
    zcash_protocol::memo::MemoBytes::from_bytes(bytes)
        .ok()
        .and_then(|bytes| RefundMemo::decode(bytes.as_array()))
}

/// Accepts the stored refund memos mined in the transactions with IDs `txids`, for every
/// account with one, enabled or not (see [`accept_memo_evidence`]). Storing blocks passes
/// the transactions they mined, which covers a memo stored before its block and one a
/// reorg's replacement chain mines again. Storing a decrypted, sent or privately enhanced
/// transaction passes that transaction, which covers a memo retrieved after its block.
/// Each ID is one indexed lookup, so a batch costs nothing per historical memo.
pub(crate) fn accept_mined_memos<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    txids: impl IntoIterator<Item = [u8; 32]>,
) -> Result<(), SqliteClientError> {
    let mut accounts: Vec<AccountUuid> = vec![];
    let mut query = conn.prepare_cached(&format!(
        "SELECT a.uuid, n.memo FROM transactions t
         JOIN ironwood_received_notes n ON n.transaction_id = t.id_tx
         JOIN accounts a ON a.id = n.account_id
         WHERE t.txid = ?1 AND {STORED_MEMO}"
    ))?;
    for txid in txids {
        let rows = query
            .query_map(params![txid, REFUND_MEMO_MAGIC], |r| {
                Ok((AccountUuid(r.get(0)?), r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (account, memo) in rows {
            if decode_memo(&memo).is_some() && !accounts.contains(&account) {
                accounts.push(account);
            }
        }
    }
    drop(query);
    for account in accounts {
        accept_memo_evidence(conn, params, account)?;
    }
    Ok(())
}

/// Accepts a mined refund memo that decodes as evidence that `account` uses one-time
/// addresses, even one the gap rule defers: enables it if it isn't enabled, which recovers
/// its memos, or recovers them, and recovery sets the use marker (see
/// [`recover_refund_memos`]). An account without an Orchard key holds no one-time keys, so
/// it is left alone.
fn accept_memo_evidence<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let owner = wallet::get_account_ref(conn, account)?;
    let enabled: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_recovery
         WHERE account_id = ?1 AND enabled = 1)",
        [owner.0],
        |r| r.get(0),
    )?;
    if enabled {
        recover_refund_memos(conn, params, account)
    } else if one_time_account(conn, params, account)?.is_some() {
        super::queue::enable(conn, params, account)
    } else {
        Ok(())
    }
}

/// Registers the refund key named by each stored refund memo on this account's mined
/// internal notes, zero-value and spent ones included. Only this wallet's keys can create an
/// output its internal key decrypts, so the memo needs no known funding input, such as
/// one-time notes not recovered yet or notes before its birthday. It reads the account's
/// memos when it runs: at enabling, at each round's start, before refund issuance and when
/// a stored transaction or block brings a mined memo (see [`accept_mined_memos`]). A memo
/// whose key already holds that funding height or an earlier one is skipped, so a repeat
/// costs one indexed read per memo.
///
/// A viewing key can also derive internal addresses, so an index is accepted only within
/// [`REFUND_MEMO_GAP`] of the highest known refund index, or when the transaction spends a
/// note this account owns, which a viewing key cannot forge. A forged memo can at most mark
/// a nearby index used, and one beyond the gap without that proof is accepted at a later
/// run, once the gap closes or ownership of a spent note is learned. Memos are taken in
/// mined order, and passes repeat until none is newly accepted, so a run of memos from
/// another device raises the bound step by step in whatever order they were mined.
/// Issuance runs this first, and each issued index raises the bound, so an index another
/// device funded is accepted before issuance could reach it.
///
/// A mined memo that decodes is evidence the account funded a swap, so it sets the use
/// marker (see `queue::mark_used`) before the gap rule decides on it, whichever caller
/// consumes it.
pub(in crate::wallet::one_time_ivk) fn recover_refund_memos<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let owner = wallet::get_account_ref(conn, account)?;
    let records = conn
        .prepare_cached(&format!(
            "SELECT n.memo, t.mined_height,
             EXISTS(SELECT 1 FROM v_received_output_spends s
                 WHERE s.transaction_id = n.transaction_id AND s.account_id = n.account_id)
             FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             WHERE n.account_id = ?1 AND {STORED_MEMO}"
        ))?
        .query_map(params![owner.0, REFUND_MEMO_MAGIC], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, u32>(1)?, r.get(2)?))
        })?
        .collect::<Result<Vec<(Vec<u8>, u32, bool)>, _>>()?;
    let mut memos: Vec<(u32, u64, bool)> = records
        .into_iter()
        .filter_map(|(bytes, height, own_send)| {
            decode_memo(&bytes).map(|memo| (height, memo.index(), own_send))
        })
        .collect();
    if memos.is_empty() {
        return Ok(());
    }
    super::queue::mark_used(conn, owner.0)?;
    memos.sort_unstable();
    let highest: Option<Vec<u8>> = conn.query_row(
        "SELECT MAX(key_index) FROM ironwood_one_time_keys WHERE account_id = ?1 AND purpose = 0",
        [owner.0],
        |r| r.get(0),
    )?;
    let mut highest = highest.map(decode_index).transpose()?.unwrap_or(0);
    let mut accepted = conn.prepare_cached(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_keys WHERE account_id = ?1
         AND purpose = 0 AND key_index = ?2 AND funding_height <= ?3)",
    )?;
    loop {
        let mut deferred = vec![];
        for (height, index, own_send) in memos {
            if accepted.query_row(params![owner.0, index.to_be_bytes(), height], |r| r.get(0))? {
                continue;
            }
            if !own_send && index > highest.saturating_add(REFUND_MEMO_GAP) {
                deferred.push((height, index, own_send));
                continue;
            }
            let (id, _) = register(conn, params, account, KeyId::new(Purpose::Refund, index))?;
            super::queue::funded(conn, params, id, BlockHeight::from(height))?;
            highest = highest.max(index);
        }
        if deferred.is_empty()
            || deferred
                .iter()
                .all(|(_, i, _)| *i > highest.saturating_add(REFUND_MEMO_GAP))
        {
            return Ok(());
        }
        memos = deferred;
    }
}
