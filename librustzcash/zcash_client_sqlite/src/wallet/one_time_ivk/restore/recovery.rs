//! Recovery from authenticated wallet data, independent of the discovery transport.
use rusqlite::{Connection, OptionalExtension, params};
use zakura_one_time_ivk::swap::{REFUND_MEMO_MAGIC, RefundMemo};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use zcash_client_backend::data_api::transparent_ledger::ChainPoint;

use super::{planner::canonical, retention::retain_spend_history};
use crate::wallet::one_time_ivk::{
    Discovery, KeyId, OneTimeKey, Purpose, RESTORED, account_key, decode_index, index_after,
    invalid, key_ref, register, restore_start, swap::RECEIVE_GAP_LIMIT,
};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// See `WalletDb::recheck_one_time_key_history`.
pub(in crate::wallet::one_time_ivk) fn recheck<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<usize, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    requeue(conn, "account_id = ?1 AND closed_at IS NOT NULL", owner.0)
}

/// Queues a new sweep of each key `predicate` selects in `ironwood_one_time_keys`, with
/// `?1` bound to `binding`, unless its sweep is pending. Returns how many were queued.
fn requeue(
    conn: &rusqlite::Transaction<'_>,
    predicate: &str,
    binding: i64,
) -> Result<usize, SqliteClientError> {
    Ok(conn.execute(
        &format!(
            "INSERT INTO ironwood_one_time_sweeps (one_time_key_id)
             SELECT id FROM ironwood_one_time_keys WHERE {predicate}
             ON CONFLICT (one_time_key_id) DO UPDATE SET
                 lookup_height = NULL, lookup_hash = NULL, attempts = 0,
                 next_attempt_at = 0, done_height = NULL
             WHERE done_height IS NOT NULL"
        ),
        [binding],
    )?)
}

/// See `WalletDb::mark_one_time_account_fresh`.
pub(in crate::wallet::one_time_ivk) fn mark_fresh<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let (fresh, keyed): (bool, bool) = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_fresh_accounts WHERE account_id = ?1),
            EXISTS(SELECT 1 FROM ironwood_one_time_keys WHERE account_id = ?1)",
        [owner.0],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if !fresh && keyed {
        return Err(invalid("account already has one-time keys"));
    }
    conn.execute(
        "INSERT OR IGNORE INTO ironwood_one_time_fresh_accounts (account_id) VALUES (?1)",
        [owner.0],
    )?;
    Ok(())
}

/// Implements `OneTimeIvkRestoreWrite::record_paid_filter_check`.
pub(crate) fn record_paid_check(
    conn: &rusqlite::Transaction<'_>,
    account: AccountUuid,
    publication: ChainPoint,
    checked: &[(KeyId, bool)],
) -> Result<(), SqliteClientError> {
    if canonical(conn, Some(publication))?.is_none() {
        return Ok(());
    }
    for &(key, paid) in checked {
        let id = key_ref(conn, account, key)?;
        if paid {
            requeue(conn, "id = ?1", id)?;
        } else {
            // A key scanned here gets a finished sweep row, so it is listed again only for
            // a newer publication. A rewind below `publication` reruns the sweep (see
            // `truncate_to_height`).
            conn.execute(
                "INSERT INTO ironwood_one_time_sweeps (one_time_key_id, done_height)
                 VALUES (?1, ?2)
                 ON CONFLICT (one_time_key_id) DO UPDATE SET done_height = excluded.done_height
                 WHERE done_height < excluded.done_height",
                params![id, u32::from(publication.height)],
            )?;
        }
    }
    Ok(())
}

/// Implements `OneTimeIvkRestoreWrite::maintain_one_time_ivks`.
pub(crate) fn maintain<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<(), SqliteClientError> {
    retain_spend_history(conn, params, account)?;
    maintain_restore_discovery(conn, params, account, now)
}

/// Whether an internal funding record may still hold an unregistered refund index after
/// [`recover_refund_memos`]: its memo is not retrieved yet, or it lacks own-send evidence
/// while scanning has not reached its block. Refund issuance and nullifier release wait.
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

/// Registers, for a restore sweep, the refund key of each confirmed internal funding
/// memo, spent and zero-value ones included, whose own-send evidence (an input of the
/// same account) authenticates it, unless a key already covers its block. A marked memo
/// that does not decode is ignored.
///
/// A marker still lacking that evidence once scanning passed its block was funded before
/// the birthday or is not this wallet's: its key is swept without advancing allocation,
/// so a forged record cannot exhaust the index space.
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
        let covered: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_keys k
             WHERE k.account_id = ?1 AND k.purpose = 0 AND k.key_index = ?2
               AND k.scan_from <= ?3 AND (k.active_from <= ?3 OR EXISTS(
                 SELECT 1 FROM ironwood_one_time_sweeps s WHERE s.one_time_key_id = k.id)))",
            params![account_ref.0, key_id.index().to_be_bytes(), height],
            |row| row.get(0),
        )?;
        if !covered {
            let from = BlockHeight::from(height);
            register(
                conn,
                params,
                account,
                key_id,
                from,
                authenticated,
                Discovery::Sweep,
                now,
            )?;
        }
    }
    Ok(())
}

/// Recovers funding memos and keeps the incoming lookahead, once scanning reaches an
/// Ironwood tip.
pub(in crate::wallet::one_time_ivk) fn maintain_restore_discovery<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<(), SqliteClientError> {
    let tip = wallet::chain_tip_height(conn)?;
    let ready = match (tip, params.activation_height(NetworkUpgrade::Nu6_3)) {
        (Some(tip), Some(activation)) => {
            tip >= activation && wallet::fully_scanned_height(conn)? == Some(tip)
        }
        _ => false,
    };
    if !ready {
        return Ok(());
    }
    recover_refund_memos(conn, params, account, now)?;
    maintain_receive_lookahead(conn, params, account, now)
}

/// Keeps [`RECEIVE_GAP_LIMIT`] incoming keys, swept from the account's restore start,
/// above the highest allocated index, while that index is a restored one or there is
/// none: above a key this wallet issued, it handed nothing out. This is bounded-gap
/// recovery, not a completeness proof. A fresh account has nothing to recover (see
/// `WalletDb::mark_one_time_account_fresh`).
pub(in crate::wallet::one_time_ivk) fn maintain_receive_lookahead<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<(), SqliteClientError> {
    let (account_ref, _) = account_key(conn, params, account)?;
    let fresh: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_fresh_accounts WHERE account_id = ?1)",
        [account_ref.0],
        |r| r.get(0),
    )?;
    if fresh {
        return Ok(());
    }
    let scan_from = restore_start(conn, params, account_ref)?;
    let top: Option<(Vec<u8>, bool)> = conn
        .query_row(
            &format!(
                "SELECT k.key_index, ({RESTORED}) FROM ironwood_one_time_keys k
                 WHERE k.account_id = ?1 AND k.purpose = 1 AND k.advances_allocation = 1
                 ORDER BY k.key_index DESC LIMIT 1"
            ),
            [account_ref.0],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let start = match top {
        Some((_, false)) => return Ok(()),
        Some((index, true)) => index_after(decode_index(index)?, 1)?,
        None => 0,
    };
    for offset in 0..RECEIVE_GAP_LIMIT {
        let index = index_after(start, offset)?;
        let exists: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM ironwood_one_time_keys
             WHERE account_id = ?1 AND purpose = 1 AND key_index = ?2 AND scan_from <= ?3)",
            params![account_ref.0, index.to_be_bytes(), u32::from(scan_from)],
            |row| row.get(0),
        )?;
        if !exists {
            watch_receive_key(conn, params, account, index, scan_from, now)?;
        }
    }
    Ok(())
}

/// Registers incoming key `index` for a sweep, without advancing allocation.
pub(in crate::wallet::one_time_ivk) fn watch_receive_key<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    index: u64,
    scan_from: BlockHeight,
    now: i64,
) -> Result<OneTimeKey, SqliteClientError> {
    let key_id = KeyId::new(Purpose::Receive, index);
    register(
        conn,
        params,
        account,
        key_id,
        scan_from,
        false,
        Discovery::Sweep,
        now,
    )
    .map(|(_, key)| key)
}
