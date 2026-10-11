//! Recovery from authenticated wallet data, independent of the discovery transport.
use rusqlite::{Connection, OptionalExtension, params};
use zakura_dynamic_ivk::{REFUND_MEMO_MAGIC, RefundMemo};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use zcash_client_backend::data_api::transparent_ledger::ChainPoint;

use super::{
    Discovery, DynamicKey, KeyId, Purpose, RESTORED, account_key, decode_index, key_ref,
    next_index, planner::canonical, register, reservations::RECEIVE_LOOKAHEAD, restore_start,
    retention::retain_spend_history,
};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// See `WalletDb::recheck_dynamic_key_history`.
pub(super) fn recheck<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<usize, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    requeue(conn, "account_id = ?1 AND closed_at IS NOT NULL", owner.0)
}

/// Queues a new sweep of each key `predicate` selects in `ironwood_receiving_keys`, with
/// `?1` bound to `binding`, unless its sweep is pending. Returns how many were queued.
fn requeue(
    conn: &rusqlite::Transaction<'_>,
    predicate: &str,
    binding: i64,
) -> Result<usize, SqliteClientError> {
    Ok(conn.execute(
        &format!(
            "INSERT INTO ironwood_dynamic_sweeps (receiving_key_id)
             SELECT id FROM ironwood_receiving_keys WHERE {predicate}
             ON CONFLICT (receiving_key_id) DO UPDATE SET
                 lookup_height = NULL, lookup_hash = NULL, attempts = 0,
                 next_attempt_at = 0, done_height = NULL
             WHERE done_height IS NOT NULL"
        ),
        [binding],
    )?)
}

/// Implements `DynamicIvkWrite::record_paid_filter_check`.
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
            // A rewind below `publication` reruns the sweep (see `truncate_to_height`).
            conn.execute(
                "UPDATE ironwood_dynamic_sweeps SET done_height = ?2
                 WHERE receiving_key_id = ?1 AND done_height < ?2",
                params![id, u32::from(publication.height)],
            )?;
        }
    }
    Ok(())
}

/// Implements `DynamicIvkWrite::maintain_dynamic_ivks`, keeping
/// [`RECEIVE_GAP_LIMIT`](super::RECEIVE_GAP_LIMIT) incoming lookahead keys.
pub(crate) fn maintain<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<(), SqliteClientError> {
    retain_spend_history(conn, params, account)?;
    maintain_restore_discovery(conn, params, account, RECEIVE_LOOKAHEAD, now)?;
    Ok(())
}

/// Whether an internal funding record may still hold an unregistered refund index after
/// [`recover_refund_memos`]: its memo is not retrieved yet, or it lacks own-send evidence
/// while scanning has not reached its block. Refund issuance and nullifier release wait.
pub(super) fn refund_memos_pending(
    conn: &Connection,
    account: AccountUuid,
) -> Result<bool, SqliteClientError> {
    let scanned = wallet::fully_scanned_height(conn)?.map(u32::from);
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes n
         JOIN transactions t ON t.id_tx = n.transaction_id
         JOIN accounts a ON a.id = n.account_id
         WHERE a.uuid = ?1 AND n.recipient_key_scope = 1
           AND n.receiving_key_id IS NULL AND t.mined_height IS NOT NULL
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
/// same account) authenticates it, unless a key already covers its block. Returns how
/// many selected records this version cannot read, with or without that evidence, as
/// `RefundMemo::decode` requires.
///
/// A marker still lacking that evidence once scanning passed its block was funded before
/// the birthday or is not this wallet's: its key is swept without advancing allocation,
/// so a forged record cannot exhaust the index space.
pub(super) fn recover_refund_memos<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<usize, SqliteClientError> {
    let (account_ref, _) = account_key(conn, params, account)?;
    let scanned = wallet::fully_scanned_height(conn)?.map(u32::from);
    let records = conn
        .prepare_cached(
            "SELECT n.memo, t.mined_height, EXISTS (SELECT 1 FROM v_received_output_spends s
                 WHERE s.transaction_id = n.transaction_id AND s.account_id = n.account_id)
             FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             WHERE n.account_id = ?1 AND n.recipient_key_scope = 1
               AND n.receiving_key_id IS NULL AND t.mined_height IS NOT NULL
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
    let mut unreadable = 0;
    for (bytes, height, authenticated) in records {
        // SQLite omits trailing zero padding when storing MemoBytes.
        let memo = zcash_protocol::memo::MemoBytes::from_bytes(&bytes)
            .ok()
            .and_then(|bytes| RefundMemo::decode(bytes.as_array()));
        let register_as = match memo {
            None => {
                unreadable += 1;
                continue;
            }
            Some(memo) if authenticated => (memo, true),
            Some(memo) if scanned.is_some_and(|scanned| height <= scanned) => (memo, false),
            _ => continue,
        };
        let (memo, authenticated) = register_as;
        let key_id = KeyId::new(Purpose::Refund, memo.index());
        // Storing the funding transaction already started a key scanned here (see
        // `start_funded_refund_keys`), and an earlier call queued any other.
        let covered: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_receiving_keys k
             WHERE k.account_id = ?1 AND k.purpose = 0 AND k.key_index = ?2
               AND k.scan_from <= ?3 AND (k.active_from <= ?3 OR EXISTS(
                 SELECT 1 FROM ironwood_dynamic_sweeps s WHERE s.receiving_key_id = k.id)))",
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
    Ok(unreadable)
}

/// [`maintain`] with `lookahead` incoming keys, once scanning reaches an Ironwood tip.
/// Returns the unreadable count from [`recover_refund_memos`], zero before then.
pub(super) fn maintain_restore_discovery<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    lookahead: u32,
    now: i64,
) -> Result<usize, SqliteClientError> {
    let tip = wallet::chain_tip_height(conn)?;
    let ready = match (tip, params.activation_height(NetworkUpgrade::Nu6_3)) {
        (Some(tip), Some(activation)) => {
            tip >= activation && wallet::fully_scanned_height(conn)? == Some(tip)
        }
        _ => false,
    };
    if !ready {
        return Ok(0);
    }
    let unreadable = recover_refund_memos(conn, params, account, now)?;
    let (account_ref, _) = account_key(conn, params, account)?;
    let start = restore_start(conn, params, account_ref)?;
    maintain_receive_lookahead(conn, params, account, lookahead, start, now)?;
    Ok(unreadable)
}

/// Keeps [`RECEIVE_LOOKAHEAD`] incoming keys from the account's restore start.
pub(super) fn extend_receive_lookahead<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<(), SqliteClientError> {
    let (account_ref, _) = account_key(conn, params, account)?;
    let start = restore_start(conn, params, account_ref)?;
    maintain_receive_lookahead(conn, params, account, RECEIVE_LOOKAHEAD, start, now)
}

/// Keeps `count` swept incoming keys above the highest allocated index. In a new account
/// it stops above a key this wallet issued, since nothing above it was handed out; in an
/// account restored with `recover_until`, the old device may have quoted beyond the keys
/// this wallet issues, so it always keeps going. This is bounded-gap recovery, not a
/// completeness proof.
pub(super) fn maintain_receive_lookahead<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    count: u32,
    scan_from: BlockHeight,
    now: i64,
) -> Result<(), SqliteClientError> {
    let (account_ref, _) = account_key(conn, params, account)?;
    let top: Option<(Vec<u8>, bool)> = conn
        .query_row(
            &format!(
                "SELECT k.key_index, ({RESTORED}) OR a.recover_until_height IS NOT NULL
                 FROM ironwood_receiving_keys k JOIN accounts a ON a.id = k.account_id
                 WHERE k.account_id = ?1 AND k.purpose = 1 AND k.advances_allocation = 1
                 ORDER BY k.key_index DESC LIMIT 1"
            ),
            [account_ref.0],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let start = match top {
        Some((_, false)) => return Ok(()),
        Some((index, true)) => next_index(decode_index(index)?)?,
        None => 0,
    };
    for offset in 0..u64::from(count) {
        let index = start
            .checked_add(offset)
            .ok_or(SqliteClientError::DynamicIvkIndexExhausted)?;
        let exists: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM ironwood_receiving_keys
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
pub(super) fn watch_receive_key<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    index: u64,
    scan_from: BlockHeight,
    now: i64,
) -> Result<DynamicKey, SqliteClientError> {
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
