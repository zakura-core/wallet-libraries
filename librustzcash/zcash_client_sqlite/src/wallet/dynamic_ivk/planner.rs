//! Restore sweep scheduling, which never derives viewing keys.
use rusqlite::{Connection, params};
use zcash_client_backend::data_api::{
    dynamic_ivk::{DiscoveryWork, SweepDeferral},
    transparent_ledger::ChainPoint,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::{
    KeyId, PendingPayment, account_key, corrupt, invalid, key_ref, payments::queue_payment,
    stored_key_id,
};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// Returns `anchor` only while its block is still on the wallet's chain.
pub(super) fn canonical(
    conn: &Connection,
    anchor: Option<ChainPoint>,
) -> Result<Option<ChainPoint>, SqliteClientError> {
    Ok(match anchor {
        Some(a) if wallet::get_block_hash(conn, a.height)? == Some(a.hash) => Some(a),
        _ => None,
    })
}

/// Builds an anchor from a stored height and hash pair.
pub(super) fn anchor(height: Option<u32>, hash: Option<[u8; 32]>) -> Option<ChainPoint> {
    height.zip(hash).map(|(height, hash)| ChainPoint {
        height: BlockHeight::from(height),
        hash: BlockHash(hash),
    })
}

/// Implements `DynamicIvkRead::dynamic_history_pending`.
pub(crate) fn history_pending<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    through: BlockHeight,
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_dynamic_sweeps s
            JOIN ironwood_receiving_keys k ON k.id = s.receiving_key_id
            WHERE k.account_id = ?1 AND k.scan_from <= ?2 AND s.done_height IS NULL)
         OR EXISTS(SELECT 1 FROM ironwood_dynamic_payment_recovery p
            JOIN ironwood_receiving_keys k ON k.id = p.receiving_key_id
            WHERE k.account_id = ?1)",
        params![owner.0, u32::from(through)],
        |r| r.get(0),
    )?)
}

/// Implements `DynamicIvkWrite::prepare_dynamic_sweeps`.
pub(crate) fn prepare_sweeps<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    through: ChainPoint,
    now: i64,
    limit: std::num::NonZeroU32,
) -> Result<Result<Vec<DiscoveryWork>, SweepDeferral>, SqliteClientError> {
    if now < 0 {
        return Err(invalid("invalid sweep time"));
    }
    let (owner, _) = account_key(conn, params, account)?;
    if canonical(conn, Some(through))?.is_none() {
        return Ok(Err(SweepDeferral::UnknownAnchor));
    }
    // A finished sweep is offered again while a late lookup left candidates queued.
    let mut stmt = conn.prepare(
        "SELECT k.purpose, k.key_index, k.receiver, s.lookup_height, s.lookup_hash
         FROM ironwood_dynamic_sweeps s
         JOIN ironwood_receiving_keys k ON k.id = s.receiving_key_id
         WHERE k.account_id = ?1 AND k.scan_from <= ?2 AND s.next_attempt_at <= ?3
           AND (s.done_height IS NULL OR EXISTS(
               SELECT 1 FROM ironwood_dynamic_payment_recovery p
               WHERE p.receiving_key_id = s.receiving_key_id))
         ORDER BY s.next_attempt_at, s.receiving_key_id LIMIT ?4",
    )?;
    let mut rows = stmt.query(params![
        owner.0,
        u32::from(through.height),
        now,
        limit.get()
    ])?;
    let mut work = Vec::new();
    while let Some(r) = rows.next()? {
        work.push(DiscoveryWork {
            key: stored_key_id(r)?,
            receiver: r
                .get::<_, Vec<u8>>(2)?
                .try_into()
                .map_err(|_| corrupt("invalid stored receiver"))?,
            lookup: canonical(conn, anchor(r.get(3)?, r.get(4)?))?,
        });
    }
    Ok(Ok(work))
}

/// Implements `DynamicIvkWrite::begin_dynamic_sweep_attempt`, backing off from one
/// minute to twelve hours.
pub(crate) fn begin_sweep_attempt(
    conn: &Connection,
    account: AccountUuid,
    key: KeyId,
    now: i64,
) -> Result<(), SqliteClientError> {
    let id = key_ref(conn, account, key)?;
    let attempt: u32 = conn.query_row(
        "SELECT attempts FROM ironwood_dynamic_sweeps WHERE receiving_key_id = ?1",
        [id],
        |r| r.get(0),
    )?;
    let delay = (60i64 << attempt.min(10)).min(43200);
    conn.execute(
        "UPDATE ironwood_dynamic_sweeps
         SET attempts = MIN(attempts + 1, 30), next_attempt_at = ?2
         WHERE receiving_key_id = ?1",
        params![id, now.saturating_add(delay)],
    )?;
    Ok(())
}

/// Queues authenticated candidates from a lookup of `key` at `anchor` and, if
/// `complete`, records its coverage, which the caller validated.
pub(super) fn queue_lookup<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    anchor: ChainPoint,
    payments: &[PendingPayment],
    complete: bool,
) -> Result<Result<(), SweepDeferral>, SqliteClientError> {
    if canonical(conn, Some(anchor))?.is_none() {
        return Ok(Err(SweepDeferral::UnknownAnchor));
    }
    for payment in payments {
        if payment.height > anchor.height {
            return Err(invalid("directory payment exceeds lookup coverage"));
        }
        queue_payment(conn, params, account, key, payment)?;
    }
    if complete {
        conn.execute(
            "UPDATE ironwood_dynamic_sweeps SET lookup_height = ?2, lookup_hash = ?3
             WHERE receiving_key_id = ?1 AND (lookup_height IS NULL OR lookup_height <= ?2)",
            params![
                key_ref(conn, account, key)?,
                u32::from(anchor.height),
                anchor.hash.0
            ],
        )?;
    }
    Ok(Ok(()))
}
