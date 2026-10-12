//! Restore sweep scheduling, which never derives viewing keys.
use rusqlite::{Connection, params};
use zcash_client_backend::data_api::{
    one_time_ivk::restore::{DiscoveryWork, SweepDeferral},
    transparent_ledger::ChainPoint,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::{PendingPayment, payments::queue_payment};
use crate::wallet::one_time_ivk::{
    KeyId, account_key, corrupt, invalid, key_ref, stored_key_id,
    swap::reservations::record_provider_seen,
};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// Returns `anchor` only while its block is still on the wallet's chain.
pub(in crate::wallet::one_time_ivk) fn canonical(
    conn: &Connection,
    anchor: Option<ChainPoint>,
) -> Result<Option<ChainPoint>, SqliteClientError> {
    Ok(match anchor {
        Some(a) if wallet::get_block_hash(conn, a.height)? == Some(a.hash) => Some(a),
        _ => None,
    })
}

/// Builds an anchor from a stored height and hash pair.
pub(in crate::wallet::one_time_ivk) fn anchor(
    height: Option<u32>,
    hash: Option<[u8; 32]>,
) -> Option<ChainPoint> {
    height.zip(hash).map(|(height, hash)| ChainPoint {
        height: BlockHeight::from(height),
        hash: BlockHash(hash),
    })
}

/// Implements `OneTimeIvkRestoreRead::one_time_history_pending`.
pub(crate) fn history_pending<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    through: BlockHeight,
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_sweeps s
            JOIN ironwood_receiving_keys k ON k.id = s.receiving_key_id
            WHERE k.account_id = ?1 AND k.scan_from <= ?2 AND s.done_height IS NULL)
         OR EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
            JOIN ironwood_receiving_keys k ON k.id = p.receiving_key_id
            WHERE k.account_id = ?1)",
        params![owner.0, u32::from(through)],
        |r| r.get(0),
    )?)
}

/// Implements `OneTimeIvkRestoreWrite::prepare_one_time_sweeps`. Selects nothing unless
/// `through` is both the stored chain tip and the fully scanned height: below either, an
/// attempt's network lookups could end only in `PaymentApplication::AwaitingScan` for any
/// payment they find, as `apply::apply_payment` checks again.
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
    if wallet::fully_scanned_height(conn)? != Some(through.height)
        || wallet::chain_tip_height(conn)? != Some(through.height)
    {
        return Ok(Ok(vec![]));
    }
    // A finished sweep is offered again while a late lookup left candidates queued.
    let mut stmt = conn.prepare(
        "SELECT k.purpose, k.key_index, k.receiver
         FROM ironwood_one_time_sweeps s
         JOIN ironwood_receiving_keys k ON k.id = s.receiving_key_id
         WHERE k.account_id = ?1 AND k.scan_from <= ?2 AND s.next_attempt_at <= ?3
           AND (s.done_height IS NULL OR EXISTS(
               SELECT 1 FROM ironwood_one_time_payment_recovery p
               WHERE p.receiving_key_id = s.receiving_key_id))
         ORDER BY s.next_attempt_at, s.receiving_key_id LIMIT ?4",
    )?;
    let rows = stmt.query(params![
        owner.0,
        u32::from(through.height),
        now,
        limit.get()
    ])?;
    discovery_work(rows).map(Ok)
}

/// Implements `OneTimeIvkRestoreRead::one_time_keys_to_recheck`: closed keys without a mined
/// payment whose sweep row, if any, is finished below `height`. A key scanned here has
/// none until its first paid filter check (see `recovery::record_paid_check`). `used`
/// is not payment evidence: it also marks a receipt that expired unmined.
pub(crate) fn keys_to_recheck<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    height: BlockHeight,
) -> Result<Vec<DiscoveryWork>, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let mut stmt = conn.prepare(
        "SELECT k.purpose, k.key_index, k.receiver
         FROM ironwood_receiving_keys k
         LEFT JOIN ironwood_one_time_sweeps s ON s.receiving_key_id = k.id
         WHERE k.account_id = ?1 AND k.closed_at IS NOT NULL AND k.paid_before_birthday = 0
           AND NOT EXISTS(SELECT 1 FROM ironwood_received_notes n
               JOIN transactions t ON t.id_tx = n.transaction_id
               WHERE n.receiving_key_id = k.id AND t.mined_height IS NOT NULL)
           AND (s.receiving_key_id IS NULL OR s.done_height < ?2)
         ORDER BY k.id",
    )?;
    discovery_work(stmt.query(params![owner.0, u32::from(height)])?)
}

/// Decodes `rows` of key purpose, index and receiver.
fn discovery_work(mut rows: rusqlite::Rows<'_>) -> Result<Vec<DiscoveryWork>, SqliteClientError> {
    let mut work = Vec::new();
    while let Some(r) = rows.next()? {
        work.push(DiscoveryWork {
            key: stored_key_id(r)?,
            receiver: r
                .get::<_, Vec<u8>>(2)?
                .try_into()
                .map_err(|_| corrupt("invalid stored receiver"))?,
        });
    }
    Ok(work)
}

/// Implements `OneTimeIvkRestoreWrite::begin_one_time_sweep_attempt`, backing off from one
/// minute to twelve hours.
pub(crate) fn begin_sweep_attempt(
    conn: &Connection,
    account: AccountUuid,
    key: KeyId,
    now: i64,
    seen: bool,
) -> Result<(), SqliteClientError> {
    let id = key_ref(conn, account, key)?;
    if seen {
        record_provider_seen(conn, id)?;
    }
    let attempt: u32 = conn.query_row(
        "SELECT attempts FROM ironwood_one_time_sweeps WHERE receiving_key_id = ?1",
        [id],
        |r| r.get(0),
    )?;
    let delay = (60i64 << attempt.min(10)).min(43200);
    conn.execute(
        "UPDATE ironwood_one_time_sweeps
         SET attempts = MIN(attempts + 1, 30), next_attempt_at = ?2
         WHERE receiving_key_id = ?1",
        params![id, now.saturating_add(delay)],
    )?;
    Ok(())
}

/// Queues authenticated candidates from a complete lookup of `key` at `anchor`, the
/// answer that replaced the key's queued set, records its coverage, which the caller
/// validated, and reopens the sweep until they are applied.
pub(in crate::wallet::one_time_ivk) fn queue_lookup<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    anchor: ChainPoint,
    payments: &[PendingPayment],
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
    conn.execute(
        "UPDATE ironwood_one_time_sweeps
         SET lookup_height = ?2, lookup_hash = ?3, done_height = NULL
         WHERE receiving_key_id = ?1",
        params![
            key_ref(conn, account, key)?,
            u32::from(anchor.height),
            anchor.hash.0
        ],
    )?;
    Ok(Ok(()))
}
