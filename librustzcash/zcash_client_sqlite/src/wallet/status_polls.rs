//! The private status poll window (`docs/pir-remaining-leaks-plan.md`, change A).
//!
//! When private status work is queued, the wallet fixes when it will ask: once at each of
//! [`WINDOW`] chain tips starting at the queue tip, and once more at the first tip at or past
//! the transaction's expiry height when that is past the window. A due poll is returned once per
//! tip, mined or not, whatever earlier replies said, so the status service sees the same queries
//! whether the transaction mined early, late, never, or the service lied about it. Only a request
//! outcome, which records nothing, leaves a poll due at the same tip.
//!
//! Work queued without a known tip, and rows inserted by older code, have no window yet. They
//! keep the eligibility rules of public work until their first recorded poll opens a window at
//! that poll's tip.

use std::collections::HashSet;

use rusqlite::{Connection, named_params};
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

use super::TxQueryType;
use crate::error::SqliteClientError;

/// The number of consecutive chain tips at which a queued transaction is polled.
pub(crate) const WINDOW: u32 = 10;

/// The tip as `chain_tip_height` computes it, or NULL without one.
const TIP: &str = "(SELECT MAX(MAX(block_range_end) - 1, 0) FROM scan_queue)";

/// The expiry poll height of transaction `t` for a window ending at `end`: its expiry height
/// when nonzero and past the window, otherwise NULL.
macro_rules! expiry_poll {
    ($end:literal) => {
        concat!(
            "CASE WHEN t.expiry_height > 0 AND t.expiry_height >= ",
            $end,
            " THEN t.expiry_height END"
        )
    };
}

/// Opens a window at the current tip for `txid`. A `fresh` window replaces any earlier one;
/// otherwise an existing window is kept. Without a known tip nothing is written.
pub(crate) fn open(conn: &Connection, txid: TxId, fresh: bool) -> Result<(), SqliteClientError> {
    let conflict = if fresh {
        "DO UPDATE SET window_start_height = excluded.window_start_height,
                       window_end_height = excluded.window_end_height,
                       expiry_poll_height = excluded.expiry_poll_height,
                       last_polled_height = NULL"
    } else {
        "DO NOTHING"
    };
    conn.execute(
        &format!(
            "INSERT INTO tx_status_polls
                 (txid, window_start_height, window_end_height, expiry_poll_height)
             SELECT :txid, tip.h, tip.h + :window, (
                 SELECT {expiry} FROM transactions t WHERE t.txid = :txid)
             FROM (SELECT {TIP} AS h) tip
             WHERE tip.h IS NOT NULL
             ON CONFLICT (txid) {conflict}",
            expiry = expiry_poll!("tip.h + :window"),
        ),
        named_params![":txid": txid.as_ref(), ":window": WINDOW],
    )?;
    Ok(())
}

/// Opens a fresh window at the current tip for every transaction matching `predicate`, an SQL
/// condition over transaction `t` with the caller's named parameters.
pub(crate) fn reopen_where(
    conn: &Connection,
    predicate: &str,
    params: &[(&str, &dyn rusqlite::ToSql)],
) -> Result<(), SqliteClientError> {
    let window = WINDOW;
    let mut all = params.to_vec();
    all.push((":window", &window));
    conn.execute(
        &format!(
            "INSERT INTO tx_status_polls
                 (txid, window_start_height, window_end_height, expiry_poll_height)
             SELECT t.txid, tip.h, tip.h + :window, {expiry}
             FROM transactions t, (SELECT {TIP} AS h) tip
             WHERE tip.h IS NOT NULL AND ({predicate})
             ON CONFLICT (txid) DO UPDATE SET
                 window_start_height = excluded.window_start_height,
                 window_end_height = excluded.window_end_height,
                 expiry_poll_height = excluded.expiry_poll_height,
                 last_polled_height = NULL",
            expiry = expiry_poll!("tip.h + :window"),
        ),
        all.as_slice(),
    )?;
    Ok(())
}

/// Records that a private reply for `txid` came back at `tip`. Status work without a window
/// opens one at `tip`; a txid without status work is ignored.
pub(crate) fn record_poll(
    conn: &Connection,
    txid: TxId,
    tip: BlockHeight,
) -> Result<(), SqliteClientError> {
    let updated = conn.execute(
        "UPDATE tx_status_polls
         SET last_polled_height = MAX(IFNULL(last_polled_height, 0), :tip)
         WHERE txid = :txid",
        named_params![":txid": txid.as_ref(), ":tip": u32::from(tip)],
    )?;
    if updated == 0 {
        conn.execute(
            &format!(
                "INSERT INTO tx_status_polls (txid, window_start_height, window_end_height,
                                              expiry_poll_height, last_polled_height)
                 SELECT q.txid, :tip, :tip + :window, {expiry}, :tip
                 FROM tx_retrieval_queue q
                 LEFT JOIN transactions t ON t.txid = q.txid
                 WHERE q.txid = :txid AND q.query_type = :status_type",
                expiry = expiry_poll!(":tip + :window"),
            ),
            named_params![
                ":txid": txid.as_ref(),
                ":tip": u32::from(tip),
                ":window": WINDOW,
                ":status_type": TxQueryType::Status.code(),
            ],
        )?;
    }
    Ok(())
}

/// A poll due at `tip`.
pub(crate) struct DuePoll {
    pub(crate) txid: TxId,
    pub(crate) earliest: Option<BlockHeight>,
}

/// The windowed polls due at `tip`, in txid order, for transactions the wallet still knows.
pub(crate) fn due(conn: &Connection, tip: BlockHeight) -> Result<Vec<DuePoll>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT p.txid,
                CASE WHEN t.target_height IS NOT NULL
                     THEN MIN(t.target_height, t.min_observed_height) END
         FROM tx_status_polls p
         LEFT JOIN transactions t ON t.txid = p.txid
         WHERE (t.id_tx IS NOT NULL OR EXISTS (
                   SELECT 1 FROM tx_retrieval_queue q
                   WHERE q.txid = p.txid AND q.query_type = :status_type))
           AND (p.last_polled_height IS NULL OR p.last_polled_height < :tip)
           AND ((:tip >= p.window_start_height AND :tip < p.window_end_height)
                OR (:tip >= p.expiry_poll_height
                    AND (p.last_polled_height IS NULL
                         OR p.last_polled_height < p.expiry_poll_height)))
         ORDER BY p.txid",
    )?;
    stmt.query_and_then(
        named_params![
            ":tip": u32::from(tip),
            ":status_type": TxQueryType::Status.code(),
        ],
        |row| -> Result<_, rusqlite::Error> {
            Ok(DuePoll {
                txid: TxId::from_bytes(row.get(0)?),
                earliest: row.get::<_, Option<u32>>(1)?.map(BlockHeight::from),
            })
        },
    )?
    .collect::<Result<_, _>>()
    .map_err(Into::into)
}

/// Every txid with a window. Their private work follows the window alone.
pub(crate) fn windowed(conn: &Connection) -> Result<HashSet<TxId>, SqliteClientError> {
    let mut stmt = conn.prepare_cached("SELECT txid FROM tx_status_polls")?;
    stmt.query_and_then([], |row| row.get(0).map(TxId::from_bytes))?
        .collect::<Result<_, rusqlite::Error>>()
        .map_err(Into::into)
}
