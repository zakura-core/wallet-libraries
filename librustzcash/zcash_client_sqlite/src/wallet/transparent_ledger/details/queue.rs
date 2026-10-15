//! Queuing detail work for transactions the wallet records without their raw bytes.

use rusqlite::{Connection, named_params};
use zcash_client_backend::data_api::transparent_ledger::TransparentDetailReasons;
use zcash_primitives::transaction::TxId;

use crate::{TxRef, error::SqliteClientError, wallet::chain_tip_height};

use super::super::session::SessionState;
use super::{sql::ROUTE_TWO, store::revalidate};

/// Queues work with `reasons` for the transactions `filter` selects from `transactions t`,
/// OR-ed into an existing row, while they are mined, have no raw bytes and no stored display
/// facts. A parent transaction (known only by txid, height unknown) is never queued.
///
/// Stored facts are first checked against what the wallet now holds: facts that were valid when
/// stored can contradict a receive or spend projected later (a withdrawn receive reported
/// again, say). Contradicted facts are deleted, so the transaction is looked up again.
///
/// Each transaction this call newly queues is recorded in `session` at the current chain tip,
/// so the listing holds it back until the tip changes: work a reply creates is asked at a later
/// tip, never in the sync that received the reply. Adding reasons to queued work records
/// nothing.
fn enqueue(
    conn: &Connection,
    session: &SessionState,
    filter: &str,
    params: &[(&str, &dyn rusqlite::ToSql)],
    reasons: TransparentDetailReasons,
) -> Result<(), SqliteClientError> {
    session.check_transaction(conn)?;
    revalidate(conn, filter, params)?;
    let tip = chain_tip_height(conn)?;
    let new = match tip {
        Some(_) => conn
            .prepare_cached(&format!(
                "SELECT t.txid FROM transactions t
                 WHERE {filter} AND t.raw IS NULL AND t.mined_height IS NOT NULL
                   AND NOT EXISTS (SELECT 1 FROM transparent_tx_display d
                                   WHERE d.transaction_id = t.id_tx)
                   AND NOT EXISTS (SELECT 1 FROM transparent_detail_work w
                                   WHERE w.transaction_id = t.id_tx)"
            ))?
            .query_map(params, |row| row.get(0).map(TxId::from_bytes))?
            .collect::<Result<Vec<_>, _>>()?,
        None => vec![],
    };
    let bits = reasons.bits();
    let mut all = params.to_vec();
    all.push((":reasons", &bits));
    conn.prepare_cached(&format!(
        "INSERT INTO transparent_detail_work (transaction_id, reasons)
         SELECT t.id_tx, :reasons FROM transactions t
         WHERE {filter} AND t.raw IS NULL AND t.mined_height IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM transparent_tx_display d
                           WHERE d.transaction_id = t.id_tx)
         ON CONFLICT (transaction_id) DO UPDATE SET reasons = reasons | excluded.reasons"
    ))?
    .execute(&all[..])?;
    if let Some(tip) = tip {
        session.queued(tip, new);
    }
    Ok(())
}

/// Queues work for `txid` with `reasons`; see [`enqueue`].
#[cfg_attr(
    not(any(feature = "transparent-inputs", feature = "orchard")),
    allow(dead_code)
)]
pub(crate) fn enqueue_txid(
    conn: &Connection,
    session: &SessionState,
    txid: &TxId,
    reasons: TransparentDetailReasons,
) -> Result<(), SqliteClientError> {
    enqueue(
        conn,
        session,
        "t.txid = :txid",
        named_params![":txid": txid.as_ref()],
        reasons,
    )
}

/// Like [`enqueue_txid`], by the wallet's transaction id.
#[cfg_attr(
    not(any(feature = "transparent-inputs", feature = "orchard")),
    allow(dead_code)
)]
pub(crate) fn enqueue_tx(
    conn: &Connection,
    session: &SessionState,
    tx_ref: TxRef,
    reasons: TransparentDetailReasons,
) -> Result<(), SqliteClientError> {
    enqueue(
        conn,
        session,
        "t.id_tx = :tx",
        named_params![":tx": tx_ref.0],
        reasons,
    )
}

/// Queues mixed-transaction work for every unresolved route-2 transaction; see [`enqueue`].
pub(crate) fn enqueue_route_two(
    conn: &Connection,
    session: &SessionState,
) -> Result<(), SqliteClientError> {
    enqueue(
        conn,
        session,
        ROUTE_TWO,
        &[],
        TransparentDetailReasons::MIXED,
    )
}

/// Queues mixed-transaction work for `txid` as it is mined, when it is a route-2 transaction.
///
/// A route-2 marker written while the transaction was unmined (rewound, or seen unmined) could
/// not queue it, since work requires a mined height.
pub(crate) fn enqueue_mined_route_two(
    conn: &Connection,
    session: &SessionState,
    txid: &TxId,
) -> Result<(), SqliteClientError> {
    enqueue(
        conn,
        session,
        &format!("t.txid = :txid AND {ROUTE_TWO}"),
        named_params![":txid": txid.as_ref()],
        TransparentDetailReasons::MIXED,
    )
}
