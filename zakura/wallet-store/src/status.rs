//! Outstanding questions about transactions, and what their answers mean.
//!
//! Two kinds of question share one table because they share one RPC, and they
//! are kept apart because they have different lifetimes. An enhancement request
//! asks for a transaction's bytes, is answered once, and is then deleted. A
//! status request asks whether a transaction is mined, and is durable: it lies
//! dormant while the answer is yes, and reactivates by itself if a rewind
//! un-mines the transaction.
//!
//! The delicate part is deciding when a transaction is *dead*, because that is
//! what releases the notes it spent. Expiry is proved, never inferred: the
//! chain tip passing a transaction's expiry height means nothing on its own,
//! since the wallet may simply never have asked. Only a server's positive
//! assertion that it does not have the transaction, recorded as
//! `confirmed_unmined_at_height`, counts. Inferring instead of proving here is
//! a double spend.

use rusqlite::named_params;
use zcash_protocol::{TxId, consensus::BlockHeight};

pub use zakura_wallet_core::enhanced::TransactionStatus;

use crate::{error::Error, schema::CACHE_SCHEMA};

/// What is being asked about a transaction.
///
/// The codes match the fork's `TxQueryType` so the two schemas read the same
/// way. Note that the fork's *schema comment* has them the other way round; its
/// Rust, which is what runs, agrees with this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxQuery {
    /// Whether the transaction is mined.
    Status = 0,
    /// The transaction's full bytes, for memo and outgoing recovery.
    Enhancement = 1,
}

impl TxQuery {
    /// The stored code.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Reads a stored code.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Status),
            1 => Some(Self::Enhancement),
            _ => None,
        }
    }
}

/// How far past its last sighting a transaction of unknown expiry is pursued.
///
/// A transaction that never declared an expiry height cannot be proved dead by
/// the ordinary rule, so it is given the deepest reorg the wallet will consider
/// plus the protocol's default expiry window, after which it is treated as
/// gone. Both halves matter: the first says the transaction cannot come back,
/// the second says it cannot still be pending.
pub const CERTAINTY_DEPTH: u32 = PRUNING_DEPTH + EXPIRY_DELTA;

/// The deepest rewind the wallet will consider.
pub const PRUNING_DEPTH: u32 = 100;

/// The protocol's default expiry window, in blocks.
pub const EXPIRY_DELTA: u32 = 40;

/// The condition under which a transaction is not yet provably dead.
///
/// Written once and interpolated everywhere it is needed — the request drain,
/// the status transitions, balance, history and note selection — because five
/// copies of a predicate this subtle is how the five come to disagree, and a
/// disagreement between "spendable" and "expired" is money.
///
/// Expects the `transactions` row to be in scope as `t`.
pub const UNEXPIRED: &str = "(
    t.confirmed_unmined_at_height IS NULL
    OR t.expiry_height = 0
    OR t.confirmed_unmined_at_height < t.expiry_height
    OR (t.expiry_height IS NULL
        AND t.confirmed_unmined_at_height < COALESCE(t.min_observed_height, 0) + 140)
)";

/// Records an outstanding question, if it is not already recorded.
///
/// Never converts one kind of question into the other: an enhancement intent
/// and a status intent for the same transaction are separate rows, and
/// answering one must not silently discard the other.
pub(crate) fn queue_request(
    conn: &rusqlite::Connection,
    txid: TxId,
    query: TxQuery,
    dependent: Option<i64>,
) -> Result<(), Error> {
    conn.execute(
        &format!(
            "INSERT INTO {CACHE_SCHEMA}.tx_requests
                (txid, query_type, dependent_transaction_id)
             VALUES (:txid, :query, :dependent)
             ON CONFLICT (txid, query_type) DO UPDATE SET
                dependent_transaction_id =
                    IFNULL(dependent_transaction_id, :dependent)"
        ),
        named_params![
            ":txid": txid.as_ref(),
            ":query": query.code(),
            ":dependent": dependent,
        ],
    )
    .map_err(Error::Query)?;
    Ok(())
}

/// Removes one kind of outstanding question about a transaction.
pub(crate) fn delete_request(
    conn: &rusqlite::Connection,
    txid: TxId,
    query: TxQuery,
) -> Result<(), Error> {
    conn.execute(
        &format!(
            "DELETE FROM {CACHE_SCHEMA}.tx_requests
             WHERE txid = :txid AND query_type = :query"
        ),
        named_params![":txid": txid.as_ref(), ":query": query.code()],
    )
    .map_err(Error::Query)?;
    Ok(())
}

/// Which outstanding questions a drain should return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestScope {
    /// Only transactions this installation created.
    ///
    /// `target_height` is set by the send path and by nothing else, so it marks
    /// exactly the transactions somebody is waiting on. These are asked about
    /// first, because a person watching a payment should not wait behind a
    /// historic recovery draining.
    PendingSends,
    /// Everything outstanding.
    All,
}

/// One outstanding question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxRequest {
    /// The transaction being asked about.
    pub txid: TxId,
    /// What is being asked.
    pub query: TxQuery,
}

/// Returns outstanding questions worth asking at this chain tip.
///
/// Enhancement requests stand until answered. Status requests are returned only
/// while the transaction could still plausibly be mined: once it is mined the
/// row lies dormant rather than being deleted, so that un-mining it in a rewind
/// puts the question back without anything having to re-queue it.
///
/// `last_polled_height` is what stops a pending transaction being re-asked on
/// every step. The wallet learns nothing by asking the same server the same
/// question twice at the same tip.
pub(crate) fn tx_requests(
    conn: &rusqlite::Connection,
    scope: RequestScope,
    tip: BlockHeight,
    limit: usize,
) -> Result<Vec<TxRequest>, Error> {
    let only_sends = scope == RequestScope::PendingSends;
    let sql = format!(
        "SELECT r.txid, r.query_type
         FROM {CACHE_SCHEMA}.tx_requests r
         LEFT JOIN {CACHE_SCHEMA}.transactions t ON t.txid = r.txid
         WHERE (r.last_polled_height IS NULL OR r.last_polled_height < :tip)
           AND ( r.query_type = {enhancement}
              OR ( r.query_type = {status}
                   AND (t.id IS NULL
                        OR (t.mined_height IS NULL AND {UNEXPIRED})) ) )
           AND (NOT :only_sends OR t.target_height IS NOT NULL)
         ORDER BY (t.target_height IS NOT NULL) DESC, r.rowid
         LIMIT :limit",
        enhancement = TxQuery::Enhancement as u8,
        status = TxQuery::Status as u8,
    );

    let mut stmt = conn.prepare(&sql).map_err(Error::Query)?;
    let rows = stmt
        .query_map(
            named_params![
                ":tip": u32::from(tip),
                ":only_sends": only_sends,
                ":limit": limit as i64,
            ],
            |row| {
                let txid: Vec<u8> = row.get(0)?;
                let code: u8 = row.get(1)?;
                Ok((txid, code))
            },
        )
        .map_err(Error::Query)?;

    let mut out = Vec::new();
    for row in rows {
        let (txid, code) = row.map_err(Error::Query)?;
        let bytes: [u8; 32] = txid
            .try_into()
            .map_err(|_| Error::Corrupt("a queued request has a malformed txid".into()))?;
        let query = TxQuery::from_code(code)
            .ok_or_else(|| Error::Corrupt(format!("unknown request type {code}")))?;
        out.push(TxRequest {
            txid: TxId::from_bytes(bytes),
            query,
        });
    }
    Ok(out)
}

/// Records that a request was asked at this tip.
pub(crate) fn mark_polled(
    conn: &rusqlite::Connection,
    txid: TxId,
    tip: BlockHeight,
) -> Result<(), Error> {
    conn.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.tx_requests SET last_polled_height = :tip
             WHERE txid = :txid"
        ),
        named_params![":txid": txid.as_ref(), ":tip": u32::from(tip)],
    )
    .map_err(Error::Query)?;
    Ok(())
}

/// Applies what a source said about a transaction.
pub(crate) fn set_transaction_status(
    conn: &rusqlite::Transaction<'_>,
    txid: TxId,
    status: TransactionStatus,
    tip: BlockHeight,
) -> Result<(), Error> {
    match status {
        TransactionStatus::Mined(height) => {
            conn.execute(
                &format!(
                    "UPDATE {CACHE_SCHEMA}.transactions
                     SET mined_height = :height,
                         min_observed_height =
                            MIN(IFNULL(min_observed_height, :height), :height),
                         -- Cleared, because it recorded proof the transaction
                         -- was *not* mined, and it now is. The CHECK forbids
                         -- both being set, and rightly.
                         confirmed_unmined_at_height = NULL,
                         -- Only when the block has been scanned: `block_height`
                         -- is a foreign key onto `blocks`, and knowing a
                         -- transaction is mined is not the same as holding the
                         -- block it is mined in.
                         block_height = (SELECT height FROM {CACHE_SCHEMA}.blocks
                                          WHERE height = :height)
                     WHERE txid = :txid"
                ),
                named_params![":txid": txid.as_ref(), ":height": u32::from(height)],
            )
            .map_err(Error::Query)?;

            // Only the enhancement request is retired. The status row stays,
            // dormant, so that a rewind reactivates it for free.
            delete_request(conn, txid, TxQuery::Enhancement)?;
        }
        TransactionStatus::NotFound | TransactionStatus::NotInMainChain => {
            conn.execute(
                &format!(
                    "UPDATE {CACHE_SCHEMA}.transactions
                     SET confirmed_unmined_at_height =
                            MAX(IFNULL(confirmed_unmined_at_height, 0), :tip)
                     WHERE txid = :txid AND mined_height IS NULL"
                ),
                named_params![":txid": txid.as_ref(), ":tip": u32::from(tip)],
            )
            .map_err(Error::Query)?;

            // The server has said it cannot supply the transaction, so asking
            // again for its contents is asking a question already answered.
            delete_request(conn, txid, TxQuery::Enhancement)?;

            // The status question is retired only once the answer can no longer
            // change — that is, once the transaction is provably dead. Until
            // then it is still worth asking, because it may yet be mined.
            conn.execute(
                &format!(
                    "DELETE FROM {CACHE_SCHEMA}.tx_requests
                     WHERE txid = :txid AND query_type = {status}
                       AND NOT EXISTS (
                            SELECT 1 FROM {CACHE_SCHEMA}.transactions t
                             WHERE t.txid = :txid
                               AND (t.mined_height IS NOT NULL OR {UNEXPIRED})
                       )",
                    status = TxQuery::Status as u8,
                ),
                named_params![":txid": txid.as_ref()],
            )
            .map_err(Error::Query)?;
        }
    }
    Ok(())
}

/// The set of notes held by a spend that could still go through.
///
/// A note is unavailable while some transaction that spends it might yet be
/// mined. It becomes available again only when every such transaction is
/// *provably* dead — which is why this is written against
/// `confirmed_unmined_at_height` and never against the chain tip alone. The tip
/// passing a transaction's expiry height means only that the wallet has not
/// asked; releasing a note on that basis is a double spend.
///
/// Expressed as a subquery on `received_notes.id` so both balance and note
/// selection can use exactly the same rule.
pub fn held_by_live_spend() -> String {
    format!(
        "SELECT s.received_note_id
           FROM {CACHE_SCHEMA}.received_note_spends s
           JOIN {CACHE_SCHEMA}.transactions t ON t.id = s.transaction_id
          WHERE t.mined_height IS NOT NULL OR {UNEXPIRED}"
    )
}

/// The transparent outputs held by a spend that could still go through.
///
/// The same rule as [`held_by_live_spend`], over the transparent tables. Kept
/// as a separate string rather than parameterised, because the two sets of
/// tables have different column names and a single templated version would be
/// harder to read than two explicit ones.
pub fn held_by_live_spend_transparent() -> String {
    format!(
        "SELECT s.output_id
           FROM {CACHE_SCHEMA}.transparent_received_output_spends s
           JOIN {CACHE_SCHEMA}.transactions t ON t.id = s.transaction_id
          WHERE t.mined_height IS NOT NULL OR {UNEXPIRED}"
    )
}
