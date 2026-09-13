//! The queue of what the wallet still needs from outside.
//!
//! One table, keyed by [`Locator`] rather than by transaction identifier. The
//! shape matters: enhancement used to be the only question, "give me the bytes
//! of this transaction", and a txid key said that exactly. Private retrieval
//! asks a different question — "give me the item at this tree position" — whose
//! entire value is that the transaction is *not* named. A queue that can only
//! be keyed by transaction cannot hold that request, and adding a second table
//! beside it would mean two drains, two poll policies and two ways to be
//! already answered.
//!
//! What a row does and does not carry is the privacy boundary. `locator` is the
//! only part that ever reaches a server. `subject_txid` is what the wallet
//! knows locally about the same row, and it stays here.

use rusqlite::{OptionalExtension, named_params};
use zakura_wallet_core::retrieval::{Locator, LocatorKind, LocatorKinds};
use zcash_protocol::{TxId, consensus::BlockHeight};

use crate::{error::Error, schema::CACHE_SCHEMA, status::UNEXPIRED};

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

/// One outstanding question, as the drain hands it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueuedRequest {
    /// What is being asked for. The only part that may be sent.
    pub locator: Locator,
    /// The transaction it concerns, when the wallet knows locally.
    pub subject: Option<TxId>,
    /// Whether this subject has already been shown to need the public path.
    ///
    /// Once set it is never cleared: the disclosure it records cannot be taken
    /// back, and a later response claiming the transaction is private after all
    /// must not be able to re-protect it.
    pub fallback_barred: bool,
}

/// Records an outstanding question, if it is not already recorded.
///
/// Never converts one kind of question into another: the key is the pair, so a
/// request for a transaction's bytes and a request for its status are separate
/// rows and answering one cannot silently discard the other.
pub(crate) fn queue(
    conn: &rusqlite::Connection,
    locator: Locator,
    dependent: Option<i64>,
) -> Result<(), Error> {
    queue_about(conn, locator, locator.subject(), dependent)
}

/// Records a question whose subject the locator does not name.
///
/// An action locator deliberately carries no transaction identifier — that is
/// the disclosure it exists to avoid — but the wallet knows which transaction
/// the action belongs to, and has to keep knowing. Barring a transaction from
/// private retrieval, cleaning up after a rewind and the already-fetched guard
/// all key on the subject, and a row that cannot name its own would be
/// invisible to every one of them.
pub(crate) fn queue_about(
    conn: &rusqlite::Connection,
    locator: Locator,
    subject: Option<TxId>,
    dependent: Option<i64>,
) -> Result<(), Error> {
    conn.execute(
        &format!(
            "INSERT INTO {CACHE_SCHEMA}.retrieval_queue
                (kind, locator, subject_txid, locator_height, dependent_transaction_id)
             VALUES (:kind, :locator, :subject, :height, :dependent)
             ON CONFLICT (kind, locator) DO UPDATE SET
                dependent_transaction_id =
                    IFNULL(dependent_transaction_id, :dependent),
                subject_txid = IFNULL(subject_txid, :subject)"
        ),
        named_params![
            ":kind": locator.kind().code(),
            ":locator": locator.encode(),
            ":subject": subject.map(|t| t.as_ref().to_vec()),
            ":height": locator.height().map(u32::from),
            ":dependent": dependent,
        ],
    )
    .map_err(Error::Query)?;
    Ok(())
}

/// Records an outstanding question about a subject the wallet learned about
/// only now, unless that transaction's bytes are already stored.
///
/// This is the back edge of the discovery loop, and the guard is what makes it
/// terminate. `raw_transactions` is durable and written on every successful
/// enhancement, so a transaction whose bytes are present has been through this
/// path already; it also survives a cache rebuild, which a queue row does not.
pub(crate) fn queue_unless_fetched(
    conn: &rusqlite::Connection,
    locator: Locator,
    subject: TxId,
) -> Result<(), Error> {
    let fetched: bool = conn
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM main.raw_transactions WHERE txid = :txid)")?
        .query_row(named_params![":txid": subject.as_ref()], |row| row.get(0))?;

    if fetched {
        return Ok(());
    }

    // The subject is passed explicitly: a block locator names a height, not a
    // transaction, but the reconstruction it drives belongs to one.
    queue_about(conn, locator, Some(subject), None)
}

/// Removes one outstanding question.
pub(crate) fn delete(conn: &rusqlite::Connection, locator: Locator) -> Result<(), Error> {
    conn.execute(
        &format!(
            "DELETE FROM {CACHE_SCHEMA}.retrieval_queue
             WHERE kind = :kind AND locator = :locator"
        ),
        named_params![
            ":kind": locator.kind().code(),
            ":locator": locator.encode(),
        ],
    )
    .map_err(Error::Query)?;
    Ok(())
}

/// Drops the private work for a transaction the wallet now holds whole.
///
/// Once the raw transaction is stored, every field a position-keyed request
/// would have recovered is already in hand, so continuing to ask would be a
/// query spent on nothing — and each one still costs whatever a private
/// backend's query volume reveals.
pub(crate) fn clear_private_work(conn: &rusqlite::Connection, subject: TxId) -> Result<(), Error> {
    conn.execute(
        &format!(
            "DELETE FROM {CACHE_SCHEMA}.retrieval_queue
             WHERE kind = :action AND subject_txid = :subject"
        ),
        named_params![
            ":subject": subject.as_ref(),
            ":action": LocatorKind::Action.code(),
        ],
    )
    .map_err(Error::Query)?;
    Ok(())
}

/// Records that this subject can never be served privately again.
///
/// Called when a response reveals the transaction touches a pool private
/// retrieval cannot cover. It bars every row about that subject, and it clears
/// the position-keyed work, because continuing to spend private queries on a
/// transaction whose identifier is about to be disclosed anyway buys nothing.
pub(crate) fn bar_fallback(conn: &rusqlite::Connection, subject: TxId) -> Result<(), Error> {
    // Recorded by *creating* the public request, not merely by flagging rows
    // that happen to exist. The two are not the same: a subject can be barred
    // at a moment when it has no queue row at all, and a rescan that re-derives
    // its rows from scratch would then re-derive them unbarred. Writing the row
    // here makes the decision a fact of its own — and it is the right row,
    // because what barring means is that this transaction must now be fetched
    // whole and publicly.
    let public = Locator::Transaction(subject);
    conn.execute(
        &format!(
            "INSERT INTO {CACHE_SCHEMA}.retrieval_queue
                (kind, locator, subject_txid, fallback_barred)
             VALUES (:kind, :locator, :subject, 1)
             ON CONFLICT (kind, locator) DO UPDATE SET fallback_barred = 1"
        ),
        named_params![
            ":kind": public.kind().code(),
            ":locator": public.encode(),
            ":subject": subject.as_ref(),
        ],
    )
    .map_err(Error::Query)?;

    // Every remaining question about the same subject is barred too, and the
    // position-keyed work is dropped: spending another private query on a
    // transaction whose identifier is about to be disclosed buys nothing.
    conn.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.retrieval_queue SET fallback_barred = 1
             WHERE subject_txid = :subject"
        ),
        named_params![":subject": subject.as_ref()],
    )
    .map_err(Error::Query)?;

    conn.execute(
        &format!(
            "DELETE FROM {CACHE_SCHEMA}.retrieval_queue
             WHERE subject_txid = :subject AND kind = :action"
        ),
        named_params![
            ":subject": subject.as_ref(),
            ":action": LocatorKind::Action.code(),
        ],
    )
    .map_err(Error::Query)?;
    Ok(())
}

/// Whether this subject has been barred from private retrieval.
pub(crate) fn is_barred(conn: &rusqlite::Connection, subject: TxId) -> Result<bool, Error> {
    let barred: Option<bool> = conn
        .prepare_cached(&format!(
            "SELECT 1 FROM {CACHE_SCHEMA}.retrieval_queue
             WHERE subject_txid = :subject AND fallback_barred = 1 LIMIT 1"
        ))?
        .query_row(named_params![":subject": subject.as_ref()], |row| {
            row.get(0)
        })
        .optional()?;
    Ok(barred.unwrap_or(false))
}

/// The greatest number of times a block reconstruction is retried.
///
/// A reconstruction can be handed cached data that is invalid for reasons no
/// retry will change. Without a bound it would be re-requested on every drain
/// forever, and each request reveals interest in the height again.
pub const MAX_ATTEMPTS: u32 = 5;

/// Returns outstanding questions worth asking at this chain tip.
///
/// Requests for a transaction's bytes, for an action and for a block stand
/// until answered. Status requests are returned only while the transaction
/// could still plausibly be mined: once it is mined the row lies dormant rather
/// than being deleted, so that un-mining it in a rewind puts the question back
/// without anything having to re-queue it.
///
/// `last_polled_height` is what stops a pending transaction being re-asked on
/// every step. The wallet learns nothing by asking the same server the same
/// question twice at the same tip.
pub(crate) fn pending(
    conn: &rusqlite::Connection,
    scope: RequestScope,
    kinds: LocatorKinds,
    tip: BlockHeight,
    limit: usize,
) -> Result<Vec<QueuedRequest>, Error> {
    let only_sends = scope == RequestScope::PendingSends;

    // Filtered here rather than skipped after the fact. A backend serves a
    // fixed set of locator kinds, and a row it cannot take on is not merely
    // wasted work: rows it cannot serve would fill the batch and starve the
    // ones it can, leaving the wallet with outstanding work and a drain that
    // reports nothing to do.
    let servable: Vec<String> = [
        (kinds.status, LocatorKind::Status),
        (kinds.transaction, LocatorKind::Transaction),
        (kinds.action, LocatorKind::Action),
        (kinds.block, LocatorKind::Block),
    ]
    .into_iter()
    .filter(|(served, _)| *served)
    .map(|(_, kind)| kind.code().to_string())
    .collect();
    if servable.is_empty() {
        return Ok(Vec::new());
    }
    let servable = servable.join(",");
    let sql = format!(
        "SELECT r.kind, r.locator, r.subject_txid, r.fallback_barred
         FROM {CACHE_SCHEMA}.retrieval_queue r
         LEFT JOIN {CACHE_SCHEMA}.transactions t ON t.txid = r.subject_txid
         WHERE (r.last_polled_height IS NULL OR r.last_polled_height < :tip)
           AND r.kind IN ({servable})
           AND r.attempts < {MAX_ATTEMPTS}
           -- A block request is dispatched only once the wallet holds the
           -- block below it, which is what anchors the re-detection. Filtered
           -- here rather than checked after fetching, for two reasons: asking
           -- for a block that cannot be used still tells the server which
           -- height the wallet cares about, and it would do so again on every
           -- tip; and rows that can never be answered would fill the batch and
           -- starve the ones that can. Ordinary scanning makes the predecessor
           -- available, and the row becomes dispatchable on its own.
           AND ( r.kind != {block}
              OR EXISTS (SELECT 1 FROM {CACHE_SCHEMA}.blocks b
                          WHERE b.height = r.locator_height - 1) )
           AND ( r.kind != {status}
              OR ( t.id IS NULL
                   OR (t.mined_height IS NULL AND {UNEXPIRED}) ) )
           AND (NOT :only_sends OR t.target_height IS NOT NULL)
         ORDER BY (t.target_height IS NOT NULL) DESC, r.rowid
         LIMIT :limit",
        status = LocatorKind::Status.code(),
        block = LocatorKind::Block.code(),
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
                let kind: u8 = row.get(0)?;
                let locator: Vec<u8> = row.get(1)?;
                let subject: Option<Vec<u8>> = row.get(2)?;
                let barred: bool = row.get(3)?;
                Ok((kind, locator, subject, barred))
            },
        )
        .map_err(Error::Query)?;

    let mut out = Vec::new();
    for row in rows {
        let (code, bytes, subject, fallback_barred) = row.map_err(Error::Query)?;
        let kind = LocatorKind::from_code(code)
            .ok_or_else(|| Error::Corrupt(format!("unknown request kind {code}")))?;
        let locator = Locator::decode(kind, &bytes)
            .ok_or_else(|| Error::Corrupt("a queued request has a malformed locator".into()))?;
        let subject = subject
            .map(|s| {
                <[u8; 32]>::try_from(s)
                    .map(TxId::from_bytes)
                    .map_err(|_| Error::Corrupt("a queued request has a malformed txid".into()))
            })
            .transpose()?;
        out.push(QueuedRequest {
            locator,
            subject,
            fallback_barred,
        });
    }
    Ok(out)
}

/// Records that a request was asked at this tip.
pub(crate) fn mark_polled(
    conn: &rusqlite::Connection,
    locator: Locator,
    tip: BlockHeight,
) -> Result<(), Error> {
    conn.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.retrieval_queue SET last_polled_height = :tip
             WHERE kind = :kind AND locator = :locator"
        ),
        named_params![
            ":kind": locator.kind().code(),
            ":locator": locator.encode(),
            ":tip": u32::from(tip),
        ],
    )
    .map_err(Error::Query)?;
    Ok(())
}

/// Records an attempt that produced nothing usable.
///
/// Separate from polling because the two bound different things: polling stops
/// the same question being asked twice at one tip, while attempts stop a
/// request that can never succeed being retried forever.
pub(crate) fn mark_attempted(conn: &rusqlite::Connection, locator: Locator) -> Result<(), Error> {
    conn.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.retrieval_queue SET attempts = attempts + 1
             WHERE kind = :kind AND locator = :locator"
        ),
        named_params![
            ":kind": locator.kind().code(),
            ":locator": locator.encode(),
        ],
    )
    .map_err(Error::Query)?;
    Ok(())
}
