//! What a transaction's status means, and when it becomes final.
//!
//! The queue of outstanding questions lives in [`crate::retrieval`]. What is
//! left here is the harder half: reading an answer.
//!
//! The delicate part is deciding when a transaction is *dead*, because that is
//! what releases the notes it spent. Expiry is proved, never inferred: the
//! chain tip passing a transaction's expiry height means nothing on its own,
//! since the wallet may simply never have asked. Only a server's positive
//! assertion that it does not have the transaction, recorded as
//! `confirmed_unmined_at_height`, counts. Inferring instead of proving here is
//! a double spend.

use rusqlite::named_params;
use zakura_wallet_core::retrieval::{Locator, LocatorKind};
use zcash_protocol::{TxId, consensus::BlockHeight};

pub use zakura_wallet_core::enhanced::TransactionStatus;

use crate::{error::Error, schema::CACHE_SCHEMA};

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
            crate::retrieval::delete(conn, Locator::Transaction(txid))?;
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
            crate::retrieval::delete(conn, Locator::Transaction(txid))?;

            // The status question is retired only once the answer can no longer
            // change — that is, once the transaction is provably dead. Until
            // then it is still worth asking, because it may yet be mined.
            conn.execute(
                &format!(
                    "DELETE FROM {CACHE_SCHEMA}.retrieval_queue
                     WHERE subject_txid = :txid AND kind = {status}
                       AND NOT EXISTS (
                            SELECT 1 FROM {CACHE_SCHEMA}.transactions t
                             WHERE t.txid = :txid
                               AND (t.mined_height IS NOT NULL OR {UNEXPIRED})
                       )",
                    status = LocatorKind::Status.code(),
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
