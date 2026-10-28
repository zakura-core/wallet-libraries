//! One durable queue for seed restore, live hints, catch-up and explicit history checks.
use crate::wallet::scanning::priority_code;
use rusqlite::{Connection, OptionalExtension, named_params, params};
use zcash_client_backend::data_api::scanning::ScanPriority;
use zcash_client_backend::data_api::{
    one_time_ivk::restore::{
        DirectoryRecord, DiscoveryWork, FilterOutcome, FilterReceiver, FilterSpan, LookupCursor,
        LookupPage, LookupWork, ManualProgress, RECEIVE_GAP, RECOVERY_PAGE_LIMIT,
        RecoveryPublication, RecoveryStatus, RecoveryToken, WitnessAnswer, WitnessRequest,
        decode_witness_payload,
    },
    transparent_ledger::ChainPoint,
};
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::{
    consensus::{BlockHeight, NetworkUpgrade, Parameters, SECONDS_PER_BLOCK},
    zip318::BlockSpacing,
};

use super::{
    apply::{Admission, Sessions, WitnessPath, apply_payment},
    payments::{
        PendingPayment, action_holds, authenticate, directory_candidate, pending_payment,
        queue_payment, stored_action,
    },
    recovery::recover_refund_memos,
};
use crate::wallet::one_time_ivk::{
    KeyId, Purpose, account_key, corrupt, decode_index, index_after, invalid, key_ref,
    one_time_account, register, stored_key_id,
};
use crate::{AccountUuid, PRUNING_DEPTH, error::SqliteClientError, wallet};

const AUTOMATIC: u8 = 1;
/// Lookup reason bit marking history an event invalidated: a positive filter hint, a
/// correction, a rewind below the settled height, a disputed receipt label, a rejected
/// payment claim or a lowered birthday. The key may have been paid in what was read before,
/// so its receiver is not reused until the lookup settles (see [`RECEIVE_PENDING`]), which
/// clears the bit. Reading new blocks never sets it. It only holds reservations: a lookup is
/// exposed and processed only while it has an active [`AUTOMATIC`] or [`MANUAL`] reason
/// (`reasons & 3`), so cancelling a manual search pauses an invalidated manual-only lookup.
pub(crate) const INVALIDATED: u8 = 4;

/// SQL over key alias `k`: history an event invalidated (see [`INVALIDATED`]) or a payment
/// candidate on the key is unresolved, so the key may already be paid. Ordinary catch-up
/// does not count, so this never waits for coverage to reach the chain tip.
pub(in crate::wallet::one_time_ivk) const RECEIVE_PENDING: &str = "(EXISTS(SELECT 1
        FROM ironwood_one_time_lookups l WHERE l.one_time_key_id = k.id AND l.reasons & 4 != 0)
    OR EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p WHERE p.one_time_key_id = k.id))";
const MANUAL: u8 = 2;
/// Local cursor entries one progress step may advance, keeping each transaction short. A
/// step that runs out with work left hands it to the worker (see [`hand_off`]).
const STEP_BUDGET: usize = 64;

use crate::wallet::one_time_rewind::CURSOR_RESET;

/// The first height receiver history can hold, where seed receive discovery starts.
pub(crate) fn activation<P: Parameters>(params: &P) -> u32 {
    params
        .activation_height(NetworkUpgrade::Nu6_3)
        .map_or(0, u32::from)
}

/// SQL over receipt alias `n` and its transaction `t`: the receipt's own chain placement is
/// not restored. Placement is per receipt: a rewind clears each private receipt's position
/// (see `one_time_rewind::truncate`), and repairing one receipt marks its whole transaction
/// mined while a sibling receipt still waits for its own position and witness.
const UNPLACED: &str = "(t.mined_height IS NULL OR n.commitment_tree_position IS NULL)";

const _: () = assert!(
    PRUNING_DEPTH == 100,
    "REPAIR_KEY writes the pruning depth inline"
);

/// SQL over key alias `k`: an already-owned receipt is [`UNPLACED`], or its transaction
/// label is disputed (see [`check_raw_receipts`]), so it needs repair.
///
/// A reorg-displaced receipt needs none once the key's completed history reaches its
/// transaction's expiry height and filters have passed [`PRUNING_DEPTH`] blocks beyond it.
/// A reorg clamps that history to the fork and reads it again from there, so the current
/// chain does not hold the transaction, and no reorg the wallet follows can mine it again.
/// That happens when another transaction replaced it. A paused account records no history,
/// so it keeps repairing.
const REPAIR_KEY: &str = "(EXISTS(SELECT 1 FROM ironwood_received_notes n JOIN transactions t
    ON t.id_tx = n.transaction_id WHERE n.one_time_key_id = k.id
    AND (t.mined_height IS NULL OR n.commitment_tree_position IS NULL)
    AND NOT (t.mined_height IS NULL AND IFNULL(t.expiry_height, 0) > 0
        AND t.expiry_height + 100 <= IFNULL((SELECT r.filter_height
            FROM ironwood_one_time_recovery r WHERE r.account_id = k.account_id), 0)
        AND EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
            WHERE l.one_time_key_id = k.id AND l.done_height >= t.expiry_height)))
    OR EXISTS(SELECT 1 FROM ironwood_one_time_disputed_receipts d
        JOIN ironwood_received_notes n ON n.id = d.note_id WHERE n.one_time_key_id = k.id))";

/// SQL over key alias `k`: a local operation owes a receipt not yet attributed to it, either
/// a promised one or the possible one of a funded operation that ended inconclusively.
/// Only a mined note in a transaction the provider reported for that operation counts.
/// Chain timing and the absence of other local quotes cannot attribute a payment, since
/// another device's quote may share the address.
pub(in crate::wallet::one_time_ivk) const UNSETTLED: &str =
    "EXISTS(SELECT 1 FROM ironwood_one_time_operations o
    WHERE o.one_time_key_id = k.id AND (o.expectation = 2 OR (o.expectation = 3 AND o.funded = 1))
    AND COALESCE(o.expected_value, 1) > COALESCE((SELECT SUM(n.value)
        FROM ironwood_received_notes n JOIN transactions t ON t.id_tx = n.transaction_id
        JOIN ironwood_one_time_operation_receipts r ON r.operation_id = o.id AND r.txid = t.txid
        WHERE n.one_time_key_id = k.id AND t.mined_height IS NOT NULL
          AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_disputed_receipts d
              WHERE d.note_id = n.id)), 0))";

/// SQL over key alias `k`: a complete lookup checked the key from `:from` through `:height`
/// and left no candidate waiting for admission.
const CHECKED_THROUGH: &str = "EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
    WHERE l.one_time_key_id = k.id AND l.done_height >= :height AND l.done_from <= :from
    AND l.read_complete = 1
    AND l.target_height IS NULL AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
        WHERE p.one_time_key_id = k.id))";

/// Whether this exact output was already admitted, independent of its current chain placement.
fn known_receipt(
    conn: &Connection,
    key: i64,
    txid: TxId,
    action: u32,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM ironwood_received_notes n JOIN transactions t
        ON t.id_tx = n.transaction_id WHERE n.one_time_key_id = ?1 AND t.txid = ?2 AND n.action_index = ?3)",
        params![key, txid.as_ref(), action], |r| r.get(0))?)
}

/// Whether this exact output is already admitted and mined where the directory places it,
/// under a label no raw bytes disputed, so reading its history again needs no new witness
/// query.
fn admitted(
    conn: &Connection,
    key: i64,
    candidate: &PendingPayment,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes n JOIN transactions t
        ON t.id_tx = n.transaction_id WHERE n.one_time_key_id = ?1 AND t.txid = ?2
            AND n.action_index = ?3 AND t.mined_height = ?4 AND n.commitment_tree_position = ?5
            AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_disputed_receipts d
                WHERE d.note_id = n.id))",
        params![
            key,
            candidate.txid.as_ref(),
            candidate.action_index,
            u32::from(candidate.height),
            candidate.position
        ],
        |r| r.get(0),
    )?)
}

/// Makes `key`'s lookup read its history again from the shard holding `height`, keeping
/// its reasons (callers whose event invalidates settled history add [`INVALIDATED`]): checked progress, any cursor and a completion reaching that height are
/// void. `retry_at` delays the next attempt.
fn rewind_lookup(
    conn: &Connection,
    key: i64,
    height: u32,
    retry_at: i64,
) -> Result<(), SqliteClientError> {
    let reasons: Option<u8> = conn
        .query_row(
            "SELECT reasons FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
            [key],
            |r| r.get(0),
        )
        .optional()?;
    enqueue(
        conn,
        key,
        height,
        height,
        reasons.filter(|r| *r & 3 != 0).unwrap_or(AUTOMATIC),
    )?;
    conn.execute(
        &format!(
            "UPDATE ironwood_one_time_lookups SET start_height = MIN(start_height, ?2),
            checked_height = CASE WHEN checked_height >= ?2 THEN ?2 - 1 ELSE checked_height END,
            done_from = CASE WHEN done_height >= ?2 AND NOT done_from < ?2 THEN NULL ELSE done_from END,
            done_height = CASE WHEN done_height >= ?2
                THEN CASE WHEN done_from < ?2 THEN ?2 - 1 ELSE NULL END ELSE done_height END,
            {CURSOR_RESET}, read_complete = 0, attempts = 0, next_attempt_at = ?3
            WHERE one_time_key_id = ?1"
        ),
        params![key, height, retry_at],
    )?;
    Ok(())
}

/// Whether disabled discovery may still admit `candidate` for key `id`: the exact output
/// was already admitted, or its authenticated note is a stored receipt whose transaction
/// label is disputed (see [`check_raw_receipts`]), so the candidate may carry its true label.
fn repairable<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    id: i64,
    candidate: &PendingPayment,
) -> Result<bool, SqliteClientError> {
    if known_receipt(conn, id, candidate.txid, candidate.action_index)? {
        return Ok(true);
    }
    let (_, note) = authenticate(conn, params, account, key, candidate)?;
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_disputed_receipts d
             JOIN ironwood_received_notes n ON n.id = d.note_id
             WHERE n.one_time_key_id = ?1 AND n.nf = ?2)",
        params![id, note.nullifier().to_bytes()],
        |r| r.get(0),
    )?)
}

/// Marks `key`'s lookup with [`INVALIDATED`] after an event voided its settled history.
fn invalidate(conn: &Connection, key: i64) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_one_time_lookups SET reasons = reasons | ?2 WHERE one_time_key_id = ?1",
        params![key, INVALIDATED],
    )?;
    Ok(())
}

/// Drops a candidate's session binding and witness and reads its key's history again, so a
/// current session binds a fresh ordinal; an ordinal is never reinterpreted under another
/// session. The candidate stays pending, never an empty answer. The lookup keeps its reasons,
/// so a refresh never turns manual-only work automatic. `retry_at` backs off a witness the
/// wallet itself found unusable.
fn refresh_witness(
    conn: &Connection,
    key: i64,
    txid: TxId,
    action: u32,
    height: BlockHeight,
    retry_at: i64,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_one_time_payment_recovery SET payments = NULL, ordinal = NULL,
        witnesses = NULL, witness = NULL, witness_height = NULL, witness_hash = NULL,
        witness_size = NULL WHERE txid = ?1 AND action_index = ?2",
        params![txid.as_ref(), action],
    )?;
    rewind_lookup(conn, key, u32::from(height), retry_at)?;
    Ok(())
}

/// Allows disabled accounts to repair only keys with a receipt that needs it (see
/// [`REPAIR_KEY`]).
fn can_lookup(
    conn: &Connection,
    owner: i64,
    key: i64,
    captured: RecoveryToken,
) -> Result<bool, SqliteClientError> {
    let (enabled, current) = token(conn, owner)?;
    Ok(current == captured
        && (enabled
            || conn.query_row(
                &format!("SELECT {REPAIR_KEY} FROM ironwood_one_time_keys k WHERE k.id = ?1"),
                [key],
                |r| r.get(0),
            )?))
}

/// Ensures account progress exists without enabling network work. Only enabling recovery
/// and the flows it starts (registering keys, widening the receive window) create it, and
/// [`begin`] for an account that already holds receipts needing repair, so an account that
/// never used the feature has no row and costs no per-batch work.
pub(crate) fn ensure_account(conn: &Connection, owner: i64) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT OR IGNORE INTO ironwood_one_time_recovery(account_id) VALUES (?1)",
        [owner],
    )?;
    Ok(())
}

/// The fence of an account that never enabled one-time recovery, which has no progress row.
const NO_RECOVERY: RecoveryToken = RecoveryToken {
    generation: 0,
    history_revision: 0,
};

/// Reads the cancellation fence and feature setting in the current transaction. An account
/// with no progress row never enabled recovery, so it is disabled at [`NO_RECOVERY`].
fn token(conn: &Connection, owner: i64) -> Result<(bool, RecoveryToken), SqliteClientError> {
    let Some((enabled, generation, revision)): Option<(bool, u64, Vec<u8>)> = conn.query_row(
        "SELECT enabled, generation, history_revision FROM ironwood_one_time_recovery WHERE account_id = ?1",
        [owner], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?
    else {
        return Ok((false, NO_RECOVERY));
    };
    Ok((
        enabled,
        RecoveryToken {
            generation,
            history_revision: decode_index(revision)?,
        },
    ))
}

/// Raises a request to need history `[from, through]` without discarding a recorded positive
/// or valid progress. After completion, a request reaching back into the completed span
/// starts where that span ends. Lowering a pending request's start voids its progress,
/// which held only from the old start.
/// A completed history that already covers the request settles it without a target, since
/// nothing would query or clear one; this returns true, and a caller stepping through keys
/// continues rather than waiting for work that will never be exposed.
pub(crate) fn enqueue(
    conn: &Connection,
    key: i64,
    from: u32,
    through: u32,
    reason: u8,
) -> Result<bool, SqliteClientError> {
    #[allow(clippy::type_complexity)]
    let current: Option<(Option<u32>, u32, Option<u32>, Option<u32>, bool)> = conn
        .query_row(
            "SELECT target_height, start_height, done_height, done_from, read_complete
             FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
            [key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((target, start, done, done_from, read)) = current else {
        conn.execute(
            "INSERT INTO ironwood_one_time_lookups(one_time_key_id, target_height, reasons, start_height)
             VALUES (?1, ?2, ?3, ?4)",
            params![key, through, reason, from],
        )?;
        return Ok(false);
    };
    // Completed coverage this request can build on: it must reach back to `from`, and
    // history it already covers is not required again.
    let covered = done
        .zip(done_from)
        .filter(|(_, f)| *f <= from)
        .map(|(d, _)| d);
    let from = covered
        .filter(|d| from <= d.saturating_add(1))
        .map_or(from, |d| d.saturating_add(1));
    match target {
        None if covered.is_some_and(|d| d >= through) && !candidates(conn, key)? => {
            // Completed coverage already answers the request: settle it here, since nothing
            // would query or clear a target for it.
            // Settled history answers any invalidation too (see `INVALIDATED`).
            conn.execute(
                "UPDATE ironwood_one_time_lookups SET read_complete = 1, reasons = reasons & ?2
                 WHERE one_time_key_id = ?1",
                params![key, AUTOMATIC | MANUAL],
            )?;
            return Ok(true);
        }
        None => {
            let start = from;
            conn.execute(
                &format!(
                    "UPDATE ironwood_one_time_lookups SET target_height = ?2, reasons = reasons | ?3,
                    start_height = ?4, checked_height = NULL, {CURSOR_RESET}, read_complete = ?5,
                    attempts = 0, next_attempt_at = 0 WHERE one_time_key_id = ?1"
                ),
                params![key, through, reason, start, covered.is_some_and(|d| d >= through)],
            )?;
        }
        Some(target) => {
            let lowered = from < start;
            let raised = through > target;
            let keep = read && !lowered && covered.is_some_and(|d| d >= through.max(target));
            conn.execute(
                "UPDATE ironwood_one_time_lookups SET target_height = MAX(target_height, ?2),
                    reasons = reasons | ?3, start_height = MIN(start_height, ?4),
                    checked_height = CASE WHEN ?5 THEN NULL ELSE checked_height END,
                    inventory = CASE WHEN ?5 THEN NULL ELSE inventory END,
                    shard = CASE WHEN ?5 THEN NULL ELSE shard END,
                    segment = CASE WHEN ?5 THEN NULL ELSE segment END,
                    last_record = CASE WHEN ?5 THEN NULL ELSE last_record END,
                    read_complete = ?6,
                    attempts = CASE WHEN ?7 THEN 0 ELSE attempts END,
                    next_attempt_at = CASE WHEN ?7 THEN 0 ELSE next_attempt_at END
                    WHERE one_time_key_id = ?1",
                params![key, through, reason, from, lowered, keep, raised],
            )?;
        }
    }
    Ok(false)
}

/// Whether a payment candidate of `key` still waits for admission.
fn candidates(conn: &Connection, key: i64) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery WHERE one_time_key_id = ?1)",
        [key],
        |r| r.get(0),
    )?)
}

/// Newly learned receivers must cover history from `from`, including history filters
/// already passed. The key's coverage (see [`covered`]) drops below `from`, so filters
/// re-check that history. While a complete check last advanced the account's coverage
/// (`pir_coverage`), a lookup through the processed frontier covers it instead.
pub(crate) fn register_history(
    conn: &Connection,
    owner: i64,
    key: i64,
    from: u32,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_one_time_keys SET covered_height = MIN(COALESCE(covered_height, ?2), ?2)
         WHERE id = ?1",
        params![key, from.saturating_sub(1)],
    )?;
    if recovery_flag(conn, owner, "pir_coverage")? == Some(true) {
        let through = queue_history(conn, owner, key, from)?;
        conn.execute(
            "UPDATE ironwood_one_time_keys SET covered_height = MAX(covered_height, ?2)
             WHERE id = ?1",
            params![key, through],
        )?;
    }
    Ok(())
}

/// Queues a lookup of `key`'s history from `from` through the processed frontier, the
/// higher of the account's filter frontier and the wallet's highest block, and returns that
/// height.
pub(crate) fn queue_history(
    conn: &Connection,
    owner: i64,
    key: i64,
    from: u32,
) -> Result<u32, SqliteClientError> {
    let through: u32 = conn.query_row("SELECT MAX(COALESCE(filter_height, 0),
        COALESCE((SELECT MAX(height) FROM blocks), 0)) FROM ironwood_one_time_recovery WHERE account_id = ?1",
        [owner], |r| r.get(0))?;
    enqueue(conn, key, from, through, AUTOMATIC)?;
    Ok(through)
}

/// SQL over key alias `k`: the last height filter coverage reaches for the key, either
/// checked by filters or handed to a lookup a hit or complete check queued. Unset, it is one
/// below the key's history start: a refund key's funding height, otherwise `activation`.
fn covered_sql(activation: u32) -> String {
    format!("COALESCE(k.covered_height, MAX(COALESCE(k.funding_height, {activation}), 1) - 1)")
}

/// The last height `key`'s coverage reaches (see [`covered_sql`]).
fn covered<P: Parameters>(
    conn: &Connection,
    params: &P,
    key: i64,
) -> Result<u32, SqliteClientError> {
    Ok(conn.query_row(
        &format!(
            "SELECT {} FROM ironwood_one_time_keys k WHERE k.id = ?1",
            covered_sql(activation(params))
        ),
        [key],
        |r| r.get(0),
    )?)
}

/// Covers `key`'s history through `through` with a lookup from just past its coverage
/// (see [`covered`]) for `reason`, unless coverage already reaches it. Returns whether
/// completed history already settled the request (see [`enqueue`]).
fn cover<P: Parameters>(
    conn: &Connection,
    params: &P,
    key: i64,
    through: u32,
    reason: u8,
) -> Result<bool, SqliteClientError> {
    let last = covered(conn, params, key)?;
    if last >= through {
        return Ok(false);
    }
    let settled = enqueue(conn, key, last + 1, through, reason)?;
    conn.execute(
        "UPDATE ironwood_one_time_keys SET covered_height = ?2 WHERE id = ?1",
        params![key, through],
    )?;
    Ok(settled)
}

/// Registers only the four lookahead indexes justified by mined payment evidence and
/// enrolls them for automatic discovery (see [`enroll`]).
pub(crate) fn ensure_window<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let owner = wallet::get_account_ref(conn, account)?;
    ensure_account(conn, owner.0)?;
    let end = super::super::swap::reservations::recovery_end(conn, owner.0)?;
    if end <= enrolled_end(conn, owner.0)? {
        return Ok(());
    }
    for index in end.saturating_sub(RECEIVE_GAP)..end {
        register(conn, params, account, KeyId::new(Purpose::Receive, index))?;
    }
    enroll(conn, params, owner.0, end)
}

/// The stored exclusive end of receive indexes enrolled for automatic discovery.
fn enrolled_end(conn: &Connection, owner: i64) -> Result<u64, SqliteClientError> {
    let stored: Vec<u8> = conn.query_row(
        "SELECT receive_end FROM ironwood_one_time_recovery WHERE account_id = ?1",
        [owner],
        |r| r.get(0),
    )?;
    decode_index(stored)
}

/// Enrolls registered receive indexes below `end` for automatic discovery, whether the
/// mined window or the seed walk reached them. Each newly enrolled index, including one an
/// earlier manual check already derived and completed, enters monitoring, which queues its
/// history and advances the generation (see [`fencing_monitoring`]).
fn enroll<P: Parameters>(
    conn: &Connection,
    params: &P,
    owner: i64,
    end: u64,
) -> Result<(), SqliteClientError> {
    if end <= enrolled_end(conn, owner)? {
        return Ok(());
    }
    fencing_monitoring(conn, params, &[owner], || {
        conn.execute(
            "UPDATE ironwood_one_time_recovery SET receive_end = ?2 WHERE account_id = ?1",
            params![owner, end.to_be_bytes()],
        )?;
        Ok(())
    })
}

/// The exclusive end of receive indexes that automatic discovery keeps checking. Issuance
/// uses the mined window alone, but an index once enrolled, by that window or by the
/// seed walk, stays here even after a reorg removes the payment that justified it, since
/// another device may have issued it.
pub(super) fn automatic_end(conn: &Connection, owner: i64) -> Result<u64, SqliteClientError> {
    let enrolled: Option<Vec<u8>> = conn
        .query_row(
            "SELECT receive_end FROM ironwood_one_time_recovery WHERE account_id = ?1",
            [owner],
            |r| r.get(0),
        )
        .optional()?;
    let enrolled = enrolled.map(decode_index).transpose()?.unwrap_or(0);
    Ok(super::super::swap::reservations::recovery_end(conn, owner)?.max(enrolled))
}

/// Records funded refund evidence. New or earlier funding queues the key's history from
/// that height even if ordinary sync passed it, including for a key already past
/// [`MEMO_REFUND_WINDOW`], which never enters monitoring (see [`fencing_monitoring`]).
pub(crate) fn funded<P: Parameters>(
    conn: &Connection,
    params: &P,
    key: i64,
    height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let (owner, changed): (i64, bool) = conn.query_row(
        "SELECT account_id, IFNULL(funding_height > ?2, 1) FROM ironwood_one_time_keys
         WHERE id = ?1",
        params![key, u32::from(height)],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    fencing_monitoring(conn, params, &[owner], || {
        conn.execute(
            "UPDATE ironwood_one_time_keys SET funding_height = ?2
            WHERE id = ?1 AND (funding_height IS NULL OR funding_height > ?2)",
            params![key, u32::from(height)],
        )?;
        if changed {
            register_history(conn, owner, key, u32::from(height))?;
        }
        Ok(())
    })
}

/// Pauses work and invalidates in-flight responses without deleting notes or pending requests.
/// Pausing never creates state: an account without an Orchard key or a progress row is
/// already disabled, so it is left untouched. Pausing an account that is not enabled only
/// reads, so it works on a read-only connection and never waits on another writer.
pub(crate) fn set_enabled<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    enabled: bool,
) -> Result<(), SqliteClientError> {
    if !enabled {
        if let Some(owner) = one_time_account(conn, params, account)? {
            // SQLite takes the write lock for an UPDATE even when no row matches.
            if recovery_flag(conn, owner.0, "enabled")? == Some(true) {
                conn.execute(
                    "UPDATE ironwood_one_time_recovery SET enabled = 0, generation = generation + 1
                    WHERE account_id = ?1",
                    [owner.0],
                )?;
            }
        }
        return Ok(());
    }
    let (owner, _) = account_key(conn, params, account)?;
    ensure_account(conn, owner.0)?;
    let changed = conn.execute(
        "UPDATE ironwood_one_time_recovery SET enabled = ?2, generation = generation + 1
        WHERE account_id = ?1 AND enabled != ?2",
        params![owner.0, enabled],
    )?;
    if changed > 0 && enabled {
        // Repair-only reads may have skipped new receipts. Start their history again
        // before enabled discovery can treat any saved page as complete, including partial
        // progress past a completed prefix that survived a reorg.
        conn.execute(
            &format!(
                "UPDATE ironwood_one_time_lookups SET {CURSOR_RESET}, checked_height = NULL,
                read_complete = 0 WHERE target_height IS NOT NULL
                AND (done_height IS NULL OR read_complete = 0)
                AND one_time_key_id IN (SELECT id FROM ironwood_one_time_keys WHERE account_id = ?1)"
            ),
            [owner.0],
        )?;
    }
    if enabled {
        ensure_window(conn, params, account)?;
        recover_refund_memos(conn, params, account)?;
    }
    Ok(())
}

/// Checks full-history publication coverage against locally scanned chain identity and tree size.
fn accepts<P: Parameters>(
    conn: &Connection,
    params: &P,
    publication: RecoveryPublication,
) -> Result<bool, SqliteClientError> {
    let Some(activation) = params.activation_height(NetworkUpgrade::Nu6_3) else {
        return Ok(false);
    };
    if publication.start_height > activation || publication.start_height > publication.end.height {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM blocks WHERE height = ?1 AND hash = ?2
        AND ironwood_commitment_tree_size = ?3)",
        params![
            u32::from(publication.end.height),
            publication.end.hash,
            publication.end.tree_size
        ],
        |r| r.get(0),
    )?)
}

/// Captures a usable publication. A complete check reads every monitored key, paid or not,
/// over the gap from its own coverage through the publication's end, and advances the
/// account's frontier there. A newer correction generation reads every monitored key once.
pub(crate) fn begin<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    publication: RecoveryPublication,
    complete: bool,
) -> Result<bool, SqliteClientError> {
    // An account without an Orchard key holds no one-time keys, so it has nothing to do.
    let Some(owner) = one_time_account(conn, params, account)? else {
        return Ok(false);
    };
    let (enabled, current) = token(conn, owner.0)?;
    let repair: bool = conn.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_keys k
        WHERE k.account_id = ?1 AND {REPAIR_KEY})"
        ),
        [owner.0],
        |r| r.get(0),
    )?;
    if (!enabled && !repair)
        || publication.history_revision < current.history_revision
        || !accepts(conn, params, publication)?
    {
        return Ok(false);
    }
    // Repairing receipts an earlier release or an earlier enable left needs progress even
    // while disabled. An account with no one-time state never gets here.
    ensure_account(conn, owner.0)?;
    // This client captured the publication, so the service speaks a format it supports.
    conn.execute(
        "UPDATE ironwood_one_time_recovery SET upgrade_required = 0 WHERE account_id = ?1",
        [owner.0],
    )?;
    let height = u32::from(publication.end.height);
    if publication.history_revision > current.history_revision {
        correct(conn, params, owner.0, publication.history_revision, height)?;
    }
    if !enabled {
        let keys = conn
            .prepare(&format!(
                "SELECT k.id FROM ironwood_one_time_keys k
            WHERE k.account_id = ?1 AND {REPAIR_KEY}"
            ))?
            .query_map([owner.0], |r| r.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for key in keys {
            enqueue(conn, key, activation(params), height, AUTOMATIC)?;
        }
        return Ok(true);
    }
    ensure_window(conn, params, account)?;
    recover_refund_memos(conn, params, account)?;
    conn.execute(
        "UPDATE ironwood_one_time_recovery SET restore_height = COALESCE(restore_height, ?2)
        WHERE account_id = ?1",
        params![owner.0, height],
    )?;
    if complete {
        // Advancing the frontier can age refund keys out of monitoring.
        fencing_monitoring(conn, params, &[owner.0], || {
            for key in monitored_keys(conn, params, owner.0)? {
                cover(conn, params, key, height, AUTOMATIC)?;
            }
            conn.execute(
                "UPDATE ironwood_one_time_recovery SET pir_coverage = 1,
                 filter_height = CASE WHEN COALESCE(filter_height, 0) <= ?2 THEN ?2 ELSE filter_height END,
                 filter_hash = CASE WHEN COALESCE(filter_height, 0) <= ?2 THEN ?3 ELSE filter_hash END
                 WHERE account_id = ?1",
                params![owner.0, height, publication.end.hash],
            )?;
            Ok(())
        })?;
    }
    progress(conn, params, account)?;
    Ok(true)
}

/// Applies an indexing correction to `revision`. A correction can replace payments without
/// changing any block hash, so nothing checked under the old revision is trusted: filter
/// coverage restarts from activation, for the account's frontier and every key, and lookup
/// results are voided. Filters, or a complete check if the caller starts one, then cover
/// discovery again, and a hit queues its key. Pending lookups keep their obligation and read their whole history
/// again. A key with an open reservation is held and read again through `height`, since it
/// may have been paid in the corrected history.
fn correct<P: Parameters>(
    conn: &Connection,
    params: &P,
    owner: i64,
    revision: u64,
    height: u32,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_one_time_recovery SET history_revision = ?2, generation = generation + 1,
        filter_height = NULL, filter_hash = NULL, fresh = 0, pir_coverage = 0,
        restore_next = CASE WHEN restore_done = 0 THEN X'0000000000000000' ELSE restore_next END,
        restore_gap = CASE WHEN restore_done = 0 THEN 0 ELSE restore_gap END,
        manual_purpose = CASE WHEN manual_end IS NOT NULL THEN 0 ELSE manual_purpose END,
        manual_next = CASE WHEN manual_end IS NOT NULL THEN X'0000000000000000' ELSE manual_next END
        WHERE account_id = ?1",
        params![owner, revision.to_be_bytes()],
    )?;
    // Corrections void negatives, cursors and completions captured under the old
    // generation, including progress between shards. An active request may have been
    // started after such a completion, so it needs its whole history again. Settled history
    // needs no lookup: filters check it again.
    conn.execute(
        &format!(
            "UPDATE ironwood_one_time_lookups SET {CURSOR_RESET}, checked_height = NULL,
        start_height = CASE WHEN target_height IS NOT NULL THEN MIN(start_height, ?2)
            ELSE start_height END,
        done_height = NULL, done_from = NULL, read_complete = 0,
        reasons = CASE WHEN target_height IS NOT NULL
            AND (done_height IS NOT NULL OR checked_height IS NOT NULL)
            THEN reasons | 4 ELSE reasons END
        WHERE one_time_key_id IN (SELECT id FROM ironwood_one_time_keys WHERE account_id = ?1)"
        ),
        params![owner, activation(params)],
    )?;
    conn.execute(
        "DELETE FROM ironwood_one_time_payment_recovery WHERE one_time_key_id IN
        (SELECT id FROM ironwood_one_time_keys WHERE account_id = ?1)",
        [owner],
    )?;
    // An open reservation's receiver may be paid in the corrected history, so it is held
    // until a lookup reads it again.
    let keys = conn
        .prepare(&format!(
            "SELECT k.id FROM ironwood_one_time_keys k WHERE k.account_id = ?1 AND {}
             AND k.purpose = 1 AND k.used = 0 AND {}",
            monitored(conn, params, owner)?,
            super::super::swap::RESERVED
        ))?
        .query_map([owner], |r| r.get::<_, i64>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for key in keys {
        enqueue(
            conn,
            key,
            activation(params),
            height,
            AUTOMATIC | INVALIDATED,
        )?;
    }
    crate::wallet::one_time_rewind::queue_invalidated(conn, Some(height))?;
    conn.execute(
        "UPDATE ironwood_one_time_keys SET covered_height = NULL WHERE account_id = ?1",
        [owner],
    )?;
    Ok(())
}

/// How long after its funding block a refund key with no local operation on this device,
/// such as one recovered from a funding memo, stays in automatic monitoring, in 75-second
/// reference blocks. 1Click documents no bound from funding to refund, so this is 7 days.
pub(in crate::wallet::one_time_ivk) const MEMO_REFUND_WINDOW: u32 =
    7 * 24 * 60 * 60 / SECONDS_PER_BLOCK;

/// The highest funding height of a refund key with no local operation that has left
/// automatic monitoring, as of `owner`'s filter frontier (see [`aged_cutoff`]). `None`
/// while the account has no frontier.
fn memo_refund_cutoff<P: Parameters>(
    conn: &Connection,
    params: &P,
    owner: i64,
) -> Result<Option<u32>, SqliteClientError> {
    let frontier: Option<u32> = conn
        .query_row(
            "SELECT filter_height FROM ironwood_one_time_recovery WHERE account_id = ?1",
            [owner],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    Ok(frontier.and_then(|frontier| aged_cutoff(BlockSpacing::for_network(params), frontier)))
}

/// The highest height more than [`MEMO_REFUND_WINDOW`] of chain time before `frontier` on a
/// chain with `spacing`, if any. Filters have checked that whole window after it.
pub(in crate::wallet::one_time_ivk) fn aged_cutoff(
    spacing: BlockSpacing,
    frontier: u32,
) -> Option<u32> {
    let aged = |height: u32| spacing.exceeds(height.into(), frontier.into(), MEMO_REFUND_WINDOW);
    if !aged(0) {
        return None;
    }
    // `aged` holds up to the cutoff and fails above it, at `frontier` itself at the latest.
    let (mut held, mut failed) = (0, frontier);
    while failed - held > 1 {
        let middle = held + (failed - held) / 2;
        if aged(middle) {
            held = middle;
        } else {
            failed = middle;
        }
    }
    Some(held)
}

/// SQL over key alias `k`: a refund key out of automatic monitoring, given its account's
/// [`memo_refund_cutoff`]. Either every local operation on it is conclusive, the provider
/// having reported that no refund is coming or the expected refund being received and
/// settled, or it has no local operation and was funded at or below `cutoff`. Neither holds
/// while a dispute, repair work or payment candidate is left. Refund keys are never reused,
/// so it only leaves automatic monitoring; a manual history check still covers it.
fn refund_retired(cutoff: Option<u32>) -> String {
    let aged = cutoff.map_or_else(|| "0".to_owned(), |c| format!("k.funding_height <= {c}"));
    format!(
        "(k.purpose = 0
    AND CASE WHEN EXISTS(SELECT 1 FROM ironwood_one_time_operations o WHERE o.one_time_key_id = k.id)
        THEN NOT EXISTS(SELECT 1 FROM ironwood_one_time_operations o WHERE o.one_time_key_id = k.id
            AND NOT ((o.expectation = 1 AND o.observed_at > 0) OR o.expectation = 2))
        ELSE {aged} END
    AND NOT {UNSETTLED} AND NOT {REPAIR_KEY}
    AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
        WHERE p.one_time_key_id = k.id))"
    )
}

/// SQL over key alias `k` and owner `?1`: the key is monitored automatically, a receive
/// index below the enrolled automatic end or a funded refund key not yet retired (see
/// [`refund_retired`]). Receive keys a manual check derived beyond that end are checked
/// only by that search.
fn monitored<P: Parameters>(
    conn: &Connection,
    params: &P,
    owner: i64,
) -> Result<String, SqliteClientError> {
    Ok(format!(
        "(k.purpose = 1 AND k.key_index < (SELECT receive_end
        FROM ironwood_one_time_recovery WHERE account_id = ?1)
    OR (k.funding_height IS NOT NULL AND NOT {}))",
        refund_retired(memo_refund_cutoff(conn, params, owner)?)
    ))
}

/// The account's automatically monitored keys, ordered (see [`monitored`]).
fn monitored_keys<P: Parameters>(
    conn: &Connection,
    params: &P,
    owner: i64,
) -> Result<Vec<i64>, SqliteClientError> {
    Ok(conn
        .prepare(&format!(
            "SELECT k.id FROM ironwood_one_time_keys k WHERE k.account_id = ?1 AND {}
             ORDER BY k.id",
            monitored(conn, params, owner)?
        ))?
        .query_map([owner], |r| r.get(0))?
        .collect::<Result<_, _>>()?)
}

/// Runs `change` and advances the generation of each account whose monitored keys it
/// changed, so a filter request captured with the old receiver set cannot commit.
///
/// Every key `change` adds to monitoring, by enrollment, funding evidence, a newer status,
/// a dispute or any other path, gets its history queued through the processed frontier
/// (see [`register_history`]) in the same transaction. Filters already passed blocks where
/// it was not watched, such as a payment to a refund key while it was retired.
pub(in crate::wallet::one_time_ivk) fn fencing_monitoring<P: Parameters, T>(
    conn: &Connection,
    params: &P,
    owners: &[i64],
    change: impl FnOnce() -> Result<T, SqliteClientError>,
) -> Result<T, SqliteClientError> {
    let before = owners
        .iter()
        .map(|owner| monitored_keys(conn, params, *owner))
        .collect::<Result<Vec<_>, _>>()?;
    let result = change()?;
    for (owner, before) in owners.iter().zip(before) {
        let after = monitored_keys(conn, params, *owner)?;
        for key in after.iter().filter(|k| before.binary_search(k).is_err()) {
            register_history(conn, *owner, *key, history_start(conn, params, *key)?)?;
        }
        if after != before {
            conn.execute(
                "UPDATE ironwood_one_time_recovery SET generation = generation + 1
                 WHERE account_id = ?1",
                [owner],
            )?;
        }
    }
    Ok(result)
}

/// Where a key's automatic history starts: a refund key's funding height, or activation for
/// a receive key (see `one_time_ivk::register`).
fn history_start<P: Parameters>(
    conn: &Connection,
    params: &P,
    key: i64,
) -> Result<u32, SqliteClientError> {
    let start: Option<u32> = conn.query_row(
        "SELECT CASE WHEN k.purpose = 1 THEN ?2 ELSE k.funding_height END
         FROM ironwood_one_time_keys k WHERE k.id = ?1",
        params![key, activation(params)],
        |r| r.get(0),
    )?;
    start.ok_or_else(|| invalid("monitored key has no history start"))
}

/// Returns all monitored receivers, each with its filter coverage, and the generation that
/// makes the set current.
pub(crate) fn receivers<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
) -> Result<(RecoveryToken, Vec<FilterReceiver>), SqliteClientError> {
    let Some(owner) = one_time_account(conn, params, account)? else {
        return Ok((NO_RECOVERY, vec![]));
    };
    let (enabled, token) = token(conn, owner.0)?;
    let work = if enabled {
        conn.prepare(&format!(
            "SELECT k.purpose, k.key_index, k.receiver, {} FROM ironwood_one_time_keys k
        WHERE k.account_id = ?1 AND {} ORDER BY k.purpose, k.key_index",
            covered_sql(activation(params)),
            monitored(conn, params, owner.0)?
        ))?
        .query_and_then([owner.0], |r| {
            Ok::<_, SqliteClientError>(FilterReceiver {
                work: DiscoveryWork {
                    key: stored_key_id(r)?,
                    receiver: r
                        .get::<_, Vec<u8>>(2)?
                        .try_into()
                        .map_err(|_| corrupt("invalid receiver"))?,
                },
                covered: BlockHeight::from(r.get::<_, u32>(3)?),
            })
        })?
        .collect::<Result<_, _>>()?
    } else {
        vec![]
    };
    Ok((token, work))
}

/// How far below the wallet's scanned tip a block can no longer be reorganized: Zakura's
/// `MAX_BLOCK_REORG_HEIGHT`, the same before and after NU7. A filter span ending at least
/// this deep commits without a wallet block to compare (see [`record_filter_span`]).
const REORG_LIMIT: u32 = 1000;

/// Checks that `hits` name monitored keys of `owner` at heights in `[from, through]`, and
/// returns each hit's key ID.
fn hit_keys<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    owner: i64,
    (from, through): (u32, u32),
    hits: &[(BlockHeight, KeyId)],
) -> Result<Vec<(u32, i64)>, SqliteClientError> {
    let monitored = monitored(conn, params, owner)?;
    hits.iter()
        .map(|(height, key)| {
            let id = key_ref(conn, account, *key)?;
            let eligible: bool = conn.query_row(
                &format!(
                    "SELECT {monitored} FROM ironwood_one_time_keys k
                     WHERE k.account_id = ?1 AND k.id = ?2"
                ),
                params![owner, id],
                |r| r.get(0),
            )?;
            if !eligible {
                return Err(invalid("filter hit for a key outside automatic monitoring"));
            }
            let height = u32::from(*height);
            if height < from || height > through {
                return Err(invalid("filter hit outside its span"));
            }
            Ok((height, id))
        })
        .collect()
}

/// Queues a lookup for each hit at a height past its key's coverage, from just past that
/// coverage through `through` (see [`cover`]). A hit inside coverage that a pending lookup
/// still has to read marks that lookup invalidated, so the receiver is not reused before
/// it settles; one inside history already checked was handled when that history was.
fn apply_hits<P: Parameters>(
    conn: &Connection,
    params: &P,
    hits: &[(u32, i64)],
    through: u32,
) -> Result<(), SqliteClientError> {
    for (height, id) in hits {
        if *height > covered(conn, params, *id)? {
            cover(conn, params, *id, through, AUTOMATIC | INVALIDATED)?;
        } else {
            conn.execute(
                "UPDATE ironwood_one_time_lookups SET reasons = reasons | ?3
                 WHERE one_time_key_id = ?1 AND target_height >= ?2 AND reasons & 3 != 0",
                params![id, height, INVALIDATED],
            )?;
        }
    }
    Ok(())
}

/// Restarts `owner`'s filter coverage from activation, for its frontier and every key.
fn restart_coverage(conn: &Connection, owner: i64) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_one_time_recovery SET filter_height = NULL, filter_hash = NULL,
         generation = generation + 1 WHERE account_id = ?1",
        [owner],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_keys SET covered_height = NULL WHERE account_id = ?1",
        [owner],
    )?;
    Ok(())
}

/// Commits a filter span matched against the receivers captured with `captured`.
///
/// The span must be final for the wallet: its end is a block the wallet scanned (at or
/// below its fully scanned height) with the same hash, or at least [`REORG_LIMIT`] blocks
/// below the wallet's scanned tip. A wallet block at the end with another hash refuses it.
/// The span must also continue committed coverage: it starts just past the account's
/// frontier with that frontier's hash as its parent (any parent at activation, where an
/// account without a frontier starts), or replays from inside committed coverage, as a
/// chunk sealed since does, with the wallet's own block before it as its parent. A replay
/// whose parent the wallet cannot check restarts coverage from activation.
///
/// A newer revision applies the correction (see [`correct`]). Committing advances every
/// monitored key whose coverage reaches the span's start to its end, and a hit past a key's
/// coverage queues a lookup from there (see [`apply_hits`]). Keys behind the span keep
/// their coverage and need a re-check (see [`recheck_filters`]).
pub(crate) fn record_filter_span<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    captured: RecoveryToken,
    span: &FilterSpan,
    hits: &[(BlockHeight, KeyId)],
) -> Result<FilterOutcome, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let (enabled, current) = token(conn, owner.0)?;
    if enabled && span.revision > current.history_revision {
        let tip: Option<u32> =
            conn.query_row("SELECT MAX(height) FROM blocks", [], |r| r.get(0))?;
        correct(conn, params, owner.0, span.revision, tip.unwrap_or(0))?;
        return Ok(FilterOutcome::Restart);
    }
    if !enabled || current != captured || span.revision != current.history_revision {
        return Ok(FilterOutcome::Stale);
    }
    let start = activation(params);
    let (from, end) = (u32::from(span.from), u32::from(span.end.height));
    if from < start || end < from {
        return Err(invalid("filter span outside receiver history"));
    }
    let hits = hit_keys(conn, params, account, owner.0, (from, end), hits)?;
    let own = wallet::get_block_hash(conn, span.end.height)?;
    if own.is_some_and(|own| own != span.end.hash) {
        return Ok(FilterOutcome::Mismatch);
    }
    let held =
        own.is_some() && wallet::fully_scanned_height(conn)?.is_some_and(|h| span.end.height <= h);
    let stable = scanned_tip(conn)?
        .is_some_and(|tip| u32::from(tip.height) >= end.saturating_add(REORG_LIMIT));
    if !held && !stable {
        return Ok(FilterOutcome::Wait);
    }
    let frontier: Option<(u32, [u8; 32])> = conn.query_row(
        "SELECT filter_height, filter_hash FROM ironwood_one_time_recovery WHERE account_id = ?1",
        [owner.0],
        |r| {
            Ok(r.get::<_, Option<u32>>(0)?
                .zip(r.get::<_, Option<[u8; 32]>>(1)?))
        },
    )?;
    let last = frontier.map_or(start.saturating_sub(1), |(height, _)| height);
    if from > last.saturating_add(1) {
        return Err(invalid("filter span leaves a gap after committed coverage"));
    }
    if end <= last {
        // Another commit already passed this span.
        return Ok(FilterOutcome::Stale);
    }
    if from == last + 1 {
        if frontier.is_some_and(|(_, hash)| hash != span.parent.0) {
            return Ok(FilterOutcome::Mismatch);
        }
    } else if from > start {
        match wallet::get_block_hash(conn, BlockHeight::from(from - 1))? {
            Some(own) if own == span.parent => {}
            Some(_) => return Ok(FilterOutcome::Mismatch),
            None => {
                restart_coverage(conn, owner.0)?;
                return Ok(FilterOutcome::Restart);
            }
        }
    }
    // Advancing the frontier can age refund keys out of monitoring.
    fencing_monitoring(conn, params, &[owner.0], || {
        apply_hits(conn, params, &hits, end)?;
        conn.execute(
            &format!(
                "UPDATE ironwood_one_time_keys SET covered_height = ?2 WHERE id IN
                 (SELECT k.id FROM ironwood_one_time_keys k WHERE k.account_id = ?1 AND {}
                  AND {covered} >= ?3 AND {covered} < ?2)",
                monitored(conn, params, owner.0)?,
                covered = covered_sql(start)
            ),
            params![owner.0, end, from - 1],
        )?;
        conn.execute(
            "UPDATE ironwood_one_time_recovery SET filter_height = ?2, filter_hash = ?3,
             pir_coverage = 0, restore_height = COALESCE(restore_height, ?2)
             WHERE account_id = ?1",
            params![owner.0, end, span.end.hash.0],
        )?;
        Ok(())
    })?;
    progress(conn, params, account)?;
    Ok(FilterOutcome::Committed)
}

/// Commits a re-check of `keys` over `[from, through]` of committed coverage, matched
/// against ranges the caller kept, so a key that became watched after filters passed that
/// history needs no new download. Each key's coverage must reach `from - 1`, and `through`
/// must not pass the account's frontier. The ranges were fenced when their span committed,
/// so no chain check applies. Each key's coverage then reaches `through`, and a hit past it
/// queues a lookup (see [`apply_hits`]). False if `captured` or `revision` is stale.
#[allow(clippy::too_many_arguments)]
pub(crate) fn recheck_filters<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    captured: RecoveryToken,
    revision: u64,
    (from, through): (u32, u32),
    keys: &[KeyId],
    hits: &[(BlockHeight, KeyId)],
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    if token(conn, owner.0)? != (true, captured) || revision != captured.history_revision {
        return Ok(false);
    }
    let frontier: Option<u32> = conn.query_row(
        "SELECT filter_height FROM ironwood_one_time_recovery WHERE account_id = ?1",
        [owner.0],
        |r| r.get(0),
    )?;
    if from < activation(params) || through < from || frontier.is_none_or(|f| through > f) {
        return Err(invalid("filter re-check outside committed coverage"));
    }
    let checked: Vec<_> = keys
        .iter()
        .map(|key| (BlockHeight::from(from), *key))
        .collect();
    let ids: Vec<i64> = hit_keys(conn, params, account, owner.0, (from, through), &checked)?
        .into_iter()
        .map(|(_, id)| id)
        .collect();
    for id in &ids {
        if covered(conn, params, *id)?.saturating_add(1) < from {
            return Err(invalid("filter re-check leaves a gap in a key's coverage"));
        }
    }
    let hits = hit_keys(conn, params, account, owner.0, (from, through), hits)?;
    if hits.iter().any(|(_, hit)| !ids.contains(hit)) {
        return Err(invalid("filter re-check hit for a key it did not check"));
    }
    apply_hits(conn, params, &hits, through)?;
    for id in ids {
        conn.execute(
            "UPDATE ironwood_one_time_keys SET covered_height = MAX(COALESCE(covered_height, 0), ?2)
             WHERE id = ?1",
            params![id, through],
        )?;
    }
    progress(conn, params, account)?;
    Ok(true)
}

/// Settles fully admitted requests and advances seed recovery only across genuine completed answers.
fn progress<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let owner = wallet::get_account_ref(conn, account)?;
    // A complete replacement history can retire orphaned payment evidence. Operation
    // ownership remains independent, so a live quote still prevents address recycling, and
    // a promised receipt the chain no longer holds keeps the address out of reuse.
    conn.execute(&format!("UPDATE ironwood_one_time_keys SET used = 0
        WHERE account_id = ?1 AND prebirthday_height IS NULL AND used = 1
        AND id NOT IN (SELECT k.id FROM ironwood_one_time_keys k WHERE k.account_id = ?1 AND {UNSETTLED})
        AND NOT EXISTS(SELECT 1 FROM ironwood_received_notes n JOIN transactions t
            ON t.id_tx = n.transaction_id WHERE n.one_time_key_id = ironwood_one_time_keys.id AND t.mined_height IS NOT NULL)
        AND EXISTS(SELECT 1 FROM ironwood_one_time_lookups l WHERE l.one_time_key_id = ironwood_one_time_keys.id
            AND l.read_complete = 1 AND l.done_height >= l.target_height)
        AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p WHERE p.one_time_key_id = ironwood_one_time_keys.id)"), [owner.0])?;
    conn.execute("UPDATE ironwood_one_time_lookups SET target_height = NULL, reasons = 0
        WHERE read_complete = 1 AND done_height >= target_height AND one_time_key_id IN
            (SELECT id FROM ironwood_one_time_keys WHERE account_id = ?1)
        AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p WHERE p.one_time_key_id = ironwood_one_time_lookups.one_time_key_id)", [owner.0])?;
    if !token(conn, owner.0)?.0 {
        return Ok(());
    }
    let mut handed = None;
    let pir = recovery_flag(conn, owner.0, "pir_coverage")? == Some(true);
    for _ in 0..STEP_BUDGET {
        let (height, next, gap, done): (Option<u32>, Vec<u8>, u8, bool) = conn.query_row(
            "SELECT restore_height, restore_next, restore_gap, restore_done FROM ironwood_one_time_recovery WHERE account_id = ?1",
            [owner.0], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        let Some(height) = height.filter(|_| !done) else {
            handed = None;
            break;
        };
        let next = decode_index(next)?;
        let (id, _) = register(conn, params, account, KeyId::new(Purpose::Receive, next))?;
        // The walk advances on authenticated use before confirmation, so its reach must
        // outlast a reorg that removes that use.
        enroll(conn, params, owner.0, index_after(next, 1)?)?;
        // An empty counts only with complete history from activation through the frontier,
        // so the four empties share compatible captured coverage. That is a completed
        // lookup, or filter coverage with no lookup left to run.
        let checked: Option<bool> = conn.query_row(&format!("SELECT k.used FROM ironwood_one_time_keys k
            WHERE k.id = ?1
            AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p WHERE p.one_time_key_id = k.id)
            AND (EXISTS(SELECT 1 FROM ironwood_one_time_lookups l WHERE l.one_time_key_id = k.id
                    AND l.done_height >= ?2 AND l.done_from <= ?3 AND l.target_height IS NULL
                    AND l.read_complete = 1)
                OR ({} >= ?2 AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
                    WHERE l.one_time_key_id = k.id AND l.target_height IS NOT NULL)))",
            covered_sql(activation(params))),
            params![id, height, activation(params)], |r| r.get(0)).optional()?;
        let Some(paid) = checked else {
            // Without a complete check behind the frontier, filters re-check the key.
            if pir && cover(conn, params, id, height, AUTOMATIC)? {
                // A settled key can carry the continuation if the budget runs out.
                handed = Some((id, height));
                continue;
            }
            handed = None;
            break;
        };
        let gap = if paid { 0 } else { gap + 1 };
        conn.execute("UPDATE ironwood_one_time_recovery SET restore_next = ?2, restore_gap = ?3, restore_done = ?4 WHERE account_id = ?1",
            params![owner.0, index_after(next, 1)?.to_be_bytes(), gap, gap == RECEIVE_GAP as u8])?;
        if gap == RECEIVE_GAP as u8 {
            handed = None;
            break;
        }
        handed = Some((id, height));
    }
    if let Some((id, height)) = handed {
        hand_off(conn, id, height, AUTOMATIC)?;
    }
    ensure_window(conn, params, account)?;
    manual_progress(conn, params, account)?;
    Ok(())
}

/// Leaves a runnable continuation when a budgeted step stops with local work left. The
/// worker only runs exposed lookups and witnesses, so `key`, whose history is already
/// complete, becomes due again through `height`. Its answer runs progress, which resumes
/// the cursor with a fresh budget.
fn hand_off(conn: &Connection, key: i64, height: u32, reason: u8) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_one_time_lookups SET target_height = MAX(COALESCE(target_height, 0), ?2),
        reasons = reasons | ?3, last_record = NULL, read_complete = 0, attempts = 0,
        next_attempt_at = 0 WHERE one_time_key_id = ?1",
        params![key, height, reason],
    )?;
    Ok(())
}

/// Starts a bounded historical job or resumes its durable cursor after cancellation.
/// A completed job starts again through the newly captured publication.
pub(crate) fn manual<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    publication: RecoveryPublication,
    receive_end: Option<u64>,
) -> Result<bool, SqliteClientError> {
    // Like any disabled account, one without an Orchard key or progress searches nothing.
    let Some(owner) = one_time_account(conn, params, account)? else {
        return Ok(false);
    };
    if !token(conn, owner.0)?.0 || !begin(conn, params, account, publication, false)? {
        return Ok(false);
    }
    let (owner, _) = account_key(conn, params, account)?;
    let (phase, next, old_end, old_height): (u8, Vec<u8>, Option<Vec<u8>>, Option<u32>) = conn
        .query_row(
            "SELECT manual_purpose, manual_next, manual_end, manual_height
         FROM ironwood_one_time_recovery WHERE account_id = ?1",
            [owner.0],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
    let old_end = old_end.map(decode_index).transpose()?;
    let next = decode_index(next)?;
    let resume = old_end.is_some_and(|end| phase == 0 || next < end);
    let end = receive_end.unwrap_or(automatic_end(conn, owner.0)?);
    let end = if resume {
        end.max(old_end.expect("resuming existing job"))
    } else {
        end
    };
    if end == 0 {
        return Err(invalid("manual receive bound must be positive"));
    }
    conn.execute(
        "UPDATE ironwood_one_time_recovery SET manual_active = 1,
        generation = generation + 1, manual_purpose = ?2, manual_next = ?3,
        manual_end = ?4, manual_height = ?5 WHERE account_id = ?1",
        params![
            owner.0,
            if resume { phase } else { 0 },
            if resume { next } else { 0 }.to_be_bytes(),
            end.to_be_bytes(),
            if resume {
                old_height.ok_or_else(|| corrupt("manual job has no frontier"))?
            } else {
                u32::from(publication.end.height)
            }
        ],
    )?;
    manual_progress(conn, params, account)?;
    Ok(true)
}

/// Cancels only manual work. Durable filter positives keep their automatic queue reason.
pub(crate) fn cancel_manual<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    conn.execute(
        "UPDATE ironwood_one_time_recovery SET manual_active = 0, generation = generation + 1
        WHERE account_id = ?1",
        [owner.0],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_lookups SET reasons = reasons & ?2
        WHERE one_time_key_id IN (SELECT id FROM ironwood_one_time_keys WHERE account_id = ?1)",
        params![owner.0, AUTOMATIC | INVALIDATED],
    )?;
    // A monitored key re-checked only by the search still owes its held reservation a read.
    crate::wallet::one_time_rewind::queue_invalidated(conn, None)?;
    Ok(())
}

/// Advances explicit history checks without applying seed restore's four-empty stopping rule.
fn manual_progress<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let owner = wallet::get_account_ref(conn, account)?;
    let mut handed = None;
    for _ in 0..STEP_BUDGET {
        let job: Option<(u8, Vec<u8>, Vec<u8>, u32)> = conn.query_row(
            "SELECT manual_purpose, manual_next, manual_end, manual_height
             FROM ironwood_one_time_recovery WHERE account_id = ?1 AND enabled = 1 AND manual_active = 1",
            [owner.0], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).optional()?;
        let Some((purpose, next, end, height)) = job else {
            handed = None;
            break;
        };
        let next = decode_index(next)?;
        let end = decode_index(end)?;
        // Completed entries are skipped in one query, so a resumed or extended job usually
        // reaches runnable work long before the budget runs out.
        let key = if purpose == 0 {
            conn.query_row(
                &format!(
                    "SELECT k.key_index FROM ironwood_one_time_keys k
                WHERE k.account_id = :owner AND k.purpose = 0 AND k.funding_height IS NOT NULL
                AND k.key_index >= :next AND NOT {CHECKED_THROUGH} ORDER BY k.key_index LIMIT 1"
                ),
                named_params![":owner": owner.0, ":next": next.to_be_bytes(), ":height": height,
                    ":from": activation(params)],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|bytes| decode_index(bytes).map(|index| KeyId::new(Purpose::Refund, index)))
            .transpose()?
        } else if next < end {
            let completed: Vec<(Vec<u8>, i64)> = conn
                .prepare(&format!(
                    "SELECT k.key_index, k.id FROM ironwood_one_time_keys k
                WHERE k.account_id = :owner AND k.purpose = 1 AND k.key_index >= :next
                AND k.key_index < :end AND {CHECKED_THROUGH} ORDER BY k.key_index"
                ))?
                .query_map(
                    named_params![":owner": owner.0, ":next": next.to_be_bytes(),
                    ":end": end.to_be_bytes(), ":height": height, ":from": activation(params)],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?
                .collect::<Result<_, _>>()?;
            let mut first = next;
            for (index, id) in completed {
                if decode_index(index)? != first {
                    break;
                }
                first = index_after(first, 1)?;
                handed = Some((id, height));
            }
            if first > next {
                conn.execute(
                    "UPDATE ironwood_one_time_recovery SET manual_next = ?2 WHERE account_id = ?1",
                    params![owner.0, first.to_be_bytes()],
                )?;
                continue;
            }
            Some(KeyId::new(Purpose::Receive, next))
        } else {
            None
        };
        let Some(key) = key else {
            if purpose == 0 {
                conn.execute(
                    "UPDATE ironwood_one_time_recovery SET manual_purpose = 1,
                    manual_next = X'0000000000000000' WHERE account_id = ?1",
                    [owner.0],
                )?;
                continue;
            }
            conn.execute(
                "UPDATE ironwood_one_time_recovery SET manual_active = 0 WHERE account_id = ?1",
                [owner.0],
            )?;
            handed = None;
            break;
        };
        let existed: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_keys
            WHERE account_id = ?1 AND purpose = ?2 AND key_index = ?3)",
            params![
                owner.0,
                super::super::purpose_code(key.purpose())?,
                key.index().to_be_bytes()
            ],
            |r| r.get(0),
        )?;
        let (id, _) = register(conn, params, account, key)?;
        // Derivation requested solely by an extended manual job must remain cancellable.
        if !existed
            && key.purpose() == Purpose::Receive
            && key.index() >= automatic_end(conn, owner.0)?
        {
            conn.execute(
                "UPDATE ironwood_one_time_lookups SET reasons = ?2 WHERE one_time_key_id = ?1",
                params![id, MANUAL],
            )?;
        }
        let checked: bool = conn.query_row(
            &format!("SELECT {CHECKED_THROUGH} FROM ironwood_one_time_keys k WHERE k.id = :id"),
            named_params![":id": id, ":height": height, ":from": activation(params)],
            |r| r.get(0),
        )?;
        if !checked {
            if enqueue(conn, id, activation(params), height, MANUAL)? {
                // A settled key can carry the continuation if the budget runs out.
                handed = Some((id, height));
                continue;
            }
            handed = None;
            break;
        }
        conn.execute(
            "UPDATE ironwood_one_time_recovery SET manual_next = ?2 WHERE account_id = ?1",
            params![owner.0, index_after(key.index(), 1)?.to_be_bytes()],
        )?;
        handed = Some((id, height));
    }
    if let Some((id, height)) = handed {
        hand_off(conn, id, height, MANUAL)?;
    }
    Ok(())
}

/// Reads a persisted record using the same strict codec as the network boundary.
fn decode_record(bytes: Option<Vec<u8>>) -> Result<Option<DirectoryRecord>, SqliteClientError> {
    bytes
        .map(|bytes| {
            DirectoryRecord::decode(&bytes)
                .ok()
                .flatten()
                .ok_or_else(|| corrupt("invalid recovery cursor"))
        })
        .transpose()
}

/// Lookup columns, over alias `l`, that [`progress_of`] reads from a row starting at an offset.
const PROGRESS: &str =
    "l.start_height, l.checked_height, l.inventory, l.shard, l.segment, l.last_record";

/// A request's first unchecked height and its cursor, from the [`PROGRESS`] columns starting
/// at `at`.
fn progress_of(
    row: &rusqlite::Row<'_>,
    at: usize,
) -> Result<(BlockHeight, Option<LookupCursor>), SqliteClientError> {
    let start: u32 = row.get(at)?;
    let checked: Option<u32> = row.get(at + 1)?;
    let inventory: Option<[u8; 32]> = row.get(at + 2)?;
    let cursor = inventory
        .map(|inventory| {
            Ok::<_, SqliteClientError>(LookupCursor {
                inventory,
                shard: row.get(at + 3)?,
                segment: row.get(at + 4)?,
                last: decode_record(row.get(at + 5)?)?,
            })
        })
        .transpose()?;
    let from = checked.map_or(start, |c| start.max(c.saturating_add(1)));
    Ok((BlockHeight::from(from), cursor))
}

/// The status of an account that never enabled recovery: disabled, with no progress and no
/// work.
fn disabled() -> RecoveryStatus {
    RecoveryStatus {
        enabled: false,
        upgrade_required: false,
        token: NO_RECOVERY,
        filter_frontier: None,
        fresh: true,
        restore_next: 0,
        restore_gap: 0,
        restore_complete: false,
        manual: None,
        lookups: vec![],
        witnesses: vec![],
    }
}

/// Exposes bounded due work. Disabled accounts expose only repair of already-owned receipts.
pub(crate) fn status<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<RecoveryStatus, SqliteClientError> {
    // A pure read: an account without an Orchard key or a progress row is disabled.
    let Some(owner) = one_time_account(conn, params, account)? else {
        return Ok(disabled());
    };
    let (enabled, token) = token(conn, owner.0)?;
    let Some(mut status) = conn.query_row("SELECT filter_height, filter_hash, fresh,
        restore_next, restore_gap, restore_done, manual_active, manual_purpose, manual_next, manual_end,
        upgrade_required
        FROM ironwood_one_time_recovery WHERE account_id = ?1", [owner.0], |r| {
        let height: Option<u32> = r.get(0)?;
        let next: [u8; 8] = r.get(3)?;
        let manual_next: [u8; 8] = r.get(8)?;
        let manual_end: Option<[u8; 8]> = r.get(9)?;
        Ok(RecoveryStatus { enabled, upgrade_required: r.get(10)?, token,
            filter_frontier: height.map(|height| Ok::<_, rusqlite::Error>(ChainPoint {
                height: height.into(), hash: BlockHash(r.get(1)?) })).transpose()?,
            fresh: r.get(2)?,
            restore_next: u64::from_be_bytes(next), restore_gap: r.get(4)?, restore_complete: r.get(5)?,
            manual: manual_end.map(|end| Ok::<_, rusqlite::Error>(ManualProgress { active: r.get(6)?,
                refunds_done: r.get::<_, u8>(7)? == 1, next: u64::from_be_bytes(manual_next),
                receive_end: u64::from_be_bytes(end) })).transpose()?, lookups: vec![], witnesses: vec![] })
    }).optional()? else {
        return Ok(disabled());
    };
    status.lookups = conn.prepare(&format!("SELECT k.purpose, k.key_index, k.receiver, l.target_height, {PROGRESS}
        FROM ironwood_one_time_lookups l JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
        WHERE k.account_id = ?1 AND l.target_height IS NOT NULL AND l.reasons & 3 != 0
            AND (?3 OR {REPAIR_KEY})
            AND l.read_complete = 0 AND l.next_attempt_at <= ?2 ORDER BY l.next_attempt_at, k.id LIMIT 4"))?
        .query_and_then(params![owner.0, now, enabled], |r| {
            let (from, cursor) = progress_of(r, 4)?;
            Ok::<_, SqliteClientError>(LookupWork {
                token, work: DiscoveryWork { key: stored_key_id(r)?,
                    receiver: r.get::<_, Vec<u8>>(2)?.try_into().map_err(|_| corrupt("invalid receiver"))? },
                from, through: BlockHeight::from(r.get::<_, u32>(3)?), cursor,
            })
        })?.collect::<Result<_, _>>()?;
    if status.upgrade_required {
        // Nothing this client could ask would be answered in a format it reads.
        status.lookups.clear();
        return Ok(status);
    }
    status.witnesses = conn.prepare(&format!("SELECT k.purpose, k.key_index, p.position, substr(p.encrypted_note, 33, 32),
            p.payments, p.witnesses, p.ordinal
        FROM ironwood_one_time_payment_recovery p JOIN ironwood_one_time_keys k ON k.id = p.one_time_key_id
        WHERE k.account_id = ?1 AND p.witness IS NULL AND p.payments IS NOT NULL
        AND (?2 OR EXISTS(SELECT 1 FROM ironwood_received_notes n JOIN transactions t ON t.id_tx = n.transaction_id
            WHERE n.one_time_key_id = k.id AND t.txid = p.txid AND n.action_index = p.action_index AND {UNPLACED})
            OR EXISTS(SELECT 1 FROM ironwood_one_time_disputed_receipts d
                JOIN ironwood_received_notes n ON n.id = d.note_id WHERE n.one_time_key_id = k.id))
        AND EXISTS(SELECT 1 FROM ironwood_one_time_lookups l WHERE l.one_time_key_id = k.id AND l.reasons & 3 != 0)
        ORDER BY p.height, p.position LIMIT 64"))?
        .query_and_then(params![owner.0, enabled], |r| Ok::<_, SqliteClientError>(WitnessRequest {
            key: stored_key_id(r)?, position: r.get(2)?, cmx: r.get(3)?, payments: r.get(4)?,
            witnesses: r.get(5)?, ordinal: r.get(6)?
        }))?.collect::<Result<_, _>>()?;
    Ok(status)
}

/// Rejects stale callbacks before accepting any cursor, candidate or negative answer. A
/// step's progress counts only under the inventory it was captured with; a cursor from a
/// replaced inventory is never resumed, and shards are skipped only when the step covered
/// them.
pub(crate) fn record_lookup<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    sessions: &Sessions<'_>,
    account: AccountUuid,
    work: &LookupWork,
    page: &LookupPage,
    now: i64,
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let id = key_ref(conn, account, work.work.key)?;
    let publication = page.publication;
    if !can_lookup(conn, owner.0, id, work.token)?
        || publication.history_revision != work.token.history_revision
        || publication.end.height < work.through
        || !accepts(conn, params, publication)?
        || page.records.len() > RECOVERY_PAGE_LIMIT
    {
        return Ok(false);
    }
    let receiver: Vec<u8> = conn.query_row(
        "SELECT receiver FROM ironwood_one_time_keys WHERE id = ?1",
        [id],
        |r| r.get(0),
    )?;
    if receiver != work.work.receiver {
        return Err(invalid("lookup receiver does not belong to the key"));
    }
    #[allow(clippy::type_complexity)]
    let current: Option<(
        u32,
        Option<u32>,
        Option<u32>,
        u32,
        BlockHeight,
        Option<LookupCursor>,
    )> = conn
        .query_row(
            &format!(
                "SELECT l.target_height, l.done_height, l.done_from, {PROGRESS}
                 FROM ironwood_one_time_lookups l WHERE l.one_time_key_id = ?1 AND l.reasons & 3 != 0
                   AND l.target_height IS NOT NULL AND l.read_complete = 0"
            ),
            [id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    progress_of(r, 3),
                ))
            },
        )
        .optional()?
        .map(|(target, done, done_from, start, progress)| {
            progress.map(|(from, cursor)| (target, done, done_from, start, from, cursor))
        })
        .transpose()?;
    let Some((target, done, done_from, start, from, cursor)) = current else {
        return Ok(false);
    };
    if target < u32::from(work.through) || from != work.from || cursor != work.cursor {
        return Ok(false);
    }
    // A step continues the saved segment only under the same inventory and position.
    let resumed = cursor.as_ref().filter(|c| {
        c.inventory == publication.id
            && page
                .segment
                .is_some_and(|s| (s.shard, s.segment) == (c.shard, c.segment))
    });
    // The step's coverage and continuation must follow from its position and what it read
    // (see `LookupPage::valid_step`), so it can never mark unread history checked.
    if !page.valid_step(work) {
        return Err(invalid("inconsistent receiver lookup step"));
    }
    let mut previous = resumed.and_then(|c| c.last.as_ref());
    for record in &page.records {
        let expected = previous.map_or(Some(0), |p| p.page.checked_add(1));
        if record.receiver != work.work.receiver
            || record.encode().is_err()
            || Some(record.page) != expected
            || previous.is_some_and(|p| {
                p.total != record.total
                    || p.payment.position >= record.payment.position
                    || (p.payment.height, p.payment.tx_index, p.payment.action_index)
                        >= (
                            record.payment.height,
                            record.payment.tx_index,
                            record.payment.action_index,
                        )
                    || (p.payment.height == record.payment.height
                        && p.payment.block_hash != record.payment.block_hash)
                    || (p.payment.height == record.payment.height
                        && p.payment.tx_index == record.payment.tx_index
                        && p.payment.txid != record.payment.txid)
            })
            || record.payment.height < u32::from(publication.start_height)
            || record.payment.height > u32::from(publication.end.height)
            || record.payment.position >= publication.end.tree_size
            || record.payment.tx_index == 0
        {
            return Err(invalid("invalid receiver history page"));
        }
        let candidate = directory_candidate(&record.payment)
            .ok_or_else(|| invalid("invalid receiver payment"))?;
        authenticate(conn, params, account, work.work.key, &candidate)?;
        previous = Some(record);
    }
    let discovery_enabled = token(conn, owner.0)?.0;
    // A candidate returns a retired key to monitoring, and completed history can end a
    // displaced receipt's repair (see `REPAIR_KEY`), so the page applies inside the fence.
    fencing_monitoring(conn, params, &[owner.0], || {
        if let Some(segment) = page.segment {
            for record in &page.records {
                let candidate = directory_candidate(&record.payment).expect("validated above");
                if (discovery_enabled
                    || repairable(conn, params, account, work.work.key, id, &candidate)?)
                    && !admitted(conn, id, &candidate)?
                {
                    queue_payment(
                        conn,
                        params,
                        account,
                        work.work.key,
                        &candidate,
                        (segment.payments, segment.witnesses, record.ordinal),
                    )?;
                }
            }
        }
        if let Some(next) = &page.next {
            let last = next
                .last
                .as_ref()
                .map(|r| {
                    r.encode()
                        .map(|b| b.to_vec())
                        .map_err(|_| invalid("invalid cursor"))
                })
                .transpose()?;
            conn.execute(
                "UPDATE ironwood_one_time_lookups SET checked_height = COALESCE(?2, checked_height),
                inventory = ?3, shard = ?4, segment = ?5, last_record = ?6, attempts = 0,
                next_attempt_at = 0 WHERE one_time_key_id = ?1",
                params![
                    id,
                    page.checked_through.map(u32::from),
                    next.inventory,
                    next.shard,
                    next.segment,
                    last
                ],
            )?;
        } else {
            let end = u32::from(publication.end.height);
            // Coverage joins an earlier completion only when the two spans meet.
            let joined = done
                .zip(done_from)
                .filter(|(d, f)| *f <= start && start <= d.saturating_add(1))
                .map_or(start, |(_, f)| f);
            conn.execute(
                &format!(
                    "UPDATE ironwood_one_time_lookups SET checked_height = ?2, {CURSOR_RESET},
                    read_complete = ?3, done_height = CASE WHEN ?4 THEN ?2 ELSE NULL END,
                    done_from = CASE WHEN ?4 THEN ?5 ELSE NULL END, attempts = 0,
                    next_attempt_at = 0 WHERE one_time_key_id = ?1"
                ),
                params![id, end, end >= target, discovery_enabled, joined],
            )?;
            // A candidate this history did not bind again still lacks a usable witness, so the
            // read cannot settle the key: its shard is read again later.
            let unbound: Option<u32> = conn.query_row(
                "SELECT MIN(height) FROM ironwood_one_time_payment_recovery
                 WHERE one_time_key_id = ?1 AND payments IS NULL",
                [id],
                |r| r.get(0),
            )?;
            if let Some(height) = unbound {
                rewind_lookup(conn, id, height, now.saturating_add(60))?;
            }
        }
        Ok(())
    })?;
    admit(conn, params, sessions, account, now)?;
    progress(conn, params, account)?;
    Ok(true)
}

/// Records that the receiver service answered in a protocol this client does not support,
/// so recovery waits for an app update instead of retrying. No lookup, candidate, cursor or
/// obligation changes; [`begin`] with a publication this client captured clears it.
pub(crate) fn require_upgrade<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    // An account without progress has no work to hold back, and one already waiting needs
    // no write (see `set_enabled`).
    let Some(owner) = one_time_account(conn, params, account)? else {
        return Ok(());
    };
    if recovery_flag(conn, owner.0, "upgrade_required")? == Some(false) {
        conn.execute(
            "UPDATE ironwood_one_time_recovery SET upgrade_required = 1 WHERE account_id = ?1",
            [owner.0],
        )?;
    }
    Ok(())
}

/// Reads `column`, one of the recovery row's flags, for `owner`, or `None` when the account
/// has no progress row.
fn recovery_flag(
    conn: &Connection,
    owner: i64,
    column: &'static str,
) -> Result<Option<bool>, SqliteClientError> {
    Ok(conn
        .query_row(
            &format!("SELECT {column} FROM ironwood_one_time_recovery WHERE account_id = ?1"),
            [owner],
            |r| r.get(0),
        )
        .optional()?)
}

/// Backs off a failed request without counting it as an empty or completed history.
pub(crate) fn defer<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    work: &LookupWork,
    now: i64,
) -> Result<(), SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let id = key_ref(conn, account, work.work.key)?;
    if !can_lookup(conn, owner.0, id, work.token)? {
        return Ok(());
    }
    #[allow(clippy::type_complexity)]
    let current: Option<(
        u32,
        Result<(BlockHeight, Option<LookupCursor>), SqliteClientError>,
    )> = conn
        .query_row(
            &format!(
                "SELECT l.attempts, {PROGRESS} FROM ironwood_one_time_lookups l
                 WHERE l.one_time_key_id = ?1 AND l.target_height = ?2 AND l.reasons & 3 != 0
                   AND l.read_complete = 0"
            ),
            params![id, u32::from(work.through)],
            |r| Ok((r.get(0)?, progress_of(r, 1))),
        )
        .optional()?;
    let Some((attempts, progress)) = current else {
        return Ok(());
    };
    if progress? != (work.from, work.cursor.clone()) {
        return Ok(());
    }
    let delay = (60i64 << attempts.min(10)).min(43_200);
    conn.execute("UPDATE ironwood_one_time_lookups SET attempts = MIN(attempts + 1, 30), next_attempt_at = ?2 WHERE one_time_key_id = ?1",
        params![id, now.saturating_add(delay)])?;
    Ok(())
}

/// The candidate `request` names, if it still waits for a witness under the same binding
/// and `captured` is current. Disabled accounts reach only already-owned unmined receipts.
fn requested(
    conn: &Connection,
    owner: i64,
    key: i64,
    captured: RecoveryToken,
    request: &WitnessRequest,
) -> Result<Option<(TxId, u32, BlockHeight)>, SqliteClientError> {
    let (enabled, current) = token(conn, owner)?;
    if current != captured {
        return Ok(None);
    }
    let found: Option<(Vec<u8>, u32, u32)> = conn
        .query_row(
            &format!("SELECT p.txid, p.action_index, p.height
        FROM ironwood_one_time_payment_recovery p WHERE p.one_time_key_id = ?1 AND p.position = ?2
            AND substr(p.encrypted_note, 33, 32) = ?3 AND p.payments = ?4 AND p.ordinal = ?5
            AND p.witnesses = ?7 AND p.witness IS NULL AND (?6 OR EXISTS(SELECT 1 FROM transactions t
                JOIN ironwood_received_notes n ON n.transaction_id = t.id_tx
                WHERE t.txid = p.txid AND n.one_time_key_id = p.one_time_key_id
                    AND n.action_index = p.action_index AND {UNPLACED})
                OR EXISTS(SELECT 1 FROM ironwood_one_time_disputed_receipts d
                    JOIN ironwood_received_notes n2 ON n2.id = d.note_id
                    WHERE n2.one_time_key_id = p.one_time_key_id))"),
            params![
                key,
                request.position,
                request.cmx,
                request.payments,
                request.ordinal,
                enabled,
                request.witnesses
            ],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    found
        .map(|(txid, action, height)| {
            Ok((
                TxId::from_bytes(txid.try_into().map_err(|_| corrupt("invalid txid"))?),
                action,
                BlockHeight::from(height),
            ))
        })
        .transpose()
}

/// Attaches a witness under the same account fence and session binding, then applies
/// ordinary inclusion and spend checks. A malformed payload is refused, never stored.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_witness<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    sessions: &Sessions<'_>,
    account: AccountUuid,
    captured: RecoveryToken,
    request: WitnessRequest,
    answer: &WitnessAnswer,
    now: i64,
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    if token(conn, owner.0)?.1 != captured {
        return Ok(false);
    }
    let id = key_ref(conn, account, request.key)?;
    // An answer from another companion, even for the same payment session, needs the
    // payment read again first (see `refresh`).
    if answer.payments != request.payments || answer.revision != request.witnesses {
        return Ok(false);
    }
    if decode_witness_payload(
        &answer.payload,
        u64::from(request.position),
        answer.context.tree_size,
    )
    .is_err()
    {
        return Err(invalid("malformed witness payload"));
    }
    if requested(conn, owner.0, id, captured, &request)?.is_some() {
        conn.execute(
            "UPDATE ironwood_one_time_payment_recovery SET witness = ?6,
            witness_height = ?8, witness_hash = ?9, witness_size = ?10
            WHERE one_time_key_id = ?1 AND position = ?2 AND substr(encrypted_note, 33, 32) = ?3
                AND payments = ?4 AND ordinal = ?5 AND witnesses = ?7 AND witness IS NULL",
            params![
                id,
                request.position,
                request.cmx,
                request.payments,
                request.ordinal,
                answer.payload.as_slice(),
                answer.revision,
                u32::from(answer.context.height),
                answer.context.hash,
                answer.context.tree_size
            ],
        )?;
    } else if !token(conn, owner.0)?.0 {
        return Ok(false);
    }
    admit(conn, params, sessions, account, now)?;
    progress(conn, params, account)?;
    Ok(true)
}

/// Re-reads the history of a candidate whose session can no longer answer its witness
/// request, keeping the candidate pending. False if the request is stale.
pub(crate) fn refresh<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    captured: RecoveryToken,
    request: WitnessRequest,
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let id = key_ref(conn, account, request.key)?;
    let Some((txid, action, height)) = requested(conn, owner.0, id, captured, &request)? else {
        return Ok(false);
    };
    refresh_witness(conn, id, txid, action, height, 0)?;
    Ok(true)
}

/// Ordinary sync can repair already-owned receipts while discovery is disabled.
pub(crate) fn after_blocks_stored<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    sessions: &Sessions<'_>,
    now: i64,
) -> Result<(), SqliteClientError> {
    check_deferred_receipts(conn, params)?;
    // Enabling recovery validated each account's key, so the steps below look up only its
    // row and leave decoding it, about 0.4 ms, to the rare calls that register a key.
    let accounts: Vec<(AccountUuid, bool)> = conn
        .prepare(
            "SELECT a.uuid, r.enabled FROM accounts a
        JOIN ironwood_one_time_recovery r ON r.account_id = a.id",
        )?
        .query_map([], |r| Ok((AccountUuid(r.get(0)?), r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    for (account, enabled) in accounts {
        if enabled {
            recover_refund_memos(conn, params, account)?;
        }
        admit(conn, params, sessions, account, now)?;
        progress(conn, params, account)?;
    }
    Ok(())
}

/// The deferred raw receipt checks and their transaction IDs. Every scan batch runs this,
/// so the queue, almost always empty, drives the join: SQLite would otherwise walk the
/// whole transaction index probing it once per row.
pub(in crate::wallet::one_time_ivk) const DEFERRED_RECEIPTS: &str =
    "SELECT u.transaction_id, t.txid FROM ironwood_one_time_unchecked_raw u
     CROSS JOIN transactions t ON t.id_tx = u.transaction_id";

/// Checks the raw bytes a build without Orchard stored for a private receipt's transaction
/// (see `ironwood_hooks::defer_receipt_check`), as fetching them here would, then clears the
/// private enhancement work they supersede.
fn check_deferred_receipts<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
) -> Result<(), SqliteClientError> {
    let deferred: Vec<(i64, TxId)> = conn
        .prepare(DEFERRED_RECEIPTS)?
        .query_map([], |r| Ok((r.get(0)?, TxId::from_bytes(r.get(1)?))))?
        .collect::<Result<_, _>>()?;
    for (id, txid) in deferred {
        if let Some((_, tx)) = crate::wallet::get_transaction(conn, params, txid)? {
            // These raw bytes are already stored.
            check_raw_receipts(conn, params, &tx, || Ok(()))?;
            crate::wallet::ironwood_hooks::clear_ironwood_enhancement_work(conn, crate::TxRef(id))?;
        }
        conn.execute(
            "DELETE FROM ironwood_one_time_unchecked_raw WHERE transaction_id = ?1",
            [id],
        )?;
    }
    Ok(())
}

/// Checks every one-time note admitted from the directory under `tx`'s ID against the raw
/// transaction with `action_holds`, the check admission applies when the raw transaction
/// arrives first. The directory authenticates the note and its position but not its transaction
/// label, so a mismatch disputes the receipt's label: the note row stays with its spends,
/// witness and position, nothing that trusts a transaction ID counts it, and its key's history
/// is read again, even while discovery is disabled, until admission moves it to its true
/// transaction (see `apply::apply_payment`). `store` then keeps `tx`'s raw bytes either way,
/// so a repeated mislabeled record is refused at admission. It runs inside the same fence,
/// since the expiry height those bytes record can end a displaced receipt's repair (see
/// [`REPAIR_KEY`]).
pub(crate) fn check_raw_receipts<P: Parameters>(
    conn: &Connection,
    params: &P,
    tx: &zcash_primitives::transaction::Transaction,
    store: impl FnOnce() -> Result<(), SqliteClientError>,
) -> Result<(), SqliteClientError> {
    // A disputed refund receipt returns its key to automatic monitoring.
    let owners: Vec<i64> = conn
        .prepare(
            "SELECT DISTINCT k.account_id FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             JOIN ironwood_one_time_keys k ON k.id = n.one_time_key_id
             WHERE t.txid = ?1",
        )?
        .query_map([tx.txid().as_ref()], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    fencing_monitoring(conn, params, &owners, || {
        dispute_raw_receipts(conn, activation(params), tx)?;
        store()
    })
}

/// [`check_raw_receipts`] without the monitoring fence.
fn dispute_raw_receipts(
    conn: &Connection,
    activation: u32,
    tx: &zcash_primitives::transaction::Transaction,
) -> Result<(), SqliteClientError> {
    let notes: Vec<(i64, i64, i64)> = conn
        .prepare(
            "SELECT n.id, n.one_time_key_id, k.account_id
             FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             JOIN ironwood_one_time_keys k ON k.id = n.one_time_key_id
             WHERE t.txid = ?1 AND n.compact_ciphertext IS NOT NULL",
        )?
        .query_map([tx.txid().as_ref()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<Result<_, _>>()?;
    let mut kept = false;
    let mut disputed = false;
    for (note, key, owner) in notes {
        let carried = stored_action(conn, note)?
            .is_some_and(|(action, stored)| action_holds(tx, action, &stored));
        if carried {
            kept = true;
            continue;
        }
        // Inclusion authenticates the note's value and nullifier, so its row, spends, witness
        // and position stay; only its label is disputed until its history yields the true one.
        conn.execute(
            "INSERT OR IGNORE INTO ironwood_one_time_disputed_receipts (note_id) VALUES (?1)",
            [note],
        )?;
        // Private enhancement bound to this output trusts the disputed label.
        conn.execute(
            "UPDATE ironwood_enhance_metadata_queue SET commitment_tree_position = NULL,
                output_index = NULL, compact_bound = 0
             WHERE (transaction_id, output_index) =
                 (SELECT transaction_id, action_index FROM ironwood_received_notes WHERE id = ?1)",
            [note],
        )?;
        // Where the true record lies is unknown: the label's mined height is a mutable
        // claim about the disputed transaction, not the note's placement. So the key's
        // whole history is read again from activation, through the current frontier.
        rewind_lookup(conn, key, activation, 0)?;
        invalidate(conn, key)?;
        queue_history(conn, owner, key, activation)?;
        crate::wallet::one_time_rewind::queue_invalidated(conn, None)?;
        disputed = true;
    }
    if disputed && !kept {
        // Nothing trusts this transaction as a private receipt any more, so its private
        // enhancement work goes too.
        let tx_ref: Option<i64> = conn
            .query_row(
                "SELECT id_tx FROM transactions WHERE txid = ?1",
                [tx.txid().as_ref()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(tx_ref) = tx_ref {
            wallet::enhance_pir::clear_work(conn, crate::TxRef(tx_ref))?;
            conn.execute(
                "DELETE FROM ironwood_enhance_routing WHERE transaction_id = ?1",
                [tx_ref],
            )?;
        }
    }
    Ok(())
}

/// A witnessed candidate waiting for admission: its key's registry ID and identity, its
/// transaction and action, and its witness payload, height, block hash and tree size.
type Waiting = (i64, KeyId, TxId, u32, Vec<u8>, u32, [u8; 32], u64);

/// Admits active candidates once their inclusion proof and ordinary spend coverage are usable.
pub(in crate::wallet::one_time_ivk) fn admit<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    sessions: &Sessions<'_>,
    account: AccountUuid,
    now: i64,
) -> Result<(), SqliteClientError> {
    let Some(through) = scanned_tip(conn)? else {
        return Ok(());
    };
    let owner = wallet::get_account_ref(conn, account)?;
    let waiting: Vec<Waiting> = conn
        .prepare(
            "SELECT k.purpose, k.key_index, k.id, p.txid, p.action_index, p.witness,
                 p.witness_height, p.witness_hash, p.witness_size
             FROM ironwood_one_time_payment_recovery p
             JOIN ironwood_one_time_keys k ON k.id = p.one_time_key_id
             WHERE k.account_id = ?1 AND p.witness IS NOT NULL
               AND EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
                   WHERE l.one_time_key_id = k.id AND l.reasons & 3 != 0)
             ORDER BY p.height, p.position",
        )?
        .query_and_then([owner.0], |r| {
            Ok::<_, SqliteClientError>((
                r.get(2)?,
                stored_key_id(r)?,
                TxId::from_bytes(r.get(3)?),
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
            ))
        })?
        .collect::<Result<_, _>>()?;
    // With nothing waiting nothing changes, so a quiet batch skips the fence's two reads.
    if waiting.is_empty() {
        return Ok(());
    }
    // Settling a refund, or a relabel ending a dispute, can retire a refund key from
    // automatic monitoring.
    fencing_monitoring(conn, params, &[owner.0], || {
        admit_waiting(
            conn, params, sessions, account, owner.0, through, waiting, now,
        )
    })
}

/// Admits or settles each of `waiting`, `owner`'s candidates read by [`admit`], against
/// the scanned tip `through`, without the monitoring fence.
#[allow(clippy::too_many_arguments)]
fn admit_waiting<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    sessions: &Sessions<'_>,
    account: AccountUuid,
    owner: i64,
    through: ChainPoint,
    waiting: Vec<Waiting>,
    now: i64,
) -> Result<(), SqliteClientError> {
    for (id, key, txid, action, witness, height, hash, tree_size) in waiting {
        let Some(candidate) = pending_payment(conn, txid, action)? else {
            continue;
        };
        if !token(conn, owner)?.0 && !repairable(conn, params, account, key, id, &candidate)? {
            continue;
        }
        let admission = apply_payment(
            conn,
            sessions,
            params,
            account,
            key,
            &candidate,
            through,
            WitnessPath {
                payload: &witness,
                context: ChainPoint {
                    height: BlockHeight::from(height),
                    hash: BlockHash(hash),
                },
                tree_size,
            },
        )?;
        match admission {
            Admission::Admitted | Admission::Waiting => {}
            Admission::Uncovered => rescan_uncovered(conn, owner, candidate.height, through)?,
            Admission::StaleWitness => refresh_witness(
                conn,
                id,
                txid,
                action,
                candidate.height,
                now.saturating_add(60),
            )?,
            Admission::Rejected => {
                conn.execute(
                    "DELETE FROM ironwood_one_time_payment_recovery
                     WHERE txid = ?1 AND action_index = ?2",
                    params![txid.as_ref(), action],
                )?;
                // Its pages were already read past it, so the coverage that read claimed
                // must be undone before the key can complete. The refused claim's height is
                // unauthenticated, so the key's history is read again from activation.
                rewind_lookup(conn, id, activation(params), now.saturating_add(60))?;
                invalidate(conn, id)?;
                crate::wallet::one_time_rewind::queue_invalidated(conn, None)?;
            }
        }
    }
    Ok(())
}

/// The highest block the scan stored that the scan queue no longer requires.
fn scanned_tip(conn: &Connection) -> Result<Option<ChainPoint>, SqliteClientError> {
    Ok(conn
        .query_row(
            "SELECT b.height, b.hash FROM blocks b WHERE EXISTS(SELECT 1 FROM scan_queue q
                 WHERE q.priority = ?1 AND b.height >= q.block_range_start
                   AND b.height < q.block_range_end)
             ORDER BY b.height DESC LIMIT 1",
            [priority_code(&ScanPriority::Scanned)],
            |r| {
                Ok(ChainPoint {
                    height: BlockHeight::from(r.get::<_, u32>(0)?),
                    hash: BlockHash(r.get(1)?),
                })
            },
        )
        .optional()?)
}

/// Queues for a rescan each stretch from `from` through `through` that the scan finished
/// without covering for account `owner`, as blocks scanned before the journal existed are,
/// so a late payment there is not left waiting for good.
fn rescan_uncovered(
    conn: &rusqlite::Transaction<'_>,
    owner: i64,
    from: BlockHeight,
    through: ChainPoint,
) -> Result<(), SqliteClientError> {
    let covered: Vec<(u32, u32)> = conn
        .prepare(
            "SELECT start_height, end_height FROM ironwood_journal_coverage
             WHERE account_id = ?1 AND end_height > ?2 AND start_height <= ?3
             ORDER BY start_height",
        )?
        .query_map(
            params![owner, u32::from(from), u32::from(through.height)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?
        .collect::<Result<_, _>>()?;
    let end = u32::from(through.height) + 1;
    let mut gaps = vec![];
    let mut next = u32::from(from);
    for (start, stop) in covered {
        if start > next {
            gaps.push(next..start.min(end));
        }
        next = next.max(stop);
    }
    if next < end {
        gaps.push(next..end);
    }
    for gap in gaps {
        // Only a stretch the scan finished; one still queued is covered when it is scanned.
        let finished: bool = conn.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM scan_queue
             WHERE priority != ?3 AND block_range_start < ?2 AND block_range_end > ?1)",
            params![gap.start, gap.end, priority_code(&ScanPriority::Scanned)],
            |r| r.get(0),
        )?;
        if finished {
            crate::wallet::one_time_ivk::queue_rescan(
                conn,
                BlockHeight::from(gap.start)..BlockHeight::from(gap.end),
            )?;
        }
    }
    Ok(())
}
