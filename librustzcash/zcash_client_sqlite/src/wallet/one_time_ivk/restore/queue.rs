//! One durable queue for seed restore, live hints, catch-up and explicit history checks.
use crate::wallet::scanning::priority_code;
use rusqlite::{Connection, OptionalExtension, named_params, params};
use zcash_client_backend::data_api::scanning::ScanPriority;
use zcash_client_backend::data_api::{
    one_time_ivk::restore::{
        DirectoryRecord, DiscoveryWork, LookupPage, LookupWork, ManualProgress, RECEIVE_GAP,
        RECOVERY_PAGE_LIMIT, RecoveryPublication, RecoveryStatus, RecoveryToken, WitnessRequest,
    },
    transparent_ledger::ChainPoint,
};
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use super::{
    apply::{Admission, Sessions, apply_payment, merkle_path},
    payments::{
        action_holds, authenticate, directory_candidate, pending_payment, queue_payment,
        stored_action,
    },
    recovery::recover_refund_memos,
};
use crate::wallet::one_time_ivk::{
    KeyId, Purpose, account_key, corrupt, decode_index, index_after, invalid, key_ref, register,
    stored_key_id,
};
use crate::{AccountUuid, error::SqliteClientError, wallet};

const AUTOMATIC: u8 = 1;
/// Lookup reason bit marking history an event invalidated: a positive filter hint, a
/// correction, a rewind below the settled height, a disputed receipt label, a rejected
/// payment claim or a lowered birthday. The key may have been paid in what was read before,
/// so its receiver is not reused until the lookup settles (see [`RECEIVE_PENDING`]), which
/// clears the bit. Reading new blocks never sets it.
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

/// SQL over receipt alias `n` and its transaction `t`: the receipt's own chain placement is
/// not restored. Placement is per receipt: a rewind clears each private receipt's position
/// (see `one_time_rewind::truncate`), and repairing one receipt marks its whole transaction
/// mined while a sibling receipt still waits for its own position and witness.
const UNPLACED: &str = "(t.mined_height IS NULL OR n.commitment_tree_position IS NULL)";

/// SQL over key alias `k`: an already-owned receipt is [`UNPLACED`], or its transaction
/// label is disputed (see [`check_raw_receipts`]), so it needs repair.
const REPAIR_KEY: &str = "(EXISTS(SELECT 1 FROM ironwood_received_notes n JOIN transactions t
    ON t.id_tx = n.transaction_id WHERE n.one_time_key_id = k.id
    AND (t.mined_height IS NULL OR n.commitment_tree_position IS NULL))
    OR EXISTS(SELECT 1 FROM ironwood_one_time_disputed_receipts d
        JOIN ironwood_received_notes n ON n.id = d.note_id WHERE n.one_time_key_id = k.id))";

/// SQL over key alias `k`: a local operation owes a receipt not yet attributed to it, either
/// a promised one or the possible one of a funded operation that ended inconclusively.
/// Only a mined note in a transaction the provider reported for that operation counts.
/// Chain timing and the absence of other local quotes cannot attribute a payment, since
/// another device's quote may share the address.
const UNSETTLED: &str = "EXISTS(SELECT 1 FROM ironwood_one_time_operations o
    WHERE o.one_time_key_id = k.id AND (o.expectation = 2 OR (o.expectation = 3 AND o.funded = 1))
    AND COALESCE(o.expected_value, 1) > COALESCE((SELECT SUM(n.value)
        FROM ironwood_received_notes n JOIN transactions t ON t.id_tx = n.transaction_id
        JOIN ironwood_one_time_operation_receipts r ON r.operation_id = o.id AND r.txid = t.txid
        WHERE n.one_time_key_id = k.id AND t.mined_height IS NOT NULL
          AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_disputed_receipts d
              WHERE d.note_id = n.id)), 0))";

/// SQL over key alias `k`: a complete lookup checked the key through `:height` and left no
/// candidate waiting for admission.
const CHECKED_THROUGH: &str = "EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
    WHERE l.one_time_key_id = k.id AND l.done_height >= :height AND l.read_complete = 1
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

/// Whether disabled discovery may still admit `candidate` for key `id`: the exact output
/// was already admitted, or its authenticated note is a stored receipt whose transaction
/// label is disputed (see [`check_raw_receipts`]), so the candidate may carry its true label.
fn repairable<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    id: i64,
    candidate: &super::PendingPayment,
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

/// Ensures account progress exists without enabling network work.
pub(crate) fn ensure_account(conn: &Connection, owner: i64) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT OR IGNORE INTO ironwood_one_time_recovery(account_id) VALUES (?1)",
        [owner],
    )?;
    Ok(())
}

/// Reads the cancellation fence and feature setting in the current transaction.
fn token(conn: &Connection, owner: i64) -> Result<(bool, RecoveryToken), SqliteClientError> {
    let (enabled, generation, revision): (bool, u64, Vec<u8>) = conn.query_row(
        "SELECT enabled, generation, history_revision FROM ironwood_one_time_recovery WHERE account_id = ?1",
        [owner], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    Ok((
        enabled,
        RecoveryToken {
            generation,
            history_revision: decode_index(revision)?,
        },
    ))
}

/// Raises a queued target without discarding a previously recorded positive or page cursor.
/// A settled history that already covers `through` stays settled, since no callback would
/// otherwise clear a target nothing needs to query.
pub(crate) fn enqueue(
    conn: &Connection,
    key: i64,
    through: u32,
    reason: u8,
) -> Result<(), SqliteClientError> {
    conn.execute("INSERT INTO ironwood_one_time_lookups(one_time_key_id, target_height, reasons)
        VALUES (?1, ?2, ?3) ON CONFLICT(one_time_key_id) DO UPDATE SET
        target_height = MAX(COALESCE(target_height, 0), excluded.target_height),
        reasons = reasons | excluded.reasons,
        read_complete = CASE WHEN done_height >= excluded.target_height THEN read_complete ELSE 0 END,
        attempts = CASE WHEN target_height IS NULL OR target_height < excluded.target_height THEN 0 ELSE attempts END,
        next_attempt_at = CASE WHEN target_height IS NULL OR target_height < excluded.target_height THEN 0 ELSE next_attempt_at END
        WHERE NOT (ironwood_one_time_lookups.target_height IS NULL
            AND ironwood_one_time_lookups.read_complete = 1
            AND ironwood_one_time_lookups.done_height >= excluded.target_height
            AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
                WHERE p.one_time_key_id = excluded.one_time_key_id))", params![key, through, reason])?;
    Ok(())
}

/// Newly learned receivers must cover history already passed by live filters.
pub(crate) fn register_history(
    conn: &Connection,
    owner: i64,
    key: i64,
) -> Result<(), SqliteClientError> {
    let through: u32 = conn.query_row("SELECT MAX(COALESCE(filter_height, 0),
        COALESCE((SELECT MAX(height) FROM blocks), 0)) FROM ironwood_one_time_recovery WHERE account_id = ?1",
        [owner], |r| r.get(0))?;
    enqueue(conn, key, through, AUTOMATIC)
}

/// Registers only the four lookahead indexes justified by mined payment evidence and
/// enrolls them for automatic discovery (see [`enroll`]).
pub(crate) fn ensure_window<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    ensure_account(conn, owner.0)?;
    let end = super::super::swap::reservations::recovery_end(conn, owner.0)?;
    if end <= enrolled_end(conn, owner.0)? {
        return Ok(());
    }
    for index in end.saturating_sub(RECEIVE_GAP)..end {
        register(conn, params, account, KeyId::new(Purpose::Receive, index))?;
    }
    enroll(conn, owner.0, end)
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
/// mined window or the seed walk reached them. Every newly enrolled index, including
/// one an earlier manual check already derived and completed, gets a historical target
/// through the processed filter frontier. This shares the transaction with filter progress.
///
/// Growing the automatic set advances the generation, as every change to the filter
/// receiver set must: a filter request captured before it never matched the new keys, so
/// its callback must not move the frontier past their blocks.
fn enroll(conn: &Connection, owner: i64, end: u64) -> Result<(), SqliteClientError> {
    let enrolled = enrolled_end(conn, owner)?;
    if end <= enrolled {
        return Ok(());
    }
    let exposed: Vec<i64> = conn
        .prepare(
            "SELECT id FROM ironwood_one_time_keys
            WHERE account_id = ?1 AND purpose = 1 AND key_index >= ?2 AND key_index < ?3",
        )?
        .query_map(
            params![owner, enrolled.to_be_bytes(), end.to_be_bytes()],
            |r| r.get(0),
        )?
        .collect::<Result<_, _>>()?;
    for id in exposed {
        register_history(conn, owner, id)?;
    }
    conn.execute(
        "UPDATE ironwood_one_time_recovery SET receive_end = ?2, generation = generation + 1
        WHERE account_id = ?1",
        params![owner, end.to_be_bytes()],
    )?;
    Ok(())
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

/// Records funded refund evidence and queues its history even if ordinary sync passed it.
pub(crate) fn funded(
    conn: &Connection,
    key: i64,
    height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let changed = conn.execute(
        "UPDATE ironwood_one_time_keys SET funding_height = ?2
        WHERE id = ?1 AND (funding_height IS NULL OR funding_height > ?2)",
        params![key, u32::from(height)],
    )?;
    if changed == 0 {
        return Ok(());
    }
    let owner = conn.query_row(
        "SELECT account_id FROM ironwood_one_time_keys WHERE id = ?1",
        [key],
        |r| r.get(0),
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_recovery SET generation = generation + 1 WHERE account_id = ?1",
        [owner],
    )?;
    register_history(conn, owner, key)
}

/// Pauses work and invalidates in-flight responses without deleting notes or pending requests.
pub(crate) fn set_enabled<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    enabled: bool,
) -> Result<(), SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    ensure_account(conn, owner.0)?;
    let changed = conn.execute(
        "UPDATE ironwood_one_time_recovery SET enabled = ?2, generation = generation + 1
        WHERE account_id = ?1 AND enabled != ?2",
        params![owner.0, enabled],
    )?;
    if changed > 0 && enabled {
        // Repair-only reads may have skipped new receipts. Start their history again
        // before enabled discovery can treat any saved page as complete.
        conn.execute(
            "UPDATE ironwood_one_time_lookups SET last_record = NULL, read_complete = 0
            WHERE done_height IS NULL AND target_height IS NOT NULL AND one_time_key_id IN
                (SELECT id FROM ironwood_one_time_keys WHERE account_id = ?1)",
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

/// Captures a usable frontier. Direct catch-up selects unfinished addresses, never every old
/// paid key, except that a newer correction generation reads every monitored key once.
pub(crate) fn begin<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    publication: RecoveryPublication,
    direct: bool,
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    ensure_account(conn, owner.0)?;
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
    let height = u32::from(publication.end.height);
    if publication.history_revision > current.history_revision {
        conn.execute("UPDATE ironwood_one_time_recovery SET history_revision = ?2, generation = generation + 1,
            filter_height = NULL, filter_hash = NULL,
            restore_next = CASE WHEN restore_done = 0 THEN X'0000000000000000' ELSE restore_next END,
            restore_gap = CASE WHEN restore_done = 0 THEN 0 ELSE restore_gap END,
            manual_purpose = CASE WHEN manual_end IS NOT NULL THEN 0 ELSE manual_purpose END,
            manual_next = CASE WHEN manual_end IS NOT NULL THEN X'0000000000000000' ELSE manual_next END
            WHERE account_id = ?1",
            params![owner.0, publication.history_revision.to_be_bytes()])?;
        conn.execute("UPDATE ironwood_one_time_lookups SET last_record = NULL, done_height = NULL, read_complete = 0,
            reasons = CASE WHEN done_height IS NOT NULL THEN reasons | ?2 ELSE reasons END
            WHERE one_time_key_id IN
            (SELECT id FROM ironwood_one_time_keys WHERE account_id = ?1)", params![owner.0, INVALIDATED])?;
        conn.execute(
            "DELETE FROM ironwood_one_time_payment_recovery WHERE one_time_key_id IN
            (SELECT id FROM ironwood_one_time_keys WHERE account_id = ?1)",
            [owner.0],
        )?;
        // A correction can add a payment the old history left out, even to a used key that
        // direct catch-up would skip, so every monitored key is read again once.
        let keys = conn
            .prepare(&format!(
                "SELECT k.id FROM ironwood_one_time_keys k WHERE k.account_id = ?1 AND {MONITORED}"
            ))?
            .query_map([owner.0], |r| r.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for key in keys {
            enqueue(conn, key, height, AUTOMATIC | INVALIDATED)?;
        }
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
            enqueue(conn, key, height, AUTOMATIC)?;
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
    if direct {
        let keys = direct_keys(conn, owner.0)?;
        for key in keys {
            enqueue(conn, key, height, AUTOMATIC)?;
        }
        conn.execute("UPDATE ironwood_one_time_recovery SET skipped_height = MAX(COALESCE(skipped_height, 0), ?2),
            filter_height = ?2, filter_hash = ?3 WHERE account_id = ?1 AND COALESCE(filter_height, 0) <= ?2",
            params![owner.0, height, publication.end.hash])?;
    }
    progress(conn, params, account)?;
    Ok(true)
}

/// Selects the unfinished/lookahead set used by both catch-up and its bandwidth estimate.
pub(super) fn direct_keys(conn: &Connection, owner: i64) -> Result<Vec<i64>, SqliteClientError> {
    let end = automatic_end(conn, owner)?;
    let keys: Vec<i64> = conn.prepare(&format!("SELECT k.id FROM ironwood_one_time_keys k
            WHERE k.account_id = ?1 AND ((k.purpose = 1 AND (k.key_index < ?2 OR k.reserved_at IS NOT NULL))
                OR (k.purpose = 0 AND k.funding_height IS NOT NULL))
            AND (k.used = 0 OR {REPAIR_KEY} OR {UNSETTLED})"))?
            .query_map(params![owner, end.to_be_bytes()], |r| r.get(0))?.collect::<Result<_, _>>()?;
    Ok(keys)
}

/// SQL over key alias `k` and owner `?1`: the key is monitored automatically, a receive
/// index below the enrolled automatic end or a funded key. Receive keys a manual check
/// derived beyond that end are checked only by that search.
const MONITORED: &str = "(k.purpose = 1 AND k.key_index < (SELECT receive_end
        FROM ironwood_one_time_recovery WHERE account_id = ?1)
    OR k.funding_height IS NOT NULL)";

/// Returns all known eligible receivers with the generation that makes the set current.
pub(crate) fn receivers<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
) -> Result<(RecoveryToken, Vec<DiscoveryWork>), SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let (enabled, token) = token(conn, owner.0)?;
    let work = if enabled {
        conn.prepare(&format!(
            "SELECT k.purpose, k.key_index, k.receiver FROM ironwood_one_time_keys k
        WHERE k.account_id = ?1 AND {MONITORED} ORDER BY k.purpose, k.key_index"
        ))?
        .query_and_then([owner.0], |r| {
            Ok::<_, SqliteClientError>(DiscoveryWork {
                key: stored_key_id(r)?,
                receiver: r
                    .get::<_, Vec<u8>>(2)?
                    .try_into()
                    .map_err(|_| corrupt("invalid receiver"))?,
            })
        })?
        .collect::<Result<_, _>>()?
    } else {
        vec![]
    };
    Ok((token, work))
}

/// Commits locally matched hints only if every block and the captured receiver set remain current.
pub(crate) fn record_filters<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    captured: RecoveryToken,
    revision: u64,
    blocks: &[ChainPoint],
    hits: &[KeyId],
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    if token(conn, owner.0)? != (true, captured)
        || revision != captured.history_revision
        || blocks.is_empty()
        || blocks.len() > 256
    {
        return Ok(false);
    }
    let previous: Option<u32> = conn.query_row(
        "SELECT filter_height FROM ironwood_one_time_recovery WHERE account_id = ?1",
        [owner.0],
        |r| r.get(0),
    )?;
    let Some(previous) = previous else {
        return Ok(false);
    };
    for (i, block) in blocks.iter().enumerate() {
        if u64::from(u32::from(block.height)) != u64::from(previous) + 1 + i as u64
            || wallet::get_block_hash(conn, block.height)? != Some(block.hash)
        {
            return Ok(false);
        }
    }
    let end = blocks.last().expect("nonempty");
    for key in hits {
        let id = key_ref(conn, account, *key)?;
        let eligible: bool = conn.query_row(
            &format!("SELECT {MONITORED} FROM ironwood_one_time_keys k WHERE k.account_id = ?1 AND k.id = ?2"),
            params![owner.0, id],
            |r| r.get(0),
        )?;
        if !eligible {
            return Err(invalid("filter hit for a key outside automatic monitoring"));
        }
        enqueue(conn, id, u32::from(end.height), AUTOMATIC | INVALIDATED)?;
    }
    conn.execute("UPDATE ironwood_one_time_recovery SET filter_height = ?2, filter_hash = ?3 WHERE account_id = ?1",
        params![owner.0, u32::from(end.height), end.hash.0])?;
    Ok(true)
}

/// Settles fully admitted requests and advances seed recovery only across genuine completed answers.
fn progress<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
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
        enroll(conn, owner.0, index_after(next, 1)?)?;
        let checked: Option<bool> = conn.query_row("SELECT k.used FROM ironwood_one_time_keys k
            JOIN ironwood_one_time_lookups l ON l.one_time_key_id = k.id WHERE k.id = ?1
            AND l.done_height >= ?2 AND l.target_height IS NULL AND l.read_complete = 1
            AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p WHERE p.one_time_key_id = k.id)",
            params![id, height], |r| r.get(0)).optional()?;
        let Some(paid) = checked else {
            enqueue(conn, id, height, AUTOMATIC)?;
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
    let (owner, _) = account_key(conn, params, account)?;
    ensure_account(conn, owner.0)?;
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
    Ok(())
}

/// Advances explicit history checks without applying seed restore's four-empty stopping rule.
fn manual_progress<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
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
                named_params![":owner": owner.0, ":next": next.to_be_bytes(), ":height": height],
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
                    ":end": end.to_be_bytes(), ":height": height],
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
            named_params![":id": id, ":height": height],
            |r| r.get(0),
        )?;
        if !checked {
            enqueue(conn, id, height, MANUAL)?;
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

/// Exposes bounded due work. Disabled accounts expose only repair of already-owned receipts.
pub(crate) fn status<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<RecoveryStatus, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    ensure_account(conn, owner.0)?;
    let (enabled, token) = token(conn, owner.0)?;
    let mut status = conn.query_row("SELECT filter_height, filter_hash, skipped_height,
        restore_next, restore_gap, restore_done, manual_active, manual_purpose, manual_next, manual_end
        FROM ironwood_one_time_recovery WHERE account_id = ?1", [owner.0], |r| {
        let height: Option<u32> = r.get(0)?;
        let next: [u8; 8] = r.get(3)?;
        let manual_next: [u8; 8] = r.get(8)?;
        let manual_end: Option<[u8; 8]> = r.get(9)?;
        Ok(RecoveryStatus { enabled, token,
            filter_frontier: height.map(|height| Ok::<_, rusqlite::Error>(ChainPoint {
                height: height.into(), hash: BlockHash(r.get(1)?) })).transpose()?,
            skipped_through: r.get::<_, Option<u32>>(2)?.map(Into::into),
            restore_next: u64::from_be_bytes(next), restore_gap: r.get(4)?, restore_complete: r.get(5)?,
            manual: manual_end.map(|end| Ok::<_, rusqlite::Error>(ManualProgress { active: r.get(6)?,
                refunds_done: r.get::<_, u8>(7)? == 1, next: u64::from_be_bytes(manual_next),
                receive_end: u64::from_be_bytes(end) })).transpose()?, lookups: vec![], witnesses: vec![] })
    })?;
    status.lookups = conn.prepare(&format!("SELECT k.purpose, k.key_index, k.receiver, l.target_height, l.last_record
        FROM ironwood_one_time_lookups l JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
        WHERE k.account_id = ?1 AND l.target_height IS NOT NULL AND l.reasons != 0
            AND (?3 OR {REPAIR_KEY})
            AND l.read_complete = 0 AND l.next_attempt_at <= ?2 ORDER BY l.next_attempt_at, k.id LIMIT 4"))?
        .query_and_then(params![owner.0, now, enabled], |r| Ok::<_, SqliteClientError>(LookupWork {
            token, work: DiscoveryWork { key: stored_key_id(r)?,
                receiver: r.get::<_, Vec<u8>>(2)?.try_into().map_err(|_| corrupt("invalid receiver"))? },
            through: BlockHeight::from(r.get::<_, u32>(3)?), last: decode_record(r.get(4)?)?
        }))?.collect::<Result<_, _>>()?;
    status.witnesses = conn.prepare(&format!("SELECT k.purpose, k.key_index, p.position, substr(p.encrypted_note, 33, 32)
        FROM ironwood_one_time_payment_recovery p JOIN ironwood_one_time_keys k ON k.id = p.one_time_key_id
        WHERE k.account_id = ?1 AND p.witness IS NULL
        AND (?2 OR EXISTS(SELECT 1 FROM ironwood_received_notes n JOIN transactions t ON t.id_tx = n.transaction_id
            WHERE n.one_time_key_id = k.id AND t.txid = p.txid AND n.action_index = p.action_index AND {UNPLACED})
            OR EXISTS(SELECT 1 FROM ironwood_one_time_disputed_receipts d
                JOIN ironwood_received_notes n ON n.id = d.note_id WHERE n.one_time_key_id = k.id))
        AND EXISTS(SELECT 1 FROM ironwood_one_time_lookups l WHERE l.one_time_key_id = k.id AND l.reasons != 0
            AND l.next_attempt_at <= ?3)
        ORDER BY p.height, p.position LIMIT 64"))?
        .query_and_then(params![owner.0, enabled, now], |r| Ok::<_, SqliteClientError>(WitnessRequest {
            key: stored_key_id(r)?, position: r.get(2)?, cmx: r.get(3)?
        }))?.collect::<Result<_, _>>()?;
    Ok(status)
}

/// Rejects stale callbacks before accepting any cursor, candidate or negative answer.
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
    if !can_lookup(conn, owner.0, id, work.token)?
        || page.publication.history_revision != work.token.history_revision
        || page.publication.end.height < work.through
        || !accepts(conn, params, page.publication)?
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
    let current: Option<(Option<u32>, Option<Vec<u8>>, bool)> = conn.query_row(
        "SELECT target_height, last_record, read_complete FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1 AND reasons != 0",
        [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?;
    let Some((Some(target), last, false)) = current else {
        return Ok(false);
    };
    if target < u32::from(work.through) || decode_record(last)? != work.last {
        return Ok(false);
    }
    match (&work.last, &page.previous) {
        (None, None) => {}
        (Some(old), Some(new))
            if new.encode().is_ok()
                && old.receiver == new.receiver
                && old.page == new.page
                && old.payment == new.payment
                && new.total >= old.total => {}
        _ => {
            conn.execute("UPDATE ironwood_one_time_lookups SET last_record = NULL WHERE one_time_key_id = ?1", [id])?;
            return Ok(false);
        }
    }
    let mut previous = page.previous.as_ref();
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
            || record.payment.height < u32::from(page.publication.start_height)
            || record.payment.height > u32::from(page.publication.end.height)
            || record.payment.position >= page.publication.end.tree_size
            || record.payment.tx_index == 0
        {
            return Err(invalid("invalid receiver history page"));
        }
        let candidate = directory_candidate(&record.payment)
            .ok_or_else(|| invalid("invalid receiver payment"))?;
        authenticate(conn, params, account, work.work.key, &candidate)?;
        previous = Some(record);
    }
    let ended = previous.is_none_or(|p| p.page.checked_add(1) == Some(p.total));
    if page.complete != ended || (page.records.is_empty() && !page.complete) {
        return Err(invalid(
            "incomplete receiver history advertised as complete",
        ));
    }
    let discovery_enabled = token(conn, owner.0)?.0;
    for record in &page.records {
        let candidate = directory_candidate(&record.payment).expect("validated above");
        if discovery_enabled || repairable(conn, params, account, work.work.key, id, &candidate)? {
            queue_payment(conn, params, account, work.work.key, &candidate)?;
        }
    }
    let last = previous
        .map(|r| {
            r.encode()
                .map(|b| b.to_vec())
                .map_err(|_| invalid("invalid cursor"))
        })
        .transpose()?;
    conn.execute("UPDATE ironwood_one_time_lookups SET last_record = ?2, read_complete = ?3,
        done_height = CASE WHEN NOT ?6 THEN NULL WHEN ?5 THEN ?4 ELSE done_height END, attempts = 0, next_attempt_at = 0 WHERE one_time_key_id = ?1",
        params![id, last, page.complete && u32::from(page.publication.end.height) >= target,
            u32::from(page.publication.end.height), page.complete, discovery_enabled])?;
    admit(conn, params, sessions, account, now)?;
    progress(conn, params, account)?;
    Ok(true)
}

/// Backs off a failed request without counting it as an empty or completed history.
pub(crate) fn defer(
    conn: &Connection,
    account: AccountUuid,
    work: &LookupWork,
    now: i64,
) -> Result<(), SqliteClientError> {
    let owner: i64 = conn.query_row(
        "SELECT id FROM accounts WHERE uuid = ?1",
        [account.0],
        |r| r.get(0),
    )?;
    let id = key_ref(conn, account, work.work.key)?;
    if !can_lookup(conn, owner, id, work.token)? {
        return Ok(());
    }
    let current: Option<(u32, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT attempts, last_record FROM ironwood_one_time_lookups
         WHERE one_time_key_id = ?1 AND target_height = ?2 AND reasons != 0 AND read_complete = 0",
            params![id, u32::from(work.through)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((attempts, last)) = current else {
        return Ok(());
    };
    if decode_record(last)? != work.last {
        return Ok(());
    }
    let delay = (60i64 << attempts.min(10)).min(43_200);
    conn.execute("UPDATE ironwood_one_time_lookups SET attempts = MIN(attempts + 1, 30), next_attempt_at = ?2 WHERE one_time_key_id = ?1",
        params![id, now.saturating_add(delay)])?;
    Ok(())
}

/// Attaches a proof under the same account fence, then applies ordinary inclusion and spend checks.
pub(crate) fn record_witness<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    sessions: &Sessions<'_>,
    account: AccountUuid,
    captured: RecoveryToken,
    request: WitnessRequest,
    anchor: ChainPoint,
    siblings: [[u8; 32]; 32],
    now: i64,
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let (enabled, current) = token(conn, owner.0)?;
    if current != captured {
        return Ok(false);
    }
    let id = key_ref(conn, account, request.key)?;
    if !enabled {
        let known: bool = conn.query_row(&format!("SELECT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
            JOIN transactions t ON t.txid = p.txid JOIN ironwood_received_notes n ON n.transaction_id = t.id_tx
            WHERE p.one_time_key_id = ?1 AND p.position = ?2 AND substr(p.encrypted_note, 33, 32) = ?3
                AND n.one_time_key_id = p.one_time_key_id AND n.action_index = p.action_index AND {UNPLACED})
            OR EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
                JOIN ironwood_received_notes n ON n.one_time_key_id = p.one_time_key_id
                JOIN ironwood_one_time_disputed_receipts d ON d.note_id = n.id
                WHERE p.one_time_key_id = ?1 AND p.position = ?2 AND substr(p.encrypted_note, 33, 32) = ?3)"),
            params![id, request.position, request.cmx], |r| r.get(0))?;
        if !known {
            return Ok(false);
        }
    }
    conn.execute("UPDATE ironwood_one_time_payment_recovery SET witness = ?3, witness_height = ?4, witness_hash = ?5
        WHERE one_time_key_id = ?1 AND position = ?2 AND substr(encrypted_note, 33, 32) = ?6",
        params![id, request.position, siblings.concat(), u32::from(anchor.height), anchor.hash.0, request.cmx])?;
    admit(conn, params, sessions, account, now)?;
    progress(conn, params, account)?;
    Ok(true)
}

/// Ordinary sync can repair already-owned receipts while discovery is disabled.
pub(crate) fn after_blocks_stored<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    sessions: &Sessions<'_>,
    now: i64,
) -> Result<(), SqliteClientError> {
    let accounts: Vec<AccountUuid> = conn
        .prepare(
            "SELECT a.uuid FROM accounts a
        JOIN ironwood_one_time_recovery r ON r.account_id = a.id",
        )?
        .query_map([], |r| r.get(0).map(AccountUuid))?
        .collect::<Result<_, _>>()?;
    for account in accounts {
        let (owner, _) = account_key(conn, params, account)?;
        if token(conn, owner.0)?.0 {
            recover_refund_memos(conn, params, account)?;
        }
        admit(conn, params, sessions, account, now)?;
        progress(conn, params, account)?;
    }
    Ok(())
}

/// Checks every one-time note admitted from the directory under `tx`'s ID against the raw
/// transaction with `action_holds`, the check admission applies when the raw transaction
/// arrives first. The directory authenticates the note and its position but not its transaction
/// label, so a mismatch disputes the receipt's label: the note row stays with its spends,
/// witness and position, nothing that trusts a transaction ID counts it, and its key's history
/// is read again, even while discovery is disabled, until admission moves it to its true
/// transaction (see `apply::apply_payment`). The caller
/// keeps `tx`'s raw bytes either way, so a repeated mislabeled record is refused at
/// admission.
pub(crate) fn check_raw_receipts(
    conn: &Connection,
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
        conn.execute(
            "UPDATE ironwood_one_time_lookups SET last_record = NULL, done_height = NULL,
                read_complete = 0, attempts = 0, next_attempt_at = 0, reasons = reasons | ?2
             WHERE one_time_key_id = ?1",
            params![key, INVALIDATED],
        )?;
        register_history(conn, owner, key)?;
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
    let (owner, _) = account_key(conn, params, account)?;
    let waiting: Vec<(i64, KeyId, TxId, u32, Vec<u8>, u32, [u8; 32])> = conn
        .prepare(
            "SELECT k.purpose, k.key_index, k.id, p.txid, p.action_index, p.witness,
                 p.witness_height, p.witness_hash
             FROM ironwood_one_time_payment_recovery p
             JOIN ironwood_one_time_keys k ON k.id = p.one_time_key_id
             WHERE k.account_id = ?1 AND p.witness IS NOT NULL
               AND EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
                   WHERE l.one_time_key_id = k.id AND l.reasons != 0)
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
            ))
        })?
        .collect::<Result<_, _>>()?;
    for (id, key, txid, action, witness, anchor_height, anchor_hash) in waiting {
        let Some(candidate) = pending_payment(conn, txid, action)? else {
            continue;
        };
        if !token(conn, owner.0)?.0 && !repairable(conn, params, account, key, id, &candidate)? {
            continue;
        }
        let anchor = ChainPoint {
            height: BlockHeight::from(anchor_height),
            hash: BlockHash(anchor_hash),
        };
        // A stored witness is the path's 32 sibling hashes.
        let (chunks, rest) = witness.as_chunks::<32>();
        let path = <[[u8; 32]; 32]>::try_from(chunks)
            .ok()
            .filter(|_| rest.is_empty())
            .and_then(|siblings| merkle_path(candidate.position, siblings));
        let admission = match path {
            Some(path) => apply_payment(
                conn,
                sessions,
                params,
                account,
                key,
                &candidate,
                through,
                (anchor, &path),
            )?,
            None => Admission::StaleWitness,
        };
        match admission {
            Admission::Admitted | Admission::Waiting => {}
            Admission::Uncovered => rescan_uncovered(conn, owner.0, candidate.height, through)?,
            Admission::StaleWitness => {
                conn.execute(
                    "UPDATE ironwood_one_time_payment_recovery
                     SET witness = NULL, witness_height = NULL, witness_hash = NULL
                     WHERE txid = ?1 AND action_index = ?2",
                    params![txid.as_ref(), action],
                )?;
                // A path fetched again at once is usually built and checked against the
                // same trees, so it backs off rather than costing a lookup every step.
                conn.execute(
                    "UPDATE ironwood_one_time_lookups SET next_attempt_at = ?2
                     WHERE one_time_key_id = ?1",
                    params![id, now.saturating_add(60)],
                )?;
            }
            Admission::Rejected => {
                conn.execute(
                    "DELETE FROM ironwood_one_time_payment_recovery
                     WHERE txid = ?1 AND action_index = ?2",
                    params![txid.as_ref(), action],
                )?;
                conn.execute(
                    "UPDATE ironwood_one_time_lookups SET last_record = NULL, read_complete = 0,
                    next_attempt_at = ?2, reasons = reasons | ?3 WHERE one_time_key_id = ?1",
                    params![id, now.saturating_add(60), INVALIDATED],
                )?;
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
