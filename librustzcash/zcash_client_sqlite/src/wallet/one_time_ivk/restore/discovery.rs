//! The lookups and late payments of recovery's store side (see `OneTimeIvkRestoreWrite`).
//!
//! Each hit's lookup pages through its key's history up to its target (the cutoff), over a
//! publication that reaches it. A payment whose block the scan has not stored is a scan
//! hint: the batch holding that block tries its key (see
//! `one_time_ivk::scanning_keys_for_range`). Any other payment is a late candidate, admitted by `apply::apply_payment` once its publication matched the
//! wallet's chain, it has an inclusion path, and the scan covers every block from it on
//! for the account. The spend journal then says whether it was spent.
//!
//! Every publication a lookup reads from is judged against the wallet's chain when the
//! scan stores its last block, or at once if the block is already stored.
use std::ops::Range;

use rusqlite::{Connection, OptionalExtension, params};
use zcash_client_backend::data_api::{
    one_time_ivk::restore::{
        DirectoryPayment, DiscoveryWork, LookupWork, PublicationEnd, WitnessRequest,
    },
    scanning::ScanPriority,
    transparent_ledger::ChainPoint,
};
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::{
    apply::{Admission, Sessions, apply_payment, merkle_path},
    payments::{authenticate, directory_candidate, pending_payment, queue_payment},
    recovery::recover_refund_memos,
};
use crate::wallet::one_time_ivk::{
    KeyId, Purpose, account_key, corrupt, index_after, key_ref, recovering_accounts, restore_start,
    stored_key_id,
};
use crate::wallet::one_time_rewind::{
    ACCEPTED, PROVISIONAL, REJECTED, restart_cursor, restart_walk,
};
use crate::{AccountUuid, error::SqliteClientError, wallet::scanning::priority_code};

/// Whether account `owner` has no lookup due or left without a target, no payment it found
/// waiting to be admitted, and no lookup cursor that read from a publication not matched
/// against the wallet's chain, unless it ended before the birthday.
pub(in crate::wallet::one_time_ivk) fn settled<P: Parameters>(
    conn: &Connection,
    params: &P,
    owner: crate::AccountRef,
) -> Result<bool, SqliteClientError> {
    let start = restore_start(conn, params, owner)?;
    Ok(conn.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
             JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
             WHERE k.account_id = ?1
               AND (l.cutoff_height IS NOT NULL OR l.done_height IS NULL))
         AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery c
             JOIN ironwood_one_time_keys k ON k.id = c.one_time_key_id
             WHERE k.account_id = ?1)
         AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_lookup_reads r
             JOIN ironwood_one_time_keys k ON k.id = r.one_time_key_id
             JOIN ironwood_one_time_publications p
               ON p.height = r.publication_height AND p.hash = r.publication_hash
             WHERE k.account_id = ?1 AND p.state != ?2
               AND NOT (p.state = ?3 AND p.height < ?4))",
        params![owner.0, ACCEPTED, PROVISIONAL, u32::from(start)],
        |r| r.get(0),
    )?)
}

/// Account `owner`'s late candidates whose inclusion path is due, unless their publication
/// was rejected.
pub(in crate::wallet::one_time_ivk) fn witness_requests(
    conn: &Connection,
    owner: i64,
) -> Result<Vec<WitnessRequest>, SqliteClientError> {
    conn.prepare(
        "SELECT k.purpose, k.key_index, p.position, substr(p.encrypted_note, 33, 32)
         FROM ironwood_one_time_payment_recovery p
         JOIN ironwood_one_time_keys k ON k.id = p.one_time_key_id
         JOIN ironwood_one_time_publications u
           ON u.height = p.publication_height AND u.hash = p.publication_hash
         WHERE k.account_id = ?1 AND p.scan_hint = 0 AND p.witness IS NULL
           AND u.state != ?2
         ORDER BY p.height, p.position",
    )?
    .query_and_then(params![owner, REJECTED], |r| {
        Ok::<_, SqliteClientError>(WitnessRequest {
            key: stored_key_id(r)?,
            position: r.get(2)?,
            cmx: r.get(3)?,
        })
    })?
    .collect()
}

/// The lowest block a late candidate's inclusion path may be anchored at (see
/// `RecoveryStatus::witness_anchor_floor`).
pub(in crate::wallet::one_time_ivk) fn witness_anchor_floor(
    conn: &Connection,
) -> Result<BlockHeight, SqliteClientError> {
    Ok(scanned_tip(conn)?.map_or(BlockHeight::from(0), |tip| {
        tip.height.saturating_sub(crate::PRUNING_DEPTH)
    }))
}

/// The columns of key `k` and its lookup `l` that [`lookup_work`] reads.
pub(in crate::wallet::one_time_ivk) const LOOKUP_COLUMNS: &str =
    "k.purpose, k.key_index, k.receiver, l.cutoff_height, l.applied, l.last_position,
    l.last_nullifier";

/// The due lookup of a row selecting [`LOOKUP_COLUMNS`] first.
pub(in crate::wallet::one_time_ivk) fn lookup_work(
    r: &rusqlite::Row<'_>,
) -> Result<LookupWork, SqliteClientError> {
    Ok(LookupWork {
        work: DiscoveryWork {
            key: stored_key_id(r)?,
            receiver: r
                .get::<_, Vec<u8>>(2)?
                .try_into()
                .map_err(|_| corrupt("invalid stored receiver"))?,
        },
        cutoff: BlockHeight::from(r.get::<_, u32>(3)?),
        applied: r.get(4)?,
        last: r
            .get::<_, Option<u64>>(5)?
            .zip(r.get::<_, Option<[u8; 32]>>(6)?),
    })
}

/// Implements `OneTimeIvkRestoreRead::one_time_receivers`.
pub(crate) fn receivers<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    purpose: Purpose,
    from: u64,
    count: u32,
) -> Result<Vec<DiscoveryWork>, SqliteClientError> {
    let (_, parent) = account_key(conn, params, account)?;
    (0..u64::from(count))
        .map(|offset| {
            let key = KeyId::new(purpose, index_after(from, offset)?);
            let receiver = key
                .derive(&parent)?
                .address_at(0u32, orchard::keys::Scope::External)
                .to_raw_address_bytes();
            Ok(DiscoveryWork { key, receiver })
        })
        .collect()
}

/// Records `publication` if it is new, and judges it at once if the scan stored its block.
/// Returns its state, or `None` if a claim for the same block with another tree size is
/// accepted or not judged yet.
fn note_publication(
    conn: &rusqlite::Transaction<'_>,
    publication: PublicationEnd,
) -> Result<Option<u8>, SqliteClientError> {
    let height = u32::from(publication.height);
    let stored: Option<(u64, u8)> = conn
        .query_row(
            "SELECT tree_size, state FROM ironwood_one_time_publications
             WHERE height = ?1 AND hash = ?2",
            params![height, publication.hash],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match stored {
        None => {
            conn.execute(
                "INSERT INTO ironwood_one_time_publications (height, hash, tree_size)
                 VALUES (?1, ?2, ?3)",
                params![height, publication.hash, publication.tree_size],
            )?;
        }
        Some((size, _)) if size == publication.tree_size => {}
        // A rejected claim for this block gives way to a corrected size, judged afresh.
        Some((_, REJECTED)) => {
            conn.execute(
                "UPDATE ironwood_one_time_publications SET tree_size = ?3, state = ?4
                 WHERE height = ?1 AND hash = ?2",
                params![height, publication.hash, publication.tree_size, PROVISIONAL],
            )?;
        }
        Some(_) => return Ok(None),
    }
    judge(conn, publication.height)?;
    Ok(Some(conn.query_row(
        "SELECT state FROM ironwood_one_time_publications WHERE height = ?1 AND hash = ?2",
        params![height, publication.hash],
        |r| r.get(0),
    )?))
}

/// Applies a lookup page for `key`, registry ID `id`, as
/// `OneTimeIvkCoverageWrite::record_one_time_lookup_page` describes, against `cutoff`, with
/// `applied` records already applied. Completing the walk marks the lookup done through
/// `cutoff`, and leaves a target widened past it due.
#[allow(clippy::too_many_arguments)]
pub(in crate::wallet::one_time_ivk) fn apply_page<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    sessions: &Sessions<'_>,
    account: AccountUuid,
    (key, id): (KeyId, i64),
    (cutoff, applied): (u32, u32),
    revision: PublicationEnd,
    page: u32,
    records: &[DirectoryPayment],
    complete: bool,
    now: i64,
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    // A revision ending below the cutoff cannot show the history through it.
    if (page != applied && page != 0) || u32::from(revision.height) < cutoff {
        return Ok(false);
    }
    if note_publication(conn, revision)?.is_none_or(|state| state == REJECTED) {
        return Ok(false);
    }
    if page == 0 && applied > 0 {
        restart_walk(conn, id)?;
    }
    let start = restore_start(conn, params, owner)?;
    conn.execute_batch("SAVEPOINT lookup_page")?;
    let mut last = None;
    for payment in records {
        let Some(candidate) = directory_candidate(payment) else {
            return refuse(conn, id, now);
        };
        if u32::from(candidate.height) > cutoff {
            return refuse(conn, id, now);
        }
        let note = match authenticate(conn, params, account, key, &candidate) {
            Ok((_, note)) => note,
            Err(SqliteClientError::InvalidOneTimeIvkInput(_)) => return refuse(conn, id, now),
            Err(e) => return Err(e),
        };
        // A note the scan already found stays as it is. One a rewind left unmined is found
        // again, since its key may not scan the replacing blocks.
        let found: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             WHERE n.nf = ?1 AND t.mined_height IS NOT NULL)",
            [note.nullifier().to_bytes()],
            |r| r.get(0),
        )?;
        if !found {
            // Whether the scan stored the block since the scan queue last required it.
            let scanned: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM blocks WHERE height = ?1)
                 AND EXISTS(SELECT 1 FROM scan_queue WHERE priority = ?2
                     AND block_range_start <= ?1 AND block_range_end > ?1)",
                params![
                    u32::from(candidate.height),
                    priority_code(&ScanPriority::Scanned)
                ],
                |r| r.get(0),
            )?;
            let hint = candidate.height >= start && !scanned;
            match queue_payment(conn, params, account, key, &candidate, revision, hint) {
                Ok(()) => {}
                Err(SqliteClientError::InvalidOneTimeIvkInput(_)) => {
                    return refuse(conn, id, now);
                }
                Err(e) => return Err(e),
            }
        }
        last = Some((
            candidate.position,
            payment.action_nullifier,
            candidate.height,
        ));
    }
    conn.execute_batch("RELEASE lookup_page")?;
    if let Some((position, nullifier, height)) = last {
        conn.execute(
            "UPDATE ironwood_one_time_lookups
             SET applied = ?2, last_position = ?3, last_nullifier = ?4, last_height = ?5
             WHERE one_time_key_id = ?1",
            params![
                id,
                page + u32::try_from(records.len()).map_err(|_| corrupt("too many records"))?,
                position,
                nullifier,
                u32::from(height)
            ],
        )?;
    }
    conn.execute(
        "INSERT OR IGNORE INTO ironwood_one_time_lookup_reads
            (one_time_key_id, publication_height, publication_hash)
         VALUES (?1, ?2, ?3)",
        params![id, u32::from(revision.height), revision.hash],
    )?;
    if complete {
        conn.execute(
            "UPDATE ironwood_one_time_lookups
             SET done_height = ?2,
                 cutoff_height = CASE WHEN cutoff_height > ?2 THEN cutoff_height END,
                 dispatched_cutoff = NULL, dispatched_generation = NULL, attempts = 0,
                 next_attempt_at = 0
             WHERE one_time_key_id = ?1",
            params![id, cutoff],
        )?;
    }
    admit(conn, params, sessions, account, now)?;
    Ok(true)
}

/// Undoes what a refused page queued since `apply_page`'s savepoint, so a corrected
/// answer is not refused as a conflict, then backs lookup `id` off (see [`defer`]).
fn refuse(conn: &Connection, id: i64, now: i64) -> Result<bool, SqliteClientError> {
    conn.execute_batch("ROLLBACK TO lookup_page; RELEASE lookup_page")?;
    defer(conn, id, now)
}

/// Backs lookup `id` off from `now`, from one minute to twelve hours, and returns false.
fn defer(conn: &Connection, id: i64, now: i64) -> Result<bool, SqliteClientError> {
    let attempts: u32 = conn.query_row(
        "SELECT attempts FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
        [id],
        |r| r.get(0),
    )?;
    let delay = (60i64 << attempts.min(10)).min(43200);
    conn.execute(
        "UPDATE ironwood_one_time_lookups
         SET attempts = MIN(attempts + 1, 30), next_attempt_at = ?2
         WHERE one_time_key_id = ?1",
        params![id, now.saturating_add(delay)],
    )?;
    Ok(false)
}

/// Implements `OneTimeIvkRestoreWrite::defer_one_time_lookup`.
pub(crate) fn defer_lookup(
    conn: &Connection,
    account: AccountUuid,
    key: KeyId,
    now: i64,
) -> Result<(), SqliteClientError> {
    defer(conn, key_ref(conn, account, key)?, now).map(|_| ())
}

/// Implements `OneTimeIvkRestoreWrite::record_one_time_witness`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_witness<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    sessions: &Sessions<'_>,
    account: AccountUuid,
    key: KeyId,
    position: u32,
    anchor: ChainPoint,
    siblings: [[u8; 32]; 32],
    now: i64,
) -> Result<(), SqliteClientError> {
    let id = key_ref(conn, account, key)?;
    conn.execute(
        "UPDATE ironwood_one_time_payment_recovery
         SET witness = ?3, witness_height = ?4, witness_hash = ?5
         WHERE one_time_key_id = ?1 AND position = ?2 AND scan_hint = 0",
        params![
            id,
            position,
            siblings.concat(),
            u32::from(anchor.height),
            anchor.hash.0
        ],
    )?;
    admit(conn, params, sessions, account, now)
}

/// Runs after the scan stores `range`, with one-time keys `keys` if it used them: judges
/// the publications ending in it, settles its hints, recovers refund keys from newly
/// stored funding memos at `now`, and admits the late candidates the scan now covers, for
/// every account whose one-time keys are recovered.
pub(crate) fn after_blocks_stored<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    sessions: &Sessions<'_>,
    keys: Option<&[(AccountUuid, KeyId)]>,
    range: Range<BlockHeight>,
    now: i64,
) -> Result<(), SqliteClientError> {
    let heights: Vec<u32> = conn
        .prepare(
            "SELECT DISTINCT height FROM ironwood_one_time_publications
             WHERE state = ?1 AND height >= ?2 AND height < ?3",
        )?
        .query_map(
            params![PROVISIONAL, u32::from(range.start), u32::from(range.end)],
            |r| r.get(0),
        )?
        .collect::<Result<_, _>>()?;
    for height in heights {
        judge(conn, BlockHeight::from(height))?;
    }
    check_hints(conn, keys.unwrap_or(&[]), range, now)?;
    for account in recovering_accounts(conn, params)? {
        recover_refund_memos(conn, params, account, now)?;
        admit(conn, params, sessions, account, now)?;
    }
    Ok(())
}

/// Accepts each provisional publication ending at `height` whose last block and tree size
/// match the stored block, and rejects any that does not. Nothing changes until the scan
/// stores that block.
fn judge(conn: &rusqlite::Transaction<'_>, height: BlockHeight) -> Result<(), SqliteClientError> {
    let stored: Option<([u8; 32], Option<u64>)> = conn
        .query_row(
            "SELECT hash, ironwood_commitment_tree_size FROM blocks WHERE height = ?1",
            [u32::from(height)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((hash, tree_size)) = stored else {
        return Ok(());
    };
    let provisional: Vec<([u8; 32], u64)> = conn
        .prepare(
            "SELECT hash, tree_size FROM ironwood_one_time_publications
             WHERE height = ?1 AND state = ?2",
        )?
        .query_map(params![u32::from(height), PROVISIONAL], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<Result<_, _>>()?;
    for (claimed, claimed_size) in provisional {
        if claimed == hash && tree_size == Some(claimed_size) {
            conn.execute(
                "UPDATE ironwood_one_time_publications SET state = ?3
                 WHERE height = ?1 AND hash = ?2",
                params![u32::from(height), claimed, ACCEPTED],
            )?;
        } else {
            reject(conn, height, claimed)?;
        }
    }
    Ok(())
}

/// Rejects the publication ending at `height` with hash `hash`: every lookup cursor that read
/// from it restarts, and the candidates it supplied that are not notes yet are dropped.
fn reject(
    conn: &rusqlite::Transaction<'_>,
    height: BlockHeight,
    hash: [u8; 32],
) -> Result<(), SqliteClientError> {
    let height = u32::from(height);
    conn.execute(
        "UPDATE ironwood_one_time_publications SET state = ?3 WHERE height = ?1 AND hash = ?2",
        params![height, hash, REJECTED],
    )?;
    conn.execute(
        "DELETE FROM ironwood_one_time_payment_recovery
         WHERE publication_height = ?1 AND publication_hash = ?2",
        params![height, hash],
    )?;
    let readers: Vec<i64> = conn
        .prepare(
            "SELECT one_time_key_id FROM ironwood_one_time_lookup_reads
             WHERE publication_height = ?1 AND publication_hash = ?2",
        )?
        .query_map(params![height, hash], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for id in readers {
        restart_cursor(conn, "?1", id)?;
    }
    Ok(())
}

/// Settles the hints in `range`, which the scan just stored with one-time keys `keys`. A
/// hint is satisfied only by its own note. One whose key the batch did not try, because
/// the lookup came in after the scanner took its keys or the scan used none, becomes a late
/// candidate. One the batch tried and missed is the directory's error: its key's lookup
/// restarts.
fn check_hints(
    conn: &rusqlite::Transaction<'_>,
    keys: &[(AccountUuid, KeyId)],
    range: Range<BlockHeight>,
    now: i64,
) -> Result<(), SqliteClientError> {
    let hints: Vec<(KeyId, AccountUuid, i64, TxId, u32, u32, Vec<u8>)> = conn
        .prepare(
            "SELECT k.purpose, k.key_index, a.uuid, p.one_time_key_id, p.txid,
                 p.action_index, p.position, substr(p.encrypted_note, 1, 32)
             FROM ironwood_one_time_payment_recovery p
             JOIN ironwood_one_time_keys k ON k.id = p.one_time_key_id
             JOIN accounts a ON a.id = k.account_id
             WHERE p.scan_hint = 1 AND p.height >= ?1 AND p.height < ?2",
        )?
        .query_and_then(params![u32::from(range.start), u32::from(range.end)], |r| {
            Ok::<_, SqliteClientError>((
                stored_key_id(r)?,
                AccountUuid(r.get(2)?),
                r.get(3)?,
                TxId::from_bytes(r.get(4)?),
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        })?
        .collect::<Result<_, _>>()?;
    for (key, account, id, txid, action, position, rho) in hints {
        if !keys.contains(&(account, key)) {
            conn.execute(
                "UPDATE ironwood_one_time_payment_recovery SET scan_hint = 0
                 WHERE txid = ?1 AND action_index = ?2",
                params![txid.as_ref(), action],
            )?;
            continue;
        }
        // The note's rho is the action's nullifier, which the candidate carries, so another
        // payment to the key at the claimed position does not satisfy the hint.
        let found: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes
             WHERE one_time_key_id = ?1 AND commitment_tree_position = ?2 AND rho = ?3)",
            params![id, position, rho],
            |r| r.get(0),
        )?;
        conn.execute(
            "DELETE FROM ironwood_one_time_payment_recovery WHERE txid = ?1 AND action_index = ?2",
            params![txid.as_ref(), action],
        )?;
        if !found {
            restart_cursor(conn, "?1", id)?;
            defer(conn, id, now)?;
        }
    }
    Ok(())
}

/// Admits `account`'s late candidates that have an inclusion path, whose publication matched
/// the wallet's chain, and that the scan now covers (see `apply::apply_payment`). A note
/// admitted spent can be a funding transaction's own-send evidence, so the account's
/// funding memos are recovered again after any admission.
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
             JOIN ironwood_one_time_publications u
               ON u.height = p.publication_height AND u.hash = p.publication_hash
             WHERE k.account_id = ?1 AND p.scan_hint = 0 AND p.witness IS NOT NULL
               AND u.state = ?2
             ORDER BY p.height, p.position",
        )?
        .query_and_then(params![owner.0, ACCEPTED], |r| {
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
    let mut admitted = false;
    for (id, key, txid, action, witness, anchor_height, anchor_hash) in waiting {
        let Some(candidate) = pending_payment(conn, txid, action)? else {
            continue;
        };
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
            Admission::Admitted => admitted = true,
            Admission::Waiting => {}
            Admission::Uncovered => rescan_uncovered(conn, owner.0, candidate.height, through)?,
            Admission::StaleWitness => {
                conn.execute(
                    "UPDATE ironwood_one_time_payment_recovery
                     SET witness = NULL, witness_height = NULL, witness_hash = NULL
                     WHERE txid = ?1 AND action_index = ?2",
                    params![txid.as_ref(), action],
                )?;
            }
            Admission::Rejected => {
                conn.execute(
                    "DELETE FROM ironwood_one_time_payment_recovery
                     WHERE txid = ?1 AND action_index = ?2",
                    params![txid.as_ref(), action],
                )?;
                restart_cursor(conn, "?1", id)?;
                defer(conn, id, now)?;
            }
        }
    }
    if admitted {
        recover_refund_memos(conn, params, account, now)?;
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
