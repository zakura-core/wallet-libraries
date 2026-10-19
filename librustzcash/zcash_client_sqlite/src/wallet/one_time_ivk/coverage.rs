//! Directory coverage's store side (see `OneTimeIvkCoverageWrite`).
//!
//! A registered key stays in its account's receiver set whatever its state, and each
//! purpose's window covers indices from zero to [`WINDOW_FLOOR`], or [`RECEIVE_GAP_LIMIT`]
//! past the highest key that advances allocation. Keys keep separate facts:
//!
//! | Fact | Column |
//! |---|---|
//! | Authenticated: this wallet reserved it, a funding memo with own-send evidence names it, or a payment to it was authenticated | `authenticated` |
//! | Issuance-blocking: a quote for it was shown for funding, a funding memo names it, it was paid, or the provider saw it without this wallet exposing it | `issuance_blocked` |
//! | Bound-advancing: it moves the window and allocation | `advances_allocation` |
//! | Locally watched: trial decryption is open | `active_from`, `closed_at` |
//! | Paid | `used`, `paid_before_birthday` |
//!
//! A key outside its window, such as one an unauthenticated funding memo names, is sparse:
//! it joins the set alone and never widens the window. The window's receivers are a cache
//! derived from the account's viewing key, never registered, so caching one reserves no
//! index and changes no allocation. A registered key's receiver comes from the registry.
//!
//! Every addition to the set raises the account's generation and, in the same
//! transaction, owes the newcomers the history the frontier already passed (see
//! `one_time_rewind::join_set`). A frontier step tested against an older generation is
//! refused, so it cannot vouch for receivers it never saw.

use rusqlite::{Connection, OptionalExtension, params};
use zcash_client_backend::data_api::{
    one_time_ivk::{
        coverage::{
            CoverageOutcome, CoverageState, CoverageStep, CoverageTarget, DirectoryHistory,
            LookupTicket, Obligation, ObligationReceivers, ReceiverSet, RecoveryStatus, Snapshot,
            Window,
        },
        restore::{DirectoryPayment, DiscoveryWork, PublicationEnd},
    },
    transparent_ledger::ChainPoint,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::{
    Discovery, KeyId, Purpose, account_key, corrupt, decode_index, decode_purpose, invalid,
    purpose_code, register,
    restore::discovery,
    restore::recovery,
    restore_start, stored_key_id,
    swap::{RECEIVE_GAP_LIMIT, reservations::record_provider_seen},
};
use crate::wallet::{
    self,
    one_time_rewind::{Owed, join_set, restart_cursor},
};
use crate::{AccountUuid, error::SqliteClientError};

/// The fewest indices each purpose's window covers.
pub const WINDOW_FLOOR: u64 = 100;

/// Both purposes, in the order windows are reported.
const PURPOSES: [Purpose; 2] = [Purpose::Receive, Purpose::Refund];

/// The window columns of `ironwood_one_time_recovery` for purpose code `purpose`.
fn window_columns(purpose: u8) -> (&'static str, &'static str) {
    if purpose == 0 {
        ("refund_end", "refund_derived")
    } else {
        ("receive_end", "receive_derived")
    }
}

/// An account's row of `ironwood_one_time_recovery`, or its defaults before it has one.
struct Recovery {
    generation: u64,
    windows: [Window; 2],
    history: Option<DirectoryHistory>,
    frontier: Option<(ChainPoint, u64)>,
    bootstrap: Option<Snapshot>,
    seen_checked_at: Option<i64>,
}

impl Recovery {
    /// Whether every window receiver is derived.
    fn complete(&self) -> bool {
        self.windows.iter().all(|w| w.derived == w.end)
    }

    /// `purpose`'s window.
    fn window(&self, purpose: Purpose) -> Window {
        let index = PURPOSES.iter().position(|p| *p == purpose);
        self.windows[index.expect("both purposes have windows")]
    }
}

/// Account `owner`'s recovery row.
fn recovery(conn: &Connection, owner: i64) -> Result<Recovery, SqliteClientError> {
    type Row = (
        u64,
        [u64; 4],
        Option<([u8; 32], u64)>,
        Option<(u32, [u8; 32], u64)>,
        Option<(u32, [u8; 32], [u8; 32])>,
        Option<i64>,
    );
    let stored: Option<Row> = conn
        .query_row(
            "SELECT generation, receive_end, receive_derived, refund_end, refund_derived,
                catalog, epoch, frontier_height, frontier_hash, tested_generation,
                bootstrap_height, bootstrap_hash, bootstrap_digest, seen_checked_at
             FROM ironwood_one_time_recovery WHERE account_id = ?1",
            [owner],
            |r| {
                let catalog: Option<[u8; 32]> = r.get(5)?;
                let frontier: Option<u32> = r.get(7)?;
                let bootstrap: Option<u32> = r.get(10)?;
                Ok((
                    r.get(0)?,
                    [r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?],
                    catalog.map(|c| r.get(6).map(|e| (c, e))).transpose()?,
                    frontier
                        .map(|h| Ok::<_, rusqlite::Error>((h, r.get(8)?, r.get(9)?)))
                        .transpose()?,
                    bootstrap
                        .map(|h| Ok::<_, rusqlite::Error>((h, r.get(11)?, r.get(12)?)))
                        .transpose()?,
                    r.get(13)?,
                ))
            },
        )
        .optional()?;
    let (generation, ends, history, frontier, bootstrap, seen_checked_at) =
        stored.unwrap_or_default();
    let point = |height: u32, hash: [u8; 32]| ChainPoint {
        height: BlockHeight::from(height),
        hash: BlockHash(hash),
    };
    Ok(Recovery {
        generation,
        windows: [
            Window {
                purpose: Purpose::Receive,
                end: ends[0],
                derived: ends[1],
            },
            Window {
                purpose: Purpose::Refund,
                end: ends[2],
                derived: ends[3],
            },
        ],
        history: history.map(|(catalog, epoch)| DirectoryHistory { catalog, epoch }),
        frontier: frontier.map(|(h, hash, g)| (point(h, hash), g)),
        bootstrap: bootstrap.map(|(h, hash, digest)| Snapshot {
            cutoff: point(h, hash),
            digest,
        }),
        seen_checked_at,
    })
}

/// Grows account `owner`'s window of purpose code `purpose` to cover its keys that advance
/// allocation (see the module docs), owing the indices it adds their history. The indices
/// it adds were never checked against a seen set, so the account's seen check is cleared.
pub(super) fn grow_window(
    conn: &rusqlite::Transaction<'_>,
    owner: i64,
    purpose: u8,
) -> Result<(), SqliteClientError> {
    let last: Option<Vec<u8>> = conn.query_row(
        "SELECT MAX(key_index) FROM ironwood_one_time_keys
         WHERE account_id = ?1 AND purpose = ?2 AND advances_allocation = 1",
        params![owner, purpose],
        |r| r.get(0),
    )?;
    // SQLite integers end at i64::MAX, far past any index a wallet issues.
    let target = last
        .map(decode_index)
        .transpose()?
        .map_or(0, |index| index.saturating_add(RECEIVE_GAP_LIMIT + 1))
        .clamp(WINDOW_FLOOR, i64::MAX as u64);
    let end = recovery(conn, owner)?.window(decode_purpose(purpose)?).end;
    if target > end {
        let (column, _) = window_columns(purpose);
        conn.execute(
            &format!(
                "INSERT INTO ironwood_one_time_recovery (account_id, {column}) VALUES (?1, ?2)
                 ON CONFLICT (account_id) DO UPDATE SET {column} = excluded.{column},
                     seen_checked_at = NULL"
            ),
            params![owner, target],
        )?;
        join_set(conn, owner, Owed::Window(purpose, end, target))?;
    }
    Ok(())
}

/// Grows the window of key `id`'s account and purpose after the key came to advance
/// allocation (see [`grow_window`]).
pub(super) fn advanced(conn: &rusqlite::Transaction<'_>, id: i64) -> Result<(), SqliteClientError> {
    let (owner, purpose): (i64, u8) = conn.query_row(
        "SELECT account_id, purpose FROM ironwood_one_time_keys WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    grow_window(conn, owner, purpose)
}

/// The first index past account `owner`'s window of purpose code `purpose`, which covers
/// at least [`WINDOW_FLOOR`] indices before any key advances allocation.
pub(super) fn window_end(
    conn: &Connection,
    owner: i64,
    purpose: u8,
) -> Result<u64, SqliteClientError> {
    let window = recovery(conn, owner)?.window(decode_purpose(purpose)?);
    Ok(window.end.max(WINDOW_FLOOR))
}

/// Adds newly registered key `id`, `key` of account `owner`, to the receiver set alone if
/// its window does not cover it.
pub(super) fn enter_set(
    conn: &rusqlite::Transaction<'_>,
    owner: i64,
    id: i64,
    key: KeyId,
) -> Result<(), SqliteClientError> {
    if key.index() >= recovery(conn, owner)?.window(key.purpose()).end {
        join_set(conn, owner, Owed::Key(id, purpose_code(key.purpose())?))?;
    }
    Ok(())
}

/// Implements `OneTimeIvkCoverageRead::one_time_coverage`.
pub(crate) fn state<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
) -> Result<Option<CoverageState>, SqliteClientError> {
    wallet::get_account(conn, params, account)?.ok_or(SqliteClientError::AccountUnknown)?;
    if !super::recovering_accounts(conn, params)?.contains(&account) {
        return Ok(None);
    }
    let (owner, _) = account_key(conn, params, account)?;
    let row = recovery(conn, owner.0)?;
    let obligations = conn
        .prepare(
            "SELECT k.purpose, k.key_index, o.id, o.purpose, o.range_start, o.range_end,
                o.lower_height, o.through_height, o.cutoff_height, o.cutoff_hash,
                o.cutoff_digest, o.bridged_height
             FROM ironwood_one_time_obligations o
             LEFT JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id
             WHERE o.account_id = ?1 ORDER BY o.id",
        )?
        .query_and_then([owner.0], obligation)?
        .collect::<Result<_, _>>()?;
    Ok(Some(CoverageState {
        generation: row.generation,
        history: row.history,
        frontier: row.frontier,
        bootstrap: row.bootstrap,
        windows: row.windows,
        obligations,
    }))
}

/// The obligation of a row selecting the key's purpose and index, then the obligation's
/// columns in declaration order from `id`, without `account_id` and `one_time_key_id`.
fn obligation(r: &rusqlite::Row<'_>) -> Result<Obligation, SqliteClientError> {
    let receivers = match r.get::<_, Option<u64>>(4)? {
        Some(start) => ObligationReceivers::Window {
            purpose: decode_purpose(r.get(3)?)?,
            start,
            end: r.get(5)?,
        },
        None => ObligationReceivers::Key(stored_key_id(r)?),
    };
    let snapshot = r
        .get::<_, Option<u32>>(8)?
        .map(|height| {
            Ok::<_, rusqlite::Error>(Snapshot {
                cutoff: ChainPoint {
                    height: BlockHeight::from(height),
                    hash: BlockHash(r.get(9)?),
                },
                digest: r.get(10)?,
            })
        })
        .transpose()?;
    Ok(Obligation {
        id: r.get(2)?,
        receivers,
        lower: BlockHeight::from(r.get::<_, u32>(6)?),
        through: BlockHeight::from(r.get::<_, u32>(7)?),
        snapshot,
        bridged: r.get::<_, Option<u32>>(11)?.map(BlockHeight::from),
    })
}

/// Implements `OneTimeIvkCoverageRead::one_time_receiver_set`.
pub(crate) fn receiver_set<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
) -> Result<ReceiverSet, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let row = recovery(conn, owner.0)?;
    let receivers = conn
        .prepare(
            "SELECT purpose, key_index, receiver FROM ironwood_one_time_keys
             WHERE account_id = ?1
             UNION ALL
             SELECT c.purpose, c.key_index, c.receiver FROM ironwood_one_time_receiver_cache c
             WHERE c.account_id = ?1 AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_keys k
                 WHERE k.account_id = c.account_id AND k.purpose = c.purpose
                   AND k.key_index = c.key_index)
             ORDER BY 1, 2",
        )?
        .query_and_then([owner.0], |r| {
            Ok::<_, SqliteClientError>(DiscoveryWork {
                key: stored_key_id(r)?,
                receiver: r
                    .get::<_, Vec<u8>>(2)?
                    .try_into()
                    .map_err(|_| corrupt("invalid stored receiver"))?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(ReceiverSet {
        generation: row.generation,
        receivers,
        complete: row.complete(),
    })
}

/// Implements `OneTimeIvkCoverageWrite::prepare_one_time_coverage`.
pub(crate) fn prepare<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    budget: u32,
    now: i64,
) -> Result<bool, SqliteClientError> {
    recovery::recover_refund_memos(conn, params, account, now)?;
    let (owner, _) = account_key(conn, params, account)?;
    let mut budget = u64::from(budget);
    for purpose in PURPOSES {
        let code = purpose_code(purpose)?;
        grow_window(conn, owner.0, code)?;
        let window = recovery(conn, owner.0)?.window(purpose);
        let through = window.end.min(window.derived.saturating_add(budget));
        let registered: Vec<Vec<u8>> = conn
            .prepare(
                "SELECT key_index FROM ironwood_one_time_keys
                 WHERE account_id = ?1 AND purpose = ?2 AND key_index >= ?3 AND key_index < ?4",
            )?
            .query_map(
                params![
                    owner.0,
                    code,
                    window.derived.to_be_bytes(),
                    through.to_be_bytes()
                ],
                |r| r.get(0),
            )?
            .collect::<Result<_, _>>()?;
        for index in window.derived..through {
            if registered.contains(&index.to_be_bytes().to_vec()) {
                continue;
            }
            for work in discovery::receivers(conn, params, account, purpose, index, 1)? {
                conn.execute(
                    "INSERT OR REPLACE INTO ironwood_one_time_receiver_cache
                        (account_id, purpose, key_index, receiver)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![owner.0, code, index.to_be_bytes(), work.receiver],
                )?;
            }
        }
        let (_, column) = window_columns(code);
        conn.execute(
            &format!("UPDATE ironwood_one_time_recovery SET {column} = ?2 WHERE account_id = ?1"),
            params![owner.0, through],
        )?;
        budget -= through - window.derived;
    }
    Ok(recovery(conn, owner.0)?.complete())
}

/// Implements `OneTimeIvkCoverageWrite::pin_one_time_snapshot`.
pub(crate) fn pin<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    target: CoverageTarget,
    snapshot: Snapshot,
) -> Result<Option<Snapshot>, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let row = recovery(conn, owner.0)?;
    if generation(target) != row.generation {
        return Ok(None);
    }
    let pinned = match target {
        CoverageTarget::Frontier { .. } => {
            if row.bootstrap.is_some() {
                return Ok(row.bootstrap);
            }
            if row
                .frontier
                .is_some_and(|(frontier, _)| snapshot.cutoff.height <= frontier.height)
            {
                return Ok(None);
            }
            conn.execute(
                "INSERT INTO ironwood_one_time_recovery
                    (account_id, bootstrap_height, bootstrap_hash, bootstrap_digest)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (account_id) DO UPDATE SET bootstrap_height = excluded.bootstrap_height,
                     bootstrap_hash = excluded.bootstrap_hash,
                     bootstrap_digest = excluded.bootstrap_digest",
                params![
                    owner.0,
                    u32::from(snapshot.cutoff.height),
                    snapshot.cutoff.hash.0,
                    snapshot.digest
                ],
            )?;
            snapshot
        }
        CoverageTarget::Obligation { id, .. } => {
            let Some(found) = account_obligation(conn, owner.0, id)? else {
                return Ok(None);
            };
            if found.bridged.is_some() {
                return Ok(None);
            }
            if found.snapshot.is_some() {
                return Ok(found.snapshot);
            }
            conn.execute(
                "UPDATE ironwood_one_time_obligations
                 SET cutoff_height = ?2, cutoff_hash = ?3, cutoff_digest = ?4 WHERE id = ?1",
                params![
                    id,
                    u32::from(snapshot.cutoff.height),
                    snapshot.cutoff.hash.0,
                    snapshot.digest
                ],
            )?;
            snapshot
        }
    };
    Ok(Some(pinned))
}

/// The receiver-set generation `target` was read at.
fn generation(target: CoverageTarget) -> u64 {
    match target {
        CoverageTarget::Frontier { generation } | CoverageTarget::Obligation { generation, .. } => {
            generation
        }
    }
}

/// Account `owner`'s obligation `id`, if it is still outstanding.
fn account_obligation(
    conn: &Connection,
    owner: i64,
    id: u64,
) -> Result<Option<Obligation>, SqliteClientError> {
    conn.query_row(
        "SELECT k.purpose, k.key_index, o.id, o.purpose, o.range_start, o.range_end,
            o.lower_height, o.through_height, o.cutoff_height, o.cutoff_hash,
            o.cutoff_digest, o.bridged_height
         FROM ironwood_one_time_obligations o
         LEFT JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id
         WHERE o.account_id = ?1 AND o.id = ?2",
        params![owner, id],
        |r| Ok(obligation(r)),
    )
    .optional()?
    .transpose()
}

/// Implements `OneTimeIvkCoverageWrite::record_one_time_coverage`.
pub(crate) fn record<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    target: CoverageTarget,
    step: CoverageStep,
    hits: &[KeyId],
    now: i64,
) -> Result<CoverageOutcome, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let row = recovery(conn, owner.0)?;
    if row.history.is_some_and(|history| history != step.history) {
        return Ok(CoverageOutcome::HistoryChanged);
    }
    let start = restore_start(conn, params, owner)?;
    if step.end.height >= start {
        match wallet::get_block_hash(conn, step.end.height)? {
            None => return Ok(CoverageOutcome::Pending),
            Some(hash) if hash != step.end.hash => return Ok(CoverageOutcome::OffChain),
            Some(_) => {}
        }
    }
    let pinned = |snapshot: Option<Snapshot>| {
        snapshot.is_some_and(|s| s.cutoff == step.end && s.digest == step.digest)
    };
    if generation(target) != row.generation {
        return Ok(CoverageOutcome::Stale);
    }
    match target {
        CoverageTarget::Frontier { generation } => {
            if !row.complete() {
                return Ok(CoverageOutcome::Stale);
            }
            let continues = match (step.start, row.frontier) {
                // A pinned snapshot past the frontier bridges a gap no retained bucket covers.
                (None, frontier) => {
                    pinned(row.bootstrap)
                        && frontier.is_none_or(|(f, _)| f.height < step.end.height)
                }
                (Some(from), Some((frontier, _))) => {
                    from.height <= frontier.height
                        && frontier.height < step.end.height
                        && (from.height < frontier.height || from.hash == frontier.hash)
                }
                _ => false,
            };
            if !continues {
                return Ok(CoverageOutcome::Discontinuous);
            }
            for hit in hits {
                let registered = registered(conn, owner.0, *hit)?.is_some();
                if !registered && hit.index() >= row.window(hit.purpose()).end {
                    return Err(invalid("coverage hit outside the receiver set"));
                }
            }
            conn.execute(
                "UPDATE ironwood_one_time_recovery
                 SET frontier_height = ?2, frontier_hash = ?3, tested_generation = ?4,
                     catalog = ?5, epoch = ?6, bootstrap_height = NULL, bootstrap_hash = NULL,
                     bootstrap_digest = NULL
                 WHERE account_id = ?1",
                params![
                    owner.0,
                    u32::from(step.end.height),
                    step.end.hash.0,
                    generation,
                    step.history.catalog,
                    step.history.epoch
                ],
            )?;
            // A snapshot tested the whole set, whose receivers every obligation's are among,
            // so it covers the history each owes through its cutoff.
            if step.start.is_none() {
                conn.execute(
                    "DELETE FROM ironwood_one_time_obligations
                     WHERE account_id = ?1 AND through_height <= ?2",
                    params![owner.0, u32::from(step.end.height)],
                )?;
            }
        }
        CoverageTarget::Obligation { id, .. } => {
            // An obligation's window receivers may not be derived yet.
            let Some(found) = account_obligation(conn, owner.0, id)?.filter(|_| row.complete())
            else {
                return Ok(CoverageOutcome::Stale);
            };
            let continues = match (step.start, found.bridged) {
                (None, None) => pinned(found.snapshot),
                (Some(from), Some(bridged)) => from.height <= bridged && bridged < step.end.height,
                _ => false,
            };
            if !continues {
                return Ok(CoverageOutcome::Discontinuous);
            }
            for hit in hits {
                let owed = match found.receivers {
                    ObligationReceivers::Key(key) => key == *hit,
                    ObligationReceivers::Window {
                        purpose,
                        start,
                        end,
                    } => hit.purpose() == purpose && (start..end).contains(&hit.index()),
                };
                if !owed {
                    return Err(invalid("coverage hit outside the obligation"));
                }
            }
            if step.end.height >= found.through {
                conn.execute(
                    "DELETE FROM ironwood_one_time_obligations WHERE id = ?1",
                    [id],
                )?;
            } else {
                conn.execute(
                    "UPDATE ironwood_one_time_obligations SET bridged_height = ?2 WHERE id = ?1",
                    params![id, u32::from(step.end.height)],
                )?;
            }
        }
    }
    for hit in hits {
        let id = match registered(conn, owner.0, *hit)? {
            Some(id) => id,
            None => {
                register(
                    conn,
                    params,
                    account,
                    *hit,
                    start,
                    false,
                    Discovery::Funding,
                    now,
                )?
                .0
            }
        };
        // Even a key scanned from before the step is looked up: a scan that started
        // without it may still owe a rescan, and the key may close before that runs.
        conn.execute(
            "INSERT INTO ironwood_one_time_lookups (one_time_key_id, cutoff_height)
             VALUES (?1, ?2)
             ON CONFLICT (one_time_key_id) DO UPDATE SET
                 cutoff_height = MAX(COALESCE(cutoff_height, 0), excluded.cutoff_height)
             WHERE cutoff_height IS NOT NULL OR done_height IS NULL
                OR done_height < excluded.cutoff_height",
            params![id, u32::from(step.end.height)],
        )?;
    }
    Ok(CoverageOutcome::Recorded)
}

/// The registry ID of account `owner`'s key `key`, if registered.
fn registered(conn: &Connection, owner: i64, key: KeyId) -> Result<Option<i64>, SqliteClientError> {
    Ok(conn
        .query_row(
            "SELECT id FROM ironwood_one_time_keys
             WHERE account_id = ?1 AND purpose = ?2 AND key_index = ?3",
            params![
                owner,
                purpose_code(key.purpose())?,
                key.index().to_be_bytes()
            ],
            |r| r.get(0),
        )
        .optional()?)
}

/// Implements `OneTimeIvkCoverageWrite::reset_one_time_history`.
pub(crate) fn reset_history<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    history: DirectoryHistory,
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    if recovery(conn, owner.0)?
        .history
        .is_some_and(|old| old.catalog == history.catalog && old.epoch >= history.epoch)
    {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO ironwood_one_time_recovery (account_id, catalog, epoch, generation)
         VALUES (?1, ?2, ?3, 1)
         ON CONFLICT (account_id) DO UPDATE SET catalog = excluded.catalog,
             epoch = excluded.epoch, generation = generation + 1, frontier_height = NULL,
             frontier_hash = NULL, tested_generation = NULL, bootstrap_height = NULL,
             bootstrap_hash = NULL, bootstrap_digest = NULL",
        params![owner.0, history.catalog, history.epoch],
    )?;
    conn.execute(
        "DELETE FROM ironwood_one_time_obligations WHERE account_id = ?1",
        [owner.0],
    )?;
    restart_cursor(
        conn,
        "SELECT id FROM ironwood_one_time_keys WHERE account_id = ?1",
        owner.0,
    )?;
    Ok(true)
}

/// Implements `OneTimeIvkCoverageWrite::dispatch_one_time_lookups`.
pub(crate) fn dispatch<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<Vec<LookupTicket>, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let tickets = conn
        .prepare(&format!(
            "SELECT {}, l.generation FROM ironwood_one_time_lookups l
             JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
             WHERE k.account_id = ?1 AND l.cutoff_height IS NOT NULL AND l.next_attempt_at <= ?2
             ORDER BY l.next_attempt_at, k.id",
            discovery::LOOKUP_COLUMNS
        ))?
        .query_and_then(params![owner.0, now], |r| {
            Ok::<_, SqliteClientError>(LookupTicket {
                work: discovery::lookup_work(r)?,
                generation: r.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    conn.execute(
        "UPDATE ironwood_one_time_lookups
         SET dispatched_cutoff = cutoff_height, dispatched_generation = generation
         WHERE cutoff_height IS NOT NULL AND next_attempt_at <= ?2 AND one_time_key_id IN (
             SELECT id FROM ironwood_one_time_keys WHERE account_id = ?1)",
        params![owner.0, now],
    )?;
    Ok(tickets)
}

/// Implements `OneTimeIvkCoverageWrite::record_one_time_lookup_page`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_page<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    sessions: &super::restore::apply::Sessions<'_>,
    account: AccountUuid,
    ticket: &LookupTicket,
    revision: PublicationEnd,
    page: u32,
    records: &[DirectoryPayment],
    complete: bool,
    now: i64,
) -> Result<bool, SqliteClientError> {
    let key = ticket.work.work.key;
    let id = super::key_ref(conn, account, key)?;
    let cutoff = u32::from(ticket.work.cutoff);
    let current: Option<u32> = conn
        .query_row(
            "SELECT applied FROM ironwood_one_time_lookups
             WHERE one_time_key_id = ?1 AND generation = ?2
               AND dispatched_cutoff = ?3 AND dispatched_generation = ?2",
            params![id, ticket.generation, cutoff],
            |r| r.get(0),
        )
        .optional()?;
    let Some(applied) = current else {
        return Ok(false);
    };
    discovery::apply_page(
        conn,
        params,
        sessions,
        account,
        (key, id),
        (cutoff, applied),
        revision,
        page,
        records,
        complete,
        now,
    )
}

/// Implements `OneTimeIvkCoverageRead::one_time_recovery_status`.
pub(crate) fn recovery_status<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
) -> Result<Option<RecoveryStatus>, SqliteClientError> {
    let Some(coverage) = state(conn, params, account)? else {
        return Ok(None);
    };
    let (owner, _) = account_key(conn, params, account)?;
    let lookups: usize = conn.query_row(
        "SELECT COUNT(*) FROM ironwood_one_time_lookups l
         JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
         WHERE k.account_id = ?1 AND l.cutoff_height IS NOT NULL",
        [owner.0],
        |r| r.get(0),
    )?;
    let derived = coverage.windows.iter().all(|w| w.derived == w.end);
    let complete = coverage.frontier.is_some()
        && derived
        && coverage.obligations.is_empty()
        && discovery::settled(conn, params, owner)?;
    Ok(Some(RecoveryStatus {
        frontier: coverage.frontier.map(|(point, _)| point.height),
        obligations: coverage.obligations.len(),
        lookups,
        witnesses: discovery::witness_requests(conn, owner.0)?,
        witness_anchor_floor: discovery::witness_anchor_floor(conn)?,
        seen_checked_at: recovery(conn, owner.0)?.seen_checked_at,
        complete,
    }))
}

/// Implements `OneTimeIvkCoverageWrite::unpin_one_time_snapshot`.
pub(crate) fn unpin<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    target: CoverageTarget,
    snapshot: Snapshot,
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    if generation(target) != recovery(conn, owner.0)?.generation {
        return Ok(false);
    }
    let pinned = params![
        owner.0,
        u32::from(snapshot.cutoff.height),
        snapshot.cutoff.hash.0,
        snapshot.digest
    ];
    let dropped = match target {
        CoverageTarget::Frontier { .. } => conn.execute(
            "UPDATE ironwood_one_time_recovery
             SET bootstrap_height = NULL, bootstrap_hash = NULL, bootstrap_digest = NULL
             WHERE account_id = ?1 AND bootstrap_height = ?2 AND bootstrap_hash = ?3
               AND bootstrap_digest = ?4",
            pinned,
        )?,
        CoverageTarget::Obligation { id, .. } => conn.execute(
            "UPDATE ironwood_one_time_obligations
             SET cutoff_height = NULL, cutoff_hash = NULL, cutoff_digest = NULL,
                 bridged_height = NULL
             WHERE account_id = ?1 AND cutoff_height = ?2 AND cutoff_hash = ?3
               AND cutoff_digest = ?4 AND id = ?5",
            params![
                owner.0,
                u32::from(snapshot.cutoff.height),
                snapshot.cutoff.hash.0,
                snapshot.digest,
                id
            ],
        )?,
    };
    Ok(dropped == 1)
}

/// Implements `OneTimeIvkCoverageWrite::record_one_time_seen`.
pub(crate) fn record_seen<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    generation: u64,
    hits: &[KeyId],
    now: i64,
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let before = recovery(conn, owner.0)?;
    let start = restore_start(conn, params, owner)?;
    for hit in hits {
        purpose_code(hit.purpose())?;
        // A sparse key never widens a window, however a seen set's false match lands.
        if hit.index() >= before.window(hit.purpose()).end {
            return Err(invalid("seen hit outside its window"));
        }
        let (id, _) = register(
            conn,
            params,
            account,
            *hit,
            start,
            true,
            Discovery::Funding,
            now,
        )?;
        record_provider_seen(conn, id)?;
    }
    let after = recovery(conn, owner.0)?;
    let stable =
        generation == before.generation && after.generation == generation && after.complete();
    if stable {
        conn.execute(
            "UPDATE ironwood_one_time_recovery SET seen_checked_at = ?2 WHERE account_id = ?1",
            params![owner.0, now],
        )?;
    }
    Ok(stable)
}

/// Implements `OneTimeIvkCoverageWrite::restart_one_time_lookups`.
pub(crate) fn restart_lookups<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    found: &[KeyId],
    cutoff: BlockHeight,
    now: i64,
) -> Result<(), SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let start = restore_start(conn, params, owner)?;
    for key in found {
        if registered(conn, owner.0, *key)?.is_none() {
            register(
                conn,
                params,
                account,
                *key,
                start,
                false,
                Discovery::Funding,
                now,
            )?;
        }
    }
    conn.execute(
        "INSERT INTO ironwood_one_time_lookups (one_time_key_id, cutoff_height)
         SELECT id, ?2 FROM ironwood_one_time_keys WHERE account_id = ?1 AND true
         ON CONFLICT (one_time_key_id) DO UPDATE SET
             cutoff_height = MAX(COALESCE(cutoff_height, 0), COALESCE(done_height, 0),
                 excluded.cutoff_height),
             attempts = 0, next_attempt_at = 0",
        params![owner.0, u32::from(cutoff)],
    )?;
    restart_cursor(
        conn,
        "SELECT id FROM ironwood_one_time_keys WHERE account_id = ?1",
        owner.0,
    )
}

#[cfg(test)]
pub(super) mod tests;
