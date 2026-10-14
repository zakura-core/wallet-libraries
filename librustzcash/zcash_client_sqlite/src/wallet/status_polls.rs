//! The private status poll window (`docs/pir-remaining-leaks-plan.md`, change A).
//!
//! Each transaction with private status work is polled once at each of [`WINDOW`] chain tips
//! starting at its window start, and once more at the first tip at or past its expiry height
//! when that is past the window. A due poll is returned once per tip, mined or not, whatever
//! earlier replies said, so the status service sees the same queries whether the transaction
//! mined early, late, never, or the service lied about it. Only a request outcome, which records
//! nothing, leaves a poll due at the same tip.
//!
//! No table holds the window. It is rebuilt from durable columns where they fix it, and the rest
//! lives in the open wallet's [`StatusPollSession`]:
//!
//! - A transaction this wallet built (`transactions.target_height` set) starts its window at
//!   the tip it was built at, `target_height - 1`, which is about when it was broadcast. Its
//!   expiry poll comes from `transactions.expiry_height`.
//! - A rewound transaction awaiting reconfirmation is polled from a new window, opened in the
//!   session at the tip the wallet first reads its work at, whether or not local evidence
//!   already settles it.
//! - Other status work without a target height keeps the eligibility rules of public work until
//!   its first recorded poll, which opens a window at that poll's tip in the session.
//! - The tip of the last recorded poll is kept in the session.
//!
//! Reopening the wallet starts a fresh session. That is the application's doing, not a reply's,
//! so it cannot be aimed at a transaction: windows anchored to a target height are rebuilt as
//! they were, and what is lost costs at most one more poll at the current tip, an expiry poll
//! asked once more, or a new window for work without an anchor.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, named_params};
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

use super::TxQueryType;
use crate::error::SqliteClientError;

/// The number of consecutive chain tips at which a queued transaction is polled.
pub(crate) const WINDOW: u32 = 10;

/// The private status polls of one open-wallet session: which tips were polled, and the windows
/// of status work without a durable anchor.
///
/// Keep this object alive across syncs. Handles opened for the same wallet can share it with
/// `WalletDb::with_status_poll_session`; serialize their wallet operations. Never share it
/// between wallets. A fresh session rebuilds what the database fixes and starts the rest anew.
#[derive(Clone, Default)]
pub struct StatusPollSession(Arc<Mutex<Polls>>);

#[derive(Clone, Default)]
struct Polls {
    /// The tip of the last private reply recorded, per txid.
    polled: BTreeMap<TxId, BlockHeight>,
    /// Windows opened in this session, per txid without a durable anchor.
    opened: BTreeMap<TxId, Opened>,
}

/// A window opened at a first recorded poll.
#[derive(Clone, Copy)]
struct Opened {
    start: BlockHeight,
    /// Whether the obligation was a rewind's reconfirmation when last read. A later rewind sets
    /// it again; seeing it set after it was clear means the window belongs to an earlier
    /// obligation.
    reconfirm: bool,
}

/// One private status obligation, as the database holds it.
struct Obligation {
    txid: TxId,
    target_height: Option<u32>,
    expiry_height: Option<u32>,
    reconfirm: bool,
    earliest: Option<BlockHeight>,
}

impl Obligation {
    /// The window start the database fixes: the tip a transaction this wallet built was built
    /// at. A rewound transaction is polled again from a new window instead.
    fn durable_start(&self) -> Option<BlockHeight> {
        self.target_height
            .filter(|_| !self.reconfirm)
            .map(|target| BlockHeight::from(target.saturating_sub(1)))
    }
}

const OBLIGATIONS: &str = "SELECT q.txid, t.target_height, t.expiry_height, q.reconfirm_mined,
            CASE WHEN t.target_height IS NOT NULL
                 THEN MIN(t.target_height, t.min_observed_height) END
     FROM tx_retrieval_queue q
     LEFT JOIN transactions t ON t.txid = q.txid
     WHERE q.query_type = :status_type";

fn obligation(row: &rusqlite::Row<'_>) -> Result<Obligation, rusqlite::Error> {
    Ok(Obligation {
        txid: TxId::from_bytes(row.get(0)?),
        target_height: row.get(1)?,
        expiry_height: row.get(2)?,
        reconfirm: row.get::<_, i64>(3)? != 0,
        earliest: row.get::<_, Option<u32>>(4)?.map(BlockHeight::from),
    })
}

impl StatusPollSession {
    /// Copies the session for one SQL transaction. Serialized wallet handles publish
    /// the copy only after SQL commits; a rollback leaves the open session unchanged.
    pub(crate) fn transaction(&self) -> Self {
        Self(Arc::new(Mutex::new(self.lock().clone())))
    }

    pub(crate) fn commit_into(&self, session: &Self) {
        *session.lock() = self.lock().clone();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Polls> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Records that a private reply for `txid` came back at `tip`. Status work without a window
/// opens one at `tip`; a txid without status work is ignored.
pub(crate) fn record_poll(
    conn: &Connection,
    session: &StatusPollSession,
    txid: TxId,
    tip: BlockHeight,
) -> Result<(), SqliteClientError> {
    let Some(obligation) = conn
        .query_row(
            &format!("{OBLIGATIONS} AND q.txid = :txid"),
            named_params![
                ":status_type": TxQueryType::Status.code(),
                ":txid": txid.as_ref(),
            ],
            obligation,
        )
        .optional()?
    else {
        return Ok(());
    };
    let mut polls = session.lock();
    let polled = polls.polled.entry(txid).or_insert(tip);
    *polled = (*polled).max(tip);
    if obligation.durable_start().is_none() {
        polls.opened.entry(txid).or_insert(Opened {
            start: tip,
            reconfirm: obligation.reconfirm,
        });
    }
    Ok(())
}

/// A poll due at `tip`.
pub(crate) struct DuePoll {
    pub(crate) txid: TxId,
    pub(crate) earliest: Option<BlockHeight>,
}

/// The windowed polls due at `tip`, in txid order, and every txid with a window: their private
/// work follows the window alone.
///
/// Also forgets session state of obligations that are gone, and windows a later rewind
/// replaced.
pub(crate) fn due(
    conn: &Connection,
    session: &StatusPollSession,
    tip: BlockHeight,
) -> Result<(Vec<DuePoll>, HashSet<TxId>), SqliteClientError> {
    let mut stmt = conn.prepare_cached(&format!("{OBLIGATIONS} ORDER BY q.txid"))?;
    let obligations = stmt
        .query_map(
            named_params![":status_type": TxQueryType::Status.code()],
            obligation,
        )?
        .collect::<Result<Vec<_>, _>>()?;

    let mut polls = session.lock();
    let live: HashSet<TxId> = obligations.iter().map(|o| o.txid).collect();
    polls.polled.retain(|txid, _| live.contains(txid));
    polls.opened.retain(|txid, _| live.contains(txid));

    let mut due = vec![];
    let mut windowed = HashSet::new();
    for o in obligations {
        if let Some(opened) = polls.opened.get_mut(&o.txid) {
            if o.reconfirm && !opened.reconfirm {
                polls.opened.remove(&o.txid);
            } else {
                opened.reconfirm = o.reconfirm;
            }
        }
        if o.reconfirm && !polls.opened.contains_key(&o.txid) {
            // A rewind re-arms polling: tips polled before it say nothing about the new window.
            polls.opened.insert(
                o.txid,
                Opened {
                    start: tip,
                    reconfirm: true,
                },
            );
            polls.polled.remove(&o.txid);
        }
        let Some(start) = polls
            .opened
            .get(&o.txid)
            .map(|opened| opened.start)
            .or_else(|| o.durable_start())
        else {
            continue;
        };
        windowed.insert(o.txid);
        let end = start + WINDOW;
        let expiry_poll = o
            .expiry_height
            .filter(|expiry| *expiry > 0 && BlockHeight::from(*expiry) >= end)
            .map(BlockHeight::from);
        let polled = polls.polled.get(&o.txid).copied();
        let unpolled_since = |height: BlockHeight| polled.is_none_or(|p| p < height);
        if unpolled_since(tip)
            && ((tip >= start && tip < end)
                || expiry_poll.is_some_and(|expiry| tip >= expiry && unpolled_since(expiry)))
        {
            due.push(DuePoll {
                txid: o.txid,
                earliest: o.earliest,
            });
        }
    }
    Ok((due, windowed))
}

/// A rewind starts fresh polling for every queued reconfirmation, even if no intervening
/// read observed the previous obligation complete. Called on the transaction's session
/// copy so a failed rewind cannot reset the open wallet's polls.
pub(crate) fn rearm_reconfirmation(
    conn: &Connection,
    session: &StatusPollSession,
) -> Result<(), SqliteClientError> {
    let txids = conn
        .prepare_cached("SELECT txid FROM tx_retrieval_queue WHERE query_type = :status_type AND reconfirm_mined = 1")?
        .query_map(named_params![":status_type": TxQueryType::Status.code()], |row| {
            Ok(TxId::from_bytes(row.get(0)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut polls = session.lock();
    for txid in txids {
        polls.opened.remove(&txid);
        polls.polled.remove(&txid);
    }
    Ok(())
}
