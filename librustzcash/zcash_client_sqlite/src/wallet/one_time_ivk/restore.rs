//! Private receiver recovery with short database transactions around network work.

pub(crate) mod apply;
pub(super) mod payments;
pub(crate) mod queue;
pub(crate) mod recovery;

use crate::{AccountUuid, WalletDb, error::SqliteClientError, util::Clock};
use payments::PendingPayment;
use rand_core::Rng;
use rusqlite::Connection;
use std::borrow::{Borrow, BorrowMut};
use zakura_one_time_ivk::KeyId;
use zcash_client_backend::data_api::one_time_ivk::restore::{
    DiscoveryWork, FilterOutcome, FilterSpan, LookupPage, LookupWork, RecoveryPublication,
    RecoveryStatus, RecoveryToken,
};
use zcash_protocol::consensus::{BlockHeight, Parameters};

impl<C: Borrow<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Returns bounded due network work without retaining a database lock across requests.
    /// An account that isn't enabled exposes none. With the
    /// captured inventory's `inventory_end`, the listed lookups are those it can answer,
    /// and `waits_for_retry` and `waits_for_publication` tell why any others wait.
    pub fn one_time_recovery(
        &self,
        account: AccountUuid,
        now: i64,
        inventory_end: Option<BlockHeight>,
    ) -> Result<RecoveryStatus, SqliteClientError> {
        queue::status(
            self.conn.borrow(),
            &self.params,
            account,
            now,
            inventory_end,
        )
    }

    /// Captures the monitored receivers for local filter matching and the cancellation
    /// fence the match commits under.
    pub fn one_time_receivers(
        &self,
        account: AccountUuid,
    ) -> Result<(RecoveryToken, Vec<DiscoveryWork>), SqliteClientError> {
        queue::receivers(self.conn.borrow(), &self.params, account)
    }
}

impl<C: BorrowMut<Connection>, P: Parameters, CL: Clock, R: Rng> WalletDb<C, P, CL, R> {
    /// Enables discovery for `account`, which then stays enabled: it registers the receive
    /// window and recovers stored refund memos. Enabling an enabled account changes nothing
    /// that a later step would not redo.
    pub fn enable_one_time_recovery(
        &mut self,
        account: AccountUuid,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| queue::enable(db.conn.0, db.params, account))
    }

    /// Accepts a chain-compatible publication for queued work. With `complete`, it also runs
    /// a complete check, which a round needs when the account has no filter marker or its
    /// marker is older than the filters served: every monitored key, paid receive keys and
    /// refund keys still monitored included, gets a lookup from its last PIR check through
    /// the publication's end. The marker moves to the highest block at or below both that
    /// end and the wallet's fully scanned block, and stays put when there is none, so the
    /// round asks again after more sync. A repeat payment to a paid key is found either way.
    ///
    /// The first publication an account accepts, before any marker, seed walk or history
    /// check, runs that complete check even without `complete` when the account's untouched
    /// receive bootstraps were queued past the publication's end and the marker can be
    /// placed. Those lookups then read only through that end, and filters from the marker
    /// cover the blocks after it, so the account's first receive address doesn't wait for
    /// the publication to reach the wallet's tip. Every other target is kept.
    pub fn begin_one_time_recovery(
        &mut self,
        account: AccountUuid,
        publication: RecoveryPublication,
        complete: bool,
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| {
            queue::begin(db.conn.0, db.params, account, publication, complete)
        })
    }

    /// Commits a filter span matched against the receivers [`Self::one_time_receivers`]
    /// captured with `captured`, with each hit's height, and moves the account's marker to
    /// its end. The span must start just past the marker with the marker's hash as its
    /// parent, or at Ironwood activation with no marker; any other start is an error. Its
    /// end must be a block the wallet has fully scanned, with the same hash. See
    /// [`FilterOutcome`] for what to do otherwise. Each hit queues a lookup of its key from
    /// the key's history start through the hit. A negative never completes a key's history.
    pub fn record_one_time_filter_span(
        &mut self,
        account: AccountUuid,
        captured: RecoveryToken,
        span: &FilterSpan,
        hits: &[(BlockHeight, KeyId)],
    ) -> Result<FilterOutcome, SqliteClientError> {
        self.transactionally(|db| {
            queue::record_filter_span(db.conn.0, db.params, account, captured, span, hits)
        })
    }

    /// Accepts one bounded history step only if its captured account, birthday and chain
    /// remain current. Each new candidate is stored with its witness payload and admitted
    /// once that payload is usable against the wallet's own tree.
    pub fn record_one_time_lookup(
        &mut self,
        account: AccountUuid,
        work: &LookupWork,
        page: &LookupPage,
        now: i64,
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| {
            queue::record_lookup(
                db.conn.0,
                db.params,
                &db.one_time_sessions(),
                account,
                work,
                page,
                now,
            )
        })
    }

    /// Records that the receiver service needs a newer client, after any step returned
    /// `Unsupported` for its inventory, session or record format. Show the user that the
    /// app needs an update; do not defer the work. `one_time_recovery` then exposes no
    /// lookups, while every pending lookup, candidate and obligation is
    /// kept. A later `begin_one_time_recovery` with a publication this client captured
    /// resumes the work.
    pub fn require_one_time_upgrade(
        &mut self,
        account: AccountUuid,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| queue::require_upgrade(db.conn.0, db.params, account))
    }

    /// Forgets every history result `account` holds, as a history correction does: the
    /// filter marker, each lookup's coverage and cursor, and payment candidates not yet
    /// admitted. The next round reads each watched address again from its history start, and
    /// open receive reservations are held until then. Call it after switching to another
    /// receiver service, since the old one's answers, such as a payment it left out, need
    /// not hold for the new one.
    pub fn reset_one_time_history(
        &mut self,
        account: AccountUuid,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| queue::reset(db.conn.0, db.params, account))
    }

    /// Backs off a lookup whose answer failed, from a minute doubling up to twelve hours,
    /// without recording an empty result. A transport failure needs no deferral, since the
    /// lookup stays due, and [`Self::check_one_time_history`] makes backed-off lookups due
    /// again.
    pub fn defer_one_time_lookup(
        &mut self,
        account: AccountUuid,
        work: &LookupWork,
        now: i64,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| queue::defer(db.conn.0, db.params, account, work, now))
    }

    /// Starts or resumes explicit older-address recovery through a captured publication.
    /// `receive_end` is exclusive. Known funded refunds are included without an index sweep.
    pub fn check_one_time_history(
        &mut self,
        account: AccountUuid,
        publication: RecoveryPublication,
        receive_end: Option<u64>,
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| {
            queue::manual(db.conn.0, db.params, account, publication, receive_end)
        })
    }

    /// Starts or resumes the history check of every account in `accounts` through one
    /// captured publication, each up to its automatic receive end, in one transaction. If
    /// any account refuses, as one not enabled or one whose chain no longer holds the
    /// publication's end does, none start: this returns that account, and nothing changes.
    pub fn check_one_time_history_for(
        &mut self,
        accounts: &[AccountUuid],
        publication: RecoveryPublication,
    ) -> Result<Option<AccountUuid>, SqliteClientError> {
        let started = self.transactionally(|db| {
            for account in accounts {
                if !queue::manual(db.conn.0, db.params, *account, publication, None)
                    .map_err(Batch::Failed)?
                {
                    return Err(Batch::Refused(*account));
                }
            }
            Ok(())
        });
        match started {
            Ok(()) => Ok(None),
            Err(Batch::Refused(account)) => Ok(Some(account)),
            Err(Batch::Failed(e)) => Err(e),
        }
    }

    /// Cancels the manual job while retaining its cursor and automatic filter obligations.
    pub fn cancel_one_time_history(
        &mut self,
        account: AccountUuid,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| queue::cancel_manual(db.conn.0, db.params, account))
    }
}

/// Why a batch operation rolled back: an account refused it, or the store failed.
enum Batch {
    Refused(AccountUuid),
    Failed(SqliteClientError),
}

impl From<rusqlite::Error> for Batch {
    /// A database failure fails the batch.
    fn from(e: rusqlite::Error) -> Self {
        Batch::Failed(e.into())
    }
}

#[cfg(test)]
pub(super) mod tests;
