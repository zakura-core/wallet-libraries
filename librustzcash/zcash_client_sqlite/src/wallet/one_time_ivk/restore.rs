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
    FilterOutcome, FilterReceiver, FilterSpan, LookupPage, LookupWork, RecoveryPublication,
    RecoveryStatus, RecoveryToken, WitnessAnswer, WitnessRequest,
};
use zcash_protocol::consensus::{BlockHeight, Parameters};

impl<C: Borrow<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Returns bounded due network work without retaining a database lock across requests.
    /// Disabled discovery still exposes repair work for already-owned receipts. With the
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

    /// A counter that goes up in the same transaction as every new recovery obligation of
    /// any account: a key registered, refund funding learned from a memo, a filter hit
    /// queuing a lookup, a repair queued or a rescan requested. It is cheap to read, so an app can compare it with the value
    /// its last round saw and run a round only when it changed.
    pub fn one_time_new_work(&self) -> Result<u64, SqliteClientError> {
        Ok(self.conn.borrow().query_row(
            "SELECT sequence FROM ironwood_one_time_work",
            [],
            |r| r.get(0),
        )?)
    }

    /// Captures the monitored receivers for local filter matching, each with how far its
    /// filter coverage reaches, and the cancellation fence the match commits under.
    pub fn one_time_receivers(
        &self,
        account: AccountUuid,
    ) -> Result<(RecoveryToken, Vec<FilterReceiver>), SqliteClientError> {
        queue::receivers(self.conn.borrow(), &self.params, account)
    }
}

impl<C: BorrowMut<Connection>, P: Parameters, CL: Clock, R: Rng> WalletDb<C, P, CL, R> {
    /// Pauses or resumes discovery without deleting known notes or extending the receive window.
    pub fn set_one_time_recovery_enabled(
        &mut self,
        account: AccountUuid,
        enabled: bool,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| queue::set_enabled(db.conn.0, db.params, account, enabled))
    }

    /// Accepts a chain-compatible publication for queued work. With `complete`, it also runs
    /// a complete check, the alternative to filters over a gap: every monitored key, paid
    /// receive keys and refund keys still monitored included, gets a lookup from just past
    /// its filter coverage through the publication's end, and the account's frontier moves
    /// there. A repeat payment to a paid key is found either way. For a fresh account
    /// without a frontier (see `RecoveryStatus::fresh`), this is the four-lookup seed window.
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
    /// captured with `captured`, with each hit's height. The store decides whether the span
    /// is final for the wallet and continues committed coverage; see [`FilterOutcome`] for
    /// what to do otherwise. Each hit past its key's coverage queues a lookup from there.
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

    /// Accepts one bounded history page only if its captured account and chain remain current.
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
    /// lookups or witness requests, while every pending lookup, candidate and obligation is
    /// kept. A later `begin_one_time_recovery` with a publication this client captured
    /// resumes the work.
    pub fn require_one_time_upgrade(
        &mut self,
        account: AccountUuid,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| queue::require_upgrade(db.conn.0, db.params, account))
    }

    /// Delays a failed request without recording an empty result.
    pub fn defer_one_time_lookup(
        &mut self,
        account: AccountUuid,
        work: &LookupWork,
        now: i64,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| queue::defer(db.conn.0, db.params, account, work, now))
    }

    /// Attaches the companion witness `answer` to the candidate `request` names, then applies
    /// it through the normal note, inclusion and spend-evidence checks. A payload whose
    /// construction tree is unusable locally re-reads the payment for a fresh binding.
    pub fn record_one_time_witness(
        &mut self,
        account: AccountUuid,
        captured: RecoveryToken,
        request: WitnessRequest,
        answer: &WitnessAnswer,
        now: i64,
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| {
            queue::record_witness(
                db.conn.0,
                db.params,
                &db.one_time_sessions(),
                account,
                captured,
                request,
                answer,
                now,
            )
        })
    }

    /// Re-reads the payment behind `request` when its payment session can no longer serve
    /// the witness, for example after the session was replaced. The candidate stays pending
    /// and its old ordinal is discarded rather than reinterpreted.
    pub fn refresh_one_time_witness(
        &mut self,
        account: AccountUuid,
        captured: RecoveryToken,
        request: WitnessRequest,
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| queue::refresh(db.conn.0, db.params, account, captured, request))
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

    /// Cancels the manual job while retaining its cursor and automatic filter obligations.
    pub fn cancel_one_time_history(
        &mut self,
        account: AccountUuid,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| queue::cancel_manual(db.conn.0, db.params, account))
    }
}

#[cfg(test)]
pub(super) mod tests;
