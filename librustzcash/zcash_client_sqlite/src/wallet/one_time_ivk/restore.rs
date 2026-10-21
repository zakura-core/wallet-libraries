//! Private receiver recovery with short database transactions around network work.

pub(crate) mod apply;
pub(super) mod payments;
pub(crate) mod queue;
pub(super) mod recovery;

use crate::{AccountUuid, WalletDb, error::SqliteClientError, util::Clock};
use payments::PendingPayment;
use rand_core::Rng;
use rusqlite::Connection;
use std::borrow::{Borrow, BorrowMut};
use zakura_one_time_ivk::KeyId;
use zcash_client_backend::data_api::{
    one_time_ivk::restore::{
        DiscoveryWork, LookupPage, LookupWork, RecoveryPublication, RecoveryStatus, RecoveryToken,
        WitnessAnswer, WitnessRequest,
    },
    transparent_ledger::ChainPoint,
};
use zcash_protocol::consensus::Parameters;

impl<C: Borrow<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Returns bounded due network work without retaining a database lock across requests.
    /// Disabled discovery still exposes repair work for already-owned receipts.
    pub fn one_time_recovery(
        &self,
        account: AccountUuid,
        now: i64,
    ) -> Result<RecoveryStatus, SqliteClientError> {
        queue::status(self.conn.borrow(), &self.params, account, now)
    }

    /// Counts the actual direct catch-up set without queuing requests or including completed old keys.
    pub fn one_time_direct_query_count(
        &self,
        account: AccountUuid,
    ) -> Result<usize, SqliteClientError> {
        let (owner, _) = super::account_key(self.conn.borrow(), &self.params, account)?;
        Ok(queue::direct_keys(self.conn.borrow(), owner.0)?.len())
    }

    /// Captures eligible receiver identities for local filter matching and its cancellation fence.
    pub fn one_time_receivers(
        &self,
        account: AccountUuid,
    ) -> Result<(RecoveryToken, Vec<DiscoveryWork>), SqliteClientError> {
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

    /// Accepts a chain-compatible publication and optionally queues unfinished direct catch-up.
    pub fn begin_one_time_recovery(
        &mut self,
        account: AccountUuid,
        publication: RecoveryPublication,
        direct: bool,
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| queue::begin(db.conn.0, db.params, account, publication, direct))
    }

    /// Commits filter progress together with its matching receiver obligations.
    pub fn record_one_time_filters(
        &mut self,
        account: AccountUuid,
        captured: RecoveryToken,
        revision: u64,
        blocks: &[ChainPoint],
        hits: &[KeyId],
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| {
            queue::record_filters(
                db.conn.0, db.params, account, captured, revision, blocks, hits,
            )
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
