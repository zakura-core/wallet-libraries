//! Restore of one-time keys from the seed: funding-memo recovery and the incoming
//! lookahead, receiver-directory sweeps (planning, lookups, applying payments), the
//! Ironwood spend evidence they need, and the paid-filter backstop for closed keys.

pub(super) mod apply;
pub(crate) mod early;
pub(super) mod payments;
pub(super) mod planner;
pub(super) mod recovery;
pub(super) mod retention;
pub(crate) mod sweep;

pub(crate) use apply::apply_sweep;
use payments::{PendingPayment, SpendStatus};
pub(crate) use planner::{begin_sweep_attempt, history_pending, keys_to_recheck, prepare_sweeps};
pub(crate) use recovery::{maintain, record_paid_check};
pub(crate) use retention::finish_nullifier_recovery;
pub(crate) use sweep::{publication_anchor, queue_directory_lookup};

use std::borrow::BorrowMut;

use rand_core::Rng;
use rusqlite::Connection;
use zcash_protocol::consensus::Parameters;

use crate::{AccountUuid, WalletDb, error::SqliteClientError, util::Clock};

impl<C: BorrowMut<Connection>, P: Parameters, CL: Clock, R: Rng> WalletDb<C, P, CL, R> {
    /// Queues a receiver-directory sweep of each of `account`'s closed keys, as a restore
    /// does, to find a payment after its key closed, and returns how many were queued.
    pub fn recheck_one_time_key_history(
        &mut self,
        account: AccountUuid,
    ) -> Result<usize, SqliteClientError> {
        self.transactionally(|db| recovery::recheck(db.conn.0, db.params, account))
    }

    /// Declares that `account`'s seed was generated for it and never used elsewhere, so
    /// it has no one-time key history to restore: incoming issuance then waits for no
    /// restore sweeps, and needs no receiver directory before the first swap. Issuance
    /// still checks the provider's seen set. Call it when creating the account, before any
    /// other one-time IVK call; an account with one-time keys is refused. An account
    /// never declared fresh is treated as restored.
    pub fn mark_one_time_account_fresh(
        &mut self,
        account: AccountUuid,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| recovery::mark_fresh(db.conn.0, db.params, account))
    }
}

#[cfg(test)]
pub(super) mod tests;
