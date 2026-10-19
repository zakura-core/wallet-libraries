//! Discovery of one-time keys a restored seed used: checking candidate receivers against a
//! receiver directory's filters, paging through paid keys' histories, turning payments
//! into scan hints or late candidates, and recovering refund keys from funding memos.

pub(crate) mod apply;
pub(crate) mod discovery;
pub(super) mod payments;
pub(crate) mod recovery;

use payments::PendingPayment;

use std::borrow::BorrowMut;

use rand_core::Rng;
use rusqlite::Connection;
use zcash_protocol::consensus::Parameters;

use crate::{AccountUuid, WalletDb, error::SqliteClientError, util::Clock};

impl<C: BorrowMut<Connection>, P: Parameters, CL: Clock, R: Rng> WalletDb<C, P, CL, R> {
    /// Ends `account`'s discovery pass, so the next one checks every key against the
    /// directory's current filters and reads each paid key's history past its cursor, to
    /// find a payment after its key closed. This is "Check swap history": once discovery is
    /// complete, nothing else starts a pass. A fresh account then runs that pass as a
    /// restored one does, so new swap addresses wait for it to register the keys it finds.
    pub fn recheck_one_time_key_history(
        &mut self,
        account: AccountUuid,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| recovery::recheck(db.conn.0, db.params, account))
    }

    /// Declares that `account`'s seed was generated for it and never used elsewhere, so
    /// it has no one-time key history to restore: issuance then waits for no discovery, and
    /// needs no receiver directory before the first swap. Issuance
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
