//! Local quote ownership, receive recycling and authenticated refund funding.

pub(super) mod funding;
pub(super) mod lifecycle;
pub(super) mod preparations;
pub(super) mod reservations;

pub(crate) use funding::record_funded_refund_keys;
pub use funding::verify_refund_funding_proposal;
pub use reservations::{OperationOutcome, ReceiveDeposit};

use super::{OneTimeKey, account_key, restore::queue};
use crate::{AccountUuid, WalletDb, error::SqliteClientError, util::Clock};
use rand_core::Rng;
use rusqlite::{Connection, OptionalExtension};
use std::borrow::{Borrow, BorrowMut};
use zakura_one_time_ivk::swap::Observation;
use zcash_protocol::{
    consensus::{BlockHeight, Parameters},
    memo::MemoBytes,
};

/// Why a new private address or operation cannot currently be issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationPolicy {
    /// The feature is disabled for this account.
    Disabled,
    /// The requested index exceeds the payment-backed receive window.
    Gap,
    /// Unresolved operations occupy every eligible receive address.
    Limit,
    /// The reservation or operation is no longer available.
    Stale,
    /// Ordinary history must catch up before allocating another refund index.
    FundingHistory,
    /// Automatic discovery has not finished checking the next receive address's history,
    /// which a restored seed may already have paid. Run recovery, then ask again.
    ReceiveHistory,
    /// The next refund index's own lookup has not finished, and another device may have
    /// used it. Run recovery, then ask again.
    RefundHistory,
}

impl<C: Borrow<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Returns the authenticated internal memo required on the funding transaction.
    pub fn refund_funding_memo(
        &self,
        account: AccountUuid,
        index: u64,
        deposit: &str,
    ) -> Result<MemoBytes, SqliteClientError> {
        funding::funding_memo(self.conn.borrow(), &self.params, account, index, deposit)
    }
}

impl<C: BorrowMut<Connection>, P: Parameters, CL: Clock, R: Rng> WalletDb<C, P, CL, R> {
    /// Hands out the prepared refund key after ordinary funding history catches up, once
    /// its own lookup finished and it is still unused and unfunded (see
    /// [`Self::prepare_one_time_keys`]).
    pub fn reserve_refund_key(
        &mut self,
        account: AccountUuid,
        tip: BlockHeight,
    ) -> Result<Result<OneTimeKey, ReservationPolicy>, SqliteClientError> {
        self.transactionally(|db| {
            if !enabled(db.conn.0, db.params, account)? {
                return Ok(Err(ReservationPolicy::Disabled));
            }
            funding::reserve(db.conn.0, db.params, account, tip, true)
        })
    }

    /// Binds the quoted deposit to its reserved refund key before funding can occur.
    pub fn record_refund_operation(
        &mut self,
        account: AccountUuid,
        index: u64,
        deposit: &str,
        deadline: i64,
        now: i64,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| {
            if !enabled(db.conn.0, db.params, account)? {
                return Err(super::invalid("private receivers disabled"));
            }
            funding::record_operation(db.conn.0, db.params, account, index, deposit, deadline, now)
        })
    }

    /// Resumes a live draft or recycles the lowest unpaid eligible receive index.
    /// Payment evidence alone extends the four-index window. A new index is issued only
    /// once its own automatic history lookup completed, never waiting on other indexes.
    pub fn prepare_receive_reservation(
        &mut self,
        account: AccountUuid,
        now: i64,
    ) -> Result<Result<OneTimeKey, ReservationPolicy>, SqliteClientError> {
        self.transactionally(|db| {
            if !enabled(db.conn.0, db.params, account)? {
                return Ok(Err(ReservationPolicy::Disabled));
            }
            reservations::reap(db.conn.0, db.params, account, now)?;
            queue::ensure_window(db.conn.0, db.params, account)?;
            reservations::prepare(db.conn.0, db.params, account, now, true)
        })
    }

    /// Prepares the next receive address and the next refund key ahead of a swap, each
    /// checked by its own lookup through the wallet's scanned tip, without handing either
    /// out. Calls are idempotent: each keeps its candidate until it is handed out by
    /// [`Self::prepare_receive_reservation`] or [`Self::reserve_refund_key`], which re-check
    /// it then, or a payment or funding memo makes it ineligible and it moves to the next
    /// index. Returns the receive and refund outcomes; `ReceiveHistory` and `RefundHistory`
    /// mean the lookup is still due.
    #[allow(clippy::type_complexity)]
    pub fn prepare_one_time_keys(
        &mut self,
        account: AccountUuid,
        tip: BlockHeight,
        now: i64,
    ) -> Result<
        (
            Result<OneTimeKey, ReservationPolicy>,
            Result<OneTimeKey, ReservationPolicy>,
        ),
        SqliteClientError,
    > {
        self.transactionally(|db| {
            if !enabled(db.conn.0, db.params, account)? {
                let off = ReservationPolicy::Disabled;
                return Ok((Err(off), Err(off)));
            }
            reservations::reap(db.conn.0, db.params, account, now)?;
            queue::ensure_window(db.conn.0, db.params, account)?;
            let receive = reservations::prepare(db.conn.0, db.params, account, now, false)?;
            let refund = funding::reserve(db.conn.0, db.params, account, tip, false)?;
            Ok((receive, refund))
        })
    }

    /// Drops the account's preparations. Their candidate keys stay registered.
    pub fn cancel_one_time_preparations(
        &mut self,
        account: AccountUuid,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| {
            let Some(owner) = super::one_time_account(db.conn.0, db.params, account)? else {
                return Ok(());
            };
            preparations::consume(db.conn.0, owner.0, super::Purpose::Receive)?;
            preparations::consume(db.conn.0, owner.0, super::Purpose::Refund)
        })
    }

    /// Records request ownership before sending a quote request, fencing stale responses.
    pub fn begin_receive_operation(
        &mut self,
        account: AccountUuid,
        index: u64,
        deadline: i64,
        now: i64,
    ) -> Result<Result<String, ReservationPolicy>, SqliteClientError> {
        let mut id = [0; 16];
        self.rng.fill_bytes(&mut id);
        let request = hex::encode(id);
        self.transactionally(|db| {
            if !enabled(db.conn.0, db.params, account)? {
                return Ok(Err(ReservationPolicy::Disabled));
            }
            reservations::begin(db.conn.0, account, index, &request, deadline, now)
                .map(|begun| begun.map(|()| request))
        })
    }

    /// Records an accepted quote or definitive rejection. Timeouts remain unresolved.
    pub fn finish_receive_operation(
        &mut self,
        account: AccountUuid,
        request: &str,
        outcome: &OperationOutcome,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| reservations::finish(db.conn.0, account, request, outcome))
    }

    /// Claims the current accepted request and returns its stored deposit instructions.
    pub fn start_receive_operation(
        &mut self,
        account: AccountUuid,
        request: &str,
        now: i64,
    ) -> Result<Result<ReceiveDeposit, ReservationPolicy>, SqliteClientError> {
        self.transactionally(|db| {
            if !enabled(db.conn.0, db.params, account)? {
                return Ok(Err(ReservationPolicy::Disabled));
            }
            reservations::start(db.conn.0, account, request, now)
        })
    }

    /// Updates operation ownership, expected receipts and the provider's reported receipt
    /// transactions without granting note ownership.
    pub fn record_operation_status(
        &mut self,
        account: AccountUuid,
        deposit: &str,
        memo: Option<&str>,
        observation: Observation,
        now: i64,
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| {
            reservations::record_status(
                db.conn.0,
                db.params,
                account,
                (deposit, memo),
                observation,
                now,
            )
        })
    }
}

/// SQL condition on `ironwood_one_time_keys k`: local receive reservation ownership.
pub(in crate::wallet::one_time_ivk) const RESERVED: &str =
    "(k.reserved_at IS NOT NULL AND k.released_at IS NULL)";

/// Reads the durable toggle inside the same transaction as the issuance mutation. An
/// account that never enabled recovery has no progress row and is disabled. One without an
/// Orchard key is refused, since these calls issue keys.
fn enabled<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
) -> Result<bool, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    Ok(conn
        .query_row(
            "SELECT enabled FROM ironwood_one_time_recovery WHERE account_id = ?1",
            [owner.0],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(false))
}

#[cfg(test)]
mod tests;
