//! Swaps built on one-time keys: incoming reservations and their quote operations,
//! refund keys and their funding, and the provider-status lifecycle that closes keys.

pub(super) mod funding;
pub(super) mod lifecycle;
pub(super) mod reservations;

pub(crate) use funding::start_funded_refund_keys;
pub use funding::verify_refund_funding_proposal;
pub(crate) use reservations::RECEIVE_LOOKAHEAD;
pub use reservations::{
    OperationOutcome, ProviderSeen, RECEIVE_GAP_LIMIT, RECEIVE_RECLAIM_SECONDS, ReceiveDeposit,
    SEEN_SLACK_SECONDS,
};

use std::borrow::{Borrow, BorrowMut};

use rand_core::Rng;
use rusqlite::{Connection, named_params};
use zakura_one_time_ivk::swap::Observation;
use zcash_protocol::{
    consensus::{BlockHeight, Parameters},
    memo::MemoBytes,
};

use super::{
    Discovery, KeyId, OneTimeKey, Purpose, account_key, decode_index, next_index, purpose_code,
    register, restore::recovery, unix_now,
};
use crate::{AccountUuid, WalletDb, error::SqliteClientError, util::Clock};

/// Why issuance or an incoming operation must wait. The app owns its wording.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationPolicy {
    /// Recovery has not established the next safe index.
    Gap,
    /// Swaps in progress hold every incoming index the recovery gap allows.
    Limit,
    /// The reservation or operation is no longer available.
    Stale,
    /// The wallet has not scanned this address through the chain tip.
    Coverage,
}

impl<C: Borrow<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// The recovery memo for funding the refund operation recorded for `deposit`, to put
    /// on the funding transaction's internal Ironwood change (see
    /// [`verify_refund_funding_proposal`]).
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
    /// Reserves the next refund index, after recovering every funding memo so an index the
    /// seed already used is never issued again. `tip` is the network's chain tip (see
    /// [`ISSUANCE_TIP_LAG`]). The key scans only once its funding transaction is stored
    /// (see [`WalletDb::record_refund_operation`]).
    pub fn reserve_refund_key(
        &mut self,
        account: AccountUuid,
        tip: BlockHeight,
    ) -> Result<Result<OneTimeKey, ReservationPolicy>, SqliteClientError> {
        let now = unix_now(&self.clock);
        self.transactionally(|db| funding::reserve(db.conn.0, db.params, account, tip, now))
    }

    /// Binds a refund quote's deposit address to the refund key reserved at `index`,
    /// before the quote is shown; funding requires it. Repeating the binding is a no-op,
    /// and a key already bound to another deposit is refused. A refund only follows a deposit,
    /// so the key starts scanning when this wallet stores a transaction funding
    /// `deposit`, from the block above the scanned chain.
    pub fn record_refund_operation(
        &mut self,
        account: AccountUuid,
        index: u64,
        deposit: &str,
        deadline: i64,
        now: i64,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| {
            funding::record_operation(db.conn.0, db.params, account, index, deposit, deadline, now)
        })
    }

    /// Resumes the account's draft reservation or reserves an incoming address, scanned
    /// from the first unscanned block, after reclaiming abandoned reservations. See
    /// [`ProviderSeen`] for the addresses never issued and [`RECEIVE_GAP_LIMIT`] for the
    /// window. `seen` is the provider's current set, if the caller could fetch it, and
    /// `tip` the network's chain tip (see [`ISSUANCE_TIP_LAG`]). Issuance waits for the
    /// restore lookahead's sweeps, which may reveal paid or seen indices, and checks the
    /// set first, so the lookahead covers any window its hits widen.
    pub fn prepare_receive_reservation(
        &mut self,
        account: AccountUuid,
        now: i64,
        tip: BlockHeight,
        seen: Option<&ProviderSeen<'_>>,
    ) -> Result<Result<OneTimeKey, ReservationPolicy>, SqliteClientError> {
        let registered_at = unix_now(&self.clock);
        self.transactionally(|db| {
            let (conn, params) = (db.conn.0, db.params);
            if let Some(seen) = seen {
                let (account_ref, _) = account_key(conn, params, account)?;
                reservations::record_seen(conn, account_ref.0, seen)?;
            }
            recovery::extend_receive_lookahead(conn, params, account, registered_at)?;
            reservations::reap(conn, params, account, now)?;
            let scan_from = match issuance_start(conn, tip)? {
                Ok(from) => from,
                Err(policy) => return Ok(Err(policy)),
            };
            reservations::prepare(conn, params, account, now, scan_from, seen)
        })
    }

    /// Saves an unknown outcome for a quote request on the reservation at incoming
    /// `index`, just before the request leaves the device, and returns the request's
    /// identity. `deadline` is the deposit deadline it sends. The address must be
    /// scanned empty through the chain tip.
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
            reservations::begin(db.conn.0, account, index, &request, deadline, now)
                .map(|begun| begun.map(|()| request))
        })
    }

    /// Records how `request` ended. An accepted deadline only shortens the requested one,
    /// and a repeat must keep the accepted deposit address and memo, which no other
    /// operation in the account may hold. A rejection releases the request's hold on the
    /// address.
    pub fn finish_receive_operation(
        &mut self,
        account: AccountUuid,
        request: &str,
        outcome: &OperationOutcome,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| reservations::finish(db.conn.0, account, request, outcome))
    }

    /// Starts the accepted operation `request` and returns its deposit instructions,
    /// which the UI shows rather than a copy held elsewhere.
    pub fn start_receive_operation(
        &mut self,
        account: AccountUuid,
        request: &str,
    ) -> Result<Result<ReceiveDeposit, ReservationPolicy>, SqliteClientError> {
        self.transactionally(|db| reservations::start(db.conn.0, account, request))
    }

    /// Records a provider status, requested at `now` and normalized by the app's provider
    /// adapter, on `account`'s accepted operations with this deposit address and memo,
    /// then reclaims what became reclaimable. Returns whether any matched. `funded`,
    /// sticky, says a deposit was seen.
    ///
    /// An observation older than the stored one is ignored, except that its `funded` still
    /// sticks. A deadline only fills a missing one. A refund key this wallet never funded
    /// starts at its issuance point on a refund owed or an inconclusive end, in case the
    /// deposit was paid from elsewhere; a closed key stays closed (see
    /// [`Self::close_finished_one_time_keys`]).
    pub fn record_operation_status(
        &mut self,
        account: AccountUuid,
        deposit: &str,
        memo: Option<&str>,
        observation: Observation,
        funded: bool,
        now: i64,
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| {
            reservations::record_status(
                db.conn.0,
                db.params,
                account,
                (deposit, memo),
                observation,
                funded,
                now,
            )
        })
    }

    /// Reclaims what became reclaimable, then stops trial decryption for `account`'s
    /// finished keys and returns how many closed.
    ///
    /// A key closes once every operation on it has a conclusive final status and its
    /// receipts cover what the provider promised, or `COMPLETION_LIMIT_SECS` after its
    /// latest deadline (registration without one); a key only a restore sweep found
    /// closes `RESTORE_WATCH_SECS` after its sweep's lookup block, or registration if
    /// later. An open reservation holds its key open, once started only until that limit:
    /// the address then stays reserved, so it is never reissued. A key stays open while
    /// a receipt is unmined and unexpired or short of the default untrusted
    /// confirmations, so a reorg cannot strand one. Nothing closes unless the stored tip
    /// and the scanned height equal `tip`, which the caller just confirmed, and closing
    /// uses the earlier of `now` and `tip`'s block time.
    ///
    /// No provider status reopens a closed key; a rewind does, when it un-mines a receipt
    /// or leaves it short of those confirmations. A later payment to a closed key without
    /// a known payment is found once a newer publication's paid filter holds it (see
    /// `OneTimeIvkRestoreWrite::record_paid_filter_check`). One to a closed key that was already
    /// paid, such as a corrected larger payout, is found only by
    /// [`Self::recheck_one_time_key_history`], and an incoming index beyond the restored
    /// lookahead is never swept.
    pub fn close_finished_one_time_keys(
        &mut self,
        account: AccountUuid,
        now: i64,
        tip: BlockHeight,
    ) -> Result<usize, SqliteClientError> {
        self.transactionally(|db| {
            lifecycle::close_finished(db.conn.0, db.params, account, now, tip)
        })
    }
}

/// Blocks a wallet may trail the network tip and still issue an address. Further
/// behind, restore discovery may not yet have reached an index the seed already used.
pub const ISSUANCE_TIP_LAG: u32 = 10;

/// SQL condition on `ironwood_receiving_keys k`: its incoming reservation is open.
const RESERVED: &str = "(k.reserved_at IS NOT NULL AND k.released_at IS NULL)";

/// The first block a key issued now scans, if scanning is within [`ISSUANCE_TIP_LAG`] of
/// `tip` and the stored tip.
fn issuance_start(
    conn: &Connection,
    tip: BlockHeight,
) -> Result<Result<BlockHeight, ReservationPolicy>, SqliteClientError> {
    let Some(scanned) = crate::wallet::fully_scanned_height(conn)? else {
        return Ok(Err(ReservationPolicy::Coverage));
    };
    let tip = tip.max(crate::wallet::chain_tip_height(conn)?.unwrap_or(scanned));
    Ok(
        if u32::from(tip).saturating_sub(u32::from(scanned)) > ISSUANCE_TIP_LAG {
            Err(ReservationPolicy::Coverage)
        } else {
            Ok(scanned + 1)
        },
    )
}

/// Reserves the next `purpose` index, expecting payments from `scan_from`, without
/// readiness checks, skipping refund indices registered without advancing allocation.
/// Refuses with [`ReservationPolicy::Gap`] to scan a key whose restore sweep is pending.
pub(super) fn reserve_next<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    purpose: Purpose,
    scan_from: BlockHeight,
    discovery: Discovery,
    now: i64,
) -> Result<Result<OneTimeKey, ReservationPolicy>, SqliteClientError> {
    let (account_ref, _) = account_key(conn, params, account)?;
    // SQLite orders fixed-width big-endian blobs numerically. Unlike INTEGER, this
    // represents the entire u64 index space, including u64::MAX.
    let last: Option<Vec<u8>> = conn.query_row(
        "SELECT MAX(key_index) FROM ironwood_receiving_keys
         WHERE account_id = :account AND purpose = :purpose AND advances_allocation = 1",
        named_params![":account": account_ref.0, ":purpose": purpose_code(purpose)?],
        |row| row.get(0),
    )?;
    let mut index = match last {
        Some(bytes) => next_index(decode_index(bytes)?)?,
        None => 0,
    };
    while purpose == Purpose::Refund
        && conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_receiving_keys
             WHERE account_id = ?1 AND purpose = 0 AND key_index = ?2)",
            rusqlite::params![account_ref.0, index.to_be_bytes()],
            |row| row.get::<_, bool>(0),
        )?
    {
        index = next_index(index)?;
    }
    let key_id = KeyId::new(purpose, index);
    if matches!(discovery, Discovery::Scan) && sweep_pending(conn, account_ref.0, key_id)? {
        return Ok(Err(ReservationPolicy::Gap));
    }
    register(
        conn, params, account, key_id, scan_from, true, discovery, now,
    )
    .map(|(_, key)| Ok(key))
}

/// Whether `key_id`'s restore sweep is pending, so it cannot start (see [`super::activate`]).
fn sweep_pending(
    conn: &Connection,
    account_ref: i64,
    key_id: KeyId,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_receiving_keys k
         JOIN ironwood_one_time_sweeps s ON s.receiving_key_id = k.id
         WHERE k.account_id = ?1 AND k.purpose = ?2 AND k.key_index = ?3
           AND k.active_from IS NULL AND s.done_height IS NULL)",
        rusqlite::params![
            account_ref,
            purpose_code(key_id.purpose())?,
            key_id.index().to_be_bytes()
        ],
        |row| row.get(0),
    )?)
}

#[cfg(test)]
mod tests;
