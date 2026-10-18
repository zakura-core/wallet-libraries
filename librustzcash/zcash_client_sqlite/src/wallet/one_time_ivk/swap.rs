//! Swaps built on one-time keys: incoming reservations and their quote operations,
//! refund keys and their funding, and the provider-status lifecycle that closes keys.

pub(super) mod funding;
pub(super) mod lifecycle;
pub(super) mod reservations;

pub(crate) use funding::start_funded_refund_keys;
pub use funding::verify_refund_funding_proposal;
pub use reservations::{
    OperationOutcome, ProviderSeen, RECEIVE_GAP_LIMIT, RECEIVE_RECLAIM_SECONDS, ReceiveDeposit,
    SEEN_SLACK_SECONDS,
};

use std::borrow::{Borrow, BorrowMut};

use rand_core::Rng;
use rusqlite::Connection;
use zakura_one_time_ivk::swap::Observation;
use zcash_protocol::{
    consensus::{BlockHeight, Parameters},
    memo::MemoBytes,
};

use super::{OneTimeKey, account_key};
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
    /// Issuance needs the provider's seen set read within the last
    /// `PROVIDER_READ_MAX_AGE_SECS` of the caller's clock, and at most
    /// `PROVIDER_READ_CLOCK_SKEW_SECS` ahead of it (see
    /// [`zakura_one_time_ivk::swap::provider_read_is_current`]), to rule out an address
    /// another device of the seed gave the provider. There was none, or it was older or
    /// further ahead: fetch it again.
    SeenUnavailable,
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
    /// seed already used is never issued again, skipping any the provider's seen set holds
    /// (see [`ProviderSeen`]). `seen` is the provider's current set, which must be fresh at
    /// `now`, the caller's clock in Unix seconds, or issuance is refused as
    /// [`ReservationPolicy::SeenUnavailable`]. `tip` is the network's chain tip (see
    /// [`ISSUANCE_TIP_LAG`]). The key scans only once its funding transaction is stored
    /// (see [`WalletDb::record_refund_operation`]). A seen set that holds a long run of
    /// unissued indices yields [`ReservationPolicy::Gap`] after registering a bounded
    /// number of them, which a later reservation continues past.
    pub fn reserve_refund_key(
        &mut self,
        account: AccountUuid,
        now: i64,
        tip: BlockHeight,
        seen: Option<&ProviderSeen<'_>>,
    ) -> Result<Result<OneTimeKey, ReservationPolicy>, SqliteClientError> {
        self.transactionally(|db| funding::reserve(db.conn.0, db.params, account, tip, seen, now))
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
    /// window. `seen` is the provider's current set, if the caller could fetch it, `now`
    /// the caller's clock in Unix seconds, and `tip` the network's chain tip (see
    /// [`ISSUANCE_TIP_LAG`]). Issuance waits for the account's discovery to register the
    /// indices its filters mark paid or seen (see `DiscoveryStatus::complete`), and checks
    /// the set first, so the lookahead covers any window its hits widen.
    ///
    /// One swap attempt keeps one address however often it is quoted again. The draft, an
    /// open reservation not started, paid or awaiting a payment, is resumed while its
    /// latest request's deadline (the accepted one, or else the requested one) has not
    /// passed by the earlier of `now` and the latest block time, even without a fresh set.
    /// Once it has passed, the next attempt gets another address. Only the current
    /// reservation's requests count, not a reissued address's earlier ones, though a
    /// reservation made before `ONE_TIME_IVK_DISCOVERY` counts every request on its key.
    /// A draft never quoted needs a fresh set, and is retired if the set holds it: never
    /// issued again, and scanned until `COMPLETION_LIMIT_SECS` after, in case the other
    /// device's swap pays it. Reserving a new address needs a set that is fresh at `now`
    /// (see [`ReservationPolicy::SeenUnavailable`]).
    pub fn prepare_receive_reservation(
        &mut self,
        account: AccountUuid,
        now: i64,
        tip: BlockHeight,
        seen: Option<&ProviderSeen<'_>>,
    ) -> Result<Result<OneTimeKey, ReservationPolicy>, SqliteClientError> {
        self.transactionally(|db| {
            let (conn, params) = (db.conn.0, db.params);
            if let Some(seen) = seen {
                let (account_ref, _) = account_key(conn, params, account)?;
                reservations::record_seen(conn, account_ref.0, seen)?;
            }
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
    /// identity. `deadline` is the deposit deadline it sends, and `now` the caller's clock
    /// in Unix seconds. The address must be scanned empty through the chain tip.
    ///
    /// Refused as [`ReservationPolicy::Stale`] once the reservation's latest request has
    /// expired as [`Self::prepare_receive_reservation`] judges it, so the next attempt
    /// prepares another address. A reservation's first request needs `seen`, the
    /// provider's current set, fresh at `now` (see [`ReservationPolicy::SeenUnavailable`]);
    /// if the set holds the address, another device gave it to the provider, so the
    /// reservation is retired (see [`Self::prepare_receive_reservation`]) and the request
    /// refused as stale.
    pub fn begin_receive_operation(
        &mut self,
        account: AccountUuid,
        index: u64,
        deadline: i64,
        now: i64,
        seen: Option<&ProviderSeen<'_>>,
    ) -> Result<Result<String, ReservationPolicy>, SqliteClientError> {
        let mut id = [0; 16];
        self.rng.fill_bytes(&mut id);
        let request = hex::encode(id);
        self.transactionally(|db| {
            reservations::begin(db.conn.0, account, index, &request, deadline, now, seen)
                .map(|begun| begun.map(|()| request))
        })
    }

    /// Records how `request` ended. An accepted deadline only shortens the requested one,
    /// and is refused if it has already passed by the earlier of the request time and the
    /// latest block time. A repeat must keep the accepted deposit address and memo, which
    /// no other operation in the account may hold. A request ends one way only: the other
    /// outcome is refused afterwards. Either way the provider has the address (see
    /// [`ProviderSeen`]).
    pub fn finish_receive_operation(
        &mut self,
        account: AccountUuid,
        request: &str,
        outcome: &OperationOutcome,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| reservations::finish(db.conn.0, account, request, outcome))
    }

    /// Starts the accepted operation `request` and returns its deposit instructions,
    /// which the UI shows rather than a copy held elsewhere. Refused as
    /// [`ReservationPolicy::Stale`] once another request on the same reservation has
    /// started, or once the deposit deadline has passed by the earlier of `now`, the
    /// caller's clock in Unix seconds, and the latest block time. Starting the same request
    /// again returns the same instructions.
    pub fn start_receive_operation(
        &mut self,
        account: AccountUuid,
        request: &str,
        now: i64,
    ) -> Result<Result<ReceiveDeposit, ReservationPolicy>, SqliteClientError> {
        self.transactionally(|db| reservations::start(db.conn.0, account, request, now))
    }

    /// Records a provider status, requested at `now` and normalized by the app's provider
    /// adapter (for NEAR Intents, `zakura_near_intents::near_observation`), on `account`'s
    /// accepted operations with this deposit address and memo, then reclaims what became
    /// reclaimable. Returns whether any matched.
    ///
    /// An observation older than the stored one is ignored, except that its `funded` still
    /// sticks. A refund key this wallet never funded
    /// starts at its issuance point on a refund owed or an inconclusive end, in case the
    /// deposit was paid from elsewhere; a closed key stays closed (see
    /// [`Self::close_finished_one_time_keys`]).
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

    /// Reclaims what became reclaimable, then stops trial decryption for `account`'s
    /// finished keys and returns how many closed.
    ///
    /// A key closes once every operation on it has a conclusive final status and its
    /// receipts cover what the provider promised, or `COMPLETION_LIMIT_SECS` after its
    /// latest deadline (registration without operations); a key only discovery found
    /// closes `RESTORE_WATCH_SECS` after the block its lookup finished at, or registration
    /// if later. An open reservation holds its key open, once started only until that limit:
    /// the address then stays reserved, so it is never reissued. A key stays open while
    /// a receipt is unmined and unexpired or short of the default untrusted
    /// confirmations, so a reorg cannot strand one. Nothing closes unless the stored tip
    /// and the scanned height equal `tip`, which the caller just confirmed, and closing
    /// uses the earlier of `now` and `tip`'s block time.
    ///
    /// No provider status reopens a closed key; a rewind does, when it un-mines a receipt
    /// or leaves it short of those confirmations. A later payment to a closed key is found
    /// only by [`Self::recheck_one_time_key_history`], and an incoming index beyond the
    /// restored lookahead is never checked.
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

/// SQL condition on `ironwood_one_time_keys k`: its incoming reservation is open.
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

#[cfg(test)]
mod tests;
