//! Incoming allocation fills old holes without forgetting issued payment instructions.
use super::{
    Discovery, Error, KeyId, Purpose, RegisteredKey, account_key, corrupt, decode_index,
    issuance_start, register,
};
use crate::{AccountUuid, WalletDb, util::Clock, wallet};
use rand_core::Rng;
use rusqlite::{Connection, OptionalExtension, params};
use std::borrow::{Borrow, BorrowMut};
use zakura_swap_receiving::lifecycle::{ProviderStatus, near_observation};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_protocol::consensus::{BlockHeight, Parameters};

/// Incoming seed recovery must search at least this many consecutive empty indices.
pub const RECEIVE_GAP_LIMIT: u64 = 30;
/// [`RECEIVE_GAP_LIMIT`] as a lookahead key count.
pub(super) const RECEIVE_LOOKAHEAD: u32 = RECEIVE_GAP_LIMIT as u32;
/// Grace after the last deposit deadline before an unpaid reservation can be recycled.
pub const RECEIVE_RECLAIM_SECONDS: i64 = 24 * 60 * 60;
/// Maximum number of distinct addresses held by unfunded drafts or swaps per account:
/// half the [`RECEIVE_GAP_LIMIT`], so issuance stays well inside the recovery gap. A
/// reservation stops counting once the provider sees its deposit or its payment arrives.
pub const RECEIVE_UNFUNDED_LIMIT: u32 = RECEIVE_LOOKAHEAD / 2;
const STATUS_FRESH_SECONDS: i64 = 120;

/// A durable draft or started swap, independent of whether it received funds.
pub struct ReceiveReservation {
    /// Stable identity; quote attempts and retries must retain it.
    pub id: i64,
    /// Its receiving key. Never log viewing material.
    pub key: RegisteredKey,
}

/// Provider lookup information retained even when a quote was never started in the UI.
#[derive(Clone, Debug)]
pub struct ReceiveQuote {
    /// Local request identity created before contacting the provider.
    pub request_id: String,
    /// Provider deposit address used for status lookups.
    pub operation_id: String,
    /// Provider memo required for memo-based deposits.
    pub deposit_memo: Option<String>,
}

/// Deposit instructions of an accepted incoming quote, as the provider issued them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveDeposit {
    /// Provider deposit address, which also identifies the provider operation.
    pub address: String,
    /// Memo the deposit must carry, on routes that tell deposits apart by memo.
    pub memo: Option<String>,
    /// Unix time after which the provider stops accepting the deposit.
    pub deadline: i64,
}

/// How a request begun with [`WalletDb::begin_swap_receive_quote`] ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuoteOutcome {
    /// The provider accepted the request with these deposit instructions.
    Accepted(ReceiveDeposit),
    /// The provider definitively rejected the request. A timeout or a malformed
    /// response is not a rejection: leave the outcome unknown instead.
    Rejected,
}

/// The key of `account`'s reservation `id`.
fn reservation_key(conn: &Connection, account: AccountUuid, id: i64) -> Result<i64, Error> {
    Ok(conn.query_row(
        "SELECT r.receiving_key_id FROM ironwood_swap_receive_reservations r
         JOIN ironwood_receiving_keys k ON k.id = r.receiving_key_id
         JOIN accounts a ON a.id = k.account_id
         WHERE a.uuid = ?1 AND r.id = ?2",
        params![account.0, id],
        |r| r.get(0),
    )?)
}

/// The key of the quote begun as `request`, which must belong to `account`.
fn request_key(conn: &Connection, account: AccountUuid, request: &str) -> Result<i64, Error> {
    let id: i64 = conn.query_row(
        "SELECT reservation_id FROM ironwood_swap_receive_quotes WHERE request_id = ?1",
        [request],
        |r| r.get(0),
    )?;
    reservation_key(conn, account, id)
}

/// Whether key `key` ever received a payment.
pub(super) fn used(conn: &Connection, key: i64) -> Result<bool, Error> {
    Ok(conn.query_row(
        "SELECT used FROM ironwood_receiving_keys WHERE id = ?1",
        [key],
        |r| r.get(0),
    )?)
}

/// Whether `key` is open and scanned through the chain tip without a payment or
/// queued candidate. Reuse relies on the key having been scanned since issuance.
fn scanned_empty(conn: &Connection, key: i64) -> Result<bool, Error> {
    let active: bool = conn.query_row(
        "SELECT active_from IS NOT NULL AND closed_at IS NULL
         FROM ironwood_receiving_keys WHERE id = ?1",
        [key],
        |r| r.get(0),
    )?;
    let pending: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_swap_payment_recovery WHERE receiving_key_id=?1)",
        [key],
        |r| r.get(0),
    )?;
    let tip = wallet::chain_tip_height(conn)?;
    Ok(active
        && !pending
        && !used(conn, key)?
        && tip.is_some()
        && wallet::fully_scanned_height(conn)? == tip)
}

/// The first incoming index seed recovery may not reach: [`RECEIVE_GAP_LIMIT`] past
/// the highest paid one. Local issuance and provider deposits cannot move it. A
/// receipt counts once it has the default untrusted confirmations, so a reorg cannot
/// lower the bound below keys already issued; a payment before the birthday counts
/// once its inclusion was checked (see `PaymentApplication::BeforeBirthday`).
fn recovery_end(conn: &Connection, account: i64) -> Result<u64, Error> {
    let confirmed_below = wallet::chain_tip_height(conn)?.map(|tip| {
        u32::from(tip)
            .saturating_add(1)
            .saturating_sub(ConfirmationsPolicy::default().untrusted().get())
    });
    let paid: Option<Vec<u8>> = conn.query_row(
        "SELECT MAX(k.key_index) FROM ironwood_receiving_keys k
         WHERE k.account_id = ?1 AND k.purpose = 1 AND (k.paid_before_birthday = 1
             OR EXISTS(SELECT 1 FROM ironwood_received_notes n
                 JOIN transactions t ON t.id_tx = n.transaction_id
                 JOIN blocks b ON b.height = t.mined_height
                 WHERE n.receiving_key_id = k.id AND t.mined_height <= ?2))",
        params![account, confirmed_below],
        |r| r.get(0),
    )?;
    paid.map(decode_index)
        .transpose()?
        .map(|i| i.checked_add(1).ok_or(Error::IndexExhausted))
        .transpose()?
        .unwrap_or(0)
        .checked_add(RECEIVE_GAP_LIMIT)
        .ok_or(Error::IndexExhausted)
}

/// Closes reservation `id`, keeping its quote associations. Its quotes are no longer
/// polled; the caller decides when the key's scanning ends.
/// Reaping admits only expired unfunded deposits as still open, which expect no receipt.
fn close_reservation(conn: &Connection, id: i64, now: i64) -> Result<(), Error> {
    conn.execute(
        "UPDATE ironwood_swap_receive_reservations SET closed_at = ?2 WHERE id = ?1",
        params![id, now],
    )?;
    conn.execute(
        "UPDATE ironwood_swap_operations
         SET expectation = 1, expected_value = NULL, observed_at = MAX(observed_at, ?2)
         WHERE expectation = 0
           AND receiving_key_id = (SELECT receiving_key_id
               FROM ironwood_swap_receive_reservations WHERE id = ?1)
           AND operation_id IN (SELECT 'receive-quote:' || request_id
               FROM ironwood_swap_receive_quotes WHERE reservation_id = ?1)",
        params![id, now],
    )?;
    Ok(())
}

/// Whether unpaid reservation `id` can be reclaimed at `now`. Every quote must be
/// past its deadline and the cooldown. An unknown request outcome needs nothing
/// more: its deposit window has closed. Accepted quotes also need a fresh conclusive
/// status. A clock change cannot turn a response from the future into a fresh one.
fn reusable(conn: &Connection, id: i64, now: i64) -> Result<bool, Error> {
    Ok(conn.query_row(
        "SELECT r.closed_at IS NULL AND r.created_at <= ?2 - ?3
            AND NOT (SELECT used FROM ironwood_receiving_keys WHERE id = r.receiving_key_id)
            AND NOT EXISTS(SELECT 1 FROM ironwood_swap_receive_quotes q
                WHERE q.reservation_id = r.id AND q.rejected = 0 AND (
                    q.deadline IS NULL OR q.deadline > ?2 - ?3
                    OR (q.operation_id IS NOT NULL AND (
                        q.checked_at IS NULL OR q.checked_at < ?2 - ?4 OR q.checked_at > ?2
                        OR q.status IS NULL
                        OR q.status NOT IN ('PENDING_DEPOSIT', 'REFUNDED', 'FAILED')
                        OR (q.funded = 1 AND q.status = 'PENDING_DEPOSIT')))))
         FROM ironwood_swap_receive_reservations r WHERE r.id = ?1",
        params![id, now, RECEIVE_RECLAIM_SECONDS, STATUS_FRESH_SECONDS],
        |r| r.get(0),
    )?)
}

impl<C: Borrow<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Whether an account-internal funding record may still hold an unregistered refund
    /// index after [`WalletDb::recover_refund_memos`]: its memo is not retrieved yet, or
    /// a decrypted marker lacks the own-send evidence that authenticates it while an
    /// input could still be found, because scanning from the birthday has not reached
    /// its block. Refund issuance and nullifier recovery wait for these records.
    /// Unrelated outgoing metadata does not block them.
    pub(crate) fn swap_refund_memos_pending(&self, account: AccountUuid) -> Result<bool, Error> {
        let conn = self.conn.borrow();
        let scanned = wallet::fully_scanned_height(conn)?.map(u32::from);
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             JOIN accounts a ON a.id = n.account_id
             WHERE a.uuid = ?1 AND n.recipient_key_scope = 1
               AND n.receiving_key_id IS NULL AND t.mined_height IS NOT NULL
               AND (n.memo IS NULL OR (substr(n.memo, 1, 5) = X'FF5A535750'
                 AND NOT EXISTS(SELECT 1 FROM v_received_output_spends s
                   WHERE s.transaction_id = n.transaction_id
                     AND s.account_id = n.account_id)
                 AND (?2 IS NULL OR t.mined_height > ?2))))",
            params![account.0, scanned],
            |r| r.get(0),
        )?)
    }

    /// Quotes requiring status reconciliation, including locally expired and never-started quotes.
    /// Caller errors must not be recorded as successful observations.
    pub fn swap_receive_quotes_due(
        &self,
        account: AccountUuid,
        now: i64,
    ) -> Result<Vec<ReceiveQuote>, Error> {
        let mut stmt = self.conn.borrow().prepare(
            "SELECT q.request_id, q.operation_id, q.deposit_memo
             FROM ironwood_swap_receive_quotes q
             JOIN ironwood_swap_receive_reservations r ON r.id = q.reservation_id
             JOIN ironwood_receiving_keys k ON k.id = r.receiving_key_id
             JOIN accounts a ON a.id = k.account_id
             WHERE a.uuid = ?1 AND r.closed_at IS NULL AND q.rejected = 0
               AND q.operation_id IS NOT NULL
               AND (q.checked_at IS NULL OR q.checked_at <= ?2 - 30 OR q.checked_at > ?2)
             ORDER BY r.id, q.rowid",
        )?;
        Ok(stmt
            .query_map(params![account.0, now], |r| {
                Ok(ReceiveQuote {
                    request_id: r.get(0)?,
                    operation_id: r.get(1)?,
                    deposit_memo: r.get(2)?,
                })
            })?
            .collect::<Result<_, _>>()?)
    }

    /// Reloads a reservation under its owning account, including closed history.
    pub(crate) fn swap_receive_reservation(
        &self,
        account: AccountUuid,
        id: i64,
    ) -> Result<ReceiveReservation, Error> {
        let key = self
            .swap_receiving_key_matching(
                account,
                "k.id = (SELECT receiving_key_id FROM ironwood_swap_receive_reservations
                         WHERE id = ?2)",
                params![account.0, id],
            )?
            .ok_or_else(|| corrupt("missing reserved receive key"))?;
        Ok(ReceiveReservation { id, key })
    }
}

impl<C: BorrowMut<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// [`WalletDb::begin_swap_receive_quote`] with a chosen request identity.
    pub(crate) fn begin_swap_receive_quote_as(
        &mut self,
        account: AccountUuid,
        reservation: i64,
        request: &str,
        deadline: i64,
        now: i64,
    ) -> Result<(), Error> {
        if request.is_empty() {
            return Err(corrupt("empty receive quote request"));
        }
        if deadline <= now {
            return Err(corrupt("receive quote deadline has passed"));
        }
        self.transactionally(|db| {
            let conn = db.conn.0;
            let key = reservation_key(conn, account, reservation)?;
            let open: bool = conn.query_row(
                "SELECT closed_at IS NULL AND started = 0
                 FROM ironwood_swap_receive_reservations WHERE id = ?1",
                [reservation],
                |r| r.get(0),
            )?;
            if !open || used(conn, key)? {
                return Err(Error::ReservationPolicy(super::ReservationPolicy::Stale));
            }
            let (owner, index): (i64, Vec<u8>) = conn.query_row(
                "SELECT account_id, key_index FROM ironwood_receiving_keys WHERE id = ?1",
                [key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if decode_index(index)? >= recovery_end(conn, owner)? {
                return Err(Error::ReservationPolicy(super::ReservationPolicy::Gap));
            }
            if !scanned_empty(conn, key)? {
                return Err(Error::ReservationPolicy(super::ReservationPolicy::Coverage));
            }
            conn.execute(
                "INSERT INTO ironwood_swap_receive_quotes (request_id, reservation_id, deadline)
                 VALUES (?1, ?2, ?3)",
                params![request, reservation, deadline],
            )?;
            // The provider now has the address, so issuance avoids it from here on.
            conn.execute(
                "UPDATE ironwood_receiving_keys SET quoted = 1 WHERE id = ?1",
                [key],
            )?;
            conn.execute(
                "INSERT INTO ironwood_swap_operations
                    (receiving_key_id, operation_id, observed_at, deadline)
                 VALUES (?1, ?2, ?3, ?4)",
                params![key, format!("receive-quote:{request}"), now, deadline],
            )?;
            Ok(())
        })
    }

    /// Records how a request begun with [`WalletDb::begin_swap_receive_quote`] ended.
    /// An accepted quote keeps its deposit instructions even if the requesting UI has
    /// moved on, and its deadline replaces the requested one. A rejection releases the
    /// request's hold on the address.
    pub fn finish_swap_receive_quote(
        &mut self,
        account: AccountUuid,
        request: &str,
        outcome: &QuoteOutcome,
    ) -> Result<(), Error> {
        if matches!(outcome, QuoteOutcome::Accepted(deposit) if deposit.address.is_empty()) {
            return Err(corrupt("empty receive quote deposit address"));
        }
        self.transactionally(|db| {
            let conn = db.conn.0;
            let key = request_key(conn, account, request)?;
            let operation = format!("receive-quote:{request}");
            match outcome {
                QuoteOutcome::Accepted(deposit) => {
                    let changed = conn.execute(
                        "UPDATE ironwood_swap_receive_quotes
                         SET operation_id = ?2, deposit_memo = ?3, deadline = ?4
                         WHERE request_id = ?1 AND rejected = 0
                           AND (operation_id IS NULL OR operation_id = ?2)",
                        params![request, deposit.address, deposit.memo, deposit.deadline],
                    )?;
                    if changed != 1 {
                        return Err(corrupt("receive quote identity changed"));
                    }
                    // The accepted deadline bounds scanning even if status responses omit it.
                    conn.execute(
                        "UPDATE ironwood_swap_operations SET deadline = ?3
                         WHERE receiving_key_id = ?1 AND operation_id = ?2",
                        params![key, operation, deposit.deadline],
                    )?;
                }
                QuoteOutcome::Rejected => {
                    conn.execute(
                        "UPDATE ironwood_swap_receive_quotes SET rejected = 1
                         WHERE request_id = ?1 AND operation_id IS NULL",
                        [request],
                    )?;
                    conn.execute(
                        "DELETE FROM ironwood_swap_operations
                         WHERE receiving_key_id = ?1 AND operation_id = ?2
                           AND EXISTS(SELECT 1 FROM ironwood_swap_receive_quotes
                             WHERE request_id = ?3 AND rejected = 1)",
                        params![key, operation, request],
                    )?;
                }
            }
            Ok(())
        })
    }

    /// Locks the draft of the accepted quote `request` before the UI exposes funding
    /// instructions, and returns those instructions. Show these, not a copy held
    /// elsewhere.
    pub fn start_swap_receive_quote(
        &mut self,
        account: AccountUuid,
        request: &str,
    ) -> Result<ReceiveDeposit, Error> {
        self.transactionally(|db| {
            let (a, _) = account_key(db.conn.0, &db.params, account)?;
            let quote: Option<(i64, String, Option<String>, i64)> = db
                .conn
                .0
                .query_row(
                    "SELECT r.id, q.operation_id, q.deposit_memo, q.deadline
                     FROM ironwood_swap_receive_quotes q
                     JOIN ironwood_swap_receive_reservations r ON r.id = q.reservation_id
                     JOIN ironwood_receiving_keys k ON k.id = r.receiving_key_id
                     WHERE q.request_id = ?1 AND k.account_id = ?2 AND q.rejected = 0
                       AND q.operation_id IS NOT NULL AND q.deadline IS NOT NULL
                       AND r.closed_at IS NULL",
                    params![request, a.0],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            let (reservation, address, memo, deadline) =
                quote.ok_or(Error::ReservationPolicy(super::ReservationPolicy::Stale))?;
            db.conn.0.execute(
                "UPDATE ironwood_swap_receive_reservations SET started=1 WHERE id=?1",
                [reservation],
            )?;
            Ok(ReceiveDeposit {
                address,
                memo,
                deadline,
            })
        })
    }

    /// Provider observations are monotonic in request time; deposit evidence is sticky.
    /// Unknown statuses hold the reservation and leave the key's operation alone.
    pub fn observe_swap_receive_quote(
        &mut self,
        account: AccountUuid,
        request: &str,
        status: &ProviderStatus<'_>,
        funded: bool,
        checked_at: i64,
    ) -> Result<(), Error> {
        self.transactionally(|db| {
            let conn = db.conn.0;
            let key = request_key(conn, account, request)?;
            let changed = conn.execute(
                "UPDATE ironwood_swap_receive_quotes
                 SET status = ?2, funded = MAX(funded, ?3), checked_at = ?4
                 WHERE request_id = ?1 AND operation_id IS NOT NULL
                   AND (checked_at IS NULL OR checked_at <= ?4)",
                params![request, status.status, funded, checked_at],
            )?;
            if changed == 0 {
                return Ok(());
            }
            if let Some(observation) = near_observation(Purpose::Receive, status) {
                let operation = format!("receive-quote:{request}");
                super::lifecycle::record_observation(
                    conn,
                    key,
                    &operation,
                    observation,
                    checked_at,
                )?;
            }
            Ok(())
        })
    }

    /// Ends settled paid reservations and reclaims abandoned unpaid ones whose
    /// addresses local scanning shows are still empty, in one transaction, and returns
    /// the reclaimed reservations. A reclaimed key stops scanning: each of its quotes
    /// is past its deadline with a conclusive status, so no swap can pay it. Issuing it
    /// again scans from the new reservation. Reconcile the quotes from
    /// [`WalletDb::swap_receive_quotes_due`] with the provider first: reclamation needs
    /// fresh conclusive statuses.
    pub fn reap_swap_receive_reservations(
        &mut self,
        account: AccountUuid,
        now: i64,
    ) -> Result<Vec<i64>, Error> {
        self.transactionally(|db| {
            let conn = db.conn.0;
            let (owner, _) = account_key(conn, &db.params, account)?;
            // A paid reservation keeps its key's used marker. Its old unfunded quote
            // edits finish after the cooldown and a fresh status, and unknown outcomes
            // after the cooldown alone.
            let paid = conn
                .prepare(
                    "SELECT r.id FROM ironwood_swap_receive_reservations r
                     JOIN ironwood_receiving_keys k ON k.id = r.receiving_key_id
                     WHERE k.account_id = ?1 AND k.used = 1 AND r.closed_at IS NULL
                       AND NOT EXISTS(SELECT 1 FROM ironwood_swap_receive_quotes q
                         WHERE q.reservation_id = r.id AND q.rejected = 0 AND (
                           (q.operation_id IS NULL AND (q.deadline IS NULL OR q.deadline > ?2 - ?3))
                           OR (q.operation_id IS NOT NULL AND (
                             q.status IS NULL OR q.checked_at IS NULL OR q.checked_at > ?2
                             OR (q.status NOT IN ('SUCCESS', 'REFUNDED', 'FAILED')
                               AND NOT (q.status = 'PENDING_DEPOSIT' AND q.funded = 0
                                 AND q.deadline IS NOT NULL AND q.deadline <= ?2 - ?3
                                 AND q.checked_at >= ?2 - ?4))))))",
                )?
                .query_map(
                    params![owner.0, now, RECEIVE_RECLAIM_SECONDS, STATUS_FRESH_SECONDS],
                    |r| r.get::<_, i64>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?;
            for id in paid {
                close_reservation(conn, id, now)?;
            }
            let open = conn
                .prepare(
                    "SELECT r.id, r.receiving_key_id FROM ironwood_swap_receive_reservations r
                     JOIN ironwood_receiving_keys k ON k.id = r.receiving_key_id
                     WHERE k.account_id = ?1 AND r.closed_at IS NULL ORDER BY k.key_index",
                )?
                .query_map([owner.0], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let mut reclaimed = Vec::new();
            for (id, key) in open {
                if reusable(conn, id, now)? && scanned_empty(conn, key)? {
                    close_reservation(conn, id, now)?;
                    conn.execute(
                        "UPDATE ironwood_receiving_keys SET closed_at = ?2
                         WHERE id = ?1 AND closed_at IS NULL",
                        params![key, now],
                    )?;
                    reclaimed.push(id);
                }
            }
            Ok(reclaimed)
        })
    }
}

impl<C: BorrowMut<Connection>, P: Parameters, CL, R: Rng> WalletDb<C, P, CL, R> {
    /// Saves an unknown quote outcome before a network request, so a lost response
    /// cannot free the address while a deposit could still reach it. `deadline` is
    /// the deposit deadline sent in the request. The outcome holds the reservation
    /// until that deadline is [`RECEIVE_RECLAIM_SECONDS`] in the past. Call this just
    /// before the request leaves the device, after any local validation. Requires
    /// the address to be scanned empty through the chain tip, checked atomically.
    /// Returns the request's identity, which later calls for this quote take.
    pub fn begin_swap_receive_quote(
        &mut self,
        account: AccountUuid,
        reservation: i64,
        deadline: i64,
        now: i64,
    ) -> Result<String, Error> {
        let mut id = [0; 16];
        self.rng.fill_bytes(&mut id);
        let request = hex::encode(id);
        self.begin_swap_receive_quote_as(account, reservation, &request, deadline, now)?;
        Ok(request)
    }
}

impl<C: BorrowMut<Connection>, P: Parameters, CL: Clock, R> WalletDb<C, P, CL, R> {
    /// Atomically resumes the single draft or locks the lowest free index that was never
    /// quoted, reusing the lowest abandoned one only when the recovery window holds no
    /// other. Does not expose the address.
    ///
    /// `tip` is the chain tip last observed from the network, within
    /// [`ISSUANCE_TIP_LAG`](super::ISSUANCE_TIP_LAG) blocks of the wallet's scan. A new
    /// key is scanned from the first unscanned block. Commits the restore lookahead if
    /// it is missing, then waits for pending incoming restore sweeps, which may reveal
    /// paid indices. Only canonical received notes advance the recovery bound; local
    /// issuance never does.
    pub fn prepare_swap_receive_reservation(
        &mut self,
        account: AccountUuid,
        now: i64,
        tip: BlockHeight,
    ) -> Result<ReceiveReservation, Error> {
        self.transactionally(|db| db.extend_receive_lookahead(account, RECEIVE_LOOKAHEAD))?;
        let id = self.transactionally(|db| {
            let scan_from = issuance_start(db.conn.0, tip)?;
            prepare(db.conn.0, &db.params, account, now, scan_from)
        })?;
        self.swap_receive_reservation(account, id)
    }
}

/// See [`WalletDb::prepare_swap_receive_reservation`]. Returns the reservation ID.
pub(super) fn prepare<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
    scan_from: BlockHeight,
) -> Result<i64, Error> {
    let (a, _) = account_key(conn, params, account)?;
    let sweeping: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_swap_sweeps s
        JOIN ironwood_receiving_keys k ON k.id=s.receiving_key_id
        WHERE k.account_id=?1 AND k.purpose=1 AND s.done_height IS NULL)",
        [a.0],
        |r| r.get(0),
    )?;
    if sweeping {
        return Err(Error::ReservationPolicy(super::ReservationPolicy::Gap));
    }
    // A received address is permanently excluded, even if later spent or rewound.
    conn.execute(
        "UPDATE ironwood_swap_receive_reservations SET started=1
        WHERE receiving_key_id IN (SELECT id FROM ironwood_receiving_keys WHERE used = 1)",
        [],
    )?;
    let end = recovery_end(conn, a.0)?;
    let draft: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT r.id,k.key_index FROM ironwood_swap_receive_reservations r
        JOIN ironwood_receiving_keys k ON k.id=r.receiving_key_id WHERE k.account_id=?1
        AND r.closed_at IS NULL AND r.started=0 ORDER BY r.id LIMIT 1",
            [a.0],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((id, index)) = draft {
        if decode_index(index)? >= end {
            return Err(Error::ReservationPolicy(super::ReservationPolicy::Gap));
        }
        return Ok(id);
    }
    let unfunded: u32 = conn.query_row(
        "SELECT COUNT(*) FROM ironwood_swap_receive_reservations r
         JOIN ironwood_receiving_keys k ON k.id = r.receiving_key_id
         WHERE k.account_id = ?1 AND r.closed_at IS NULL AND k.used = 0
           AND NOT EXISTS(SELECT 1 FROM ironwood_swap_receive_quotes q
             WHERE q.reservation_id = r.id AND q.funded = 1)",
        [a.0],
        |r| r.get(0),
    )?;
    if unfunded >= RECEIVE_UNFUNDED_LIMIT {
        return Err(Error::ReservationPolicy(super::ReservationPolicy::Limit));
    }
    // An address the provider was given is reissued only when the gap rule leaves no
    // fresh one, since reusing it lets the provider link the two swaps.
    let mut abandoned = None;
    let mut fresh = None;
    for index in 0..end {
        let (blocked, quoted): (bool, bool) = conn
            .query_row(
                "SELECT k.used = 1
                      OR EXISTS(SELECT 1 FROM ironwood_swap_receive_reservations r
                        WHERE r.receiving_key_id = k.id AND r.closed_at IS NULL)
                      OR EXISTS(SELECT 1 FROM ironwood_swap_payment_recovery p
                        WHERE p.receiving_key_id = k.id),
                    k.quoted = 1
                 FROM ironwood_receiving_keys k
                 WHERE k.account_id = ?1 AND k.purpose = 1 AND k.key_index = ?2",
                params![a.0, index.to_be_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or_default();
        if blocked {
            continue;
        }
        if !quoted {
            fresh = Some(index);
            break;
        }
        abandoned.get_or_insert(index);
    }
    let index = fresh
        .or(abandoned)
        .ok_or(Error::ReservationPolicy(super::ReservationPolicy::Gap))?;
    let (key, _) = register(
        conn,
        params,
        account,
        KeyId::new(Purpose::Receive, index),
        scan_from,
        true,
        Discovery::Scan,
        now,
    )?;
    conn.execute(
        "INSERT INTO ironwood_swap_receive_reservations (receiving_key_id, created_at)
         VALUES (?1, ?2)",
        params![key, now],
    )?;
    Ok(conn.last_insert_rowid())
}
