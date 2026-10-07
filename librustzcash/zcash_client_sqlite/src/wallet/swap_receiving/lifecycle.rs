//! Provider observations and the rule that ends a key's trial decryption.
use super::{Error, KeyId, RESTORED_INCOMING, account_key, corrupt, payments::key_ref};
use crate::{AccountUuid, WalletDb, util::Clock, wallet, wallet::common::tx_unexpired_condition};
use rusqlite::{Connection, named_params, params};
use std::borrow::BorrowMut;
use zakura_swap_receiving::lifecycle::{
    COMPLETION_LIMIT_SECS, Observation, OperationStatus, RESTORE_WATCH_SECS, ReceiptExpectation,
};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_protocol::consensus::{BlockHeight, Parameters};

impl<C: BorrowMut<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Persists a provider observation of `operation` on `key` immediately.
    /// Observations older than the stored one are ignored.
    pub fn record_swap_observation(
        &mut self,
        account: AccountUuid,
        key: KeyId,
        operation: &str,
        observation: Observation,
        now: i64,
    ) -> Result<(), Error> {
        self.transactionally(|db| {
            let id = key_ref(db.conn.0, account, key)?;
            record_observation(db.conn.0, id, operation, observation, now)
        })
    }
}

impl<C: BorrowMut<Connection>, P: Parameters, CL: Clock, R> WalletDb<C, P, CL, R> {
    /// Stops trial decryption for `account`'s finished keys and returns how many closed.
    ///
    /// A key closes as soon as every operation on it has a conclusive terminal status
    /// and its receipts cover what the provider promised, or [`COMPLETION_LIMIT_SECS`]
    /// after its latest quote deadline (after registration without one), whatever the
    /// provider reports. Either way it stays open while a receipt is unmined and
    /// unexpired or has fewer than the untrusted confirmations of the default
    /// [`ConfirmationsPolicy`], so a reorg cannot strand a receipt on a closed key.
    /// Keys with an open reservation, and unpaid incoming keys this wallet issued, stay
    /// active, so an index can be reissued without a gap in its scanned history. An incoming key found by a restore sweep and never issued here has no
    /// known swap, so it closes [`RESTORE_WATCH_SECS`] after registration. A payment
    /// that arrives after its key closed is found by [`WalletDb::recheck_swap_history`]
    /// or a seed restore. Provider status never credits a note; a closed key keeps its
    /// notes.
    ///
    /// `tip` is the chain tip the caller has just confirmed with the network. The
    /// stored tip can be stale after time offline, so nothing closes unless the
    /// stored tip and the fully scanned height both equal `tip`, and a queued rescan
    /// never skips a key.
    ///
    /// `now` is the caller's clock. Closing uses the earlier of it and `tip`'s block
    /// time, so a clock that runs fast cannot end scanning early, and one that runs
    /// slow only delays it.
    pub fn close_finished_swap_keys(
        &mut self,
        account: AccountUuid,
        now: i64,
        tip: BlockHeight,
    ) -> Result<usize, Error> {
        self.transactionally(|db| {
            let (owner, _) = account_key(db.conn.0, &db.params, account)?;
            if wallet::chain_tip_height(db.conn.0)? != Some(tip)
                || wallet::fully_scanned_height(db.conn.0)? != Some(tip)
            {
                return Ok(0);
            }
            let tip_time: i64 = db.conn.0.query_row(
                "SELECT time FROM blocks WHERE height = ?1",
                [u32::from(tip)],
                |r| r.get(0),
            )?;
            let now = now.min(tip_time);
            let confirmed_below = u32::from(tip)
                .saturating_add(1)
                .saturating_sub(ConfirmationsPolicy::default().untrusted().get());
            let mut stmt = db.conn.0.prepare(&format!(
                "SELECT k.id, k.registered_at, k.purpose = 1,
                    EXISTS(SELECT 1 FROM ironwood_swap_receive_reservations r
                        WHERE r.receiving_key_id = k.id AND r.closed_at IS NULL),
                    EXISTS(SELECT 1 FROM ironwood_received_notes n
                        JOIN transactions t ON t.id_tx = n.transaction_id
                        WHERE n.receiving_key_id = k.id
                          AND (t.mined_height > :confirmed_below
                               OR (t.mined_height IS NULL AND ({unexpired})))),
                    k.used, ({RESTORED_INCOMING}),
                    (SELECT COUNT(*) FROM ironwood_swap_operations o
                        WHERE o.receiving_key_id = k.id),
                    (SELECT COUNT(*) FROM ironwood_swap_operations o
                        WHERE o.receiving_key_id = k.id
                          AND o.expectation IN (0, 3)),
                    (SELECT MAX(o.deadline) FROM ironwood_swap_operations o
                        WHERE o.receiving_key_id = k.id),
                    (SELECT COALESCE(SUM(COALESCE(o.expected_value, 1)), 0)
                        FROM ironwood_swap_operations o
                        WHERE o.receiving_key_id = k.id AND o.expectation = 2),
                    (SELECT COALESCE(SUM(n.value), 0) FROM ironwood_received_notes n
                        JOIN transactions t ON t.id_tx = n.transaction_id
                        WHERE n.receiving_key_id = k.id AND t.mined_height <= :confirmed_below)
                 FROM ironwood_receiving_keys k
                 WHERE k.account_id = :account AND k.active_from IS NOT NULL
                   AND k.closed_at IS NULL",
                unexpired = tx_unexpired_condition("t"),
            ))?;
            let bounds = named_params![
                ":account": owner.0,
                ":confirmed_below": confirmed_below,
                ":target_height": u32::from(tip + 1),
            ];
            let finished = stmt
                .query_map(bounds, |row| {
                    let id: i64 = row.get(0)?;
                    let registered_at: i64 = row.get(1)?;
                    let incoming: bool = row.get(2)?;
                    let open_reservation: bool = row.get(3)?;
                    let pending_receipt: bool = row.get(4)?;
                    let paid: bool = row.get(5)?;
                    let restored: bool = row.get(6)?;
                    let operations: u32 = row.get(7)?;
                    let unresolved: u32 = row.get(8)?;
                    let deadline: Option<i64> = row.get(9)?;
                    let expected: i64 = row.get(10)?;
                    let received: i64 = row.get(11)?;
                    if incoming && (open_reservation || !(paid || restored)) {
                        return Ok((id, false));
                    }
                    let limit = if restored {
                        registered_at.saturating_add(RESTORE_WATCH_SECS)
                    } else {
                        deadline
                            .unwrap_or(registered_at)
                            .saturating_add(COMPLETION_LIMIT_SECS)
                    };
                    let settled = operations > 0 && unresolved == 0 && received >= expected;
                    Ok((id, !pending_receipt && (settled || now >= limit)))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let mut closed = 0;
            for (id, finished) in finished {
                if finished {
                    db.conn.0.execute(
                        "UPDATE ironwood_receiving_keys SET closed_at = ?2 WHERE id = ?1",
                        params![id, now],
                    )?;
                    closed += 1;
                }
            }
            Ok(closed)
        })
    }
}

/// See [`WalletDb::record_swap_observation`]. Shared with reservations and funding.
///
/// An `observed_at` of 0 marks a record no provider status has updated yet, which
/// any observed status replaces. `expectation` stores the status: 0 active, 1 final
/// with no receipt, 2 final with a receipt, 3 final but inconclusive.
pub(super) fn record_observation(
    conn: &Connection,
    id: i64,
    operation: &str,
    observation: Observation,
    now: i64,
) -> Result<(), Error> {
    if now < 0 || operation.is_empty() {
        return Err(corrupt("invalid swap observation"));
    }
    let (expectation, amount) = match observation.status {
        OperationStatus::Active => (0, None),
        OperationStatus::Terminal(ReceiptExpectation::None) => (1, None),
        OperationStatus::Terminal(ReceiptExpectation::Positive(value)) => (2, value),
        OperationStatus::Terminal(ReceiptExpectation::Unknown) => (3, None),
    };
    let amount = amount
        .map(|v| i64::try_from(u64::from(v)).ok().filter(|v| *v > 0))
        .map(|v| v.ok_or_else(|| corrupt("expected receipt must be positive")))
        .transpose()?;
    conn.execute(
        "INSERT INTO ironwood_swap_operations
            (receiving_key_id, operation_id, observed_at, expectation, expected_value, deadline)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (receiving_key_id, operation_id) DO UPDATE SET
            observed_at = excluded.observed_at,
            expectation = excluded.expectation,
            expected_value = excluded.expected_value,
            deadline = COALESCE(excluded.deadline, deadline)
         WHERE observed_at <= excluded.observed_at",
        params![
            id,
            operation,
            now,
            expectation,
            amount,
            observation.deadline
        ],
    )?;
    Ok(())
}
