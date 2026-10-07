//! Outgoing swap funding: the refund quote record, its recovery memo and the proposal shape.
use std::borrow::{Borrow, BorrowMut};

use rusqlite::{Connection, OptionalExtension, params};
use zakura_swap_receiving::{
    RefundMemo,
    lifecycle::{Observation, OperationStatus},
};
use zcash_client_backend::proposal::Proposal;
use zcash_keys::{address::Address, encoding::AddressCodec as _};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{PoolType, consensus::Parameters, memo::MemoBytes};

use super::{
    Error, ReservationPolicy, account_key, activate, corrupt, lifecycle::record_observation,
    wallet_error,
};
use crate::{AccountUuid, WalletDb, error::SqliteClientError};

impl<C: Borrow<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// The recovery memo for funding a refund quote recorded with
    /// [`WalletDb::record_swap_refund_quote`]. Put it on the funding transaction's
    /// internal Ironwood change, and check the proposal with
    /// [`verify_swap_funding_proposal`] before signing.
    pub fn swap_funding_memo(
        &self,
        account: AccountUuid,
        index: u64,
        deposit: &str,
    ) -> Result<MemoBytes, Error> {
        check_deposit(&self.params, deposit)?;
        let conn = self.conn.borrow();
        let key = refund_key(conn, &self.params, account, index)?;
        let quoted: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_swap_operations
             WHERE receiving_key_id = ?1 AND operation_id = ?2)",
            params![key, deposit],
            |r| r.get(0),
        )?;
        if !quoted {
            return Err(corrupt("swap refund quote was not recorded for this key"));
        }
        MemoBytes::from_bytes(&RefundMemo::new(index).encode())
            .map_err(|_| corrupt("invalid swap refund memo"))
    }
}

impl<C: BorrowMut<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Binds a refund quote's deposit address to the refund key reserved for it, before
    /// the quote is shown. Funding requires this record.
    ///
    /// A refund can only follow a deposit, so the key starts scanning when this wallet
    /// stores a transaction funding `deposit`, from the first block above the scanned
    /// chain, and the swap's outcome then decides when it closes (see
    /// [`WalletDb::record_swap_observation`]). A quote never funded never starts the
    /// key. Without a status, a started key closes [`COMPLETION_LIMIT_SECS`] after
    /// `deadline`.
    ///
    /// [`COMPLETION_LIMIT_SECS`]: zakura_swap_receiving::lifecycle::COMPLETION_LIMIT_SECS
    pub fn record_swap_refund_quote(
        &mut self,
        account: AccountUuid,
        index: u64,
        deposit: &str,
        deadline: i64,
        now: i64,
    ) -> Result<(), Error> {
        check_deposit(&self.params, deposit)?;
        if now < 0 || deadline <= now {
            return Err(corrupt("invalid swap refund quote deadline"));
        }
        self.transactionally(|db| {
            let key = refund_key(db.conn.0, &db.params, account, index)?;
            let elsewhere: bool = db.conn.0.query_row(
                "SELECT EXISTS(SELECT 1 FROM ironwood_swap_operations
                 WHERE operation_id = ?2 AND receiving_key_id <> ?1)",
                params![key, deposit],
                |r| r.get(0),
            )?;
            if elsewhere {
                return Err(corrupt("swap deposit address is quoted for another key"));
            }
            db.conn.0.execute(
                "INSERT INTO ironwood_swap_operations
                    (receiving_key_id, operation_id, observed_at, expectation, deadline)
                 VALUES (?1, ?2, 0, 1, ?3)
                 ON CONFLICT (receiving_key_id, operation_id) DO NOTHING",
                params![key, deposit, deadline],
            )?;
            Ok(())
        })
    }
}

/// Checks that `proposal` funds `deposit` in one transaction that carries `memo` on
/// internal Ironwood change, as refund recovery requires. The deposit must be the
/// transaction's only transparent output and its only payment.
pub fn verify_swap_funding_proposal<FeeRuleT, NoteRef>(
    proposal: &Proposal<FeeRuleT, NoteRef>,
    memo: &MemoBytes,
    deposit: &str,
) -> Result<(), Error> {
    if proposal.steps().len() != 1 {
        return Err(corrupt("swap funding must be a single transaction"));
    }
    let step = proposal.steps().first();
    let payments = step.transaction_request().payments();
    if payments.len() != 1
        || payments
            .values()
            .any(|p| p.recipient_address().to_string() != deposit || p.memo().is_some())
    {
        return Err(corrupt("swap funding must pay only the deposit address"));
    }
    let change = step.balance().proposed_change();
    if change
        .iter()
        .any(|c| c.is_ephemeral() || c.output_pool() == PoolType::TRANSPARENT)
        || !change
            .iter()
            .any(|c| c.output_pool() == PoolType::IRONWOOD && c.memo() == Some(memo))
    {
        return Err(corrupt(
            "swap funding requires the recovery memo on internal Ironwood change",
        ));
    }
    Ok(())
}

/// The funding transaction pays the deposit as its only transparent output, matched by
/// its encoding (see [`verify_swap_funding_proposal`]), so it must be a canonically
/// encoded P2PKH or P2SH address on this network.
fn check_deposit<P: Parameters>(params: &P, deposit: &str) -> Result<(), Error> {
    match Address::decode(params, deposit) {
        Some(address) if address.encode(params) != deposit => {
            Err(corrupt("invalid swap deposit address for this network"))
        }
        Some(Address::Transparent(_)) => Ok(()),
        Some(_) => Err(corrupt(
            "swap funding requires a transparent deposit address",
        )),
        None => Err(corrupt("invalid swap deposit address for this network")),
    }
}

/// The ID of `account`'s refund key at `index`, which must have been reserved here
/// and not closed, so its refund cannot be missed.
fn refund_key<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    index: u64,
) -> Result<i64, Error> {
    let (account_ref, _) = account_key(conn, params, account)?;
    conn.query_row(
        "SELECT id FROM ironwood_receiving_keys
         WHERE account_id = ?1 AND purpose = 0 AND key_index = ?2
           AND advances_allocation = 1 AND closed_at IS NULL",
        params![account_ref.0, index.to_be_bytes()],
        |r| r.get(0),
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            corrupt("refund key is not reserved and open in this account")
        }
        e => e.into(),
    })
}

/// Starts the refund keys that `tx`, which this wallet just stored to send, funds. See
/// [`WalletDb::record_swap_refund_quote`].
///
/// Blocks already scanned were mined before `tx` existed, so a key starts above them
/// with no rescan. Its funded quote then waits for the swap's outcome.
pub(crate) fn start_funded_refund_keys<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    tx: &Transaction,
) -> Result<(), SqliteClientError> {
    // `verify_swap_funding_proposal` makes the deposit the only transparent output.
    let deposit = match tx.transparent_bundle().map(|bundle| &bundle.vout[..]) {
        Some([output]) => output.recipient_address().map(|a| a.encode(params)),
        _ => None,
    };
    let Some(deposit) = deposit else {
        return Ok(());
    };
    let memos = conn
        .prepare_cached(
            "SELECT n.account_id, n.memo FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             WHERE t.txid = ?1 AND n.recipient_key_scope = 1
               AND n.receiving_key_id IS NULL AND substr(n.memo, 1, 5) = X'FF5A535750'",
        )?
        .query_map([tx.txid().as_ref()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let above_scanned: Option<u32> =
        conn.query_row("SELECT MAX(height) + 1 FROM blocks", [], |row| row.get(0))?;
    for (account, memo) in memos {
        let Some(memo) = MemoBytes::from_bytes(&memo)
            .ok()
            .and_then(|memo| RefundMemo::decode(memo.as_array()))
        else {
            continue;
        };
        let Some((id, scan_from)) = conn
            .query_row(
                "SELECT id, scan_from FROM ironwood_receiving_keys
                 WHERE account_id = ?1 AND purpose = 0 AND key_index = ?2
                   AND advances_allocation = 1",
                params![account, memo.index().to_be_bytes()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, u32>(1)?)),
            )
            .optional()?
        else {
            continue;
        };
        match activate(conn, id, above_scanned.unwrap_or(scan_from).into()) {
            // A pending restore sweep starts the key at its anchor instead.
            Ok(()) | Err(Error::ReservationPolicy(ReservationPolicy::Gap)) => {}
            Err(e) => return Err(wallet_error(e)),
        }
        let funded = Observation {
            status: OperationStatus::Active,
            deadline: None,
        };
        record_observation(conn, id, &deposit, funded, 0).map_err(wallet_error)?;
    }
    Ok(())
}
