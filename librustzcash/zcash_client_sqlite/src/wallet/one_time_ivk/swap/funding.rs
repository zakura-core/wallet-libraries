//! Refund keys, their operations, and the funding transaction's memo and shape.
use orchard::keys::Scope;
use rusqlite::{Connection, OptionalExtension, params};
use zakura_one_time_ivk::swap::{Observation, OperationStatus, REFUND_MEMO_MAGIC, RefundMemo};
use zcash_client_backend::proposal::Proposal;
use zcash_keys::{address::Address, encoding::AddressCodec as _};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    PoolType,
    consensus::{BlockHeight, Parameters},
    memo::MemoBytes,
};

use super::{
    ProviderSeen, ReservationPolicy, issuance_start, lifecycle::record,
    reservations::record_provider_seen,
};
use crate::wallet::one_time_ivk::{
    Discovery, KeyId, OneTimeKey, Purpose, account_key, activate, decode_index, index_after,
    invalid, register, restore::recovery, restore_start,
};
use crate::{AccountUuid, error::SqliteClientError};

/// See `WalletDb::reserve_refund_key`.
pub(in crate::wallet::one_time_ivk) fn reserve<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    tip: BlockHeight,
    seen: Option<&ProviderSeen<'_>>,
    now: i64,
) -> Result<Result<OneTimeKey, ReservationPolicy>, SqliteClientError> {
    let scan_from = match issuance_start(conn, tip)? {
        Ok(from) => from,
        Err(policy) => return Ok(Err(policy)),
    };
    recovery::recover_refund_memos(conn, params, account, now)?;
    if recovery::refund_memos_pending(conn, account)? {
        return Ok(Err(ReservationPolicy::Coverage));
    }
    let index = next_refund_index(conn, params, account, seen, now)?;
    let key = KeyId::new(Purpose::Refund, index);
    let (_, key) = register(
        conn,
        params,
        account,
        key,
        scan_from,
        true,
        Discovery::Funding,
        now,
    )?;
    Ok(Ok(key))
}

/// The lowest refund index above every allocated one that no key is registered at and
/// `seen` does not hold. A held index is registered for a restore sweep, since a swap
/// may have paid it, and recorded as seen, so it is never issued.
pub(in crate::wallet::one_time_ivk) fn next_refund_index<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    seen: Option<&ProviderSeen<'_>>,
    now: i64,
) -> Result<u64, SqliteClientError> {
    let (account_ref, parent) = account_key(conn, params, account)?;
    // SQLite orders fixed-width big-endian blobs numerically. Unlike INTEGER, this
    // represents the entire u64 index space, including u64::MAX.
    let last: Option<Vec<u8>> = conn.query_row(
        "SELECT MAX(key_index) FROM ironwood_receiving_keys
         WHERE account_id = ?1 AND purpose = 0 AND advances_allocation = 1",
        [account_ref.0],
        |row| row.get(0),
    )?;
    let mut index = match last {
        Some(bytes) => index_after(decode_index(bytes)?, 1)?,
        None => 0,
    };
    loop {
        let registered = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_receiving_keys
             WHERE account_id = ?1 AND purpose = 0 AND key_index = ?2)",
            params![account_ref.0, index.to_be_bytes()],
            |row| row.get::<_, bool>(0),
        )?;
        if !registered {
            let Some(seen) = seen else {
                return Ok(index);
            };
            let key = KeyId::new(Purpose::Refund, index);
            let receiver = key.derive(&parent)?.address_at(0u32, Scope::External);
            if (seen.contains)(&[receiver.to_raw_address_bytes()]) != [true] {
                return Ok(index);
            }
            let from = restore_start(conn, params, account_ref)?;
            let (id, _) = register(
                conn,
                params,
                account,
                key,
                from,
                false,
                Discovery::Sweep,
                now,
            )?;
            record_provider_seen(conn, id)?;
        }
        index = index_after(index, 1)?;
    }
}

/// See `WalletDb::refund_funding_memo`.
pub(in crate::wallet::one_time_ivk) fn funding_memo<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    index: u64,
    deposit: &str,
) -> Result<MemoBytes, SqliteClientError> {
    check_deposit(params, deposit)?;
    let key = refund_key(conn, params, account, index)?;
    if refund_operation(conn, key, deposit)?.is_none() {
        return Err(invalid("refund operation was not recorded for this key"));
    }
    Ok(MemoBytes::from_bytes(&RefundMemo::new(index).encode()).expect("a full-length memo"))
}

/// See `WalletDb::record_refund_operation`.
pub(in crate::wallet::one_time_ivk) fn record_operation<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    index: u64,
    deposit: &str,
    deadline: i64,
    now: i64,
) -> Result<(), SqliteClientError> {
    check_deposit(params, deposit)?;
    if now < 0 || deadline <= now {
        return Err(invalid("invalid refund operation deadline"));
    }
    let key = refund_key(conn, params, account, index)?;
    let (elsewhere, recorded, rebound): (bool, bool, bool) = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_operations
                WHERE reference = ?2 AND receiving_key_id <> ?1),
            EXISTS(SELECT 1 FROM ironwood_one_time_operations
                WHERE reference = ?2 AND receiving_key_id = ?1),
            EXISTS(SELECT 1 FROM ironwood_one_time_operations
                WHERE reference <> ?2 AND receiving_key_id = ?1)",
        params![key, deposit],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if elsewhere {
        return Err(invalid("deposit address is recorded for another key"));
    }
    if rebound {
        return Err(invalid("refund key is bound to another deposit"));
    }
    // Until its funding transaction is stored, the operation expects no receipt.
    if !recorded {
        conn.execute(
            "INSERT INTO ironwood_one_time_operations
                (receiving_key_id, reference, deadline, begun_at, expectation)
             VALUES (?1, ?2, ?3, ?4, 1)",
            params![key, deposit, deadline, now],
        )?;
    }
    Ok(())
}

/// Refund key `key`'s operation for `deposit`, if recorded.
fn refund_operation(
    conn: &Connection,
    key: i64,
    deposit: &str,
) -> Result<Option<i64>, SqliteClientError> {
    Ok(conn
        .query_row(
            "SELECT id FROM ironwood_one_time_operations
             WHERE receiving_key_id = ?1 AND reference = ?2",
            params![key, deposit],
            |r| r.get(0),
        )
        .optional()?)
}

/// Checks that `proposal` funds `deposit` in one transaction that carries `memo` on
/// internal Ironwood change, as refund recovery requires. The deposit must be the
/// transaction's only transparent output and its only payment.
pub fn verify_refund_funding_proposal<FeeRuleT, NoteRef>(
    proposal: &Proposal<FeeRuleT, NoteRef>,
    memo: &MemoBytes,
    deposit: &str,
) -> Result<(), SqliteClientError> {
    if proposal.steps().len() != 1 {
        return Err(invalid("refund funding must be a single transaction"));
    }
    let step = proposal.steps().first();
    let payments = step.transaction_request().payments();
    if payments.len() != 1
        || payments
            .values()
            .any(|p| p.recipient_address().to_string() != deposit || p.memo().is_some())
    {
        return Err(invalid("refund funding must pay only the deposit address"));
    }
    let change = step.balance().proposed_change();
    if change
        .iter()
        .any(|c| c.is_ephemeral() || c.output_pool() == PoolType::TRANSPARENT)
        || !change
            .iter()
            .any(|c| c.output_pool() == PoolType::IRONWOOD && c.memo() == Some(memo))
    {
        return Err(invalid(
            "refund funding requires the recovery memo on internal Ironwood change",
        ));
    }
    Ok(())
}

/// Checks that `deposit` is a canonically encoded transparent address on this network,
/// since funding matches it by encoding (see [`verify_refund_funding_proposal`]).
fn check_deposit<P: Parameters>(params: &P, deposit: &str) -> Result<(), SqliteClientError> {
    match Address::decode(params, deposit) {
        Some(address) if address.encode(params) != deposit => {
            Err(invalid("invalid deposit address for this network"))
        }
        Some(Address::Transparent(_)) => Ok(()),
        Some(_) => Err(invalid(
            "refund funding requires a transparent deposit address",
        )),
        None => Err(invalid("invalid deposit address for this network")),
    }
}

/// The ID of `account`'s refund key at `index`, reserved here and still open.
fn refund_key<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    index: u64,
) -> Result<i64, SqliteClientError> {
    let (account_ref, _) = account_key(conn, params, account)?;
    conn.query_row(
        "SELECT id FROM ironwood_receiving_keys
         WHERE account_id = ?1 AND purpose = 0 AND key_index = ?2
           AND advances_allocation = 1 AND closed_at IS NULL",
        params![account_ref.0, index.to_be_bytes()],
        |r| r.get(0),
    )
    .optional()?
    .ok_or_else(|| invalid("refund key is not reserved and open in this account"))
}

/// Starts the refund keys that `tx`, which this wallet just stored to send, funds, above
/// the scanned blocks since those predate `tx`, and marks their operations active. A
/// reserved key's memo funding a deposit not recorded for that key is an error, so the
/// send is not stored.
pub(crate) fn start_funded_refund_keys<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    tx: &Transaction,
) -> Result<(), SqliteClientError> {
    // `verify_refund_funding_proposal` makes the deposit the only transparent output.
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
               AND n.receiving_key_id IS NULL AND substr(n.memo, 1, 5) = ?2",
        )?
        .query_map(params![tx.txid().as_ref(), REFUND_MEMO_MAGIC], |row| {
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
        let Some(operation) = refund_operation(conn, id, &deposit)? else {
            return Err(invalid(
                "refund memo funds a deposit not recorded for its key",
            ));
        };
        activate(conn, id, above_scanned.unwrap_or(scan_from).into())?;
        // The wallet's own funding is not a provider observation, so `funded` stays unset.
        let sent = Observation {
            status: OperationStatus::Active,
            funded: false,
        };
        record(conn, operation, sent, 0)?;
    }
    Ok(())
}
