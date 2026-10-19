//! Refund keys, their operations, and the funding transaction's memo and shape.
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
    ProviderSeen, RESERVED, ReservationPolicy, issuance_start,
    lifecycle::record,
    reservations::{
        LATEST_DEADLINE, check_unquoted, current, fresh_seen, issuance_end, next_index, operation,
        receiver_bytes, record_seen, reserve_index, scanned_empty,
    },
};
use crate::wallet::one_time_ivk::{
    Discovery, KeyId, OneTimeKey, Purpose, account_key, activate, block_issuance, block_recovery,
    invalid, restore::recovery,
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
    if !super::enabled(conn, account)? {
        return Ok(Err(ReservationPolicy::Gap));
    }
    recovery::recover_refund_memos(conn, params, account, now)?;
    if recovery::refund_memos_pending(conn, account)? {
        return Ok(Err(ReservationPolicy::Coverage));
    }
    // Until the windows were checked against a seen set, another device may have given
    // out any refund index.
    let (owner, _) = account_key(conn, params, account)?;
    if !block_recovery::seen_ready(conn, owner.0)? {
        return Ok(Err(ReservationPolicy::Gap));
    }
    let seen = match fresh_seen(seen, now) {
        Ok(seen) => seen,
        Err(policy) => return Ok(Err(policy)),
    };
    record_seen(conn, owner.0, 0, seen)?;
    let index = match next_index(conn, params, account, Purpose::Refund, seen, now)? {
        Ok(index) => index,
        Err(policy) => return Ok(Err(policy)),
    };
    let key = KeyId::new(Purpose::Refund, index);
    reserve_index(
        conn,
        params,
        account,
        key,
        scan_from,
        Discovery::Funding,
        now,
    )
    .map(Ok)
}

/// See `WalletDb::begin_refund_operation`, which chooses `request`.
pub(in crate::wallet::one_time_ivk) fn begin(
    conn: &rusqlite::Transaction<'_>,
    account: AccountUuid,
    index: u64,
    request: &str,
    deadline: i64,
    now: i64,
    seen: Option<&ProviderSeen<'_>>,
) -> Result<Result<(), ReservationPolicy>, SqliteClientError> {
    if !super::enabled(conn, account)? {
        return Ok(Err(ReservationPolicy::Gap));
    }
    if request.is_empty() {
        return Err(invalid("empty operation request"));
    }
    if now < 0 || deadline <= now {
        return Err(invalid("operation deadline has passed"));
    }
    let (key, owner, open, provider_seen, receiver, latest): (
        i64,
        i64,
        bool,
        bool,
        Vec<u8>,
        Option<i64>,
    ) = conn
        .query_row(
            &format!(
                "SELECT k.id, k.account_id,
                    {RESERVED} AND k.issuance_blocked = 0 AND k.used = 0
                      AND NOT EXISTS(SELECT 1 FROM ironwood_block_matches m WHERE m.account_id=k.account_id AND m.purpose=k.purpose AND m.key_index=k.key_index)
                      AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
                        WHERE p.one_time_key_id = k.id),
                    k.provider_seen, k.receiver, {LATEST_DEADLINE}
                 FROM ironwood_one_time_keys k JOIN accounts a ON a.id = k.account_id
                 WHERE a.uuid = ?1 AND k.purpose = 0 AND k.key_index = ?2"
            ),
            params![account.0, index.to_be_bytes()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| invalid("unknown refund reservation"))?;
    if !open || latest.is_some() {
        return Ok(Err(ReservationPolicy::Stale));
    }
    let receiver = receiver_bytes(&receiver)?;
    match check_unquoted(conn, (key, 0), &receiver, provider_seen, seen, now)? {
        Ok(true) => {}
        Ok(false) => return Ok(Err(ReservationPolicy::Stale)),
        Err(policy) => return Ok(Err(policy)),
    }
    if index >= issuance_end(conn, owner, 0)? {
        return Ok(Err(ReservationPolicy::Gap));
    }
    let exposed:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM ironwood_one_time_operations WHERE one_time_key_id=?1 AND request IS NOT NULL)",[key],|r|r.get(0))?;
    if exposed && !scanned_empty(conn, key)? {
        return Ok(Err(ReservationPolicy::Coverage));
    }
    // Until its funding transaction is stored, the operation expects no receipt, and it
    // has no observation, so storing that transaction records it active.
    conn.execute(
        "INSERT INTO ironwood_one_time_operations
            (one_time_key_id, request, deadline, begun_at, expectation,local_watch_deadline)
         VALUES (?1, ?2, ?3, ?4, 1,?3)",
        params![key, request, deadline, now],
    )?;
    conn.execute("UPDATE ironwood_one_time_keys SET watch_closed_height=NULL,watch_closed_hash=NULL WHERE id=?1",[key])?;
    Ok(Ok(()))
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
    request: &str,
    deposit: &str,
    deadline: i64,
    now: i64,
) -> Result<Result<(), ReservationPolicy>, SqliteClientError> {
    if !super::enabled(conn, account)? {
        return Ok(Err(ReservationPolicy::Gap));
    }
    let id = operation(conn, account, request)?;
    let (key, refund): (i64, bool) = conn.query_row(
        "SELECT o.one_time_key_id, k.purpose = 0 FROM ironwood_one_time_operations o
         JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id WHERE o.id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if !refund {
        return Err(invalid("not a refund operation request"));
    }
    // A retired request's late response is refused whatever it holds.
    if !current(conn, id)? {
        return Ok(Err(ReservationPolicy::Stale));
    }
    check_deposit(params, deposit)?;
    if now < 0 || deadline <= now {
        return Err(invalid("invalid refund operation deadline"));
    }
    let (elsewhere, rebound): (bool, bool) = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_operations
                WHERE reference = ?2 AND one_time_key_id <> ?1),
            EXISTS(SELECT 1 FROM ironwood_one_time_operations
                WHERE reference <> ?2 AND one_time_key_id = ?1)",
        params![key, deposit],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if elsewhere {
        return Err(invalid("deposit address is recorded for another key"));
    }
    if rebound {
        return Err(invalid("refund key is bound to another deposit"));
    }
    conn.execute(
        "UPDATE ironwood_one_time_operations SET reference = ?2, deadline = MIN(deadline, ?3),
            local_watch_deadline=CASE WHEN local_watch_deadline IS NOT NULL AND local_watch_accepted=0 THEN ?3 ELSE local_watch_deadline END,
            local_watch_accepted=CASE WHEN local_watch_deadline IS NOT NULL THEN 1 ELSE local_watch_accepted END
         WHERE id = ?1",
        params![id, deposit, deadline],
    )?;
    // Shown for funding from here on, so the key is never issued again.
    block_issuance(conn, key)?;
    Ok(Ok(()))
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
             WHERE one_time_key_id = ?1 AND reference = ?2",
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
        "SELECT id FROM ironwood_one_time_keys
         WHERE account_id = ?1 AND purpose = 0 AND key_index = ?2
           AND advances_allocation = 1 AND closed_at IS NULL",
        params![account_ref.0, index.to_be_bytes()],
        |r| r.get(0),
    )
    .optional()?
    .ok_or_else(|| invalid("refund key is not reserved and open in this account"))
}

/// Starts the refund keys that `tx`, which this wallet just stored to send, funds, above
/// the scanned blocks since those predate `tx`, and marks their operations active. This is
/// the only way a refund key this wallet reserved starts scanning, and a key whose watch
/// ended stays closed. A reserved key's memo funding a deposit not recorded for that key is
/// an error, so the send is not stored.
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
               AND n.one_time_key_id IS NULL AND substr(n.memo, 1, 5) = ?2",
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
        let Some((id, scan_from, closed)) = conn
            .query_row(
                "SELECT id, scan_from, closed_at IS NOT NULL FROM ironwood_one_time_keys
                 WHERE account_id = ?1 AND purpose = 0 AND key_index = ?2
                   AND advances_allocation = 1",
                params![account, memo.index().to_be_bytes()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
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
        // Storing the transaction again never reopens a watch that ended (see
        // `OneTimeIvkWrite::expire_refund_watches`).
        if !closed {
            activate(conn, id, above_scanned.unwrap_or(scan_from).into())?;
        }
        // The wallet's own funding is not a provider observation, so `funded` stays unset.
        let sent = Observation {
            status: OperationStatus::Active,
            funded: false,
        };
        record(conn, operation, sent, 0)?;
    }
    Ok(())
}
