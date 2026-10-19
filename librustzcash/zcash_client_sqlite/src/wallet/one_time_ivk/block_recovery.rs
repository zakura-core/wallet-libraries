//! Per-receiver filter cursors and durable positive obligations. Negative judgments
//! advance only the receivers actually tested, never ordinary chain scan progress.
use super::{
    KeyId, Purpose, account_key, corrupt, decode_index, invalid, purpose_code, restore_start,
    stored_key_id,
};
use crate::{AccountUuid, error::SqliteClientError};
use orchard::keys::Scope;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::collections::HashSet;
use zcash_client_backend::data_api::{
    one_time_ivk::{
        recovery::{
            Fence, FilterJudgment, FilterWork, History, PendingMatch, RecoveryState, Window,
        },
        restore::DiscoveryWork,
    },
    transparent_ledger::ChainPoint,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, Parameters};

const PURPOSES: [Purpose; 2] = [Purpose::Refund, Purpose::Receive];
const MAX_KEYS: u32 = 1024;
const MAX_BLOCKS: usize = 256;

/// Creates account state from its actual birthday. Registration never enables discovery.
fn ensure<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    account: AccountUuid,
) -> Result<i64, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let birthday = u32::from(restore_start(conn, params, owner)?);
    conn.execute(
        "INSERT OR IGNORE INTO ironwood_block_recovery(account_id,birthday) VALUES (?1,?2)",
        params![owner.0, birthday],
    )?;
    for purpose in 0..=1 {
        conn.execute(
            "INSERT OR IGNORE INTO ironwood_block_windows(account_id,purpose) VALUES (?1,?2)",
            params![owner.0, purpose],
        )?;
    }
    let old: u32 = conn.query_row(
        "SELECT birthday FROM ironwood_block_recovery WHERE account_id=?1",
        [owner.0],
        |r| r.get(0),
    )?;
    if birthday < old {
        conn.execute("UPDATE ironwood_block_recovery SET birthday=?2,work_generation=work_generation+1 WHERE account_id=?1",params![owner.0,birthday])?;
        conn.execute("UPDATE ironwood_block_receivers SET next_height=MIN(next_height,?2) WHERE account_id=?1",params![owner.0,birthday])?;
    }
    Ok(owner.0)
}

/// Adds a receiver and its historical obligation atomically with registration or derivation.
/// Existing cached receivers keep their progress when promoted into the key registry.
pub(super) fn join<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    receiver: &[u8; 43],
) -> Result<(), SqliteClientError> {
    let owner = ensure(conn, params, account)?;
    let inserted = conn.execute("INSERT OR IGNORE INTO ironwood_block_receivers(account_id,purpose,key_index,receiver,next_height)
        SELECT account_id,?2,?3,?4,birthday FROM ironwood_block_recovery WHERE account_id=?1",
        params![owner,purpose_code(key.purpose())?,key.index().to_be_bytes(),receiver])?;
    let saved: Vec<u8> = conn.query_row("SELECT receiver FROM ironwood_block_receivers WHERE account_id=?1 AND purpose=?2 AND key_index=?3",
        params![owner,purpose_code(key.purpose())?,key.index().to_be_bytes()],|r|r.get(0))?;
    if saved != receiver {
        return Err(corrupt("recovery receiver differs from derived key"));
    }
    if inserted > 0 {
        conn.execute("UPDATE ironwood_block_recovery SET key_generation=key_generation+1 WHERE account_id=?1",[owner])?;
    }
    Ok(())
}

/// Decodes a 65-bit exclusive index bound without losing the last u64 key index.
fn bound(bytes: Vec<u8>) -> Result<u128, SqliteClientError> {
    let n = u128::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| corrupt("invalid recovery window"))?,
    );
    if n > u128::from(u64::MAX) + 1 {
        return Err(corrupt("recovery window exceeds key space"));
    }
    Ok(n)
}

/// Reads account state without creating it or inferring completion from a scan tip.
pub(crate) fn state<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
) -> Result<Option<RecoveryState>, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let row = conn.query_row("SELECT enabled,key_generation,work_generation,genesis,archive,epoch,needs_prepare FROM ironwood_block_recovery WHERE account_id=?1",[owner.0],|r| {
        Ok((r.get::<_,bool>(0)?,r.get::<_,u64>(1)?,r.get::<_,u64>(2)?,r.get::<_,Option<[u8;32]>>(3)?,r.get::<_,Option<[u8;32]>>(4)?,r.get::<_,Option<u64>>(5)?,r.get::<_,bool>(6)?))
    }).optional()?;
    let Some((enabled, keys, work, genesis, archive, epoch, needs_prepare)) = row else {
        return Ok(None);
    };
    let history = match (genesis, archive, epoch) {
        (Some(genesis), Some(archive), Some(epoch)) => Some(History {
            genesis,
            archive,
            epoch,
        }),
        (None, None, None) => None,
        _ => return Err(corrupt("partial recovery history")),
    };
    let mut windows = [
        Window {
            purpose: Purpose::Refund,
            end: 100,
            derived: 0,
        },
        Window {
            purpose: Purpose::Receive,
            end: 100,
            derived: 0,
        },
    ];
    for window in &mut windows {
        let (end,derived): (Vec<u8>,Vec<u8>) = conn.query_row("SELECT end_index,derived FROM ironwood_block_windows WHERE account_id=?1 AND purpose=?2",
            params![owner.0,purpose_code(window.purpose)?],|r|Ok((r.get(0)?,r.get(1)?)))?;
        window.end = bound(end)?;
        window.derived = bound(derived)?;
    }
    let next: Option<u64> = conn.query_row(
        "SELECT MIN(next_height) FROM ironwood_block_receivers WHERE account_id=?1",
        [owner.0],
        |r| r.get(0),
    )?;
    let pending_matches = conn.query_row(
        "SELECT COUNT(*) FROM ironwood_block_matches WHERE account_id=?1",
        [owner.0],
        |r| r.get(0),
    )?;
    Ok(Some(RecoveryState {
        enabled,
        needs_prepare,
        history,
        keys,
        work,
        windows,
        next_height: next
            .and_then(|n| u32::try_from(n).ok())
            .map(BlockHeight::from),
        pending_matches,
    }))
}

/// Settings changes fence in-flight work but preserve all existing obligations and scan evidence.
pub(crate) fn set_enabled<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    account: AccountUuid,
    enabled: bool,
) -> Result<(), SqliteClientError> {
    let owner = ensure(conn, params, account)?;
    conn.execute("UPDATE ironwood_block_recovery SET enabled=?2,needs_prepare=1,work_generation=work_generation+1 WHERE account_id=?1 AND enabled<>?2",params![owner,enabled])?;
    Ok(())
}

/// Imports registered keys and derives the supported window in bounded resumable chunks.
pub(crate) fn prepare<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    account: AccountUuid,
    budget: u32,
    now: i64,
) -> Result<bool, SqliteClientError> {
    let owner = ensure(conn, params, account)?;
    if !state(conn, params, account)?
        .expect("ensured state")
        .enabled
    {
        return Ok(false);
    }
    super::restore::recovery::recover_refund_memos(conn, params, account, now)?;
    let (_, parent) = account_key(conn, params, account)?;
    let registered = conn
        .prepare(
            "SELECT purpose,key_index,receiver FROM ironwood_one_time_keys WHERE account_id=?1",
        )?
        .query_and_then([owner], |r| {
            Ok::<_, SqliteClientError>((stored_key_id(r)?, r.get::<_, [u8; 43]>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (key, receiver) in registered {
        join(conn, params, account, key, &receiver)?;
    }
    let mut remaining = u128::from(budget.min(MAX_KEYS));
    for purpose in PURPOSES {
        let code = purpose_code(purpose)?;
        let highest: Option<Vec<u8>> = conn.query_row("SELECT MAX(key_index) FROM ironwood_one_time_keys WHERE account_id=?1 AND purpose=?2 AND advances_allocation=1",params![owner,code],|r|r.get(0))?;
        let end = highest
            .map(|b| decode_index(b).map(|v| (u128::from(v) + 31).min(u128::from(u64::MAX) + 1)))
            .transpose()?
            .unwrap_or(100)
            .max(100);
        conn.execute("UPDATE ironwood_block_windows SET end_index=MAX(end_index,?3) WHERE account_id=?1 AND purpose=?2",params![owner,code,end.to_be_bytes()])?;
        let (end,derived): (Vec<u8>,Vec<u8>) = conn.query_row("SELECT end_index,derived FROM ironwood_block_windows WHERE account_id=?1 AND purpose=?2",params![owner,code],|r|Ok((r.get(0)?,r.get(1)?)))?;
        let (end, derived) = (bound(end)?, bound(derived)?);
        let through = end.min(derived + remaining);
        for index in derived..through {
            let key = KeyId::new(purpose, index as u64);
            let receiver = key
                .derive(&parent)?
                .address_at(0u32, Scope::External)
                .to_raw_address_bytes();
            join(conn, params, account, key, &receiver)?;
        }
        conn.execute(
            "UPDATE ironwood_block_windows SET derived=?3 WHERE account_id=?1 AND purpose=?2",
            params![owner, code, through.to_be_bytes()],
        )?;
        remaining -= through - derived;
    }
    conn.execute(
        "UPDATE ironwood_block_recovery SET needs_prepare=0 WHERE account_id=?1",
        [owner],
    )?;
    Ok(state(conn, params, account)?
        .expect("ensured state")
        .windows
        .iter()
        .all(|w| w.derived == w.end))
}

/// Accepts a current anchored history and creates full replay obligations on correction or identity change.
pub(crate) fn accept_history<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    account: AccountUuid,
    history: History,
) -> Result<bool, SqliteClientError> {
    let owner = ensure(conn, params, account)?;
    let current = state(conn, params, account)?.expect("ensured state");
    if !current.enabled || history.archive == [0; 32] || history.epoch > i64::MAX as u64 {
        return Ok(false);
    }
    let known: Option<u64> = conn
        .query_row(
            "SELECT epoch FROM ironwood_block_histories WHERE account_id=?1 AND archive=?2",
            params![owner, history.archive],
            |r| r.get(0),
        )
        .optional()?;
    if current.history.is_some_and(|h| {
        h.genesis != history.genesis || (h.archive != history.archive && known.is_some())
    }) || known.is_some_and(|epoch| history.epoch < epoch)
    {
        return Ok(false);
    }
    if current.history == Some(history) {
        return Ok(true);
    }
    conn.execute("INSERT INTO ironwood_block_histories VALUES (?1,?2,?3) ON CONFLICT(account_id,archive) DO UPDATE SET epoch=excluded.epoch",params![owner,history.archive,history.epoch])?;
    conn.execute("UPDATE ironwood_block_recovery SET genesis=?2,archive=?3,epoch=?4,work_generation=work_generation+1 WHERE account_id=?1",params![owner,history.genesis,history.archive,history.epoch])?;
    conn.execute("UPDATE ironwood_block_receivers SET next_height=(SELECT birthday FROM ironwood_block_recovery WHERE account_id=?1) WHERE account_id=?1",[owner])?;
    // Existing positive obligations survive until their exact scans or compatible PIR results settle them.
    Ok(true)
}

/// Captures a bounded receiver group at its oldest unchecked height, never while disabled.
pub(crate) fn filter_work<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    limit: u32,
) -> Result<Option<FilterWork<AccountUuid>>, SqliteClientError> {
    let Some(state) = state(conn, params, account)? else {
        return Ok(None);
    };
    let (Some(history), Some(next)) = (state.history, state.next_height) else {
        return Ok(None);
    };
    if !state.enabled || state.needs_prepare || limit == 0 {
        return Ok(None);
    }
    let (owner, _) = account_key(conn, params, account)?;
    let receivers=conn.prepare("SELECT purpose,key_index,receiver FROM ironwood_block_receivers WHERE account_id=?1 AND next_height=?2 ORDER BY purpose,key_index LIMIT ?3")?
        .query_and_then(params![owner.0,u32::from(next),limit.min(MAX_KEYS)],|r|Ok::<_,SqliteClientError>(DiscoveryWork{key:stored_key_id(r)?,receiver:r.get(2)?}))?.collect::<Result<Vec<_>,_>>()?;
    Ok(Some(FilterWork {
        account,
        fence: Fence {
            history,
            keys: state.keys,
            work: state.work,
        },
        next_height: next,
        receivers,
    }))
}

/// Atomically advances only the captured receivers and persists every positive match.
pub(crate) fn record_filters<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    account: AccountUuid,
    work: &FilterWork<AccountUuid>,
    judgments: &[FilterJudgment],
) -> Result<bool, SqliteClientError> {
    let Some(state) = state(conn, params, account)? else {
        return Ok(false);
    };
    if account != work.account
        || state.needs_prepare
        || !state.enabled
        || state.history != Some(work.fence.history)
        || state.keys != work.fence.keys
        || state.work != work.fence.work
    {
        return Ok(false);
    }
    if judgments.is_empty()
        || judgments.len() > MAX_BLOCKS
        || work.receivers.is_empty()
        || work.receivers.len() > MAX_KEYS as usize
    {
        return Err(invalid("invalid filter work size"));
    }
    let (owner, _) = account_key(conn, params, account)?;
    let keys: HashSet<_> = work.receivers.iter().map(|r| r.key).collect();
    if keys.len() != work.receivers.len() {
        return Err(invalid("duplicate filter receiver"));
    }
    for (offset, judgment) in judgments.iter().enumerate() {
        if u64::from(u32::from(judgment.block.height))
            != u64::from(u32::from(work.next_height)) + offset as u64
            || judgment.hits.iter().any(|key| !keys.contains(key))
        {
            return Err(invalid("discontinuous filter work or unknown match"));
        }
    }
    for receiver in &work.receivers {
        let saved: Option<(Vec<u8>,u64)>=conn.query_row("SELECT receiver,next_height FROM ironwood_block_receivers WHERE account_id=?1 AND purpose=?2 AND key_index=?3",
            params![owner.0,purpose_code(receiver.key.purpose())?,receiver.key.index().to_be_bytes()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if saved.as_ref().is_none_or(|(bytes, next)| {
            bytes.as_slice() != receiver.receiver || *next != u64::from(u32::from(work.next_height))
        }) {
            return Ok(false);
        }
    }
    for judgment in judgments {
        for key in &judgment.hits {
            let code = purpose_code(key.purpose())?;
            let scanned: bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM ironwood_key_scans s JOIN ironwood_one_time_keys k ON k.id=s.one_time_key_id
                WHERE k.account_id=?1 AND k.purpose=?2 AND k.key_index=?3 AND s.height=?4 AND s.hash=?5)",
                params![owner.0,code,key.index().to_be_bytes(),u32::from(judgment.block.height),judgment.block.hash.0],|r|r.get(0))?;
            if !scanned {
                conn.execute("INSERT INTO ironwood_block_matches VALUES (?1,?2,?3,?4,?5) ON CONFLICT(account_id,purpose,key_index,height) DO UPDATE SET hash=excluded.hash",
                    params![owner.0,code,key.index().to_be_bytes(),u32::from(judgment.block.height),judgment.block.hash.0])?;
            }
        }
    }
    let next = u64::from(u32::from(judgments.last().expect("nonempty").block.height)) + 1;
    for receiver in &work.receivers {
        conn.execute("UPDATE ironwood_block_receivers SET next_height=?4 WHERE account_id=?1 AND purpose=?2 AND key_index=?3",
            params![owner.0,purpose_code(receiver.key.purpose())?,receiver.key.index().to_be_bytes(),next])?;
    }
    Ok(true)
}

/// Returns positive obligations in a bounded stable order, suppressing dispatch while disabled.
pub(crate) fn pending<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    limit: u32,
) -> Result<Vec<PendingMatch>, SqliteClientError> {
    if !state(conn, params, account)?.is_some_and(|s| s.enabled) {
        return Ok(vec![]);
    }
    let (owner, _) = account_key(conn, params, account)?;
    conn.prepare("SELECT m.purpose,m.key_index,r.receiver,m.height,m.hash FROM ironwood_block_matches m JOIN ironwood_block_receivers r USING(account_id,purpose,key_index)
        WHERE m.account_id=?1 ORDER BY m.height,m.purpose,m.key_index LIMIT ?2")?
        .query_and_then(params![owner.0,limit.min(MAX_KEYS)],|r|Ok::<_,SqliteClientError>(PendingMatch {
            receiver:DiscoveryWork{key:stored_key_id(r)?,receiver:r.get(2)?},block:ChainPoint{height:BlockHeight::from(r.get::<_,u32>(3)?),hash:BlockHash(r.get(4)?)},
        }))?.collect()
}

/// Commits exact key/block evidence with notes and the spend journal after complete trial decryption.
pub(crate) fn scanned(
    conn: &Transaction<'_>,
    keys: &[(AccountUuid, KeyId)],
    blocks: &[(BlockHeight, BlockHash)],
) -> Result<(), SqliteClientError> {
    for (account, key) in keys {
        let identity: Option<(i64,i64)>=conn.query_row("SELECT k.id,k.account_id FROM ironwood_one_time_keys k JOIN accounts a ON a.id=k.account_id WHERE a.uuid=?1 AND k.purpose=?2 AND k.key_index=?3",
            params![account.0,purpose_code(key.purpose())?,key.index().to_be_bytes()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((id, owner)) = identity else {
            return Err(invalid("scanned one-time key is not registered"));
        };
        for (height, hash) in blocks {
            conn.execute("INSERT INTO ironwood_key_scans VALUES (?1,?2,?3) ON CONFLICT(one_time_key_id,height) DO UPDATE SET hash=excluded.hash",params![id,u32::from(*height),hash.0])?;
            conn.execute("DELETE FROM ironwood_block_matches WHERE account_id=?1 AND purpose=?2 AND key_index=?3 AND height=?4 AND hash=?5",
                params![owner,purpose_code(key.purpose())?,key.index().to_be_bytes(),u32::from(*height),hash.0])?;
        }
    }
    Ok(())
}

use crate::{WalletDb, util::Clock};
use rand_core::Rng;
use std::borrow::{Borrow, BorrowMut};
use zcash_client_backend::data_api::one_time_ivk::recovery::{
    OneTimeRecoveryRead, OneTimeRecoveryWrite,
};

impl<C: Borrow<Connection>, P: Parameters, CL, R> OneTimeRecoveryRead for WalletDb<C, P, CL, R> {
    /// Reads this account's durable recovery status.
    fn one_time_recovery_state(
        &self,
        account: AccountUuid,
    ) -> Result<Option<RecoveryState>, SqliteClientError> {
        state(self.conn.borrow(), &self.params, account)
    }
    /// Selects eligible local operations while their account's feature is enabled.
    fn one_time_local_watch_keys(
        &self,
        range: std::ops::Range<BlockHeight>,
        now: i64,
    ) -> Result<
        Vec<zcash_client_backend::scanning::one_time_ivk::OneTimeScanningKey<AccountUuid>>,
        SqliteClientError,
    > {
        if now < 0 {
            return Err(invalid("invalid watch time"));
        }
        if range.is_empty() {
            return Ok(vec![]);
        }
        super::keys_by_account(self.conn.borrow(), &self.params, |account| {
            super::keys_where(self.conn.borrow(),&self.params,account,
                "k.scan_from < ?2 AND k.watch_closed_height IS NULL
                 AND EXISTS(SELECT 1 FROM ironwood_block_recovery r WHERE r.account_id=k.account_id AND r.enabled=1)
                 AND EXISTS(SELECT 1 FROM ironwood_one_time_operations o WHERE o.one_time_key_id=k.id
                     AND o.local_watch_deadline IS NOT NULL AND o.local_watch_deadline>?3-86400)",
                 params![account.0,u32::from(range.end),now])
        })
    }
    /// Captures bounded work without dispatching while paused.
    fn one_time_filter_work(
        &self,
        account: AccountUuid,
        limit: u32,
    ) -> Result<Option<FilterWork<AccountUuid>>, SqliteClientError> {
        filter_work(self.conn.borrow(), &self.params, account, limit)
    }
    /// Reads only this account's outstanding matches.
    fn one_time_pending_matches(
        &self,
        account: AccountUuid,
        limit: u32,
    ) -> Result<Vec<PendingMatch>, SqliteClientError> {
        pending(self.conn.borrow(), &self.params, account, limit)
    }
}

impl<C: BorrowMut<Connection>, P: Parameters, CL: Clock, R: Rng> OneTimeRecoveryWrite
    for WalletDb<C, P, CL, R>
{
    /// Commits the setting and its callback fence together.
    fn set_one_time_recovery_enabled(
        &mut self,
        account: AccountUuid,
        enabled: bool,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| set_enabled(db.conn.0, &db.params, account, enabled))
    }
    /// Commits each bounded derivation batch and its new historical obligations together.
    fn prepare_one_time_recovery(
        &mut self,
        account: AccountUuid,
        budget: u32,
        now: i64,
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| prepare(db.conn.0, &db.params, account, budget, now))
    }
    /// Commits accepted history and replay requirements in one transaction.
    fn accept_one_time_history(
        &mut self,
        account: AccountUuid,
        history: History,
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| accept_history(db.conn.0, &db.params, account, history))
    }
    /// Atomically stores filter progress and all matches after rechecking the captured work.
    fn record_one_time_filters(
        &mut self,
        account: AccountUuid,
        work: &FilterWork<AccountUuid>,
        judgments: &[FilterJudgment],
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| record_filters(db.conn.0, &db.params, account, work, judgments))
    }
}

/// Closes a local watch only after the entire block was scanned with its key and all
/// operations and known receipts are settled. Empty success alone never closes it.
pub(crate) fn close_local_watches(
    conn: &Transaction<'_>,
    block: (BlockHeight, BlockHash),
) -> Result<(), SqliteClientError> {
    let confirmed = u32::from(block.0).saturating_add(1).saturating_sub(
        zcash_client_backend::data_api::wallet::ConfirmationsPolicy::default()
            .untrusted()
            .get(),
    );
    let candidates = conn.prepare("SELECT k.id FROM ironwood_one_time_keys k
        WHERE k.watch_closed_height IS NULL
        AND EXISTS(SELECT 1 FROM ironwood_block_recovery r WHERE r.account_id=k.account_id AND r.enabled=1)
        AND EXISTS(SELECT 1 FROM ironwood_one_time_operations o WHERE o.one_time_key_id=k.id AND o.local_watch_deadline IS NOT NULL)
        AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_operations o WHERE o.one_time_key_id=k.id AND o.expectation NOT IN(1,2))
        AND EXISTS(SELECT 1 FROM ironwood_key_scans s WHERE s.one_time_key_id=k.id AND s.height=?1 AND s.hash=?2)
        AND EXISTS(SELECT 1 FROM ironwood_received_notes n JOIN transactions t ON t.id_tx=n.transaction_id WHERE n.one_time_key_id=k.id AND t.mined_height<=?3)
        AND NOT EXISTS(SELECT 1 FROM ironwood_received_notes n JOIN transactions t ON t.id_tx=n.transaction_id
            WHERE n.one_time_key_id=k.id AND NOT EXISTS(SELECT 1 FROM ironwood_key_scans s JOIN blocks b ON b.height=s.height AND b.hash=s.hash
                WHERE s.one_time_key_id=k.id AND s.height=t.mined_height))
        AND NOT EXISTS(SELECT 1 FROM ironwood_received_notes n JOIN transactions t ON t.id_tx=n.transaction_id WHERE n.one_time_key_id=k.id AND (t.mined_height IS NULL OR t.mined_height>?3))")?
        .query_map(params![u32::from(block.0),block.1.0,confirmed], |r| r.get::<_,i64>(0))?
        .collect::<Result<Vec<_>,_>>()?;
    for key in candidates {
        let expectations = conn.prepare("SELECT expected_value FROM ironwood_one_time_operations WHERE one_time_key_id=?1 AND expectation=2")?
            .query_map([key], |r| r.get::<_,Option<u64>>(0))?.collect::<Result<Vec<_>,_>>()?;
        // An unknown amount cannot be attributed among multiple operations on one key.
        if expectations.len() > 1 && expectations.iter().any(Option::is_none) {
            continue;
        }
        let expected: u128 = expectations
            .into_iter()
            .map(|v| u128::from(v.unwrap_or(1)))
            .sum();
        let received = conn.prepare("SELECT n.value FROM ironwood_received_notes n JOIN transactions t ON t.id_tx=n.transaction_id WHERE n.one_time_key_id=?1 AND t.mined_height<=?2")?
            .query_map(params![key,confirmed], |r| r.get::<_,u64>(0))?
            .try_fold(0u128, |total,v| v.map(|v|total+u128::from(v)))?;
        if received >= expected {
            conn.execute("UPDATE ironwood_one_time_keys SET watch_closed_height=?2,watch_closed_hash=?3 WHERE id=?1",params![key,u32::from(block.0),block.1.0])?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
