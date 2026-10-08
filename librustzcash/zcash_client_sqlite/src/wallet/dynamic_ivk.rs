//! Durable dynamic IVKs (see [`zakura_dynamic_ivk`]), each trial-decrypted while open.
//!
//! Issued keys scan from issuance, refund keys from their stored funding transaction,
//! until they close. Keys recovered from the seed are swept once through a receiver
//! directory, then scanned only while a swap may still pay them. A closed key keeps its
//! notes. A wallet drives dynamic IVKs with these calls:
//!
//! - `scan_cached_blocks_with_dynamic_ivks` and
//!   `decrypt_and_store_transaction_with_dynamic_ivks` in place of the ordinary
//!   scanning and decryption; while a key is open, the others are refused.
//! - [`DynamicIvkWrite::maintain_dynamic_ivks`] when each sync starts and again at the
//!   tip, and [`WalletDb::close_finished_dynamic_keys`] once sync reaches a tip it
//!   confirmed with the network.
//! - For an outgoing swap, [`WalletDb::reserve_refund_key`], then
//!   [`WalletDb::record_refund_operation`] when the quote arrives,
//!   [`WalletDb::refund_funding_memo`] for the funding transaction and
//!   [`verify_refund_funding_proposal`] before signing.
//! - For an incoming swap, [`WalletDb::prepare_receive_reservation`], then
//!   [`WalletDb::begin_receive_operation`], [`WalletDb::finish_receive_operation`] and
//!   [`WalletDb::start_receive_operation`].
//! - [`WalletDb::record_operation_status`] for each provider status of either.
//! - `zakura_pir_receiver::sweep` for restore sweeps, and
//!   [`WalletDb::recheck_dynamic_key_history`] when the user asks to recheck swaps.
//!
//! [`DynamicIvkRead`]: zcash_client_backend::data_api::dynamic_ivk::DynamicIvkRead
//! [`DynamicIvkWrite`]: zcash_client_backend::data_api::dynamic_ivk::DynamicIvkWrite
//! [`DynamicIvkWrite::maintain_dynamic_ivks`]: zcash_client_backend::data_api::dynamic_ivk::DynamicIvkWrite::maintain_dynamic_ivks

mod apply;
mod funding;
mod lifecycle;
mod payments;
mod planner;
mod recovery;
mod reservations;
mod retention;
mod sweep;

pub(crate) use apply::apply_sweep;
pub(crate) use funding::start_funded_refund_keys;
pub use funding::verify_refund_funding_proposal;
use payments::{PendingPayment, SpendStatus};
pub(crate) use planner::{begin_sweep_attempt, history_pending, prepare_sweeps};
pub(crate) use recovery::maintain;
pub(crate) use reservations::RECEIVE_LOOKAHEAD;
pub use reservations::{
    OperationOutcome, ProviderSeen, RECEIVE_GAP_LIMIT, RECEIVE_RECLAIM_SECONDS, ReceiveDeposit,
    SEEN_SLACK_SECONDS,
};
pub(crate) use retention::finish_nullifier_recovery;
pub(crate) use sweep::{note_data_needed, publication_anchor, queue_directory_lookup};

use std::{
    borrow::{Borrow, BorrowMut},
    collections::HashSet,
    ops::Range,
    time::UNIX_EPOCH,
};

use orchard::keys::{FullViewingKey, Scope};
use rand_core::Rng;
use rusqlite::{Connection, OptionalExtension, named_params};
use zcash_client_backend::{
    data_api::{
        Account as _,
        scanning::{ScanPriority, ScanRange},
    },
    scanning::dynamic_ivk::DynamicScanningKey,
};
use zcash_protocol::{
    consensus::{BlockHeight, Parameters},
    memo::MemoBytes,
};

use zakura_dynamic_ivk::lifecycle::Observation;
pub use zakura_dynamic_ivk::{KeyId, Purpose};

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
    /// A refund record cannot be read by this version, and may hold a refund index.
    Unreadable,
}

/// A registered key, re-derived from its account's viewing key. It holds viewing
/// material, so it deliberately does not implement `Debug`.
pub struct DynamicKey {
    scanning_key: DynamicScanningKey<AccountUuid>,
}

impl DynamicKey {
    /// The key's purpose and index.
    pub fn key_id(&self) -> KeyId {
        self.scanning_key.key_id()
    }

    /// The derived FVK, for note reconstruction and spending.
    pub fn full_viewing_key(&self) -> &FullViewingKey {
        self.scanning_key.full_viewing_key()
    }

    /// The receiver at external diversifier index zero.
    pub fn receiver(&self) -> orchard::Address {
        self.full_viewing_key().address_at(0u32, Scope::External)
    }
}

impl<C: Borrow<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// The key `account` registered for `receiver`, if any.
    pub fn get_dynamic_key_for_receiver(
        &self,
        account: AccountUuid,
        receiver: &orchard::Address,
    ) -> Result<Option<DynamicKey>, SqliteClientError> {
        key_matching(
            self.conn.borrow(),
            &self.params,
            account,
            "k.receiver = ?2",
            rusqlite::params![account.0, receiver.to_raw_address_bytes()],
        )
    }

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
    ) -> Result<Result<DynamicKey, ReservationPolicy>, SqliteClientError> {
        let now = unix_now(&self.clock);
        self.transactionally(|db| funding::reserve(db.conn.0, db.params, account, tip, now))
    }

    /// Binds a refund quote's deposit address to the refund key reserved at `index`,
    /// before the quote is shown; funding requires it. A refund only follows a deposit,
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
    /// restore lookahead's sweeps, which may reveal paid or seen indices.
    pub fn prepare_receive_reservation(
        &mut self,
        account: AccountUuid,
        now: i64,
        tip: BlockHeight,
        seen: Option<&ProviderSeen<'_>>,
    ) -> Result<Result<DynamicKey, ReservationPolicy>, SqliteClientError> {
        let registered_at = unix_now(&self.clock);
        self.transactionally(|db| {
            let (conn, params) = (db.conn.0, db.params);
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
    /// and a rejection releases the request's hold on the address.
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

    /// Records a provider status, requested at `now` and normalized by the caller (such as
    /// with `near_observation`), on `account`'s accepted operations with this deposit
    /// address and memo, then reclaims what became reclaimable. Returns whether any
    /// matched. `funded`, sticky, says a deposit was seen.
    ///
    /// An older observation than the stored one is ignored, and its deadline only fills a
    /// missing one, so a status can neither close a key early nor hold it open. A refund
    /// key this wallet never funded starts at its issuance point on a refund owed or an
    /// inconclusive end, in case the deposit was paid from elsewhere.
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
    /// later. It stays open while its reservation is, or while a receipt is unmined and
    /// unexpired or short of the default untrusted confirmations, so a reorg cannot
    /// strand one. Nothing closes unless the stored tip and the scanned height equal
    /// `tip`, which the caller just confirmed, and closing uses the earlier of `now` and
    /// `tip`'s block time.
    pub fn close_finished_dynamic_keys(
        &mut self,
        account: AccountUuid,
        now: i64,
        tip: BlockHeight,
    ) -> Result<usize, SqliteClientError> {
        self.transactionally(|db| {
            lifecycle::close_finished(db.conn.0, db.params, account, now, tip)
        })
    }

    /// Queues a receiver-directory sweep of each of `account`'s closed keys, as a restore
    /// does, to find a payment after its key closed, and returns how many were queued.
    pub fn recheck_dynamic_key_history(
        &mut self,
        account: AccountUuid,
    ) -> Result<usize, SqliteClientError> {
        self.transactionally(|db| recovery::recheck(db.conn.0, db.params, account))
    }
}

/// Blocks a wallet may trail the network tip and still issue an address. Further
/// behind, restore discovery may not yet have reached an index the seed already used.
pub const ISSUANCE_TIP_LAG: u32 = 10;

/// SQL condition on key `k`: swept, with no reservation or operation of this wallet's.
const RESTORED: &str =
    "EXISTS(SELECT 1 FROM ironwood_dynamic_sweeps s WHERE s.receiving_key_id = k.id)
    AND k.reserved_at IS NULL
    AND NOT EXISTS(SELECT 1 FROM ironwood_dynamic_operations o WHERE o.receiving_key_id = k.id)";

/// SQL condition on `ironwood_receiving_keys k`: its incoming reservation is open.
const RESERVED: &str = "(k.reserved_at IS NOT NULL AND k.released_at IS NULL)";

/// `account`'s keys matching `predicate` on `ironwood_receiving_keys k`, selected and
/// decoded in one query since row IDs may be reused. Predicates are library-owned SQL;
/// `?1` is the account UUID.
fn keys_where<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    predicate: &str,
    bindings: impl rusqlite::Params,
) -> Result<Vec<DynamicKey>, SqliteClientError> {
    let (_, parent) = account_key(conn, params, account)?;
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT k.purpose, k.key_index, k.receiver
         FROM ironwood_receiving_keys k JOIN accounts a ON a.id = k.account_id
         WHERE a.uuid = ?1 AND ({predicate}) ORDER BY k.purpose, k.key_index",
    ))?;
    let mut rows = stmt.query(bindings)?;
    let mut keys = Vec::new();
    while let Some(row) = rows.next()? {
        keys.push(registered_key(row, account, &parent)?);
    }
    Ok(keys)
}

/// The key [`keys_where`] selects, if any.
fn key_matching<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    predicate: &str,
    bindings: impl rusqlite::Params,
) -> Result<Option<DynamicKey>, SqliteClientError> {
    Ok(keys_where(conn, params, account, predicate, bindings)?
        .into_iter()
        .next())
}

/// `account`'s key with registry ID `id`.
fn key_by_id<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    id: i64,
) -> Result<DynamicKey, SqliteClientError> {
    key_matching(
        conn,
        params,
        account,
        "k.id = ?2",
        rusqlite::params![account.0, id],
    )?
    .ok_or_else(|| corrupt("missing dynamic key"))
}

/// Implements `DynamicIvkRead::get_dynamic_scanning_keys`, failing on a corrupt key.
pub(crate) fn scanning_keys<P: Parameters>(
    conn: &Connection,
    params: &P,
) -> Result<Vec<DynamicScanningKey<AccountUuid>>, SqliteClientError> {
    keys_by_account(conn, params, |account| {
        let open = "k.active_from IS NOT NULL AND k.closed_at IS NULL";
        keys_where(conn, params, account, open, [account.0])
    })
}

/// The scanning keys `keys` returns for each account with an Orchard viewing key.
fn keys_by_account<P: Parameters>(
    conn: &Connection,
    params: &P,
    keys: impl Fn(AccountUuid) -> Result<Vec<DynamicKey>, SqliteClientError>,
) -> Result<Vec<DynamicScanningKey<AccountUuid>>, SqliteClientError> {
    let mut result = Vec::new();
    for (account, ufvk) in super::get_unified_full_viewing_keys(conn, params)? {
        if ufvk.orchard().is_some() {
            result.extend(keys(account)?.into_iter().map(|key| key.scanning_key));
        }
    }
    Ok(result)
}

/// Implements `DynamicIvkRead::get_dynamic_transaction_keys`: keys that may own outputs
/// of `txid`, which are those its stored notes or queued payments name, open keys active
/// by the next block (by `height` without a chain tip), and keys for `receivers`.
pub(crate) fn transaction_keys<P: Parameters>(
    conn: &Connection,
    params: &P,
    txid: zcash_primitives::transaction::TxId,
    height: Option<BlockHeight>,
    receivers: &[orchard::Address],
) -> Result<Vec<DynamicScanningKey<AccountUuid>>, SqliteClientError> {
    let height = super::chain_tip_height(conn)?
        .map(|h| BlockHeight::from(u32::from(h).saturating_add(1)))
        .or(height);
    let receivers = receivers
        .iter()
        .map(|r| format!("X'{}'", hex::encode(r.to_raw_address_bytes())))
        .collect::<Vec<_>>()
        .join(",");
    // Only matching keys are derived, so enhancing a closed key's note does not derive
    // the historical registry.
    let predicate = format!(
        "k.id IN (SELECT receiving_key_id FROM ironwood_received_notes
                WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?2)
            UNION SELECT receiving_key_id FROM ironwood_dynamic_payment_recovery
                WHERE txid = ?2)
         OR (k.closed_at IS NULL AND k.active_from <= COALESCE(?3, k.active_from))
         OR k.receiver IN ({receivers})"
    );
    keys_by_account(conn, params, |account| {
        let bindings = rusqlite::params![account.0, txid.as_ref(), height.map(u32::from)];
        keys_where(conn, params, account, &predicate, bindings)
    })
}

/// The key of a registry row selecting purpose, key_index and receiver, checked.
fn registered_key(
    row: &rusqlite::Row<'_>,
    account: AccountUuid,
    parent: &FullViewingKey,
) -> Result<DynamicKey, SqliteClientError> {
    let scanning_key = DynamicScanningKey::derive(account, stored_key_id(row)?, parent)?;
    check_receiver(row.get(2)?, scanning_key.full_viewing_key())?;
    Ok(DynamicKey { scanning_key })
}

/// Checks a stored receiver against the one `fvk` derives, which also rejects a key
/// registered to another account.
fn check_receiver(stored: Vec<u8>, fvk: &FullViewingKey) -> Result<(), SqliteClientError> {
    if stored != fvk.address_at(0u32, Scope::External).to_raw_address_bytes() {
        return Err(corrupt(
            "stored dynamic key receiver does not match its key",
        ));
    }
    Ok(())
}

/// The key identity of a registry row selecting purpose and key_index first.
fn stored_key_id(row: &rusqlite::Row<'_>) -> Result<KeyId, SqliteClientError> {
    let purpose = match row.get::<_, u8>(0)? {
        0 => Purpose::Refund,
        1 => Purpose::Receive,
        _ => return Err(corrupt("unsupported dynamic key purpose")),
    };
    Ok(KeyId::new(purpose, decode_index(row.get(1)?)?))
}

/// `account`'s database reference and the Orchard FVK its dynamic keys derive from.
fn account_key<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
) -> Result<(super::AccountRef, FullViewingKey), SqliteClientError> {
    let account =
        super::get_account(conn, params, account)?.ok_or(SqliteClientError::AccountUnknown)?;
    let fvk = account
        .ufvk()
        .and_then(|key| key.orchard())
        .ok_or_else(|| {
            SqliteClientError::BadAccountData(
                "dynamic IVKs require an Orchard full viewing key".into(),
            )
        })?;
    Ok((account.id, fvk.clone()))
}

/// The registry ID of `account`'s key `key`.
fn key_ref(conn: &Connection, account: AccountUuid, key: KeyId) -> Result<i64, SqliteClientError> {
    conn.query_row(
        "SELECT k.id FROM ironwood_receiving_keys k JOIN accounts a ON a.id = k.account_id
         WHERE a.uuid = ?1 AND k.purpose = ?2 AND k.key_index = ?3",
        rusqlite::params![
            account.0,
            purpose_code(key.purpose()),
            key.index().to_be_bytes()
        ],
        |r| r.get(0),
    )
    .optional()?
    .ok_or_else(|| invalid("unregistered dynamic key"))
}

/// Where restore discovery starts: the account's birthday or Ironwood activation.
fn restore_start<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: super::AccountRef,
) -> Result<BlockHeight, SqliteClientError> {
    let birthday: u32 = conn.query_row(
        "SELECT birthday_height FROM accounts WHERE id = ?1",
        [account.0],
        |row| row.get(0),
    )?;
    let activation = params
        .activation_height(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
        .ok_or_else(|| corrupt("Ironwood inactive"))?;
    Ok(BlockHeight::from(birthday).max(activation))
}

/// The first block a key issued now scans, if scanning is within [`ISSUANCE_TIP_LAG`] of
/// `tip` and the stored tip.
fn issuance_start(
    conn: &Connection,
    tip: BlockHeight,
) -> Result<Result<BlockHeight, ReservationPolicy>, SqliteClientError> {
    let Some(scanned) = super::fully_scanned_height(conn)? else {
        return Ok(Err(ReservationPolicy::Coverage));
    };
    let tip = tip.max(super::chain_tip_height(conn)?.unwrap_or(scanned));
    Ok(
        if u32::from(tip).saturating_sub(u32::from(scanned)) > ISSUANCE_TIP_LAG {
            Err(ReservationPolicy::Coverage)
        } else {
            Ok(scanned + 1)
        },
    )
}

/// How a newly registered key's history is covered.
#[derive(Clone, Copy)]
enum Discovery {
    /// Trial-decrypt from `scan_from` until the key closes.
    Scan,
    /// Sweep the receiver directory once, unless the key is already scanned.
    Sweep,
    /// Wait for its funding transaction (see [`start_funded_refund_keys`]).
    Funding,
}

/// Reserves the next `purpose` index, expecting payments from `scan_from`, without
/// readiness checks, skipping refund indices registered without advancing allocation.
/// Refuses with [`ReservationPolicy::Gap`] to scan a key whose restore sweep is pending.
fn reserve_next<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    purpose: Purpose,
    scan_from: BlockHeight,
    discovery: Discovery,
    now: i64,
) -> Result<Result<DynamicKey, ReservationPolicy>, SqliteClientError> {
    let (account_ref, _) = account_key(conn, params, account)?;
    // SQLite orders fixed-width big-endian blobs numerically. Unlike INTEGER, this
    // represents the entire u64 index space, including u64::MAX.
    let last: Option<Vec<u8>> = conn.query_row(
        "SELECT MAX(key_index) FROM ironwood_receiving_keys
         WHERE account_id = :account AND purpose = :purpose AND advances_allocation = 1",
        named_params![":account": account_ref.0, ":purpose": purpose_code(purpose)],
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

/// Whether `key_id`'s restore sweep is pending, so it cannot start (see [`activate`]).
fn sweep_pending(
    conn: &Connection,
    account_ref: i64,
    key_id: KeyId,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_receiving_keys k
         JOIN ironwood_dynamic_sweeps s ON s.receiving_key_id = k.id
         WHERE k.account_id = ?1 AND k.purpose = ?2 AND k.key_index = ?3
           AND k.active_from IS NULL AND s.done_height IS NULL)",
        rusqlite::params![
            account_ref,
            purpose_code(key_id.purpose()),
            key_id.index().to_be_bytes()
        ],
        |row| row.get(0),
    )?)
}

/// Registers `key_id`, expecting payments from `scan_from`, or widens its registration,
/// and returns its row ID and key.
#[allow(clippy::too_many_arguments)]
fn register<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    key_id: KeyId,
    scan_from: BlockHeight,
    advances_allocation: bool,
    discovery: Discovery,
    now: i64,
) -> Result<(i64, DynamicKey), SqliteClientError> {
    let (account_ref, parent) = account_key(conn, params, account)?;
    let scanning_key = DynamicScanningKey::derive(account, key_id, &parent)?;
    let receiver = scanning_key
        .full_viewing_key()
        .address_at(0u32, Scope::External)
        .to_raw_address_bytes();
    // Repeated recovery can widen required history or promote a lookahead key. It must
    // never forget a reservation, narrow history, or replace a receiver.
    let (id, stored_from, active_from): (i64, u32, Option<u32>) = conn
        .query_row(
            "INSERT INTO ironwood_receiving_keys
             (account_id, purpose, key_index, receiver, scan_from, advances_allocation,
              registered_at)
         VALUES (:account, :purpose, :index, :receiver, :scan_from, :allocated, :now)
         ON CONFLICT (account_id, purpose, key_index) DO UPDATE SET
             scan_from = MIN(ironwood_receiving_keys.scan_from, excluded.scan_from),
             advances_allocation = MAX(
                 ironwood_receiving_keys.advances_allocation, excluded.advances_allocation)
         WHERE ironwood_receiving_keys.receiver = excluded.receiver
         RETURNING id, scan_from, active_from",
            named_params![
                ":account": account_ref.0,
                ":purpose": purpose_code(key_id.purpose()),
                ":index": &key_id.index().to_be_bytes(),
                ":receiver": &receiver,
                ":scan_from": u32::from(scan_from),
                ":allocated": advances_allocation,
                ":now": now,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or_else(|| corrupt("stored dynamic key receiver does not match its key"))?;
    match discovery {
        Discovery::Scan => {
            activate(conn, id, scan_from)?;
        }
        // Only a key scanned from its earliest possible payment needs no directory history.
        Discovery::Sweep if active_from.is_none_or(|start| start > stored_from) => {
            conn.execute(
                "INSERT OR IGNORE INTO ironwood_dynamic_sweeps (receiving_key_id) VALUES (?1)",
                [id],
            )?;
        }
        Discovery::Sweep | Discovery::Funding => {}
    }
    Ok((id, DynamicKey { scanning_key }))
}

/// Starts or extends trial decryption of key `id` from `from`, reopening a closed key and
/// requeuing blocks scanned without it, or returns false while its restore sweep is
/// pending. A swept key whose address someone was given starts no later than the block
/// after the sweep's coverage; any other cannot have been paid since.
fn activate(
    conn: &rusqlite::Transaction<'_>,
    id: i64,
    from: BlockHeight,
) -> Result<bool, SqliteClientError> {
    let (active_from, closed, quoted, swept, sweep_done): (
        Option<u32>,
        bool,
        bool,
        bool,
        Option<u32>,
    ) = conn.query_row(
        "SELECT k.active_from, k.closed_at IS NOT NULL,
                k.provider_seen = 1 OR EXISTS(SELECT 1 FROM ironwood_dynamic_operations o
                    WHERE o.receiving_key_id = k.id AND o.request IS NOT NULL),
                s.receiving_key_id IS NOT NULL, s.done_height
         FROM ironwood_receiving_keys k
         LEFT JOIN ironwood_dynamic_sweeps s ON s.receiving_key_id = k.id
         WHERE k.id = ?1",
        [id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let from = match (active_from, swept, sweep_done) {
        (None, true, Some(done)) if quoted => from.min(BlockHeight::from(done.saturating_add(1))),
        (None, true, None) => return Ok(false),
        _ => from,
    };
    let scanned_end = conn
        .query_row("SELECT MAX(height) FROM blocks", [], |row| {
            row.get::<_, Option<u32>>(0)
        })?
        .map_or(u32::from(from), |h| h.saturating_add(1));
    let rescan_end = match active_from {
        Some(start) if !closed && start <= u32::from(from) => return Ok(true),
        // Lowering an open key's start only adds the older blocks.
        Some(start) if !closed => start.min(scanned_end),
        _ => scanned_end,
    };
    conn.execute(
        "UPDATE ironwood_receiving_keys SET active_from = ?2, closed_at = NULL WHERE id = ?1",
        rusqlite::params![id, u32::from(from)],
    )?;
    queue_rescan(conn, from..BlockHeight::from(rescan_end))?;
    Ok(true)
}

/// Queues `range` for a forced rescan with historic priority.
fn queue_rescan(
    conn: &rusqlite::Transaction<'_>,
    range: Range<BlockHeight>,
) -> Result<(), SqliteClientError> {
    if !range.is_empty() {
        crate::wallet::scanning::replace_queue_entries::<SqliteClientError>(
            conn,
            &range,
            std::iter::once(ScanRange::from_parts(range.clone(), ScanPriority::Historic)),
            true,
        )?;
    }
    Ok(())
}

/// Requeues the part of a stored batch that open keys outside `used`, the snapshot that
/// scanned it, missed.
pub(crate) fn rescan_missed_keys(
    conn: &rusqlite::Transaction<'_>,
    used: &[(AccountUuid, KeyId)],
    range: Range<BlockHeight>,
) -> Result<(), SqliteClientError> {
    let used: HashSet<_> = used.iter().copied().collect();
    let mut stmt = conn.prepare_cached(
        "SELECT k.purpose, k.key_index, a.uuid, k.active_from
         FROM ironwood_receiving_keys k JOIN accounts a ON a.id = k.account_id
         WHERE k.closed_at IS NULL AND k.active_from < ?1",
    )?;
    let mut rows = stmt.query([u32::from(range.end)])?;
    let mut missed = Vec::new();
    while let Some(row) = rows.next()? {
        if !used.contains(&(AccountUuid(row.get(2)?), stored_key_id(row)?)) {
            missed.push(BlockHeight::from(row.get::<_, u32>(3)?).max(range.start));
        }
    }
    drop(rows);
    if let Some(start) = missed.into_iter().min() {
        queue_rescan(conn, start..range.end)?;
    }
    Ok(())
}

/// Whether a dynamic key is open, so that blocks scanned without it must not be stored.
pub(crate) fn key_open(conn: &Connection) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_receiving_keys
         WHERE active_from IS NOT NULL AND closed_at IS NULL)",
        [],
        |row| row.get(0),
    )?)
}

/// Seconds since the Unix epoch on the wallet clock, or 0 before it.
pub(crate) fn unix_now(clock: &impl Clock) -> i64 {
    clock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Re-derives registered key `id` from `parent`, the viewing key of its note's account.
pub(super) fn note_key(
    conn: &Connection,
    id: i64,
    parent: &FullViewingKey,
) -> Result<(KeyId, FullViewingKey), SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT purpose, key_index, receiver FROM ironwood_receiving_keys WHERE id = ?1",
    )?;
    let mut rows = stmt.query([id])?;
    let row = rows
        .next()?
        .ok_or_else(|| corrupt("missing dynamic note key"))?;
    let key_id = stored_key_id(row)?;
    let fvk = key_id.derive(parent)?;
    check_receiver(row.get(2)?, &fvk)?;
    Ok((key_id, fvk))
}

/// The incoming key that decrypts queued dynamic-key note `id` for Enhance. Any other
/// recipient than the key's receiver is corrupt, never a fallback to the account's key.
pub(crate) fn queued_note_ivk(
    conn: &Connection,
    account: &crate::wallet::Account,
    id: i64,
    scope: Scope,
    diversifier: orchard::keys::Diversifier,
) -> Result<orchard::keys::IncomingViewingKey, SqliteClientError> {
    let parent = account
        .ufvk()
        .and_then(|key| key.orchard())
        .ok_or_else(|| corrupt("missing dynamic note account FVK"))?;
    let (_, fvk) = note_key(conn, id, parent)?;
    let ivk = fvk.to_ivk(Scope::External);
    if scope != Scope::External || ivk.address(diversifier) != fvk.address_at(0u32, Scope::External)
    {
        return Err(corrupt("invalid queued dynamic note recipient"));
    }
    Ok(ivk)
}

/// Validates an output's dynamic key before it is stored, returning its registry ID.
pub(super) fn validate_received_key<
    P: Parameters,
    T: zcash_client_backend::data_api::ll::ReceivedOrchardOutput<AccountId = AccountUuid>,
>(
    conn: &Connection,
    params: &P,
    pool: zcash_protocol::ShieldedPool,
    output: &T,
) -> Result<Option<i64>, SqliteClientError> {
    let Some(key_id) = output.dynamic_key_id() else {
        return Ok(None);
    };
    let (_, parent) = account_key(conn, params, output.account_id())?;
    let id = key_ref(conn, output.account_id(), key_id)?;
    let (_, fvk) = note_key(conn, id, &parent)?;
    if pool != zcash_protocol::ShieldedPool::Ironwood
        || output.note().version() != orchard::note::NoteVersion::V3
        || output.recipient_key_scope() != Some(Scope::External)
        || output.note().recipient() != fvk.address_at(0u32, Scope::External)
        || output
            .nullifier()
            .is_some_and(|nf| *nf != output.note().nullifier(&fvk))
    {
        return Err(corrupt(
            "dynamic-key note does not match its registered key",
        ));
    }
    Ok(Some(id))
}

/// Moves a stored Ironwood note with nullifier `nf` to `action_index` of `tx_ref`, where
/// it was just found, from the transaction a directory claimed for it, which is deleted
/// once nothing refers to it. Only the note itself was authenticated.
pub(super) fn adopt_found_note(
    conn: &Connection,
    nf: &[u8; 32],
    tx_ref: crate::TxRef,
    action_index: usize,
) -> Result<(), SqliteClientError> {
    let index = i64::try_from(action_index).expect("output indices are representable as i64");
    let stored: Option<(i64, i64)> = conn
        .query_row(
            "SELECT id, transaction_id FROM ironwood_received_notes
             WHERE nf = ?1 AND (transaction_id != ?2 OR action_index != ?3)",
            rusqlite::params![nf, tx_ref.0, index],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((id, claimed)) = stored else {
        return Ok(());
    };
    conn.execute(
        "UPDATE ironwood_received_notes SET transaction_id = ?2, action_index = ?3 WHERE id = ?1",
        rusqlite::params![id, tx_ref.0, index],
    )?;
    conn.execute(
        "DELETE FROM transactions WHERE id_tx = ?1 AND raw IS NULL
         AND NOT EXISTS(SELECT 1 FROM v_received_outputs WHERE transaction_id = ?1)
         AND NOT EXISTS(SELECT 1 FROM v_received_output_spends WHERE transaction_id = ?1)
         AND NOT EXISTS(SELECT 1 FROM sent_notes WHERE transaction_id = ?1)",
        [claimed],
    )?;
    Ok(())
}

/// The stored code of `purpose`.
fn purpose_code(purpose: Purpose) -> u8 {
    match purpose {
        Purpose::Refund => 0,
        Purpose::Receive => 1,
    }
}

/// Decodes a stored big-endian key index.
fn decode_index(bytes: Vec<u8>) -> Result<u64, SqliteClientError> {
    bytes
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| corrupt("invalid dynamic key index"))
}

/// The index after `index`. A purpose's index space never wraps back to zero.
fn next_index(index: u64) -> Result<u64, SqliteClientError> {
    index
        .checked_add(1)
        .ok_or(SqliteClientError::DynamicIvkIndexExhausted)
}

/// A corrupted-data error with `message`.
fn corrupt(message: &str) -> SqliteClientError {
    SqliteClientError::CorruptedData(message.to_owned())
}

/// An invalid-input error with `message`.
fn invalid(message: &'static str) -> SqliteClientError {
    SqliteClientError::InvalidDynamicIvkInput(message)
}

#[cfg(test)]
pub(crate) mod tests;
