//! Experimental durable swap receiving-key registration.
//!
//! Reserve before exposing an address, and persist the returned key ID with the
//! operation. Retries reuse that ID rather than reserving again. Incoming keys this
//! wallet issues are trial-decrypted from issuance, and refund keys from when the
//! wallet stores their funding transaction, until they close. Keys recovered from the
//! seed are swept once through the receiver directory, then scanned only while their
//! swap is still open. Ownership remains available after a key closes.
//!
//! A wallet drives the feature with these calls:
//!
//! - [`WalletDb::maintain_swap_receiving`] when each sync starts and again at the
//!   chain tip, and [`WalletDb::close_finished_swap_keys`] once sync reaches a tip it
//!   confirmed with the network.
//! - [`WalletDb::reserve_swap_refund_key`] for a refund address and
//!   [`WalletDb::prepare_swap_receive_reservation`] for an incoming one.
//! - For an outgoing swap, [`WalletDb::record_swap_refund_quote`] when the quote
//!   arrives, then [`WalletDb::swap_funding_memo`] for the funding transaction and
//!   [`verify_swap_funding_proposal`] before signing.
//! - For an incoming swap, [`WalletDb::begin_swap_receive_quote`],
//!   [`WalletDb::finish_swap_receive_quote`] and
//!   [`WalletDb::start_swap_receive_quote`], then
//!   [`WalletDb::observe_swap_receive_quote`] for each of
//!   [`WalletDb::swap_receive_quotes_due`] and
//!   [`WalletDb::reap_swap_receive_reservations`].
//! - `zakura_pir_receiver::sweep` for restore sweeps, and
//!   [`WalletDb::recheck_swap_history`] when the user asks to recheck swaps.

mod apply;
pub use apply::PaymentApplication;
mod funding;
pub(crate) use funding::start_funded_refund_keys;
pub use funding::verify_swap_funding_proposal;
mod lifecycle;
mod payments;
mod planner;
pub use planner::{DiscoveryBatch, DiscoveryWork};
mod recovery;
mod reservations;
mod retention;
mod sweep;
use payments::{PendingPayment, SpendStatus};
pub use reservations::{
    QuoteOutcome, RECEIVE_GAP_LIMIT, RECEIVE_RECLAIM_SECONDS, RECEIVE_UNFUNDED_LIMIT,
    ReceiveDeposit, ReceiveQuote, ReceiveReservation,
};
pub use sweep::{DirectoryPayment, MAX_PUBLICATION_LAG, SweepDeferral};

use std::{
    borrow::{Borrow, BorrowMut},
    collections::HashSet,
    ops::Range,
    time::UNIX_EPOCH,
};

use orchard::keys::{FullViewingKey, Scope};
use rusqlite::{Connection, OptionalExtension, named_params};
use zcash_client_backend::{
    data_api::{
        Account as _,
        scanning::{ScanPriority, ScanRange},
    },
    scanning::swap_receiving::SwapScanningKey,
};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use zakura_swap_receiving::DerivationError;
pub use zakura_swap_receiving::{KeyId, Purpose};

use crate::{AccountUuid, SqlTransaction, WalletDb, error::SqliteClientError, util::Clock};

/// Stable allocation outcomes for wallet UI and retry policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationPolicy {
    /// Recovery has not established the next safe index.
    Gap,
    /// Too many unfunded incoming operations are reserved.
    Limit,
    /// The selected draft is no longer available.
    Stale,
    /// The wallet has not scanned this address through the chain tip.
    Coverage,
    /// A swap refund record cannot be read by this version, and may hold a refund index.
    Unreadable,
}
impl std::fmt::Display for ReservationPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Gap => {
                "Incoming address recovery is pending. \
                 Wait for a payment or abandoned-address reconciliation."
            }
            Self::Limit => {
                "Too many incoming swaps are awaiting deposits. \
                 Resume one, or wait for an unused one to expire."
            }
            Self::Stale => "This receive reservation is no longer available. Request a new quote.",
            Self::Coverage => "Finish syncing to the chain tip before requesting a quote.",
            Self::Unreadable => {
                "A swap refund record could not be read. \
                 Update the app before swapping ZEC again."
            }
        })
    }
}

/// An error reserving or reconstructing a receiving key.
#[derive(Debug)]
pub enum Error {
    /// Database, account, or stored-data validation failed.
    Wallet(SqliteClientError),
    /// The index has no valid viewing key.
    Derivation(DerivationError),
    /// This purpose's index space is exhausted. Never wrap back to zero.
    IndexExhausted,
    /// Address allocation is waiting for recovery or an existing reservation.
    ReservationPolicy(ReservationPolicy),
    /// A restore sweep step must wait for more scanning or a newer publication.
    SweepDeferred(SweepDeferral),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wallet(e) => e.fmt(f),
            Self::Derivation(e) => e.fmt(f),
            Self::IndexExhausted => f.write_str("swap receiving index space exhausted"),
            Self::ReservationPolicy(policy) => policy.fmt(f),
            Self::SweepDeferred(reason) => reason.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wallet(e) => Some(e),
            Self::Derivation(e) => Some(e),
            Self::IndexExhausted | Self::ReservationPolicy(_) | Self::SweepDeferred(_) => None,
        }
    }
}

impl From<SqliteClientError> for Error {
    fn from(e: SqliteClientError) -> Self {
        Self::Wallet(e)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Wallet(e.into())
    }
}

impl From<DerivationError> for Error {
    fn from(e: DerivationError) -> Self {
        Self::Derivation(e)
    }
}

/// A registered key reconstructed from the wallet's account viewing key.
///
/// This contains viewing material. It deliberately does not implement `Debug`.
pub struct RegisteredKey {
    scanning_key: SwapScanningKey<AccountUuid>,
}

impl RegisteredKey {
    /// The purpose/index identity to retain with operations and received notes.
    pub fn key_id(&self) -> KeyId {
        self.scanning_key.key_id()
    }
    /// The derived FVK to use for note reconstruction and spending.
    pub fn full_viewing_key(&self) -> &FullViewingKey {
        self.scanning_key.full_viewing_key()
    }

    /// The receiver at external diversifier index zero.
    pub fn receiver(&self) -> orchard::Address {
        self.full_viewing_key().address_at(0u32, Scope::External)
    }
}

impl<C: Borrow<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Finds one registered receiver under its owning account and validates its key.
    ///
    /// Returns `None` for ordinary addresses or receivers owned by another account.
    pub fn get_swap_receiving_key_for_receiver(
        &self,
        account: AccountUuid,
        receiver: &orchard::Address,
    ) -> Result<Option<RegisteredKey>, Error> {
        self.swap_receiving_key_matching(
            account,
            "k.receiver=?2",
            rusqlite::params![account.0, receiver.to_raw_address_bytes()],
        )
    }

    /// The key registered to `account` matching `predicate`, selected and decoded in
    /// one query because row IDs may be reused if another connection deletes a
    /// registration. Predicates are library-owned SQL only.
    fn swap_receiving_key_matching(
        &self,
        account: AccountUuid,
        predicate: &'static str,
        bindings: impl rusqlite::Params,
    ) -> Result<Option<RegisteredKey>, Error> {
        let conn = self.conn.borrow();
        let (_, parent) = account_key(conn, &self.params, account)?;
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT k.purpose, k.key_index, k.receiver
             FROM ironwood_receiving_keys k JOIN accounts a ON a.id=k.account_id
             WHERE a.uuid=?1 AND {predicate}",
        ))?;
        let mut rows = stmt.query(bindings)?;
        rows.next()?
            .map(|row| registered_key(row, account, &parent))
            .transpose()
    }

    /// Keys to trial-decrypt in every scan batch: active and not yet closed. Each
    /// must re-derive its stored receiver; a corrupt registration is an error, not a
    /// silently shortened list.
    pub(crate) fn swap_scanning_keys(
        &self,
        account: AccountUuid,
    ) -> Result<Vec<RegisteredKey>, Error> {
        let conn = self.conn.borrow();
        let (account_ref, parent) = account_key(conn, &self.params, account)?;
        let mut stmt = conn.prepare_cached(
            "SELECT purpose, key_index, receiver FROM ironwood_receiving_keys
             WHERE account_id = ?1 AND active_from IS NOT NULL AND closed_at IS NULL
             ORDER BY purpose, key_index",
        )?;
        let mut rows = stmt.query([account_ref.0])?;
        let mut keys = Vec::new();
        while let Some(row) = rows.next()? {
            keys.push(registered_key(row, account, &parent)?);
        }
        Ok(keys)
    }

    /// Keys that may own outputs of `txid`: those its stored notes or queued payments
    /// name, open keys active by the next block (by `height` without a chain tip),
    /// and keys registered for `receivers`.
    pub(crate) fn swap_receiving_transaction_keys(
        &self,
        account: AccountUuid,
        txid: zcash_primitives::transaction::TxId,
        height: Option<BlockHeight>,
        receivers: &[orchard::Address],
    ) -> Result<Vec<RegisteredKey>, Error> {
        let conn = self.conn.borrow();
        let (account_ref, parent) = account_key(conn, &self.params, account)?;
        let height = super::chain_tip_height(conn)?
            .map(|h| BlockHeight::from(u32::from(h).saturating_add(1)))
            .or(height);
        let mut selected = HashSet::new();
        let mut by_receiver = conn.prepare_cached(
            "SELECT id FROM ironwood_receiving_keys WHERE account_id=?1 AND receiver=?2",
        )?;
        for receiver in receivers {
            for id in by_receiver.query_map(
                rusqlite::params![account_ref.0, receiver.to_raw_address_bytes()],
                |r| r.get::<_, i64>(0),
            )? {
                selected.insert(id?);
            }
        }
        let extra = selected
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        // Each union branch starts from transaction or scanning indexes. Enhancing
        // one closed key's note does not walk or derive the historical registry.
        let sql = format!(
            "SELECT purpose,key_index,receiver
            FROM ironwood_receiving_keys WHERE account_id=?1 AND id IN (
                SELECT receiving_key_id FROM ironwood_received_notes
                    WHERE transaction_id=(SELECT id_tx FROM transactions WHERE txid=?2)
                UNION SELECT receiving_key_id FROM ironwood_swap_payment_recovery WHERE txid=?2
                UNION SELECT id FROM ironwood_receiving_keys WHERE account_id=?1
                    AND closed_at IS NULL AND active_from<=COALESCE(?3,active_from)
                UNION SELECT id FROM ironwood_receiving_keys WHERE id IN ({extra}))"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(rusqlite::params![
            account_ref.0,
            txid.as_ref(),
            height.map(u32::from)
        ])?;
        let mut keys = Vec::new();
        while let Some(row) = rows.next()? {
            keys.push(registered_key(row, account, &parent)?);
        }
        Ok(keys)
    }

    /// The scanning keys `keys` returns for each account with an Orchard viewing key.
    pub(crate) fn swap_keys_by_account(
        &self,
        keys: impl Fn(AccountUuid) -> Result<Vec<RegisteredKey>, Error>,
    ) -> Result<Vec<SwapScanningKey<AccountUuid>>, SqliteClientError> {
        let mut result = Vec::new();
        for (account, ufvk) in
            super::get_unified_full_viewing_keys(self.conn.borrow(), &self.params)?
        {
            if ufvk.orchard().is_some() {
                let found = keys(account).map_err(wallet_error)?;
                result.extend(found.into_iter().map(|key| key.scanning_key));
            }
        }
        Ok(result)
    }
}

impl<C: BorrowMut<Connection>, P: Parameters, CL: Clock, R> WalletDb<C, P, CL, R> {
    /// Atomically reserves and registers the next refund index. The key starts
    /// scanning only when this wallet stores a transaction funding its swap (see
    /// [`WalletDb::record_swap_refund_quote`]), so a quote never funded never scans.
    ///
    /// `tip` is the chain tip the caller last observed from the network. The wallet
    /// must be scanned to within [`ISSUANCE_TIP_LAG`] blocks of it. Every funding memo
    /// is recovered first, so an index the seed already used is never issued again.
    /// Only a committed result may be exposed. On a concurrent-write error, retry
    /// the whole operation. To also persist application operation state, call this
    /// on the wallet handle inside `transactionally_with_extension`. Incoming
    /// addresses come from [`WalletDb::prepare_swap_receive_reservation`].
    pub fn reserve_swap_refund_key(
        &mut self,
        account: AccountUuid,
        tip: BlockHeight,
    ) -> Result<RegisteredKey, Error> {
        self.transactionally(|wdb| wdb.reserve_swap_refund_key(account, tip))
    }
}

impl<P: Parameters, CL: Clock, R> WalletDb<SqlTransaction<'_>, P, CL, R> {
    /// Reserves in the enclosing transaction. Expose the address only after commit.
    /// See [`WalletDb::reserve_swap_refund_key`] on a connection-backed handle.
    pub fn reserve_swap_refund_key(
        &mut self,
        account: AccountUuid,
        tip: BlockHeight,
    ) -> Result<RegisteredKey, Error> {
        let scan_from = issuance_start(self.conn.0, tip)?;
        if self.recover_refund_memos(account)? > 0 {
            return Err(Error::ReservationPolicy(ReservationPolicy::Unreadable));
        }
        if self.swap_refund_memos_pending(account)? {
            return Err(Error::ReservationPolicy(ReservationPolicy::Coverage));
        }
        self.reserve_swap_receiving_key_from(
            account,
            Purpose::Refund,
            scan_from,
            Discovery::Funding,
        )
    }

    /// Reserves the next index, expecting payments from `scan_from`, without readiness
    /// checks.
    fn reserve_swap_receiving_key_from(
        &mut self,
        account: AccountUuid,
        purpose: Purpose,
        scan_from: BlockHeight,
        discovery: Discovery,
    ) -> Result<RegisteredKey, Error> {
        let (account_ref, _) = account_key(self.conn.0, &self.params, account)?;
        // SQLite orders fixed-width big-endian blobs numerically. Unlike INTEGER,
        // this represents the entire u64 index space, including u64::MAX.
        let last: Option<Vec<u8>> = self.conn.0.query_row(
            "SELECT MAX(key_index) FROM ironwood_receiving_keys
             WHERE account_id = :account AND purpose = :purpose AND advances_allocation = 1",
            named_params![":account": account_ref.0, ":purpose": purpose_code(purpose)],
            |row| row.get(0),
        )?;
        let mut index = match last {
            Some(bytes) => decode_index(bytes)?
                .checked_add(1)
                .ok_or(Error::IndexExhausted)?,
            None => 0,
        };
        // A funding memo the wallet could not authenticate registers its refund key
        // without advancing allocation (see `recover_refund_memos`); skip that index.
        while purpose == Purpose::Refund
            && self.conn.0.query_row(
                "SELECT EXISTS(SELECT 1 FROM ironwood_receiving_keys
                 WHERE account_id = ?1 AND purpose = 0 AND key_index = ?2)",
                rusqlite::params![account_ref.0, index.to_be_bytes()],
                |row| row.get::<_, bool>(0),
            )?
        {
            index = index.checked_add(1).ok_or(Error::IndexExhausted)?;
        }
        let key_id = KeyId::new(purpose, index);
        let now = unix_now(&self.clock);
        register(
            self.conn.0,
            &self.params,
            account,
            key_id,
            scan_from,
            true,
            discovery,
            now,
        )
        .map(|(_, key)| key)
    }

    /// Registers an incoming lookahead key for a receiver-directory sweep without
    /// advancing address allocation.
    pub(crate) fn watch_swap_receive_key(
        &mut self,
        account: AccountUuid,
        index: u64,
        scan_from: BlockHeight,
    ) -> Result<RegisteredKey, Error> {
        let key_id = KeyId::new(Purpose::Receive, index);
        let now = unix_now(&self.clock);
        register(
            self.conn.0,
            &self.params,
            account,
            key_id,
            scan_from,
            false,
            Discovery::Sweep,
            now,
        )
        .map(|(_, key)| key)
    }
}

/// Reconstructs a key from a registry row whose first three columns are purpose,
/// key_index and receiver.
fn registered_key(
    row: &rusqlite::Row<'_>,
    account: AccountUuid,
    parent: &FullViewingKey,
) -> Result<RegisteredKey, Error> {
    let scanning_key = SwapScanningKey::derive(account, stored_key_id(row)?, parent)?;
    check_receiver(row.get(2)?, scanning_key.full_viewing_key())?;
    Ok(RegisteredKey { scanning_key })
}

/// Checks a stored receiver against the one `fvk` derives. Since keys derive from
/// their account's viewing key, this also rejects a key registered to another account.
fn check_receiver(stored: Vec<u8>, fvk: &FullViewingKey) -> Result<(), Error> {
    if stored != fvk.address_at(0u32, Scope::External).to_raw_address_bytes() {
        return Err(corrupt(
            "stored swap receiver does not match its derived key",
        ));
    }
    Ok(())
}

/// The key identity of a registry row whose first two columns are purpose and
/// key_index.
fn stored_key_id(row: &rusqlite::Row<'_>) -> Result<KeyId, Error> {
    let purpose = match row.get::<_, u8>(0)? {
        0 => Purpose::Refund,
        1 => Purpose::Receive,
        _ => return Err(corrupt("unsupported swap key purpose")),
    };
    Ok(KeyId::new(purpose, decode_index(row.get(1)?)?))
}

/// `account`'s database reference and the Orchard viewing key its swap keys derive from.
fn account_key<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
) -> Result<(super::AccountRef, FullViewingKey), Error> {
    let account =
        super::get_account(conn, params, account)?.ok_or(SqliteClientError::AccountUnknown)?;
    let fvk = account
        .ufvk()
        .and_then(|key| key.orchard())
        .ok_or_else(|| {
            SqliteClientError::BadAccountData(
                "swap receiving requires an Orchard full viewing key".into(),
            )
        })?;
    Ok((account.id, fvk.clone()))
}

/// Where restore discovery starts for an account: its birthday or Ironwood
/// activation, whichever is later.
fn restore_start<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: super::AccountRef,
) -> Result<BlockHeight, Error> {
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

/// Blocks a wallet may trail the network tip and still issue a swap address.
/// Further behind, restore discovery may not yet have reached an index the
/// seed already used.
pub const ISSUANCE_TIP_LAG: u32 = 10;

/// SQL condition on `ironwood_receiving_keys k`: an incoming key that a restore sweep
/// found and this wallet never reserved, so no swap of its own is known.
const RESTORED_INCOMING: &str = "k.purpose = 1
    AND EXISTS(SELECT 1 FROM ironwood_swap_sweeps s WHERE s.receiving_key_id = k.id)
    AND NOT EXISTS(SELECT 1 FROM ironwood_swap_receive_reservations r
        WHERE r.receiving_key_id = k.id)";

/// The first block a key issued now must scan, once the fully scanned height is
/// within [`ISSUANCE_TIP_LAG`] of both `tip` and the stored chain tip.
pub(super) fn issuance_start(conn: &Connection, tip: BlockHeight) -> Result<BlockHeight, Error> {
    let coverage = || Error::ReservationPolicy(ReservationPolicy::Coverage);
    let scanned = crate::wallet::fully_scanned_height(conn)?.ok_or_else(coverage)?;
    let tip = tip.max(crate::wallet::chain_tip_height(conn)?.unwrap_or(scanned));
    if u32::from(tip).saturating_sub(u32::from(scanned)) > ISSUANCE_TIP_LAG {
        return Err(coverage());
    }
    Ok(scanned + 1)
}

/// How a newly registered key's history is covered.
#[derive(Clone, Copy)]
pub(super) enum Discovery {
    /// Trial-decrypt from `scan_from` until the key closes.
    Scan,
    /// Sweep the receiver directory once, unless the key is already scanned.
    Sweep,
    /// Wait for a stored transaction funding the key's swap, which starts its scan
    /// (see [`start_funded_refund_keys`]).
    Funding,
}

/// Registers `key_id` for `account`, or widens an existing registration, and returns
/// its row ID with the key. Payments to it are expected from `scan_from`.
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
) -> Result<(i64, RegisteredKey), Error> {
    let (account_ref, parent) = account_key(conn, params, account)?;
    let scanning_key = SwapScanningKey::derive(account, key_id, &parent)?;
    let receiver = scanning_key
        .full_viewing_key()
        .address_at(0u32, Scope::External)
        .to_raw_address_bytes();
    // Repeated recovery can widen required history or promote a lookahead key.
    // It must never forget a reservation, narrow history, or replace a receiver.
    let updated: Option<(i64, u32, Option<u32>)> = conn
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
        .optional()?;
    let (id, stored_from, active_from) =
        updated.ok_or_else(|| corrupt("stored swap receiver does not match its derived key"))?;
    match discovery {
        Discovery::Scan => activate(conn, id, scan_from)?,
        // Only a key scanned from its earliest possible payment needs no directory history.
        Discovery::Sweep if active_from.is_none_or(|start| start > stored_from) => {
            conn.execute(
                "INSERT OR IGNORE INTO ironwood_swap_sweeps (receiving_key_id) VALUES (?1)",
                [id],
            )?;
        }
        Discovery::Sweep | Discovery::Funding => {}
    }
    Ok((id, RegisteredKey { scanning_key }))
}

/// Starts or extends trial decryption of key `id` from `from`, reopening a closed key.
///
/// Blocks at or above `from` that were scanned without this key are queued for
/// rescanning, so no block in the key's active range is left unchecked. A key
/// first found by a restore sweep starts no later than the block after the
/// sweep's coverage, and cannot start while that sweep is pending.
pub(super) fn activate(
    conn: &rusqlite::Transaction<'_>,
    id: i64,
    from: BlockHeight,
) -> Result<(), Error> {
    let (active_from, closed, swept, sweep_done): (Option<u32>, bool, bool, Option<u32>) = conn
        .query_row(
            "SELECT k.active_from, k.closed_at IS NOT NULL,
                    s.receiving_key_id IS NOT NULL, s.done_height
             FROM ironwood_receiving_keys k
             LEFT JOIN ironwood_swap_sweeps s ON s.receiving_key_id = k.id
             WHERE k.id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    let from = match (active_from, swept, sweep_done) {
        (None, true, Some(done)) => from.min(BlockHeight::from(done.saturating_add(1))),
        (None, true, None) => return Err(Error::ReservationPolicy(ReservationPolicy::Gap)),
        _ => from,
    };
    let scanned_end = conn
        .query_row("SELECT MAX(height) FROM blocks", [], |row| {
            row.get::<_, Option<u32>>(0)
        })?
        .map_or(u32::from(from), |h| h.saturating_add(1));
    let rescan_end = match active_from {
        Some(start) if !closed && start <= u32::from(from) => return Ok(()),
        // Lowering an open key's start only adds the older blocks.
        Some(start) if !closed => start.min(scanned_end),
        _ => scanned_end,
    };
    conn.execute(
        "UPDATE ironwood_receiving_keys SET active_from = ?2, closed_at = NULL WHERE id = ?1",
        rusqlite::params![id, u32::from(from)],
    )?;
    queue_rescan(conn, from..BlockHeight::from(rescan_end))
}

/// Queues `range` for a forced rescan with historic priority.
pub(super) fn queue_rescan(
    conn: &rusqlite::Transaction<'_>,
    range: Range<BlockHeight>,
) -> Result<(), Error> {
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

/// Requeues the part of a stored batch that active keys missed.
///
/// `used` is the key snapshot the batch was scanned with. A key activated while
/// the batch was in flight was not in that snapshot, so its share is rescanned.
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
        let key = stored_key_id(row).map_err(wallet_error)?;
        if !used.contains(&(AccountUuid(row.get(2)?), key)) {
            missed.push(BlockHeight::from(row.get::<_, u32>(3)?).max(range.start));
        }
    }
    drop(rows);
    if let Some(start) = missed.into_iter().min() {
        queue_rescan(conn, start..range.end).map_err(wallet_error)?;
    }
    Ok(())
}

/// Seconds since the Unix epoch on the wallet clock, or 0 before it.
fn unix_now(clock: &impl Clock) -> i64 {
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
        .ok_or_else(|| wallet_error(corrupt("missing swap note key")))?;
    let key_id = stored_key_id(row).map_err(wallet_error)?;
    let fvk = key_id.derive(parent).map_err(|e| wallet_error(e.into()))?;
    check_receiver(row.get(2)?, &fvk).map_err(wallet_error)?;
    Ok((key_id, fvk))
}

/// Validates scan metadata naming a swap key before it can change a note or advance
/// allocation. Returns the key's registry ID.
pub(super) fn validate_received_key<
    P: Parameters,
    T: zcash_client_backend::data_api::ll::ReceivedOrchardOutput<AccountId = AccountUuid>,
>(
    conn: &Connection,
    params: &P,
    pool: zcash_protocol::ShieldedPool,
    output: &T,
) -> Result<Option<i64>, SqliteClientError> {
    let Some(key_id) = output.swap_key_id() else {
        return Ok(None);
    };
    let (_, parent) = account_key(conn, params, output.account_id()).map_err(wallet_error)?;
    let id = payments::key_ref(conn, output.account_id(), key_id).map_err(wallet_error)?;
    let (_, fvk) = note_key(conn, id, &parent)?;
    if pool != zcash_protocol::ShieldedPool::Ironwood
        || output.note().version() != orchard::note::NoteVersion::V3
        || output.recipient_key_scope() != Some(Scope::External)
        || output.note().recipient() != fvk.address_at(0u32, Scope::External)
        || output
            .nullifier()
            .is_some_and(|nf| *nf != output.note().nullifier(&fvk))
    {
        return Err(SqliteClientError::CorruptedData(
            "swap note does not match its registered key".into(),
        ));
    }
    Ok(Some(id))
}

/// Moves a stored Ironwood note with nullifier `nf` to `action_index` of `tx_ref`,
/// where scanning or a full transaction has just found it.
///
/// A sweep stores a note under the transaction ID its directory claims; only the note
/// itself is authenticated. The transaction it is found in is authoritative, so the
/// note moves there with its key and spends, and the claimed transaction is deleted
/// once nothing else refers to it.
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

/// Converts a swap error for storage-trait callers. Database errors pass through.
fn wallet_error(error: Error) -> SqliteClientError {
    match error {
        Error::Wallet(error) => error,
        other => SqliteClientError::CorruptedData(other.to_string()),
    }
}

/// The stored code of `purpose`.
fn purpose_code(purpose: Purpose) -> u8 {
    match purpose {
        Purpose::Refund => 0,
        Purpose::Receive => 1,
    }
}

/// Decodes a stored big-endian key index.
fn decode_index(bytes: Vec<u8>) -> Result<u64, Error> {
    bytes
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| corrupt("invalid swap key index"))
}

/// A corrupted-data error with `message`.
fn corrupt(message: &str) -> Error {
    SqliteClientError::CorruptedData(message.to_owned()).into()
}

#[cfg(test)]
mod tests;
