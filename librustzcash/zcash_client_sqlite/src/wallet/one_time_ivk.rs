//! Durable one-time IVKs (see [`zakura_one_time_ivk`]), each trial-decrypted while open.
//!
//! This module holds the key registry, scanning, spending and the storage guards.
//! [`swap`] issues keys for swaps and closes them from provider status, and `restore`
//! recovers keys from the seed and sweeps them through a receiver directory.
//!
//! Issued keys scan from issuance, refund keys from their stored funding transaction,
//! until they close. Keys recovered from the seed are swept once through a receiver
//! directory, then scanned for a restore watch only while a swap may still pay them (see
//! [`WalletDb::close_finished_one_time_keys`]). A closed key keeps its notes.
//! One-time-key notes carry no memo the wallet reads; only internal change carries the
//! refund marker. So neither a directory nor private Enhance retrieval stores or fetches
//! one. A wallet drives one-time IVKs with these calls:
//!
//! - [`WalletDb::mark_one_time_account_fresh`] when it creates an account from a newly
//!   generated seed.
//! - `scan_cached_blocks_with_one_time_ivks` and
//!   `decrypt_and_store_transaction_with_one_time_ivks` in place of the ordinary
//!   scanning and decryption; while a key is open, the others are refused.
//! - [`OneTimeIvkRestoreWrite::maintain_one_time_ivks`] when each sync starts and again at the
//!   tip, and [`WalletDb::close_finished_one_time_keys`] once sync reaches a tip it
//!   confirmed with the network.
//! - For an outgoing swap, [`WalletDb::reserve_refund_key`], then
//!   [`WalletDb::record_refund_operation`] when the quote arrives,
//!   [`WalletDb::refund_funding_memo`] for the funding transaction and
//!   [`swap::verify_refund_funding_proposal`] before signing.
//! - For an incoming swap, [`WalletDb::prepare_receive_reservation`], then
//!   [`WalletDb::begin_receive_operation`], [`WalletDb::finish_receive_operation`] and
//!   [`WalletDb::start_receive_operation`].
//! - [`WalletDb::record_operation_status`] for each provider status of either.
//! - `zakura_pir_receiver::sweep`, over the [`OneTimeIvkRestoreWrite`] steps, for restore
//!   sweeps, and [`WalletDb::recheck_one_time_key_history`] when the user asks to recheck
//!   swaps.
//!
//! [`OneTimeIvkRestoreWrite`]: zcash_client_backend::data_api::one_time_ivk::restore::OneTimeIvkRestoreWrite
//! [`OneTimeIvkRestoreWrite::maintain_one_time_ivks`]: zcash_client_backend::data_api::one_time_ivk::restore::OneTimeIvkRestoreWrite::maintain_one_time_ivks

pub(crate) mod restore;
pub mod swap;

use std::{borrow::Borrow, collections::HashSet, ops::Range, time::UNIX_EPOCH};

use orchard::keys::{FullViewingKey, Scope};
use rusqlite::{Connection, OptionalExtension, named_params};
use zcash_client_backend::{
    data_api::{
        Account as _,
        scanning::{ScanPriority, ScanRange},
        wallet::ConfirmationsPolicy,
    },
    scanning::one_time_ivk::OneTimeScanningKey,
};
use zcash_protocol::consensus::{BlockHeight, Parameters};

pub use zakura_one_time_ivk::{KeyId, Purpose};

use crate::{AccountUuid, WalletDb, error::SqliteClientError, util::Clock};

/// A registered key, re-derived from its account's viewing key. It holds viewing
/// material, so it deliberately does not implement `Debug`.
pub struct OneTimeKey {
    scanning_key: OneTimeScanningKey<AccountUuid>,
}

impl OneTimeKey {
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
    pub fn get_one_time_key_for_receiver(
        &self,
        account: AccountUuid,
        receiver: &orchard::Address,
    ) -> Result<Option<OneTimeKey>, SqliteClientError> {
        key_matching(
            self.conn.borrow(),
            &self.params,
            account,
            "k.receiver = ?2",
            rusqlite::params![account.0, receiver.to_raw_address_bytes()],
        )
    }
}

/// SQL condition on key `k`: swept, with no reservation or operation of this wallet's.
const RESTORED: &str =
    "EXISTS(SELECT 1 FROM ironwood_one_time_sweeps s WHERE s.one_time_key_id = k.id)
    AND k.reserved_at IS NULL
    AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_operations o WHERE o.one_time_key_id = k.id)";

/// `account`'s keys matching `predicate` on `ironwood_one_time_keys k`, selected and
/// decoded in one query since row IDs may be reused. Predicates are library-owned SQL;
/// `?1` is the account UUID.
fn keys_where<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    predicate: &str,
    bindings: impl rusqlite::Params,
) -> Result<Vec<OneTimeKey>, SqliteClientError> {
    let (_, parent) = account_key(conn, params, account)?;
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT k.purpose, k.key_index, k.receiver
         FROM ironwood_one_time_keys k JOIN accounts a ON a.id = k.account_id
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
) -> Result<Option<OneTimeKey>, SqliteClientError> {
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
) -> Result<OneTimeKey, SqliteClientError> {
    key_matching(
        conn,
        params,
        account,
        "k.id = ?2",
        rusqlite::params![account.0, id],
    )?
    .ok_or_else(|| corrupt("missing one-time key"))
}

/// Implements `OneTimeIvkRead::get_one_time_scanning_keys`, failing on a corrupt key.
pub(crate) fn scanning_keys<P: Parameters>(
    conn: &Connection,
    params: &P,
) -> Result<Vec<OneTimeScanningKey<AccountUuid>>, SqliteClientError> {
    keys_by_account(conn, params, |account| {
        let open = "k.active_from IS NOT NULL AND k.closed_at IS NULL";
        keys_where(conn, params, account, open, [account.0])
    })
}

/// The scanning keys `keys` returns for each account with an Orchard viewing key.
fn keys_by_account<P: Parameters>(
    conn: &Connection,
    params: &P,
    keys: impl Fn(AccountUuid) -> Result<Vec<OneTimeKey>, SqliteClientError>,
) -> Result<Vec<OneTimeScanningKey<AccountUuid>>, SqliteClientError> {
    let mut result = Vec::new();
    for (account, ufvk) in super::get_unified_full_viewing_keys(conn, params)? {
        if ufvk.orchard().is_some() {
            result.extend(keys(account)?.into_iter().map(|key| key.scanning_key));
        }
    }
    Ok(result)
}

/// Implements `OneTimeIvkRead::get_one_time_transaction_keys`: keys that may own outputs
/// of `txid`, which are those its stored notes or queued payments name, open keys active
/// by the next block (by `height` without a chain tip), and keys for `receivers`.
pub(crate) fn transaction_keys<P: Parameters>(
    conn: &Connection,
    params: &P,
    txid: zcash_primitives::transaction::TxId,
    height: Option<BlockHeight>,
    receivers: &[orchard::Address],
) -> Result<Vec<OneTimeScanningKey<AccountUuid>>, SqliteClientError> {
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
        "k.id IN (SELECT one_time_key_id FROM ironwood_received_notes
                WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?2)
            UNION SELECT one_time_key_id FROM ironwood_one_time_payment_recovery
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
) -> Result<OneTimeKey, SqliteClientError> {
    let scanning_key = OneTimeScanningKey::derive(account, stored_key_id(row)?, parent)?;
    check_receiver(row.get(2)?, scanning_key.full_viewing_key())?;
    Ok(OneTimeKey { scanning_key })
}

/// Checks a stored receiver against the one `fvk` derives, which also rejects a key
/// registered to another account.
fn check_receiver(stored: Vec<u8>, fvk: &FullViewingKey) -> Result<(), SqliteClientError> {
    if stored != fvk.address_at(0u32, Scope::External).to_raw_address_bytes() {
        return Err(corrupt(
            "stored one-time key receiver does not match its key",
        ));
    }
    Ok(())
}

/// The key identity of a registry row selecting purpose and key_index first.
fn stored_key_id(row: &rusqlite::Row<'_>) -> Result<KeyId, SqliteClientError> {
    let purpose = match row.get::<_, u8>(0)? {
        0 => Purpose::Refund,
        1 => Purpose::Receive,
        _ => return Err(corrupt("unsupported one-time key purpose")),
    };
    Ok(KeyId::new(purpose, decode_index(row.get(1)?)?))
}

/// `account`'s database reference and the Orchard FVK its one-time keys derive from.
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
                "one-time IVKs require an Orchard full viewing key".into(),
            )
        })?;
    Ok((account.id, fvk.clone()))
}

/// The registry ID of `account`'s key `key`.
fn key_ref(conn: &Connection, account: AccountUuid, key: KeyId) -> Result<i64, SqliteClientError> {
    conn.query_row(
        "SELECT k.id FROM ironwood_one_time_keys k JOIN accounts a ON a.id = k.account_id
         WHERE a.uuid = ?1 AND k.purpose = ?2 AND k.key_index = ?3",
        rusqlite::params![
            account.0,
            purpose_code(key.purpose())?,
            key.index().to_be_bytes()
        ],
        |r| r.get(0),
    )
    .optional()?
    .ok_or_else(|| invalid("unregistered one-time key"))
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

/// How a newly registered key's history is covered.
#[derive(Clone, Copy)]
enum Discovery {
    /// Trial-decrypt from `scan_from` until the key closes.
    Scan,
    /// Sweep the receiver directory once, unless the key is already scanned.
    Sweep,
    /// Wait for its funding transaction (see [`swap::start_funded_refund_keys`]).
    Funding,
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
) -> Result<(i64, OneTimeKey), SqliteClientError> {
    let (account_ref, parent) = account_key(conn, params, account)?;
    let scanning_key = OneTimeScanningKey::derive(account, key_id, &parent)?;
    let receiver = scanning_key
        .full_viewing_key()
        .address_at(0u32, Scope::External)
        .to_raw_address_bytes();
    // Repeated recovery can widen required history or promote a lookahead key. It must
    // never forget a reservation, narrow history, or replace a receiver.
    let (id, stored_from, active_from): (i64, u32, Option<u32>) = conn
        .query_row(
            "INSERT INTO ironwood_one_time_keys
             (account_id, purpose, key_index, receiver, scan_from, advances_allocation,
              registered_at)
         VALUES (:account, :purpose, :index, :receiver, :scan_from, :allocated, :now)
         ON CONFLICT (account_id, purpose, key_index) DO UPDATE SET
             scan_from = MIN(ironwood_one_time_keys.scan_from, excluded.scan_from),
             advances_allocation = MAX(
                 ironwood_one_time_keys.advances_allocation, excluded.advances_allocation)
         WHERE ironwood_one_time_keys.receiver = excluded.receiver
         RETURNING id, scan_from, active_from",
            named_params![
                ":account": account_ref.0,
                ":purpose": purpose_code(key_id.purpose())?,
                ":index": &key_id.index().to_be_bytes(),
                ":receiver": &receiver,
                ":scan_from": u32::from(scan_from),
                ":allocated": advances_allocation,
                ":now": now,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or_else(|| corrupt("stored one-time key receiver does not match its key"))?;
    match discovery {
        Discovery::Scan => {
            activate(conn, id, scan_from)?;
        }
        // Only a key scanned from its earliest possible payment needs no directory history.
        Discovery::Sweep if active_from.is_none_or(|start| start > stored_from) => {
            conn.execute(
                "INSERT OR IGNORE INTO ironwood_one_time_sweeps (one_time_key_id) VALUES (?1)",
                [id],
            )?;
        }
        Discovery::Sweep | Discovery::Funding => {}
    }
    Ok((id, OneTimeKey { scanning_key }))
}

/// Starts or extends trial decryption of key `id` from `from`, reopening a closed key and
/// requeuing blocks scanned without it, or returns false while its restore sweep is
/// pending.
fn activate(
    conn: &rusqlite::Transaction<'_>,
    id: i64,
    from: BlockHeight,
) -> Result<bool, SqliteClientError> {
    let (active_from, closed, pending): (Option<u32>, bool, bool) = conn.query_row(
        "SELECT k.active_from, k.closed_at IS NOT NULL,
                s.one_time_key_id IS NOT NULL AND s.done_height IS NULL
         FROM ironwood_one_time_keys k
         LEFT JOIN ironwood_one_time_sweeps s ON s.one_time_key_id = k.id
         WHERE k.id = ?1",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if active_from.is_none() && pending {
        return Ok(false);
    }
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
        "UPDATE ironwood_one_time_keys SET active_from = ?2, closed_at = NULL WHERE id = ?1",
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
         FROM ironwood_one_time_keys k JOIN accounts a ON a.id = k.account_id
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

/// Repairs one-time IVK state for a rewind that rescans every block above `height`: spend
/// evidence and replays above it go, and a sweep whose lookup or completion the rewind removed runs again. Active
/// keys need no repair, since the scanner rescans the truncated blocks with them. A
/// closed key that scanned reopens if the rewind leaves one of its receipts short of the
/// confirmations closing requires (see `WalletDb::close_finished_one_time_keys`), and
/// closes again once that receipt is confirmed again; a key a sweep closed without
/// scanning has nothing to rescan.
pub(crate) fn truncate_to_height(
    conn: &rusqlite::Transaction<'_>,
    height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let confirmed_below = u32::from(height)
        .saturating_add(1)
        .saturating_sub(ConfirmationsPolicy::default().untrusted().get());
    conn.execute(
        "UPDATE ironwood_one_time_spend_retention SET
            nullifier_retention_height = MIN(nullifier_retention_height, ?1 + 1),
            replay_through = MIN(replay_through, ?1)",
        [u32::from(height)],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_keys SET closed_at = NULL
         WHERE closed_at IS NOT NULL AND active_from IS NOT NULL AND id IN (
             SELECT n.one_time_key_id FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             WHERE t.mined_height > ?1)",
        [confirmed_below],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_sweeps SET done_height = NULL, next_attempt_at = 0,
            lookup_height = CASE WHEN lookup_height > ?1 THEN NULL ELSE lookup_height END,
            lookup_hash = CASE WHEN lookup_height > ?1 THEN NULL ELSE lookup_hash END
         WHERE done_height > ?1 OR lookup_height > ?1",
        [u32::from(height)],
    )?;
    conn.execute(
        "DELETE FROM ironwood_nullifier_scan_blocks WHERE height > ?1",
        [u32::from(height)],
    )?;
    conn.execute(
        "DELETE FROM ironwood_one_time_payment_recovery WHERE height > ?1",
        [u32::from(height)],
    )?;
    Ok(())
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
        "SELECT purpose, key_index, receiver FROM ironwood_one_time_keys WHERE id = ?1",
    )?;
    let mut rows = stmt.query([id])?;
    let row = rows
        .next()?
        .ok_or_else(|| corrupt("missing one-time note key"))?;
    let key_id = stored_key_id(row)?;
    let fvk = key_id.derive(parent)?;
    check_receiver(row.get(2)?, &fvk)?;
    Ok((key_id, fvk))
}

/// The key identity and recipient of a stored note that registered key `id` received at
/// `diversifier` under `scope`, re-derived from `ufvk`, its account's viewing key. Only
/// the key's receiver, at external scope, is a valid recipient.
pub(crate) fn note_recipient(
    conn: &Connection,
    id: i64,
    ufvk: &zcash_keys::keys::UnifiedFullViewingKey,
    scope: Scope,
    diversifier: orchard::keys::Diversifier,
) -> Result<(KeyId, orchard::Address), SqliteClientError> {
    let parent = ufvk
        .orchard()
        .ok_or_else(|| corrupt("missing one-time note account FVK"))?;
    let (key_id, fvk) = note_key(conn, id, parent)?;
    let recipient = fvk.to_ivk(scope).address(diversifier);
    if scope != Scope::External || recipient != fvk.address_at(0u32, Scope::External) {
        return Err(corrupt("invalid one-time-key note recipient"));
    }
    Ok((key_id, recipient))
}

/// The incoming key that decrypts queued one-time-key note `id` for Enhance. Any other
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
        .ok_or_else(|| corrupt("missing one-time note account FVK"))?;
    let (_, fvk) = note_key(conn, id, parent)?;
    let ivk = fvk.to_ivk(Scope::External);
    if scope != Scope::External || ivk.address(diversifier) != fvk.address_at(0u32, Scope::External)
    {
        return Err(corrupt("invalid queued one-time note recipient"));
    }
    Ok(ivk)
}

/// Validates an output's one-time key before it is stored, moving an Ironwood note found
/// here from a directory's claimed transaction (see [`adopt_found_note`]), and returns its
/// registry ID. A stored note keeps its key identity.
pub(super) fn received_note_key<
    P: Parameters,
    T: zcash_client_backend::data_api::ll::ReceivedOrchardOutput<AccountId = AccountUuid>,
>(
    conn: &Connection,
    params: &P,
    pool: zcash_protocol::ShieldedPool,
    output: &T,
    tx_ref: crate::TxRef,
) -> Result<Option<i64>, SqliteClientError> {
    let key = validate_received_key(conn, params, pool, output)?;
    if pool != zcash_protocol::ShieldedPool::Ironwood {
        return Ok(key);
    }
    if let Some(nf) = output.nullifier() {
        adopt_found_note(conn, &nf.to_bytes(), tx_ref, output.index())?;
    }
    let index = i64::try_from(output.index()).expect("output indices are representable as i64");
    let stored: Option<i64> = conn
        .query_row(
            "SELECT one_time_key_id FROM ironwood_received_notes
             WHERE transaction_id = ?1 AND action_index = ?2",
            rusqlite::params![tx_ref.0, index],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    if stored.is_some() && stored != key {
        return Err(corrupt("one-time-key note key identity changed"));
    }
    Ok(key)
}

/// Binds stored note `note` to registered key `key`, which makes the key's index used: it
/// advances allocation and is never issued again. This commits with the note, so a
/// restart cannot allocate the paid address again.
pub(super) fn bind_received_note(
    conn: &Connection,
    key: i64,
    note: i64,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_received_notes SET one_time_key_id = ?1 WHERE id = ?2",
        rusqlite::params![key, note],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_keys SET advances_allocation = 1, used = 1 WHERE id = ?1",
        [key],
    )?;
    Ok(())
}

/// Validates an output's one-time key before it is stored, returning its registry ID.
pub(super) fn validate_received_key<
    P: Parameters,
    T: zcash_client_backend::data_api::ll::ReceivedOrchardOutput<AccountId = AccountUuid>,
>(
    conn: &Connection,
    params: &P,
    pool: zcash_protocol::ShieldedPool,
    output: &T,
) -> Result<Option<i64>, SqliteClientError> {
    let Some(key_id) = output.one_time_key_id() else {
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
            "one-time-key note does not match its registered key",
        ));
    }
    Ok(Some(id))
}

/// Moves a stored Ironwood note with nullifier `nf` to `action_index` of `tx_ref`, where
/// it was just found, from the transaction a directory claimed for it, which is deleted
/// once nothing refers to it. Only the note itself was authenticated.
fn adopt_found_note(
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

/// The stored code of `purpose`, or an error for a purpose this store does not support.
fn purpose_code(purpose: Purpose) -> Result<u8, SqliteClientError> {
    match purpose {
        Purpose::Refund => Ok(0),
        Purpose::Receive => Ok(1),
        _ => Err(invalid("unsupported one-time key purpose")),
    }
}

/// Decodes a stored big-endian key index.
fn decode_index(bytes: Vec<u8>) -> Result<u64, SqliteClientError> {
    bytes
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| corrupt("invalid one-time key index"))
}

/// The index `by` after `index`. A purpose's index space never wraps back to zero.
fn index_after(index: u64, by: u64) -> Result<u64, SqliteClientError> {
    index
        .checked_add(by)
        .ok_or_else(|| invalid("one-time key index space is exhausted"))
}

/// A corrupted-data error with `message`.
fn corrupt(message: &str) -> SqliteClientError {
    SqliteClientError::CorruptedData(message.to_owned())
}

/// An invalid-input error with `message`.
fn invalid(message: &'static str) -> SqliteClientError {
    SqliteClientError::InvalidOneTimeIvkInput(message)
}

#[cfg(test)]
pub(crate) mod tests;
