//! Derived receiver registry, payment authentication and spending.
//! Ordinary scanning uses account keys. PIR recovery authenticates individual returned
//! payments with these derived keys and retains their ownership for later spending.

pub(crate) mod journal;
pub(crate) mod restore;
pub mod swap;

use std::{ops::Range, time::UNIX_EPOCH};

use orchard::keys::{FullViewingKey, Scope};
use rusqlite::{Connection, OptionalExtension};
use zcash_client_backend::data_api::{
    Account as _,
    scanning::{ScanPriority, ScanRange},
};
use zcash_protocol::consensus::{BlockHeight, Parameters};

pub use zakura_one_time_ivk::{KeyId, Purpose};

use crate::{AccountUuid, error::SqliteClientError, util::Clock};

/// A registered key, re-derived from its account's viewing key. It holds viewing
/// material, so it deliberately does not implement `Debug`.
pub struct OneTimeKey {
    key_id: KeyId,
    fvk: FullViewingKey,
}

impl OneTimeKey {
    /// The key's purpose and index.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The derived FVK, for note reconstruction and spending.
    pub fn full_viewing_key(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// The receiver at external diversifier index zero.
    pub fn receiver(&self) -> orchard::Address {
        self.full_viewing_key().address_at(0u32, Scope::External)
    }
}

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
        keys.push(registered_key(row, &parent)?);
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

/// The key of a registry row selecting purpose, key_index and receiver, checked.
fn registered_key(
    row: &rusqlite::Row<'_>,
    parent: &FullViewingKey,
) -> Result<OneTimeKey, SqliteClientError> {
    let key_id = stored_key_id(row)?;
    let fvk = key_id.derive(parent)?;
    check_receiver(row.get(2)?, &fvk)?;
    Ok(OneTimeKey { key_id, fvk })
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

/// `account`'s database reference, or `None` when it has no Orchard full viewing key, so
/// one-time IVKs never apply to it. Reads and pausing treat such an account as disabled;
/// calls that issue keys use [`account_key`], which refuses it.
fn one_time_account<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
) -> Result<Option<super::AccountRef>, SqliteClientError> {
    let account =
        super::get_account(conn, params, account)?.ok_or(SqliteClientError::AccountUnknown)?;
    Ok(account
        .ufvk()
        .and_then(|key| key.orchard())
        .map(|_| account.id))
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

/// Registers a deterministic receiver without activating any scanner or changing paid state.
fn register<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    key_id: KeyId,
) -> Result<(i64, OneTimeKey), SqliteClientError> {
    let (owner, parent) = account_key(conn, params, account)?;
    restore::queue::ensure_account(conn, owner.0)?;
    let fvk = key_id.derive(&parent)?;
    let receiver = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO ironwood_one_time_keys
        (account_id, purpose, key_index, receiver) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            owner.0,
            purpose_code(key_id.purpose())?,
            key_id.index().to_be_bytes(),
            receiver
        ],
    )?;
    let id = key_ref(conn, account, key_id)?;
    let stored: Vec<u8> = conn.query_row(
        "SELECT receiver FROM ironwood_one_time_keys WHERE id = ?1",
        [id],
        |r| r.get(0),
    )?;
    check_receiver(stored, &fvk)?;
    if inserted != 0 {
        conn.execute("UPDATE ironwood_one_time_recovery SET generation = generation + 1 WHERE account_id = ?1", [owner.0])?;
        if key_id.purpose() == Purpose::Receive {
            restore::queue::register_history(
                conn,
                owner.0,
                id,
                restore::queue::activation(params),
            )?;
        }
    }
    Ok((id, OneTimeKey { key_id, fvk }))
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

/// Validates an output's one-time key before it is stored and returns its registry ID.
/// A stored note keeps its key identity.
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

/// Binds stored note `note` to registered key `key` and marks the key used, committing
/// with the note so a restart cannot reserve the paid address again. Use alone does not
/// widen issuance: the receive window follows payments mined on the current chain,
/// and reorg repair can retire use evidence a replacement history no longer holds.
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
        "UPDATE ironwood_one_time_keys SET used = 1 WHERE id = ?1",
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
