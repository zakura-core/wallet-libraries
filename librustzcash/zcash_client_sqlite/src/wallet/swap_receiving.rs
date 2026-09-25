//! Experimental durable swap receiving-key registration.
//!
//! Reserve before exposing an address, and persist the returned key ID with the
//! operation. Retries reuse that ID rather than reserving again. Registration
//! does not yet add these keys to block scanning or make their notes spendable.

use std::borrow::{Borrow, BorrowMut};

use orchard::keys::{FullViewingKey, Scope};
use rusqlite::{Connection, OptionalExtension, named_params};
use zcash_client_backend::data_api::Account as _;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use zakura_swap_receiving::DerivationError;
pub use zakura_swap_receiving::{KeyId, Purpose};

use crate::{AccountUuid, SqlTransaction, WalletDb, error::SqliteClientError};

/// An error reserving or reconstructing a receiving key.
#[derive(Debug)]
pub enum Error {
    /// Database, account, or stored-data validation failed.
    Wallet(SqliteClientError),
    /// No valid key was found in the KDF retry space.
    Derivation(DerivationError),
    /// This purpose's index space is exhausted. Never wrap back to zero.
    IndexExhausted,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wallet(e) => e.fmt(f),
            Self::Derivation(e) => e.fmt(f),
            Self::IndexExhausted => f.write_str("swap receiving index space exhausted"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wallet(e) => Some(e),
            Self::Derivation(e) => Some(e),
            Self::IndexExhausted => None,
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
    account: AccountUuid,
    key_id: KeyId,
    fvk: FullViewingKey,
    scan_from: BlockHeight,
    advances_allocation: bool,
}

impl RegisteredKey {
    /// The owning wallet account.
    pub fn account(&self) -> AccountUuid {
        self.account
    }
    /// The purpose/index identity to retain with operations and received notes.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }
    /// The derived FVK to use for note reconstruction and spending.
    pub fn full_viewing_key(&self) -> &FullViewingKey {
        &self.fvk
    }
    /// The receiver at external diversifier index zero.
    pub fn receiver(&self) -> orchard::Address {
        self.fvk.address_at(0u32, Scope::External)
    }
    /// Earliest requested scan height, inclusive. This is not scanned coverage.
    pub fn scan_from(&self) -> BlockHeight {
        self.scan_from
    }
    /// Whether reservation or recovery evidence puts subsequent allocations above this key.
    pub fn advances_allocation(&self) -> bool {
        self.advances_allocation
    }
}

impl<C: Borrow<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Reloads registered keys, including unpaid lookahead keys, for an account.
    ///
    /// Re-derivation must reproduce the stored receiver. Corrupt or unsupported
    /// registrations return an error, not a silently shortened recovery list.
    pub fn get_swap_receiving_keys(
        &self,
        account: AccountUuid,
    ) -> Result<Vec<RegisteredKey>, Error> {
        let conn = self.conn.borrow();
        let (account_ref, parent) = account_key(conn, &self.params, account)?;
        let mut stmt = conn.prepare_cached(
            "SELECT purpose, derivation_version, key_index, receiver, scan_from, advances_allocation
             FROM ironwood_receiving_keys WHERE account_id = :account
             ORDER BY purpose, key_index"
        )?;
        let mut rows = stmt.query(named_params![":account": account_ref.0])?;
        let mut keys = Vec::new();
        while let Some(row) = rows.next()? {
            let version: u8 = row.get(1)?;
            if version != 1 {
                return Err(corrupt("unsupported swap key derivation version"));
            }
            let purpose = match row.get::<_, u8>(0)? {
                0 => Purpose::Refund,
                1 => Purpose::Receive,
                _ => return Err(corrupt("unsupported swap key purpose")),
            };
            let key_id = KeyId::new(purpose, decode_index(row.get(2)?)?);
            let key = RegisteredKey {
                account,
                key_id,
                fvk: key_id.derive(&parent)?,
                scan_from: BlockHeight::from(row.get::<_, u32>(4)?),
                advances_allocation: row.get(5)?,
            };
            let receiver: Vec<u8> = row.get(3)?;
            if receiver != key.receiver().to_raw_address_bytes() {
                return Err(corrupt(
                    "stored swap receiver does not match its derived key",
                ));
            }
            keys.push(key);
        }
        Ok(keys)
    }
}

impl<C: BorrowMut<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Atomically reserves and registers the next index for this purpose.
    ///
    /// Only a committed result may be exposed. On a concurrent-write error,
    /// retry the whole operation. To also persist application operation state,
    /// call this on the wallet handle inside `transactionally_with_extension`.
    pub fn reserve_swap_receiving_key(
        &mut self,
        account: AccountUuid,
        purpose: Purpose,
        scan_from: BlockHeight,
    ) -> Result<RegisteredKey, Error> {
        self.transactionally(|wdb| wdb.reserve_swap_receiving_key(account, purpose, scan_from))
    }

    /// Registers a key backed by authenticated recovery evidence.
    ///
    /// For refunds the caller must validate its own funding memo. For incoming
    /// keys it must validate a payment, including one already spent. An empty
    /// directory result is not evidence. Repeated registration is idempotent.
    pub fn recover_swap_receiving_key(
        &mut self,
        account: AccountUuid,
        key_id: KeyId,
        scan_from: BlockHeight,
    ) -> Result<RegisteredKey, Error> {
        self.transactionally(|wdb| wdb.recover_swap_receiving_key(account, key_id, scan_from))
    }

    /// Registers an incoming lookahead key without advancing address allocation.
    pub fn watch_swap_receive_key(
        &mut self,
        account: AccountUuid,
        index: u64,
        scan_from: BlockHeight,
    ) -> Result<RegisteredKey, Error> {
        self.transactionally(|wdb| wdb.watch_swap_receive_key(account, index, scan_from))
    }
}

impl<P: Parameters, CL, R> WalletDb<SqlTransaction<'_>, P, CL, R> {
    /// Reserves in the enclosing transaction. Expose the address only after commit.
    pub fn reserve_swap_receiving_key(
        &mut self,
        account: AccountUuid,
        purpose: Purpose,
        scan_from: BlockHeight,
    ) -> Result<RegisteredKey, Error> {
        let (account_ref, _) = account_key(self.conn.0, &self.params, account)?;
        // SQLite orders fixed-width big-endian blobs numerically. Unlike INTEGER,
        // this represents the entire u64 index space, including u64::MAX.
        let last: Option<Vec<u8>> = self.conn.0.query_row(
            "SELECT MAX(key_index) FROM ironwood_receiving_keys
             WHERE account_id = :account AND purpose = :purpose
               AND derivation_version = 1 AND advances_allocation = 1",
            named_params![":account": account_ref.0, ":purpose": purpose_code(purpose)],
            |row| row.get(0),
        )?;
        let index = match last {
            Some(bytes) => decode_index(bytes)?
                .checked_add(1)
                .ok_or(Error::IndexExhausted)?,
            None => 0,
        };
        register(
            self.conn.0,
            &self.params,
            account,
            KeyId::new(purpose, index),
            scan_from,
            true,
        )
    }

    /// Records authenticated recovery evidence in the enclosing transaction.
    /// See [`WalletDb::recover_swap_receiving_key`] on a connection-backed handle.
    pub fn recover_swap_receiving_key(
        &mut self,
        account: AccountUuid,
        key_id: KeyId,
        scan_from: BlockHeight,
    ) -> Result<RegisteredKey, Error> {
        register(self.conn.0, &self.params, account, key_id, scan_from, true)
    }

    /// Watches an unpaid incoming index in the enclosing transaction.
    pub fn watch_swap_receive_key(
        &mut self,
        account: AccountUuid,
        index: u64,
        scan_from: BlockHeight,
    ) -> Result<RegisteredKey, Error> {
        register(
            self.conn.0,
            &self.params,
            account,
            KeyId::new(Purpose::Receive, index),
            scan_from,
            false,
        )
    }
}

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

fn register<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    key_id: KeyId,
    scan_from: BlockHeight,
    advances_allocation: bool,
) -> Result<RegisteredKey, Error> {
    let (account_ref, parent) = account_key(conn, params, account)?;
    let fvk = key_id.derive(&parent)?;
    let receiver = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
    // Repeated recovery can widen required history or promote a lookahead key.
    // It must never forget a reservation, narrow history, or replace a receiver.
    let updated: Option<(u32, bool)> = conn.query_row(
        "INSERT INTO ironwood_receiving_keys
             (account_id, purpose, derivation_version, key_index, receiver, scan_from, advances_allocation)
         VALUES (:account, :purpose, 1, :index, :receiver, :scan_from, :allocated)
         ON CONFLICT (account_id, purpose, derivation_version, key_index) DO UPDATE SET
             scan_from = MIN(ironwood_receiving_keys.scan_from, excluded.scan_from),
             advances_allocation = MAX(ironwood_receiving_keys.advances_allocation, excluded.advances_allocation)
         WHERE ironwood_receiving_keys.receiver = excluded.receiver
         RETURNING scan_from, advances_allocation",
        named_params![
            ":account": account_ref.0,
            ":purpose": purpose_code(key_id.purpose()),
            ":index": &key_id.index().to_be_bytes(),
            ":receiver": &receiver,
            ":scan_from": u32::from(scan_from),
            ":allocated": advances_allocation,
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    let (scan_from, advances_allocation) =
        updated.ok_or_else(|| corrupt("stored swap receiver does not match its derived key"))?;
    Ok(RegisteredKey {
        account,
        key_id,
        fvk,
        scan_from: scan_from.into(),
        advances_allocation,
    })
}

fn purpose_code(purpose: Purpose) -> u8 {
    match purpose {
        Purpose::Refund => 0,
        Purpose::Receive => 1,
    }
}

fn decode_index(bytes: Vec<u8>) -> Result<u64, Error> {
    bytes
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| corrupt("invalid swap key index"))
}

fn corrupt(message: &str) -> Error {
    SqliteClientError::CorruptedData(message.to_owned()).into()
}

#[cfg(test)]
mod tests;
