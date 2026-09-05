//! Accounts, their keys, and the addresses they issue.
//!
//! An account is the durable half of a wallet: a viewing key, a birthday, and
//! the diversifier indices it has handed out. Everything else the wallet holds
//! is derived from those plus the chain, which is why these live in
//! `wallet.db` and survive a cache rebuild.
//!
//! Key derivation is ZIP 32 through `zcash_keys`. This wallet does not
//! reimplement unified key or address encoding: those are consensus-adjacent
//! formats where a subtle difference is an address nobody can pay.

use orchard::keys::{FullViewingKey, Scope};
use rusqlite::{OptionalExtension, named_params};
use zakura_wallet_core::{AccountId, KeyScope};
use zcash_keys::{
    address::UnifiedAddress,
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zip32::{AccountId as Zip32AccountId, DiversifierIndex, fingerprint::SeedFingerprint};

use crate::{error::Error, schema::CACHE_SCHEMA};

/// An account the wallet holds.
#[derive(Debug, Clone)]
pub struct Account {
    /// The wallet-local identifier.
    pub id: AccountId,
    /// The height below which this account has no history.
    pub birthday: BlockHeight,
    /// Whether the wallet can spend this account's notes.
    ///
    /// A watch-only account has a viewing key and no spending key; it can see
    /// everything and sign nothing.
    pub has_spend_key: bool,
    /// The ZIP 32 account index, for accounts derived from a seed.
    pub hd_account_index: Option<u32>,
    /// The account's unified full viewing key.
    pub ufvk: UnifiedFullViewingKey,
}

impl Account {
    /// Returns the Orchard viewing key, which also views Ironwood.
    ///
    /// Ironwood shares Orchard's keys entirely; an account without an Orchard
    /// key can see neither pool, and this wallet supports no others.
    pub fn orchard_fvk(&self) -> Result<&FullViewingKey, Error> {
        self.ufvk.orchard().ok_or_else(|| {
            Error::Serialization(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the account's viewing key covers no pool this wallet supports",
            ))
        })
    }
}

/// Creates an account derived from `seed` at ZIP 32 account index
/// `account_index`.
///
/// The seed is used and dropped; only the viewing key is stored. A wallet that
/// kept the seed would be storing the ability to spend in the same place as the
/// ability to see, and the two have very different exposure.
pub(crate) fn create<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    seed: &[u8],
    account_index: Zip32AccountId,
    birthday: BlockHeight,
) -> Result<AccountId, Error> {
    let usk = UnifiedSpendingKey::from_seed(params, seed, account_index).map_err(|e| {
        Error::Serialization(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("the seed does not derive a spending key: {e:?}"),
        ))
    })?;

    insert(
        conn,
        params,
        &usk.to_unified_full_viewing_key(),
        birthday,
        true,
        Some(SeedFingerprint::from_seed(seed).ok_or_else(|| {
            Error::Serialization(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a ZIP 32 seed must be at least 32 bytes",
            ))
        })?),
        Some(account_index.into()),
    )
}

/// Imports a watch-only account from a unified full viewing key.
pub(crate) fn import<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    ufvk: &UnifiedFullViewingKey,
    birthday: BlockHeight,
) -> Result<AccountId, Error> {
    insert(conn, params, ufvk, birthday, false, None, None)
}

fn insert<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    ufvk: &UnifiedFullViewingKey,
    birthday: BlockHeight,
    has_spend_key: bool,
    seed_fingerprint: Option<SeedFingerprint>,
    hd_account_index: Option<u32>,
) -> Result<AccountId, Error> {
    let encoded = ufvk.encode(params);
    let uivk = ufvk.to_unified_incoming_viewing_key().encode(params);

    // The incoming viewing key is the account's identity: two accounts with the
    // same one would see the same notes, and storing both would double every
    // balance.
    if conn
        .query_row(
            "SELECT 1 FROM accounts WHERE uivk = :uivk",
            named_params![":uivk": &uivk],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        return Err(Error::AccountExists);
    }

    conn.execute(
        "INSERT INTO accounts
            (uuid, ufvk, uivk, seed_fingerprint, hd_account_index,
             birthday_height, has_spend_key)
         VALUES (:uuid, :ufvk, :uivk, :fingerprint, :hd_index, :birthday, :has_spend_key)",
        named_params![
            ":uuid": &uuid_for(&uivk)[..],
            ":ufvk": &encoded,
            ":uivk": &uivk,
            ":fingerprint": seed_fingerprint.map(|f| f.to_bytes().to_vec()),
            ":hd_index": hd_account_index,
            ":birthday": u32::from(birthday),
            ":has_spend_key": has_spend_key,
        ],
    )?;

    Ok(AccountId(
        u32::try_from(conn.last_insert_rowid()).expect("account ids are assigned sequentially"),
    ))
}

/// Derives a stable identifier for an account from its viewing key.
///
/// Not random: an account restored from the same key in a rebuilt wallet should
/// carry the same identifier, so that anything referring to it by uuid still
/// refers to the same account.
fn uuid_for(uivk: &str) -> [u8; 16] {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut out = [0u8; 16];
    for (chunk, salt) in out.chunks_mut(8).zip(0u64..) {
        let mut hasher = DefaultHasher::new();
        salt.hash(&mut hasher);
        uivk.hash(&mut hasher);
        chunk.copy_from_slice(&hasher.finish().to_le_bytes());
    }
    out
}

/// Reads an account back.
pub(crate) fn get<P: Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    id: AccountId,
) -> Result<Option<Account>, Error> {
    conn.query_row(
        "SELECT ufvk, birthday_height, has_spend_key, hd_account_index
         FROM accounts WHERE id = :id",
        named_params![":id": id.0],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, Option<u32>>(3)?,
            ))
        },
    )
    .optional()?
    .map(|(ufvk, birthday, has_spend_key, hd_account_index)| {
        Ok(Account {
            id,
            birthday: BlockHeight::from_u32(birthday),
            has_spend_key,
            hd_account_index,
            ufvk: UnifiedFullViewingKey::decode(params, &ufvk).map_err(|e| {
                Error::Serialization(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("a stored viewing key could not be decoded: {e}"),
                ))
            })?,
        })
    })
    .transpose()
}

/// Returns every account, in creation order.
pub(crate) fn list<P: Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
) -> Result<Vec<Account>, Error> {
    let ids: Vec<u32> = conn
        .prepare("SELECT id FROM accounts ORDER BY id")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;

    ids.into_iter()
        .map(|id| {
            get(conn, params, AccountId(id))?.ok_or_else(|| {
                Error::Serialization(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "an account disappeared between listing and reading it",
                ))
            })
        })
        .collect()
}

/// Returns the earliest birthday across all accounts.
///
/// Scanning below it can produce nothing for any account, so it is the floor
/// for every range the wallet ever queues.
pub(crate) fn earliest_birthday(
    conn: &rusqlite::Connection,
) -> Result<Option<BlockHeight>, Error> {
    conn.query_row("SELECT MIN(birthday_height) FROM accounts", [], |row| {
        Ok(row.get::<_, Option<u32>>(0)?.map(BlockHeight::from))
    })
    .map_err(Error::Query)
}

/// Issues the next unused address for an account.
///
/// Addresses are handed out in diversifier order and recorded as they are, so
/// that the wallet knows which of its addresses have been exposed. Two calls
/// return two different addresses: reusing one would let anyone who has seen it
/// link the payments made to it.
pub(crate) fn next_address<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    id: AccountId,
    scope: KeyScope,
    exposed_at: Option<BlockHeight>,
) -> Result<(UnifiedAddress, DiversifierIndex), Error> {
    let account = get(conn, params, id)?.ok_or(Error::NoSuchAccount { id })?;

    let next: Option<Vec<u8>> = conn
        .query_row(
            &format!(
                "SELECT MAX(diversifier_index_be) FROM {CACHE_SCHEMA}.addresses
                 WHERE account_id = :account AND key_scope = :scope"
            ),
            named_params![":account": id.0, ":scope": scope.code()],
            |row| row.get(0),
        )
        .optional()?
        .flatten();

    let start = match next {
        None => DiversifierIndex::new(),
        Some(bytes) => {
            let mut index = decode_diversifier_index(&bytes)?;
            index.increment().map_err(|_| {
                Error::Serialization(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the account has exhausted its diversifier space",
                ))
            })?;
            index
        }
    };

    // Not every diversifier index yields a valid address, so the search moves
    // forward until one does rather than failing on the first gap.
    let (address, index) = account
        .ufvk
        .find_address(start, UnifiedAddressRequest::ORCHARD)
        .map_err(|e| {
            Error::Serialization(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("no address could be derived: {e:?}"),
            ))
        })?;

    conn.execute(
        &format!(
            "INSERT INTO {CACHE_SCHEMA}.addresses
                (account_id, key_scope, diversifier_index_be, unified_address, exposed_at_height)
             VALUES (:account, :scope, :index, :address, :exposed)
             ON CONFLICT (account_id, key_scope, diversifier_index_be) DO NOTHING"
        ),
        named_params![
            ":account": id.0,
            ":scope": scope.code(),
            ":index": encode_diversifier_index(index),
            ":address": address.encode(params),
            ":exposed": exposed_at.map(u32::from),
        ],
    )?;

    Ok((address, index))
}

/// Returns the Orchard address for an account's internal scope, which is where
/// change is paid.
pub(crate) fn change_address<P: Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    id: AccountId,
) -> Result<orchard::Address, Error> {
    let account = get(conn, params, id)?.ok_or(Error::NoSuchAccount { id })?;
    Ok(account.orchard_fvk()?.address_at(0u32, Scope::Internal))
}

/// Diversifier indices are stored big-endian so that ordering them as bytes
/// orders them as numbers, which is what the "next unused" query relies on.
fn encode_diversifier_index(index: DiversifierIndex) -> Vec<u8> {
    let mut bytes = *index.as_bytes();
    bytes.reverse();
    bytes.to_vec()
}

fn decode_diversifier_index(bytes: &[u8]) -> Result<DiversifierIndex, Error> {
    let mut le = <[u8; 11]>::try_from(bytes).map_err(|_| {
        Error::Serialization(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "a stored diversifier index was not 11 bytes",
        ))
    })?;
    le.reverse();
    Ok(DiversifierIndex::from(le))
}
