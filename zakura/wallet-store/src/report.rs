//! Balance and transaction history.
//!
//! The design deletes all fifteen of the fork's SQL views on the grounds that
//! an aggregation which can be tested and profiled is worth more than one
//! embedded in a 225-line view. This is that aggregation. It is deliberately
//! plain SQL over the same tables, with the interpretation — what counts as
//! spendable, what a transaction did to the wallet — done here where it can be
//! read.

use rusqlite::named_params;
use zakura_wallet_core::{AccountId, pool::PoolId};
use zcash_protocol::{TxId, consensus::BlockHeight, value::Zatoshis};

use crate::{error::Error, schema::CACHE_SCHEMA};

/// What an account is worth.
///
/// The three figures are not alternatives; they are the same funds at different
/// stages of becoming usable, and a wallet that shows only one of them will
/// confuse somebody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balance {
    /// Value that can be spent right now: received, unspent, and with a witness
    /// a reorg can no longer invalidate.
    pub spendable: Zatoshis,
    /// Value received and unspent whose witness is not yet stable.
    ///
    /// Real money, not yet usable. Showing it as spendable produces a wallet
    /// that offers funds and then refuses to send them.
    pub pending: Zatoshis,
    /// Value the wallet has spent in a transaction that is not yet mined.
    pub spent_unconfirmed: Zatoshis,
}

impl Default for Balance {
    fn default() -> Self {
        Self {
            spendable: Zatoshis::ZERO,
            pending: Zatoshis::ZERO,
            spent_unconfirmed: Zatoshis::ZERO,
        }
    }
}

impl Balance {
    /// Returns everything the account holds, usable or not.
    pub fn total(&self) -> Zatoshis {
        (self.spendable + self.pending).expect("a wallet's balance fits in a Zatoshis")
    }
}

/// Returns an account's balance in one pool.
pub(crate) fn pool_balance(
    conn: &rusqlite::Connection,
    account: AccountId,
    pool: PoolId,
) -> Result<Balance, Error> {
    let sum = |stable: Option<bool>, spent: bool| -> Result<Zatoshis, Error> {
        let spent_clause = if spent {
            "id IN (SELECT received_note_id FROM {schema}.received_note_spends)"
        } else {
            "id NOT IN (SELECT received_note_id FROM {schema}.received_note_spends)"
        }
        .replace("{schema}", CACHE_SCHEMA);

        let stable_clause = match stable {
            Some(true) => "AND witness_stabilized = 1",
            Some(false) => "AND witness_stabilized = 0",
            None => "",
        };

        let total: i64 = conn.query_row(
            &format!(
                "SELECT COALESCE(SUM(value), 0) FROM {CACHE_SCHEMA}.received_notes
                 WHERE account_id = :account AND pool = :pool
                   AND {spent_clause} {stable_clause}"
            ),
            named_params![":account": account.0, ":pool": pool.code()],
            |row| row.get(0),
        )?;

        Zatoshis::from_u64(total as u64).map_err(|_| {
            Error::Serialization(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the stored note values sum to an impossible balance",
            ))
        })
    };

    Ok(Balance {
        spendable: sum(Some(true), false)?,
        pending: sum(Some(false), false)?,
        // A note spent by a transaction with no mined height is committed but
        // not yet confirmed; the funds are gone from the user's point of view
        // and not yet gone from the chain's.
        spent_unconfirmed: unconfirmed_spends(conn, account, pool)?,
    })
}

fn unconfirmed_spends(
    conn: &rusqlite::Connection,
    account: AccountId,
    pool: PoolId,
) -> Result<Zatoshis, Error> {
    let total: i64 = conn.query_row(
        &format!(
            "SELECT COALESCE(SUM(n.value), 0)
             FROM {CACHE_SCHEMA}.received_notes n
             JOIN {CACHE_SCHEMA}.received_note_spends s ON s.received_note_id = n.id
             JOIN {CACHE_SCHEMA}.transactions t ON t.id = s.transaction_id
             WHERE n.account_id = :account AND n.pool = :pool AND t.mined_height IS NULL"
        ),
        named_params![":account": account.0, ":pool": pool.code()],
        |row| row.get(0),
    )?;
    Zatoshis::from_u64(total as u64).map_err(|_| {
        Error::Serialization(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the stored note values sum to an impossible balance",
        ))
    })
}

/// One transaction, as it affected the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// The transaction's identifier.
    pub txid: TxId,
    /// The height it was mined at, if it has been.
    pub mined_height: Option<BlockHeight>,
    /// What the wallet received.
    pub received: Zatoshis,
    /// What the wallet spent.
    pub spent: Zatoshis,
    /// Whether everything received was change.
    ///
    /// A transaction that only returns change is the wallet paying somebody
    /// else, and presenting it as an incoming payment would be wrong.
    pub is_change_only: bool,
}

impl HistoryEntry {
    /// Returns the transaction's net effect on the wallet, in zatoshis.
    ///
    /// Negative when the wallet paid out; the fee is included, because from the
    /// wallet's side a fee is indistinguishable from value that left.
    pub fn net(&self) -> i64 {
        self.received.into_u64() as i64 - self.spent.into_u64() as i64
    }
}

/// Returns an account's transactions, most recent first.
///
/// Unmined transactions sort above mined ones: they are the ones a user is
/// waiting on.
pub(crate) fn history(
    conn: &rusqlite::Connection,
    account: AccountId,
    limit: usize,
) -> Result<Vec<HistoryEntry>, Error> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT t.txid,
                t.mined_height,
                COALESCE((
                    SELECT SUM(n.value) FROM {CACHE_SCHEMA}.received_notes n
                    WHERE n.transaction_id = t.id AND n.account_id = :account
                ), 0) AS received,
                COALESCE((
                    SELECT SUM(n.value)
                    FROM {CACHE_SCHEMA}.received_note_spends s
                    JOIN {CACHE_SCHEMA}.received_notes n ON n.id = s.received_note_id
                    WHERE s.transaction_id = t.id AND n.account_id = :account
                ), 0) AS spent,
                COALESCE((
                    SELECT MIN(n.is_change) FROM {CACHE_SCHEMA}.received_notes n
                    WHERE n.transaction_id = t.id AND n.account_id = :account
                ), 1) AS all_change
         FROM {CACHE_SCHEMA}.transactions t
         WHERE received > 0 OR spent > 0
         ORDER BY t.mined_height IS NULL DESC, t.mined_height DESC, t.id DESC
         LIMIT :limit"
    ))?;

    let mut rows = stmt.query(named_params![":account": account.0, ":limit": limit])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let txid = <[u8; 32]>::try_from(&row.get::<_, Vec<u8>>(0)?[..]).map_err(|_| {
            Error::Serialization(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "a stored txid was not 32 bytes",
            ))
        })?;
        let received = row.get::<_, i64>(2)? as u64;
        out.push(HistoryEntry {
            txid: TxId::from_bytes(txid),
            mined_height: row.get::<_, Option<u32>>(1)?.map(BlockHeight::from),
            received: Zatoshis::const_from_u64(received),
            spent: Zatoshis::const_from_u64(row.get::<_, i64>(3)? as u64),
            // Only meaningful when something was received.
            is_change_only: received > 0 && row.get::<_, bool>(4)?,
        });
    }
    Ok(out)
}
