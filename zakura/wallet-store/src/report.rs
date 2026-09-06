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
        // Not simply "is there a spend row": a spend by a transaction that can
        // no longer be mined does not hold anything, and the note it named must
        // come back. The spend row stays on record either way, which is why
        // this is a junction table and not a boolean column.
        let held = crate::status::held_by_live_spend();
        let spent_clause = if spent {
            format!("id IN ({held})")
        } else {
            format!("id NOT IN ({held})")
        };

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

/// Returns an account's transparent balance.
///
/// Transparent funds have no witness and no commitment tree, so there is
/// nothing to stabilise: an output is either confirmed or it is not. It is
/// still reported as three figures, because that is what the shielded pools
/// report and a caller adding them together should not have to know which
/// kind of funds it is looking at.
pub(crate) fn transparent_balance(
    conn: &rusqlite::Connection,
    account: AccountId,
    min_confirmations: u32,
    tip: Option<BlockHeight>,
) -> Result<Balance, Error> {
    let held = crate::status::held_by_live_spend_transparent();
    let confirmed_below = tip
        .map(|t| u32::from(t).saturating_sub(min_confirmations.saturating_sub(1)))
        .unwrap_or(0);

    let sum = |clause: &str| -> Result<Zatoshis, Error> {
        let total: i64 = conn.query_row(
            &format!(
                "SELECT COALESCE(SUM(o.value), 0)
                 FROM {CACHE_SCHEMA}.transparent_received_outputs o
                 JOIN {CACHE_SCHEMA}.transactions t ON t.id = o.transaction_id
                 WHERE o.account_id = :account AND {clause}"
            ),
            named_params![":account": account.0],
            |row| row.get(0),
        )?;
        Zatoshis::from_u64(total as u64).map_err(|_| {
            Error::Serialization(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the stored output values sum to an impossible balance",
            ))
        })
    };

    // Interpolated rather than bound: it is a height this function computed,
    // and binding it would mean every clause had to mention it whether or not
    // it needed it.
    let unspent = format!("o.id NOT IN ({held}) AND o.observed_spent_at_height IS NULL");

    Ok(Balance {
        // Buried deep enough that a reorg is not expected to take it back, and
        // not an immature coinbase. Unknown coinbase-ness counts as immature.
        spendable: sum(&format!(
            "{unspent} AND t.mined_height IS NOT NULL \
             AND t.mined_height <= {confirmed_below} AND o.is_coinbase IS 0"
        ))?,
        // Received but not yet usable: too recent, or a coinbase whose maturity
        // this wallet cannot establish.
        pending: sum(&format!(
            "{unspent} AND (t.mined_height IS NULL \
              OR t.mined_height > {confirmed_below} OR o.is_coinbase IS NOT 0)"
        ))?,
        spent_unconfirmed: sum(&format!(
            "o.id IN ({held}) AND t.mined_height IS NOT NULL \
             AND o.id IN (SELECT s.output_id
                          FROM {CACHE_SCHEMA}.transparent_received_output_spends s
                          JOIN {CACHE_SCHEMA}.transactions st ON st.id = s.transaction_id
                          WHERE st.mined_height IS NULL)"
        ))?,
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
         -- A transaction that only paid somebody, with no change coming back,
         -- touches no note of this wallet's and would otherwise be invisible in
         -- its own history. That shape is common once sends are recorded.
         WHERE received > 0 OR spent > 0
            OR EXISTS (SELECT 1 FROM main.sent_outputs so
                        WHERE so.txid = t.txid AND so.from_account_id = :account)
            OR EXISTS (SELECT 1 FROM {CACHE_SCHEMA}.transparent_received_outputs o
                        WHERE o.transaction_id = t.id AND o.account_id = :account)
         -- Unmined first, because those are what somebody is waiting on, and
         -- among them by the height they were built for: ordering by row id
         -- would show a queue of pending payments in an order with no meaning.
         ORDER BY t.mined_height IS NULL DESC,
                  COALESCE(t.mined_height, t.target_height) DESC,
                  t.id DESC
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

/// A transparent output the wallet can spend.
#[derive(Debug, Clone)]
pub struct SpendableUtxo {
    /// Which of the account's addresses holds it, for deriving the key.
    pub scope: zakura_wallet_core::KeyScope,
    /// The address index, the other half of the derivation path.
    pub index: u32,
    /// The stored address row.
    pub address_id: i64,
    /// The outpoint being spent.
    pub outpoint: transparent::bundle::OutPoint,
    /// The output itself, which the builder needs to check the script and the
    /// signer needs to compute the sighash.
    pub txout: transparent::bundle::TxOut,
}

/// Which of an account's transparent outputs a transaction may spend.
///
/// There is no "all addresses" default, and that is deliberate. Spending two
/// addresses in one transaction proves publicly and permanently that one person
/// holds both, so it is never something the wallet does without being asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentSpendPolicy {
    /// Every unspent output at one address.
    ///
    /// The addresses are already linked by having been paid at the same place,
    /// so this reveals nothing that was not already public.
    OneAddress(i64),
    /// Every unspent output the account holds, linking its addresses.
    AnyAddress,
}

/// Returns the transparent outputs an account can spend, largest first.
pub(crate) fn spendable_utxos(
    conn: &rusqlite::Connection,
    account: AccountId,
    policy: TransparentSpendPolicy,
    min_confirmations: u32,
    tip: BlockHeight,
) -> Result<Vec<SpendableUtxo>, Error> {
    let held = crate::status::held_by_live_spend_transparent();
    let confirmed_below = u32::from(tip).saturating_sub(min_confirmations.saturating_sub(1));
    // Interpolated rather than bound, because a bound parameter the statement
    // does not mention is an error in rusqlite — and the clause is absent
    // entirely when every address is in scope.
    let address_clause = match policy {
        TransparentSpendPolicy::OneAddress(id) => format!("AND o.address_id = {id}"),
        TransparentSpendPolicy::AnyAddress => String::new(),
    };

    let mut stmt = conn.prepare(&format!(
        "SELECT a.key_scope, a.transparent_child_index, o.address_id,
                t.txid, o.output_index, o.value, o.script
         FROM {CACHE_SCHEMA}.transparent_received_outputs o
         JOIN {CACHE_SCHEMA}.addresses a ON a.id = o.address_id
         JOIN {CACHE_SCHEMA}.transactions t ON t.id = o.transaction_id
         WHERE o.account_id = :account
           {address_clause}
           -- Mined and buried. There is no witness to stabilise here, so depth
           -- is the whole of the guarantee.
           AND t.mined_height IS NOT NULL
           AND t.mined_height <= {confirmed_below}
           -- Not already committed to a transaction that might still go
           -- through, and not observed missing by a sweep.
           AND o.id NOT IN ({held})
           AND o.observed_spent_at_height IS NULL
           -- Never an immature coinbase, and never one whose maturity the
           -- wallet cannot establish.
           AND o.is_coinbase IS 0
           -- Dust is not worth spending: an input costing more in fee than it
           -- carries makes the transaction worse, not better.
           AND o.value > {marginal}
           -- Deterministic, so two runs of the same wallet propose the same
           -- transaction.
         ORDER BY o.value DESC, t.txid, o.output_index",
        marginal = 5_000u64,
    ))?;

    let rows = stmt.query_map(
        named_params![":account": account.0],
        |row| {
            Ok((
                row.get::<_, u8>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, u32>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        },
    )?;

    let mut out = Vec::new();
    for row in rows {
        let (scope, index, address_id, txid, output_index, value, script) = row?;
        let scope = zakura_wallet_core::KeyScope::from_code(scope)
            .ok_or_else(|| Error::Corrupt(format!("unknown key scope {scope}")))?;
        let hash: [u8; 32] = txid
            .try_into()
            .map_err(|_| Error::Corrupt("a stored txid was not 32 bytes".into()))?;
        let value = Zatoshis::from_u64(value as u64)
            .map_err(|_| Error::Corrupt("a stored output value is out of range".into()))?;

        out.push(SpendableUtxo {
            scope,
            index,
            address_id,
            outpoint: transparent::bundle::OutPoint::new(hash, output_index),
            txout: transparent::bundle::TxOut::new(
                value,
                transparent::address::Script(zcash_script::script::Code(script)),
            ),
        });
    }
    Ok(out)
}
