//! Reading what the wallet holds.
//!
//! These are the core's own queries with their types flattened into plain data.
//! The shapes are deliberately the same, because the core's are already the
//! right ones: a balance is three figures rather than one, and a history entry
//! says what a transaction did to this wallet rather than what it contained.

use zakura_wallet_core::{KeyScope, pool::PoolId};

use crate::{Wallet, error::Error};

/// What an account is worth, in zatoshis.
///
/// The three figures are the same funds at different stages of becoming
/// usable, and an interface that shows only one of them will mislead somebody.
/// `pending` in particular is real money that cannot yet be sent: presenting it
/// as spendable produces a wallet that offers funds and then refuses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Balance {
    /// Received, unspent, and with a witness a reorg can no longer invalidate.
    pub spendable: u64,
    /// Received and unspent, but not yet buried deeply enough to spend.
    pub pending: u64,
    /// Committed by a transaction that has not been mined yet.
    pub spent_unconfirmed: u64,
    /// Value held on transparent addresses.
    ///
    /// Kept apart from [`Balance::spendable`] because it cannot be sent
    /// directly: transparent funds have to be shielded first. Folding the two
    /// together would offer money the send path would then refuse.
    pub transparent: u64,
}

impl Balance {
    /// Returns everything the account holds, however it is held.
    ///
    /// Includes transparent value: it is the account's money, even though
    /// spending it takes an extra step.
    pub fn total(&self) -> u64 {
        self.spendable
            .saturating_add(self.pending)
            .saturating_add(self.transparent)
    }

    /// Returns the shielded value, which is what can be sent directly.
    pub fn shielded(&self) -> u64 {
        self.spendable.saturating_add(self.pending)
    }
}

/// Value, by where in the protocol it sat.
///
/// A total alone cannot answer what somebody actually wants to know about a
/// transaction — whether it was private, and if so in which pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PoolAmounts {
    /// Value in the Orchard pool.
    pub orchard: u64,
    /// Value in the Ironwood pool.
    pub ironwood: u64,
    /// Value on transparent addresses, which is to say in public.
    pub transparent: u64,
}

impl PoolAmounts {
    /// Returns the sum across every pool.
    pub fn total(&self) -> u64 {
        self.orchard
            .saturating_add(self.ironwood)
            .saturating_add(self.transparent)
    }

    /// Whether nothing moved anywhere.
    pub fn is_zero(&self) -> bool {
        self.total() == 0
    }
}

/// One transaction, as it affected the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// The transaction's identifier, as bytes.
    ///
    /// Displayed reversed by convention; that is a presentation decision and is
    /// left to whoever is displaying it.
    pub txid: [u8; 32],
    /// The height it was mined at, or `None` if it is still unmined.
    pub mined_height: Option<u32>,
    /// What the wallet received.
    pub received: u64,
    /// What the wallet spent.
    pub spent: u64,
    /// Whether everything received was change.
    ///
    /// A transaction that only returns change is the wallet paying somebody
    /// else, and showing it as an incoming payment would be wrong.
    pub is_change_only: bool,
    /// What the wallet received, by where it landed.
    pub received_by_pool: PoolAmounts,
    /// What the wallet spent, by where it came from.
    pub spent_by_pool: PoolAmounts,
    /// Value this transaction paid out to transparent addresses.
    ///
    /// Read from the transaction's own bytes, not from the wallet's notes. The
    /// wallet's side says only what it spent — that value left Ironwood — and
    /// not where it went, which may have been another shielded address or, as
    /// here, out into the open. Somebody reading their history needs to know
    /// which, and calling an unshielding "Ironwood" is the wallet keeping the
    /// most important part to itself.
    ///
    /// Zero when the wallet does not hold the transaction's bytes, which is the
    /// case for anything it had no reason to fetch.
    pub paid_to_transparent: u64,
}

impl HistoryEntry {
    /// Returns the transaction's net effect on the wallet, in zatoshis.
    ///
    /// Negative when the wallet paid out. The fee is included, because from the
    /// wallet's side a fee is indistinguishable from value that left.
    pub fn net(&self) -> i64 {
        self.received as i64 - self.spent as i64
    }
}

/// An account, as an interface needs to see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSummary {
    /// The wallet-local identifier.
    pub id: u32,
    /// The height below which this account has no history.
    pub birthday: u32,
    /// Whether the wallet can spend this account's notes.
    pub can_spend: bool,
    /// The ZIP 32 account index, for accounts derived from a seed.
    pub hd_account_index: Option<u32>,
}

impl Wallet {
    /// Confirms an account exists before reporting anything about it.
    ///
    /// The store's aggregates are sums over rows carrying an account
    /// identifier, so an identifier that names no account produces no rows and
    /// a balance of zero rather than an error. A zero balance for an account
    /// that does not exist is indistinguishable from a real one, which turns a
    /// caller's bug into a wallet that quietly shows nothing.
    fn require_account(&self, db: &zakura_wallet_store::WalletDb, account: u32) -> Result<(), Error> {
        db.account(self.params(), Self::account_id(account))?
            .map(|_| ())
            .ok_or(Error::NoSuchAccount(account))
    }

    /// Returns every account, in creation order.
    pub fn accounts(&self) -> Result<Vec<AccountSummary>, Error> {
        self.with_reader(|db| {
            Ok(db
                .accounts(self.params())?
                .into_iter()
                .map(|a| AccountSummary {
                    id: a.id.0,
                    birthday: a.birthday.into(),
                    can_spend: a.has_spend_key,
                    hd_account_index: a.hd_account_index,
                })
                .collect())
        })
    }

    /// Returns an account's balance across every shielded pool.
    ///
    /// Transparent value is not included, because this build cannot spend it
    /// and reporting a balance the wallet cannot back would be worse than
    /// reporting none.
    pub fn balance(&self, account: u32) -> Result<Balance, Error> {
        self.with_reader(|db| {
            self.require_account(db, account)?;
            let id = Self::account_id(account);
            let shielded = db.total_balance(id)?;
            let transparent = db.transparent_balance(id)?;
            Ok(Balance {
                spendable: shielded.spendable.into_u64(),
                pending: shielded.pending.into_u64(),
                spent_unconfirmed: shielded.spent_unconfirmed.into_u64(),
                // Only the settled part. Transparent value that is not yet
                // confirmed cannot be shielded either, so presenting it as held
                // would be the same mistake in a different pool.
                transparent: transparent.spendable.into_u64(),
            })
        })
    }

    /// Returns an account's balance in one pool.
    pub fn pool_balance(&self, account: u32, ironwood: bool) -> Result<Balance, Error> {
        let pool = if ironwood {
            PoolId::Ironwood
        } else {
            PoolId::Orchard
        };
        self.with_reader(|db| {
            self.require_account(db, account)?;
            let b = db.balance(Self::account_id(account), pool)?;
            Ok(Balance {
                spendable: b.spendable.into_u64(),
                pending: b.pending.into_u64(),
                spent_unconfirmed: b.spent_unconfirmed.into_u64(),
                transparent: 0,
            })
        })
    }

    /// Returns how many transparent addresses the wallet is watching for.
    ///
    /// Exposed because the number being zero is a silent failure rather than a
    /// visible one: the scanner matches the scripts the wallet has recorded, so
    /// a wallet watching nothing sees no transparent payments and reports no
    /// error while doing it.
    pub fn watched_transparent_addresses(&self) -> Result<usize, Error> {
        self.with_reader(|db| Ok(db.transparent_watch()?.addresses.len()))
    }

    /// Returns an account's transactions, most recent first.
    ///
    /// Unmined transactions sort above mined ones: they are the ones somebody
    /// is waiting on.
    pub fn history(&self, account: u32, limit: usize) -> Result<Vec<HistoryEntry>, Error> {
        let mut entries = self.history_from_notes(account, limit)?;

        // Fill in where an outgoing payment actually went. Only for the ones
        // that spent something — a receipt's destination is this wallet — and
        // only over the page being shown, so the cost is bounded by what is on
        // screen rather than by how long the history is.
        for entry in &mut entries {
            if entry.spent == 0 {
                continue;
            }
            if let Some(shape) = self.transaction_shape(&entry.txid)? {
                entry.paid_to_transparent = shape.transparent_out_value;
            }
        }
        Ok(entries)
    }

    fn history_from_notes(&self, account: u32, limit: usize) -> Result<Vec<HistoryEntry>, Error> {
        self.with_reader(|db| {
            self.require_account(db, account)?;
            Ok(db
                .history(Self::account_id(account), limit)?
                .into_iter()
                .map(|e| {
                    let pools = |a: zakura_wallet_store::PoolAmounts| PoolAmounts {
                        orchard: a.orchard.into_u64(),
                        ironwood: a.ironwood.into_u64(),
                        transparent: a.transparent.into_u64(),
                    };
                    HistoryEntry {
                        txid: *e.txid.as_ref(),
                        mined_height: e.mined_height.map(u32::from),
                        received: e.received.into_u64(),
                        spent: e.spent.into_u64(),
                        is_change_only: e.is_change_only,
                        received_by_pool: pools(e.received_by_pool),
                        spent_by_pool: pools(e.spent_by_pool),
                        paid_to_transparent: 0,
                    }
                })
                .collect::<Vec<_>>())
        })
    }

    /// Issues the next unused receive address for an account.
    ///
    /// Two calls return two different addresses. Reusing one lets anybody who
    /// has seen it link the payments made to it, which is a privacy loss the
    /// user never asked for and cannot undo.
    ///
    /// `exposed_at` is the height at which the address is being handed out, if
    /// known; it is what lets the wallet tell an address it has shown somebody
    /// from one it merely generated.
    pub fn next_address(&self, account: u32, exposed_at: Option<u32>) -> Result<String, Error> {
        let params = self.params;
        self.with_writer_pausing_sync(|db| {
            let (address, _index) = db.next_address(
                &params,
                Self::account_id(account),
                KeyScope::External,
                exposed_at.map(zcash_protocol::consensus::BlockHeight::from_u32),
            )?;
            Ok(address.encode(&params))
        })
    }
}
