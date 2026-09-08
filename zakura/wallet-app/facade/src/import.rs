//! Bringing an existing wallet into this one, and choosing where to start
//! looking.
//!
//! A birthday is the height below which an account has no history. It is the
//! one number a restore can get catastrophically wrong: too high and the wallet
//! silently skips the blocks its money arrived in, showing a balance that is
//! simply missing funds, with nothing on screen to suggest anything is wrong.
//! Too low only costs scanning time.
//!
//! So the asymmetry is built into the API rather than left to whoever calls it.
//! An unknown birthday means [`Wallet::earliest_birthday`] — the height the
//! wallet's pools activated at, below which nothing can be its money — and not
//! a guess.

use zakura_wallet_core::pool::{Orchard, ShieldedPool};
use rusqlite::OptionalExtension;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::BlockHeight;
use zeroize::Zeroizing;

use crate::{Wallet, error::Error};

impl Wallet {
    /// Returns the earliest height an account on this network could have
    /// history at.
    ///
    /// The activation of the oldest pool this wallet supports. Restoring from
    /// here misses nothing and costs the most time, which is the right way
    /// round for somebody who does not know their birthday.
    pub fn earliest_birthday(&self) -> u32 {
        Orchard::activation_height(&self.params)
            .map(u32::from)
            // A network with no activation height for the pool cannot hold any
            // of its notes, so the floor is the genesis block.
            .unwrap_or(1)
    }

    /// Asks the server for the current chain tip.
    ///
    /// Used to give a brand-new wallet a birthday: an account created now has
    /// no history before now, so starting anywhere earlier only costs time.
    pub fn fetch_chain_tip(&self) -> Result<u32, Error> {
        let url = self.config.lightwalletd_url.clone();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Source(format!("could not start a runtime: {e}")))?;

        runtime.block_on(async move {
            let source = zakura_wallet_lwd::LightwalletdSource::connect(&url).await?;
            let tip = zakura_wallet_sync::ChainSource::tip(&source)
                .await
                .map_err(|e| Error::Source(e.to_string()))?;
            Ok(u32::from(tip.height))
        })
    }

    /// Creates a wallet that has no history, and returns its account.
    ///
    /// The birthday is the current chain tip, because an account that did not
    /// exist a moment ago cannot have been paid before then. If the server
    /// cannot be reached the earliest possible height is used instead: slower,
    /// and never wrong in the direction that loses money.
    pub fn create_wallet(&self, seed: &Zeroizing<Vec<u8>>) -> Result<u32, Error> {
        let birthday = self.fetch_chain_tip().unwrap_or_else(|_| self.earliest_birthday());
        self.create_account(seed, 0, birthday)
    }

    /// Restores an existing wallet from its seed.
    ///
    /// `birthday` is the height below which the wallet is known to have no
    /// history. Passing `None` means "not known", and scans from
    /// [`Wallet::earliest_birthday`] rather than guessing — a guess that is too
    /// high loses transactions, and does so silently.
    ///
    /// Fails with [`Error::AccountExists`] if this wallet is already here: two
    /// accounts sharing a viewing key would see the same notes and double every
    /// balance.
    pub fn import_wallet(
        &self,
        seed: &Zeroizing<Vec<u8>>,
        birthday: Option<u32>,
    ) -> Result<u32, Error> {
        self.create_account(seed, 0, birthday.unwrap_or_else(|| self.earliest_birthday()))
    }

    /// Returns the transparent addresses the wallet watches for an account,
    /// with whatever the server says is unspent at each.
    ///
    /// A diagnostic, and one worth having: transparent funds going unseen looks
    /// exactly like having none, so the only way to tell them apart is to ask
    /// what the wallet is actually looking for and what the server actually
    /// answers. A missing address here means the gap limit did not reach it.
    pub fn transparent_addresses(&self, account: u32) -> Result<Vec<String>, Error> {
        self.with_reader(|db| Ok(db.transparent_addresses(Self::account_id(account))?))
    }

    /// Returns what the private ledger holds for an account: address, value,
    /// and the height the output was mined at where that is known.
    ///
    /// It asks nobody. The whole point of the change this replaced is that a
    /// wallet no longer names its addresses to a server to find out what it
    /// holds, so a diagnostic that did would answer a question the wallet no
    /// longer asks. What it reports is what has been recovered, and
    /// [`Wallet::transparent_coverage`] says how far that reaches — which is
    /// the pair a person needs to tell "no transparent funds" from "not yet
    /// read that far".
    pub fn transparent_utxos(&self, account: u32) -> Result<Vec<(String, u64, Option<u32>)>, Error> {
        self.with_reader(|db| {
            Ok(db
                .transparent_utxos(Self::account_id(account))?
                .into_iter()
                .map(|(address, value, height)| (address, value, height.map(u32::from)))
                .collect())
        })
    }

    /// How far the private transparent ledger has read, and what still
    /// contradicts it.
    ///
    /// A transparent balance is true as of a height, and this is that height.
    /// `settled_through` rests on sealed shards alone; `covered_through` may
    /// reach further into a tail that can still be republished. An unresolved
    /// spend forbids calling the balance synchronized however current the
    /// coverage looks: it is an output still counted that something has
    /// already consumed.
    pub fn transparent_coverage(&self, account: u32) -> Result<TransparentCoverage, Error> {
        let birthday = self
            .accounts()?
            .into_iter()
            .find(|a| a.id == account)
            .map(|a| a.birthday)
            .unwrap_or_else(|| self.earliest_birthday());

        self.with_reader(|db| {
            let state =
                db.transparent_state(Self::account_id(account), BlockHeight::from_u32(birthday))?;
            Ok(TransparentCoverage {
                settled_through: state.settled_through.map(u32::from),
                covered_through: state.covered_through.map(u32::from),
                unresolved_spends: state.unresolved_spends,
                provisional_shards: state.provisional_shards,
            })
        })
    }

    /// Imports a watch-only account from a unified full viewing key.
    ///
    /// The result can see everything and sign nothing, which is what a viewing
    /// key is for. [`Wallet::send`] refuses it with [`Error::WatchOnly`].
    pub fn import_viewing_key(&self, ufvk: &str, birthday: Option<u32>) -> Result<u32, Error> {
        let params = self.params;
        let parsed = UnifiedFullViewingKey::decode(&params, ufvk)
            .map_err(|e| Error::BadViewingKey(e.to_string()))?;
        let birthday = birthday.unwrap_or_else(|| self.earliest_birthday());

        self.with_writer_pausing_sync(|db| {
            let id = db.import_account(&params, &parsed, BlockHeight::from_u32(birthday))?;
            // A watch-only account still needs transparent addresses derived,
            // or the scanner is not looking for its transparent receipts.
            Self::maintain_watch(db, &params, id)?;
            Ok(id.0)
        })
    }
}

/// How far the private transparent ledger has read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentCoverage {
    /// The last height covered by sealed shards alone.
    ///
    /// `None` when the account watches no transparent script, or when nothing
    /// has been read yet. Never reported as a height of zero: a wallet that
    /// could not ask and a wallet that read to genesis are different states.
    pub settled_through: Option<u32>,
    /// The last height covered, including any shard still growing.
    pub covered_through: Option<u32>,
    /// Spends the ledger could not resolve to an output it holds.
    pub unresolved_spends: u32,
    /// How many unsealed shard revisions the current coverage rests on.
    pub provisional_shards: u32,
}

/// What a transaction did, read from its own bytes.
///
/// The wallet's own side of a transaction says what it spent and what came
/// back, and that is not the same as what the transaction *was*: value spent
/// from Ironwood may have left to a transparent address, to another shielded
/// one, or back to the wallet. Only the bytes say which, and the wallet keeps
/// them for its own transactions.
pub struct TransactionShape {
    /// How many transparent inputs it spends.
    pub transparent_inputs: usize,
    /// How many transparent outputs it creates.
    pub transparent_outputs: usize,
    /// The total value of those outputs, which is value made public.
    pub transparent_out_value: u64,
    /// How many Orchard actions it carries.
    pub orchard_actions: usize,
    /// How many Ironwood actions it carries.
    pub ironwood_actions: usize,
    /// The Orchard bundle's value balance: positive when value leaves the pool.
    pub orchard_value_balance: i64,
    /// The Ironwood bundle's value balance.
    pub ironwood_value_balance: i64,
}

impl TransactionShape {
    /// Whether value was made public: shielded in, transparent out.
    pub fn is_unshielding(&self) -> bool {
        self.transparent_outputs > 0
            && (self.orchard_value_balance > 0 || self.ironwood_value_balance > 0)
    }

    /// Whether value was made private: transparent in, shielded out.
    pub fn is_shielding(&self) -> bool {
        self.transparent_inputs > 0
            && (self.orchard_value_balance < 0 || self.ironwood_value_balance < 0)
    }
}

impl Wallet {
    /// Returns what a transaction did, if the wallet kept its bytes.
    ///
    /// Only transactions the wallet has a reason to hold — its own, and those
    /// enhancement fetched — are here. Everything else returns `None` rather
    /// than a guess.
    pub fn transaction_shape(&self, txid: &[u8; 32]) -> Result<Option<TransactionShape>, Error> {
        let params = self.params;
        self.with_reader(|db| {
            let row: Option<(Vec<u8>, Option<u32>)> = db
                .connection()
                .query_row(
                    "SELECT r.bytes, t.mined_height
                     FROM main.raw_transactions r
                     LEFT JOIN cache.transactions t ON t.txid = r.txid
                     WHERE r.txid = ?1",
                    [&txid[..]],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|e| Error::Storage(e.to_string()))?;

            let Some((bytes, height)) = row else {
                return Ok(None);
            };

            let height = height
                .map(BlockHeight::from_u32)
                .or(db.chain_tip()?)
                .unwrap_or_else(|| BlockHeight::from_u32(self.earliest_birthday()));
            let branch = zcash_protocol::consensus::BranchId::for_height(&params, height);

            let tx = zcash_primitives::transaction::Transaction::read(&bytes[..], branch)
                .map_err(|e| Error::Build(format!("the stored transaction did not parse: {e}")))?;

            let transparent = tx.transparent_bundle();
            Ok(Some(TransactionShape {
                transparent_inputs: transparent.map_or(0, |b| b.vin.len()),
                transparent_outputs: transparent.map_or(0, |b| b.vout.len()),
                transparent_out_value: transparent.map_or(0, |b| {
                    b.vout.iter().map(|o| o.value.into_u64()).sum()
                }),
                orchard_actions: tx.orchard_bundle().map_or(0, |b| b.actions().len()),
                ironwood_actions: tx.ironwood_bundle().map_or(0, |b| b.actions().len()),
                orchard_value_balance: tx
                    .orchard_bundle()
                    .map_or(0, |b| (*b.value_balance()).into()),
                ironwood_value_balance: tx
                    .ironwood_bundle()
                    .map_or(0, |b| (*b.value_balance()).into()),
            }))
        })
    }
}
