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

    /// Asks the server what is unspent at the wallet's transparent addresses.
    ///
    /// This is the same request the recovery sweep makes, run on demand so that
    /// "no transparent funds" can be told apart from "not looked for".
    pub fn transparent_utxos(&self, account: u32) -> Result<Vec<(String, u64, u32)>, Error> {
        let addresses = self.transparent_addresses(account)?;
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        let from = self
            .accounts()?
            .into_iter()
            .find(|a| a.id == account)
            .map(|a| a.birthday)
            .unwrap_or_else(|| self.earliest_birthday());

        let url = self.config.lightwalletd_url.clone();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Source(format!("could not start a runtime: {e}")))?;

        runtime.block_on(async move {
            let source = zakura_wallet_lwd::LightwalletdSource::connect(&url).await?;
            let utxos = zakura_wallet_sync::ChainSource::address_utxos(
                &source,
                addresses,
                BlockHeight::from_u32(from),
            )
            .await
            .map_err(|e| Error::Source(e.to_string()))?;

            Ok(utxos
                .into_iter()
                .map(|u| (u.address, u.value, u32::from(u.height)))
                .collect())
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
