//! The wallet-facing API over the Zakura wallet core.
//!
//! The core is six crates with a generic consensus parameter, six error types,
//! and a synchronisation engine that takes ownership of the database it drives.
//! That is the right shape for a library. It is the wrong shape for something
//! an application binds to across a foreign-function boundary, which needs one
//! object, one error, plain data, and no lifetimes.
//!
//! This crate is that shape. Every public signature takes and returns plain
//! values — zatoshis as `u64`, addresses as `String`, transaction identifiers
//! as `[u8; 32]` — so no `orchard` or `zcash_*` type ever crosses the boundary,
//! and changing one does not automatically change the application.
//!
//! # What it adds
//!
//! Four things the core deliberately leaves out, because they are only needed
//! once there is a user: seed phrases ([`mnemonic`]), turning a typed address
//! into a payable one ([`address`]), deriving spending keys from a seed
//! ([`keys`]), and the ordered sequence that turns "pay this person" into
//! broadcast bytes ([`send`]).
//!
//! # What it refuses
//!
//! A payment funded from the Orchard pool is necessarily a ZIP 318 crossing,
//! and a crossing has a canonical shape it has to be indistinguishable within.
//! This build cannot produce that shape on a wallet that has scanned a chain,
//! so rather than assemble one ad hoc — which would work, and would be
//! identifiable — [`Wallet::send`] refuses with
//! [`Error::CrossingUnavailable`]. See `docs/wallet_app.md`.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod address;
mod config;
mod error;
pub mod keys;
pub mod mnemonic;
mod query;
mod send;
mod sync;

pub use config::{NetworkKind, WalletConfig};
pub use error::{Error, ErrorCode};
pub use query::{AccountSummary, Balance, HistoryEntry};
pub use send::{SendReceipt, SpendQuote};
pub use sync::{SyncPhase, SyncProgress};

use std::sync::{Arc, Mutex};

use zakura_wallet_core::AccountId;
use zakura_wallet_store::WalletDb;
use zcash_protocol::consensus::{BlockHeight, Network};
use zeroize::Zeroizing;

/// An open wallet.
///
/// Holds two connections to the same pair of files. The synchronisation engine
/// takes ownership of a `WalletDb` while it runs, so a single handle would make
/// the interface unable to read a balance during a sync — which is precisely
/// when it most wants to. The store enables WAL for this reason, and the second
/// connection is the reader it was enabled for.
pub struct Wallet {
    config: WalletConfig,
    params: Network,
    /// The reader. Used for every query, and never moved.
    reader: Mutex<WalletDb>,
    /// The writer. Held here when idle, moved into the engine while syncing.
    writer: Arc<Mutex<Option<WalletDb>>>,
    session: Mutex<Option<sync::Session>>,
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The contents are somebody's transaction history; never render them.
        f.write_str("Wallet")
    }
}

impl Wallet {
    /// Opens the wallet described by `config`, creating it if it does not
    /// exist.
    ///
    /// Returns [`Error::VersionMismatch`] if a schema version does not match
    /// this build's, carrying the remedy. Nothing is destroyed here: deciding
    /// to rebuild the cache costs a rescan, which on a phone is a decision with
    /// a visible price, so it belongs to whoever can ask.
    pub fn open(config: WalletConfig) -> Result<Self, Error> {
        if let Some(dir) = config.wallet_path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| Error::Storage(format!("could not create {}: {e}", dir.display())))?;
        }
        let params = config.network.params();
        let writer = WalletDb::open(&config.wallet_path, &config.cache_path)?;
        let reader = WalletDb::open(&config.wallet_path, &config.cache_path)?;

        Ok(Self {
            config,
            params,
            reader: Mutex::new(reader),
            writer: Arc::new(Mutex::new(Some(writer))),
            session: Mutex::new(None),
        })
    }

    /// Returns the configuration the wallet was opened with.
    pub fn config(&self) -> &WalletConfig {
        &self.config
    }

    /// Creates an account from a seed, and returns its identifier.
    ///
    /// The seed is used and dropped: only the viewing key is stored, so the
    /// ability to spend does not sit in the same file as the ability to see.
    /// Whoever calls this owns the seed from then on, and should put it
    /// somewhere the operating system protects.
    ///
    /// `birthday` is the height below which this account has no history.
    /// Getting it wrong upwards loses transactions; getting it wrong downwards
    /// only costs scanning time.
    pub fn create_account(
        &self,
        seed: &Zeroizing<Vec<u8>>,
        account_index: u32,
        birthday: u32,
    ) -> Result<u32, Error> {
        let index = zip32::AccountId::try_from(account_index)
            .map_err(|_| Error::Build(format!("{account_index} is not a ZIP 32 account index")))?;

        self.with_writer(|db| {
            let id = db.create_account(
                &self.params,
                seed.as_slice(),
                index,
                BlockHeight::from_u32(birthday),
            )?;
            Ok(id.0)
        })
    }

    /// Runs `f` against the writing connection.
    ///
    /// Fails with [`Error::AlreadySyncing`] while the engine holds it. Writes
    /// that change what the scanner must look for — creating an account, or
    /// issuing an address — cannot be interleaved with a scan that is deciding
    /// what to look for, so refusing is the honest answer rather than blocking.
    fn with_writer<T>(&self, f: impl FnOnce(&mut WalletDb) -> Result<T, Error>) -> Result<T, Error> {
        let mut guard = self.writer.lock().expect("the writer lock is never poisoned");
        match guard.as_mut() {
            Some(db) => f(db),
            None => Err(Error::AlreadySyncing),
        }
    }

    /// Runs `f` against the reading connection.
    fn with_reader<T>(&self, f: impl FnOnce(&WalletDb) -> Result<T, Error>) -> Result<T, Error> {
        let guard = self.reader.lock().expect("the reader lock is never poisoned");
        f(&guard)
    }

    /// Returns the consensus parameters this wallet is using.
    pub(crate) fn params(&self) -> &Network {
        &self.params
    }

    pub(crate) fn account_id(id: u32) -> AccountId {
        AccountId(id)
    }
}
