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
//! Paying an arbitrary amount out of the Orchard pool. Value leaves Orchard only
//! as a ZIP 318 crossing, and every crossing carries one of a fixed set of
//! denominations so that they cannot be told apart; an amount that is not one of
//! them is refused with [`Error::NotCanonicalDenomination`] rather than adjusted
//! to fit. See `docs/wallet_app.md`.
//!

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod address;
mod config;
mod import;
mod error;
pub mod keys;
pub mod mnemonic;
mod query;
mod send;
mod sync;

pub use config::{NetworkKind, WalletConfig};
pub use import::TransactionShape;
pub use error::{Error, ErrorCode};
pub use query::{AccountSummary, Balance, HistoryEntry, PoolAmounts};
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
    /// Why the last sync stopped, when it stopped because of a failure.
    failure: Arc<Mutex<Option<String>>>,
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
            failure: Arc::new(Mutex::new(None)),
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

        self.with_writer_pausing_sync(|db| {
            let id = db.create_account(
                &self.params,
                seed.as_slice(),
                index,
                BlockHeight::from_u32(birthday),
            )?;

            // Derive the transparent addresses the account will be watched on.
            // The scanner matches the scripts the wallet has recorded, so an
            // address that was never derived is one nothing is looking for, and
            // a payment to it goes unseen.
            Self::maintain_watch(db, &self.params, id)?;

            Ok(id.0)
        })
    }

    /// Runs `f` against the writing connection, pausing any sync around it.
    ///
    /// The engine takes ownership of the writing handle while it runs, so
    /// everything that writes — creating an account, issuing an address,
    /// reading the anchors a spend needs — would otherwise be refused for as
    /// long as the wallet was synchronising, which in ordinary use is most of
    /// the time. A wallet that cannot be paid into or spent from while it is
    /// catching up is not a wallet.
    ///
    /// Stopping is cheap by construction: a batch is applied in one
    /// transaction that also marks the scan queue, so cancelling discards
    /// nothing and resuming is re-reading the queue. Restarting also rebuilds
    /// the scanner's key set, which is what makes an account created here
    /// visible to the sync that follows.
    ///
    /// The sync is stopped *before* the writer lock is taken. Holding it across
    /// the join would deadlock: the thread needs that same lock to hand the
    /// database back.
    pub(crate) fn with_writer_pausing_sync<T>(
        &self,
        f: impl FnOnce(&mut WalletDb) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let was_syncing = self.is_syncing();
        if was_syncing {
            self.stop_sync();
        }

        let result = self.with_writer(f);

        if was_syncing {
            // A failure to resume is recorded where a failure to sync is
            // recorded, rather than replacing the caller's result: whatever
            // they asked for either happened or did not, and that is the
            // answer they need.
            let _ = self.start_sync();
        }
        result
    }

    /// Runs `f` against the writing connection.
    ///
    /// Fails with [`Error::AlreadySyncing`] if the engine holds it. Callers
    /// that need to write while a sync may be running want
    /// [`Wallet::with_writer_pausing_sync`].
    pub(crate) fn with_writer<T>(
        &self,
        f: impl FnOnce(&mut WalletDb) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut guard = self.writer.lock().expect("the writer lock is never poisoned");
        match guard.as_mut() {
            Some(db) => f(db),
            None => Err(Error::AlreadySyncing),
        }
    }

    /// Runs `f` against the reading connection.
    pub(crate) fn with_reader<T>(&self, f: impl FnOnce(&WalletDb) -> Result<T, Error>) -> Result<T, Error> {
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

    /// Keeps an account's window of watched transparent addresses full.
    ///
    /// The window is consumed by an address being *paid*, not by one being
    /// issued, so it goes stale as a result of scanning rather than of anything
    /// the interface does. It is topped up when an account is created and again
    /// whenever a sync starts, which is the point at which what was found last
    /// time has been applied.
    ///
    /// A window that runs out is a silent failure: the scanner keeps matching
    /// the addresses it knows and simply never sees a payment to one it does
    /// not.
    pub(crate) fn maintain_watch(
        db: &mut WalletDb,
        params: &Network,
        account: AccountId,
    ) -> Result<(), Error> {
        db.maintain_transparent_addresses(
            params,
            account,
            &zakura_wallet_store::GapLimits::default(),
        )?;
        Ok(())
    }
}
