//! Running the synchronisation engine, and reporting what it is doing.
//!
//! Two constraints shape this module, and both come from the core rather than
//! from taste.
//!
//! The engine takes ownership of the database while it runs, so starting a sync
//! moves the writing handle out of the wallet and stopping it moves the handle
//! back. Queries go to the reading connection throughout.
//!
//! Detection uses rayon and the apply stage is a synchronous SQLite transaction
//! inside the engine's async step, with no `spawn_blocking` between them. On a
//! shared runtime that stalls a worker thread for the length of a batch, so the
//! engine gets a thread of its own with a current-thread runtime. It is not a
//! task that can be politely interleaved with anything.

use std::sync::Arc;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use zakura_wallet_lwd::LightwalletdSource;
use zakura_wallet_scan::{ScanKeys, TransparentWatch};
use zakura_wallet_store::WalletDb;
use zakura_wallet_sync::{ByteBudget, SyncConfig, SyncEngine};

use crate::{Wallet, error::Error};

/// What the engine is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPhase {
    /// Nothing has been scanned yet.
    Bootstrapping,
    /// Working backwards through history.
    Recovering,
    /// Following the chain tip.
    Tracking,
    /// Nothing left to scan right now.
    ///
    /// Not the same as "finished". An empty fetch also reports idle, so a
    /// transient failure to reach the server is indistinguishable from having
    /// caught up. An interface should keep the scanned height and the tip
    /// visible rather than presenting this as a settled result.
    Idle,
    /// The engine is not running.
    Stopped,
}

/// How far synchronisation has got.
///
/// Progress is note-commitment coverage rather than blocks scanned. Blocks are
/// a poor proxy: the empty stretches of the chain scan orders of magnitude
/// faster than the busy ones, so a block-count bar moves in lurches and lies
/// about how much time is left.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SyncProgress {
    /// What the engine is doing.
    pub phase: SyncPhase,
    /// Coverage of the whole wallet, between 0 and 1, if there is anything to
    /// measure yet.
    pub fraction: Option<f64>,
    /// The highest block the server reported.
    pub tip: Option<u32>,
    /// The highest block the wallet has scanned.
    pub scanned_to: Option<u32>,
    /// How many blocks remain queued.
    pub blocks_remaining: u64,
}

impl Default for SyncProgress {
    fn default() -> Self {
        Self {
            phase: SyncPhase::Stopped,
            fraction: None,
            tip: None,
            scanned_to: None,
            blocks_remaining: 0,
        }
    }
}

impl SyncProgress {
    fn from_status(status: &zakura_wallet_sync::SyncStatus) -> Self {
        // Coverage is per pool; the wallet wants one number. Summing the parts
        // rather than averaging the ratios keeps a pool with a large tree from
        // being outweighed by one with a small one.
        let (done, total) = status
            .per_pool
            .iter()
            .fold((0u64, 0u64), |(d, t), (_, ratio)| {
                (d + ratio.numerator, t + ratio.denominator)
            });

        Self {
            phase: match status.phase {
                zakura_wallet_sync::SyncPhase::Bootstrapping => SyncPhase::Bootstrapping,
                zakura_wallet_sync::SyncPhase::Recovering => SyncPhase::Recovering,
                zakura_wallet_sync::SyncPhase::Tracking => SyncPhase::Tracking,
                zakura_wallet_sync::SyncPhase::Idle => SyncPhase::Idle,
            },
            fraction: (total > 0).then(|| done as f64 / total as f64),
            tip: status.tip.map(u32::from),
            scanned_to: status.scanned_to.map(u32::from),
            blocks_remaining: status.blocks_remaining,
        }
    }
}

/// A running sync.
pub(crate) struct Session {
    cancel: CancellationToken,
    progress: watch::Receiver<SyncProgress>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Session {
    fn stop(mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.handle.take() {
            // Cancellation is checked between batches, and a batch is applied
            // in one transaction, so the worst this waits for is one batch and
            // there is never partially-applied state to reason about.
            let _ = handle.join();
        }
    }
}

impl Wallet {
    /// Starts synchronising, and returns immediately.
    ///
    /// The engine runs on its own thread until [`Wallet::stop_sync`] is called
    /// or it has nothing left to do. Progress is read with
    /// [`Wallet::progress`], which is a poll rather than a callback: the status
    /// channel is lossy by design, so a reader that falls behind sees the
    /// latest value instead of a queue of stale ones.
    pub fn start_sync(&self) -> Result<(), Error> {
        let mut session = self.session.lock().expect("the session lock is never poisoned");
        if session.is_some() {
            return Err(Error::AlreadySyncing);
        }

        let db = self
            .writer
            .lock()
            .expect("the writer lock is never poisoned")
            .take()
            .ok_or(Error::AlreadySyncing)?;

        // The scanner needs one prepared key set per account. Building it here
        // rather than in the engine keeps the engine free of the store's
        // account vocabulary.
        let keys = match self.scan_keys(&db) {
            Ok(keys) => keys,
            Err(e) => {
                *self.writer.lock().expect("the writer lock is never poisoned") = Some(db);
                return Err(e);
            }
        };

        let cancel = CancellationToken::new();
        let (tx, rx) = watch::channel(SyncProgress {
            phase: SyncPhase::Bootstrapping,
            ..SyncProgress::default()
        });

        let url = self.config.lightwalletd_url.clone();
        let params = self.params;
        let budget = ByteBudget::new(self.config.batch_bytes);
        let writer = Arc::clone(&self.writer);
        let token = cancel.clone();

        let handle = std::thread::Builder::new()
            .name("zakura-sync".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        *writer.lock().expect("the writer lock is never poisoned") = Some(db);
                        return;
                    }
                };

                let finish = tx.clone();
                let db = runtime.block_on(async move {
                    let source = match LightwalletdSource::connect(&url).await {
                        Ok(source) => source,
                        Err(_) => return db,
                    };

                    let mut engine = SyncEngine::new(
                        source,
                        params,
                        db,
                        keys,
                        TransparentWatch::default(),
                        SyncConfig {
                            budget,
                            ..SyncConfig::default()
                        },
                    );

                    let mut status = engine.status();
                    let publish = tx.clone();
                    // Republish the engine's own channel onto ours, so the
                    // application never sees the core's types.
                    let forward = tokio::spawn(async move {
                        while status.changed().await.is_ok() {
                            let next = SyncProgress::from_status(&status.borrow_and_update());
                            if publish.send(next).is_err() {
                                break;
                            }
                        }
                    });

                    if engine.update_tip().await.is_ok() {
                        let _ = engine.run(&token).await;
                    }

                    forward.abort();
                    engine.into_db()
                });

                let last = *finish.borrow();
                let _ = finish.send(SyncProgress {
                    phase: SyncPhase::Stopped,
                    ..last
                });
                *writer.lock().expect("the writer lock is never poisoned") = Some(db);
            })
            .map_err(|e| Error::Build(format!("could not start the sync thread: {e}")))?;

        *session = Some(Session {
            cancel,
            progress: rx,
            handle: Some(handle),
        });
        Ok(())
    }

    /// Stops synchronising, waiting for the batch in flight to finish.
    ///
    /// Safe to call when nothing is running.
    pub fn stop_sync(&self) {
        let session = self
            .session
            .lock()
            .expect("the session lock is never poisoned")
            .take();
        if let Some(session) = session {
            session.stop();
        }
    }

    /// Returns how far synchronisation has got.
    pub fn progress(&self) -> SyncProgress {
        self.session
            .lock()
            .expect("the session lock is never poisoned")
            .as_ref()
            .map(|s| *s.progress.borrow())
            .unwrap_or_default()
    }

    /// Returns whether a sync is running.
    pub fn is_syncing(&self) -> bool {
        self.session
            .lock()
            .expect("the session lock is never poisoned")
            .is_some()
    }

    fn scan_keys(&self, db: &WalletDb) -> Result<ScanKeys, Error> {
        let accounts = db.accounts(&self.params)?;
        let mut prepared = Vec::with_capacity(accounts.len());
        for account in &accounts {
            prepared.push((account.id, account.orchard_fvk()?.clone()));
        }
        Ok(ScanKeys::from_accounts(prepared))
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        // Dropping the engine is how a sync is cancelled, but the thread holds
        // the database, so leaving it running would outlive the wallet that
        // owns the files.
        let session = self
            .session
            .lock()
            .expect("the session lock is never poisoned")
            .take();
        if let Some(session) = session {
            session.stop();
        }
    }
}
