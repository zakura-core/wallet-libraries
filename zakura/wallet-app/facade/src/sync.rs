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

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

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
    /// Whether the last attempt ended in a failure rather than a finish.
    ///
    /// Without this, an unreachable server is indistinguishable from having
    /// caught up: both leave the engine stopped with nothing queued. Somebody
    /// looking at a wallet that says it is up to date, when in fact it has not
    /// spoken to a server in an hour, is being told something false about their
    /// own money.
    pub failed: bool,
}

impl Default for SyncProgress {
    fn default() -> Self {
        Self {
            phase: SyncPhase::Stopped,
            fraction: None,
            tip: None,
            scanned_to: None,
            blocks_remaining: 0,
            failed: false,
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
            failed: false,
        }
    }
}

/// Drives an engine until it is cancelled or cannot continue.
///
/// Returns the reason it stopped, or `None` if it was cancelled.
///
/// Extracted from the thread so it can be driven against any [`ChainSource`],
/// including the in-memory one. The two mistakes it exists to not make are both
/// easy to make and invisible once made: stopping at the tip, and treating a
/// stall as having caught up.
pub(crate) async fn drive<S, P>(
    engine: &mut SyncEngine<S, P>,
    token: &CancellationToken,
    poll_interval: std::time::Duration,
) -> Option<String>
where
    // The same bounds the engine itself carries: a fetch runs on its own task
    // while the batch before it is applied.
    S: zakura_wallet_sync::ChainSource + Send + Sync + 'static,
    P: zcash_protocol::consensus::Parameters + Clone + Send + 'static,
{
    loop {
        if token.is_cancelled() {
            return None;
        }

        match engine.run(token).await {
            Ok(summary) if summary.cancelled => return None,
            Ok(summary) => {
                // Stalled is not caught up. Work is still queued and the source
                // would not serve it, and the engine is explicit that a caller
                // has to be able to tell the two apart.
                if let Some(range) = summary.stalled {
                    return Some(format!(
                        "the server would not serve blocks {} to {}",
                        u32::from(range.start),
                        u32::from(range.end),
                    ));
                }
            }
            Err(e) => return Some(e.to_string()),
        }

        // Caught up. Wait for the chain to move rather than spinning on a tip
        // that is not going to change for another minute or so. Without this
        // loop a wallet syncs once and then goes deaf to every block that
        // follows, including the one carrying somebody's payment.
        tokio::select! {
            _ = tokio::time::sleep(poll_interval) => {}
            _ = token.cancelled() => return None,
        }
    }
}

/// A running sync.
pub(crate) struct Session {
    cancel: CancellationToken,
    progress: watch::Receiver<SyncProgress>,
    handle: Option<std::thread::JoinHandle<()>>,
    /// Set by the thread as it exits.
    ///
    /// A sync ends on its own as soon as there is nothing left to scan, which
    /// in ordinary use is most of the time. Without this the session would look
    /// live forever after the first one finished, and no second sync could ever
    /// be started.
    finished: Arc<AtomicBool>,
}

impl Session {
    fn is_running(&self) -> bool {
        !self.finished.load(Ordering::SeqCst)
    }

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

        // A sync that has run to completion leaves its session behind. Reap it
        // rather than refusing: reaching the tip is the ordinary outcome, and a
        // wallet that could only ever sync once would be useless.
        if session.as_ref().is_some_and(|s| !s.is_running()) {
            if let Some(finished) = session.take() {
                finished.stop();
            }
        }
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
        // account vocabulary, and means an account created since the last sync
        // is picked up by this one.
        let keys = match self.scan_keys(&db) {
            Ok(keys) => keys,
            Err(e) => {
                *self.writer.lock().expect("the writer lock is never poisoned") = Some(db);
                return Err(e);
            }
        };

        *self.failure.lock().expect("the failure lock is never poisoned") = None;

        let cancel = CancellationToken::new();
        let (tx, rx) = watch::channel(SyncProgress {
            phase: SyncPhase::Bootstrapping,
            ..SyncProgress::default()
        });

        let url = self.config.lightwalletd_url.clone();
        let params = self.params;
        let budget = ByteBudget::new(self.config.batch_bytes);
        let poll_interval = self.config.poll_interval;
        let writer = Arc::clone(&self.writer);
        let failure = Arc::clone(&self.failure);
        let finished = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&finished);
        let token = cancel.clone();

        let handle = std::thread::Builder::new()
            .name("zakura-sync".to_owned())
            .spawn(move || {
                let record = |e: String| {
                    *failure.lock().expect("the failure lock is never poisoned") = Some(e);
                };

                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(e) => {
                        record(format!("could not start the sync runtime: {e}"));
                        *writer.lock().expect("the writer lock is never poisoned") = Some(db);
                        done.store(true, Ordering::SeqCst);
                        let _ = tx.send(SyncProgress {
                            phase: SyncPhase::Stopped,
                            failed: true,
                            ..SyncProgress::default()
                        });
                        return;
                    }
                };

                let publish_final = tx.clone();
                let db = runtime.block_on(async move {
                    let source = match LightwalletdSource::connect(&url).await {
                        Ok(source) => source,
                        Err(e) => {
                            record(format!("could not reach {url}: {e}"));
                            return db;
                        }
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

                    if let Some(reason) = drive(&mut engine, &token, poll_interval).await {
                        record(reason);
                    }

                    forward.abort();
                    engine.into_db()
                });

                *writer.lock().expect("the writer lock is never poisoned") = Some(db);
                done.store(true, Ordering::SeqCst);

                let last = *publish_final.borrow();
                let _ = publish_final.send(SyncProgress {
                    phase: SyncPhase::Stopped,
                    failed: failure
                        .lock()
                        .expect("the failure lock is never poisoned")
                        .is_some(),
                    ..last
                });
            })
            .map_err(|e| Error::Build(format!("could not start the sync thread: {e}")))?;

        *session = Some(Session {
            cancel,
            progress: rx,
            handle: Some(handle),
            finished,
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
        let mut progress = self
            .session
            .lock()
            .expect("the session lock is never poisoned")
            .as_ref()
            .map(|s| *s.progress.borrow())
            .unwrap_or_default();

        // The failure outlives the session, so that reaping a finished sync
        // does not quietly turn a server that could not be reached into a
        // wallet that looks up to date.
        progress.failed = self
            .failure
            .lock()
            .expect("the failure lock is never poisoned")
            .is_some();
        progress
    }

    /// Returns why the last sync stopped, if it stopped because of a failure.
    ///
    /// Cleared when a new sync starts. The message is for a log or a details
    /// pane; [`SyncProgress::failed`] is what an interface branches on.
    pub fn sync_failure(&self) -> Option<String> {
        self.failure
            .lock()
            .expect("the failure lock is never poisoned")
            .clone()
    }

    /// Returns whether a sync is running right now.
    ///
    /// False once the engine has run out of work, even though the session has
    /// not been stopped: reaching the tip is a finish, not a pause.
    pub fn is_syncing(&self) -> bool {
        self.session
            .lock()
            .expect("the session lock is never poisoned")
            .as_ref()
            .is_some_and(|s| s.is_running())
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use zakura_wallet_core::{KeyScope, pool::PoolId};
    use zakura_wallet_scan::{
        ScanKeys,
        testing::{ChainBuilder, IRONWOOD_ACTIVATION, test_params},
    };
    use zakura_wallet_store::testing::test_db;
    use zakura_wallet_sync::testing::InMemoryChain;
    use zcash_protocol::consensus::BlockHeight;

    use super::*;

    const START: u32 = IRONWOOD_ACTIVATION + 10;

    /// An engine over an in-memory chain carrying one note, and the account it
    /// was paid to.
    ///
    /// Account identifiers are assigned by the store and do not start at zero,
    /// so the caller is handed the one it got rather than guessing.
    fn engine() -> (
        SyncEngine<InMemoryChain, zcash_protocol::local_consensus::LocalNetwork>,
        zakura_wallet_core::AccountId,
    ) {
        let mut db = test_db().unwrap();
        let id = db
            .create_account(
                &test_params(),
                &[3u8; 32],
                zip32::AccountId::try_from(0).unwrap(),
                BlockHeight::from_u32(START),
            )
            .unwrap();
        let fvk = db
            .account(&test_params(), id)
            .unwrap()
            .unwrap()
            .orchard_fvk()
            .unwrap()
            .clone();

        let mut chain = ChainBuilder::new(START);
        chain.block(|b| {
            b.tx(|t| {
                t.receive(PoolId::Ironwood, &fvk, KeyScope::External, 100_000);
            });
        });
        chain.empty_blocks(3);

        let engine = SyncEngine::new(
            InMemoryChain::new(chain.anchor(), chain.blocks().to_vec()),
            test_params(),
            db,
            ScanKeys::from_accounts([(id, fvk)]),
            TransparentWatch::default(),
            SyncConfig::default(),
        );
        (engine, id)
    }

    /// The defect this exists for: `run` returns the moment there is nothing
    /// queued, so a single call syncs once and then goes deaf to every block
    /// that follows. Timed rather than spawned, because the engine owns a
    /// SQLite connection and so is not `Send` — which is also why the real
    /// thread drives it with `block_on` rather than a task.
    #[tokio::test]
    async fn it_keeps_following_the_chain_after_catching_up() {
        let (mut engine, _) = engine();
        let token = CancellationToken::new();

        let canceller = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
            canceller.cancel();
        });

        let started = std::time::Instant::now();
        let reason = drive(&mut engine, &token, Duration::from_millis(20)).await;
        let elapsed = started.elapsed();

        assert_eq!(reason, None, "cancelling is not a failure");
        assert!(
            elapsed >= Duration::from_millis(200),
            "it stopped at the tip after {elapsed:?} instead of waiting to be cancelled",
        );
    }

    /// And it stops promptly when asked, rather than sitting out the poll
    /// interval first.
    #[tokio::test]
    async fn cancelling_ends_it_without_waiting_for_the_next_poll() {
        let (mut engine, _) = engine();
        let token = CancellationToken::new();

        let canceller = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            canceller.cancel();
        });

        let started = std::time::Instant::now();
        drive(&mut engine, &token, Duration::from_secs(30)).await;

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "it waited out a thirty-second poll instead of cancelling",
        );
    }

    /// Cancelling before the first pass does nothing and reports nothing.
    #[tokio::test]
    async fn cancelling_first_is_not_a_failure() {
        let (mut engine, _) = engine();
        let token = CancellationToken::new();
        token.cancel();

        assert_eq!(
            drive(&mut engine, &token, Duration::from_millis(20)).await,
            None
        );
    }

    /// And the wallet really did scan, which is what makes the test above about
    /// tracking rather than about an engine that never started.
    #[tokio::test]
    async fn it_scans_before_it_starts_waiting() {
        let (mut engine, account) = engine();
        let token = CancellationToken::new();

        let canceller = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
            canceller.cancel();
        });
        drive(&mut engine, &token, Duration::from_millis(20)).await;

        let db = engine.into_db();
        let balance = db.total_balance(account).expect("the account is there");
        assert_eq!(balance.total().into_u64(), 100_000, "the note was not found");
    }
}
