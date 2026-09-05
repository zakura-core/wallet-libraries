//! The synchronisation engine.
//!
//! The engine is a loop over one invariant: **a batch is fetched, detected and
//! applied as one unit, and the scan queue is updated inside the same database
//! transaction that stores its data.** Everything else follows from that.
//! Cancelling is dropping the engine. Resuming is reading the queue. There is
//! no checkpoint file, no cursor, and no partially-applied state to reconcile,
//! because the only record of what has been scanned is written atomically with
//! the thing it describes.
//!
//! Work is driven by [`SyncEngine::step`], which advances by exactly one batch
//! and says what it did. [`SyncEngine::run`] is a loop over it. Exposing the
//! single step is what makes the engine testable at the granularity its
//! failures occur at — a reorg, a cancellation, a budget boundary.

use std::ops::Range;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use zakura_wallet_core::{
    BlockAnchor,
    pool::PoolId,
    scanning::{ScanPriority, ScanRange},
};
use zakura_wallet_scan::{
    NullifierSnapshot, ScanError, ScanKeys, TransparentWatch, detect_batch,
};
use zakura_wallet_store::{PRUNING_DEPTH, WalletDb};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::{
    error::Error,
    progress::{Ratio, SyncPhase, SyncStatus},
    source::{ByteBudget, ChainSource, Direction, SourceError, estimated_size},
};

/// Returns which end of a range to fetch, given what the range is for.
///
/// Recovery works backwards, from the tip towards the birthday, because
/// spendable value concentrates near the tip and Ironwood exists only there: a
/// restoring user sees their current balance long before the whole history has
/// been downloaded. Tip-following works forwards, because there the next block
/// is the one that matters and there is nothing below it left to find.
pub fn direction_for(priority: ScanPriority) -> Direction {
    match priority {
        ScanPriority::ChainTip | ScanPriority::Verify => Direction::Ascending,
        _ => Direction::Descending,
    }
}

/// How far the engine rewinds on the first continuity failure.
///
/// Doubling from here on repeated failure, capped at [`PRUNING_DEPTH`]. The
/// depth is engine policy on purpose: the fork leaves it to the caller, and
/// every caller gets it wrong, because choosing it correctly requires knowing
/// how checkpoints are retained.
const INITIAL_REWIND: u32 = 10;

/// How many subtree roots to ask for at a time.
///
/// Each is a hash and a height, so a large batch is cheap; the limit exists so
/// that a wallet far behind does not ask for the whole chain's worth in one
/// message.
const SUBTREE_ROOT_BATCH: u32 = 1_024;

/// How the engine is configured.
#[derive(Debug, Clone, Copy)]
pub struct SyncConfig {
    /// How much block data may be held in memory at once.
    pub budget: ByteBudget,
    /// The lowest priority worth scanning.
    ///
    /// Ranges below this are left alone, which is how a caller asks for "just
    /// catch up to the tip" rather than a full recovery.
    pub min_priority: ScanPriority,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            budget: ByteBudget::MOBILE,
            min_priority: ScanPriority::Historic,
        }
    }
}

/// What one call to [`SyncEngine::step`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A batch was scanned and applied.
    Scanned {
        /// The heights covered.
        range: Range<BlockHeight>,
        /// How many notes belonging to the wallet it contained.
        notes: usize,
    },
    /// A continuity failure was found and the wallet was rewound.
    ///
    /// The discarded range is back in the queue, so the next step re-fetches it.
    Rewound {
        /// The height the wallet was rewound to.
        to: BlockHeight,
        /// What triggered the rewind.
        cause: ScanError,
    },
    /// There is nothing left to scan.
    Idle,
    /// The engine was asked to stop.
    Cancelled,
}

/// Drives synchronisation of one wallet against one chain source.
pub struct SyncEngine<S, P> {
    source: S,
    params: P,
    db: WalletDb,
    keys: ScanKeys,
    watch_set: TransparentWatch,
    config: SyncConfig,
    status: watch::Sender<SyncStatus>,
    /// How far the *next* rewind will go, doubling after each one.
    rewind_depth: u32,
    timings: Timings,
}

impl<S: ChainSource, P: Parameters> SyncEngine<S, P> {
    /// Builds an engine over an open wallet.
    pub fn new(
        source: S,
        params: P,
        db: WalletDb,
        keys: ScanKeys,
        watch_set: TransparentWatch,
        config: SyncConfig,
    ) -> Self {
        Self {
            source,
            params,
            db,
            keys,
            watch_set,
            config,
            status: watch::Sender::new(SyncStatus::default()),
            rewind_depth: INITIAL_REWIND,
            timings: Timings::default(),
        }
    }

    /// Returns a receiver for progress updates.
    pub fn status(&self) -> watch::Receiver<SyncStatus> {
        self.status.subscribe()
    }

    /// Returns where the engine's time has gone so far.
    pub fn timings(&self) -> Timings {
        self.timings
    }

    /// Returns the chain source this engine reads from.
    pub fn source(&self) -> &S {
        &self.source
    }

    /// Returns the wallet this engine is driving.
    pub fn db(&self) -> &WalletDb {
        &self.db
    }

    /// Returns the wallet this engine is driving, mutably.
    pub fn db_mut(&mut self) -> &mut WalletDb {
        &mut self.db
    }

    /// Consumes the engine, returning the wallet.
    pub fn into_db(self) -> WalletDb {
        self.db
    }

    /// Asks the source for the tip and reconciles the queue with it.
    pub async fn update_tip(&mut self) -> Result<BlockHeight, Error> {
        let tip = self.source.tip().await.map_err(SourceError::new).map_err(Error::Source)?;
        self.db.update_chain_tip(&self.params, tip.height)?;
        self.publish(Some(tip.height))?;
        Ok(tip.height)
    }

    /// Advances by one batch.
    ///
    /// Returns without doing anything if `cancel` has been triggered; the
    /// check happens between batches only, which is safe precisely because a
    /// batch is atomic.
    pub async fn step(&mut self, cancel: &CancellationToken) -> Result<Step, Error> {
        if cancel.is_cancelled() {
            return Ok(Step::Cancelled);
        }

        let Some(range) = self.next_range()? else {
            self.publish(None)?;
            return Ok(Step::Idle);
        };

        // Recovery works backwards and tip-following works forwards, so which
        // end of the range is fetched is decided by what the range is *for*.
        // The anchor therefore cannot be resolved until the blocks are in hand:
        // it belongs to whichever block turned out to be lowest.
        let direction = direction_for(range.priority());

        let fetch_began = std::time::Instant::now();
        let blocks = self
            .source
            .fetch(range.block_range().clone(), self.config.budget, direction)
            .await
            .map_err(SourceError::new)
            .map_err(Error::Source)?;
        self.timings.fetch += fetch_began.elapsed();

        if blocks.is_empty() {
            // The source has nothing for this range. Treat it as scanned rather
            // than spinning on it: a range the source cannot serve will not
            // become servable by asking again immediately.
            return Ok(Step::Idle);
        }

        debug_assert!(
            blocks.iter().map(estimated_size).sum::<usize>() <= self.config.budget.bytes()
                || blocks.len() == 1,
            "the source must honour the byte budget, except for a single oversized block",
        );
        debug_assert!(
            blocks.windows(2).all(|w| w[1].height == w[0].height + 1),
            "the source must return a contiguous, ascending run whichever end it took",
        );

        let anchor = self.resolve_anchor(blocks[0].height).await?;

        let nullifiers = self.load_nullifiers()?;
        let detect_began = std::time::Instant::now();
        let detected = detect_batch(
            &self.params,
            &self.keys,
            &self.watch_set,
            &nullifiers,
            &anchor,
            &blocks,
        );
        self.timings.detect += detect_began.elapsed();

        match detected {
            Ok(batch) => {
                let covered = batch.blocks[0].height..(batch.end_anchor.height + 1);
                let notes = batch.received_notes().count();
                let apply_began = std::time::Instant::now();
                self.db.put_batch(&self.params, &batch)?;
                self.timings.apply += apply_began.elapsed();
                // A clean batch means the chain is where we thought it was, so
                // the next failure starts from a shallow rewind again.
                self.rewind_depth = INITIAL_REWIND;
                self.publish(None)?;
                Ok(Step::Scanned {
                    range: covered,
                    notes,
                })
            }
            Err(cause) if cause.is_continuity_error() => {
                let to = self.rewind(&cause)?;
                self.publish(None)?;
                Ok(Step::Rewound { to, cause })
            }
            Err(cause) => Err(Error::Unrecoverable {
                cause,
                rewound_by: 0,
            }),
        }
    }

    /// Downloads any subtree roots the wallet does not yet hold.
    ///
    /// Without these a note found near the tip cannot be witnessed until every
    /// shard beneath it has been scanned, which would make descending recovery
    /// pointless: the balance would appear and remain unspendable. A root is
    /// orders of magnitude cheaper than the shard it summarises.
    pub async fn update_subtree_roots(&mut self) -> Result<usize, Error> {
        let mut total = 0;
        for pool in PoolId::ALL {
            let start = self.db.next_subtree_index(pool)?;
            let roots = self
                .source
                .subtree_roots(pool, start, SUBTREE_ROOT_BATCH)
                .await
                .map_err(SourceError::new)
                .map_err(Error::Source)?;

            if roots.is_empty() {
                continue;
            }

            // The server may know of shards beyond the wallet's next index but
            // not at it; inserting out of order would leave a hole the tree
            // cannot be walked across.
            let contiguous: Vec<_> = roots
                .iter()
                .enumerate()
                .take_while(|(offset, root)| root.index == start + *offset as u64)
                .map(|(_, root)| zakura_wallet_store::SubtreeRoot {
                    end_height: root.end_height,
                    root: root.root,
                })
                .collect();

            total += contiguous.len();
            self.db.put_subtree_roots(pool, start, &contiguous)?;
        }
        Ok(total)
    }

    /// Runs until there is nothing left to scan, or until cancelled.
    ///
    /// Returns how many batches were applied and how many rewinds happened.
    pub async fn run(&mut self, cancel: &CancellationToken) -> Result<SyncSummary, Error> {
        self.update_tip().await?;
        // Before scanning, not after: a note found in the first batch needs the
        // roots of the shards around it in order to be witnessable at all.
        self.update_subtree_roots().await?;

        let mut summary = SyncSummary::default();
        loop {
            match self.step(cancel).await? {
                Step::Scanned { notes, .. } => {
                    summary.batches += 1;
                    summary.notes += notes;
                }
                Step::Rewound { .. } => summary.rewinds += 1,
                Step::Idle => return Ok(summary),
                Step::Cancelled => {
                    summary.cancelled = true;
                    return Ok(summary);
                }
            }
        }
    }

    /// Returns the most urgent range still to scan.
    fn next_range(&self) -> Result<Option<ScanRange>, Error> {
        Ok(self
            .db
            .suggest_scan_ranges(self.config.min_priority)?
            .into_iter()
            .find(|r| !r.is_empty() && r.priority() != ScanPriority::Scanned))
    }

    /// Finds the chain state the block below `start` left the trees in.
    ///
    /// Prefers the wallet's own record, because that is what the trees were
    /// actually built from; falls back to the source for a range that does not
    /// continue from anything scanned, which under descending recovery is most
    /// of them.
    async fn resolve_anchor(&self, start: BlockHeight) -> Result<BlockAnchor, Error> {
        if start == BlockHeight::from_u32(0) {
            return Err(Error::MissingAnchor { height: start });
        }
        let below = start - 1;

        if let Some(anchor) = self.db.block_anchor(below)? {
            return Ok(anchor);
        }

        self.source
            .anchor(below)
            .await
            .map_err(SourceError::new)
            .map_err(Error::Source)
    }

    /// Loads the wallet's unspent nullifiers.
    fn load_nullifiers(&self) -> Result<NullifierSnapshot, Error> {
        Ok(self.db.unspent_nullifiers()?)
    }

    /// Rewinds after a continuity failure, deepening on repeated failures.
    fn rewind(&mut self, cause: &ScanError) -> Result<BlockHeight, Error> {
        let depth = self.rewind_depth;
        if depth > PRUNING_DEPTH as u32 {
            // Beyond the checkpoint window there is nothing to rewind to, so
            // recovery is a rescan from the birthday. That is a decision with a
            // visible cost, so it belongs to the caller.
            return Err(Error::Unrecoverable {
                cause: cause.clone(),
                rewound_by: depth,
            });
        }

        let target = cause.at_height().saturating_sub(depth);
        let floor = self.db.birthday()?.map(|b| b.saturating_sub(1));
        let target = match floor {
            Some(floor) if target < floor => floor,
            _ => target,
        };

        self.db.truncate_to(target)?;
        self.rewind_depth = depth.saturating_mul(2);
        Ok(target)
    }

    /// Publishes a progress snapshot.
    fn publish(&self, tip: Option<BlockHeight>) -> Result<(), Error> {
        let scanned_to = self.db.block_height_extrema()?.map(|(_, hi)| hi);
        let remaining: u64 = self
            .db
            .suggest_scan_ranges(self.config.min_priority)?
            .iter()
            .filter(|r| r.priority() != ScanPriority::Scanned)
            .map(|r| r.len() as u64)
            .sum();

        let previous = self.status.borrow().clone();
        let tip = tip.or(previous.tip);

        let phase = if remaining == 0 {
            SyncPhase::Idle
        } else if scanned_to.is_none() {
            SyncPhase::Bootstrapping
        } else if matches!((scanned_to, tip), (Some(s), Some(t)) if u32::from(t) - u32::from(s) < PRUNING_DEPTH as u32)
        {
            SyncPhase::Tracking
        } else {
            SyncPhase::Recovering
        };

        let mut per_pool = previous.per_pool;
        for (pool, ratio) in per_pool.iter_mut() {
            *ratio = self.coverage(*pool)?;
        }

        // A watch channel with no receivers is not an error: progress is
        // advisory, and the engine must not stop because nobody is listening.
        let _ = self.status.send(SyncStatus {
            phase,
            per_pool,
            tip,
            scanned_to,
            blocks_remaining: remaining,
        });
        Ok(())
    }

    /// Returns how much of a pool's commitment tree the wallet has covered.
    fn coverage(&self, pool: PoolId) -> Result<Ratio, Error> {
        let (covered, total) = self.db.commitment_coverage(pool)?;
        Ok(Ratio {
            numerator: covered,
            denominator: total,
        })
    }
}

/// Where the engine's time went.
///
/// Accumulated across every batch. This exists to answer one question: whether
/// overlapping fetching with detection would be worth building. While the
/// engine is a sequential loop, the wallet is idle for the whole of each fetch
/// and the server is idle for the whole of each detect, so the smaller of the
/// two is what a pipeline could recover.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timings {
    /// Time spent waiting for blocks.
    pub fetch: std::time::Duration,
    /// Time spent trial-decrypting and assembling results.
    pub detect: std::time::Duration,
    /// Time spent writing to storage.
    pub apply: std::time::Duration,
}

impl Timings {
    /// Returns the total time accounted for.
    pub fn total(&self) -> std::time::Duration {
        self.fetch + self.detect + self.apply
    }

    /// Returns the time a perfect pipeline could recover: the smaller of the
    /// network and CPU phases, which is what currently runs to completion while
    /// the other side does nothing.
    pub fn pipelining_headroom(&self) -> std::time::Duration {
        self.fetch.min(self.detect + self.apply)
    }
}

/// What a run of the engine accomplished.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncSummary {
    /// How many batches were applied.
    pub batches: usize,
    /// How many notes belonging to the wallet were found.
    pub notes: usize,
    /// How many times a continuity failure forced a rewind.
    pub rewinds: usize,
    /// Whether the run stopped because it was cancelled.
    pub cancelled: bool,
}
