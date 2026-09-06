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
use zakura_wallet_core::{enhanced::TransactionStatus,
    BlockAnchor,
    pool::PoolId,
    retrieval::Locator,
    scanning::{ScanPriority, ScanRange},
};
use zakura_wallet_scan::{
    EnhanceError, ScanError, ScanKeys, TransparentWatch, detect_batch,
    enhance::decrypt_transaction,
};
use zakura_wallet_store::{
    PRUNING_DEPTH, WalletDb,
    enhance::TxMeta,
    retrieval::RequestScope,
};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::{
    error::Error,
    progress::{Ratio, SyncPhase, SyncStatus},
    retrieval::{PublicRetrieval, Request, Retrieval, Retrieved},
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
    /// How transparent outputs are discovered.
    pub transparent_discovery: TransparentDiscovery,
    /// How many transactions one enhancement step may fetch.
    ///
    /// A cap rather than "drain it": a step that ran until the queue emptied
    /// would stop reporting progress and stop honouring cancellation for as
    /// long as it took, which on a recovering wallet is a long time.
    pub enhance_batch: usize,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            budget: ByteBudget::MOBILE,
            min_priority: ScanPriority::Historic,
            enhance_batch: 16,
            transparent_discovery: TransparentDiscovery::SweepOnRestore,
        }
    }
}

/// How the wallet finds transparent outputs it did not see arrive.
///
/// Detection from compact blocks needs the address to have been derived before
/// the block was scanned. Recovery runs from the tip downwards, so a receipt at
/// a high address index near the tip is met while the window is still narrow,
/// and the lower-index receipt that would have widened it arrives too late.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentDiscovery {
    /// Match scripts against blocks and nothing else.
    ///
    /// Names no address to anybody. The cost is the case above: a restored
    /// wallet may not see funds at addresses beyond the window it started with.
    CompactOnly,
    /// Ask the server once, when recovery completes, then compact-only.
    ///
    /// The request names the wallet's addresses, and a server can group them
    /// into one wallet on that basis. That is a real disclosure, made once at
    /// restore rather than continuously, in exchange for not silently missing
    /// funds a restored wallet already holds.
    SweepOnRestore,
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
    /// Transactions were fetched whole and folded in.
    Enhanced {
        /// How many the source supplied.
        fetched: usize,
        /// How many touched the wallet and were stored.
        applied: usize,
        /// How many the source could not be asked about.
        ///
        /// Counted rather than fatal: one unreachable transaction must not stop
        /// a wallet synchronising. It stays queued and is asked again later.
        failed: usize,
    },
    /// A transparent UTXO sweep reconciled the wallet's transparent outputs.
    Swept,
    /// There is nothing left to scan.
    Idle,
    /// The source returned nothing for a range that is still queued.
    ///
    /// Distinct from [`Step::Idle`], which means the queue is empty. This means
    /// there is work outstanding that the source would not serve, so the wallet
    /// is *not* synced — reporting it as idle would make a transient server
    /// failure indistinguishable from having caught up, and would leave the
    /// range silently unscanned.
    Stalled {
        /// The range the source declined to serve.
        range: Range<BlockHeight>,
    },
    /// The engine was asked to stop.
    Cancelled,
}

/// A fetch already in flight for a range the engine intends to scan next.
struct Prefetch<S: ChainSource> {
    range: ScanRange,
    #[allow(clippy::type_complexity)]
    task: tokio::task::JoinHandle<
        Result<(Vec<zakura_wallet_core::CompactBlock>, Option<BlockAnchor>), S::Error>,
    >,
}

/// What detecting and applying one batch produced.
enum Applied {
    Scanned {
        covered: Range<BlockHeight>,
        notes: usize,
        /// How much of the blocking work was detection rather than storage.
        detect: std::time::Duration,
    },
    Failed(ScanError),
}

/// Returns the part of `range` this batch did not cover, if any.
///
/// Which end is left over depends on which end was taken: descending recovery
/// consumes the top of a range, tip-following the bottom.
fn remainder(
    range: &ScanRange,
    blocks: &[zakura_wallet_core::CompactBlock],
    direction: Direction,
) -> Option<ScanRange> {
    let (lowest, highest) = (blocks.first()?.height, blocks.last()?.height);
    let covered = range.block_range();
    let rest = match direction {
        Direction::Descending => covered.start..lowest,
        Direction::Ascending => (highest + 1)..covered.end,
    };
    (rest.start < rest.end).then(|| ScanRange::from_parts(rest, range.priority()))
}

/// Drives synchronisation of one wallet against one chain source.
pub struct SyncEngine<S: ChainSource, P> {
    // Shared rather than owned, so a fetch can run on its own task while the
    // engine is busy detecting and applying the batch before it.
    source: std::sync::Arc<S>,
    params: P,
    // `None` only while a blocking task holds it; see `detect_and_apply`.
    db: Option<WalletDb>,
    keys: ScanKeys,
    watch_set: TransparentWatch,
    /// Whether the transparent sweep has already run in this engine's life.
    swept: bool,
    config: SyncConfig,
    status: watch::Sender<SyncStatus>,
    /// How far the *next* rewind will go, doubling after each one, and the
    /// height whose repeated failure has been driving that escalation.
    ///
    /// Keyed to the height rather than reset on any clean batch. Under
    /// descending recovery the queue interleaves the reorged range near the tip
    /// with historic ranges far below it, so a global "reset on success" counter
    /// is reset by an unrelated historic batch before the reorged range is
    /// retried — and the doubling never escalates past its first step, which is
    /// exactly the case the escalation exists for.
    rewind_depth: u32,
    rewinding_at: Option<BlockHeight>,
    timings: Timings,
    /// A fetch started while the previous batch was being applied.
    prefetch: Option<Prefetch<S>>,
}

impl<S, P> SyncEngine<S, P>
where
    // `Send + Sync + 'static` is what lets a fetch run on its own task while the
    // engine applies the batch before it; `P: Clone + Send` is what lets the
    // network parameters cross into the blocking detect-and-apply task.
    S: ChainSource + Send + Sync + 'static,
    P: Parameters + Clone + Send + 'static,
{
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
            source: std::sync::Arc::new(source),
            params,
            db: Some(db),
            keys,
            watch_set,
            swept: false,
            config,
            status: watch::Sender::new(SyncStatus::default()),
            rewind_depth: INITIAL_REWIND,
            rewinding_at: None,
            timings: Timings::default(),
            prefetch: None,
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
        self.db.as_ref().expect("the wallet is present between steps")
    }

    /// Returns the wallet this engine is driving, mutably.
    pub fn db_mut(&mut self) -> &mut WalletDb {
        self.db.as_mut().expect("the wallet is present between steps")
    }

    /// Consumes the engine, returning the wallet.
    pub fn into_db(mut self) -> WalletDb {
        self.discard_prefetch();
        self.db.take().expect("the wallet is present between steps")
    }

    /// Asks the source for the tip and reconciles the queue with it.
    pub async fn update_tip(&mut self) -> Result<BlockHeight, Error> {
        let tip = self.source.tip().await.map_err(SourceError::new).map_err(Error::Source)?;
        let params = self.params.clone();
        self.db_mut().update_chain_tip(&params, tip.height)?;
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
            self.discard_prefetch();
            return Ok(Step::Cancelled);
        }

        // Watched sends first, and unconditionally. Somebody waiting to see
        // their payment confirm should not wait behind a historic recovery, and
        // this set is small: only transactions this installation created.
        if let Some(step) = self.drain_requests(RequestScope::PendingSends).await? {
            return Ok(step);
        }

        // Either a fetch this engine started while applying the previous batch,
        // or a fresh one for the most urgent range the queue offers.
        let prefetch = match self.prefetch.take() {
            Some(prefetch) => prefetch,
            None => {
                let Some(range) = self.next_range()? else {
                    // Only with nothing left to scan. Memos and outgoing
                    // history are recovery, not balance: fetching them ahead of
                    // blocks would delay the number somebody is actually
                    // looking at.
                    // Recovery is finished: nothing is left to scan. This is
                    // the one moment the sweep is worth its disclosure, and it
                    // runs before enhancement so a restored balance is right
                    // before its history is filled in.
                    if self.sweep_transparent().await? {
                        return Ok(Step::Swept);
                    }
                    if let Some(step) = self.drain_requests(RequestScope::All).await? {
                        return Ok(step);
                    }
                    self.publish(None)?;
                    return Ok(Step::Idle);
                };
                self.spawn_fetch(range)
            }
        };

        let range = prefetch.range.clone();
        // Recovery works backwards and tip-following works forwards, so which
        // end of the range is fetched is decided by what the range is *for*.
        // The anchor therefore cannot be resolved until the blocks are in hand:
        // it belongs to whichever block turned out to be lowest.
        let direction = direction_for(range.priority());

        let fetch_began = std::time::Instant::now();
        let (blocks, prefetched_anchor) = prefetch
            .task
            .await
            .expect("the fetch task does not panic")
            .map_err(SourceError::new)
            .map_err(Error::Source)?;
        // Only the part actually waited for counts. A fetch that overlapped the
        // previous batch's work has usually finished by the time it is awaited,
        // and charging its whole duration here would hide exactly the saving
        // the overlap exists to produce.
        self.timings.fetch += fetch_began.elapsed();

        if blocks.is_empty() {
            // The source served nothing for a range that is still queued, so
            // asking again immediately would spin. Stop, but say why: the range
            // is not scanned, and reporting this as `Idle` would tell the caller
            // the wallet had caught up when it has a hole in it.
            return Ok(Step::Stalled {
                range: range.block_range().clone(),
            });
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

        // Under descending recovery this is a fresh assertion from the source
        // rather than the wallet's own record, and the scanner cannot check it:
        // its end-of-block check compares the batch against block metadata from
        // that same source, so a source wrong about both is self-consistent.
        //
        // The check that catches it lives in the store, and the two directions
        // reach it from opposite sides. Ascending, the block *below* the batch
        // is already scanned, so the anchor is compared against it directly.
        // Descending, the batch's own first block is what the *previous* batch
        // was anchored on — so the block above this one is always already
        // stored, and the store compares this batch's end against where that
        // block started. Every batch after the first in either direction is
        // therefore pinned against something the wallet recorded itself.
        let anchor_began = std::time::Instant::now();
        let anchor = self
            .resolve_anchor(blocks[0].height, prefetched_anchor)
            .await?;
        self.timings.anchor += anchor_began.elapsed();

        // Start the next fetch *before* the CPU and disk work, so the network
        // and this machine are busy at the same time. This is the whole of the
        // pipeline: fetch dominates recovery, and detect-plus-apply is what it
        // overlaps with.
        //
        // Only the remainder of the range in hand is prefetched. Asking the
        // queue for the next range would be wrong, because the queue does not
        // learn what this batch covered until it commits, so it would hand back
        // a range overlapping the one being applied.
        if let Some(next) = remainder(&range, &blocks, direction) {
            self.prefetch = Some(self.spawn_fetch(next));
        }

        let detect_and_apply_began = std::time::Instant::now();
        let outcome = self.detect_and_apply(anchor, blocks).await?;
        let elapsed = detect_and_apply_began.elapsed();

        match outcome {
            Applied::Scanned {
                covered,
                notes,
                detect,
            } => {
                self.timings.detect += detect;
                self.timings.apply += elapsed.saturating_sub(detect);
                // The escalation is cleared only when the range that was
                // failing is the one that succeeded. Clearing it on any clean
                // batch lets an unrelated historic range reset the counter
                // between two attempts at a reorged tip, so the depth never
                // grows and the give-up path is never reached.
                if matches!(self.rewinding_at, Some(h) if covered.contains(&h)) {
                    self.rewind_depth = INITIAL_REWIND;
                    self.rewinding_at = None;
                }
                self.publish(None)?;
                Ok(Step::Scanned {
                    range: covered,
                    notes,
                })
            }
            Applied::Failed(cause) if cause.is_continuity_error() => {
                self.timings.detect += elapsed;
                // Anything already in flight was fetched against the chain the
                // wallet is about to stop believing in, so it is discarded
                // rather than applied on top of the rewind.
                self.discard_prefetch();
                let to = self.rewind(&cause)?;
                self.publish(None)?;
                Ok(Step::Rewound { to, cause })
            }
            Applied::Failed(cause) => {
                self.discard_prefetch();
                Err(Error::Unrecoverable {
                    cause,
                    rewound_by: 0,
                })
            }
        }
    }

    /// Detects and applies one batch away from the async runtime.
    ///
    /// Both halves are blocking: detection saturates rayon, and applying holds a
    /// SQLite transaction. Running them on a runtime worker parks it for the
    /// whole of both, which starves everything sharing that runtime — the fetch
    /// this engine just started, and, in the destination this core is built for,
    /// a user interface. `spawn_blocking` moves them to a thread that is allowed
    /// to block, which is also what makes the overlap real on a single-threaded
    /// runtime.
    ///
    /// The wallet is moved into the task and moved back out, because it holds a
    /// `rusqlite::Connection` that cannot be shared. `self.db` is `None` only
    /// for the duration of this call, and `&mut self` means nothing else can
    /// observe it.
    async fn detect_and_apply(
        &mut self,
        anchor: BlockAnchor,
        blocks: Vec<zakura_wallet_core::CompactBlock>,
    ) -> Result<Applied, Error> {
        let mut db = self.db.take().expect("the wallet is present between steps");
        let params = self.params.clone();
        let keys = self.keys.clone();
        // Any addresses the previous batch obliged the wallet to watch must
        // exist before this one is detected, or a payment to one of them goes
        // unseen and there is no second chance: transparent outputs are matched
        // by script, not decrypted.
        let watch_seed = self.watch_set.clone();

        let (db, outcome) = tokio::task::spawn_blocking(move || {
            let nullifiers = match db.unspent_nullifiers() {
                Ok(nullifiers) => nullifiers,
                Err(e) => return (db, Err(Error::from(e))),
            };

            // Rebuilt from storage every batch rather than held as a field.
            // It is a query over a few hundred rows, and the alternative is a
            // watch set that silently goes stale as the wallet derives more
            // addresses — which looks exactly like having no transparent funds.
            let watch = match db.transparent_watch() {
                Ok(data) => merge_watch(&watch_seed, data),
                Err(e) => return (db, Err(Error::from(e))),
            };

            let detect_began = std::time::Instant::now();
            let detected = detect_batch(&params, &keys, &watch, &nullifiers, &anchor, &blocks);
            let detect = detect_began.elapsed();

            match detected {
                Ok(batch) => {
                    let covered = batch.blocks[0].height..(batch.end_anchor.height + 1);
                    let notes = batch.received_notes().count();
                    match db.put_batch(&params, &batch) {
                        Ok(()) => {
                            // Being paid at an address obliges the wallet to
                            // watch further ahead, and the addresses it has to
                            // add must exist before the *next* batch is
                            // detected — a transparent output is matched by
                            // script or not seen at all.
                            if let Err(e) = widen_transparent_window(&mut db, &params) {
                                return (db, Err(e));
                            }
                            (
                                db,
                                Ok(Applied::Scanned {
                                    covered,
                                    notes,
                                    detect,
                                }),
                            )
                        }
                        Err(e) => (db, Err(Error::from(e))),
                    }
                }
                Err(cause) => (db, Ok(Applied::Failed(cause))),
            }
        })
        .await
        .expect("the detect-and-apply task does not panic");

        self.db = Some(db);
        outcome
    }

    /// Starts fetching `range` in the background.
    fn spawn_fetch(&self, range: ScanRange) -> Prefetch<S> {
        let source = self.source.clone();
        let budget = self.config.budget;
        let direction = direction_for(range.priority());
        let block_range = range.block_range().clone();
        let task = tokio::spawn(async move {
            let blocks = source.fetch(block_range, budget, direction).await?;

            // The anchor is fetched here, in the same task, rather than by the
            // caller once the blocks are in hand. Measured over a 19-batch
            // recovery it was 56% of accounted time — larger than fetching the
            // blocks themselves — because it is a full round trip per batch that
            // overlaps nothing: the batch cannot be detected without it.
            //
            // It has to happen after the blocks arrive, because under descending
            // recovery which block is lowest depends on where the byte budget
            // ran out. Doing it here still puts it inside the window the caller
            // spends detecting and applying the *previous* batch.
            //
            // Only for descending ranges. Ascending ones continue from a block
            // the wallet has already scanned, so the anchor comes from local
            // data and this would be a wasted request.
            let anchor = match blocks.first() {
                Some(first)
                    if direction == Direction::Descending
                        && u32::from(first.height) > 0 =>
                {
                    Some(source.anchor(first.height - 1).await?)
                }
                _ => None,
            };

            Ok((blocks, anchor))
        });
        Prefetch { range, task }
    }

    /// Drops any fetch in flight, aborting it.
    ///
    /// Called when what it was fetched against no longer holds: a rewind, an
    /// unrecoverable failure, or cancellation. The blocks are always safe to
    /// throw away, because nothing is recorded as scanned until it is applied.
    fn discard_prefetch(&mut self) {
        if let Some(prefetch) = self.prefetch.take() {
            prefetch.task.abort();
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
            let start = self.db().next_subtree_index(pool)?;
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
            self.db_mut().put_subtree_roots(pool, start, &contiguous)?;
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
                Step::Swept => summary.swept = true,
                Step::Enhanced {
                    applied, failed, ..
                } => {
                    summary.enhanced += applied;
                    summary.enhance_failures += failed;
                }
                Step::Idle => return Ok(summary),
                // Not a successful run: work is still queued and the source
                // would not serve it. The caller decides whether to retry, back
                // off or surface it, but it must be able to tell this apart
                // from having caught up.
                Step::Stalled { range } => {
                    summary.stalled = Some(range);
                    return Ok(summary);
                }
                Step::Cancelled => {
                    summary.cancelled = true;
                    return Ok(summary);
                }
            }
        }
    }

    /// Asks the source about outstanding transactions and folds in what it says.
    ///
    /// Returns `None` when there was nothing to ask, so the caller can get on
    /// with scanning.
    ///
    /// Each transaction is stored in its own database transaction. One that
    /// fails must not roll back the ones already folded in, and one the source
    /// will not serve must not stop the wallet synchronising — it is counted
    /// and asked about again later.
    async fn drain_requests(&mut self, scope: RequestScope) -> Result<Option<Step>, Error> {
        let Some(tip) = self.db().chain_tip()? else {
            return Ok(None);
        };

        let backend = PublicRetrieval::new(std::sync::Arc::clone(&self.source));
        let serves = backend.serves();

        let requests =
            self.db()
                .pending_requests(scope, serves, tip, self.config.enhance_batch)?;
        if requests.is_empty() {
            return Ok(None);
        }

        let params = self.params.clone();
        let keys = self.keys.clone();
        // Built once for the whole drain, the same way detection builds it per
        // batch: a full transaction carries its transparent bundle, so an
        // enhanced transaction can reveal outputs the wallet owns and spends of
        // outputs it already held. Without a watch set here that side of the
        // transaction is parsed and thrown away.
        let watch = merge_watch(&self.watch_set, self.db().transparent_watch()?);
        let (mut fetched, mut applied, mut failed) = (0, 0, 0);
        // Requests this backend could actually take on. A drain that attempted
        // nothing must report nothing: returning a step saying "enhanced zero"
        // would leave the engine with work outstanding and no way to make
        // progress on it, and `run` would spin on the same batch forever.
        let mut attempted = 0;

        // The batch is answered one request at a time, which is what the public
        // protocol offers. The trait takes a slice so a backend that can
        // amortise a batch — most of the point of a private one — is not forced
        // to pretend it cannot.
        for request in requests {
            // Belt and braces: the query already filtered by what this backend
            // serves. For an action the property is not an optimisation —
            // asking a public server for one would mean naming the transaction
            // it belongs to, which is exactly what a position-keyed request
            // exists to avoid.
            debug_assert!(serves.serves(&request.locator));
            attempted += 1;

            let answers = backend
                .retrieve(std::slice::from_ref(&Request {
                    locator: request.locator,
                    guard: None,
                }))
                .await;

            match answers.into_iter().next().expect("one answer per request") {
                Ok(Some(Retrieved::Transaction(tx))) => {
                    fetched += 1;
                    let subject = request
                        .subject
                        .expect("a transaction request carries its subject");
                    // The height the transaction is parsed under. If the source
                    // says where it is mined, that; otherwise the next tip,
                    // which is where an unmined transaction would go.
                    let height = tx.status.height().unwrap_or(tip + 1);

                    match decrypt_transaction(&params, &keys, &watch, subject, height, &tx.raw) {
                        Ok(decrypted) => {
                            let meta = TxMeta {
                                mined_height: tx.status.height(),
                                ..TxMeta::default()
                            };
                            self.db_mut().put_enhanced_tx(&params, &decrypted, meta)?;
                            if tx.status.height().is_none() {
                                self.db_mut()
                                    .set_transaction_status(subject, tx.status, tip)?;
                            }
                            applied += 1;
                        }
                        // A server answering with a different transaction than
                        // the one asked for is not a transient condition, and
                        // continuing would mean grafting its data onto the row
                        // the wallet asked about.
                        Err(e @ EnhanceError::TxIdMismatch { .. }) => {
                            return Err(Error::Enhance(e));
                        }
                        Err(EnhanceError::Malformed(_)) => failed += 1,
                    }
                }
                // A block, fetched to reconstruct the enhance candidates that
                // descending recovery could not record the first time.
                Ok(Some(Retrieved::Block(block))) => {
                    fetched += 1;
                    match self.rebuild_candidates(&request.locator, *block) {
                        Ok(true) => applied += 1,
                        // Nothing was applied and nothing is wrong: the wallet
                        // cannot anchor this block yet. Reported as neither
                        // progress nor failure, and left queued.
                        Ok(false) => {}
                        Err(_) => {
                            failed += 1;
                            self.db().mark_attempted(request.locator)?;
                        }
                    }
                }
                // No backend here answers with an action yet; the arm exists so
                // that adding one is a change in one place.
                Ok(Some(Retrieved::Action(_))) => failed += 1,
                // A definite negative, which is what starts the expiry clock —
                // but only for a question about a transaction. A height that
                // came back empty says nothing, because a block that exists
                // cannot go missing.
                Ok(None) => {
                    fetched += 1;
                    match request.subject {
                        Some(subject) if request.locator.subject().is_some() => {
                            self.db_mut().set_transaction_status(
                                subject,
                                TransactionStatus::NotFound,
                                tip,
                            )?;
                        }
                        _ => self.db().mark_attempted(request.locator)?,
                    }
                }
                // A transport failure, which says nothing about the
                // transaction. Recording it as a negative here would expire
                // live transactions and hand back the notes they spend.
                Err(_) => failed += 1,
            }

            self.db().mark_polled(request.locator, tip)?;
        }

        self.publish(None)?;
        if attempted == 0 {
            return Ok(None);
        }

        Ok(Some(Step::Enhanced {
            fetched,
            applied,
            failed,
        }))
    }
}

impl<S, P> SyncEngine<S, P>
where
    S: ChainSource + Send + Sync + 'static,
    P: Parameters + Clone + Send + 'static,
{
    /// Reconciles transparent outputs against the server, once per run.
    ///
    /// Returns whether it did anything, so the caller can report it as a step.
    async fn sweep_transparent(&mut self) -> Result<bool, Error> {
        if self.config.transparent_discovery != TransparentDiscovery::SweepOnRestore
            || self.swept
        {
            return Ok(false);
        }
        // Marked before the request rather than after: a sweep that fails must
        // not be retried on every step, because each attempt names the wallet's
        // addresses to the server again.
        self.swept = true;

        let Some(tip) = self.db().chain_tip()? else {
            return Ok(false);
        };

        let watch = self.db().transparent_watch()?;
        if watch.addresses.is_empty() {
            return Ok(false);
        }

        let params = self.params.clone();
        let accounts = self.db().accounts(&params)?;
        let mut acted = false;

        for account in accounts {
            let addresses = self.db().transparent_addresses(account.id)?;
            if addresses.is_empty() {
                continue;
            }
            // From the account's birthday: below it there is nothing of this
            // account's to find, and asking about more than necessary widens
            // what the server learns for no gain.
            let from = account.birthday;
            let utxos = self
                .source
                .address_utxos(addresses, from)
                .await
                .map_err(|e| Error::Source(SourceError::new(e)))?;

            let swept: Vec<_> = utxos
                .into_iter()
                .map(|u| zakura_wallet_store::SweptOutput {
                    address: u.address,
                    txid: u.txid,
                    output_index: u.output_index,
                    script: u.script,
                    value: u.value,
                    height: u.height,
                })
                .collect();

            self.db_mut().apply_utxo_sweep(account.id, from, tip, &swept)?;
            acted = true;
        }

        Ok(acted)
    }

    /// Re-detects one already-scanned block to recover the enhance candidates
    /// that were not recordable the first time.
    ///
    /// The block is detected against the wallet's *current* nullifier snapshot,
    /// which is the whole point: at scan time the funding note had not been
    /// seen, so the spend linked to nothing and the transaction looked like a
    /// stranger's. Now it links, `funding_accounts` is non-empty, and the same
    /// pure detection produces the candidates it could not produce before.
    ///
    /// Its anchor comes from the wallet's own record of the preceding block. If
    /// that block is not stored — a range boundary — the job is left queued
    /// rather than anchored on anything a server said, and ordinary scanning
    /// makes it possible later.
    /// Returns whether it applied anything. `false` means the wallet cannot
    /// anchor the block yet, which the queue normally filters out before the
    /// request is sent; it can still happen if a rewind earlier in this same
    /// drain removed the predecessor. Nothing was applied, so the caller must
    /// not report progress, and the row stays queued for a later tip.
    fn rebuild_candidates(
        &mut self,
        locator: &Locator,
        block: zakura_wallet_core::CompactBlock,
    ) -> Result<bool, Error> {
        let Locator::Block { height, hash } = locator else {
            return Err(Error::Rediscovery(
                "a rediscovery job was queued with the wrong locator kind".into(),
            ));
        };

        let Some(anchor) = self.db().block_anchor(*height - 1)? else {
            // Not an error and not an attempt: the wallet simply cannot anchor
            // this yet. Counting it against the retry bound would burn the
            // budget on a condition ordinary sync is about to fix.
            return Ok(false);
        };

        // Spent notes included, and that is the point: by now the wallet has
        // recognised the spend this block makes, so the note funding it is
        // marked spent. A snapshot of unspent notes would find no funding here
        // and return an empty candidate list indistinguishable from a correct
        // one.
        let nullifiers = self.db().all_nullifiers()?;
        let watch = merge_watch(&self.watch_set, self.db().transparent_watch()?);
        let detected = detect_batch(
            &self.params,
            &self.keys,
            &watch,
            &nullifiers,
            &anchor,
            std::slice::from_ref(&block),
        )
        .map_err(|e| Error::Rediscovery(e.to_string()))?;

        let Some(detected_block) = detected.blocks.first() else {
            return Err(Error::Rediscovery(
                "a rediscovered block detected to nothing at all".into(),
            ));
        };
        self.db_mut()
            .put_rediscovered_candidates(*height, hash, detected_block)?;
        self.db_mut().resolve_request(*locator)?;
        Ok(true)
    }
}

/// Keeps every account's window of unused transparent addresses full.
///
/// Cheap when nothing moved: the gap query finds the window already wide enough
/// and derives nothing.
fn widen_transparent_window<P: Parameters>(
    db: &mut zakura_wallet_store::WalletDb,
    params: &P,
) -> Result<(), Error> {
    let limits = zakura_wallet_store::GapLimits::default();
    for account in db.accounts(params)? {
        db.maintain_transparent_addresses(params, account.id, &limits)?;
    }
    Ok(())
}

/// Combines the caller-supplied watch set with the wallet's stored addresses.
///
/// The caller's is kept so that a consumer watching something the wallet did
/// not derive — an imported key, a test fixture — is not silently dropped.
pub fn merge_watch(
    seed: &TransparentWatch,
    stored: zakura_wallet_store::TransparentWatchData,
) -> TransparentWatch {
    let mut scripts: Vec<_> = stored
        .addresses
        .into_iter()
        .map(|a| {
            (
                transparent::address::Script(zcash_script::script::Code(a.script)),
                a.account,
                a.address_id,
            )
        })
        .collect();
    scripts.extend(seed.entries());

    TransparentWatch::new(scripts, stored.unspent.into_iter().chain(seed.outpoints()))
}

impl<S, P> SyncEngine<S, P>
where
    S: ChainSource + Send + Sync + 'static,
    P: Parameters + Clone + Send + 'static,
{
    /// Returns the most urgent range still to scan.
    fn next_range(&self) -> Result<Option<ScanRange>, Error> {
        Ok(self
            .db()
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
    async fn resolve_anchor(
        &self,
        start: BlockHeight,
        prefetched: Option<BlockAnchor>,
    ) -> Result<BlockAnchor, Error> {
        if start == BlockHeight::from_u32(0) {
            return Err(Error::MissingAnchor { height: start });
        }
        let below = start - 1;

        // The wallet's own record first, always: it is what the trees were built
        // from, and it costs nothing.
        if let Some(anchor) = self.db().block_anchor(below)? {
            return Ok(anchor);
        }

        // Then the one the fetch task already asked for, which is the usual case
        // under descending recovery and has cost nothing here because it
        // happened while the previous batch was being applied.
        if let Some(anchor) = prefetched.filter(|a| a.height == below) {
            return Ok(anchor);
        }

        self.source
            .anchor(below)
            .await
            .map_err(SourceError::new)
            .map_err(Error::Source)
    }

    /// Rewinds after a continuity failure, deepening on repeated failures.
    fn rewind(&mut self, cause: &ScanError) -> Result<BlockHeight, Error> {
        // The depth is *not* reset here, even though the failing height usually
        // differs from last time. It differs because the previous rewind moved
        // the range, so treating a new height as a new problem would reset the
        // escalation on every attempt and the doubling would never leave its
        // first step — which is how a source that is simply broken, rather than
        // reorged, would be retried forever.
        //
        // Escalation is cleared by progress instead: a batch that applies and
        // covers the height being rewound at. See `step`.
        let failed_at = cause.at_height();
        self.rewinding_at = Some(failed_at);
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

        let target = failed_at.saturating_sub(depth);
        let floor = self.db().birthday()?.map(|b| b.saturating_sub(1));
        let target = match floor {
            Some(floor) if target < floor => floor,
            _ => target,
        };

        self.db_mut().truncate_to(target)?;
        self.rewind_depth = depth.saturating_mul(2);
        Ok(target)
    }

    /// Publishes a progress snapshot.
    fn publish(&self, tip: Option<BlockHeight>) -> Result<(), Error> {
        let scanned_to = self.db().block_height_extrema()?.map(|(_, hi)| hi);
        let remaining: u64 = self
            .db()
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
        let (covered, total) = self.db().commitment_coverage(pool)?;
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
    /// Time spent resolving a batch's starting anchor.
    ///
    /// Under descending recovery this is a `GetTreeState` round trip per batch,
    /// because a range that continues from nothing scanned has no local
    /// predecessor. It is a network cost that is *not* part of `fetch`, and it
    /// does not overlap anything: the batch cannot be detected without it.
    pub anchor: std::time::Duration,
}

impl Timings {
    /// Returns the total time accounted for.
    pub fn total(&self) -> std::time::Duration {
        self.fetch + self.detect + self.apply + self.anchor
    }

    /// Returns the time a perfect pipeline could recover: the smaller of the
    /// network and CPU phases, which is what currently runs to completion while
    /// the other side does nothing.
    pub fn pipelining_headroom(&self) -> std::time::Duration {
        self.fetch.min(self.detect + self.apply)
    }
}

/// What a run of the engine accomplished.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncSummary {
    /// How many batches were applied.
    pub batches: usize,
    /// How many notes belonging to the wallet were found.
    pub notes: usize,
    /// How many times a continuity failure forced a rewind.
    pub rewinds: usize,
    /// Whether a transparent sweep ran during this run.
    pub swept: bool,
    /// How many transactions were fetched whole and folded in.
    pub enhanced: usize,
    /// How many transactions the source could not be asked about.
    ///
    /// Not a failure of the run: these stay queued and are asked again. But a
    /// caller that sees this climbing is talking to a server that will not
    /// answer, and a wallet with no memos and no outgoing history is the
    /// symptom.
    pub enhance_failures: usize,
    /// Whether the run stopped because it was cancelled.
    pub cancelled: bool,
    /// The range the source would not serve, if that is why the run stopped.
    ///
    /// `Some` means the wallet is *not* caught up: this range is still queued.
    /// Without it a transient server failure would be reported exactly like a
    /// completed sync.
    pub stalled: Option<Range<BlockHeight>>,
}

impl SyncSummary {
    /// Returns whether the run finished the work that was queued.
    pub fn is_complete(&self) -> bool {
        !self.cancelled && self.stalled.is_none()
    }
}
