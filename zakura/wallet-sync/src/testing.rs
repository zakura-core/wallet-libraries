//! An in-memory chain source.
//!
//! This is the second implementation that justifies [`ChainSource`] being a
//! trait, and it is what makes the engine's failure modes testable: a reorg is
//! replacing the tail of a vector, and a stalled server is returning fewer
//! blocks than asked for.
//!
//! The blocks it serves are the real thing — built by
//! `zakura_wallet_scan::testing`, carrying real encrypted notes — so a test
//! here exercises the same cryptography the engine will meet on mainnet.

use std::{
    convert::Infallible,
    ops::Range,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use zakura_wallet_core::{BlockAnchor, BlockHash, CompactBlock, pool::TreeSizes};
use zcash_protocol::consensus::BlockHeight;

use crate::source::{ByteBudget, ChainSource, ChainTip, Direction, estimated_size};

/// A chain held in memory, which can be reorganised under a running engine.
#[derive(Clone, Default)]
pub struct InMemoryChain {
    inner: Arc<Mutex<Inner>>,
    /// How many blocks were served, so a test can assert the engine did not
    /// re-fetch what it already had.
    served: Arc<AtomicUsize>,
    tx_served: Arc<AtomicUsize>,
}

#[derive(Default)]
struct Inner {
    /// Blocks in ascending height order, contiguous.
    blocks: Vec<CompactBlock>,
    /// The chain state below the first block.
    anchor: Option<BlockAnchor>,
    /// Subtree roots the server would serve, by pool.
    roots: std::collections::BTreeMap<zakura_wallet_core::pool::PoolId, Vec<crate::SubtreeRoot>>,
    transactions: std::collections::BTreeMap<zcash_protocol::TxId, crate::FetchedTransaction>,
    utxos: Vec<crate::SweptUtxo>,
}

impl InMemoryChain {
    /// Builds a chain from `blocks`, anchored on `anchor`.
    pub fn new(anchor: BlockAnchor, blocks: Vec<CompactBlock>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                blocks,
                anchor: Some(anchor),
                roots: Default::default(),
                transactions: Default::default(),
                utxos: Vec::new(),
            })),
            served: Arc::new(AtomicUsize::new(0)),
            tx_served: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Replaces every block from `height` upwards with `replacement`.
    ///
    /// This is a reorg: the blocks above `height` are gone, and the ones that
    /// take their place have different hashes, so a wallet that scanned the old
    /// ones will find its `prev_hash` check failing.
    pub fn reorg(&self, height: BlockHeight, replacement: Vec<CompactBlock>) {
        let mut inner = self.inner.lock().expect("the chain lock is not poisoned");
        inner.blocks.retain(|b| b.height < height);
        inner.blocks.extend(replacement);
        inner.blocks.sort_by_key(|b| b.height);
    }

    /// Gives the server subtree roots to serve for a pool.
    pub fn with_subtree_roots(
        &self,
        pool: zakura_wallet_core::pool::PoolId,
        roots: Vec<crate::SubtreeRoot>,
    ) {
        self.inner
            .lock()
            .expect("the chain lock is not poisoned")
            .roots
            .insert(pool, roots);
    }

    /// Gives the server a transaction to serve when asked for it.
    pub fn with_transaction(
        &self,
        txid: zcash_protocol::TxId,
        raw: Vec<u8>,
        status: crate::TransactionStatus,
    ) {
        self.inner
            .lock()
            .expect("the chain lock is not poisoned")
            .transactions
            .insert(txid, crate::FetchedTransaction { raw, status });
    }

    /// Gives the server unspent transparent outputs to report.
    pub fn with_utxos(&self, utxos: Vec<crate::SweptUtxo>) {
        self.inner
            .lock()
            .expect("the chain lock is not poisoned")
            .utxos = utxos;
    }

    /// Returns how many transactions have been asked for.
    ///
    /// The point of counting is that a wallet must not re-ask the same question
    /// of the same server on every step; without a count, a driver that polls
    /// in a loop looks identical to one that does not.
    pub fn transactions_served(&self) -> usize {
        self.tx_served.load(Ordering::Relaxed)
    }

    /// Returns how many blocks have been served since the chain was built.
    pub fn blocks_served(&self) -> usize {
        self.served.load(Ordering::Relaxed)
    }

    /// Returns the blocks currently in the chain.
    pub fn blocks(&self) -> Vec<CompactBlock> {
        self.inner
            .lock()
            .expect("the chain lock is not poisoned")
            .blocks
            .clone()
    }
}

impl ChainSource for InMemoryChain {
    type Error = Infallible;

    async fn tip(&self) -> Result<ChainTip, Self::Error> {
        let inner = self.inner.lock().expect("the chain lock is not poisoned");
        Ok(match inner.blocks.last() {
            Some(block) => ChainTip {
                height: block.height,
                hash: block.hash,
            },
            None => {
                let anchor = inner.anchor.clone().unwrap_or(BlockAnchor {
                    height: BlockHeight::from_u32(0),
                    hash: BlockHash([0; 32]),
                    tree_sizes: TreeSizes::default(),
                });
                ChainTip {
                    height: anchor.height,
                    hash: anchor.hash,
                }
            }
        })
    }

    async fn anchor(&self, height: BlockHeight) -> Result<BlockAnchor, Self::Error> {
        let inner = self.inner.lock().expect("the chain lock is not poisoned");

        if let Some(block) = inner.blocks.iter().find(|b| b.height == height) {
            return Ok(BlockAnchor {
                height,
                hash: block.hash,
                tree_sizes: block.tree_sizes,
            });
        }

        Ok(inner.anchor.clone().unwrap_or(BlockAnchor {
            height,
            hash: BlockHash([0; 32]),
            tree_sizes: TreeSizes::default(),
        }))
    }

    async fn fetch(
        &self,
        range: Range<BlockHeight>,
        budget: ByteBudget,
        direction: Direction,
    ) -> Result<Vec<CompactBlock>, Self::Error> {
        let inner = self.inner.lock().expect("the chain lock is not poisoned");

        let in_range = || {
            inner
                .blocks
                .iter()
                .filter(|b| b.height >= range.start && b.height < range.end)
        };

        let mut out = Vec::new();
        let mut spent = 0usize;
        let take = |block: &CompactBlock, out: &mut Vec<CompactBlock>, spent: &mut usize| {
            let size = estimated_size(block);
            // Always yield at least one block: a block larger than the whole
            // budget must still be scannable, or the wallet would stall on it
            // forever.
            if !out.is_empty() && *spent + size > budget.bytes() {
                return false;
            }
            *spent += size;
            out.push(block.clone());
            true
        };

        match direction {
            Direction::Ascending => {
                for block in in_range() {
                    if !take(block, &mut out, &mut spent) {
                        break;
                    }
                }
            }
            Direction::Descending => {
                for block in in_range().rev() {
                    if !take(block, &mut out, &mut spent) {
                        break;
                    }
                }
                // Contiguous and ascending whichever end they came from.
                out.reverse();
            }
        }

        self.served.fetch_add(out.len(), Ordering::Relaxed);
        Ok(out)
    }

    async fn address_utxos(
        &self,
        addresses: Vec<String>,
        _start: BlockHeight,
    ) -> Result<Vec<crate::SweptUtxo>, Self::Error> {
        let inner = self.inner.lock().expect("the chain lock is not poisoned");
        Ok(inner
            .utxos
            .iter()
            .filter(|u| addresses.contains(&u.address))
            .cloned()
            .collect())
    }

    async fn transaction(
        &self,
        txid: zcash_protocol::TxId,
    ) -> Result<Option<crate::FetchedTransaction>, Self::Error> {
        let inner = self.inner.lock().expect("the chain lock is not poisoned");
        // Absent from the map means the chain positively does not have it,
        // which is what a source is allowed to say. A source that cannot answer
        // returns an error instead, and `FailingChain` is what exercises that.
        self.tx_served.fetch_add(1, Ordering::Relaxed);
        Ok(inner.transactions.get(&txid).cloned())
    }

    async fn subtree_roots(
        &self,
        pool: zakura_wallet_core::pool::PoolId,
        start_index: u64,
        limit: u32,
    ) -> Result<Vec<crate::SubtreeRoot>, Self::Error> {
        let inner = self.inner.lock().expect("the chain lock is not poisoned");
        Ok(inner
            .roots
            .get(&pool)
            .into_iter()
            .flatten()
            .filter(|r| r.index >= start_index)
            .take(limit as usize)
            .copied()
            .collect())
    }
}

/// A source whose blocks never join up with anything.
///
/// Every block it serves carries a fresh, arbitrary `prev_hash`, so continuity
/// fails no matter how far the wallet rewinds. This is not a reorg — a reorg
/// converges once the wallet gets below the fork point — but a source that is
/// simply broken or hostile, which is the case the engine's give-up policy
/// exists for.
#[derive(Clone)]
pub struct IncoherentChain {
    inner: InMemoryChain,
    counter: Arc<AtomicUsize>,
}

impl IncoherentChain {
    /// Wraps a chain, breaking the continuity of everything it serves.
    pub fn new(inner: InMemoryChain) -> Self {
        Self {
            inner,
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl ChainSource for IncoherentChain {
    type Error = Infallible;

    async fn tip(&self) -> Result<ChainTip, Self::Error> {
        self.inner.tip().await
    }

    async fn anchor(&self, height: BlockHeight) -> Result<BlockAnchor, Self::Error> {
        self.inner.anchor(height).await
    }

    async fn fetch(
        &self,
        range: Range<BlockHeight>,
        budget: ByteBudget,
        direction: Direction,
    ) -> Result<Vec<CompactBlock>, Self::Error> {
        let mut blocks = self.inner.fetch(range, budget, direction).await?;
        if let Some(first) = blocks.first_mut() {
            let n = self.counter.fetch_add(1, Ordering::Relaxed) as u8;
            first.prev_hash = BlockHash([n.wrapping_add(1); 32]);
        }
        Ok(blocks)
    }

    async fn address_utxos(
        &self,
        addresses: Vec<String>,
        start: BlockHeight,
    ) -> Result<Vec<crate::SweptUtxo>, Self::Error> {
        self.inner.address_utxos(addresses, start).await
    }

    async fn transaction(
        &self,
        txid: zcash_protocol::TxId,
    ) -> Result<Option<crate::FetchedTransaction>, Self::Error> {
        self.inner.transaction(txid).await
    }

    async fn subtree_roots(
        &self,
        pool: zakura_wallet_core::pool::PoolId,
        start_index: u64,
        limit: u32,
    ) -> Result<Vec<crate::SubtreeRoot>, Self::Error> {
        self.inner.subtree_roots(pool, start_index, limit).await
    }
}

/// A source that fails every request, for testing error propagation.
#[derive(Debug, Clone, Copy, Default)]
pub struct FailingChain;

/// The error [`FailingChain`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unavailable;

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the chain source is unavailable")
    }
}

impl std::error::Error for Unavailable {}

impl ChainSource for FailingChain {
    type Error = Unavailable;

    async fn tip(&self) -> Result<ChainTip, Self::Error> {
        Err(Unavailable)
    }

    async fn anchor(&self, _height: BlockHeight) -> Result<BlockAnchor, Self::Error> {
        Err(Unavailable)
    }

    async fn fetch(
        &self,
        _range: Range<BlockHeight>,
        _budget: ByteBudget,
        _direction: Direction,
    ) -> Result<Vec<CompactBlock>, Self::Error> {
        Err(Unavailable)
    }

    async fn address_utxos(
        &self,
        _addresses: Vec<String>,
        _start: BlockHeight,
    ) -> Result<Vec<crate::SweptUtxo>, Self::Error> {
        Err(Unavailable)
    }

    async fn transaction(
        &self,
        _txid: zcash_protocol::TxId,
    ) -> Result<Option<crate::FetchedTransaction>, Self::Error> {
        // An error, never `Ok(None)`. The distinction is the whole contract:
        // `Ok(None)` would tell the wallet this transaction is definitely not
        // out there, and start it expiring.
        Err(Unavailable)
    }

    async fn subtree_roots(
        &self,
        _pool: zakura_wallet_core::pool::PoolId,
        _start_index: u64,
        _limit: u32,
    ) -> Result<Vec<crate::SubtreeRoot>, Self::Error> {
        Err(Unavailable)
    }
}

/// A chain that serves blocks normally but will not answer about transactions.
///
/// This is the case that matters most for enhancement, and it is not the same
/// as a chain that is simply down. A wallet talking to this source must keep
/// synchronising, must not treat silence as an answer, and above all must not
/// retire the request — a transport failure says nothing about whether the
/// transaction exists, and acting as though it did would expire live
/// transactions and hand back the notes they spend.
#[derive(Clone)]
pub struct UnservedTransactions {
    inner: InMemoryChain,
}

impl UnservedTransactions {
    /// Wraps a chain, refusing only its transaction lookups.
    pub fn new(inner: InMemoryChain) -> Self {
        Self { inner }
    }

    /// The chain underneath, for assertions about what was served.
    pub fn inner(&self) -> &InMemoryChain {
        &self.inner
    }
}

impl ChainSource for UnservedTransactions {
    type Error = Unavailable;

    async fn tip(&self) -> Result<ChainTip, Self::Error> {
        self.inner.tip().await.map_err(|_| Unavailable)
    }

    async fn anchor(&self, height: BlockHeight) -> Result<BlockAnchor, Self::Error> {
        self.inner.anchor(height).await.map_err(|_| Unavailable)
    }

    async fn fetch(
        &self,
        range: Range<BlockHeight>,
        budget: ByteBudget,
        direction: Direction,
    ) -> Result<Vec<CompactBlock>, Self::Error> {
        self.inner
            .fetch(range, budget, direction)
            .await
            .map_err(|_| Unavailable)
    }

    async fn address_utxos(
        &self,
        addresses: Vec<String>,
        start: BlockHeight,
    ) -> Result<Vec<crate::SweptUtxo>, Self::Error> {
        self.inner
            .address_utxos(addresses, start)
            .await
            .map_err(|_| Unavailable)
    }

    async fn transaction(
        &self,
        _txid: zcash_protocol::TxId,
    ) -> Result<Option<crate::FetchedTransaction>, Self::Error> {
        Err(Unavailable)
    }

    async fn subtree_roots(
        &self,
        pool: zakura_wallet_core::pool::PoolId,
        start_index: u64,
        limit: u32,
    ) -> Result<Vec<crate::SubtreeRoot>, Self::Error> {
        self.inner
            .subtree_roots(pool, start_index, limit)
            .await
            .map_err(|_| Unavailable)
    }
}
