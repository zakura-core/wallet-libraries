#![allow(clippy::needless_doctest_main)]
//! Tools for blockchain validation & scanning
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "test-dependencies")]
//! # {
//! use zcash_protocol::{
//!     consensus::{BlockHeight, Network, Parameters},
//! };
//!
//! use zcash_client_backend::{
//!     data_api::{
//!         WalletRead, WalletWrite, WalletCommitmentTrees,
//!         chain::{
//!             BlockSource,
//!             CommitmentTreeRoot,
//!             error::Error,
//!             scan_cached_blocks,
//!             testing as chain_testing,
//!         },
//!         scanning::ScanPriority,
//!         testing,
//!     },
//! };
//!
//! # use std::convert::Infallible;
//!
//! # fn main() {
//! #   test();
//! # }
//! #
//! # fn test() -> Result<(), Error<(), Infallible>> {
//! let network = Network::TestNetwork;
//! let block_source = chain_testing::MockBlockSource;
//! let mut wallet_db = testing::MockWalletDb::new(Network::TestNetwork);
//!
//! // 1) Download note commitment tree data from lightwalletd
//! let roots: Vec<CommitmentTreeRoot<sapling::Node>> = unimplemented!();
//!
//! // 2) Pass the commitment tree data to the database.
//! wallet_db.put_sapling_subtree_roots(0, &roots).unwrap();
//!
//! // 3) Download chain tip metadata from lightwalletd
//! let tip_height: BlockHeight = unimplemented!();
//!
//! // 4) Notify the wallet of the updated chain tip.
//! wallet_db.update_chain_tip(tip_height).map_err(Error::Wallet)?;
//!
//! // 5) Get the suggested scan ranges from the wallet database
//! let mut scan_ranges = wallet_db.suggest_scan_ranges().map_err(Error::Wallet)?;
//!
//! // 6) Run the following loop until the wallet's view of the chain tip as of the previous wallet
//! //    session is valid.
//! loop {
//!     // If there is a range of blocks that needs to be verified, it will always be returned as
//!     // the first element of the vector of suggested ranges.
//!     match scan_ranges.first() {
//!         Some(scan_range) if scan_range.priority() == ScanPriority::Verify => {
//!             // Download the chain state for the block prior to the start of the range you want
//!             // to scan.
//!             let chain_state = unimplemented!("get_chain_state(scan_range.block_range().start - 1)?;");
//!             // Download the blocks in `scan_range` into the block source, overwriting any
//!             // existing blocks in this range.
//!             unimplemented!("cache_blocks(scan_range)?;");
//!
//!             // Scan the downloaded blocks
//!             let scan_result = scan_cached_blocks(
//!                 &network,
//!                 &block_source,
//!                 &mut wallet_db,
//!                 scan_range.block_range().start,
//!                 chain_state,
//!                 scan_range.len()
//!             );
//!
//!             // Check for scanning errors that indicate that the wallet's chain tip is out of
//!             // sync with blockchain history.
//!             match scan_result {
//!                 Ok(_) => {
//!                     // At this point, the cache and scanned data are locally consistent (though
//!                     // not necessarily consistent with the latest chain tip - this would be
//!                     // discovered the next time this codepath is executed after new blocks are
//!                     // received) so we can break out of the loop.
//!                     break;
//!                 }
//!                 Err(Error::Scan(err)) if err.is_continuity_error() => {
//!                     // Pick a height to rewind to, which must be at least one block before
//!                     // the height at which the error occurred, but may be an earlier height
//!                     // determined based on heuristics such as the platform, available bandwidth,
//!                     // size of recent CompactBlocks, etc.
//!                     let rewind_height = err.at_height().saturating_sub(10);
//!
//!                     // Rewind to the chosen height.
//!                     wallet_db.truncate_to_height(rewind_height).map_err(Error::Wallet)?;
//!
//!                     // Delete cached blocks from rewind_height onwards.
//!                     //
//!                     // This does imply that assumed-valid blocks will be re-downloaded, but it
//!                     // is also possible that in the intervening time, a chain reorg has
//!                     // occurred that orphaned some of those blocks.
//!                     unimplemented!();
//!                 }
//!                 Err(other) => {
//!                     // Handle or return other errors
//!                 }
//!             }
//!
//!             // In case we updated the suggested scan ranges, now re-request.
//!             scan_ranges = wallet_db.suggest_scan_ranges().map_err(Error::Wallet)?;
//!         }
//!         _ => {
//!             // Nothing to verify; break out of the loop
//!             break;
//!         }
//!     }
//! }
//!
//! // 7) Loop over the remaining suggested scan ranges, retrieving the requested data and calling
//! //    `scan_cached_blocks` on each range. Periodically, or if a continuity error is
//! //    encountered, this process should be repeated starting at step (3).
//! let scan_ranges = wallet_db.suggest_scan_ranges().map_err(Error::Wallet)?;
//! for scan_range in scan_ranges {
//!     // Download the chain state for the block prior to the start of the range you want
//!     // to scan.
//!     let chain_state = unimplemented!("get_chain_state(scan_range.block_range().start - 1)?;");
//!     // Download the blocks in `scan_range` into the block source. While in this example this
//!     // step is performed in-line, it's fine for the download of scan ranges to be asynchronous
//!     // and for the scanner to process the downloaded ranges as they become available in a
//!     // separate thread. The scan ranges should also be broken down into smaller chunks as
//!     // appropriate, and for ranges with priority `Historic` it can be useful to download and
//!     // scan the range in reverse order (to discover more recent unspent notes sooner), or from
//!     // the start and end of the range inwards.
//!     unimplemented!("cache_blocks(scan_range)?;");
//!
//!     // Scan the downloaded blocks.
//!     let scan_result = scan_cached_blocks(
//!         &network,
//!         &block_source,
//!         &mut wallet_db,
//!         scan_range.block_range().start,
//!         chain_state,
//!         scan_range.len()
//!     )?;
//!
//!     // Handle scan errors, etc.
//! }
//! # Ok(())
//! # }
//! # }
//! ```

use std::collections::{HashMap, HashSet};
use std::ops::Range;

use incrementalmerkletree::frontier::Frontier;
use sapling::note_encryption::Zip212Enforcement;
use subtle::ConditionallySelectable;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::{
    block::BlockHash,
    transaction::{TxId, components::sapling::zip212_enforcement},
};
use zcash_protocol::consensus::{self, BlockHeight};
use zip32::Scope;

use crate::{
    data_api::{ScannedBlock, WalletWrite},
    proto::compact_formats::CompactBlock,
    scanning::{
        Nullifiers, ScanningKeys,
        compact::{BatchRunners, scan_block_with_runners},
    },
};

#[cfg(feature = "sync")]
use {
    super::scanning::ScanPriority, crate::data_api::scanning::ScanRange, async_trait::async_trait,
};

pub mod error;
use error::Error;

use super::WalletRead;
use crate::scanning::{InternalPass, InternalPassTriggers};

/// A struct containing metadata about a subtree root of the note commitment tree.
///
/// This stores the block height at which the leaf that completed the subtree was
/// added, and the root hash of the complete subtree.
#[derive(Debug)]
pub struct CommitmentTreeRoot<H> {
    subtree_end_height: BlockHeight,
    root_hash: H,
}

impl<H> CommitmentTreeRoot<H> {
    /// Construct a new `CommitmentTreeRoot` from its constituent parts.
    ///
    /// - `subtree_end_height`: The height of the block containing the note commitment that
    ///   completed the subtree.
    /// - `root_hash`: The Merkle root of the completed subtree.
    pub fn from_parts(subtree_end_height: BlockHeight, root_hash: H) -> Self {
        Self {
            subtree_end_height,
            root_hash,
        }
    }

    /// Returns the block height at which the leaf that completed the subtree was added.
    pub fn subtree_end_height(&self) -> BlockHeight {
        self.subtree_end_height
    }

    /// Returns the root of the complete subtree.
    pub fn root_hash(&self) -> &H {
        &self.root_hash
    }
}

/// This trait provides sequential access to raw blockchain data via a callback-oriented
/// API.
pub trait BlockSource {
    type Error;

    /// Scan the specified `limit` number of blocks from the blockchain, starting at
    /// `from_height`, applying the provided callback to each block. If `from_height`
    /// is `None` then scanning will begin at the first available block.
    ///
    /// * `WalletErrT`: the types of errors produced by the wallet operations performed
    ///   as part of processing each row.
    /// * `NoteRefT`: the type of note identifiers in the wallet data store, for use in
    ///   reporting errors related to specific notes.
    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        with_block: F,
    ) -> Result<(), error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), error::Error<WalletErrT, Self::Error>>;
}

/// `BlockCache` is a trait that extends `BlockSource` and defines methods for managing
/// a cache of compact blocks.
///
/// # Examples
///
/// ```
///    use async_trait::async_trait;
///    use std::sync::{Arc, Mutex};
///    use zcash_client_backend::data_api::{
///        chain::{error, BlockCache, BlockSource},
///        scanning::{ScanPriority, ScanRange},
///    };
///    use zcash_client_backend::proto::compact_formats::CompactBlock;
///    use zcash_protocol::consensus::BlockHeight;
///
///    struct ExampleBlockCache {
///        cached_blocks: Arc<Mutex<Vec<CompactBlock>>>,
///    }
///
/// #    impl BlockSource for ExampleBlockCache {
/// #        type Error = ();
/// #
/// #        fn with_blocks<F, WalletErrT>(
/// #            &self,
/// #            _from_height: Option<BlockHeight>,
/// #            _limit: Option<usize>,
/// #            _with_block: F,
/// #        ) -> Result<(), error::Error<WalletErrT, Self::Error>>
/// #        where
/// #            F: FnMut(CompactBlock) -> Result<(), error::Error<WalletErrT, Self::Error>>,
/// #        {
/// #            Ok(())
/// #        }
/// #    }
/// #
///    #[async_trait]
///    impl BlockCache for ExampleBlockCache {
///        fn get_tip_height(&self, range: Option<&ScanRange>) -> Result<Option<BlockHeight>, Self::Error> {
///            let cached_blocks = self.cached_blocks.lock().unwrap();
///            let blocks: Vec<&CompactBlock> = match range {
///                Some(range) => cached_blocks
///                    .iter()
///                    .filter(|&block| {
///                        let block_height = BlockHeight::from_u32(block.height as u32);
///                        range.block_range().contains(&block_height)
///                    })
///                    .collect(),
///                None => cached_blocks.iter().collect(),
///            };
///            let highest_block = blocks.iter().max_by_key(|&&block| block.height);
///            Ok(highest_block.map(|&block| BlockHeight::from_u32(block.height as u32)))
///        }
///
///        async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
///            Ok(self
///                .cached_blocks
///                .lock()
///                .unwrap()
///                .iter()
///                .filter(|block| {
///                    let block_height = BlockHeight::from_u32(block.height as u32);
///                    range.block_range().contains(&block_height)
///                })
///                .cloned()
///                .collect())
///        }
///
///        async fn insert(&self, mut compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
///            self.cached_blocks
///                .lock()
///                .unwrap()
///                .append(&mut compact_blocks);
///            Ok(())
///        }
///
///        async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
///            self.cached_blocks
///                .lock()
///                .unwrap()
///                .retain(|block| !range.block_range().contains(&BlockHeight::from_u32(block.height as u32)));
///            Ok(())
///        }
///    }
///
///    // Example usage
///    let rt = tokio::runtime::Runtime::new().unwrap();
///    let mut block_cache = ExampleBlockCache {
///        cached_blocks: Arc::new(Mutex::new(Vec::new())),
///    };
///    let range = ScanRange::from_parts(
///        BlockHeight::from_u32(1)..BlockHeight::from_u32(3),
///        ScanPriority::Historic,
///    );
/// #    let extsk = sapling::zip32::ExtendedSpendingKey::master(&[]);
/// #    let dfvk = extsk.to_diversifiable_full_viewing_key();
/// #    let compact_block1 = zcash_client_backend::scanning::testing::fake_compact_block(
/// #        1u32.into(),
/// #        zcash_primitives::block::BlockHash([0; 32]),
/// #        sapling::Nullifier([0; 32]),
/// #        &dfvk,
/// #        zcash_protocol::value::Zatoshis::const_from_u64(5),
/// #        false,
/// #        None,
/// #    );
/// #    let compact_block2 = zcash_client_backend::scanning::testing::fake_compact_block(
/// #        2u32.into(),
/// #        zcash_primitives::block::BlockHash([0; 32]),
/// #        sapling::Nullifier([0; 32]),
/// #        &dfvk,
/// #        zcash_protocol::value::Zatoshis::const_from_u64(5),
/// #        false,
/// #        None,
/// #    );
///    let compact_blocks = vec![compact_block1, compact_block2];
///
///    // Insert blocks into the block cache
///    rt.block_on(async {
///        block_cache.insert(compact_blocks.clone()).await.unwrap();
///    });
///    assert_eq!(block_cache.cached_blocks.lock().unwrap().len(), 2);
///
///    // Find highest block in the block cache
///    let get_tip_height = block_cache.get_tip_height(None).unwrap();
///    assert_eq!(get_tip_height, Some(BlockHeight::from_u32(2)));
///
///    // Read from the block cache
///    rt.block_on(async {
///        let blocks_from_cache = block_cache.read(&range).await.unwrap();
///        assert_eq!(blocks_from_cache, compact_blocks);
///    });
///
///    // Truncate the block cache
///    rt.block_on(async {
///        block_cache.truncate(BlockHeight::from_u32(1)).await.unwrap();
///    });
///    assert_eq!(block_cache.cached_blocks.lock().unwrap().len(), 1);
///    assert_eq!(
///        block_cache.get_tip_height(None).unwrap(),
///        Some(BlockHeight::from_u32(1))
///    );
///
///    // Delete blocks from the block cache
///    rt.block_on(async {
///        block_cache.delete(range).await.unwrap();
///    });
///    assert_eq!(block_cache.cached_blocks.lock().unwrap().len(), 0);
///    assert_eq!(block_cache.get_tip_height(None).unwrap(), None);
/// ```
#[cfg(feature = "sync")]
#[async_trait]
pub trait BlockCache: BlockSource + Send + Sync
where
    Self::Error: Send,
{
    /// Finds the height of the highest block known to the block cache within a specified range.
    ///
    /// If `range` is `None`, returns the tip of the entire cache.
    /// If no blocks are found in the cache, returns Ok(`None`).
    fn get_tip_height(&self, range: Option<&ScanRange>)
    -> Result<Option<BlockHeight>, Self::Error>;

    /// Retrieves contiguous compact blocks specified by the given `range` from the block cache.
    ///
    /// Short reads are allowed, meaning that this method may return fewer blocks than requested
    /// provided that all returned blocks are contiguous and start from `range.block_range().start`.
    ///
    /// # Errors
    ///
    /// This method should return an error if contiguous blocks cannot be read from the cache,
    /// indicating there are blocks missing.
    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error>;

    /// Inserts a vec of compact blocks into the block cache.
    ///
    /// This method permits insertion of non-contiguous compact blocks.
    async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error>;

    /// Removes all cached blocks above a specified block height.
    async fn truncate(&self, block_height: BlockHeight) -> Result<(), Self::Error> {
        if let Some(latest) = self.get_tip_height(None)? {
            self.delete(ScanRange::from_parts(
                Range {
                    start: block_height + 1,
                    end: latest + 1,
                },
                ScanPriority::Ignored,
            ))
            .await?;
        }
        Ok(())
    }

    /// Deletes a range of compact blocks from the block cache.
    ///
    /// # Errors
    ///
    /// In the case of an error, some blocks requested for deletion may remain in the block cache.
    async fn delete(&self, range: ScanRange) -> Result<(), Self::Error>;
}

/// Metadata about modifications to the wallet state made in the course of scanning a set of
/// blocks.
#[derive(Clone, Debug)]
pub struct ScanSummary {
    pub(crate) scanned_range: Range<BlockHeight>,
    pub(crate) spent_sapling_note_count: usize,
    pub(crate) received_sapling_note_count: usize,
    #[cfg(feature = "orchard")]
    pub(crate) spent_orchard_note_count: usize,
    #[cfg(feature = "orchard")]
    pub(crate) received_orchard_note_count: usize,
}

impl ScanSummary {
    /// Constructs a new [`ScanSummary`] for the provided block range.
    pub(crate) fn for_range(scanned_range: Range<BlockHeight>) -> Self {
        Self {
            scanned_range,
            spent_sapling_note_count: 0,
            received_sapling_note_count: 0,
            #[cfg(feature = "orchard")]
            spent_orchard_note_count: 0,
            #[cfg(feature = "orchard")]
            received_orchard_note_count: 0,
        }
    }

    /// Returns the range of blocks successfully scanned.
    pub fn scanned_range(&self) -> Range<BlockHeight> {
        self.scanned_range.clone()
    }

    /// Returns the number of our previously-detected Sapling notes that were spent in transactions
    /// in blocks in the scanned range. If we have not yet detected a particular note as ours, for
    /// example because we are scanning the chain in reverse height order, we will not detect it
    /// being spent at this time.
    pub fn spent_sapling_note_count(&self) -> usize {
        self.spent_sapling_note_count
    }

    /// Returns the number of Sapling notes belonging to the wallet that were received in blocks in
    /// the scanned range. Note that depending upon the scanning order, it is possible that some of
    /// the received notes counted here may already have been spent in later blocks closer to the
    /// chain tip.
    pub fn received_sapling_note_count(&self) -> usize {
        self.received_sapling_note_count
    }

    /// Returns the number of our previously-detected Orchard notes that were spent in transactions
    /// in blocks in the scanned range. If we have not yet detected a particular note as ours, for
    /// example because we are scanning the chain in reverse height order, we will not detect it
    /// being spent at this time.
    #[cfg(feature = "orchard")]
    pub fn spent_orchard_note_count(&self) -> usize {
        self.spent_orchard_note_count
    }

    /// Returns the number of Orchard notes belonging to the wallet that were received in blocks in
    /// the scanned range. Note that depending upon the scanning order, it is possible that some of
    /// the received notes counted here may already have been spent in later blocks closer to the
    /// chain tip.
    #[cfg(feature = "orchard")]
    pub fn received_orchard_note_count(&self) -> usize {
        self.received_orchard_note_count
    }
}

/// The final note commitment tree state for each shielded pool, as of a particular block height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    block_height: BlockHeight,
    block_hash: BlockHash,
    final_sapling_tree: Frontier<sapling::Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>,
    #[cfg(feature = "orchard")]
    final_orchard_tree:
        Frontier<orchard::tree::MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
    // The Ironwood note commitment tree is Orchard-shaped, but Ironwood is a distinct pool with
    // its own tree, tracked separately from Orchard.
    #[cfg(feature = "orchard")]
    final_ironwood_tree:
        Frontier<orchard::tree::MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
}

impl ChainState {
    /// Construct a new empty chain state.
    pub fn empty(block_height: BlockHeight, block_hash: BlockHash) -> Self {
        Self {
            block_height,
            block_hash,
            final_sapling_tree: Frontier::empty(),
            #[cfg(feature = "orchard")]
            final_orchard_tree: Frontier::empty(),
            #[cfg(feature = "orchard")]
            final_ironwood_tree: Frontier::empty(),
        }
    }

    /// Construct a new [`ChainState`] from its constituent parts.
    pub fn new(
        block_height: BlockHeight,
        block_hash: BlockHash,
        final_sapling_tree: Frontier<sapling::Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>,
        #[cfg(feature = "orchard")] final_orchard_tree: Frontier<
            orchard::tree::MerkleHashOrchard,
            { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
        >,
        #[cfg(feature = "orchard")] final_ironwood_tree: Frontier<
            orchard::tree::MerkleHashOrchard,
            { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
        >,
    ) -> Self {
        Self {
            block_height,
            block_hash,
            final_sapling_tree,
            #[cfg(feature = "orchard")]
            final_orchard_tree,
            #[cfg(feature = "orchard")]
            final_ironwood_tree,
        }
    }

    /// Returns the block height to which this chain state applies.
    pub fn block_height(&self) -> BlockHeight {
        self.block_height
    }

    /// Return the hash of the block.
    pub fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    /// Returns the frontier of the Sapling note commitment tree as of the end of the block at
    /// [`Self::block_height`].
    pub fn final_sapling_tree(
        &self,
    ) -> &Frontier<sapling::Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }> {
        &self.final_sapling_tree
    }

    /// Returns the frontier of the Orchard note commitment tree as of the end of the block at
    /// [`Self::block_height`].
    #[cfg(feature = "orchard")]
    pub fn final_orchard_tree(
        &self,
    ) -> &Frontier<orchard::tree::MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>
    {
        &self.final_orchard_tree
    }

    /// Returns the frontier of the Ironwood note commitment tree as of the end of the block at
    /// [`Self::block_height`].
    #[cfg(feature = "orchard")]
    pub fn final_ironwood_tree(
        &self,
    ) -> &Frontier<orchard::tree::MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>
    {
        &self.final_ironwood_tree
    }
}

/// Scans at most `limit` blocks from the provided block source in order to find transactions
/// received by the accounts tracked in the provided wallet database.
///
/// This function will return after scanning at most `limit` new blocks, to enable the caller to
/// update their UI with scanning progress.
///
/// The blocks are scanned for the accounts whose birthday is at or below the last of these
/// `limit` heights. An account with a later birthday cannot have received notes in the range,
/// so its viewing keys are not tried against the range's outputs. A range that reaches an
/// account's birthday is scanned for that account in all of its blocks, so whether a note sent
/// to the account below its birthday is found depends on where the ranges begin and end.
///
/// ## Errors
///
/// - [`Error::BlockSource`] if the requested blocks cannot be read from `block_source`.
/// - [`Error::Scan`] if a scanned block violates chain-continuity rules or contains note
///   commitments that cannot be reconciled with the wallet's note commitment tree(s).
/// - [`Error::Wallet`] if a wallet-database operation fails. This covers reading the tracked
///   viewing keys, block metadata, and nullifiers, as well as persisting the scanned blocks via
///   [`WalletWrite::put_blocks`]. In particular, a failure to update the note commitment trees
///   with the scanned data is reported here (for example, the `zcash_client_sqlite` backend
///   surfaces such a failure as a `PutBlocksCommitmentTree` error identifying the affected
///   shielded pool and block range).
///
/// ## Panics
///
/// This method will panic if `from_height != from_state.block_height() + 1`.
#[tracing::instrument(skip(params, block_source, data_db, from_state))]
#[allow(clippy::type_complexity)]
pub fn scan_cached_blocks<ParamsT, DbT, BlockSourceT>(
    params: &ParamsT,
    block_source: &BlockSourceT,
    data_db: &mut DbT,
    from_height: BlockHeight,
    from_state: &ChainState,
    limit: usize,
) -> Result<ScanSummary, Error<<DbT as WalletRead>::Error, BlockSourceT::Error>>
where
    ParamsT: consensus::Parameters + Send + 'static,
    BlockSourceT: BlockSource,
    DbT: WalletWrite,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
{
    assert_eq!(from_height, from_state.block_height + 1);

    let account_ufvks =
        account_ufvks_for_range(&*data_db, from_height, limit).map_err(Error::Wallet)?;
    let scanning_keys = ScanningKeys::from_account_ufvks(account_ufvks);
    let (scan_summary, scanned_blocks) = scan_blocks(
        params,
        block_source,
        data_db,
        from_height,
        limit,
        &scanning_keys,
        None,
    )?;

    data_db
        .put_blocks(from_state, scanned_blocks)
        .map_err(Error::Wallet)?;
    Ok(scan_summary)
}

/// How far a caller has retrieved and stored the transactions that involve the wallet's
/// transparent addresses.
///
/// A compact block carries the transparent inputs of its transactions only when the client asks
/// the server for the transparent pool, which no current light wallet does. A transaction that
/// shields transparent funds into an account's internal receiver is therefore indistinguishable,
/// in compact data alone, from a payment to a third party.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransparentHistory {
    /// Every transaction that involves a transparent address of the wallet and is mined at or
    /// below the given height is already stored in the wallet.
    ///
    /// Calling `forget_transparent_ledger` revokes this guarantee because it deletes TPIR-only
    /// `transactions` rows while leaving `blocks` intact.
    SyncedTo(BlockHeight),
    /// The caller gives no such guarantee.
    Unsynced,
}

impl TransparentHistory {
    /// Whether the guarantee extends to `height`.
    fn covers(&self, height: BlockHeight) -> bool {
        match self {
            Self::SyncedTo(synced) => height <= *synced,
            Self::Unsynced => false,
        }
    }
}

/// Monotone ownership evidence that a backend supplies for an external-only linear scan.
///
/// Every entry records a monotone ownership fact ("the wallet stored this txid" or "the wallet
/// stored a note with this nullifier"), never status-filtered belief. The scanner uses these sets
/// only to decide whether to run the inline internal-key pass on a transaction; spend recording
/// continues to use [`WalletRead::get_sapling_nullifiers`] and its pool counterparts with
/// [`NullifierQuery::Unspent`].
///
/// [`NullifierQuery::Unspent`]: crate::data_api::NullifierQuery::Unspent
#[derive(Clone, Debug)]
pub struct LinearScanEvidence {
    known_txids: HashSet<TxId>,
    sapling_nullifiers: HashSet<[u8; 32]>,
    #[cfg(feature = "orchard")]
    orchard_nullifiers: HashSet<[u8; 32]>,
    #[cfg(feature = "orchard")]
    ironwood_nullifiers: HashSet<[u8; 32]>,
}

impl LinearScanEvidence {
    /// Constructs linear-scan trigger evidence from the wallet's stored txids and nullifiers.
    pub fn new(
        known_txids: HashSet<TxId>,
        sapling_nullifiers: impl IntoIterator<Item = sapling::Nullifier>,
        #[cfg(feature = "orchard")] orchard_nullifiers: impl IntoIterator<
            Item = orchard::note::Nullifier,
        >,
        #[cfg(feature = "orchard")] ironwood_nullifiers: impl IntoIterator<
            Item = orchard::note::Nullifier,
        >,
    ) -> Self {
        Self {
            known_txids,
            sapling_nullifiers: sapling_nullifiers.into_iter().map(|nf| nf.0).collect(),
            #[cfg(feature = "orchard")]
            orchard_nullifiers: orchard_nullifiers
                .into_iter()
                .map(|nf| nf.to_bytes())
                .collect(),
            #[cfg(feature = "orchard")]
            ironwood_nullifiers: ironwood_nullifiers
                .into_iter()
                .map(|nf| nf.to_bytes())
                .collect(),
        }
    }

    /// Returns all txids stored in the wallet.
    pub fn known_txids(&self) -> &HashSet<TxId> {
        &self.known_txids
    }

    /// Returns whether `nf` is among the wallet's stored Sapling nullifiers.
    pub fn contains_sapling_nullifier(&self, nf: &sapling::Nullifier) -> bool {
        self.sapling_nullifiers.contains(&nf.0)
    }

    /// Returns whether `nf` is among the wallet's stored Orchard nullifiers.
    #[cfg(feature = "orchard")]
    pub fn contains_orchard_nullifier(&self, nf: &orchard::note::Nullifier) -> bool {
        self.orchard_nullifiers.contains(&nf.to_bytes())
    }

    /// Returns whether `nf` is among the wallet's stored Ironwood nullifiers.
    #[cfg(feature = "orchard")]
    pub fn contains_ironwood_nullifier(&self, nf: &orchard::note::Nullifier) -> bool {
        self.ironwood_nullifiers.contains(&nf.to_bytes())
    }

    fn into_triggers(self) -> InternalPassTriggers {
        InternalPassTriggers {
            wallet_spend: true,
            known_txids: self.known_txids,
            known_sapling_nullifiers: self.sapling_nullifiers,
            #[cfg(feature = "orchard")]
            known_orchard_nullifiers: self.orchard_nullifiers,
            #[cfg(feature = "orchard")]
            known_ironwood_nullifiers: self.ironwood_nullifiers,
            transparent_inputs_or_coinbase: true,
        }
    }
}

/// What a caller guarantees about the blocks that precede a scan.
///
/// A pipelined driver that decrypts batch N+1 while batch N writes are still in flight leaves the
/// wallet's stored frontier behind batch N+1. Passing [`Self::with_writes_issued_through`] to
/// [`decrypt_cached_blocks_with_policy`] lets prediction select external-only decryption; at scan
/// time, [`scan_decrypted_blocks`] verifies linearity against the stored frontier alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinearScanGuarantee {
    transparent_history: TransparentHistory,
    writes_issued_through: Option<BlockHeight>,
}

impl LinearScanGuarantee {
    /// A guarantee that rests on the wallet's stored state alone.
    pub const fn new(transparent_history: TransparentHistory) -> Self {
        Self {
            transparent_history,
            writes_issued_through: None,
        }
    }

    /// Declares that every block up to and including `height` has been scanned and its writes
    /// issued in block order.
    ///
    /// A pipelined driver must pass `with_writes_issued_through(end - 1)` when prefetching the
    /// next batch with [`decrypt_cached_blocks_with_policy`], so prediction selects external-only
    /// keys before the prior batch commits. At scan time, [`scan_decrypted_blocks`] and
    /// [`scan_cached_blocks_with_policy`] re-check linearity against the stored frontier alone;
    /// a misdeclared height falls back safely to all scopes rather than missing outputs.
    pub const fn with_writes_issued_through(self, height: BlockHeight) -> Self {
        Self {
            writes_issued_through: Some(height),
            ..self
        }
    }

    /// The caller's transparent-history guarantee.
    pub const fn transparent_history(&self) -> TransparentHistory {
        self.transparent_history
    }
}

/// How [`scan_cached_blocks_with_policy`] chooses the viewing-key scopes it trial-decrypts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrialDecryptionPolicy {
    /// Every output is trial-decrypted with the external and internal viewing keys of every
    /// account: the behaviour of [`scan_cached_blocks`].
    AllScopes,
    /// When the scan is linear, the range contains no previously stored blocks, and the guarantee
    /// covers every block the scan may reach, outputs are trial-decrypted with external keys only
    /// and transactions selected by monotone wallet triggers also run internal keys; otherwise
    /// this behaves as [`Self::AllScopes`].
    ///
    /// Premise: only an account's own spending key pays its internal receiver. Rescans of
    /// already-stored blocks always use [`Self::AllScopes`].
    ExternalWhenLinear(LinearScanGuarantee),
}

/// Returns the greatest height a scan of at most `limit` blocks from `from_height` can reach.
fn batch_end(from_height: BlockHeight, limit: usize) -> BlockHeight {
    let limit = u32::try_from(limit).unwrap_or(u32::MAX);
    BlockHeight::from(u32::from(from_height).saturating_add(limit.saturating_sub(1)))
}

/// Returns the half-open block range for a scan of at most `limit` blocks from `from_height`.
fn batch_range(from_height: BlockHeight, limit: usize) -> Range<BlockHeight> {
    let limit = u32::try_from(limit).unwrap_or(u32::MAX);
    let end = BlockHeight::from(u32::from(from_height).saturating_add(limit));
    from_height..end
}

/// Returns whether every block from the wallet's birthday up to `from_height` has been scanned.
fn is_linear<DbT: WalletRead>(
    db: &DbT,
    from_height: BlockHeight,
    writes_issued_through: Option<BlockHeight>,
) -> Result<bool, DbT::Error> {
    let stored = match db.block_fully_scanned()? {
        Some(meta) => Some(meta.block_height() + 1),
        None => db.get_wallet_birthday()?,
    };
    let declared = writes_issued_through.map(|height| height + 1);
    let frontier = match (stored, declared) {
        (Some(stored), Some(declared)) => Some(std::cmp::max(stored, declared)),
        (frontier, None) | (None, frontier) => frontier,
    };
    Ok(frontier.is_some_and(|frontier| from_height <= frontier))
}

/// Evaluates the scan-time gate against the stored frontier alone and loads monotone evidence.
///
/// Returns `Ok(None)` when the guarantee does not cover the batch, when the stored frontier has
/// a gap before `from_height`, or when the backend vetoes the range (for example, on a rescan).
fn external_only_triggers<DbT: WalletRead>(
    db: &DbT,
    from_height: BlockHeight,
    limit: usize,
    guarantee: LinearScanGuarantee,
) -> Result<Option<InternalPassTriggers>, DbT::Error> {
    if !guarantee
        .transparent_history()
        .covers(batch_end(from_height, limit))
        || !is_linear(db, from_height, None)?
    {
        return Ok(None);
    }
    Ok(db
        .linear_scan_evidence(batch_range(from_height, limit))?
        .map(LinearScanEvidence::into_triggers))
}

/// Scans as [`scan_cached_blocks`] does, trial-decrypting with the scopes `policy` selects.
///
/// ## Panics
///
/// This method will panic if `from_height != from_state.block_height() + 1`.
#[tracing::instrument(skip(params, block_source, data_db, from_state))]
#[allow(clippy::type_complexity)]
pub fn scan_cached_blocks_with_policy<ParamsT, DbT, BlockSourceT>(
    params: &ParamsT,
    block_source: &BlockSourceT,
    data_db: &mut DbT,
    from_height: BlockHeight,
    from_state: &ChainState,
    limit: usize,
    policy: TrialDecryptionPolicy,
) -> Result<ScanSummary, Error<<DbT as WalletRead>::Error, BlockSourceT::Error>>
where
    ParamsT: consensus::Parameters + Send + 'static,
    BlockSourceT: BlockSource,
    DbT: WalletWrite,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
{
    let triggers = match policy {
        TrialDecryptionPolicy::AllScopes => None,
        TrialDecryptionPolicy::ExternalWhenLinear(guarantee) => {
            external_only_triggers(&*data_db, from_height, limit, guarantee)
                .map_err(Error::Wallet)?
        }
    };
    scan_cached_blocks_in_mode(
        params,
        block_source,
        data_db,
        from_height,
        from_state,
        limit,
        triggers,
    )
}

/// Scans as [`scan_cached_blocks`] does, with external keys only plus an inline internal pass on
/// the transactions `triggers` select, or with every scope when `triggers` is `None`.
#[allow(clippy::type_complexity)]
pub(crate) fn scan_cached_blocks_in_mode<ParamsT, DbT, BlockSourceT>(
    params: &ParamsT,
    block_source: &BlockSourceT,
    data_db: &mut DbT,
    from_height: BlockHeight,
    from_state: &ChainState,
    limit: usize,
    triggers: Option<InternalPassTriggers>,
) -> Result<ScanSummary, Error<<DbT as WalletRead>::Error, BlockSourceT::Error>>
where
    ParamsT: consensus::Parameters + Send + 'static,
    BlockSourceT: BlockSource,
    DbT: WalletWrite,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
{
    assert_eq!(from_height, from_state.block_height + 1);

    let account_ufvks =
        account_ufvks_for_range(&*data_db, from_height, limit).map_err(Error::Wallet)?;
    let (scanning_keys, internal_keys) = match &triggers {
        None => (ScanningKeys::from_account_ufvks(account_ufvks), None),
        Some(_) => (
            ScanningKeys::from_account_ufvks_with_scopes(account_ufvks.clone(), &[Scope::External]),
            Some(ScanningKeys::from_account_ufvks_with_scopes(
                account_ufvks,
                &[Scope::Internal],
            )),
        ),
    };
    let internal_pass = internal_keys
        .as_ref()
        .zip(triggers.as_ref())
        .map(|(keys, triggers)| InternalPass { keys, triggers });

    let (scan_summary, scanned_blocks) = scan_blocks(
        params,
        block_source,
        data_db,
        from_height,
        limit,
        &scanning_keys,
        internal_pass,
    )?;

    data_db
        .put_blocks(from_state, scanned_blocks)
        .map_err(Error::Wallet)?;
    Ok(scan_summary)
}

/// Trial decryption of a range of cached blocks, started by [`decrypt_cached_blocks`]
/// before the range is scanned with [`scan_decrypted_blocks`].
///
/// Its work runs on the rayon thread pool that was current when it was started, so a
/// caller can let it run while it writes the previous range.
/// The internal-scope keys of a [`BlockDecryption`] and the caller's guarantee.
///
/// Trigger evidence and the stored-frontier gate are not frozen here; [`scan_decrypted_blocks`]
/// evaluates them at scan time.
type InlinePass<AccountId> = (
    ScanningKeys<AccountId, (AccountId, Scope)>,
    LinearScanGuarantee,
);

pub struct BlockDecryption<AccountId: Copy + Eq + std::hash::Hash + Send + Sync + 'static> {
    from_height: BlockHeight,
    limit: usize,
    /// Each decrypted block, in order. Decryption results are looked up by block hash and
    /// txid, and a missing result reads as "no notes", so the scan checks each block it
    /// reads against these and uses the decryption only if the blocks, and the ZIP 212
    /// enforcement the scan's parameters give them, are exactly these.
    blocks: Vec<DecryptedBlock>,
    /// The encoded viewing keys the decryption used, so that a scan after an account
    /// change decrypts again.
    encoded_ufvks: HashMap<AccountId, String>,
    scanning_keys: ScanningKeys<AccountId, (AccountId, Scope)>,
    runners: BatchRunners<(AccountId, Scope), (), (), ()>,
    /// The internal-scope keys and the triggers that select the transactions they are applied
    /// to, when the decryption was started with external keys only. `None` means the
    /// decryption covers every scope, so no inline pass is needed.
    internal_pass: Option<InlinePass<AccountId>>,
}

/// Starts trial decryption of at most `limit` cached blocks from `from_height` with the
/// viewing keys [`scan_cached_blocks`] would scan them with, for a later
/// [`scan_decrypted_blocks`] of the same blocks.
///
/// It reads the blocks once to queue their outputs, and returns while the decryption
/// still runs on the current rayon thread pool. It reads `data_db` but does not write it.
///
/// ## Errors
///
/// - [`Error::BlockSource`] if the requested blocks cannot be read from `block_source`.
/// - [`Error::Wallet`] if the tracked viewing keys cannot be read.
#[tracing::instrument(skip(params, block_source, data_db))]
#[allow(clippy::type_complexity)]
pub fn decrypt_cached_blocks<ParamsT, DbT, BlockSourceT>(
    params: &ParamsT,
    block_source: &BlockSourceT,
    data_db: &DbT,
    from_height: BlockHeight,
    limit: usize,
) -> Result<
    BlockDecryption<<DbT as WalletRead>::AccountId>,
    Error<<DbT as WalletRead>::Error, BlockSourceT::Error>,
>
where
    ParamsT: consensus::Parameters + Send + 'static,
    BlockSourceT: BlockSource,
    DbT: WalletRead,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
{
    decrypt_cached_blocks_with_policy(
        params,
        block_source,
        data_db,
        from_height,
        limit,
        TrialDecryptionPolicy::AllScopes,
    )
}

/// Starts trial decryption as [`decrypt_cached_blocks`] does, with the viewing-key scopes
/// `policy` selects.
///
/// The scope choice is made here rather than in [`scan_decrypted_blocks`], because this is
/// where the batch runners that do the decryption are built. A caller that prefetches must
/// therefore pass the policy to this function; passing it only to the scan would have no
/// effect.
#[tracing::instrument(skip(params, block_source, data_db))]
#[allow(clippy::type_complexity)]
pub fn decrypt_cached_blocks_with_policy<ParamsT, DbT, BlockSourceT>(
    params: &ParamsT,
    block_source: &BlockSourceT,
    data_db: &DbT,
    from_height: BlockHeight,
    limit: usize,
    policy: TrialDecryptionPolicy,
) -> Result<
    BlockDecryption<<DbT as WalletRead>::AccountId>,
    Error<<DbT as WalletRead>::Error, BlockSourceT::Error>,
>
where
    ParamsT: consensus::Parameters + Send + 'static,
    BlockSourceT: BlockSource,
    DbT: WalletRead,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
{
    let account_ufvks =
        account_ufvks_for_range(data_db, from_height, limit).map_err(Error::Wallet)?;
    let encoded_ufvks = encode_ufvks(params, &account_ufvks);

    let predicted_guarantee = match policy {
        TrialDecryptionPolicy::AllScopes => None,
        TrialDecryptionPolicy::ExternalWhenLinear(guarantee) => {
            // Predict whether the scan-time gate will accept external-only keys, including the
            // backend's stored-block rescan veto, without freezing trigger evidence in
            // `BlockDecryption`.
            if guarantee
                .transparent_history()
                .covers(batch_end(from_height, limit))
                && is_linear(data_db, from_height, guarantee.writes_issued_through)
                    .map_err(Error::Wallet)?
                && data_db
                    .linear_scan_evidence(batch_range(from_height, limit))
                    .map_err(Error::Wallet)?
                    .is_some()
            {
                Some(guarantee)
            } else {
                None
            }
        }
    };
    let (scanning_keys, internal_pass) = match predicted_guarantee {
        None => (ScanningKeys::from_account_ufvks(account_ufvks), None),
        Some(guarantee) => (
            ScanningKeys::from_account_ufvks_with_scopes(account_ufvks.clone(), &[Scope::External]),
            Some((
                ScanningKeys::from_account_ufvks_with_scopes(account_ufvks, &[Scope::Internal]),
                guarantee,
            )),
        ),
    };
    let mut runners = BatchRunners::<_, (), (), ()>::for_keys(100, &scanning_keys);
    let mut blocks = vec![];
    block_source.with_blocks::<_, <DbT as WalletRead>::Error>(
        Some(from_height),
        Some(limit),
        |block| {
            blocks.push(DecryptedBlock::new(params, &block));
            runners.add_block(params, block).map_err(|e| e.into())
        },
    )?;
    runners.flush();

    Ok(BlockDecryption {
        from_height,
        limit,
        blocks,
        encoded_ufvks,
        scanning_keys,
        runners,
        internal_pass,
    })
}

/// Scans at most `limit` cached blocks from `from_height` and stores them, as
/// [`scan_cached_blocks`] does, using the trial decryption `decryption` that
/// [`decrypt_cached_blocks`] started.
///
/// `decryption` is used only if it covers the same `from_height` and `limit` and the
/// viewing keys [`scan_cached_blocks`] would scan the range with now, and only for the
/// blocks it decrypted under the
/// ZIP 212 enforcement that `params` gives them: the scan compares each block it reads,
/// and that enforcement at its height, with the decrypted block at the same position. If
/// either differs, or the scan reads a different number of blocks, the blocks scanned so
/// far are discarded before anything is stored, and the range is scanned as
/// [`scan_cached_blocks`] scans it, with the viewing keys read at the start of this call.
/// A decryption of other blocks, under other keys or under another ZIP 212 enforcement
/// therefore never decides which notes are found.
///
/// ## Errors
///
/// As for [`scan_cached_blocks`].
///
/// ## Panics
///
/// This method will panic if `from_height != from_state.block_height() + 1`.
#[tracing::instrument(skip(params, block_source, data_db, from_state, decryption))]
#[allow(clippy::type_complexity)]
pub fn scan_decrypted_blocks<ParamsT, DbT, BlockSourceT>(
    params: &ParamsT,
    block_source: &BlockSourceT,
    data_db: &mut DbT,
    from_height: BlockHeight,
    from_state: &ChainState,
    limit: usize,
    decryption: BlockDecryption<<DbT as WalletRead>::AccountId>,
) -> Result<ScanSummary, Error<<DbT as WalletRead>::Error, BlockSourceT::Error>>
where
    ParamsT: consensus::Parameters + Send + 'static,
    BlockSourceT: BlockSource,
    DbT: WalletWrite,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
{
    assert_eq!(from_height, from_state.block_height + 1);

    let current_ufvks =
        account_ufvks_for_range(&*data_db, from_height, limit).map_err(Error::Wallet)?;
    let scan_pass = if decryption.from_height == from_height
        && decryption.limit == limit
        && decryption.encoded_ufvks == encode_ufvks(params, &current_ufvks)
    {
        let BlockDecryption {
            blocks,
            scanning_keys,
            runners,
            internal_pass,
            ..
        } = decryption;
        let resolved_internal = match internal_pass {
            None => Some(None),
            Some((keys, guarantee)) => {
                // Re-check linearity against the stored frontier and reload monotone evidence at
                // scan time. Any veto makes the external-only prefetch stale and falls back to all
                // scopes.
                external_only_triggers(&*data_db, from_height, limit, guarantee)
                    .map_err(Error::Wallet)?
                    .map(|triggers| Some((keys, triggers)))
            }
        };
        match resolved_internal {
            None => ScanPass::Stale,
            Some(inline) => {
                let internal_pass = inline
                    .as_ref()
                    .map(|(keys, triggers)| InternalPass { keys, triggers });
                scan_with_runners(
                    params,
                    block_source,
                    data_db,
                    from_height,
                    limit,
                    &scanning_keys,
                    internal_pass,
                    runners,
                    Some(&blocks),
                )?
            }
        }
    } else {
        ScanPass::Stale
    };
    let (scan_summary, scanned_blocks) = match scan_pass {
        ScanPass::Scanned(scan_summary, scanned_blocks) => (scan_summary, scanned_blocks),
        // Nothing has been stored, so the range is scanned as `scan_cached_blocks` scans it.
        ScanPass::Stale => scan_blocks(
            params,
            block_source,
            data_db,
            from_height,
            limit,
            &ScanningKeys::from_account_ufvks(current_ufvks),
            None,
        )?,
    };

    data_db
        .put_blocks(from_state, scanned_blocks)
        .map_err(Error::Wallet)?;
    Ok(scan_summary)
}

fn encode_ufvks<ParamsT: consensus::Parameters, AccountId: Copy + Eq + std::hash::Hash>(
    params: &ParamsT,
    account_ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
) -> HashMap<AccountId, String> {
    account_ufvks
        .iter()
        .map(|(account, ufvk)| (*account, ufvk.encode(params)))
        .collect()
}

/// The viewing keys of the accounts that the at most `limit` blocks from `from_height` are
/// scanned for: those whose birthday is at or below the last of these heights.
///
/// An account's birthday is the first block that can hold its notes, and the wallet stores
/// only blocks from `from_height` in sequence, so the scan stores no block above that last
/// height.
fn account_ufvks_for_range<DbT: WalletRead>(
    data_db: &DbT,
    from_height: BlockHeight,
    limit: usize,
) -> Result<HashMap<<DbT as WalletRead>::AccountId, UnifiedFullViewingKey>, DbT::Error> {
    let end = u64::from(from_height).saturating_add(u64::try_from(limit).unwrap_or(u64::MAX));
    let mut account_ufvks = HashMap::new();
    for (account, ufvk) in data_db.get_unified_full_viewing_keys()? {
        if u64::from(data_db.get_account_birthday(account)?) < end {
            account_ufvks.insert(account, ufvk);
        }
    }
    Ok(account_ufvks)
}

/// What the trial decryption of a block depends on besides the viewing keys.
#[derive(Clone, Copy, PartialEq, Eq)]
struct DecryptedBlock {
    /// The block's hash, by which its decryption results are looked up.
    hash: BlockHash,
    /// The ZIP 212 enforcement under which its Sapling outputs are decrypted, which the
    /// consensus parameters decide.
    zip212_enforcement: Zip212Enforcement,
}

impl DecryptedBlock {
    fn new<ParamsT: consensus::Parameters>(params: &ParamsT, block: &CompactBlock) -> Self {
        DecryptedBlock {
            hash: block.hash(),
            zip212_enforcement: zip212_enforcement(params, block.height()),
        }
    }
}

/// Scans at most `limit` blocks from `from_height` with `scanning_keys`, for
/// [`scan_cached_blocks`], returning the blocks to store.
#[allow(clippy::type_complexity)]
fn scan_blocks<ParamsT, DbT, BlockSourceT, IvkTag>(
    params: &ParamsT,
    block_source: &BlockSourceT,
    data_db: &DbT,
    from_height: BlockHeight,
    limit: usize,
    scanning_keys: &ScanningKeys<<DbT as WalletRead>::AccountId, IvkTag>,
    internal_pass: Option<InternalPass<'_, <DbT as WalletRead>::AccountId, IvkTag>>,
) -> Result<
    (
        ScanSummary,
        Vec<ScannedBlock<<DbT as WalletRead>::AccountId>>,
    ),
    Error<<DbT as WalletRead>::Error, BlockSourceT::Error>,
>
where
    ParamsT: consensus::Parameters + Send + 'static,
    BlockSourceT: BlockSource,
    DbT: WalletRead,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
    IvkTag: Copy + std::hash::Hash + Eq + Send + 'static,
{
    let mut runners = BatchRunners::<_, (), (), ()>::for_keys(100, scanning_keys);

    block_source.with_blocks::<_, <DbT as WalletRead>::Error>(
        Some(from_height),
        Some(limit),
        |block| runners.add_block(params, block).map_err(|e| e.into()),
    )?;
    runners.flush();

    match scan_with_runners(
        params,
        block_source,
        data_db,
        from_height,
        limit,
        scanning_keys,
        internal_pass,
        runners,
        None,
    )? {
        ScanPass::Scanned(scan_summary, scanned_blocks) => Ok((scan_summary, scanned_blocks)),
        ScanPass::Stale => unreachable!("a scan pass without decrypted blocks is never stale"),
    }
}

/// The outcome of [`scan_with_runners`].
enum ScanPass<AccountId> {
    /// The blocks were scanned and are ready to store.
    Scanned(ScanSummary, Vec<ScannedBlock<AccountId>>),
    /// The blocks read, or their ZIP 212 enforcement, are not those of the decryption the
    /// runners hold.
    Stale,
}

/// The wallet error with which [`scan_with_runners`] stops reading the block source at a
/// block whose decryption the runners do not hold.
struct StaleDecryption;

/// The scanning half of [`scan_blocks`], with the blocks' trial decryption already queued
/// on `runners`.
///
/// If `decrypted_blocks` is given, `runners` hold the decryption of these blocks, in order.
/// The pass then compares each block it reads, with its ZIP 212 enforcement under
/// `params`, with the decrypted block at the same position before scanning it, and
/// returns [`ScanPass::Stale`] at the first block that differs, or at the end if it read
/// fewer blocks.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
fn scan_with_runners<ParamsT, DbT, BlockSourceT, IvkTag>(
    params: &ParamsT,
    block_source: &BlockSourceT,
    data_db: &DbT,
    from_height: BlockHeight,
    limit: usize,
    scanning_keys: &ScanningKeys<<DbT as WalletRead>::AccountId, IvkTag>,
    internal_pass: Option<InternalPass<'_, <DbT as WalletRead>::AccountId, IvkTag>>,
    mut runners: BatchRunners<IvkTag, (), (), ()>,
    decrypted_blocks: Option<&[DecryptedBlock]>,
) -> Result<
    ScanPass<<DbT as WalletRead>::AccountId>,
    Error<<DbT as WalletRead>::Error, BlockSourceT::Error>,
>
where
    ParamsT: consensus::Parameters + Send + 'static,
    BlockSourceT: BlockSource,
    DbT: WalletRead,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
    IvkTag: Copy + std::hash::Hash + Eq + Send + 'static,
{
    let mut prior_block_metadata = if from_height > BlockHeight::from(0) {
        data_db
            .block_metadata(from_height - 1)
            .map_err(Error::Wallet)?
    } else {
        None
    };

    // Get the nullifiers for the unspent notes we are tracking
    let mut nullifiers = Nullifiers::unspent(data_db).map_err(Error::Wallet)?;

    let mut scanned_blocks = vec![];
    let mut scan_summary = ScanSummary::for_range(from_height..from_height);
    let read = block_source.with_blocks::<_, StaleDecryption>(
        Some(from_height),
        Some(limit),
        |block: CompactBlock| {
            if decrypted_blocks.is_some_and(|decrypted| {
                decrypted.get(scanned_blocks.len()) != Some(&DecryptedBlock::new(params, &block))
            }) {
                return Err(Error::Wallet(StaleDecryption));
            }

            scan_summary.scanned_range.end = block.height() + 1;
            let scanned_block = scan_block_with_runners::<_, _, _, (), (), ()>(
                params,
                block,
                scanning_keys,
                &nullifiers,
                internal_pass.as_ref(),
                prior_block_metadata.as_ref(),
                Some(&mut runners),
            )
            .map_err(Error::Scan)?;

            for wtx in &scanned_block.transactions {
                scan_summary.spent_sapling_note_count += wtx.sapling_spends().len();
                scan_summary.received_sapling_note_count += wtx.sapling_outputs().len();
                #[cfg(feature = "orchard")]
                {
                    scan_summary.spent_orchard_note_count += wtx.orchard_spends().len();
                    scan_summary.received_orchard_note_count += wtx.orchard_outputs().len();
                }
            }

            nullifiers.update_with(&scanned_block);
            prior_block_metadata = Some(scanned_block.to_block_metadata());
            scanned_blocks.push(scanned_block);

            Ok(())
        },
    );
    match read {
        Ok(()) => {}
        Err(Error::Wallet(StaleDecryption)) => return Ok(ScanPass::Stale),
        Err(Error::BlockSource(e)) => return Err(Error::BlockSource(e)),
        Err(Error::Scan(e)) => return Err(Error::Scan(e)),
    }
    if decrypted_blocks.is_some_and(|decrypted| decrypted.len() != scanned_blocks.len()) {
        return Ok(ScanPass::Stale);
    }

    Ok(ScanPass::Scanned(scan_summary, scanned_blocks))
}

#[cfg(feature = "test-dependencies")]
pub mod testing {
    use std::convert::Infallible;
    use zcash_protocol::consensus::BlockHeight;

    use crate::proto::compact_formats::CompactBlock;

    use super::{BlockSource, error::Error};

    use subtle::ConditionallySelectable;
    use zcash_protocol::consensus;

    use super::{
        ChainState, ScanSummary, TrialDecryptionPolicy, scan_cached_blocks_in_mode,
        scan_cached_blocks_with_policy,
    };
    use crate::{
        data_api::{WalletRead, WalletWrite},
        scanning::InternalPassTriggers,
    };

    /// A trial-decryption configuration forced on a scan, including one that is unsound.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ForcedScanMode {
        /// Every output is trial-decrypted with every scope.
        AllScopes,
        /// Outputs are trial-decrypted with external keys only. Unsound: no output paying an
        /// internal receiver is ever found.
        ExternalOnly,
        /// The given policy, as [`super::scan_cached_blocks_with_policy`] applies it.
        Policy(TrialDecryptionPolicy),
    }

    /// Scans as [`super::scan_cached_blocks`] does, in the given forced mode.
    #[allow(clippy::type_complexity)]
    pub fn scan_cached_blocks_forced<ParamsT, DbT, BlockSourceT>(
        params: &ParamsT,
        block_source: &BlockSourceT,
        data_db: &mut DbT,
        from_height: BlockHeight,
        from_state: &ChainState,
        limit: usize,
        mode: ForcedScanMode,
    ) -> Result<ScanSummary, Error<<DbT as WalletRead>::Error, BlockSourceT::Error>>
    where
        ParamsT: consensus::Parameters + Send + 'static,
        BlockSourceT: BlockSource,
        DbT: WalletWrite,
        <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
    {
        let triggers = match mode {
            ForcedScanMode::AllScopes => None,
            ForcedScanMode::ExternalOnly => Some(InternalPassTriggers::default()),
            ForcedScanMode::Policy(policy) => {
                return scan_cached_blocks_with_policy(
                    params,
                    block_source,
                    data_db,
                    from_height,
                    from_state,
                    limit,
                    policy,
                );
            }
        };
        scan_cached_blocks_in_mode(
            params,
            block_source,
            data_db,
            from_height,
            from_state,
            limit,
            triggers,
        )
    }

    pub struct MockBlockSource;

    impl BlockSource for MockBlockSource {
        type Error = Infallible;

        fn with_blocks<F, DbErrT>(
            &self,
            _from_height: Option<BlockHeight>,
            _limit: Option<usize>,
            _with_row: F,
        ) -> Result<(), Error<DbErrT, Infallible>>
        where
            F: FnMut(CompactBlock) -> Result<(), Error<DbErrT, Infallible>>,
        {
            Ok(())
        }
    }
}
