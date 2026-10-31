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

use std::collections::HashMap;
use std::ops::Range;

use incrementalmerkletree::frontier::Frontier;
use sapling::note_encryption::Zip212Enforcement;
use subtle::ConditionallySelectable;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::{block::BlockHash, transaction::components::sapling::zip212_enforcement};
use zcash_protocol::consensus::{self, BlockHeight};
use zeroize::Zeroizing;
use zip32::Scope;

use crate::{
    data_api::{ScannedBlock, WalletWrite},
    proto::compact_formats::CompactBlock,
    scanning::{
        AccountScanningKeys, Nullifiers, ScanningKeys,
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
    scan_cached_blocks_with_cache(
        params,
        block_source,
        data_db,
        from_height,
        from_state,
        limit,
        &mut ScanningKeyCache::new(),
    )
}

/// The decoded viewing keys and derived scanning keys of a wallet's accounts, kept by the
/// caller across [`scan_cached_blocks_with_cache`] calls.
///
/// Every scan needs each account's scanning keys. Decoding a unified full viewing key
/// validates each of its components, and deriving its IVKs needs Pedersen hashing (internal
/// Sapling keys) and a Sinsemilla `CommitIvk` per Orchard IVK. A wallet that follows the
/// chain tip scans a block or two at a time, so without a cache this work, repeated for
/// every account, can cost more than scanning the blocks themselves.
///
/// Before each scan the cache compares each account's stored key encoding, as
/// [`WalletRead::get_unified_full_viewing_key_encodings`] returns it, with the encoding its
/// keys were derived from. It drops accounts that are gone or whose keys changed, and
/// decodes and derives only new or changed accounts. A wallet that does not report
/// encodings has its keys read and encoded on every scan, which still spares the
/// derivation.
///
/// A cache is meant for one wallet: the same account identifiers in another wallet could
/// name other keys. It holds viewing keys, which can detect the wallet's transactions, for
/// as long as the caller keeps it, so drop or [`clear`](Self::clear) it when those keys
/// should leave memory, for example when the wallet is locked or reset.
///
/// Dropping or clearing it overwrites the stored key encodings and the Sapling scanning
/// keys. The Orchard keys are freed without being overwritten, because the Orchard key
/// types offer no way to wipe them; nor are the short-lived copies a scan makes.
pub struct ScanningKeyCache<AccountId> {
    accounts: HashMap<AccountId, CachedAccountKeys>,
}

/// One account's scanning keys and the stored key encoding they were derived from.
struct CachedAccountKeys {
    encoding: Zeroizing<String>,
    keys: AccountScanningKeys,
}

impl<AccountId> ScanningKeyCache<AccountId> {
    /// Constructs an empty cache.
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }

    /// Drops every cached key, overwriting what can be overwritten (see the type's
    /// documentation).
    pub fn clear(&mut self) {
        self.accounts.clear();
    }
}

impl<AccountId> Default for ScanningKeyCache<AccountId> {
    fn default() -> Self {
        Self::new()
    }
}

impl<AccountId: Copy + Eq + std::hash::Hash + Send + Sync + 'static> ScanningKeyCache<AccountId> {
    /// Brings the cache up to date with `data_db`'s accounts and returns the scanning keys
    /// of the accounts that at most `limit` blocks from `from_height` are scanned for, as
    /// [`account_ufvks_for_range`] selects them.
    fn scanning_keys_for_range<ParamsT, DbT>(
        &mut self,
        params: &ParamsT,
        data_db: &DbT,
        from_height: BlockHeight,
        limit: usize,
    ) -> Result<ScanningKeys<AccountId, (AccountId, Scope)>, DbT::Error>
    where
        ParamsT: consensus::Parameters,
        DbT: WalletRead<AccountId = AccountId>,
    {
        let (encodings, ufvks) = match data_db.get_unified_full_viewing_key_encodings()? {
            Some(encodings) => (encodings, None),
            None => {
                let ufvks = data_db.get_unified_full_viewing_keys()?;
                (encode_ufvks(params, &ufvks), Some(ufvks))
            }
        };
        self.refresh(params, encodings, ufvks, || {
            data_db.get_unified_full_viewing_keys()
        })?;
        self.in_range(data_db, from_height, limit)
    }

    /// Brings the cache up to date with the wallet's stored key `encodings`.
    ///
    /// Cached accounts whose encoding is missing or different are dropped. If any account is
    /// then uncached, its keys are decoded from `ufvks` if those were read together with
    /// `encodings`, or else from `read_ufvks`, a later read of the wallet. The wallet may
    /// have changed between the two reads, so a later read decides which accounts are cached:
    /// an account visible to it must not be left out of the scan.
    fn refresh<ParamsT, E>(
        &mut self,
        params: &ParamsT,
        encodings: HashMap<AccountId, String>,
        ufvks: Option<HashMap<AccountId, UnifiedFullViewingKey>>,
        read_ufvks: impl FnOnce() -> Result<HashMap<AccountId, UnifiedFullViewingKey>, E>,
    ) -> Result<(), E>
    where
        ParamsT: consensus::Parameters,
    {
        let mut encodings: HashMap<AccountId, Zeroizing<String>> = encodings
            .into_iter()
            .map(|(account, encoding)| (account, Zeroizing::new(encoding)))
            .collect();

        self.accounts.retain(|account, cached| {
            encodings
                .get(account)
                .is_some_and(|encoding| *encoding == cached.encoding)
        });
        if encodings
            .keys()
            .all(|account| self.accounts.contains_key(account))
        {
            return Ok(());
        }

        let ufvks = match ufvks {
            Some(ufvks) => ufvks,
            None => read_ufvks()?,
        };
        self.accounts
            .retain(|account, _| ufvks.contains_key(account));
        for (account, ufvk) in &ufvks {
            if self.accounts.contains_key(account) {
                continue;
            }
            // An account added between the two reads has no stored encoding yet, so its
            // keys are cached under their own encoding, which the next scan replaces if the
            // wallet stores the key differently.
            let encoding = encodings
                .remove(account)
                .unwrap_or_else(|| Zeroizing::new(ufvk.encode(params)));
            self.accounts.insert(
                *account,
                CachedAccountKeys {
                    encoding,
                    keys: AccountScanningKeys::derive(ufvk),
                },
            );
        }
        Ok(())
    }

    /// The scanning keys of the cached accounts that at most `limit` blocks from
    /// `from_height` are scanned for, as [`account_ufvks_for_range`] selects them.
    fn in_range<DbT>(
        &self,
        data_db: &DbT,
        from_height: BlockHeight,
        limit: usize,
    ) -> Result<ScanningKeys<AccountId, (AccountId, Scope)>, DbT::Error>
    where
        DbT: WalletRead<AccountId = AccountId>,
    {
        let end = range_end(from_height, limit);
        let mut in_range = Vec::with_capacity(self.accounts.len());
        for (account, cached) in &self.accounts {
            if u64::from(data_db.get_account_birthday(*account)?) < end {
                in_range.push((*account, &cached.keys));
            }
        }
        Ok(ScanningKeys::from_account_keys(in_range))
    }
}

/// Scans at most `limit` blocks from the provided block source, as [`scan_cached_blocks`]
/// does, taking the accounts' scanning keys from `cache` and updating it.
///
/// A caller that scans repeatedly keeps one [`ScanningKeyCache`] per wallet across calls,
/// so that unchanged accounts' viewing keys are neither decoded nor derived again.
///
/// ## Errors
///
/// As for [`scan_cached_blocks`].
///
/// ## Panics
///
/// This method will panic if `from_height != from_state.block_height() + 1`.
#[tracing::instrument(skip(params, block_source, data_db, from_state, cache))]
#[allow(clippy::type_complexity)]
pub fn scan_cached_blocks_with_cache<ParamsT, DbT, BlockSourceT>(
    params: &ParamsT,
    block_source: &BlockSourceT,
    data_db: &mut DbT,
    from_height: BlockHeight,
    from_state: &ChainState,
    limit: usize,
    cache: &mut ScanningKeyCache<<DbT as WalletRead>::AccountId>,
) -> Result<ScanSummary, Error<<DbT as WalletRead>::Error, BlockSourceT::Error>>
where
    ParamsT: consensus::Parameters + Send + 'static,
    BlockSourceT: BlockSource,
    DbT: WalletWrite,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
{
    assert_eq!(from_height, from_state.block_height + 1);

    let scanning_keys = cache
        .scanning_keys_for_range(params, &*data_db, from_height, limit)
        .map_err(Error::Wallet)?;
    let (scan_summary, scanned_blocks) = scan_blocks(
        params,
        block_source,
        data_db,
        from_height,
        limit,
        &scanning_keys,
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
    let account_ufvks =
        account_ufvks_for_range(data_db, from_height, limit).map_err(Error::Wallet)?;
    let encoded_ufvks = encode_ufvks(params, &account_ufvks);
    let scanning_keys = ScanningKeys::from_account_ufvks(account_ufvks);
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
            ..
        } = decryption;
        scan_with_runners(
            params,
            block_source,
            data_db,
            from_height,
            limit,
            &scanning_keys,
            runners,
            Some(&blocks),
        )?
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

/// One past the last height of the at most `limit` blocks from `from_height`.
fn range_end(from_height: BlockHeight, limit: usize) -> u64 {
    u64::from(from_height).saturating_add(u64::try_from(limit).unwrap_or(u64::MAX))
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
    let end = range_end(from_height, limit);
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::Infallible;

    use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
    use zcash_protocol::consensus::Network;

    use super::ScanningKeyCache;

    const PARAMS: Network = Network::TestNetwork;

    fn ufvk(seed: u8) -> UnifiedFullViewingKey {
        UnifiedSpendingKey::from_seed(&PARAMS, &[seed; 32], zip32::AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key()
    }

    fn cached_accounts(cache: &ScanningKeyCache<u32>) -> Vec<u32> {
        let mut accounts: Vec<_> = cache.accounts.keys().copied().collect();
        accounts.sort();
        accounts
    }

    /// The wallet can change between reading the key encodings and reading the keys; the
    /// later read decides which accounts are scanned for.
    #[test]
    fn the_later_key_read_decides_the_cached_accounts() {
        let (a, b) = (ufvk(1), ufvk(2));

        let mut imported_between_reads = ScanningKeyCache::new();
        imported_between_reads
            .refresh(
                &PARAMS,
                HashMap::from([(1, a.encode(&PARAMS))]),
                None,
                || Ok::<_, Infallible>(HashMap::from([(1, a.clone()), (2, b.clone())])),
            )
            .unwrap();
        assert_eq!(cached_accounts(&imported_between_reads), [1, 2]);

        let mut deleted_between_reads = ScanningKeyCache::new();
        deleted_between_reads
            .refresh(
                &PARAMS,
                HashMap::from([(1, a.encode(&PARAMS)), (2, b.encode(&PARAMS))]),
                None,
                || Ok::<_, Infallible>(HashMap::from([(1, a.clone())])),
            )
            .unwrap();
        assert_eq!(cached_accounts(&deleted_between_reads), [1]);
    }

    /// Accounts whose stored encoding is unchanged are neither read nor derived again, and a
    /// changed or removed encoding drops the account's keys.
    #[test]
    fn only_new_or_changed_accounts_are_read_again() {
        let (a, b) = (ufvk(1), ufvk(2));
        let mut cache = ScanningKeyCache::new();
        cache
            .refresh(
                &PARAMS,
                HashMap::from([(1, a.encode(&PARAMS))]),
                None,
                || Ok::<_, Infallible>(HashMap::from([(1, a.clone())])),
            )
            .unwrap();

        cache
            .refresh(
                &PARAMS,
                HashMap::from([(1, a.encode(&PARAMS))]),
                None,
                || -> Result<_, Infallible> { panic!("unchanged keys were read again") },
            )
            .unwrap();
        assert_eq!(cached_accounts(&cache), [1]);

        cache
            .refresh(
                &PARAMS,
                HashMap::from([(1, b.encode(&PARAMS))]),
                None,
                || Ok::<_, Infallible>(HashMap::from([(1, b.clone())])),
            )
            .unwrap();
        assert_eq!(*cache.accounts[&1].encoding, b.encode(&PARAMS));

        cache
            .refresh(
                &PARAMS,
                HashMap::new(),
                None,
                || -> Result<_, Infallible> { panic!("no account needs decoding") },
            )
            .unwrap();
        assert!(cached_accounts(&cache).is_empty());
    }
}
