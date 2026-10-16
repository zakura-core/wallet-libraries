//! Wallet-side range validation and matching.
//!
//! The wallet chooses a contiguous range from its own durable checkpoint to a
//! block it already accepts, and asks for all of it. It does not ask only for
//! the blocks that matched, because the set of blocks it asks about would then
//! be a function of its own scripts.

use crate::digest::filter_hash;
use crate::envelope::{
    FilterBatch, RangeFilterBatch, MAX_RANGE_RECORDS_PER_BATCH, MAX_RECORDS_PER_BATCH,
};
use crate::error::FilterError;
use crate::hash::{BlockHash, ShardKey};
use crate::matching::{map_wallet_scripts, map_wallet_scripts_keyed, match_mapped};
use crate::script::ScriptBytes;
use crate::transport::{
    ByteCharges, FilterTransport, RangeRequest, ShardFilterTransport, ShardRangeRequest,
};
use crate::validate::{validate_filter, validate_range_filter, FilterLimits, ValidatedFilter};
use crate::wire::{ShardMap, ShardMapEntry};

/// The wallet's own view of the accepted chain.
///
/// Height-to-hash comes from the wallet, never from the batch being checked. A
/// server that could supply both the filters and the chain they claim to be on
/// could place any filter anywhere.
pub trait AcceptedChain {
    /// The accepted block hash at `height`, if the wallet has accepted one.
    fn block_hash(&self, height: u64) -> Option<BlockHash>;
    /// The height of an accepted block, if it is on the accepted chain.
    fn height_of(&self, hash: BlockHash) -> Option<u64>;
}

/// An in-memory accepted chain, for tests and for a caller that already holds
/// a height-to-hash map.
#[derive(Clone, Debug, Default)]
pub struct ChainMap {
    by_height: std::collections::BTreeMap<u64, BlockHash>,
}

impl ChainMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, height: u64, hash: BlockHash) -> &mut Self {
        self.by_height.insert(height, hash);
        self
    }

    /// Drops every entry above `height`, as a chain replacement requires.
    pub fn rollback_to(&mut self, height: u64) {
        self.by_height.retain(|at, _| *at <= height);
    }

    pub fn tip(&self) -> Option<(u64, BlockHash)> {
        self.by_height
            .iter()
            .next_back()
            .map(|(h, hash)| (*h, *hash))
    }
}

impl AcceptedChain for ChainMap {
    fn block_hash(&self, height: u64) -> Option<BlockHash> {
        self.by_height.get(&height).copied()
    }
    fn height_of(&self, hash: BlockHash) -> Option<u64> {
        self.by_height
            .iter()
            .find(|(_, candidate)| **candidate == hash)
            .map(|(height, _)| *height)
    }
}

/// A record whose filter has been fully validated and located on the accepted
/// chain.
#[derive(Clone, Debug)]
pub struct CheckedRecord {
    pub height: u64,
    pub block_hash: BlockHash,
    pub filter: ValidatedFilter,
}

/// Checks a batch against the request and the wallet's accepted chain.
///
/// Rejects a batch that is on the wrong chain or profile, out of order, short,
/// long, duplicated, or anchored to blocks the wallet has not accepted. Filters
/// are fully validated here, so a caller holding the result never has to
/// remember whether validation happened.
pub fn check_batch(
    batch: &FilterBatch,
    request: &RangeRequest,
    chain: &impl AcceptedChain,
    limits: FilterLimits,
) -> Result<Vec<CheckedRecord>, FilterError> {
    if batch.genesis != request.genesis {
        return Err(FilterError::Response(
            "batch is for a different chain".into(),
        ));
    }
    if batch.profile != request.profile {
        return Err(FilterError::Response(format!(
            "batch profile {:?} is not the requested {:?}",
            batch.profile, request.profile
        )));
    }
    if batch.start_height != request.start_height {
        return Err(FilterError::Response(format!(
            "batch starts at {}, requested {}",
            batch.start_height, request.start_height
        )));
    }
    if batch.stop_block_hash != request.stop_block_hash {
        return Err(FilterError::Response(
            "batch terminates at a different block".into(),
        ));
    }

    let stop_height = chain.height_of(request.stop_block_hash).ok_or_else(|| {
        FilterError::Response("terminal block is not on the accepted chain".into())
    })?;
    if stop_height < request.start_height {
        return Err(FilterError::Response(
            "terminal block is below the requested start".into(),
        ));
    }
    let wanted = (stop_height - request.start_height + 1).min(MAX_RECORDS_PER_BATCH);
    if batch.records.len() as u64 != wanted {
        return Err(FilterError::Response(format!(
            "batch has {} records, expected exactly {wanted}",
            batch.records.len()
        )));
    }

    let mut checked = Vec::with_capacity(batch.records.len());
    for (offset, record) in batch.records.iter().enumerate() {
        let expected_height = request.start_height + offset as u64;
        // Contiguity and ordering together rule out gaps, duplicates and
        // reordering: each record must sit at exactly its position's height.
        if record.height != expected_height {
            return Err(FilterError::Response(format!(
                "record {offset} is at height {}, expected {expected_height}",
                record.height
            )));
        }
        let accepted = chain.block_hash(record.height).ok_or_else(|| {
            FilterError::Response(format!(
                "wallet has not accepted a block at height {}",
                record.height
            ))
        })?;
        if accepted != record.block_hash {
            return Err(FilterError::Response(format!(
                "record at height {} is on a different branch",
                record.height
            )));
        }
        let filter = validate_filter(&record.filter, limits)?;
        checked.push(CheckedRecord {
            height: record.height,
            block_hash: record.block_hash,
            filter,
        });
    }
    Ok(checked)
}

/// A shard filter that has been validated and tied to the published map and the
/// wallet's accepted chain.
#[derive(Clone, Debug)]
pub struct CheckedShard {
    pub shard_id: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub terminal_block_hash: BlockHash,
    /// The keying this shard's filter was built under, re-derived locally from
    /// the shard's identity rather than taken from the response.
    pub key: ShardKey,
    pub filter: ValidatedFilter,
}

/// Checks a shard batch against the request, the published map, and the
/// wallet's accepted chain.
///
/// The caller must first admit the whole map with [`ShardMap::validate_supported`]
/// before deriving coverage from any batches. This function checks the advertised
/// format and the requested records only, so processing successive batches does
/// not repeatedly scan every shard or re-cut declaration. [`sync_shards`] performs
/// that admission once before requesting any batches, including an empty pass.
///
/// With content-sealed shards a wallet cannot recompute where a shard should
/// begin and end, so the published map takes the place that height arithmetic
/// held for per-block filters. Three separate things are checked, and all three
/// are needed:
///
/// - **The map.** Every delivered record must match its map entry exactly,
///   including the filter digest. This is what stops a server delivering
///   different bytes to different wallets, since the map is public and shared.
/// - **The chain.** Both of a shard's block hashes must be on the wallet's own
///   accepted chain at the stated heights. Taken from the wallet, never the
///   batch: a server supplying both the filters and the chain they claim to sit
///   on could place any shard anywhere.
/// - **The span.** Records must be contiguous in shard id and start where the
///   request said. Combined with the map's own gapless check, that is what
///   stops a range being quietly omitted now that shard widths vary.
pub fn check_range_batch(
    batch: &RangeFilterBatch,
    request: &ShardRangeRequest,
    map: &ShardMap,
    chain: &impl AcceptedChain,
    limits: FilterLimits,
) -> Result<Vec<CheckedShard>, FilterError> {
    let profile = map
        .check_supported_format()
        .map_err(FilterError::Response)?;
    if map.profile != request.profile {
        return Err(FilterError::Response(
            "requested profile differs from the shard map".into(),
        ));
    }
    if batch.genesis != request.genesis {
        return Err(FilterError::Response(
            "batch is for a different chain".into(),
        ));
    }
    if batch.profile != request.profile {
        return Err(FilterError::Response(format!(
            "batch profile {:?} is not the requested {:?}",
            batch.profile, request.profile
        )));
    }
    if batch.start_shard != request.start_shard {
        return Err(FilterError::Response(format!(
            "batch starts at shard {}, requested {}",
            batch.start_shard, request.start_shard
        )));
    }

    let genesis = BlockHash::from_display_hex(&map.genesis_hash)?;
    if genesis != request.genesis {
        return Err(FilterError::Response(
            "shard map is for a different chain".into(),
        ));
    }

    let available = (map.shards.len() as u64).saturating_sub(request.start_shard);
    let wanted = request
        .count
        .min(available)
        .min(MAX_RANGE_RECORDS_PER_BATCH);
    if batch.records.len() as u64 != wanted {
        return Err(FilterError::Response(format!(
            "batch has {} records, expected exactly {wanted}",
            batch.records.len()
        )));
    }

    let mut checked = Vec::with_capacity(batch.records.len());
    for (offset, record) in batch.records.iter().enumerate() {
        let expected_id = request.start_shard + offset as u64;
        if record.shard_id != expected_id {
            return Err(FilterError::Response(format!(
                "record {offset} is shard {}, expected {expected_id}",
                record.shard_id
            )));
        }
        let entry: &ShardMapEntry = map.shards.get(expected_id as usize).ok_or_else(|| {
            FilterError::Response(format!("shard {expected_id} is not in the map"))
        })?;

        let parent = BlockHash::from_display_hex(&entry.parent_block_hash)?;
        let terminal = BlockHash::from_display_hex(&entry.terminal_block_hash)?;
        if record.start_height != entry.start_height
            || record.end_height != entry.end_height
            || record.parent_block_hash != parent
            || record.terminal_block_hash != terminal
        {
            return Err(FilterError::Response(format!(
                "shard {expected_id} does not match its published map entry"
            )));
        }
        // Binding the bytes to the public map is what makes the map worth
        // publishing: without it a server could hand each wallet its own
        // filter under an agreed identity.
        if filter_hash(&record.filter).to_display_hex() != entry.filter_hash {
            return Err(FilterError::Response(format!(
                "shard {expected_id} filter does not match its published digest"
            )));
        }

        let accepted_terminal = chain.block_hash(record.end_height).ok_or_else(|| {
            FilterError::Response(format!(
                "wallet has not accepted a block at height {}",
                record.end_height
            ))
        })?;
        if accepted_terminal != record.terminal_block_hash {
            return Err(FilterError::Response(format!(
                "shard {expected_id} terminates on a different branch"
            )));
        }
        // Shard zero's parent is the block before coverage begins. A wallet
        // whose accepted chain does not reach that far cannot check it, and
        // must not pretend it did.
        if let Some(parent_height) = record.start_height.checked_sub(1) {
            let accepted_parent = chain.block_hash(parent_height).ok_or_else(|| {
                FilterError::Response(format!(
                    "wallet has not accepted a block at height {parent_height}"
                ))
            })?;
            if accepted_parent != record.parent_block_hash {
                return Err(FilterError::Response(format!(
                    "shard {expected_id} starts on a different branch"
                )));
            }
        }

        let key = ShardKey::derive(
            &map.profile,
            genesis,
            record.shard_id,
            record.start_height,
            record.end_height,
            record.terminal_block_hash,
        );
        checked.push(CheckedShard {
            shard_id: record.shard_id,
            start_height: record.start_height,
            end_height: record.end_height,
            terminal_block_hash: record.terminal_block_hash,
            key,
            filter: validate_range_filter(&record.filter, limits, profile)?,
        });
    }
    Ok(checked)
}

/// One shard where at least one wallet script matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardMatch {
    pub shard_id: u64,
    pub start_height: u64,
    pub end_height: u64,
    /// Indices into the caller's script list. Every match, not just the first.
    pub script_indices: Vec<usize>,
}

/// Outcome of synchronizing a span of shards.
#[derive(Clone, Debug)]
pub struct ShardSyncOutcome {
    /// Shards with at least one match, ascending by shard id.
    pub matches: Vec<ShardMatch>,
    /// The last shard whose filter was validated and matched, if any.
    pub covered_through_shard: Option<u64>,
    pub covered_through_height: Option<u64>,
    /// Every byte the transport actually delivered.
    pub charges: ByteCharges,
    pub shards_checked: u64,
}

/// Fetches, validates and matches every shard from `start_shard` to the end of
/// the published map, in bounded batches.
///
/// The wallet asks for the whole span, not only the shards it will end up
/// querying: which shards it asks about must not be a function of its scripts.
/// What the private retrieval that follows *does* reveal is a separate matter,
/// and one this profile does not hide — see the crate documentation.
///
/// Coverage is reported only for the prefix that was fully validated. A caller
/// commits its checkpoint from `covered_through_shard` only once whatever
/// private work the matches imply is durably complete.
pub fn sync_shards(
    transport: &mut impl ShardFilterTransport,
    map: &ShardMap,
    chain: &impl AcceptedChain,
    start_shard: u64,
    wallet_scripts: &[ScriptBytes],
    limits: FilterLimits,
) -> Result<ShardSyncOutcome, FilterError> {
    map.validate_supported().map_err(FilterError::Response)?;
    let genesis = BlockHash::from_display_hex(&map.genesis_hash)?;
    let total = map.shards.len() as u64;
    if start_shard > total {
        return Err(FilterError::Response(format!(
            "shard {start_shard} is beyond the map's {total} shards"
        )));
    }

    let mut charges = ByteCharges::default();
    let mut matches = Vec::new();
    let mut shards_checked = 0u64;
    let mut covered_through_shard = None;
    let mut covered_through_height = None;
    let mut next = start_shard;

    while next < total {
        let request = ShardRangeRequest {
            genesis,
            profile: map.profile.clone(),
            start_shard: next,
            count: (total - next).min(MAX_RANGE_RECORDS_PER_BATCH),
        };
        let (batch, batch_charges) = match transport.fetch_shards(&request) {
            Ok(result) => result,
            Err(error) => {
                // Charging happens inside the transport; a failed attempt still
                // cost whatever it transferred.
                return Err(error);
            }
        };
        charges.add(batch_charges);
        let checked = check_range_batch(&batch, &request, map, chain, limits)?;
        if checked.is_empty() {
            return Err(FilterError::Response(
                "batch returned no shards, which cannot make progress".into(),
            ));
        }

        for shard in &checked {
            let mapped =
                map_wallet_scripts_keyed(&shard.filter, shard.key.filter_keys(), wallet_scripts);
            let indices = match_mapped(&shard.filter, &mapped)?;
            if !indices.is_empty() {
                matches.push(ShardMatch {
                    shard_id: shard.shard_id,
                    start_height: shard.start_height,
                    end_height: shard.end_height,
                    script_indices: indices,
                });
            }
            shards_checked += 1;
            covered_through_shard = Some(shard.shard_id);
            covered_through_height = Some(shard.end_height);
        }
        next += checked.len() as u64;
    }

    Ok(ShardSyncOutcome {
        matches,
        covered_through_shard,
        covered_through_height,
        charges,
        shards_checked,
    })
}

/// One block where at least one wallet script matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockMatch {
    pub height: u64,
    pub block_hash: BlockHash,
    /// Indices into the caller's script list. Every match, not just the first.
    pub script_indices: Vec<usize>,
}

/// Outcome of synchronizing a range.
#[derive(Clone, Debug)]
pub struct SyncOutcome {
    /// Blocks with at least one match, ascending by height.
    pub matches: Vec<BlockMatch>,
    /// The highest height whose filter was validated and matched.
    pub covered_through: u64,
    pub covered_block_hash: BlockHash,
    /// Every byte the transport actually delivered.
    pub charges: ByteCharges,
    /// Filters validated, matched or not.
    pub filters_checked: u64,
}

/// Fetches, validates and matches a contiguous range in bounded batches.
///
/// Coverage is reported only for the prefix that was fully validated. A caller
/// commits its checkpoint from `covered_through` only after whatever private
/// work the matches imply is durably complete; committing earlier would turn an
/// interruption into a silent coverage gap.
pub fn sync_range(
    transport: &mut impl FilterTransport,
    request: &RangeRequest,
    chain: &impl AcceptedChain,
    wallet_scripts: &[ScriptBytes],
    limits: FilterLimits,
) -> Result<SyncOutcome, FilterError> {
    let stop_height = chain.height_of(request.stop_block_hash).ok_or_else(|| {
        FilterError::Response("terminal block is not on the accepted chain".into())
    })?;
    let mut charges = ByteCharges::default();
    let mut matches = Vec::new();
    let mut filters_checked = 0u64;
    let mut next = request.start_height;
    let mut covered_through = request.start_height.saturating_sub(1);
    let mut covered_block_hash = request.stop_block_hash;

    while next <= stop_height {
        let batch_request = RangeRequest {
            start_height: next,
            ..request.clone()
        };
        let (batch, batch_charges) = match transport.fetch_range(&batch_request) {
            Ok(result) => result,
            Err(error) => {
                // Charging happens inside the transport; a failed attempt still
                // cost whatever it transferred.
                return Err(error);
            }
        };
        charges.add(batch_charges);
        let checked = check_batch(&batch, &batch_request, chain, limits)?;

        for record in &checked {
            let mapped = map_wallet_scripts(&record.filter, record.block_hash, wallet_scripts);
            let indices = match_mapped(&record.filter, &mapped)?;
            if !indices.is_empty() {
                matches.push(BlockMatch {
                    height: record.height,
                    block_hash: record.block_hash,
                    script_indices: indices,
                });
            }
            filters_checked += 1;
            covered_through = record.height;
            covered_block_hash = record.block_hash;
        }
        next += checked.len() as u64;
    }

    Ok(SyncOutcome {
        matches,
        covered_through,
        covered_block_hash,
        charges,
        filters_checked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_filter::build_filter;
    use crate::envelope::{FilterBatch, FilterRecord, ENVELOPE_VERSION};
    use crate::profile::PROFILE;

    fn hash_at(height: u64) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&height.to_le_bytes());
        BlockHash::from_internal_bytes(bytes)
    }

    fn genesis() -> BlockHash {
        BlockHash::from_internal_bytes([0x90u8; 32])
    }

    fn script(tag: u8) -> ScriptBytes {
        ScriptBytes::new(vec![0x76, 0xa9, 0x14, tag])
    }

    struct Fixture {
        chain: ChainMap,
        batches: std::collections::BTreeMap<u64, Vec<u8>>,
    }

    struct MapTransport {
        batches: std::collections::BTreeMap<u64, Vec<u8>>,
        charges: ByteCharges,
    }

    impl FilterTransport for MapTransport {
        fn fetch_range(
            &mut self,
            request: &RangeRequest,
        ) -> Result<(FilterBatch, ByteCharges), FilterError> {
            let bytes = self.batches.get(&request.start_height).ok_or_else(|| {
                FilterError::Response(format!("no batch at {}", request.start_height))
            })?;
            self.charges.requests += 1;
            let charges = ByteCharges {
                received: bytes.len() as u64,
                sent: 0,
                requests: 1,
            };
            Ok((FilterBatch::decode(bytes)?, charges))
        }
    }

    /// Blocks 10..=14; block 12 contains script 7.
    fn fixture() -> Fixture {
        let mut chain = ChainMap::new();
        let mut records = Vec::new();
        for height in 10u64..=14 {
            chain.insert(height, hash_at(height));
            let elements = if height == 12 {
                vec![script(7)]
            } else {
                vec![]
            };
            records.push(FilterRecord {
                height,
                block_hash: hash_at(height),
                filter: build_filter(hash_at(height), &elements).unwrap().0,
            });
        }
        let batch = FilterBatch {
            version: ENVELOPE_VERSION,
            genesis: genesis(),
            profile: PROFILE.to_string(),
            start_height: 10,
            stop_block_hash: hash_at(14),
            records,
        };
        let mut batches = std::collections::BTreeMap::new();
        batches.insert(10u64, batch.encode());
        Fixture { chain, batches }
    }

    fn request() -> RangeRequest {
        RangeRequest {
            genesis: genesis(),
            profile: PROFILE.to_string(),
            start_height: 10,
            stop_block_hash: hash_at(14),
        }
    }

    #[test]
    fn a_matching_script_is_found_at_its_block() {
        let fixture = fixture();
        let mut transport = MapTransport {
            batches: fixture.batches,
            charges: ByteCharges::default(),
        };
        let outcome = sync_range(
            &mut transport,
            &request(),
            &fixture.chain,
            &[script(7)],
            FilterLimits::default(),
        )
        .unwrap();
        assert_eq!(outcome.matches.len(), 1);
        assert_eq!(outcome.matches[0].height, 12);
        assert_eq!(outcome.matches[0].script_indices, vec![0]);
        assert_eq!(outcome.covered_through, 14);
        assert_eq!(outcome.filters_checked, 5);
        assert!(outcome.charges.received > 0);
    }

    #[test]
    fn an_absent_script_yields_coverage_with_no_matches() {
        let fixture = fixture();
        let mut transport = MapTransport {
            batches: fixture.batches,
            charges: ByteCharges::default(),
        };
        let outcome = sync_range(
            &mut transport,
            &request(),
            &fixture.chain,
            &[script(200)],
            FilterLimits::default(),
        )
        .unwrap();
        assert!(outcome.matches.is_empty());
        assert_eq!(outcome.covered_through, 14);
    }

    #[test]
    fn a_missing_middle_record_is_rejected() {
        let fixture = fixture();
        let mut batch = FilterBatch::decode(&fixture.batches[&10]).unwrap();
        batch.records.remove(2);
        let error =
            check_batch(&batch, &request(), &fixture.chain, FilterLimits::default()).unwrap_err();
        assert!(format!("{error}").contains("expected exactly 5"));
    }

    #[test]
    fn a_duplicated_height_is_rejected() {
        let fixture = fixture();
        let mut batch = FilterBatch::decode(&fixture.batches[&10]).unwrap();
        batch.records[3] = batch.records[2].clone();
        let error =
            check_batch(&batch, &request(), &fixture.chain, FilterLimits::default()).unwrap_err();
        assert!(format!("{error}").contains("expected 13"));
    }

    #[test]
    fn excess_records_are_rejected() {
        let fixture = fixture();
        let mut batch = FilterBatch::decode(&fixture.batches[&10]).unwrap();
        let extra = batch.records[4].clone();
        batch.records.push(extra);
        assert!(check_batch(&batch, &request(), &fixture.chain, FilterLimits::default()).is_err());
    }

    #[test]
    fn a_record_on_another_branch_is_rejected() {
        let fixture = fixture();
        let mut batch = FilterBatch::decode(&fixture.batches[&10]).unwrap();
        batch.records[2].block_hash = BlockHash::from_internal_bytes([0xff; 32]);
        let error =
            check_batch(&batch, &request(), &fixture.chain, FilterLimits::default()).unwrap_err();
        assert!(format!("{error}").contains("different branch"));
    }

    #[test]
    fn a_batch_for_another_chain_or_profile_is_rejected() {
        let fixture = fixture();
        let batch = FilterBatch::decode(&fixture.batches[&10]).unwrap();

        let mut wrong_chain = batch.clone();
        wrong_chain.genesis = BlockHash::from_internal_bytes([0x11; 32]);
        assert!(check_batch(
            &wrong_chain,
            &request(),
            &fixture.chain,
            FilterLimits::default()
        )
        .is_err());

        let mut wrong_profile = batch;
        wrong_profile.profile = "something-else".to_string();
        assert!(check_batch(
            &wrong_profile,
            &request(),
            &fixture.chain,
            FilterLimits::default()
        )
        .is_err());
    }

    #[test]
    fn a_terminal_block_the_wallet_has_not_accepted_is_rejected() {
        let fixture = fixture();
        let batch = FilterBatch::decode(&fixture.batches[&10]).unwrap();
        let mut request = request();
        request.stop_block_hash = BlockHash::from_internal_bytes([0xee; 32]);
        let mut batch = batch;
        batch.stop_block_hash = request.stop_block_hash;
        let error =
            check_batch(&batch, &request, &fixture.chain, FilterLimits::default()).unwrap_err();
        assert!(format!("{error}").contains("not on the accepted chain"));
    }

    #[test]
    fn a_cached_old_fork_filter_stops_counting_after_a_rollback() {
        let mut fixture = fixture();
        // The wallet's chain is replaced from height 12 upward.
        fixture.chain.rollback_to(11);
        let batch = FilterBatch::decode(&fixture.batches[&10]).unwrap();
        // The old batch's terminal block is no longer accepted at all.
        let error =
            check_batch(&batch, &request(), &fixture.chain, FilterLimits::default()).unwrap_err();
        assert!(format!("{error}").contains("not on the accepted chain"));
    }

    #[test]
    fn a_malformed_filter_fails_the_whole_batch_rather_than_reading_as_no_match() {
        let fixture = fixture();
        let mut batch = FilterBatch::decode(&fixture.batches[&10]).unwrap();
        batch.records[1].filter = vec![0x05, 0xff];
        let error =
            check_batch(&batch, &request(), &fixture.chain, FilterLimits::default()).unwrap_err();
        assert!(!matches!(error, FilterError::Response(_)));
    }

    // --- Shard sync -------------------------------------------------------

    use crate::build_filter::{build_range_filter, build_range_filter_for};
    use crate::envelope::{RangeFilterBatch, RangeFilterRecord, RANGE_ENVELOPE_VERSION};
    use crate::profile::{
        RangeProfile, MAINNET_GENESIS_DISPLAY, RANGE_PROFILE, RANGE_PROFILE_V1, RANGE_PROFILE_V2,
    };
    use crate::wire::{SealParameters, ShardMapEntry};

    const SHARD_WIDTH: u64 = 8;
    const FIRST_HEIGHT: u64 = 100;

    fn mainnet_genesis() -> BlockHash {
        BlockHash::from_display_hex(MAINNET_GENESIS_DISPLAY).unwrap()
    }

    /// Builds `count` shards, putting `script(shard_id)` in each so that a
    /// wallet holding one script matches exactly one shard.
    fn shard_fixture(count: u64) -> (ShardMap, Vec<RangeFilterRecord>, ChainMap) {
        shard_fixture_for(count, &RANGE_PROFILE_V1)
    }

    fn shard_fixture_for(
        count: u64,
        profile: &RangeProfile,
    ) -> (ShardMap, Vec<RangeFilterRecord>, ChainMap) {
        let mut chain = ChainMap::new();
        for height in (FIRST_HEIGHT - 1)..(FIRST_HEIGHT + count * SHARD_WIDTH) {
            chain.insert(height, hash_at(height));
        }

        let mut entries = Vec::new();
        let mut records = Vec::new();
        for shard_id in 0..count {
            let start_height = FIRST_HEIGHT + shard_id * SHARD_WIDTH;
            let end_height = start_height + SHARD_WIDTH - 1;
            let terminal = hash_at(end_height);
            let parent = hash_at(start_height - 1);
            let key = ShardKey::derive(
                profile.name,
                mainnet_genesis(),
                shard_id,
                start_height,
                end_height,
                terminal,
            );
            let elements = vec![script(shard_id as u8)];
            let filter = build_range_filter_for(profile, key, &elements).unwrap();
            entries.push(ShardMapEntry {
                shard_id,
                geometry: "decoupled-2k-8k".to_string(),
                start_height,
                end_height,
                parent_block_hash: parent.to_display_hex(),
                terminal_block_hash: terminal.to_display_hex(),
                filter_hash: crate::digest::filter_hash(filter.as_slice()).to_display_hex(),
                scripts: 1,
                page_rows: 0,
                txids: 1,
                directory_segments: 1,
                page_segments: 1,
                manifest_digest: format!("{shard_id:064x}"),
                revision: 0,
                sealed: true,
            });
            records.push(RangeFilterRecord {
                shard_id,
                start_height,
                end_height,
                parent_block_hash: parent,
                terminal_block_hash: terminal,
                filter: filter.as_slice().to_vec(),
            });
        }

        let map = ShardMap {
            genesis_hash: MAINNET_GENESIS_DISPLAY.to_string(),
            network: crate::profile::NETWORK.to_string(),
            profile: profile.name.to_string(),
            range_envelope_version: RANGE_ENVELOPE_VERSION,
            start_height: FIRST_HEIGHT,
            seal: std::collections::BTreeMap::from([(
                "decoupled-2k-8k".to_string(),
                SealParameters {
                    max_scripts: 16,
                    max_page_rows: 16,
                    max_txids: 16,
                },
            )]),
            shards: entries,
            recuts: Vec::new(),
        };
        (map, records, chain)
    }

    struct VecShardTransport {
        records: Vec<RangeFilterRecord>,
    }

    impl ShardFilterTransport for VecShardTransport {
        fn fetch_shards(
            &mut self,
            request: &ShardRangeRequest,
        ) -> Result<(RangeFilterBatch, ByteCharges), FilterError> {
            let start = request.start_shard as usize;
            let end = (start + request.count as usize).min(self.records.len());
            let batch = RangeFilterBatch {
                version: RANGE_ENVELOPE_VERSION,
                genesis: request.genesis,
                profile: request.profile.clone(),
                start_shard: request.start_shard,
                records: self.records[start..end].to_vec(),
            };
            let bytes = batch.encode();
            let charges = ByteCharges {
                received: bytes.len() as u64,
                sent: 0,
                requests: 1,
            };
            Ok((batch, charges))
        }
    }

    fn sync(
        map: &ShardMap,
        records: &[RangeFilterRecord],
        chain: &ChainMap,
        start_shard: u64,
        scripts: &[ScriptBytes],
    ) -> Result<ShardSyncOutcome, FilterError> {
        let mut transport = VecShardTransport {
            records: records.to_vec(),
        };
        sync_shards(
            &mut transport,
            map,
            chain,
            start_shard,
            scripts,
            FilterLimits::default(),
        )
    }

    #[test]
    fn every_registered_profile_matches_present_scripts_without_missing_coverage() {
        for profile in [&RANGE_PROFILE_V1, &RANGE_PROFILE_V2] {
            let (map, records, chain) = shard_fixture_for(4, profile);
            let outcome = sync(&map, &records, &chain, 0, &[script(2)]).unwrap();
            assert_eq!(outcome.shards_checked, 4, "{}", profile.name);
            assert_eq!(outcome.covered_through_shard, Some(3));
            assert!(
                outcome.matches.iter().any(|matched| {
                    matched.shard_id == 2 && matched.script_indices.contains(&0)
                }),
                "present script was missed under {}",
                profile.name
            );
        }
    }

    #[test]
    fn unsupported_profile_is_refused_before_fetching_even_with_no_remaining_shards() {
        struct NeverFetch;
        impl ShardFilterTransport for NeverFetch {
            fn fetch_shards(
                &mut self,
                _: &ShardRangeRequest,
            ) -> Result<(RangeFilterBatch, ByteCharges), FilterError> {
                panic!("an unsupported profile must not reach the transport")
            }
        }
        let (mut map, _, chain) = shard_fixture(1);
        map.profile = "unknown-range-profile".into();
        for start in [0, 1] {
            let error = sync_shards(
                &mut NeverFetch,
                &map,
                &chain,
                start,
                &[],
                FilterLimits::default(),
            )
            .unwrap_err();
            assert!(error
                .to_string()
                .contains("unsupported shard filter profile"));
        }
    }

    #[test]
    fn unsupported_maps_are_refused_without_fetching_or_remaining_work() {
        struct NeverFetch;
        impl ShardFilterTransport for NeverFetch {
            fn fetch_shards(
                &mut self,
                _: &ShardRangeRequest,
            ) -> Result<(RangeFilterBatch, ByteCharges), FilterError> {
                panic!("an unsupported map must not reach the transport")
            }
        }
        let (valid, _, chain) = shard_fixture(1);
        for mutate in [
            (|map: &mut ShardMap| map.range_envelope_version += 1) as fn(&mut ShardMap),
            |map: &mut ShardMap| map.profile = "unknown-range-profile".into(),
            |map: &mut ShardMap| map.shards[0].directory_segments = 0,
        ] {
            let mut map = valid.clone();
            mutate(&mut map);
            assert!(map.validate_supported().is_err());
            for start in [0, 1] {
                assert!(sync_shards(
                    &mut NeverFetch,
                    &map,
                    &chain,
                    start,
                    &[],
                    FilterLimits::default()
                )
                .is_err());
            }
        }
        for mutate in [
            (|map: &mut ShardMap| map.range_envelope_version += 1) as fn(&mut ShardMap),
            |map: &mut ShardMap| map.profile = "unknown-range-profile".into(),
        ] {
            let mut map = valid.clone();
            mutate(&mut map);
            let request = ShardRangeRequest {
                genesis: mainnet_genesis(),
                profile: map.profile.clone(),
                start_shard: 1,
                count: 0,
            };
            let batch = RangeFilterBatch {
                version: RANGE_ENVELOPE_VERSION,
                genesis: request.genesis,
                profile: request.profile.clone(),
                start_shard: 1,
                records: vec![],
            };
            assert!(
                check_range_batch(&batch, &request, &map, &chain, FilterLimits::default()).is_err()
            );
        }
        for profile in [&RANGE_PROFILE_V1, &RANGE_PROFILE_V2] {
            let (map, _, _) = shard_fixture_for(1, profile);
            assert_eq!(map.validate_supported().unwrap(), profile);
        }
    }

    /// Whole-map admission owns shape checks. Rechecking them per batch would
    /// scan unrelated shards and turn a full sync into repeated whole-map work.
    #[test]
    fn batch_validation_only_visits_requested_shards_after_admission() {
        let (mut map, records, chain) = shard_fixture(2);
        map.validate_supported().unwrap();
        let request = ShardRangeRequest {
            genesis: mainnet_genesis(),
            profile: map.profile.clone(),
            start_shard: 0,
            count: 1,
        };
        let batch = RangeFilterBatch {
            version: RANGE_ENVELOPE_VERSION,
            genesis: request.genesis,
            profile: request.profile.clone(),
            start_shard: 0,
            records: records[..1].to_vec(),
        };
        assert_eq!(
            check_range_batch(&batch, &request, &map, &chain, FilterLimits::default())
                .unwrap()
                .len(),
            1
        );
        // A newly offered map with broken unrelated history must fail admission.
        // Batch checking itself must remain local to the requested interval.
        map.shards[1].directory_segments = 0;
        assert!(map.validate_supported().is_err());
        assert_eq!(
            check_range_batch(&batch, &request, &map, &chain, FilterLimits::default())
                .unwrap()
                .len(),
            1
        );
        map.shards[0].filter_hash = "00".repeat(32);
        assert!(
            check_range_batch(&batch, &request, &map, &chain, FilterLimits::default()).is_err()
        );
    }

    #[test]
    fn a_batch_cannot_select_a_profile_different_from_the_map() {
        let (map, records, chain) = shard_fixture(1);
        let request = ShardRangeRequest {
            genesis: mainnet_genesis(),
            profile: RANGE_PROFILE_V2.name.into(),
            start_shard: 0,
            count: 1,
        };
        let batch = RangeFilterBatch {
            version: RANGE_ENVELOPE_VERSION,
            genesis: request.genesis,
            profile: request.profile.clone(),
            start_shard: 0,
            records,
        };
        let error =
            check_range_batch(&batch, &request, &map, &chain, FilterLimits::default()).unwrap_err();
        assert!(error.to_string().contains("requested profile differs"));
    }

    #[test]
    fn a_wallet_matches_only_the_shards_its_script_appears_in() {
        let (map, records, chain) = shard_fixture(4);
        let outcome = sync(&map, &records, &chain, 0, &[script(2)]).unwrap();
        assert_eq!(outcome.shards_checked, 4);
        assert_eq!(outcome.covered_through_shard, Some(3));
        assert_eq!(
            outcome.covered_through_height,
            Some(FIRST_HEIGHT + 4 * SHARD_WIDTH - 1)
        );
        let matched: Vec<u64> = outcome.matches.iter().map(|m| m.shard_id).collect();
        assert_eq!(matched, vec![2]);
        assert_eq!(outcome.matches[0].script_indices, vec![0]);
        assert!(outcome.charges.received > 0);
    }

    /// The birthday case: a wallet starting mid-chain checks only shards from
    /// its birthday forward, and never learns about earlier ones.
    #[test]
    fn syncing_from_a_birthday_shard_skips_the_earlier_shards() {
        let (map, records, chain) = shard_fixture(4);
        let outcome = sync(&map, &records, &chain, 2, &[script(1)]).unwrap();
        assert_eq!(outcome.shards_checked, 2);
        // Shard 1 holds the script but is before the birthday, so it is not
        // matched — and the wallet must not be told otherwise.
        assert!(outcome.matches.is_empty());
        assert_eq!(outcome.covered_through_shard, Some(3));
    }

    /// A wallet with no activity anywhere still checks every shard and reports
    /// full coverage with no matches. This is the case the whole design is
    /// meant to make cheap, so it must not accidentally error.
    #[test]
    fn an_unused_wallet_covers_every_shard_and_matches_nothing() {
        let (map, records, chain) = shard_fixture(4);
        let outcome = sync(&map, &records, &chain, 0, &[script(200)]).unwrap();
        assert_eq!(outcome.shards_checked, 4);
        assert!(outcome.matches.is_empty());
    }

    #[test]
    fn filter_bytes_that_do_not_match_the_published_digest_are_refused() {
        let (map, mut records, chain) = shard_fixture(3);
        let other = ShardKey::derive(
            RANGE_PROFILE,
            mainnet_genesis(),
            99,
            0,
            0,
            hash_at(FIRST_HEIGHT),
        );
        records[1].filter = build_range_filter(other, &[script(1)])
            .unwrap()
            .as_slice()
            .to_vec();
        let error = sync(&map, &records, &chain, 0, &[script(1)]).unwrap_err();
        assert!(
            format!("{error}").contains("published digest"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_shard_anchored_off_the_wallets_chain_is_refused() {
        let (map, records, mut chain) = shard_fixture(3);
        // The wallet accepted a different block where shard 1 terminates.
        chain.insert(FIRST_HEIGHT + 2 * SHARD_WIDTH - 1, hash_at(9_999));
        let error = sync(&map, &records, &chain, 0, &[script(0)]).unwrap_err();
        assert!(
            format!("{error}").contains("different branch"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_shard_whose_bounds_disagree_with_the_map_is_refused() {
        let (map, mut records, chain) = shard_fixture(3);
        records[1].end_height += 1;
        let error = sync(&map, &records, &chain, 0, &[script(1)]).unwrap_err();
        assert!(
            format!("{error}").contains("published map entry"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_map_with_a_height_gap_is_refused_before_anything_is_fetched() {
        let (mut map, records, chain) = shard_fixture(3);
        map.shards[2].start_height += 1;
        let error = sync(&map, &records, &chain, 0, &[script(0)]).unwrap_err();
        assert!(
            format!("{error}").contains("malformed"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_map_whose_shards_do_not_chain_is_refused() {
        let (mut map, records, chain) = shard_fixture(3);
        map.shards[2].parent_block_hash = hash_at(9_999).to_display_hex();
        let error = sync(&map, &records, &chain, 0, &[script(0)]).unwrap_err();
        assert!(
            format!("{error}").contains("does not chain"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn the_map_locates_a_birthday_height_and_reports_heights_it_does_not_cover() {
        let (map, _, _) = shard_fixture(4);
        assert_eq!(map.shard_for_height(FIRST_HEIGHT).unwrap().shard_id, 0);
        assert_eq!(
            map.shard_for_height(FIRST_HEIGHT + SHARD_WIDTH)
                .unwrap()
                .shard_id,
            1
        );
        // Last height of the last shard.
        assert_eq!(
            map.shard_for_height(FIRST_HEIGHT + 4 * SHARD_WIDTH - 1)
                .unwrap()
                .shard_id,
            3
        );
        // A birthday before coverage begins is not served by this deployment,
        // and must be reported rather than rounded up to shard zero.
        assert!(map.shard_for_height(FIRST_HEIGHT - 1).is_none());
        assert!(map
            .shard_for_height(FIRST_HEIGHT + 4 * SHARD_WIDTH)
            .is_none());
    }
}
