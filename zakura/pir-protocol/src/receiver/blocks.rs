//! Rolling block hints. Matches schedule PIR; they never establish ownership or absence.
//!
//! The service is trusted for complete indexing. Consumers independently check block
//! identities against their chain before advancing coverage. Pruned ranges use PIR.
use super::{Error, Hash, ReceiverBytes, gcs::Filter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Maximum consecutive filters in one response.
pub const MAX_BLOCKS: u32 = 256;
/// Maximum response size, enforced by transports before buffering.
pub const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
/// Maximum distinct receivers per block, checked before allocating decoded values.
pub const MAX_RECEIVERS: u32 = 65_536;
/// Golomb-Rice parameter and range multiplier for block hints.
const P: u8 = 20;
const M: u64 = 1_569_792;
const MAGIC: &[u8; 8] = b"IWBATCH1";
/// Magic, genesis, revision and block count of an encoded [`Batch`].
const BATCH_HEADER: usize = 8 + 32 + 8 + 4;
/// Height, hash, parent and set length that a [`Batch`] adds to each block's set.
const BATCH_BLOCK: usize = 4 + 32 + 32 + 4;
/// Maximum consecutive blocks in one [`Range`]: the longest rolling window, seven days at
/// NU7's 25-second spacing, so any gap the window covers takes one request.
pub const MAX_RANGE_BLOCKS: u32 = 24_192;
const RANGE_MAGIC: &[u8; 8] = b"IWRANGE1";
/// Magic, revision, first height, block count and chain digest.
const RANGE_HEADER: usize = 8 + 8 + 4 + 4 + 32;

/// An exact block identity, in protocol byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockId {
    pub height: u32,
    pub hash: Hash,
}

/// Available rolling history, independent of the PIR publication's frontier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub genesis: Hash,
    /// Changes whenever indexing corrections change hints on an unchanged chain.
    pub revision: u64,
    /// First available filter, inclusive. Genesis itself has no filter.
    pub first: u32,
    pub tip: BlockId,
}

impl Head {
    /// Checks network and nonempty availability. Unavailable history is never an empty set.
    pub fn validate(&self, genesis: &Hash) -> Result<(), Error> {
        if &self.genesis != genesis || self.first == 0 || self.first > self.tip.height {
            return Err(Error::Coverage);
        }
        Ok(())
    }

    /// Checks a bounded request that begins inside the available history.
    pub fn check_request(&self, from: u32, limit: u32) -> Result<(), Error> {
        self.validate(&self.genesis)?;
        if limit == 0 || limit > MAX_BLOCKS || from < self.first || from > self.tip.height {
            return Err(Error::Coverage);
        }
        Ok(())
    }

    /// Checks a bounded [`Range`] request that begins inside the available history.
    pub fn check_range(&self, from: u32, limit: u32) -> Result<(), Error> {
        self.validate(&self.genesis)?;
        if limit == 0 || limit > MAX_RANGE_BLOCKS || from < self.first || from > self.tip.height {
            return Err(Error::Coverage);
        }
        Ok(())
    }
}

/// One block's validated GCS, including explicit parent linkage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFilter {
    genesis: Hash,
    block: BlockId,
    parent: Hash,
    filter: Filter,
}

/// Derives stable coding keys independent of PIR row placement and history revision.
fn salt(genesis: &Hash, block: BlockId) -> Hash {
    Sha256::new()
        .chain_update(b"ironwood-receiver/v1/block-hints\0")
        .chain_update(genesis)
        .chain_update(block.height.to_le_bytes())
        .chain_update(block.hash)
        .finalize()
        .into()
}

impl BlockFilter {
    /// Builds a bounded set of distinct supported recipients in this block.
    pub fn build<'a>(
        genesis: &Hash,
        block: BlockId,
        parent: Hash,
        receivers: impl IntoIterator<Item = &'a ReceiverBytes>,
    ) -> Result<Self, Error> {
        let mut distinct = BTreeSet::new();
        for receiver in receivers {
            distinct.insert(*receiver);
            if distinct.len() > MAX_RECEIVERS as usize {
                return Err(Error::Capacity);
            }
        }
        Ok(Self {
            genesis: *genesis,
            block,
            parent,
            filter: Filter::build_with(&salt(genesis, block), &distinct, P, M),
        })
    }

    /// Returns the block identity to verify against the consumer's chain.
    pub fn block(&self) -> BlockId {
        self.block
    }

    /// Returns the declared parent hash, also checked by batch validation.
    pub fn parent(&self) -> Hash {
        self.parent
    }
}

/// A consecutive prefix of a requested range, with network and correction identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    genesis: Hash,
    revision: u64,
    filters: Vec<BlockFilter>,
}

impl Batch {
    /// Constructs a consecutive bounded batch. Rejects filters built for a different network.
    pub fn new(genesis: Hash, revision: u64, filters: Vec<BlockFilter>) -> Result<Self, Error> {
        let batch = Self {
            genesis,
            revision,
            filters,
        };
        batch.validate()?;
        Ok(batch)
    }

    /// Checks bounds and linkage without assuming a trusted network or chain.
    fn validate(&self) -> Result<(), Error> {
        if self.filters.is_empty() || self.filters.len() > MAX_BLOCKS as usize {
            return Err(Error::Capacity);
        }
        let mut size = BATCH_HEADER;
        for (i, filter) in self.filters.iter().enumerate() {
            size += BATCH_BLOCK + filter.filter.bytes().len();
            if size > MAX_BATCH_BYTES {
                return Err(Error::Capacity);
            }
            if filter.genesis != self.genesis || filter.block.height == 0 {
                return Err(Error::Coverage);
            }
            if i > 0 {
                let previous = self.filters[i - 1].block;
                if previous.height.checked_add(1) != Some(filter.block.height)
                    || previous.hash != filter.parent
                {
                    return Err(Error::Coverage);
                }
            }
        }
        Ok(())
    }

    /// Binds a response to the captured head and request; shorter nonempty prefixes are allowed.
    pub fn check(&self, head: &Head, from: u32, limit: u32) -> Result<(), Error> {
        head.check_request(from, limit)?;
        self.validate()?;
        let last = self.filters.last().expect("validated nonempty").block;
        if self.genesis != head.genesis
            || self.revision != head.revision
            || self.filters[0].block.height != from
            || self.filters.len() > limit as usize
            || last.height > head.tip.height
            || (last.height == head.tip.height && last.hash != head.tip.hash)
        {
            return Err(Error::Coverage);
        }
        Ok(())
    }

    /// Returns filters in increasing height order, including empty blocks.
    pub fn filters(&self) -> &[BlockFilter] {
        &self.filters
    }

    /// Tests every input against the block at `index`, preserving input order.
    pub fn matches(&self, index: usize, receivers: &[ReceiverBytes]) -> Result<Vec<bool>, Error> {
        let filter = self.filters.get(index).ok_or(Error::Coverage)?;
        Ok(filter
            .filter
            .matches(&salt(&self.genesis, filter.block), receivers))
    }

    /// Encodes the bounded canonical batch, without an archive index or proof tree.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = MAGIC.to_vec();
        out.extend(self.genesis);
        out.extend(self.revision.to_le_bytes());
        out.extend((self.filters.len() as u32).to_le_bytes());
        for filter in &self.filters {
            out.extend(filter.block.height.to_le_bytes());
            out.extend(filter.block.hash);
            out.extend(filter.parent);
            out.extend((filter.filter.bytes().len() as u32).to_le_bytes());
            out.extend(filter.filter.bytes());
        }
        Ok(out)
    }

    /// Parses the entire bounded response, rejecting truncation, gaps and invalid GCS tails.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(Error::Capacity);
        }
        let mut rest = bytes.strip_prefix(MAGIC).ok_or(Error::Malformed)?;
        let genesis = take::<32>(&mut rest)?;
        let revision = u64::from_le_bytes(take(&mut rest)?);
        let count = u32::from_le_bytes(take(&mut rest)?);
        if count == 0 || count > MAX_BLOCKS {
            return Err(Error::Capacity);
        }
        let mut filters = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let block = BlockId {
                height: u32::from_le_bytes(take(&mut rest)?),
                hash: take(&mut rest)?,
            };
            let parent = take(&mut rest)?;
            let len = u32::from_le_bytes(take(&mut rest)?) as usize;
            let (bytes, tail) = rest.split_at_checked(len).ok_or(Error::Malformed)?;
            rest = tail;
            let mut payload = bytes;
            if zakura_filters::read_compact_size(&mut payload).map_err(|_| Error::Malformed)?
                > u64::from(MAX_RECEIVERS)
            {
                return Err(Error::Capacity);
            }
            filters.push(BlockFilter {
                genesis,
                block,
                parent,
                filter: Filter::decode_with(bytes, P, M)?,
            });
        }
        if !rest.is_empty() {
            return Err(Error::Malformed);
        }
        Self::new(genesis, revision, filters)
    }
}

/// Commits to the chain a [`Range`] was coded on: the parent of its first block, then every
/// block hash in height order.
fn chain_digest(genesis: &Hash, from: u32, parent: &Hash, hashes: &[Hash]) -> Hash {
    let mut digest = Sha256::new()
        .chain_update(b"ironwood-receiver/v1/block-range\0")
        .chain_update(genesis)
        .chain_update(from.to_le_bytes())
        .chain_update(parent);
    for hash in hashes {
        digest.update(hash);
    }
    digest.finalize().into()
}

/// Consecutive block hints without per-block identities, so an empty block costs one byte.
/// A consumer recomputes the chain digest from its own blocks in [`Range::bind`], which
/// replaces the per-block hash and parent checks of a [`Batch`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    revision: u64,
    from: u32,
    digest: Hash,
    sets: Vec<Filter>,
}

impl Range {
    /// Encodes the longest prefix of consecutive `filters` that fits [`MAX_BATCH_BYTES`],
    /// up to [`MAX_RANGE_BLOCKS`]. Rejects filters for another network or broken linkage.
    pub fn encode(
        genesis: &Hash,
        revision: u64,
        filters: &[BlockFilter],
    ) -> Result<Vec<u8>, Error> {
        if filters.is_empty() {
            return Err(Error::Capacity);
        }
        let mut size = RANGE_HEADER;
        let count = filters
            .iter()
            .take(MAX_RANGE_BLOCKS as usize)
            .take_while(|filter| {
                size += filter.filter.bytes().len();
                size <= MAX_BATCH_BYTES
            })
            .count();
        let filters = &filters[..count];
        let first = filters.first().ok_or(Error::Capacity)?;
        let mut hashes = Vec::with_capacity(count);
        for (i, filter) in filters.iter().enumerate() {
            if filter.genesis != *genesis || filter.block.height == 0 {
                return Err(Error::Coverage);
            }
            if i > 0 {
                let previous = filters[i - 1].block;
                if previous.height.checked_add(1) != Some(filter.block.height)
                    || previous.hash != filter.parent
                {
                    return Err(Error::Coverage);
                }
            }
            hashes.push(filter.block.hash);
        }
        let from = first.block.height;
        let mut out = RANGE_MAGIC.to_vec();
        out.extend(revision.to_le_bytes());
        out.extend(from.to_le_bytes());
        // At most MAX_RANGE_BLOCKS, so the count fits a u32.
        out.extend((count as u32).to_le_bytes());
        out.extend(chain_digest(genesis, from, &first.parent, &hashes));
        for filter in filters {
            out.extend(filter.filter.bytes());
        }
        Ok(out)
    }

    /// Parses the entire bounded response, rejecting truncation and invalid GCS tails.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(Error::Capacity);
        }
        let mut rest = bytes.strip_prefix(RANGE_MAGIC).ok_or(Error::Malformed)?;
        let revision = u64::from_le_bytes(take(&mut rest)?);
        let from = u32::from_le_bytes(take(&mut rest)?);
        let count = u32::from_le_bytes(take(&mut rest)?);
        let digest = take::<32>(&mut rest)?;
        // Every set takes at least one byte, so the count is bounded before allocating.
        if from == 0 || count == 0 || count > MAX_RANGE_BLOCKS || count as usize > rest.len() {
            return Err(Error::Capacity);
        }
        from.checked_add(count - 1).ok_or(Error::Malformed)?;
        let mut sets = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (set, tail) = super::gcs::split(rest, P, M, u64::from(MAX_RECEIVERS))?;
            rest = tail;
            sets.push(Filter::decode_with(set, P, M)?);
        }
        if !rest.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            revision,
            from,
            digest,
            sets,
        })
    }

    /// Binds a response to the captured head and request; shorter nonempty prefixes are
    /// allowed. Chain identity is checked later, by [`Range::bind`].
    pub fn check(&self, head: &Head, from: u32, limit: u32) -> Result<(), Error> {
        head.check_range(from, limit)?;
        if self.revision != head.revision
            || self.from != from
            || self.sets.len() > limit as usize
            || self.end() > head.tip.height
        {
            return Err(Error::Coverage);
        }
        Ok(())
    }

    /// The first block's height.
    pub fn from(&self) -> u32 {
        self.from
    }

    /// The last block's height.
    pub fn end(&self) -> u32 {
        // Decoding checked that the range's heights fit a u32.
        self.from + (self.sets.len() as u32 - 1)
    }

    /// Recovers [`Batch`]es of at most [`MAX_BLOCKS`] and [`MAX_BATCH_BYTES`] from the
    /// consumer's own chain:
    /// `parent` is its hash at `from - 1` and `hashes` its hashes from `from` through
    /// [`Range::end`]. Fails with [`Error::Coverage`] unless they are exactly the chain the
    /// service coded the range on.
    pub fn bind(&self, genesis: &Hash, parent: Hash, hashes: &[Hash]) -> Result<Vec<Batch>, Error> {
        if hashes.len() != self.sets.len()
            || chain_digest(genesis, self.from, &parent, hashes) != self.digest
        {
            return Err(Error::Coverage);
        }
        let filters: Vec<_> = self
            .sets
            .iter()
            .zip(hashes)
            .enumerate()
            .map(|(i, (filter, hash))| BlockFilter {
                genesis: *genesis,
                // Decoding checked that the range's heights fit a u32.
                block: BlockId {
                    height: self.from + i as u32,
                    hash: *hash,
                },
                parent: if i == 0 { parent } else { hashes[i - 1] },
                filter: filter.clone(),
            })
            .collect();
        // A batch adds block identities that the range left out, so a dense range is split
        // by encoded size as well as block count. One block always fits: a set of at most
        // MAX_RECEIVERS values is far below the byte cap.
        let mut batches = Vec::new();
        let mut chunk = Vec::new();
        let mut size = BATCH_HEADER;
        for filter in filters {
            let block = BATCH_BLOCK + filter.filter.bytes().len();
            if !chunk.is_empty()
                && (chunk.len() == MAX_BLOCKS as usize || size + block > MAX_BATCH_BYTES)
            {
                batches.push(Batch::new(
                    *genesis,
                    self.revision,
                    std::mem::take(&mut chunk),
                )?);
                size = BATCH_HEADER;
            }
            size += block;
            chunk.push(filter);
        }
        batches.push(Batch::new(*genesis, self.revision, chunk)?);
        Ok(batches)
    }
}

/// Reads a fixed-size field without allocating or accepting a short input.
fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], Error> {
    let (field, rest) = bytes.split_first_chunk::<N>().ok_or(Error::Malformed)?;
    *bytes = rest;
    Ok(*field)
}
