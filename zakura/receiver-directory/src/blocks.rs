//! Rolling block hints. Matches schedule PIR; they never establish ownership or absence.
//!
//! The service is trusted for complete indexing. Consumers independently check block
//! identities against their chain before advancing coverage. Pruned ranges use PIR.
use crate::{gcs::Filter, Error, Hash, ReceiverBytes};
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
        let mut size = MAGIC.len() + 32 + 8 + 4;
        for (i, filter) in self.filters.iter().enumerate() {
            size += 4 + 32 + 32 + 4 + filter.filter.bytes().len();
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

/// Reads a fixed-size field without allocating or accepting a short input.
fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], Error> {
    let (field, rest) = bytes.split_first_chunk::<N>().ok_or(Error::Malformed)?;
    *bytes = rest;
    Ok(*field)
}
