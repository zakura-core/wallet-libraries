//! Receiver hints for individual canonical blocks, independent of PIR placement.
//!
//! A filter is not proof of completeness, ownership, or spendability. Archive
//! verification binds its digest to a publication; the wallet then checks the
//! connected chain and trial-decrypts matches with its own keys.
use crate::{
    gcs::{Filter, Params},
    object::{self, Reader},
    Error, Hash, ReceiverBytes,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Golomb-Rice parameter for block payment hints.
pub const P: u8 = 20;
/// Range multiplier for block payment hints.
pub const M: u64 = 1_569_792;
/// Maximum distinct recipients in one block filter.
pub const MAX_RECEIVERS: u32 = 65_536;
/// Maximum encoded block filter, including its envelope.
pub const MAX_BLOCK_FILTER_BYTES: usize = 1 << 20;
const MAGIC: &[u8; 8] = b"IWBLKF1\0";
const PARAMS: Params = Params { p: P, m: M };

/// A height and hash whose connected-chain membership the wallet must verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockId {
    pub height: u32,
    pub hash: Hash,
}

impl BlockId {
    /// Derives stable filter salt from the network and this block, not a PIR table.
    pub fn salt(&self, genesis: &Hash) -> Hash {
        Sha256::new()
            .chain_update(b"ironwood-receiver/v1/block-filter-salt\0")
            .chain_update(genesis)
            .chain_update(self.height.to_le_bytes())
            .chain_update(self.hash)
            .finalize()
            .into()
    }
}

/// Distinct recipients of eligible zero-OVK Ironwood outputs in one block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFilter {
    genesis: Hash,
    block: BlockId,
    filter: Filter,
}

impl BlockFilter {
    /// Builds a bounded filter, deduplicating recipients before applying capacity.
    pub fn build<'a>(
        genesis: Hash,
        block: BlockId,
        receivers: impl IntoIterator<Item = &'a ReceiverBytes>,
    ) -> Result<Self, Error> {
        let mut distinct = BTreeSet::new();
        for receiver in receivers {
            distinct.insert(*receiver);
            if distinct.len() > MAX_RECEIVERS as usize {
                return Err(Error::Capacity);
            }
        }
        let result = Self {
            genesis,
            block,
            filter: Filter::build_with(PARAMS, &block.salt(&genesis), &distinct),
        };
        if result.encode().len() > MAX_BLOCK_FILTER_BYTES {
            return Err(Error::Capacity);
        }
        Ok(result)
    }

    /// Returns the network identity bound into this filter.
    pub fn genesis(&self) -> Hash {
        self.genesis
    }

    /// Returns the exact block whose recipient hints this filter contains.
    pub fn block(&self) -> BlockId {
        self.block
    }

    /// Returns the number of distinct recipients, including hash collisions.
    pub fn count(&self) -> u32 {
        self.filter.count()
    }

    /// Returns candidate membership in input order; every included receiver matches.
    pub fn matches(&self, receivers: &[ReceiverBytes]) -> Vec<bool> {
        self.filter
            .matches(&self.block.salt(&self.genesis), receivers)
    }

    /// Encodes the version/profile/network header, block, salt, parameters and GCS.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = object::header(MAGIC, &self.genesis);
        out.extend(self.block.height.to_le_bytes());
        out.extend(self.block.hash);
        out.extend(self.block.salt(&self.genesis));
        out.push(P);
        out.extend(M.to_le_bytes());
        out.extend(self.count().to_le_bytes());
        out.extend((self.filter.bytes().len() as u32).to_le_bytes());
        out.extend(self.filter.bytes());
        out
    }

    /// Returns the digest an archive index must bind to this block's filter.
    pub fn digest(&self) -> Hash {
        object::digest(&self.encode())
    }

    /// Decodes canonical bounded bytes, rejecting inconsistent salt, count or coding.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BLOCK_FILTER_BYTES {
            return Err(Error::Capacity);
        }
        let (genesis, mut reader) = Reader::open(bytes, MAGIC)?;
        let block = BlockId {
            height: reader.u32()?,
            hash: reader.array()?,
        };
        let salt: Hash = reader.array()?;
        let (p, m, count) = (reader.u8()?, reader.u64()?, reader.u32()?);
        let payload = reader.payload()?;
        reader.finish()?;
        if salt != block.salt(&genesis) || p != P || m != M || count > MAX_RECEIVERS {
            return Err(Error::Malformed);
        }
        // Check the inner count before the shared codec allocates decoded values.
        let mut inner = payload;
        if zakura_filters::read_compact_size(&mut inner).map_err(|_| Error::Malformed)?
            != u64::from(count)
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            genesis,
            block,
            filter: Filter::decode_with(payload, PARAMS)?,
        })
    }
}
