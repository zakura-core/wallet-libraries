//! Canonical archive heads, bounded pages and their authenticated range index.
//!
//! The index authenticates bytes relative to an accepted head, not the publisher's
//! completeness. Callers anchor that head to their connected chain and persist its
//! identity and epoch before treating negative filters as coverage.
use crate::{
    blocks::{BlockFilter, BlockId, MAX_BLOCK_FILTER_BYTES},
    object::{self, Reader},
    seen::SeenSet,
    Error, Hash,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Blocks per transport page. Pages have fixed boundaries in the height space.
pub const PAGE_BLOCKS: u32 = 256;
/// Merkle levels for all possible pages in the `u32` block-height space.
pub const INDEX_DEPTH: usize = 24;
/// Maximum canonical page bytes, including its envelope.
pub const MAX_PAGE_BYTES: usize = 64 << 20;
/// Maximum head response, checked before parsing.
pub const MAX_HEAD_BYTES: usize = 1024;
/// Maximum page-plus-proof response.
pub const MAX_RANGE_BYTES: usize = MAX_PAGE_BYTES + INDEX_DEPTH * 32 + 4;
const HEAD_MAGIC: &[u8; 8] = b"IWHEAD1\0";
const PAGE_MAGIC: &[u8; 8] = b"IWPAGE1\0";

/// A complete provider history object. Missing history is represented by no reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeenRef {
    pub digest: Hash,
    pub since_unix: i64,
    pub until_unix: i64,
}

impl SeenRef {
    /// Binds the exact object and feed coverage declared by a head.
    pub fn check(&self, genesis: &Hash, set: &SeenSet) -> Result<(), Error> {
        if set.genesis() != *genesis
            || set.since_unix != self.since_unix
            || set.until_unix != self.until_unix
            || set.digest()? != self.digest
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

/// One immutable archive state. Its digest pins page requests and their proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub genesis: Hash,
    pub archive: Hash,
    pub epoch: u64,
    pub first_height: u32,
    pub frontier: BlockId,
    pub index_root: Hash,
    pub seen: Option<SeenRef>,
}

impl Head {
    /// Checks structural invariants, not network expectations or chain membership.
    pub fn validate(&self) -> Result<(), Error> {
        if self.archive == [0; 32]
            || self.first_height > self.frontier.height
            || self
                .seen
                .as_ref()
                .is_some_and(|s| s.since_unix > s.until_unix)
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Checks against the network and exact frontier independently accepted by the wallet.
    pub fn check_anchor(&self, genesis: &Hash, anchor: BlockId) -> Result<(), Error> {
        self.validate()?;
        if self.genesis != *genesis || self.frontier != anchor {
            return Err(Error::Coverage);
        }
        Ok(())
    }

    /// Encodes the archive identity, epoch, supported span, index root and optional seen reference.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = object::header(HEAD_MAGIC, &self.genesis);
        out.extend(self.archive);
        out.extend(self.epoch.to_le_bytes());
        out.extend(self.first_height.to_le_bytes());
        out.extend(self.frontier.height.to_le_bytes());
        out.extend(self.frontier.hash);
        out.extend(self.index_root);
        match &self.seen {
            None => out.push(0),
            Some(seen) => {
                out.push(1);
                out.extend(seen.digest);
                out.extend(seen.since_unix.to_le_bytes());
                out.extend(seen.until_unix.to_le_bytes());
            }
        }
        Ok(out)
    }

    /// Decodes one bounded head, rejecting unsupported profiles and surplus bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_HEAD_BYTES {
            return Err(Error::Capacity);
        }
        let (genesis, mut r) = Reader::open(bytes, HEAD_MAGIC)?;
        let head = Self {
            genesis,
            archive: r.array()?,
            epoch: r.u64()?,
            first_height: r.u32()?,
            frontier: BlockId {
                height: r.u32()?,
                hash: r.array()?,
            },
            index_root: r.array()?,
            seen: match r.u8()? {
                0 => None,
                1 => Some(SeenRef {
                    digest: r.array()?,
                    since_unix: r.i64()?,
                    until_unix: r.i64()?,
                }),
                _ => return Err(Error::Malformed),
            },
        };
        r.finish()?;
        head.validate()?;
        Ok(head)
    }

    /// Identifies the exact head requested by a client, including its index and seen state.
    pub fn digest(&self) -> Result<Hash, Error> {
        Ok(object::digest(&self.encode()?))
    }

    /// The complete intersection of a fixed page with this head's supported history.
    pub fn page_span(&self, page: u32) -> Result<(u32, u32), Error> {
        self.validate()?;
        if page >= (1 << INDEX_DEPTH) {
            return Err(Error::Coverage);
        }
        let first = (page * PAGE_BLOCKS).max(self.first_height);
        let last = (page * PAGE_BLOCKS + (PAGE_BLOCKS - 1)).min(self.frontier.height);
        if first > last {
            return Err(Error::Coverage);
        }
        Ok((first, last))
    }
}

/// A complete page of consecutive block hints, including explicit empty blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    genesis: Hash,
    parent: Hash,
    filters: Vec<BlockFilter>,
}

impl Page {
    /// Validates a nonempty contiguous span within one page before exposing it.
    pub fn new(parent: Hash, filters: Vec<BlockFilter>) -> Result<Self, Error> {
        let first = filters.first().ok_or(Error::Malformed)?;
        if filters.len() > PAGE_BLOCKS as usize {
            return Err(Error::Capacity);
        }
        let genesis = first.genesis();
        let start = first.block().height;
        for (offset, filter) in filters.iter().enumerate() {
            let height = start.checked_add(offset as u32).ok_or(Error::Malformed)?;
            if filter.genesis() != genesis
                || filter.block().height != height
                || height / PAGE_BLOCKS != start / PAGE_BLOCKS
            {
                return Err(Error::Malformed);
            }
        }
        Ok(Self {
            genesis,
            parent,
            filters,
        })
    }

    /// Returns the fixed index position of this page.
    pub fn number(&self) -> u32 {
        self.filters[0].block().height / PAGE_BLOCKS
    }

    /// Returns the hash preceding the first block, for joining adjacent accepted pages.
    pub fn parent(&self) -> Hash {
        self.parent
    }

    /// Returns every covered block in order. Empty filters are explicit entries.
    pub fn filters(&self) -> &[BlockFilter] {
        &self.filters
    }

    /// Encodes shared fields once, then each hash and length-delimited GCS payload.
    /// A zero length represents the canonical empty GCS payload `[0]`.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = object::header(PAGE_MAGIC, &self.genesis);
        out.extend(self.filters[0].block().height.to_le_bytes());
        out.extend((self.filters.len() as u16).to_le_bytes());
        out.extend(self.parent);
        for filter in &self.filters {
            out.extend(filter.block().hash);
            let payload = if filter.count() == 0 {
                &[][..]
            } else {
                filter.payload()
            };
            out.extend((payload.len() as u32).to_le_bytes());
            out.extend(payload);
            if out.len() > MAX_PAGE_BYTES {
                return Err(Error::Capacity);
            }
        }
        Ok(out)
    }

    /// Decodes bounded contiguous hints with canonical empty entries and strict inner filters.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_PAGE_BYTES {
            return Err(Error::Capacity);
        }
        let (genesis, mut r) = Reader::open(bytes, PAGE_MAGIC)?;
        let first = r.u32()?;
        let count = u16::from_le_bytes(r.array()?);
        if count == 0 || u32::from(count) > PAGE_BLOCKS {
            return Err(Error::Malformed);
        }
        let parent = r.array()?;
        let mut filters = Vec::with_capacity(usize::from(count));
        for offset in 0..count {
            let block = BlockId {
                height: first
                    .checked_add(u32::from(offset))
                    .ok_or(Error::Malformed)?,
                hash: r.array()?,
            };
            let payload = r.payload()?;
            if payload.len() > MAX_BLOCK_FILTER_BYTES || payload == [0] {
                return Err(Error::Malformed);
            }
            filters.push(BlockFilter::from_payload(
                genesis,
                block,
                if payload.is_empty() { &[0] } else { payload },
            )?);
        }
        r.finish()?;
        Self::new(parent, filters)
    }

    /// Returns the canonical content digest, stable across unrelated head updates.
    pub fn digest(&self) -> Result<Hash, Error> {
        Ok(object::digest(&self.encode()?))
    }
}

/// A page's Merkle siblings, from leaf to root. Position comes from the page itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof(pub [Hash; INDEX_DEPTH]);

impl Proof {
    /// Checks exact page coverage and bytes against a head the caller already anchored.
    pub fn verify(&self, head: &Head, page: &Page) -> Result<(), Error> {
        let (first, last) = head.page_span(page.number())?;
        if page.genesis != head.genesis
            || page.filters[0].block().height != first
            || page.filters.last().unwrap().block().height != last
            || (last == head.frontier.height
                && page.filters.last().unwrap().block() != head.frontier)
        {
            return Err(Error::Coverage);
        }
        let mut value = leaf(page.number(), &page.digest()?);
        let mut index = page.number();
        for (level, sibling) in self.0.iter().enumerate() {
            value = if index & 1 == 0 {
                branch(level as u8, &value, sibling)
            } else {
                branch(level as u8, sibling, &value)
            };
            index >>= 1;
        }
        if value != head.index_root {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Encodes the page and fixed-size proof as one bounded transport response.
    pub fn encode(&self, page: &Page) -> Result<Vec<u8>, Error> {
        let bytes = page.encode()?;
        let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
        out.extend(bytes);
        for hash in self.0 {
            out.extend(hash);
        }
        Ok(out)
    }

    /// Decodes and checks the requested page under the exact accepted head.
    pub fn decode(head: &Head, requested: u32, bytes: &[u8]) -> Result<Page, Error> {
        if bytes.len() > MAX_RANGE_BYTES {
            return Err(Error::Capacity);
        }
        let (length, rest) = bytes.split_first_chunk::<4>().ok_or(Error::Malformed)?;
        let (payload, proof) = rest
            .split_at_checked(u32::from_le_bytes(*length) as usize)
            .ok_or(Error::Malformed)?;
        if proof.len() != INDEX_DEPTH * 32 {
            return Err(Error::Malformed);
        }
        let page = Page::decode(payload)?;
        if page.number() != requested {
            return Err(Error::Coverage);
        }
        let siblings = std::array::from_fn(|i| proof[i * 32..(i + 1) * 32].try_into().unwrap());
        Self(siblings).verify(head, &page)?;
        Ok(page)
    }
}

/// Mutable publisher-side index. Updating one page changes only its path to the root.
#[derive(Clone, Debug)]
pub struct Index {
    nodes: BTreeMap<(u8, u32), Hash>,
    empty: [Hash; INDEX_DEPTH + 1],
}

impl Default for Index {
    /// Creates an empty index with domain-separated missing leaves.
    fn default() -> Self {
        let mut empty = [[0; 32]; INDEX_DEPTH + 1];
        empty[0] = Sha256::digest(b"ironwood-receiver/v1/index-empty\0").into();
        for level in 0..INDEX_DEPTH {
            empty[level + 1] = branch(level as u8, &empty[level], &empty[level]);
        }
        Self {
            nodes: BTreeMap::new(),
            empty,
        }
    }
}

impl Index {
    /// Gets an existing node or the missing subtree at its level.
    fn node(&self, level: u8, index: u32) -> Hash {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.empty[usize::from(level)])
    }

    /// Commits a page digest, or removes a page after a rewind. Persist page bytes first.
    pub fn update(&mut self, page: u32, digest: Option<Hash>) -> Result<(), Error> {
        if page >= (1 << INDEX_DEPTH) {
            return Err(Error::Malformed);
        }
        match digest {
            Some(digest) => {
                self.nodes.insert((0, page), leaf(page, &digest));
            }
            None => {
                self.nodes.remove(&(0, page));
            }
        }
        let mut index = page;
        for level in 0..INDEX_DEPTH as u8 {
            index >>= 1;
            let value = branch(
                level,
                &self.node(level, index * 2),
                &self.node(level, index * 2 + 1),
            );
            if value == self.empty[usize::from(level) + 1] {
                self.nodes.remove(&(level + 1, index));
            } else {
                self.nodes.insert((level + 1, index), value);
            }
        }
        Ok(())
    }

    /// Returns the root to publish only once every supported page is durable and complete.
    pub fn root(&self) -> Hash {
        self.node(INDEX_DEPTH as u8, 0)
    }

    /// Returns the proof at this index state, including for a missing page which cannot verify.
    pub fn proof(&self, page: u32) -> Result<Proof, Error> {
        if page >= (1 << INDEX_DEPTH) {
            return Err(Error::Malformed);
        }
        Ok(Proof(std::array::from_fn(|level| {
            self.node(level as u8, (page >> level) ^ 1)
        })))
    }
}

/// Binds the index position and a canonical page's content, distinct from missing leaves.
fn leaf(page: u32, digest: &Hash) -> Hash {
    Sha256::new()
        .chain_update(b"ironwood-receiver/v1/index-leaf\0")
        .chain_update(page.to_le_bytes())
        .chain_update(digest)
        .finalize()
        .into()
}

/// Binds two ordered child hashes and their level with a separate domain.
fn branch(level: u8, left: &Hash, right: &Hash) -> Hash {
    Sha256::new()
        .chain_update(b"ironwood-receiver/v1/index-branch\0")
        .chain_update([level])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// The connected-chain relationship independently checked by the wallet.
/// Do not construct this evidence by copying the server's two claimed hashes.
#[derive(Clone, Copy, Debug)]
pub struct ConnectedCoverage {
    pub genesis: Hash,
    pub target: BlockId,
    pub publication: BlockId,
}

/// A PIR session's declared archive history, served with that immutable session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coverage {
    pub genesis: Hash,
    pub archive: Hash,
    pub epoch: u64,
    pub session: Hash,
    pub first_height: u32,
    pub frontier: BlockId,
}

impl Coverage {
    /// Validates a declaration's own bounds, not its session or connected chain.
    pub fn validate(&self) -> Result<(), Error> {
        if self.archive == [0; 32] || self.first_height > self.frontier.height {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Fences completion against the captured history and independently accepted chain.
    /// The caller must additionally fence its account/settings/rewind generation after awaits.
    pub fn check(&self, target: &Head, chain: ConnectedCoverage) -> Result<(), Error> {
        self.check_through(target, target.frontier, chain)
    }

    /// Checks a captured older obligation without requiring PIR to catch the latest filter head.
    /// The head's history must already be accepted, and both chain points independently connected.
    pub fn check_through(
        &self,
        head: &Head,
        target: BlockId,
        chain: ConnectedCoverage,
    ) -> Result<(), Error> {
        self.validate()?;
        head.validate()?;
        if self.genesis != head.genesis
            || self.archive != head.archive
            || self.epoch != head.epoch
            || self.first_height > head.first_height
            || target.height < head.first_height
            || target.height > head.frontier.height
            || (target.height == head.frontier.height && target.hash != head.frontier.hash)
            || self.frontier.height < target.height
            || chain.genesis != self.genesis
            || chain.target != target
            || chain.publication != self.frontier
        {
            return Err(Error::Coverage);
        }
        Ok(())
    }

    /// Encodes a declaration whose session must match the actual PIR manifest.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = object::header(b"IWCOVR1\0", &self.genesis);
        out.extend(self.archive);
        out.extend(self.epoch.to_le_bytes());
        out.extend(self.session);
        out.extend(self.first_height.to_le_bytes());
        out.extend(self.frontier.height.to_le_bytes());
        out.extend(self.frontier.hash);
        Ok(out)
    }

    /// Decodes a bounded canonical session declaration.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_HEAD_BYTES {
            return Err(Error::Capacity);
        }
        let (genesis, mut r) = Reader::open(bytes, b"IWCOVR1\0")?;
        let result = Self {
            genesis,
            archive: r.array()?,
            epoch: r.u64()?,
            session: r.array()?,
            first_height: r.u32()?,
            frontier: BlockId {
                height: r.u32()?,
                hash: r.array()?,
            },
        };
        r.finish()?;
        result.validate()?;
        Ok(result)
    }
}
