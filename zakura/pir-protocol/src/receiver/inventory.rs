//! Sealed Receiver shards and the immutable inventory that lists them.
//!
//! History is split into contiguous shards: immutable sealed shards, then at most one
//! recent tier replaced each publication. Each shard has one or more fixed-geometry
//! segments (a payment session and its companion witness session) and, when sealed, may
//! name a GCS receiver filter. A small [`Head`] identifies an inventory fetched in bounded
//! [`Chunk`]s; the digest it carries proves the chunks are the complete, ordered list.
use super::{
    Hash,
    session::{Error, Publication},
    shards, witness,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The inventory format a head commits to.
pub const PROTOCOL: &str = "ironwood-receiver-inventory-v1";
/// Most segments in one shard: a block too large for one table spans several.
pub const MAX_SEGMENTS: usize = 8;
/// Most shards in one inventory, which also bounds the chunk requests of one capture.
pub const MAX_SHARDS: u32 = 1 << 17;
/// Shards per chunk; every chunk but the last is full.
pub const CHUNK_SHARDS: usize = 16;
/// Bound on a serialized chunk, read before parsing.
pub const MAX_CHUNK_BYTES: usize = 1024 * 1024;
/// Default bound on the serialized chunks one capture retains.
pub const MAX_CAPTURE_BYTES: usize = 128 * 1024 * 1024;

/// A sealed shard's filter: the digest and size of its encoding and its receiver count,
/// in the fixed parameters of [`shards::ShardFilter`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterRef {
    pub digest: Hash,
    pub bytes: u32,
    pub receivers: u32,
}

/// One shard: contiguous coverage including empty blocks, its segments and its filter.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shard {
    pub index: u32,
    /// Sealed shards never change under one correction generation on one chain.
    pub sealed: bool,
    pub start_height: u32,
    pub start_parent: Hash,
    pub start_position: u64,
    pub end_height: u32,
    pub end_hash: Hash,
    pub end_position: u64,
    /// Each segment's payment table covers exactly this shard; pages are segment-local.
    pub segments: Vec<Publication>,
    pub filter: Option<FilterRef>,
}

impl Shard {
    /// Whether this shard can no longer change on its chain under its correction
    /// generation: it is sealed and every segment's witness payloads are final, because the
    /// Ironwood shard holding its last position was full when they were built.
    pub fn settled(&self) -> bool {
        self.sealed
            && self.segments.iter().all(|segment| {
                self.end_position == self.start_position
                    || witness::is_final(self.end_position - 1, segment.witnesses.table.tree_size)
            })
    }

    /// The coverage its filter is keyed to.
    pub fn coverage(&self) -> shards::Coverage {
        shards::Coverage {
            start_height: self.start_height,
            end_height: self.end_height,
            end_hash: self.end_hash,
        }
    }

    /// Checks coverage order, the segment bound, that every segment validates and covers
    /// exactly this shard for `genesis` and `history_revision`, and that only a sealed
    /// shard names a bounded filter.
    fn validate(&self, genesis: &Hash, history_revision: u64) -> Result<(), Error> {
        if self.start_height > self.end_height
            || self.start_position > self.end_position
            || self.segments.is_empty()
            || self.segments.len() > MAX_SEGMENTS
            || self.filter.as_ref().is_some_and(|f| {
                !self.sealed
                    || f.bytes as usize > shards::MAX_FILTER_BYTES
                    || f.receivers > shards::MAX_RECEIVERS
            })
        {
            return Err(Error::Malformed);
        }
        for segment in &self.segments {
            segment.validate()?;
            let d = &segment.payments.directory;
            if &d.genesis != genesis
                || d.history_revision != history_revision
                || d.start_height != self.start_height
                || d.start_parent != self.start_parent
                || d.start_position != self.start_position
                || d.end_height != self.end_height
                || d.end_hash != self.end_hash
                || d.end_position != self.end_position
            {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }

    /// Binds every field, including each segment's payment and witness session IDs.
    fn digest(&self) -> Result<Hash, Error> {
        let mut h = Sha256::new();
        h.update(b"ironwood-receiver-inventory/v1/shard\0");
        h.update(self.index.to_le_bytes());
        h.update([u8::from(self.sealed)]);
        h.update(self.start_height.to_le_bytes());
        h.update(self.start_parent);
        h.update(self.start_position.to_le_bytes());
        h.update(self.end_height.to_le_bytes());
        h.update(self.end_hash);
        h.update(self.end_position.to_le_bytes());
        h.update((self.segments.len() as u32).to_le_bytes());
        for segment in &self.segments {
            h.update(segment.payments.id()?);
            h.update(segment.witnesses.id()?);
        }
        match &self.filter {
            None => h.update([0]),
            Some(f) => {
                h.update([1]);
                h.update(f.digest);
                h.update(f.bytes.to_le_bytes());
                h.update(f.receivers.to_le_bytes());
            }
        }
        Ok(h.finalize().into())
    }
}

/// The small publication head that identifies one immutable inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub protocol: String,
    pub genesis: Hash,
    /// The correction generation every shard is built under.
    pub history_revision: u64,
    /// The inventory identity, binding these fields and every shard in order.
    pub inventory: Hash,
    pub shards: u32,
    pub start_height: u32,
    pub start_position: u64,
    pub end_height: u32,
    pub end_hash: Hash,
    pub end_position: u64,
}

impl Head {
    /// Checks the protocol, network, a nonempty bounded shard count and coverage order.
    pub fn validate(&self, genesis: &Hash) -> Result<(), Error> {
        if self.protocol != PROTOCOL {
            return Err(Error::Unsupported);
        }
        if &self.genesis != genesis
            || self.shards == 0
            || self.shards > MAX_SHARDS
            || self.start_height > self.end_height
            || self.start_position > self.end_position
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// The number of chunks the inventory is fetched in.
    pub fn chunks(&self) -> u32 {
        self.shards.div_ceil(CHUNK_SHARDS as u32)
    }

    /// The identity of an inventory with these fields over `shards`' digests, in order.
    fn identity(&self, shards: &[Shard]) -> Result<Hash, Error> {
        let mut h = Sha256::new();
        h.update(b"ironwood-receiver-inventory/v1/inventory\0");
        h.update((self.protocol.len() as u64).to_le_bytes());
        h.update(self.protocol.as_bytes());
        h.update(self.genesis);
        h.update(self.history_revision.to_le_bytes());
        h.update(self.shards.to_le_bytes());
        h.update(self.start_height.to_le_bytes());
        h.update(self.start_position.to_le_bytes());
        h.update(self.end_height.to_le_bytes());
        h.update(self.end_hash);
        h.update(self.end_position.to_le_bytes());
        for shard in shards {
            h.update(shard.digest()?);
        }
        Ok(h.finalize().into())
    }
}

/// One bounded page of an inventory's shards.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub inventory: Hash,
    pub index: u32,
    pub shards: Vec<Shard>,
}

/// A complete, validated inventory: contiguous shards from its start to its end, all sealed
/// but possibly the last.
#[derive(Clone, Debug)]
pub struct Inventory {
    head: Head,
    shards: Vec<Shard>,
}

impl Inventory {
    /// Lists `shards` under one head, assigning their indexes in order.
    pub fn build(
        genesis: Hash,
        history_revision: u64,
        mut shards: Vec<Shard>,
    ) -> Result<Self, Error> {
        let (first, last) = match (shards.first(), shards.last()) {
            (Some(first), Some(last)) => (first, last),
            _ => return Err(Error::Malformed),
        };
        let mut head = Head {
            protocol: PROTOCOL.into(),
            genesis,
            history_revision,
            inventory: [0; 32],
            shards: u32::try_from(shards.len()).map_err(|_| Error::Malformed)?,
            start_height: first.start_height,
            start_position: first.start_position,
            end_height: last.end_height,
            end_hash: last.end_hash,
            end_position: last.end_position,
        };
        for (index, shard) in shards.iter_mut().enumerate() {
            shard.index = index as u32;
        }
        Self::check(&head, &shards)?;
        head.inventory = head.identity(&shards)?;
        Ok(Self { head, shards })
    }

    /// Checks the head bounds and that `shards` is its contiguous ordered list.
    fn check(head: &Head, shards: &[Shard]) -> Result<(), Error> {
        head.validate(&head.genesis)?;
        if shards.len() != head.shards as usize {
            return Err(Error::Malformed);
        }
        for (i, shard) in shards.iter().enumerate() {
            check_next(head, i.checked_sub(1).map(|p| &shards[p]), i, shard)?;
        }
        check_end(head, shards)
    }

    /// Reassembles a captured inventory from its chunks, in order. Fails unless they are
    /// exactly the head's complete list, so a missing or substituted chunk is never
    /// mistaken for absent history.
    pub fn from_chunks(head: Head, chunks: Vec<Chunk>) -> Result<Self, Error> {
        let mut capture = Capture::new(head, usize::MAX)?;
        for chunk in chunks {
            capture.push_chunk(chunk, 0)?;
        }
        capture.finish()
    }

    /// The head that identifies this inventory.
    pub fn head(&self) -> &Head {
        &self.head
    }

    /// Every shard, in chain order.
    pub fn shards(&self) -> &[Shard] {
        &self.shards
    }

    /// The bounded chunks a server serves this inventory in, each under
    /// [`MAX_CHUNK_BYTES`] when serialized.
    pub fn chunks(&self) -> Result<Vec<Chunk>, Error> {
        self.shards
            .chunks(CHUNK_SHARDS)
            .enumerate()
            .map(|(index, shards)| {
                let chunk = Chunk {
                    inventory: self.head.inventory,
                    index: index as u32,
                    shards: shards.to_vec(),
                };
                if serde_json::to_vec(&chunk)?.len() > MAX_CHUNK_BYTES {
                    return Err(Error::Malformed);
                }
                Ok(chunk)
            })
            .collect()
    }

    /// Fails unless this inventory ends at the caller's independently accepted anchor and
    /// starts at or before `required_start`. Supply both from wallet chain validation.
    pub fn accept(
        &self,
        genesis: &Hash,
        required_start: u32,
        height: u32,
        hash: &Hash,
    ) -> Result<(), Error> {
        if &self.head.genesis != genesis
            || self.head.start_height > required_start
            || self.head.end_height != height
            || &self.head.end_hash != hash
        {
            return Err(Error::Directory(super::Error::Coverage));
        }
        Ok(())
    }
}

/// Checks that `shard`, at index `i`, validates for `head` and continues `previous`, or
/// starts at the head's start when it is first.
fn check_next(head: &Head, previous: Option<&Shard>, i: usize, shard: &Shard) -> Result<(), Error> {
    shard.validate(&head.genesis, head.history_revision)?;
    let continues = match previous {
        None => {
            shard.start_height == head.start_height && shard.start_position == head.start_position
        }
        Some(previous) => {
            previous.sealed
                && previous.end_height.checked_add(1) == Some(shard.start_height)
                && previous.end_hash == shard.start_parent
                && previous.end_position == shard.start_position
        }
    };
    if shard.index as usize != i || !continues {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Checks that the last of `shards` ends where `head` says the inventory ends.
fn check_end(head: &Head, shards: &[Shard]) -> Result<(), Error> {
    let last = shards.last().ok_or(Error::Malformed)?;
    if last.end_height != head.end_height
        || last.end_hash != head.end_hash
        || last.end_position != head.end_position
    {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// An inventory captured chunk by chunk. Each chunk is checked against the head and the
/// shards before it as it arrives, so a malformed chunk ends the capture before another is
/// fetched, and the bytes retained stay within a budget.
pub struct Capture {
    head: Head,
    shards: Vec<Shard>,
    retained: usize,
    budget: usize,
}

impl Capture {
    /// Starts capturing `head`'s inventory, retaining at most `budget` serialized bytes.
    pub fn new(head: Head, budget: usize) -> Result<Self, Error> {
        head.validate(&head.genesis)?;
        Ok(Self {
            head,
            shards: vec![],
            retained: 0,
            budget,
        })
    }

    /// The index of the chunk to fetch next, or `None` once every chunk arrived.
    pub fn next_chunk(&self) -> Option<u32> {
        let next = self.shards.len().div_ceil(CHUNK_SHARDS) as u32;
        (next < self.head.chunks()).then_some(next)
    }

    /// Checks the next chunk rebuilt from cached shard descriptors, counting its serialized
    /// size against the budget like a fetched chunk.
    pub fn push_cached(&mut self, shards: Vec<Shard>) -> Result<(), Error> {
        let chunk = Chunk {
            inventory: self.head.inventory,
            index: self.next_chunk().ok_or(Error::Malformed)?,
            shards,
        };
        let bytes = serde_json::to_vec(&chunk)?.len();
        self.push_chunk(chunk, bytes)
    }

    /// Parses and checks the next chunk's serialized bytes.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > MAX_CHUNK_BYTES {
            return Err(Error::Malformed);
        }
        let chunk: Chunk = serde_json::from_slice(bytes)?;
        self.push_chunk(chunk, bytes.len())
    }

    /// Checks the next chunk, `bytes` long when serialized: its inventory, index and size,
    /// then every shard in order.
    fn push_chunk(&mut self, chunk: Chunk, bytes: usize) -> Result<(), Error> {
        let index = self.next_chunk().ok_or(Error::Malformed)?;
        let expected = (self.head.shards as usize - self.shards.len()).min(CHUNK_SHARDS);
        self.retained = self.retained.saturating_add(bytes);
        if self.retained > self.budget {
            return Err(Error::Malformed);
        }
        if chunk.inventory != self.head.inventory
            || chunk.index != index
            || chunk.shards.len() != expected
        {
            return Err(Error::Malformed);
        }
        for shard in chunk.shards {
            let i = self.shards.len();
            check_next(&self.head, self.shards.last(), i, &shard)?;
            self.shards.push(shard);
        }
        Ok(())
    }

    /// The complete inventory, once every chunk arrived and the list matches the head's
    /// identity.
    pub fn finish(self) -> Result<Inventory, Error> {
        if self.next_chunk().is_some() {
            return Err(Error::Malformed);
        }
        check_end(&self.head, &self.shards)?;
        if self.head.identity(&self.shards)? != self.head.inventory {
            return Err(Error::Revision);
        }
        Ok(Inventory {
            head: self.head,
            shards: self.shards,
        })
    }
}
