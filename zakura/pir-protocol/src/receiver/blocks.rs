//! Receiver block hints: per-block sets of the receivers each block pays, keyed by height
//! and served as sparse [`Range`]s. A match only schedules PIR; hints never establish
//! ownership or absence.
//!
//! The publisher is trusted for complete indexing and for which chain the sets were built
//! on. A wallet compares a range's end hash with its own block where it holds one, as a
//! consistency check rather than a proof.
use super::{Error, Hash, ReceiverBytes, gcs::Filter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Maximum response size, enforced by transports before buffering.
pub const MAX_RANGE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum distinct receivers per block, checked before allocating decoded values.
pub const MAX_RECEIVERS: u32 = 65_536;
/// Golomb-Rice parameter and range multiplier for block hints.
const P: u8 = 20;
const M: u64 = 1_569_792;
/// Maximum consecutive heights one [`Range`] covers. Empty blocks cost nothing on the
/// wire, so this bounds work, not bytes; [`MAX_RANGE_BYTES`] bounds bytes, and a range
/// that reaches it covers a shorter prefix.
pub const MAX_RANGE_BLOCKS: u32 = 1 << 20;
const RANGE_MAGIC: &[u8; 8] = b"IWRANGE2";
/// Magic, revision, first height, block count, parent hash, end hash and entry count.
pub const RANGE_HEADER: usize = 8 + 8 + 4 + 4 + 32 + 32 + 4;

/// An exact block identity, in protocol byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockId {
    pub height: u32,
    pub hash: Hash,
}

/// The hints a server holds: a sealed archive from `first` through `sealed`, then a tail
/// through `tip` that can still change with a reorg.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub genesis: Hash,
    /// Changes whenever an indexing correction changes sets on an unchanged chain.
    pub revision: u64,
    /// First height served, inclusive. Genesis itself has no set.
    pub first: u32,
    /// Last height of the sealed archive, or `first - 1` when nothing is sealed yet.
    pub sealed: u32,
    pub tip: BlockId,
}

impl Head {
    /// Checks the network and that the advertised heights are ordered.
    pub fn validate(&self, genesis: &Hash) -> Result<(), Error> {
        if &self.genesis != genesis
            || self.first == 0
            || self.first > self.tip.height
            || self
                .sealed
                .checked_add(1)
                .is_none_or(|next| next < self.first)
            || self.sealed > self.tip.height
        {
            return Err(Error::Coverage);
        }
        Ok(())
    }

    /// Checks a bounded [`Range`] request that begins inside the served history.
    pub fn check_range(&self, from: u32, limit: u32) -> Result<(), Error> {
        self.validate(&self.genesis)?;
        if limit == 0 || limit > MAX_RANGE_BLOCKS || from < self.first || from > self.tip.height {
            return Err(Error::Coverage);
        }
        Ok(())
    }
}

/// What serving from a height to the tip would cost, so a wallet can compare hints with
/// PIR before downloading. The server may start earlier than asked, at the start of the
/// sealed chunk holding the requested height; `from` says where.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeSize {
    pub revision: u64,
    pub from: u32,
    /// Encoded bytes of every response from `from` through the head's tip.
    pub bytes: u64,
}

/// Derives a [`HeightSet`]'s coding keys from the network and height alone, so a wallet
/// can match history below its birthday without that history's block hashes. A
/// [`Range`] binds its sets to one chain through its end hash instead.
fn height_salt(genesis: &Hash, height: u32) -> Hash {
    Sha256::new()
        .chain_update(b"ironwood-receiver/v2/height-hints\0")
        .chain_update(genesis)
        .chain_update(height.to_le_bytes())
        .finalize()
        .into()
}

/// One block's nonempty set of receivers, keyed by height (see [`height_salt`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeightSet {
    height: u32,
    filter: Filter,
}

impl HeightSet {
    /// Builds the set of distinct `receivers` paid at `height`, or `None` for a block that
    /// pays none, which a [`Range`] leaves out.
    pub fn build<'a>(
        genesis: &Hash,
        height: u32,
        receivers: impl IntoIterator<Item = &'a ReceiverBytes>,
    ) -> Result<Option<Self>, Error> {
        let mut distinct = BTreeSet::new();
        for receiver in receivers {
            distinct.insert(*receiver);
            if distinct.len() > MAX_RECEIVERS as usize {
                return Err(Error::Capacity);
            }
        }
        if distinct.is_empty() || height == 0 {
            return Ok(None);
        }
        Ok(Some(Self {
            height,
            filter: Filter::build_with(&height_salt(genesis, height), &distinct, P, M),
        }))
    }

    /// The block height this set describes.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// The set's encoded size, which a server sums to keep a [`Range`] under
    /// [`MAX_RANGE_BYTES`]; the height gap before it adds at most five bytes.
    pub fn encoded_len(&self) -> usize {
        self.filter.bytes().len()
    }

    /// The set's encoding, which [`Range::write`] can splice into a range without the
    /// decoded set.
    pub fn bytes(&self) -> &[u8] {
        self.filter.bytes()
    }
}

/// Consecutive block hints from `from` through [`Range::end`], carrying only the blocks
/// that pay a receiver. The parent hash lets a wallet check that a range continues the
/// one before it (see [`Range::follows`]), and the end hash that it agrees with the
/// wallet's own block where the wallet holds one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    revision: u64,
    from: u32,
    count: u32,
    parent: Hash,
    end: Hash,
    sets: Vec<HeightSet>,
}

impl Range {
    /// Assembles a range of `count` heights from `from`, with `parent` the hash at
    /// `from - 1`, `end` the hash at the last height, and `sets` the nonempty blocks in
    /// increasing height order.
    pub fn new(
        revision: u64,
        from: u32,
        count: u32,
        parent: Hash,
        end: Hash,
        sets: Vec<HeightSet>,
    ) -> Result<Self, Error> {
        let range = Self {
            revision,
            from,
            count,
            parent,
            end,
            sets,
        };
        range.validate()?;
        Ok(range)
    }

    /// Checks bounds and that every set lies inside the range in strictly increasing order.
    fn validate(&self) -> Result<(), Error> {
        if self.from == 0 || self.count == 0 || self.count > MAX_RANGE_BLOCKS {
            return Err(Error::Capacity);
        }
        let last = self
            .from
            .checked_add(self.count - 1)
            .ok_or(Error::Malformed)?;
        let mut previous = None;
        for set in &self.sets {
            if set.height < self.from
                || set.height > last
                || previous.is_some_and(|p| set.height <= p)
            {
                return Err(Error::Malformed);
            }
            previous = Some(set.height);
        }
        Ok(())
    }

    /// Encodes the range, refusing one past [`MAX_RANGE_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let sets: Vec<_> = self.sets.iter().map(|s| (s.height, s.bytes())).collect();
        Self::write(
            self.revision,
            self.from,
            self.count,
            self.parent,
            self.end,
            &sets,
        )
    }

    /// Encodes a range of `count` heights from `from`, as [`Range::new`] describes, from
    /// already encoded sets, `(height, set)` in increasing height order, refusing one past
    /// [`MAX_RANGE_BYTES`]. A server joins stored ranges this way without decoding them.
    /// The sets are trusted: each must come from [`HeightSet::bytes`] or from
    /// [`Range::raw_sets`] of a range [`Range::decode`] accepted.
    pub fn write(
        revision: u64,
        from: u32,
        count: u32,
        parent: Hash,
        end: Hash,
        sets: &[(u32, &[u8])],
    ) -> Result<Vec<u8>, Error> {
        if from == 0 || count == 0 || count > MAX_RANGE_BLOCKS {
            return Err(Error::Capacity);
        }
        let last = from.checked_add(count - 1).ok_or(Error::Malformed)?;
        let mut out = RANGE_MAGIC.to_vec();
        out.extend(revision.to_le_bytes());
        out.extend(from.to_le_bytes());
        out.extend(count.to_le_bytes());
        out.extend(parent);
        out.extend(end);
        // The heights below are distinct and within a u32 range of `count` heights.
        out.extend((sets.len() as u32).to_le_bytes());
        let mut next = from;
        for (height, set) in sets {
            if *height < next || *height > last {
                return Err(Error::Malformed);
            }
            zakura_filters::write_compact_size(&mut out, u64::from(height - next))
                .expect("in-memory write");
            out.extend_from_slice(set);
            next = height.saturating_add(1);
            if out.len() > MAX_RANGE_BYTES {
                return Err(Error::Capacity);
            }
        }
        Ok(out)
    }

    /// Parses an entire bounded response, rejecting truncation, trailing bytes, sets
    /// outside the range and invalid or empty GCS.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (mut range, raw) = Self::parse(bytes)?;
        for (height, set) in raw {
            let filter = Filter::decode_with(set, P, M)?;
            if filter.is_empty() {
                return Err(Error::Malformed);
            }
            range.sets.push(HeightSet { height, filter });
        }
        range.validate()?;
        Ok(range)
    }

    /// The nonempty blocks of an encoded range as `(height, set)`, borrowed from `bytes`
    /// without decoding any set, for [`Range::write`]. Checks the framing as
    /// [`Range::decode`] does, but not the sets' contents, so use it only on a range
    /// that [`Range::decode`] accepted.
    pub fn raw_sets(bytes: &[u8]) -> Result<Vec<(u32, &[u8])>, Error> {
        let (range, sets) = Self::parse(bytes)?;
        range.validate()?;
        if sets
            .last()
            .is_some_and(|(height, _)| *height > range.end().height)
        {
            return Err(Error::Malformed);
        }
        Ok(sets)
    }

    /// Splits an encoding into its header, as a range without sets, and its sets'
    /// encodings, bounding the entry count before allocating and rejecting truncation and
    /// trailing bytes.
    fn parse(bytes: &[u8]) -> Result<(Self, RawSets<'_>), Error> {
        if bytes.len() > MAX_RANGE_BYTES {
            return Err(Error::Capacity);
        }
        let mut rest = bytes.strip_prefix(RANGE_MAGIC).ok_or(Error::Malformed)?;
        let revision = u64::from_le_bytes(take(&mut rest)?);
        let from = u32::from_le_bytes(take(&mut rest)?);
        let count = u32::from_le_bytes(take(&mut rest)?);
        let parent = take::<32>(&mut rest)?;
        let end = take::<32>(&mut rest)?;
        let entries = u32::from_le_bytes(take(&mut rest)?);
        // Each entry takes at least a gap byte and a set's count byte.
        if entries > count || entries as usize > rest.len() / 2 {
            return Err(Error::Capacity);
        }
        let mut sets = Vec::with_capacity(entries as usize);
        let mut next = u64::from(from);
        for _ in 0..entries {
            let gap = zakura_filters::read_compact_size(&mut rest).map_err(|_| Error::Malformed)?;
            let height = next
                .checked_add(gap)
                .and_then(|h| u32::try_from(h).ok())
                .ok_or(Error::Malformed)?;
            let (set, tail) = super::gcs::split(rest, P, M, u64::from(MAX_RECEIVERS))?;
            rest = tail;
            sets.push((height, set));
            next = u64::from(height) + 1;
        }
        if !rest.is_empty() {
            return Err(Error::Malformed);
        }
        let range = Self {
            revision,
            from,
            count,
            parent,
            end,
            sets: Vec::new(),
        };
        Ok((range, sets))
    }

    /// Binds a response to the captured head and a request for `limit` heights from
    /// `from`. The range may start earlier, at the start of the sealed chunk holding
    /// `from`, but must cover `from` and stay within the request. When it reaches the
    /// head's tip it must end at the tip's hash.
    pub fn check(&self, head: &Head, from: u32, limit: u32) -> Result<(), Error> {
        head.check_range(from, limit)?;
        let end = self.end().height;
        let last = from.saturating_add(limit - 1);
        if self.revision != head.revision
            || self.from < head.first
            || self.from > from
            || end < from
            || end > last.min(head.tip.height)
            || (end == head.tip.height && self.end != head.tip.hash)
        {
            return Err(Error::Coverage);
        }
        Ok(())
    }

    /// The first height covered.
    pub fn from(&self) -> u32 {
        self.from
    }

    /// The hash of the block before [`Range::from`], which the previous range must end on.
    pub fn parent(&self) -> Hash {
        self.parent
    }

    /// The last block covered, which a wallet compares with its own block at that height.
    pub fn end(&self) -> BlockId {
        BlockId {
            // Validation checked that the range's heights fit a u32.
            height: self.from + (self.count - 1),
            hash: self.end,
        }
    }

    /// Whether this range continues `previous`: it starts at the next height and its
    /// parent is `previous`'s end hash.
    pub fn follows(&self, previous: &Range) -> bool {
        let end = previous.end();
        end.height.checked_add(1) == Some(self.from) && end.hash == self.parent
    }

    /// The heights of the nonempty blocks, ascending.
    pub fn heights(&self) -> impl Iterator<Item = u32> + '_ {
        self.sets.iter().map(|s| s.height)
    }

    /// Tests every receiver against every nonempty block, returning `(height, index)` for
    /// each match, where `index` is the receiver's position in `receivers`. A match may be
    /// false; an absent match is not, given complete indexing by the service.
    pub fn matches(&self, genesis: &Hash, receivers: &[ReceiverBytes]) -> Vec<(u32, usize)> {
        let mut hits = Vec::new();
        for set in &self.sets {
            let found = set
                .filter
                .matches(&height_salt(genesis, set.height), receivers);
            hits.extend(
                found
                    .into_iter()
                    .enumerate()
                    .filter(|(_, hit)| *hit)
                    .map(|(index, _)| (set.height, index)),
            );
        }
        hits
    }
}

/// Nonempty blocks as `(height, encoded set)`, borrowed from a range's encoding.
type RawSets<'a> = Vec<(u32, &'a [u8])>;

/// Reads a fixed-size field without allocating or accepting a short input.
fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], Error> {
    let (field, rest) = bytes.split_first_chunk::<N>().ok_or(Error::Malformed)?;
    *bytes = rest;
    Ok(*field)
}
