//! Paid sets: the receivers paid in a closed block interval, which a wallet tests
//! locally before any lookup.
//!
//! A [`PaidSet`] holds every receiver paid by a non-coinbase zero-OVK Ironwood output
//! with height in `(start, end]`, from all payments in that interval and deduplicated
//! within it, as a BIP 158 Golomb-coded set with [`P`] and [`M`]. One type serves both
//! uses: a bucket spans exactly one aligned interval of [`BUCKET_BLOCKS`] blocks (see
//! [`Span::is_bucket`]), and a cumulative set spans any other interval, usually from
//! the start of the directory's history to a cutoff. Empty sets are valid.
//!
//! A set binds the network, the directory profile, the format version, its interval
//! and the hashes of the blocks at both ends, its salt, [`P`], [`M`], its receiver
//! count, its payload length and the payment-history epoch (see [`crate::catalog`]).
//! The salt depends only on the network and the boundary hashes, never on a PIR
//! table's placement, so the same payments on the same chain always give the same
//! set. A wallet checks the boundary hashes against its own chain before relying on
//! a set. A match means only that a lookup may be worthwhile: a receiver outside a
//! set matches it about once in [`M`] tests.
use crate::{
    filter::{Filter, Params},
    object::{self, Reader},
    Error, Hash, ReceiverBytes,
};
use sha2::{Digest, Sha256};

/// Blocks in a bucket, nominally an hour at 75-second spacing. The count is fixed;
/// a bucket's duration changes with block spacing.
pub const BUCKET_BLOCKS: u32 = 48;
/// Golomb-Rice parameter of every paid set.
pub const P: u8 = 20;
/// Range multiplier of every paid set, BIP 158's ratio to `2^P`.
pub const M: u64 = 1_569_792;
const PARAMS: Params = Params { p: P, m: M };
/// Largest encoded bucket. A bucket holds at most a few hundred kilobytes at the
/// consensus block size limit.
pub const MAX_BUCKET_BYTES: usize = 1 << 20;
/// Largest encoded paid set of any span, about six million receivers.
pub const MAX_PAID_BYTES: usize = 16 << 20;
const MAGIC: &[u8; 8] = b"IWPAID\0\0";

/// The heights `(start, end]` and the hashes of blocks `start` and `end`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: u32,
    pub start_hash: Hash,
    pub end: u32,
    pub end_hash: Hash,
}

impl Span {
    /// Whether this is a bucket: `start` a multiple of [`BUCKET_BLOCKS`] and `end`
    /// [`BUCKET_BLOCKS`] above it.
    pub fn is_bucket(&self) -> bool {
        self.start.is_multiple_of(BUCKET_BLOCKS)
            && self.start.checked_add(BUCKET_BLOCKS) == Some(self.end)
    }

    /// The salt of a set over this span on the network with `genesis`: a
    /// domain-separated SHA-256 of `genesis` and the two boundary hashes.
    pub fn salt(&self, genesis: &Hash) -> Hash {
        Sha256::new()
            .chain_update(b"ironwood-receiver/v1/paid-salt\0")
            .chain_update(genesis)
            .chain_update(self.start_hash)
            .chain_update(self.end_hash)
            .finalize()
            .into()
    }
}

/// The start of the bucket holding `height`, or `None` for height zero, which no
/// bucket holds.
pub fn bucket_start(height: u32) -> Option<u32> {
    let below = height.checked_sub(1)?;
    Some(below - below % BUCKET_BLOCKS)
}

/// The receivers paid in one span; see the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaidSet {
    genesis: Hash,
    epoch: u64,
    span: Span,
    filter: Filter,
}

impl PaidSet {
    /// The set of the distinct `receivers` paid in `span` under payment-history `epoch`
    /// on the network with `genesis`. An empty span is [`Error::Malformed`], and an
    /// encoding over [`MAX_BUCKET_BYTES`] for a bucket or [`MAX_PAID_BYTES`] otherwise
    /// is [`Error::Capacity`].
    pub fn build<'a>(
        genesis: Hash,
        epoch: u64,
        span: Span,
        receivers: impl IntoIterator<Item = &'a ReceiverBytes>,
    ) -> Result<Self, Error> {
        if span.start >= span.end {
            return Err(Error::Malformed);
        }
        let set = Self {
            genesis,
            epoch,
            span,
            filter: Filter::build_with(PARAMS, &span.salt(&genesis), receivers),
        };
        if set.encode().len() > max_bytes(&span) {
            return Err(Error::Capacity);
        }
        Ok(set)
    }

    /// The network's genesis hash.
    pub fn genesis(&self) -> Hash {
        self.genesis
    }

    /// The payment-history epoch the set was built under.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The covered interval and its boundary hashes.
    pub fn span(&self) -> &Span {
        &self.span
    }

    /// How many distinct receivers the set holds.
    pub fn count(&self) -> u32 {
        self.filter.count()
    }

    /// Which of `receivers` may be in the set, in the same order. A member always
    /// matches.
    pub fn matches(&self, receivers: &[ReceiverBytes]) -> Vec<bool> {
        self.filter
            .matches(&self.span.salt(&self.genesis), receivers)
    }

    /// The canonical encoding: the object header (see [`crate::catalog`]), the epoch,
    /// the span's start, start hash, end and end hash, the salt, [`P`], [`M`], the
    /// receiver count, then the payload's `u32` length and the payload, a BIP 158
    /// Golomb-coded set.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = object::header(MAGIC, &self.genesis);
        out.extend(self.epoch.to_le_bytes());
        out.extend(self.span.start.to_le_bytes());
        out.extend(self.span.start_hash);
        out.extend(self.span.end.to_le_bytes());
        out.extend(self.span.end_hash);
        out.extend(self.span.salt(&self.genesis));
        out.push(P);
        out.extend(M.to_le_bytes());
        out.extend(self.count().to_le_bytes());
        let payload = self.filter.bytes();
        out.extend(u32::try_from(payload.len()).expect("bounded").to_le_bytes());
        out.extend(payload);
        out
    }

    /// The SHA-256 of [`Self::encode`], by which catalogs name the set.
    pub fn digest(&self) -> Hash {
        object::digest(&self.encode())
    }

    /// Strictly decodes a set [`Self::encode`] wrote: a nonempty span, the salt it
    /// implies, [`P`] and [`M`], a count matching the payload, the size bound
    /// [`Self::build`] applies, and nothing after the payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_PAID_BYTES {
            return Err(Error::Malformed);
        }
        let (genesis, mut r) = Reader::open(bytes, MAGIC)?;
        let epoch = r.u64()?;
        let span = Span {
            start: r.u32()?,
            start_hash: r.array()?,
            end: r.u32()?,
            end_hash: r.array()?,
        };
        let salt: Hash = r.array()?;
        let (p, m, count) = (r.u8()?, r.u64()?, r.u32()?);
        let payload = r.payload()?;
        r.finish()?;
        if span.start >= span.end
            || salt != span.salt(&genesis)
            || p != P
            || m != M
            || bytes.len() > max_bytes(&span)
        {
            return Err(Error::Malformed);
        }
        let filter = Filter::decode_with(payload, PARAMS)?;
        if filter.count() != count {
            return Err(Error::Malformed);
        }
        Ok(Self {
            genesis,
            epoch,
            span,
            filter,
        })
    }
}

/// The largest encoding of a set over `span`.
fn max_bytes(span: &Span) -> usize {
    if span.is_bucket() {
        MAX_BUCKET_BYTES
    } else {
        MAX_PAID_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bucket over [`MAX_BUCKET_BYTES`] is refused, though the same payload over a
    /// longer span decodes.
    #[test]
    fn buckets_decode_within_their_bound() {
        let receivers: Vec<ReceiverBytes> = (0..400_000u32)
            .map(|i| {
                Sha256::digest(i.to_le_bytes())[..].repeat(2)[..43]
                    .try_into()
                    .unwrap()
            })
            .collect();
        let span = |end| Span {
            start: 0,
            start_hash: [1; 32],
            end,
            end_hash: [2; 32],
        };
        let set = |span: Span| PaidSet {
            genesis: [0; 32],
            epoch: 0,
            span,
            filter: Filter::build_with(PARAMS, &span.salt(&[0; 32]), &receivers),
        };
        let bucket = set(span(BUCKET_BLOCKS)).encode();
        assert!(bucket.len() > MAX_BUCKET_BYTES);
        assert!(PaidSet::decode(&bucket).is_err());
        assert!(PaidSet::decode(&set(span(BUCKET_BLOCKS + 1)).encode()).is_ok());
    }
}
