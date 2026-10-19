//! The catalog: how a wallet finds the paid and seen sets of a publication.
//!
//! A publication's manifest commits to its [`CatalogHead`] by digest
//! ([`Manifest::catalog_sha256`](crate::snapshot::Manifest::catalog_sha256)). The head
//! names the payment-history epoch, the retained closed buckets
//! `(oldest_start, latest_end]`, and the digests of the cumulative [`PaidSet`], the
//! [`SeenSet`] and a [`BucketIndex`], which maps each retained bucket's start height
//! to its expected digest. Every object is immutable and fetched by digest. A wallet
//! checks each against the head before use, with [`CatalogHead::check_index`],
//! [`CatalogHead::check_bucket`], [`CatalogHead::check_paid`] and
//! [`CatalogHead::check_seen`].
//!
//! The payment-history epoch is durable and only increases. Any correction to
//! already published payment history increments it, which changes the digest of
//! every bucket and cumulative set. Reorgs change boundary hashes instead and need
//! no new epoch.
//!
//! Every object, here and in [`crate::paid`] and [`crate::seen`], starts with an
//! 8-byte magic naming its kind, the `u16` format version 1, the directory
//! [`PROFILE`](crate::snapshot::PROFILE) as a length byte and its bytes, and the
//! network's genesis hash. Integers are little-endian at fixed width. An object's
//! digest is the SHA-256 of its encoding, which decoding requires to be canonical.
use crate::{
    object::{self, Reader},
    paid::{PaidSet, BUCKET_BLOCKS},
    seen::SeenSet,
    Error, Hash,
};

/// Largest encoded [`CatalogHead`] a client downloads.
pub const MAX_CATALOG_BYTES: usize = 1024;
/// Most buckets a [`BucketIndex`] holds, about three and a half years of buckets at
/// 75-second spacing.
pub const MAX_INDEX_BUCKETS: u32 = 1 << 15;
/// Largest encoded [`BucketIndex`] a client downloads.
pub const MAX_INDEX_BYTES: usize = 2 << 20;
const HEAD_MAGIC: &[u8; 8] = b"IWCATLOG";
const INDEX_MAGIC: &[u8; 8] = b"IWBKTIDX";

/// What a publication offers for recovery; see the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogHead {
    pub genesis: Hash,
    /// The payment-history epoch every bucket and the cumulative set were built under.
    pub epoch: u64,
    /// The start of the oldest retained bucket.
    pub oldest_start: u32,
    /// The end of the latest closed bucket. Equal to `oldest_start` when no bucket is
    /// retained.
    pub latest_end: u32,
    /// The digest of the cumulative [`PaidSet`].
    pub paid: Hash,
    /// The digest of the [`SeenSet`].
    pub seen: Hash,
    /// The digest of the [`BucketIndex`].
    pub index: Hash,
}

impl CatalogHead {
    /// Checks that the retained buckets are whole, in order and at most
    /// [`MAX_INDEX_BUCKETS`].
    pub fn validate(&self) -> Result<(), Error> {
        if !self.oldest_start.is_multiple_of(BUCKET_BLOCKS)
            || !self.latest_end.is_multiple_of(BUCKET_BLOCKS)
            || self.oldest_start > self.latest_end
            || (self.latest_end - self.oldest_start) / BUCKET_BLOCKS > MAX_INDEX_BUCKETS
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// The canonical encoding of a valid head: the object header, the epoch, the
    /// oldest start, the latest end, then the paid, seen and index digests.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = object::header(HEAD_MAGIC, &self.genesis);
        out.extend(self.epoch.to_le_bytes());
        out.extend(self.oldest_start.to_le_bytes());
        out.extend(self.latest_end.to_le_bytes());
        out.extend(self.paid);
        out.extend(self.seen);
        out.extend(self.index);
        Ok(out)
    }

    /// The SHA-256 of [`Self::encode`], which the manifest commits to.
    pub fn digest(&self) -> Result<Hash, Error> {
        Ok(object::digest(&self.encode()?))
    }

    /// Strictly decodes a valid head of at most [`MAX_CATALOG_BYTES`] that
    /// [`Self::encode`] wrote.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err(Error::Malformed);
        }
        let (genesis, mut r) = Reader::open(bytes, HEAD_MAGIC)?;
        let head = Self {
            genesis,
            epoch: r.u64()?,
            oldest_start: r.u32()?,
            latest_end: r.u32()?,
            paid: r.array()?,
            seen: r.array()?,
            index: r.array()?,
        };
        r.finish()?;
        head.validate()?;
        Ok(head)
    }

    /// Checks that this head is valid and `index` is the one it names, on the same
    /// network, listing exactly the retained buckets.
    pub fn check_index(&self, index: &BucketIndex) -> Result<(), Error> {
        self.validate()?;
        let starts_at_oldest = index
            .starts
            .first()
            .is_none_or(|(start, _)| *start == self.oldest_start);
        let retained = u64::from(self.latest_end - self.oldest_start) / u64::from(BUCKET_BLOCKS);
        if index.genesis != self.genesis
            || index.digest() != self.index
            || !starts_at_oldest
            || index.starts.len() as u64 != retained
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Checks that `bucket` is the retained bucket `index` lists at its start, built
    /// under this head's epoch on the same network. `index` must have passed
    /// [`Self::check_index`].
    pub fn check_bucket(&self, index: &BucketIndex, bucket: &PaidSet) -> Result<(), Error> {
        if bucket.genesis() != self.genesis
            || bucket.epoch() != self.epoch
            || !bucket.span().is_bucket()
            || index.get(bucket.span().start) != Some(bucket.digest())
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Checks that `paid` is the cumulative set this head names, built under its epoch
    /// on the same network, and ending within the retained buckets so a wallet can
    /// bridge from its end with them.
    pub fn check_paid(&self, paid: &PaidSet) -> Result<(), Error> {
        let end = paid.span().end;
        if paid.genesis() != self.genesis
            || paid.epoch() != self.epoch
            || paid.digest() != self.paid
            || end < self.oldest_start
            || end > self.latest_end
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Checks that `seen` is the set this head names, on the same network.
    pub fn check_seen(&self, seen: &SeenSet) -> Result<(), Error> {
        if seen.genesis() != self.genesis || seen.digest()? != self.seen {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

/// The expected digest of each retained bucket, by start height; see the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BucketIndex {
    genesis: Hash,
    /// Each bucket's start and digest, contiguous and ascending.
    starts: Vec<(u32, Hash)>,
}

impl BucketIndex {
    /// An index on the network with `genesis` of the buckets starting at each start
    /// height with each digest. The starts must be multiples of [`BUCKET_BLOCKS`],
    /// each [`BUCKET_BLOCKS`] above the last, and at most [`MAX_INDEX_BUCKETS`].
    pub fn new(genesis: Hash, starts: Vec<(u32, Hash)>) -> Result<Self, Error> {
        let contiguous = starts
            .windows(2)
            .all(|pair| pair[0].0.checked_add(BUCKET_BLOCKS) == Some(pair[1].0));
        let ends_in_range = starts
            .last()
            .is_none_or(|(start, _)| start.checked_add(BUCKET_BLOCKS).is_some());
        if starts.len() > MAX_INDEX_BUCKETS as usize
            || starts
                .first()
                .is_some_and(|(s, _)| !s.is_multiple_of(BUCKET_BLOCKS))
            || !contiguous
            || !ends_in_range
        {
            return Err(Error::Malformed);
        }
        Ok(Self { genesis, starts })
    }

    /// The expected digest of the bucket starting at `start`, if retained.
    pub fn get(&self, start: u32) -> Option<Hash> {
        self.starts
            .binary_search_by_key(&start, |(s, _)| *s)
            .ok()
            .map(|i| self.starts[i].1)
    }

    /// Each retained bucket's start and expected digest, ascending.
    pub fn iter(&self) -> impl Iterator<Item = (u32, Hash)> + '_ {
        self.starts.iter().copied()
    }

    /// The canonical encoding: the object header, the bucket count as a `u32`, then
    /// each bucket's start and digest.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = object::header(INDEX_MAGIC, &self.genesis);
        out.extend((self.starts.len() as u32).to_le_bytes());
        for (start, digest) in &self.starts {
            out.extend(start.to_le_bytes());
            out.extend(digest);
        }
        out
    }

    /// The SHA-256 of [`Self::encode`], which the catalog head commits to.
    pub fn digest(&self) -> Hash {
        object::digest(&self.encode())
    }

    /// Strictly decodes an index of at most [`MAX_INDEX_BYTES`] that [`Self::encode`]
    /// wrote, as [`Self::new`] requires.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_INDEX_BYTES {
            return Err(Error::Malformed);
        }
        let (genesis, mut r) = Reader::open(bytes, INDEX_MAGIC)?;
        let count = r.u32()?;
        if count > MAX_INDEX_BUCKETS {
            return Err(Error::Malformed);
        }
        let starts = (0..count)
            .map(|_| Ok((r.u32()?, r.array()?)))
            .collect::<Result<_, Error>>()?;
        r.finish()?;
        Self::new(genesis, starts)
    }
}
