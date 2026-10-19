//! The seen set: the receivers swap provider feeds have reported, which issuance
//! treats as evidence that an index was used.
//!
//! Seen stores the durable union of fixed hash values ever published. Hash identity,
//! including domain, network, salt and universe, never changes. Reorgs, feed
//! corrections, rebuilds, failover and codec upgrades cannot remove membership.
//! Incorrect records may be corrected in other data, but their seen hashes remain.
//! Encoding parameters may change without changing hash values or membership.
//!
//! A receiver's value is the high 32 bits of its SipHash under keys derived from a
//! salt fixed by a domain and the network ([`hash`]), so the universe is [`U`]
//! whatever the set's size. Unlike a BIP 158 set, whose range scales with its count,
//! a value once present stays present: a false match, once published, stays a match
//! in every later set, and every later restore reproduces it. A receiver outside a
//! set of `K` values matches with probability `K / U`, about 7e-6 at 30,000 values,
//! growing with `K`. Values are stored sorted and unique, Golomb-Rice coded with a
//! parameter carried in the header ([`DEFAULT_P`] unless re-encoded); membership
//! depends on neither that parameter nor the count. [`SeenSet::union`] only adds.
use crate::{
    filter::{keys, read_rice_deltas},
    object::{self, Reader},
    Error, Hash, ReceiverBytes,
};
use bitcoin_hashes::siphash24;
use sha2::{Digest, Sha256};
use std::ops::RangeInclusive;
use zakura_filters::write_rice_deltas;

/// The size of the hash universe, fixed forever.
pub const U: u64 = 1 << 32;
/// The Golomb-Rice parameter a new set encodes with, near optimal at tens of
/// thousands of values.
pub const DEFAULT_P: u8 = 17;
/// The Golomb-Rice parameters a set may carry.
const P_RANGE: RangeInclusive<u8> = 1..=32;
/// Most values a seen set holds, whatever its parameter. About 140 times the 30,000
/// receivers the feeds hold today, where a nonmember's false match rate reaches about
/// 0.1%. Decoding checks it before allocating.
pub const MAX_SEEN_VALUES: u32 = 1 << 22;
/// Largest encoded seen set. [`MAX_SEEN_VALUES`] values take about 9.5 MB at
/// [`DEFAULT_P`].
pub const MAX_SEEN_BYTES: usize = 16 << 20;
const MAGIC: &[u8; 8] = b"IWSEEN\0\0";

/// The fixed salt of every seen set on the network with `genesis`.
fn salt(genesis: &Hash) -> Hash {
    Sha256::new()
        .chain_update(b"ironwood-receiver/v1/seen-salt\0")
        .chain_update(genesis)
        .finalize()
        .into()
}

/// The value that stands for `receiver` in every seen set on the network with
/// `genesis`; see the module docs.
pub fn hash(genesis: &Hash, receiver: &ReceiverBytes) -> u32 {
    let (k0, k1) = keys(&salt(genesis));
    (siphash24::Hash::hash_to_u64_with_keys(k0, k1, receiver) >> 32) as u32
}

/// The values of every receiver ever reported; see the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeenSet {
    genesis: Hash,
    /// When the provider feeds started, in Unix seconds. Receivers they were given
    /// earlier may be missing.
    pub since_unix: i64,
    /// When the feeds' last complete read of the providers began, in Unix seconds.
    /// Receivers they were given later are missing.
    pub until_unix: i64,
    p: u8,
    /// Ascending and unique.
    values: Vec<u32>,
}

impl SeenSet {
    /// An empty set on the network with `genesis`, with feeds read from and through
    /// `since_unix`, encoded with [`DEFAULT_P`].
    pub fn new(genesis: Hash, since_unix: i64) -> Self {
        Self {
            genesis,
            since_unix,
            until_unix: since_unix,
            p: DEFAULT_P,
            values: Vec::new(),
        }
    }

    /// This set with the values of `receivers` added. Every value already present
    /// stays; the parameter and feed times are unchanged.
    pub fn union<'a>(&self, receivers: impl IntoIterator<Item = &'a ReceiverBytes>) -> Self {
        let mut values = self.values.clone();
        values.extend(receivers.into_iter().map(|r| hash(&self.genesis, r)));
        values.sort_unstable();
        values.dedup();
        Self {
            values,
            ..self.clone()
        }
    }

    /// The same values encoded with Golomb-Rice parameter `p`, from 1 to 32.
    pub fn with_p(&self, p: u8) -> Result<Self, Error> {
        if !P_RANGE.contains(&p) {
            return Err(Error::Malformed);
        }
        Ok(Self { p, ..self.clone() })
    }

    /// The network's genesis hash.
    pub fn genesis(&self) -> Hash {
        self.genesis
    }

    /// The Golomb-Rice parameter of the encoding.
    pub fn p(&self) -> u8 {
        self.p
    }

    /// How many distinct values the set holds.
    pub fn count(&self) -> u32 {
        self.values.len() as u32
    }

    /// Which of `receivers` may be in the set, in the same order. A receiver whose
    /// value was ever added always matches.
    pub fn matches(&self, receivers: &[ReceiverBytes]) -> Vec<bool> {
        receivers
            .iter()
            .map(|r| self.values.binary_search(&hash(&self.genesis, r)).is_ok())
            .collect()
    }

    /// Whether this set holds every value of `older` on the same network, as each
    /// later publication must.
    pub fn is_superset(&self, older: &SeenSet) -> bool {
        self.genesis == older.genesis
            && older
                .values
                .iter()
                .all(|v| self.values.binary_search(v).is_ok())
    }

    /// The canonical encoding: the object header (see [`crate::catalog`]), the feed
    /// times, the parameter, the value count, then the payload's `u32` length and the
    /// payload, the Golomb-Rice coded differences between consecutive values (the
    /// first from zero) padded with zero bits to a byte. Feed times out of order are
    /// [`Error::Malformed`], and more than [`MAX_SEEN_VALUES`] values or an encoding
    /// over [`MAX_SEEN_BYTES`] is [`Error::Capacity`].
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.since_unix > self.until_unix {
            return Err(Error::Malformed);
        }
        if self.values.len() > MAX_SEEN_VALUES as usize {
            return Err(Error::Capacity);
        }
        let mut out = object::header(MAGIC, &self.genesis);
        out.extend(self.since_unix.to_le_bytes());
        out.extend(self.until_unix.to_le_bytes());
        out.push(self.p);
        out.extend(self.count().to_le_bytes());
        // Sized before writing, since a small parameter makes long unary quotients.
        let mut bits = 0u64;
        let mut last = 0;
        for &value in &self.values {
            bits += (u64::from(value - last) >> self.p) + 1 + u64::from(self.p);
            last = value;
        }
        let payload = bits.div_ceil(8);
        if out.len() as u64 + 4 + payload > MAX_SEEN_BYTES as u64 {
            return Err(Error::Capacity);
        }
        out.extend((payload as u32).to_le_bytes());
        let values: Vec<u64> = self.values.iter().map(|&v| v.into()).collect();
        write_rice_deltas(&mut out, &values, self.p).expect("in-memory set");
        Ok(out)
    }

    /// The SHA-256 of [`Self::encode`], by which catalogs name the set.
    pub fn digest(&self) -> Result<Hash, Error> {
        Ok(object::digest(&self.encode()?))
    }

    /// Strictly decodes a set [`Self::encode`] wrote, of at most [`MAX_SEEN_BYTES`]:
    /// ordered feed times, a supported parameter, at most [`MAX_SEEN_VALUES`] ascending
    /// unique values below [`U`] matching the count, zero padding and nothing after it.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SEEN_BYTES {
            return Err(Error::Malformed);
        }
        let (genesis, mut r) = Reader::open(bytes, MAGIC)?;
        let (since_unix, until_unix) = (r.i64()?, r.i64()?);
        let (p, count) = (r.u8()?, r.u32()?);
        let payload = r.payload()?;
        r.finish()?;
        if since_unix > until_unix || !P_RANGE.contains(&p) || count > MAX_SEEN_VALUES {
            return Err(Error::Malformed);
        }
        let values = read_rice_deltas(payload, count.into(), p, U, true)?
            .into_iter()
            .map(|v| v as u32)
            .collect();
        Ok(Self {
            genesis,
            since_unix,
            until_unix,
            p,
            values,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repeated value is refused while decoding, though its coding is well formed.
    #[test]
    fn values_must_be_unique() {
        let set = |values| SeenSet {
            values,
            ..SeenSet::new([1; 32], 0)
        };
        assert!(SeenSet::decode(&set(vec![5, 6]).encode().unwrap()).is_ok());
        assert!(SeenSet::decode(&set(vec![5, 5]).encode().unwrap()).is_err());
    }

    /// The encoding of `count` values with parameter `p` and an all-zero payload of
    /// `payload` bytes, whatever its values would be.
    fn forged(p: u8, count: u32, payload: u32) -> Vec<u8> {
        let mut out = object::header(MAGIC, &[1; 32]);
        out.extend(0i64.to_le_bytes());
        out.extend(0i64.to_le_bytes());
        out.push(p);
        out.extend(count.to_le_bytes());
        out.extend(payload.to_le_bytes());
        out.resize(out.len() + payload as usize, 0);
        out
    }

    /// A small parameter cannot make a bounded object claim more values than the
    /// count bound, and zero deltas fail at the first repeat.
    #[test]
    fn low_parameters_cannot_inflate_the_count() {
        // At one bit per remainder, 16 MiB would otherwise hold about 67 million values.
        let header = forged(1, 0, 0).len() as u32;
        let payload = MAX_SEEN_BYTES as u32 - header;
        let many = forged(1, payload * 4, payload);
        assert_eq!(many.len(), MAX_SEEN_BYTES);
        assert!(SeenSet::decode(&many).is_err());
        assert!(SeenSet::decode(&forged(1, MAX_SEEN_VALUES + 1, payload)).is_err());
        // Within the bound, an all-zero payload codes repeats of zero.
        let bytes = (MAX_SEEN_VALUES * 2).div_ceil(8);
        assert!(SeenSet::decode(&forged(1, MAX_SEEN_VALUES, bytes)).is_err());
        assert!(SeenSet::decode(&forged(1, 1, 1)).is_ok());
    }

    /// More values than the bound fail to encode.
    #[test]
    fn encoding_applies_the_count_bound() {
        let set = |count: u32| SeenSet {
            values: (0..count).collect(),
            ..SeenSet::new([1; 32], 0)
        };
        assert!(set(MAX_SEEN_VALUES).encode().is_ok());
        assert!(matches!(
            set(MAX_SEEN_VALUES + 1).encode(),
            Err(Error::Capacity)
        ));
    }
}
