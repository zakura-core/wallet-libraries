//! Validated GCS values shared by Receiver hint formats.
use crate::{Error, Hash, ReceiverBytes};
use bitcoin_hashes::siphash24;
use sha2::{Digest, Sha256};
use zakura_filters::{read_compact_size, BitStreamReader, GcsFilterWriter};

/// Legacy aggregate Golomb-Rice parameter.
pub const P: u8 = 10;
/// Legacy aggregate range multiplier.
pub const M: u64 = 1_533;

/// The SipHash keys of every set in a publication keyed by `key`, its salt.
pub(crate) fn keys(key: &Hash) -> (u64, u64) {
    let digest = Sha256::new()
        .chain_update(b"ironwood-receiver/v1/filter\0")
        .chain_update(key)
        .finalize();
    (
        u64::from_le_bytes(digest[..8].try_into().unwrap()),
        u64::from_le_bytes(digest[8..16].try_into().unwrap()),
    )
}

/// One BIP 158 Golomb-coded set of receivers, keyed by the publication salt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    /// The encoded set: a CompactSize count, then the Golomb-Rice coded deltas.
    bytes: Vec<u8>,
    /// The decoded values, ascending, each below `count * m`.
    values: Vec<u64>,
    m: u64,
}

impl Filter {
    /// Encodes the distinct `receivers` under `key`.
    pub fn build<'a>(key: &Hash, receivers: impl IntoIterator<Item = &'a ReceiverBytes>) -> Self {
        Self::build_with(key, receivers, P, M)
    }

    /// Encodes receivers with the caller-selected fixed protocol parameters.
    pub(crate) fn build_with<'a>(
        key: &Hash,
        receivers: impl IntoIterator<Item = &'a ReceiverBytes>,
        p: u8,
        m: u64,
    ) -> Self {
        let (k0, k1) = keys(key);
        let mut bytes = Vec::new();
        let mut writer = GcsFilterWriter::new(&mut bytes, k0, k1, m, p);
        for receiver in receivers {
            writer.add_element(receiver);
        }
        writer.finish().expect("in-memory filter");
        Self::decode_with(&bytes, p, m).expect("filter the writer encoded")
    }

    /// How many distinct receivers the set holds.
    pub fn count(&self) -> u32 {
        self.values.len() as u32
    }

    /// Which of `receivers` may be in the set, in the same order.
    pub fn matches(&self, key: &Hash, receivers: &[ReceiverBytes]) -> Vec<bool> {
        let (k0, k1) = keys(key);
        let range = self.values.len() as u64 * self.m;
        receivers
            .iter()
            .map(|r| {
                let hash = siphash24::Hash::hash_to_u64_with_keys(k0, k1, r);
                let value = ((u128::from(hash) * u128::from(range)) >> 64) as u64;
                self.values.binary_search(&value).is_ok()
            })
            .collect()
    }

    /// Strictly decodes one set: a minimal count no larger than a `u32`, every value in
    /// range, zero padding and nothing after it.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode_with(bytes, P, M)
    }

    /// Returns the canonical encoded set.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Strictly decodes a set using fixed protocol parameters, validating all bits.
    pub(crate) fn decode_with(bytes: &[u8], p: u8, m: u64) -> Result<Self, Error> {
        let mut rest = bytes;
        let count = read_compact_size(&mut rest).map_err(|_| Error::Malformed)?;
        // Each value takes at least `P + 1` bits; bound the count before allocating.
        if count > u64::from(u32::MAX) || count * (u64::from(p) + 1) > rest.len() as u64 * 8 {
            return Err(Error::Malformed);
        }
        let range = count * m;
        let mut bits = BitStreamReader::new(&mut rest);
        let mut read = |n: u8| bits.read(n).map_err(|_| Error::Malformed);
        let mut used = 0u64;
        let mut value = 0u64;
        let mut values = Vec::with_capacity(count as usize);
        for _ in 0..count {
            // A quotient is bounded by the bit count, so the shift cannot overflow.
            let mut quotient = 0u64;
            while read(1)? == 1 {
                quotient += 1;
            }
            let remainder = read(p)?;
            used += quotient + 1 + u64::from(p);
            value = value
                .checked_add((quotient << p) + remainder)
                .filter(|v| *v < range)
                .ok_or(Error::Malformed)?;
            values.push(value);
        }
        let padding = ((8 - used % 8) % 8) as u8;
        if padding > 0 && read(padding)? != 0 {
            return Err(Error::Malformed);
        }
        if !rest.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            values,
            m,
        })
    }
}
