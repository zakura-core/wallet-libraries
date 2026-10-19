//! Validated receiver GCS values shared by legacy envelopes and block filters.
use crate::{Error, Hash, ReceiverBytes};
use bitcoin_hashes::siphash24;
use sha2::{Digest, Sha256};
use zakura_filters::{read_compact_size, BitStreamReader, GcsFilterWriter};

/// Golomb-Rice parameter of the legacy aggregate sets.
pub const P: u8 = 10;
/// Range multiplier of the legacy aggregate sets.
pub const M: u64 = 1_533;
const PARAMS: Params = Params { p: P, m: M };

/// A set's Golomb-Rice parameter `p` and range multiplier `m`: each of `count` members
/// hashes to a value below `count * m`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Params {
    pub(crate) p: u8,
    pub(crate) m: u64,
}

/// The SipHash keys of every set keyed by `key`, its salt.
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

/// One BIP 158 Golomb-coded set of receivers, keyed by a salt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    /// The encoded set: a CompactSize count, then the Golomb-Rice coded deltas.
    bytes: Vec<u8>,
    /// The decoded values, ascending, each below `count * params.m`.
    values: Vec<u64>,
    params: Params,
}

impl Filter {
    /// Encodes the distinct `receivers` under `key`, with [`P`] and [`M`].
    pub fn build<'a>(key: &Hash, receivers: impl IntoIterator<Item = &'a ReceiverBytes>) -> Self {
        Self::build_with(PARAMS, key, receivers)
    }

    /// Encodes the distinct `receivers` under `key` with `params`.
    pub(crate) fn build_with<'a>(
        params: Params,
        key: &Hash,
        receivers: impl IntoIterator<Item = &'a ReceiverBytes>,
    ) -> Self {
        let (k0, k1) = keys(key);
        let mut bytes = Vec::new();
        let mut writer = GcsFilterWriter::new(&mut bytes, k0, k1, params.m, params.p);
        for receiver in receivers {
            writer.add_element(receiver);
        }
        writer.finish().expect("in-memory filter");
        Self::decode_with(&bytes, params).expect("filter the writer encoded")
    }

    /// How many distinct receivers the set holds.
    pub fn count(&self) -> u32 {
        self.values.len() as u32
    }

    /// Which of `receivers` may be in the set, in the same order.
    pub fn matches(&self, key: &Hash, receivers: &[ReceiverBytes]) -> Vec<bool> {
        let (k0, k1) = keys(key);
        let range = self.values.len() as u64 * self.params.m;
        receivers
            .iter()
            .map(|r| {
                let hash = siphash24::Hash::hash_to_u64_with_keys(k0, k1, r);
                let value = ((u128::from(hash) * u128::from(range)) >> 64) as u64;
                self.values.binary_search(&value).is_ok()
            })
            .collect()
    }

    /// The encoded set.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Strictly decodes one set with [`P`] and [`M`]; see [`Self::decode_with`].
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode_with(bytes, PARAMS)
    }

    /// Strictly decodes one set with `params`: a minimal count no larger than a `u32`,
    /// then values as [`read_rice_deltas`] requires.
    pub(crate) fn decode_with(bytes: &[u8], params: Params) -> Result<Self, Error> {
        let mut rest = bytes;
        let count = read_compact_size(&mut rest).map_err(|_| Error::Malformed)?;
        if count > u64::from(u32::MAX) {
            return Err(Error::Malformed);
        }
        let range = count.checked_mul(params.m).ok_or(Error::Malformed)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            values: read_rice_deltas(rest, count, params.p, range, false)?,
            params,
        })
    }
}

/// Strictly reads `count` ascending values from their Golomb-Rice coded deltas with
/// parameter `p`, as `zakura_filters::write_rice_deltas` writes them: every value below
/// `range`, each above the last if `distinct`, zero padding and nothing after it. The
/// caller bounds `count` before calling, since this allocates for every value.
pub(crate) fn read_rice_deltas(
    mut bytes: &[u8],
    count: u64,
    p: u8,
    range: u64,
    distinct: bool,
) -> Result<Vec<u64>, Error> {
    // Each value takes at least `p + 1` bits; bound the count before allocating.
    if count * (u64::from(p) + 1) > bytes.len() as u64 * 8 {
        return Err(Error::Malformed);
    }
    let mut bits = BitStreamReader::new(&mut bytes);
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
        let delta = (quotient << p) + remainder;
        if distinct && delta == 0 && !values.is_empty() {
            return Err(Error::Malformed);
        }
        value = value
            .checked_add(delta)
            .filter(|v| *v < range)
            .ok_or(Error::Malformed)?;
        values.push(value);
    }
    let padding = ((8 - used % 8) % 8) as u8;
    if padding > 0 && read(padding)? != 0 {
        return Err(Error::Malformed);
    }
    if !bytes.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(values)
}
