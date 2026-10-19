//! Public receiver filters that a wallet tests locally before any lookup.
//!
//! A publication's filter file holds labeled sets of receivers, each a BIP 158
//! Golomb-coded set built with the shared `zakura_filters` codec as Transparent's filters are. The
//! directory's own set, [`PAID`], holds every receiver with a payment in the publication.
//! A swap provider's feed adds `<provider>/recent`, the receivers it was given within a
//! window, and `<provider>/seen`, every payout or refund receiver it was given since its
//! feeds started; the manifest declares each set (see [`FilterSet`](crate::snapshot::FilterSet)).
//! Wallets use the sets they recognize and ignore the rest. Every wallet downloads the
//! same bytes, so a test reveals nothing. A match means only that a lookup or a watch may
//! be worthwhile: a receiver outside a set matches it about once in [`M`] tests, and the
//! publisher is trusted for completeness, as for the directory rows.
//!
//! Decoding reads every value and checks the padding before any match, because the
//! upstream reader's `match_any` stops at the first match and never checks the tail.
use crate::{Error, Hash, ReceiverBytes};
use bitcoin_hashes::siphash24;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zakura_filters::{read_compact_size, BitStreamReader, GcsFilterWriter};

/// Golomb-Rice parameter of every set.
pub const P: u8 = 10;
/// Range multiplier of every set, BIP 158's ratio to `2^P`; see the module docs for the
/// false match rate.
pub const M: u64 = 1_533;
/// The parameters of every set in a [`Filters`] file.
const PARAMS: Params = Params { p: P, m: M };
/// Largest encoded [`Filters`] a client downloads, and a publisher builds.
pub const MAX_FILTERS_BYTES: usize = 8 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"IWFLT1\0\0";
/// Longest set label.
const MAX_LABEL: usize = 64;
/// The label of the set of receivers with a payment in the publication.
pub const PAID: &str = "paid";
/// The kind of a provider set of receivers it was given within a declared window.
pub const RECENT: &str = "recent";
/// The kind of a provider set of every payout or refund receiver it was given since its feeds
/// started.
pub const SEEN: &str = "seen";

/// Whether `label` names a set: [`PAID`], or `<provider>/recent` or `<provider>/seen`
/// with a provider name of lowercase letters, digits and hyphens.
pub fn valid_label(label: &str) -> bool {
    if label == PAID {
        return true;
    }
    label.len() <= MAX_LABEL
        && label.split_once('/').is_some_and(|(provider, kind)| {
            !provider.is_empty()
                && provider
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && (kind == RECENT || kind == SEEN)
        })
}

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
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
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
            values: read_rice_deltas(rest, count, params.p, range)?,
            params,
        })
    }
}

/// Strictly reads `count` ascending values from their Golomb-Rice coded deltas with
/// parameter `p`, as `zakura_filters::write_rice_deltas` writes them: every value below
/// `range`, zero padding and nothing after it.
pub(crate) fn read_rice_deltas(
    mut bytes: &[u8],
    count: u64,
    p: u8,
    range: u64,
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
    if !bytes.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(values)
}

/// The labeled sets of one publication, in label order; see the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filters(BTreeMap<String, Filter>);

impl Filters {
    /// Filters with the [`PAID`] set and the given provider sets. Fails on an invalid
    /// or repeated label.
    pub fn new(
        paid: Filter,
        provider: impl IntoIterator<Item = (String, Filter)>,
    ) -> Result<Self, Error> {
        let mut sets = BTreeMap::from([(PAID.to_owned(), paid)]);
        for (label, filter) in provider {
            if label == PAID || !valid_label(&label) || sets.insert(label, filter).is_some() {
                return Err(Error::Malformed);
            }
        }
        Ok(Self(sets))
    }

    /// The set labeled `label`.
    pub fn get(&self, label: &str) -> Option<&Filter> {
        self.0.get(label)
    }

    /// Each set's label and filter, in label order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Filter)> {
        self.0
            .iter()
            .map(|(label, filter)| (label.as_str(), filter))
    }

    /// The publication's filter file: the magic, the set count, then for each set in
    /// label order its label length and bytes, its encoding's length and the encoding.
    /// Fails if it would exceed [`MAX_FILTERS_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = MAGIC.to_vec();
        out.extend(
            u32::try_from(self.0.len())
                .expect("set count")
                .to_le_bytes(),
        );
        for (label, filter) in &self.0 {
            out.push(u8::try_from(label.len()).expect("label length"));
            out.extend(label.as_bytes());
            out.extend(
                u32::try_from(filter.bytes.len())
                    .expect("filter size")
                    .to_le_bytes(),
            );
            out.extend(&filter.bytes);
        }
        if out.len() > MAX_FILTERS_BYTES {
            return Err(Error::Malformed);
        }
        Ok(out)
    }

    /// Strictly decodes a filter file of at most [`MAX_FILTERS_BYTES`]: valid labels in
    /// increasing order, [`PAID`] among them, and nothing after the last set.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_FILTERS_BYTES {
            return Err(Error::Malformed);
        }
        let rest = bytes.strip_prefix(MAGIC).ok_or(Error::Malformed)?;
        let (count, mut rest) = rest.split_first_chunk::<4>().ok_or(Error::Malformed)?;
        let mut sets: BTreeMap<String, Filter> = BTreeMap::new();
        for _ in 0..u32::from_le_bytes(*count) {
            let (len, tail) = rest.split_first().ok_or(Error::Malformed)?;
            let (label, tail) = tail
                .split_at_checked(usize::from(*len))
                .ok_or(Error::Malformed)?;
            let label = std::str::from_utf8(label).map_err(|_| Error::Malformed)?;
            let (bytes_len, tail) = tail.split_first_chunk::<4>().ok_or(Error::Malformed)?;
            let (set, tail) = tail
                .split_at_checked(u32::from_le_bytes(*bytes_len) as usize)
                .ok_or(Error::Malformed)?;
            rest = tail;
            if !valid_label(label)
                || sets
                    .last_key_value()
                    .is_some_and(|(last, _)| last.as_str() >= label)
            {
                return Err(Error::Malformed);
            }
            sets.insert(label.to_owned(), Filter::decode(set)?);
        }
        if !rest.is_empty() || !sets.contains_key(PAID) {
            return Err(Error::Malformed);
        }
        Ok(Self(sets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `n` distinct pseudorandom receivers; filters hash bytes and never parse them.
    fn receivers(n: u32, seed: u8) -> Vec<ReceiverBytes> {
        use sha2::{Digest, Sha512};
        (0..n)
            .map(|i| {
                let digest = Sha512::new()
                    .chain_update([seed])
                    .chain_update(i.to_le_bytes());
                digest.finalize()[..43].try_into().unwrap()
            })
            .collect()
    }

    #[test]
    fn members_match_and_others_rarely_do() {
        let key = [7; 32];
        let members = receivers(200, 1);
        let filters = Filters::new(
            Filter::build(&key, &members),
            [
                (
                    "near-intents/recent".to_owned(),
                    Filter::build(&key, &members[..3]),
                ),
                ("near-intents/seen".to_owned(), Filter::build(&key, [])),
            ],
        )
        .unwrap();
        let decoded = Filters::decode(&filters.encode().unwrap()).unwrap();
        assert_eq!(decoded, filters);
        let paid = decoded.get(PAID).unwrap();
        assert!(paid.matches(&key, &members).iter().all(|m| *m));
        assert_eq!(
            decoded
                .get("near-intents/recent")
                .unwrap()
                .matches(&key, &members[..4]),
            [true, true, true, false]
        );
        assert_eq!(
            decoded
                .get("near-intents/seen")
                .unwrap()
                .matches(&key, &members[..2]),
            [false, false]
        );
        // About one of 2,000 others matches falsely.
        let others = receivers(2000, 2);
        let false_matches = paid.matches(&key, &others).iter().filter(|m| **m).count();
        assert!(false_matches < 12, "{false_matches} false matches");
        // About 1.6 bytes per receiver.
        assert!(paid.bytes.len() < 340, "{}", paid.bytes.len());
    }

    /// The upstream BIP 158 reader agrees with the strict decoder on every member.
    #[test]
    fn sets_are_bip158_filters() {
        let key = [9; 32];
        let members = receivers(100, 3);
        let filter = Filter::build(&key, &members);
        let (k0, k1) = keys(&key);
        let reader = bitcoin::bip158::GcsFilterReader::new(k0, k1, M, P);
        assert!(reader
            .match_all(
                &mut filter.bytes.as_slice(),
                members.iter().map(|r| r.as_slice())
            )
            .unwrap());
        let mut expected = Vec::new();
        let mut upstream = bitcoin::bip158::GcsFilterWriter::new(&mut expected, k0, k1, M, P);
        for receiver in &members {
            upstream.add_element(receiver);
        }
        upstream.finish().unwrap();
        assert_eq!(
            filter.bytes, expected,
            "receiver filter bytes must remain unchanged"
        );
        assert_eq!(filter.count(), 100);
        assert_eq!(Filter::build(&key, members.iter().chain(&members)), filter);
    }

    #[test]
    fn labels_are_checked() {
        for label in ["paid", "near-intents/recent", "a1/seen"] {
            assert!(valid_label(label), "{label}");
        }
        for label in [
            "",
            "near/other",
            "/recent",
            "Near/recent",
            "near/recent/x",
            "near",
        ] {
            assert!(!valid_label(label), "{label}");
        }
        let empty = || Filter::build(&[0; 32], []);
        assert!(Filters::new(empty(), [("paid".to_owned(), empty())]).is_err());
        assert!(Filters::new(empty(), [("near/other".to_owned(), empty())]).is_err());
    }

    #[test]
    fn decoding_rejects_corruption() {
        let key = [7; 32];
        let paid = Filter::build(&key, &receivers(50, 1));
        let filters = Filters::new(
            paid,
            [("near-intents/seen".to_owned(), Filter::build(&key, []))],
        )
        .unwrap();
        let bytes = filters.encode().unwrap();
        assert!(Filters::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(Filters::decode(&longer).is_err());
        // A larger paid count no longer fits its bits.
        let mut count = bytes.clone();
        let at = bytes.windows(4).position(|w| w == PAID.as_bytes()).unwrap() + 8;
        count[at] += 1;
        assert!(Filters::decode(&count).is_err());
        // A set's count must be minimally encoded, and its padding zero.
        assert!(Filter::decode(&[0xfd, 0, 0]).is_err());
        let one = Filter::build(&key, &receivers(1, 1)).bytes;
        let mut padded = one.clone();
        *padded.last_mut().unwrap() |= 1;
        assert!(Filter::decode(&one).is_ok() && Filter::decode(&padded).is_err());
        let valid = Filter::build(&key, &receivers(100, 3)).bytes;
        for end in 0..valid.len() {
            assert!(Filter::decode(&valid[..end]).is_err());
        }
        let mut trailing = valid;
        trailing.push(0);
        assert!(Filter::decode(&trailing).is_err());
        let mut magic = bytes.clone();
        magic[0] ^= 1;
        assert!(Filters::decode(&magic).is_err());
        // A file without the paid set is refused.
        let mut no_paid = MAGIC.to_vec();
        no_paid.extend(0u32.to_le_bytes());
        assert!(Filters::decode(&no_paid).is_err());
    }

    /// A set of `count` equal values, which strictly decodes.
    fn zeros(count: u64) -> Filter {
        use bitcoin::consensus::{encode::VarInt, Encodable};
        let mut bytes = Vec::new();
        VarInt(count).consensus_encode(&mut bytes).unwrap();
        // Each zero delta is a zero unary quotient and a zero `P`-bit remainder.
        bytes.resize(
            bytes.len() + (count * (u64::from(P) + 1)).div_ceil(8) as usize,
            0,
        );
        Filter::decode(&bytes).unwrap()
    }

    /// A file over the bound is refused when encoding and before decoding, though its
    /// set is well formed.
    #[test]
    fn files_over_the_size_bound_are_refused() {
        // A file holding only the paid set of `count` zeros, by hand.
        let file = |count| {
            let filter = zeros(count);
            let mut bytes = MAGIC.to_vec();
            bytes.extend(1u32.to_le_bytes());
            bytes.push(PAID.len() as u8);
            bytes.extend(PAID.as_bytes());
            bytes.extend((filter.bytes.len() as u32).to_le_bytes());
            bytes.extend(&filter.bytes);
            (Filters::new(filter, []).unwrap(), bytes)
        };
        let fits = (MAX_FILTERS_BYTES as u64 - 30) * 8 / (u64::from(P) + 1);
        let (filters, bytes) = file(fits);
        assert!(bytes.len() <= MAX_FILTERS_BYTES);
        assert_eq!(filters.encode().unwrap(), bytes);
        assert_eq!(Filters::decode(&bytes).unwrap(), filters);
        let (filters, bytes) = file(fits + 64);
        assert!(bytes.len() > MAX_FILTERS_BYTES);
        assert!(filters.encode().is_err());
        assert!(Filters::decode(&bytes).is_err());
    }
}
