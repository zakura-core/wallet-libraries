//! Deterministic filter construction, for a single block and for a shard.

use crate::error::FilterError;
use crate::hash::{BlockHash, FilterKeys, ShardKey};
use crate::profile::{M, P};
use crate::script::ScriptBytes;
use bitcoin::bip158::GcsFilterWriter;
use std::collections::BTreeSet;

/// Serialized BIP 158 filter bytes for one block or for one shard.
///
/// The bytes carry no indication of which; that is the caller's context, and
/// the keying is what actually separates the two.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterBytes(pub Vec<u8>);

impl FilterBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for FilterBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Builds the filter for one block from its complete element set.
///
/// One filter represents exactly one accepted block. Delivery objects may
/// bundle filters, but must never merge them into a single differently keyed
/// filter, because the SipHash keys are derived from this block's hash. A
/// filter that legitimately covers more than one block is a different profile
/// with a different keying; see [`build_range_filter`].
///
/// Elements are deduplicated by raw script bytes before encoding. Deduplication
/// is on the bytes only: two distinct scripts whose hashes collide are two
/// elements, and collapsing them would drop coverage.
///
/// Callers are responsible for supplying a *complete* element set. This
/// function cannot tell an intentionally empty block from one whose previous
/// outputs failed to resolve, so a caller that cannot resolve a previous output
/// must fail rather than pass a short list.
pub fn build_filter(
    block_hash: BlockHash,
    elements: &[ScriptBytes],
) -> Result<FilterBytes, FilterError> {
    encode(block_hash.filter_keys(), elements)
}

/// Builds the filter for one shard from the complete element set of its range.
///
/// The same encoder as [`build_filter`], under the range profile's keying. The
/// element set is the union over every block in the shard, deduplicated, which
/// is the whole point: a script that appears in many of the shard's blocks
/// costs one element instead of one per block.
///
/// The completeness obligation is the same and larger. An unresolved previous
/// output anywhere in the range makes the shard incomplete, and a caller must
/// fail construction rather than seal a shard over a short list — a shard is
/// immutable once published, so a gap here is permanent.
pub fn build_range_filter(
    shard_key: ShardKey,
    elements: &[ScriptBytes],
) -> Result<FilterBytes, FilterError> {
    encode(shard_key.filter_keys(), elements)
}

/// The shared GCS encoding. Both profiles differ only in how they key it.
/// Builds a range filter under a registered profile's parameters.
///
/// `shard_key` must have been derived with the same profile name, which is
/// what binds the bytes to the profile a consumer will select.
pub fn build_range_filter_for(
    profile: &crate::profile::RangeProfile,
    shard_key: ShardKey,
    elements: &[ScriptBytes],
) -> Result<FilterBytes, FilterError> {
    encode_with(shard_key.filter_keys(), elements, profile.m, profile.p)
}

/// Builds a range filter under explicit Golomb-Rice parameters.
///
/// For evaluating alternative profiles offline. Published filters use
/// [`build_range_filter`], whose `M` and `P` are the profile's; a filter built
/// here under other values is not readable as a profile filter.
pub fn build_range_filter_with(
    shard_key: ShardKey,
    elements: &[ScriptBytes],
    m: u64,
    p: u8,
) -> Result<FilterBytes, FilterError> {
    encode_with(shard_key.filter_keys(), elements, m, p)
}

fn encode(keys: FilterKeys, elements: &[ScriptBytes]) -> Result<FilterBytes, FilterError> {
    encode_with(keys, elements, M, P)
}

fn encode_with(
    keys: FilterKeys,
    elements: &[ScriptBytes],
    m: u64,
    p: u8,
) -> Result<FilterBytes, FilterError> {
    // Filter membership is a set; sorting and deduplicating here (rather than
    // relying on the writer's internal set) keeps the element count we report
    // and the count the encoder writes the same number.
    let deduplicated: BTreeSet<&[u8]> = elements
        .iter()
        .filter(|script| script.is_filter_element())
        .map(|script| script.as_slice())
        .collect();

    let mut bytes = Vec::new();
    let mut writer = GcsFilterWriter::new(&mut bytes, keys.k0, keys.k1, m, p);
    for element in &deduplicated {
        writer.add_element(element);
    }
    writer
        .finish()
        .map_err(|error| FilterError::Encoding(error.to_string()))?;
    Ok(FilterBytes(bytes))
}

/// The number of elements `build_filter` would encode for this input.
pub fn element_count(elements: &[ScriptBytes]) -> usize {
    elements
        .iter()
        .filter(|script| script.is_filter_element())
        .map(|script| script.as_slice())
        .collect::<BTreeSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{MAINNET_GENESIS_DISPLAY, RANGE_PROFILE};
    use crate::validate::{validate_filter, FilterLimits};

    fn hash() -> BlockHash {
        BlockHash::from_internal_bytes([7u8; 32])
    }

    fn shard_key() -> ShardKey {
        ShardKey::derive(
            RANGE_PROFILE,
            BlockHash::from_display_hex(MAINNET_GENESIS_DISPLAY).unwrap(),
            0,
            3_428_143,
            3_429_166,
            hash(),
        )
    }

    fn script(tag: u8) -> ScriptBytes {
        ScriptBytes::new(vec![0x76, 0xa9, 0x14, tag])
    }

    /// The point of a shard filter: a script appearing in many of the shard's
    /// blocks is one element, not one per block. Without this the range profile
    /// would cost more than the per-block filters it replaces.
    #[test]
    fn scripts_repeated_across_a_shard_are_encoded_once() {
        let distinct: Vec<ScriptBytes> = (0..32).map(script).collect();
        let mut repeated = Vec::new();
        for _ in 0..10 {
            repeated.extend(distinct.iter().cloned());
        }
        assert_eq!(element_count(&repeated), 32);
        assert_eq!(
            build_range_filter(shard_key(), &repeated).unwrap(),
            build_range_filter(shard_key(), &distinct).unwrap()
        );
    }

    /// Profile separation, at the level that actually matters: the same
    /// elements under the two keyings must not produce the same bytes, or a
    /// shard filter could be served where a block filter was asked for.
    #[test]
    fn the_two_profiles_encode_the_same_elements_differently() {
        let elements: Vec<ScriptBytes> = (0..16).map(script).collect();
        assert_ne!(
            build_range_filter(shard_key(), &elements).unwrap(),
            build_filter(hash(), &elements).unwrap()
        );
    }

    /// A shard filter matched under block keying must not report its own
    /// elements. This is the failure a wallet would actually hit if the two
    /// profiles were confused, and it must look like "nothing matched" rather
    /// than a decode error that some caller might treat as retryable.
    #[test]
    fn a_shard_filter_does_not_match_under_block_keying() {
        let elements: Vec<ScriptBytes> = (0..64).map(script).collect();
        let bytes = build_range_filter(shard_key(), &elements).unwrap();
        let validated = validate_filter(bytes.as_slice(), FilterLimits::default()).unwrap();

        let correct =
            crate::matching::match_range_scripts(&validated, shard_key(), &elements).unwrap();
        assert_eq!(correct, (0..elements.len()).collect::<Vec<_>>());

        // Under the wrong keying the wallet's scripts map to unrelated values.
        // A handful of the 64 could collide by chance at 1/M each; requiring
        // near-zero rather than exactly zero keeps the test honest.
        let wrong = crate::matching::match_scripts(&validated, hash(), &elements).unwrap();
        assert!(
            wrong.len() < 4,
            "matched {} of 64 under block keying",
            wrong.len()
        );
    }

    #[test]
    fn the_empty_shard_filter_is_exactly_one_zero_byte() {
        assert_eq!(
            build_range_filter(shard_key(), &[]).unwrap().as_slice(),
            &[0x00]
        );
    }

    #[test]
    fn the_empty_filter_is_exactly_one_zero_byte() {
        assert_eq!(build_filter(hash(), &[]).unwrap().as_slice(), &[0x00]);
    }

    #[test]
    fn scripts_excluded_from_the_element_set_produce_the_empty_filter() {
        let excluded = vec![
            ScriptBytes::new(vec![]),
            ScriptBytes::new(vec![0x6a]),
            ScriptBytes::new(vec![0x6a, 0xff, 0xff]),
        ];
        assert_eq!(build_filter(hash(), &excluded).unwrap().as_slice(), &[0x00]);
        assert_eq!(element_count(&excluded), 0);
    }

    #[test]
    fn duplicate_and_reordered_elements_encode_identically() {
        let a = ScriptBytes::new(vec![0x76, 0xa9, 0x01]);
        let b = ScriptBytes::new(vec![0x51, 0x52]);
        let one = build_filter(hash(), &[a.clone(), b.clone()]).unwrap();
        let reordered = build_filter(hash(), &[b.clone(), a.clone()]).unwrap();
        let duplicated =
            build_filter(hash(), &[b.clone(), a.clone(), a.clone(), b.clone()]).unwrap();
        assert_eq!(one, reordered);
        assert_eq!(one, duplicated);
        assert_eq!(element_count(&[a, b]), 2);
    }

    #[test]
    fn a_different_block_hash_produces_different_bytes_for_the_same_elements() {
        let elements = vec![ScriptBytes::new(vec![0x76, 0xa9, 0x14, 0x01])];
        let one = build_filter(hash(), &elements).unwrap();
        let other = build_filter(BlockHash::from_internal_bytes([9u8; 32]), &elements).unwrap();
        assert_ne!(one, other);
    }
}
