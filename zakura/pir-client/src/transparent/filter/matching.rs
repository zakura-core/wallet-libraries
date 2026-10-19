//! Client filter matching.
pub use zakura_pir_protocol::transparent::filter::matching::*;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparent::filter::validate::{FilterLimits, validate_filter};
    use zakura_pir_publisher::transparent::filter::build_filter;
    use zakura_pir_publisher::transparent::filter::*;

    fn hash() -> BlockHash {
        BlockHash::from_internal_bytes([0x5au8; 32])
    }

    fn scripts(count: u8) -> Vec<ScriptBytes> {
        (0..count)
            .map(|index| ScriptBytes::new(vec![0x76, 0xa9, 0x14, index]))
            .collect()
    }

    fn validated(
        elements: &[ScriptBytes],
    ) -> crate::transparent::filter::validate::ValidatedFilter {
        let bytes = build_filter(hash(), elements).unwrap();
        validate_filter(bytes.as_slice(), FilterLimits::default()).unwrap()
    }

    #[test]
    fn every_included_script_matches() {
        let elements = scripts(64);
        let filter = validated(&elements);
        let matched = match_scripts(&filter, hash(), &elements).unwrap();
        assert_eq!(matched, (0..elements.len()).collect::<Vec<_>>());
    }

    #[test]
    fn all_matching_identities_are_returned_not_just_the_first() {
        let elements = scripts(10);
        let filter = validated(&elements);
        // Query a superset in an order unrelated to the element order.
        let mut query = vec![ScriptBytes::new(vec![0xde, 0xad])];
        query.extend(elements.iter().rev().cloned());
        let matched = match_scripts(&filter, hash(), &query).unwrap();
        // Indices 1..=10 are the ten real elements; index 0 is very unlikely to
        // collide, but a collision would only add an index, never remove one.
        for index in 1..=10 {
            assert!(matched.contains(&index), "missing index {index}");
        }
    }

    #[test]
    fn an_empty_query_returns_no_matches() {
        let filter = validated(&scripts(4));
        assert!(match_scripts(&filter, hash(), &[]).unwrap().is_empty());
    }

    #[test]
    fn the_empty_filter_matches_nothing() {
        let filter = validated(&[]);
        assert!(
            match_scripts(&filter, hash(), &scripts(8))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn empty_wallet_scripts_are_skipped_without_shifting_indices() {
        let elements = scripts(3);
        let filter = validated(&elements);
        let query = vec![
            ScriptBytes::new(vec![]),
            elements[1].clone(),
            ScriptBytes::new(vec![]),
        ];
        assert_eq!(match_scripts(&filter, hash(), &query).unwrap(), vec![1]);
    }

    #[test]
    fn matching_is_indifferent_to_query_order() {
        let elements = scripts(32);
        let filter = validated(&elements);
        let forward = match_scripts(&filter, hash(), &elements).unwrap();
        let mut reversed: Vec<_> = elements.clone();
        reversed.reverse();
        let backward = match_scripts(&filter, hash(), &reversed).unwrap();
        assert_eq!(forward.len(), backward.len());
    }
}
