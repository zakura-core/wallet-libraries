#[cfg(test)]
mod tests {
    use crate::transparent::filter::build_filter;
    use zakura_pir_protocol::transparent::filter::FilterError;
    use zakura_pir_protocol::transparent::filter::hash::BlockHash;
    use zakura_pir_protocol::transparent::filter::script::ScriptBytes;
    use zakura_pir_protocol::transparent::filter::validate::*;

    fn hash() -> BlockHash {
        BlockHash::from_internal_bytes([3u8; 32])
    }

    fn sample() -> Vec<u8> {
        let elements: Vec<_> = (0u8..20)
            .map(|index| ScriptBytes::new(vec![0x76, 0xa9, index]))
            .collect();
        build_filter(hash(), &elements).unwrap().0
    }

    #[test]
    fn a_built_filter_validates_and_reports_its_count() {
        let validated = validate_filter(&sample(), FilterLimits::default()).unwrap();
        assert_eq!(validated.element_count(), 20);
        assert!(validated.values().windows(2).all(|pair| pair[0] < pair[1]));
        assert!(
            validated
                .values()
                .iter()
                .all(|value| *value < validated.range())
        );
    }

    #[test]
    fn the_empty_filter_validates_to_no_elements() {
        let validated = validate_filter(&[0x00], FilterLimits::default()).unwrap();
        assert_eq!(validated.element_count(), 0);
        assert_eq!(validated.range(), 0);
    }

    #[test]
    fn an_empty_filter_with_trailing_bytes_is_rejected() {
        assert_eq!(
            validate_filter(&[0x00, 0x00], FilterLimits::default()),
            Err(FilterError::TrailingBytes(1))
        );
    }

    #[test]
    fn empty_input_is_truncated_not_empty() {
        assert!(matches!(
            validate_filter(&[], FilterLimits::default()),
            Err(FilterError::Truncated(_))
        ));
    }

    #[test]
    fn truncated_bit_streams_are_rejected() {
        let bytes = sample();
        for cut in 1..bytes.len() {
            assert!(
                validate_filter(&bytes[..cut], FilterLimits::default()).is_err(),
                "prefix of {cut} bytes validated"
            );
        }
    }

    #[test]
    fn trailing_bytes_after_a_valid_stream_are_rejected() {
        let mut bytes = sample();
        bytes.push(0x00);
        assert!(matches!(
            validate_filter(&bytes, FilterLimits::default()),
            Err(FilterError::TrailingBytes(1))
        ));
    }

    #[test]
    fn nonzero_padding_is_rejected() {
        let mut bytes = sample();
        // The final byte holds the tail of the last value plus zero padding.
        // Any set bit in the padding must be refused; find one that is padding
        // by confirming the unmodified filter is valid and the modified one is
        // rejected for padding specifically.
        let last = bytes.len() - 1;
        let original = bytes[last];
        let mut saw_padding_error = false;
        for bit in 0..8 {
            bytes[last] = original | (1 << bit);
            if bytes[last] == original {
                continue;
            }
            if matches!(
                validate_filter(&bytes, FilterLimits::default()),
                Err(FilterError::NonZeroPadding)
            ) {
                saw_padding_error = true;
            }
        }
        assert!(saw_padding_error, "no padding bit was checked");
    }

    #[test]
    fn noncanonical_compact_size_is_rejected() {
        for encoding in [
            vec![0xfd, 0x01, 0x00],
            vec![0xfe, 0x01, 0x00, 0x00, 0x00],
            vec![0xff, 0x01, 0, 0, 0, 0, 0, 0, 0],
        ] {
            assert!(matches!(
                validate_filter(&encoding, FilterLimits::default()),
                Err(FilterError::NotCanonical(_))
            ));
        }
    }

    #[test]
    fn truncated_compact_size_is_rejected() {
        assert!(matches!(
            validate_filter(&[0xfd, 0x01], FilterLimits::default()),
            Err(FilterError::Truncated(_))
        ));
    }

    #[test]
    fn a_huge_count_is_refused_before_allocation() {
        // 0xffffffffffffffff elements against an empty body.
        let bytes = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert!(matches!(
            validate_filter(&bytes, FilterLimits::default()),
            Err(FilterError::LimitExceeded(_))
        ));
    }

    #[test]
    fn a_count_larger_than_the_body_can_encode_is_refused() {
        let mut bytes = vec![0xfd, 0x00, 0x10]; // 4096 elements
        bytes.extend_from_slice(&[0x00; 8]);
        assert!(matches!(
            validate_filter(&bytes, FilterLimits::default()),
            Err(FilterError::Truncated(_))
        ));
    }

    #[test]
    fn a_long_unary_run_terminates_instead_of_spinning() {
        // One claimed element followed by all-ones: the quotient bound stops it.
        let mut bytes = vec![0x01];
        bytes.extend_from_slice(&[0xff; 4096]);
        assert!(matches!(
            validate_filter(&bytes, FilterLimits::default()),
            Err(FilterError::LimitExceeded(_))
        ));
    }

    #[test]
    fn oversize_filters_are_refused_by_byte_limit() {
        let limits = FilterLimits {
            max_bytes: 4,
            max_elements: 10,
        };
        assert!(matches!(
            validate_filter(&[0u8; 5], limits),
            Err(FilterError::LimitExceeded(_))
        ));
    }

    #[test]
    fn an_exceeded_element_cap_is_reported_as_a_limit_not_a_match() {
        let limits = FilterLimits {
            max_bytes: 1024,
            max_elements: 2,
        };
        let error = validate_filter(&sample(), limits).unwrap_err();
        assert!(matches!(error, FilterError::LimitExceeded(_)));
    }
}
