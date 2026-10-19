#[cfg(test)]
mod range_profile_tests {
    use crate::transparent::filter::{build_range_filter, build_range_filter_for};
    use zakura_pir_protocol::transparent::filter::hash::{BlockHash, ShardKey};
    use zakura_pir_protocol::transparent::filter::profile::*;
    use zakura_pir_protocol::transparent::filter::script::ScriptBytes;
    use zakura_pir_protocol::transparent::filter::validate::{FilterLimits, validate_range_filter};

    fn key(profile: &str) -> ShardKey {
        ShardKey::derive(
            profile,
            BlockHash::from_display_hex(MAINNET_GENESIS_DISPLAY).unwrap(),
            3,
            100,
            199,
            BlockHash::from_internal_bytes([9; 32]),
        )
    }

    fn elements() -> Vec<ScriptBytes> {
        (0..500u32)
            .map(|i| {
                ScriptBytes::new([&[0x76, 0xa9, 0x14][..], &i.to_le_bytes(), &[0; 16]].concat())
            })
            .collect()
    }

    #[test]
    fn profiles_resolve_by_name_and_unknown_names_do_not() {
        for profile in RANGE_PROFILES {
            assert_eq!(range_profile(profile.name), Some(profile));
        }
        assert_eq!(range_profile(RANGE_PROFILE), Some(&RANGE_PROFILE_V1));
        assert_eq!(range_profile("zcash-transparent-range-v99"), None);
        assert_eq!(
            range_profile(PROFILE),
            None,
            "the per-block profile is not a range profile"
        );
    }

    #[test]
    fn the_original_profile_encodes_exactly_as_before() {
        let elements = elements();
        assert_eq!(
            build_range_filter_for(&RANGE_PROFILE_V1, key(RANGE_PROFILE), &elements).unwrap(),
            build_range_filter(key(RANGE_PROFILE), &elements).unwrap()
        );
    }

    #[test]
    fn a_v2_filter_is_smaller_and_validates_under_its_own_parameters_only() {
        let elements = elements();
        let v1 = build_range_filter_for(&RANGE_PROFILE_V1, key(RANGE_PROFILE_V1.name), &elements)
            .unwrap();
        let v2 = build_range_filter_for(&RANGE_PROFILE_V2, key(RANGE_PROFILE_V2.name), &elements)
            .unwrap();
        assert!(
            v2.len() * 100 < v1.len() * 80,
            "{} vs {}",
            v2.len(),
            v1.len()
        );
        let validated =
            validate_range_filter(v2.as_slice(), FilterLimits::default(), &RANGE_PROFILE_V2)
                .unwrap();
        assert_eq!(validated.element_count(), elements.len());
        // Read under the wrong profile it is either refused or decodes into
        // a different value set; it must never be taken as the same filter.
        if let Ok(wrong) =
            validate_range_filter(v2.as_slice(), FilterLimits::default(), &RANGE_PROFILE_V1)
        {
            assert_ne!(wrong.values(), validated.values());
        }
    }
}
