//! The `zcash-transparent-basic-v1` application profile.
//!
//! This is a proposed application profile that reuses BIP 158's basic encoding
//! and analogous transparent-script inclusion rules. It is not an assertion of
//! an existing Zcash network standard, and it implies no support for Bitcoin
//! peer-service messages or signalling.

/// Profile identifier carried in application metadata and cache keys.
pub const PROFILE: &str = "zcash-transparent-basic-v1";

/// Profile identifier for filters covering a shard rather than a single block.
///
/// A separate profile, not a version bump of [`PROFILE`]: the two use different
/// keyings, cover different things, and a wallet must never accept one where it
/// asked for the other. The string is part of the SipHash key derivation (see
/// `ShardKey`), so the separation is enforced by the bytes and not only by
/// metadata a server could misreport.
///
/// `P` and `M` are unchanged. In BIP 158 an element is mapped into `[0, N*M)`,
/// so the per-tested-element false-positive rate is `1/M` regardless of how
/// many elements the filter holds: a shard filter over twelve thousand scripts
/// is exactly as precise per query as a block filter over twelve. What grows
/// with the element count is the filter's *size*, which is what deduplicating
/// scripts across a shard's blocks is meant to pay for.
pub const RANGE_PROFILE: &str = "zcash-transparent-range-v1";

/// Golomb-Rice parameter. Fixed by the profile; not configurable.
pub const P: u8 = 19;

/// False-positive range parameter. Fixed by the profile; not configurable.
pub const M: u64 = 784_931;

/// A range-filter profile: its name and the Golomb-Rice parameters it fixes.
///
/// The name is published in the shard map and every manifest, and it keys the
/// filter's SipHash (see `ShardKey`). A consumer selects `P` and `M` by the
/// published name and must refuse a name it does not know: decoding a filter
/// under another profile's parameters yields values that neither fail
/// reliably nor match correctly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeProfile {
    pub name: &'static str,
    pub p: u8,
    pub m: u64,
}

/// The original range profile: BIP 158's basic parameters.
pub const RANGE_PROFILE_V1: RangeProfile = RangeProfile {
    name: RANGE_PROFILE,
    p: P,
    m: M,
};

/// Lower precision tuned to ordinary wallets testing up to about 100 scripts:
/// about 45% smaller recent filters, with a false match per tested absent
/// script of `1/1,024`. A false match costs one extra directory lookup, which
/// wallets testing many more scripts pay for. See the filter precision sweep
/// in the transparent evidence.
pub const RANGE_PROFILE_V2: RangeProfile = RangeProfile {
    name: "zcash-transparent-range-v2",
    p: 10,
    m: 1_024,
};

/// Every range profile this build reads or publishes.
pub const RANGE_PROFILES: &[RangeProfile] = &[RANGE_PROFILE_V1, RANGE_PROFILE_V2];

/// The range profile named `name`, or `None`; callers must refuse `None`.
pub fn range_profile(name: &str) -> Option<&'static RangeProfile> {
    RANGE_PROFILES.iter().find(|profile| profile.name == name)
}

/// Network identifier carried alongside the genesis hash.
pub const NETWORK: &str = "main";

/// Zcash mainnet genesis block hash in RPC display order.
///
/// Chain identity is the genesis hash, not the network name: the name alone
/// would let a filter built on one chain be accepted on another that happens to
/// share it.
pub const MAINNET_GENESIS_DISPLAY: &str =
    "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08";

/// First height this profile publishes filters for.
///
/// Coverage begins at Ironwood activation rather than genesis. A wallet whose
/// birthday precedes this height is not served by this deployment; that is a
/// deployment limitation, not a property of the encoding.
pub const START_HEIGHT: u64 = 3_428_143;

#[cfg(test)]
mod range_profile_tests {
    use super::*;
    use crate::build_filter::{build_range_filter, build_range_filter_for};
    use crate::hash::{BlockHash, ShardKey};
    use crate::script::ScriptBytes;
    use crate::validate::{validate_range_filter, FilterLimits};

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
