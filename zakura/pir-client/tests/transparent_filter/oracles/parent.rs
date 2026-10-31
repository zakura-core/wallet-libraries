//! Parent filter precision compared with the pinned independent Bitcoin reader.
use std::collections::BTreeSet;
use zakura_pir_client::transparent::filter::{
    ParentClientExt, RANGE_PROFILE,
    experimental_parent::{Parent, optimal_p},
};
use zakura_pir_publisher::transparent::filter::ParentPublisherExt;

#[test]
fn precision_matches_upstream() {
    let scripts: BTreeSet<_> = (0u32..500).map(|i| i.to_le_bytes().to_vec()).collect();
    for m in [100, 1000, 10000] {
        let mut parent = Parent {
            genesis_hash: "00".repeat(32),
            profile: RANGE_PROFILE.into(),
            m,
            p: optimal_p(m),
            children: vec![],
            filter_hash: String::new(),
            bytes: 0,
            elements: 0,
        };
        let bytes = parent.build(&scripts).unwrap();
        let valid = parent.validate(&bytes).unwrap();
        assert!(
            parent
                .matches(&valid, &scripts.iter().cloned().collect::<Vec<_>>())
                .unwrap()
        );
        let keys = parent.keys().unwrap();
        let reader = bitcoin::bip158::GcsFilterReader::new(keys.k0, keys.k1, m, parent.p);
        assert!(
            reader
                .match_all(&mut bytes.as_slice(), scripts.iter().map(Vec::as_slice))
                .unwrap()
        );
    }
}
