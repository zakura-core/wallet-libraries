//! An experimental parent filter built by the publisher matches every script
//! it was built over, agrees with an independent reader, and refuses
//! corruption.

use std::collections::BTreeSet;

use zakura_transparent_private_server::filter::experimental_parent::ParentBuild as _;
use zakura_transparent_private_shared::filter::RANGE_PROFILE;
use zakura_transparent_private_shared::filter::experimental_parent::{Parent, optimal_p, sha};
use zakura_transparent_private_wallet::filter::experimental_parent::ParentMatch as _;

fn parent(m: u64) -> Parent {
    Parent {
        genesis_hash: "00".repeat(32),
        profile: RANGE_PROFILE.into(),
        m,
        p: optimal_p(m),
        children: vec![],
        filter_hash: String::new(),
        bytes: 0,
        elements: 0,
    }
}

#[test]
fn precision_matches_upstream_and_strictly_rejects_corruption() {
    let scripts: BTreeSet<_> = (0u32..500).map(|i| i.to_le_bytes().to_vec()).collect();
    for m in [100, 1000, 10000] {
        let mut p = parent(m);
        let bytes = p.build(&scripts).unwrap();
        let valid = p.validate(&bytes).unwrap();
        assert!(
            p.matches(&valid, &scripts.iter().cloned().collect::<Vec<_>>())
                .unwrap()
        );
        let keys = p.keys().unwrap();
        let reader = bitcoin::bip158::GcsFilterReader::new(keys.k0, keys.k1, m, p.p);
        assert!(
            reader
                .match_all(&mut bytes.as_slice(), scripts.iter().map(Vec::as_slice))
                .unwrap()
        );
        for script in &scripts {
            assert!(p.matches(&valid, std::slice::from_ref(script)).unwrap());
        }
        for mut corrupt in [
            bytes[..bytes.len() - 1].to_vec(),
            {
                let mut b = bytes.clone();
                b.push(0);
                b
            },
            vec![0xff; 9],
        ] {
            assert!(p.validate(&corrupt).is_err());
            // Even a matching digest must not allow a malformed stream.
            let mut q = p.clone();
            q.bytes = corrupt.len() as u64;
            q.filter_hash = sha(&corrupt);
            assert!(q.validate(&corrupt).is_err());
            corrupt.clear();
        }
    }
}
