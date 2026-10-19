//! Experimental parent filter client operations.
pub use zakura_pir_protocol::transparent::filter::experimental_parent::*;
use zakura_pir_protocol::transparent::filter::{FilterError, ScriptBytes, ValidatedFilter};
/// Operations specific to the client role.
pub trait ParentClientExt {
    fn matches(&self, filter: &ValidatedFilter, scripts: &[Vec<u8>]) -> Result<bool, FilterError>;
}
impl ParentClientExt for Parent {
    fn matches(&self, filter: &ValidatedFilter, scripts: &[Vec<u8>]) -> Result<bool, FilterError> {
        let owned: Vec<_> = scripts.iter().cloned().map(ScriptBytes::new).collect();
        Ok(
            crate::transparent::filter::matching::map_wallet_scripts_keyed(
                filter,
                self.keys()?,
                &owned,
            )
            .iter()
            .any(|(v, _)| filter.values().binary_search(v).is_ok()),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use zakura_pir_publisher::transparent::filter::ParentPublisherExt;
    fn parent(m: u64) -> Parent {
        Parent {
            genesis_hash: "00".repeat(32),
            profile: crate::transparent::filter::RANGE_PROFILE.into(),
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
    #[test]
    fn canonical_empty_and_identity_separation() {
        let mut p = parent(1000);
        assert_eq!(p.build(&BTreeSet::new()).unwrap(), vec![0]);
        let k = p.keys().unwrap();
        assert_eq!((k.k0, k.k1), (9500719077814865096, 10828449669822442003));
        p.m = 100;
        assert_ne!(k, p.keys().unwrap());
        p.m = 1000;
        p.genesis_hash = "11".repeat(32);
        assert_ne!(k, p.keys().unwrap());
        assert_eq!(
            [optimal_p(100), optimal_p(1000), optimal_p(10000)],
            [6, 9, 13]
        );
        assert!(
            crate::transparent::filter::validate::validate_parameters(&[0], LIMITS, 0, 9).is_err()
        );
        assert!(
            crate::transparent::filter::validate::validate_parameters(&[0], LIMITS, 1000, 64)
                .is_err()
        );
    }
}
