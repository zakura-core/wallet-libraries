//! Opt-in research profile. Parent negatives trust the same indexer as child
//! negatives; digests establish consistency, not chain completeness. Selective
//! child requests disclose coarse activity intervals to the filter origin.
use crate::{
    FilterError, FilterKeys, FilterLimits, ScriptBytes, ShardMap, ShardMapEntry, ValidatedFilter,
};
use bitcoin::bip158::GcsFilterWriter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const SCHEMA: &str = "transparent-parent-evaluation-v1";
pub const LIMITS: FilterLimits = FilterLimits {
    max_bytes: 64 * 1024 * 1024,
    max_elements: 25_000_000,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Parent {
    pub genesis_hash: String,
    pub profile: String,
    pub m: u64,
    pub p: u8,
    pub children: Vec<ShardMapEntry>,
    pub filter_hash: String,
    pub bytes: u64,
    pub elements: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub map_sha256: String,
    pub parents: Vec<Parent>,
    pub child_bytes: Vec<(String, u64)>,
}

/// Select precision without observing the wallet workload. Expected gaps are
/// geometric with success probability 1/M, so E[quotient] = a/(1-a),
/// a=(1-1/M)^(2^P). The +1 is the unary terminator.
pub fn optimal_p(m: u64) -> u8 {
    (0..=24)
        .min_by(|a, b| expected_bits(m, *a).total_cmp(&expected_bits(m, *b)))
        .unwrap()
}
pub fn expected_bits(m: u64, p: u8) -> f64 {
    let x = (1u64 << p) as f64 * (-1.0 / m as f64).ln_1p();
    p as f64 + 1.0 + x.exp() / -x.exp_m1()
}
pub fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
impl Parent {
    /// Fixed-width digests, integers and length-prefixed strings bind the exact
    /// ordered revision list. This domain is separate from block/shard profiles.
    pub fn keys(&self) -> Result<FilterKeys, FilterError> {
        let mut h = Sha256::new();
        h.update(b"transparent-parent-evaluation-v1\0");
        for s in [&self.genesis_hash, &self.profile] {
            h.update((s.len() as u64).to_le_bytes());
            h.update(s.as_bytes());
        }
        h.update(self.m.to_le_bytes());
        h.update([self.p]);
        h.update((self.children.len() as u64).to_le_bytes());
        for c in &self.children {
            h.update(c.shard_id.to_le_bytes());
            h.update(c.start_height.to_le_bytes());
            h.update(c.end_height.to_le_bytes());
            for s in [&c.manifest_digest, &c.filter_hash, &c.terminal_block_hash] {
                let raw = hex::decode(s).map_err(|e| FilterError::Encoding(e.to_string()))?;
                if raw.len() != 32 {
                    return Err(FilterError::Encoding("invalid child digest".into()));
                }
                h.update(raw);
            }
        }
        let d = h.finalize();
        Ok(FilterKeys {
            k0: u64::from_le_bytes(d[..8].try_into().unwrap()),
            k1: u64::from_le_bytes(d[8..16].try_into().unwrap()),
        })
    }
    pub fn agrees(&self, map: &ShardMap) -> bool {
        self.genesis_hash == map.genesis_hash
            && self.profile == map.profile
            && !self.children.is_empty()
            && self
                .children
                .iter()
                .all(|c| c.sealed && map.shards.iter().any(|e| e == c))
            && self.children.windows(2).all(|w| {
                w[0].end_height.checked_add(1) == Some(w[1].start_height)
                    && w[0].geometry == w[1].geometry
            })
            && [100, 1000, 10000].contains(&self.m)
            && self.p == optimal_p(self.m)
    }
    pub fn validate(&self, bytes: &[u8]) -> Result<ValidatedFilter, FilterError> {
        if bytes.len() as u64 != self.bytes || sha(bytes) != self.filter_hash {
            return Err(FilterError::Encoding(
                "parent digest/length mismatch".into(),
            ));
        }
        let v = crate::validate::validate_parameters(bytes, LIMITS, self.m, self.p)?;
        if v.element_count() as u64 != self.elements {
            return Err(FilterError::Encoding("parent count mismatch".into()));
        }
        Ok(v)
    }
    pub fn build(&mut self, scripts: &BTreeSet<Vec<u8>>) -> Result<Vec<u8>, FilterError> {
        if ![100, 1000, 10000].contains(&self.m)
            || self.p != optimal_p(self.m)
            || scripts.len() as u64 > LIMITS.max_elements
        {
            return Err(FilterError::Encoding(
                "invalid experimental parent parameters/size".into(),
            ));
        }
        let keys = self.keys()?;
        let mut bytes = Vec::new();
        let mut writer = GcsFilterWriter::new(&mut bytes, keys.k0, keys.k1, self.m, self.p);
        for s in scripts {
            writer.add_element(s);
        }
        writer
            .finish()
            .map_err(|e| FilterError::Encoding(e.to_string()))?;
        self.elements = scripts.len() as u64;
        self.bytes = bytes.len() as u64;
        self.filter_hash = sha(&bytes);
        self.validate(&bytes)?;
        Ok(bytes)
    }
    pub fn matches(
        &self,
        filter: &ValidatedFilter,
        scripts: &[Vec<u8>],
    ) -> Result<bool, FilterError> {
        let owned: Vec<_> = scripts.iter().cloned().map(ScriptBytes::new).collect();
        Ok(
            crate::matching::map_wallet_scripts_keyed(filter, self.keys()?, &owned)
                .iter()
                .any(|(v, _)| filter.values().binary_search(v).is_ok()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parent(m: u64) -> Parent {
        Parent {
            genesis_hash: "00".repeat(32),
            profile: crate::RANGE_PROFILE.into(),
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
            assert!(p
                .matches(&valid, &scripts.iter().cloned().collect::<Vec<_>>())
                .unwrap());
            let keys = p.keys().unwrap();
            let reader = bitcoin::bip158::GcsFilterReader::new(keys.k0, keys.k1, m, p.p);
            assert!(reader
                .match_all(&mut bytes.as_slice(), scripts.iter().map(Vec::as_slice))
                .unwrap());
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
        assert!(crate::validate::validate_parameters(&[0], LIMITS, 0, 9).is_err());
        assert!(crate::validate::validate_parameters(&[0], LIMITS, 1000, 64).is_err());
    }
}
