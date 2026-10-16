//! Opt-in research profile. Parent negatives trust the same indexer as child
//! negatives; digests establish consistency, not chain completeness. Selective
//! child requests disclose coarse activity intervals to the filter origin.
use crate::filter::{
    FilterError, FilterKeys, FilterLimits, ShardMap, ShardMapEntry, ValidatedFilter,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
        let v = crate::filter::validate::validate_parameters(bytes, LIMITS, self.m, self.p)?;
        if v.element_count() as u64 != self.elements {
            return Err(FilterError::Encoding("parent count mismatch".into()));
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_separation() {
        let mut p = Parent {
            genesis_hash: "00".repeat(32),
            profile: crate::filter::RANGE_PROFILE.into(),
            m: 1000,
            p: optimal_p(1000),
            children: vec![],
            filter_hash: String::new(),
            bytes: 0,
            elements: 0,
        };
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
        assert!(crate::filter::validate::validate_parameters(&[0], LIMITS, 0, 9).is_err());
        assert!(crate::filter::validate::validate_parameters(&[0], LIMITS, 1000, 64).is_err());
    }
}
