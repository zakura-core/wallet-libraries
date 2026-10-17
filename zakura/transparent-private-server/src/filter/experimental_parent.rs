//! Building an experimental parent filter over its children's scripts; see
//! [`zakura_transparent_private_shared::filter::experimental_parent`].

use std::collections::BTreeSet;

use bitcoin::bip158::GcsFilterWriter;
use zakura_transparent_private_shared::filter::experimental_parent::{
    optimal_p, sha, Parent, LIMITS,
};
use zakura_transparent_private_shared::filter::FilterError;

/// Building a [`Parent`]'s filter.
pub trait ParentBuild {
    /// Builds the filter over `scripts` and records its digest, length and
    /// element count in the parent.
    fn build(&mut self, scripts: &BTreeSet<Vec<u8>>) -> Result<Vec<u8>, FilterError>;
}

impl ParentBuild for Parent {
    fn build(&mut self, scripts: &BTreeSet<Vec<u8>>) -> Result<Vec<u8>, FilterError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_parent_is_canonical() {
        let mut p = Parent {
            genesis_hash: "00".repeat(32),
            profile: zakura_transparent_private_shared::filter::RANGE_PROFILE.into(),
            m: 1000,
            p: optimal_p(1000),
            children: vec![],
            filter_hash: String::new(),
            bytes: 0,
            elements: 0,
        };
        assert_eq!(p.build(&BTreeSet::new()).unwrap(), vec![0]);
    }
}
