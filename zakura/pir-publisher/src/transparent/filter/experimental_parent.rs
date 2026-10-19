//! Experimental parent filter publisher operations.
use std::collections::BTreeSet;
use zakura_pir_protocol::transparent::filter::FilterError;
pub use zakura_pir_protocol::transparent::filter::experimental_parent::*;
use zakura_pir_protocol::transparent::filter::gcs::GcsFilterWriter;
/// Operations specific to the publisher role.
pub trait ParentPublisherExt {
    fn build(&mut self, scripts: &BTreeSet<Vec<u8>>) -> Result<Vec<u8>, FilterError>;
}
impl ParentPublisherExt for Parent {
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
