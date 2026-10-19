pub use zakura_filters::GcsFilterWriter;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparent::filter::{FilterLimits, validate::validate_parameters};

    #[test]
    fn strict_decoder_still_rejects_truncation_trailing_bytes_and_bad_counts() {
        let mut bytes = Vec::new();
        let mut writer = GcsFilterWriter::new(&mut bytes, 3, 5, 100, 6);
        for value in 0u32..64 {
            writer.add_element(&value.to_le_bytes());
        }
        writer.finish().unwrap();
        let limits = FilterLimits::default();
        assert!(validate_parameters(&bytes, limits, 100, 6).is_ok());
        for end in 0..bytes.len() {
            assert!(validate_parameters(&bytes[..end], limits, 100, 6).is_err());
        }
        bytes.push(0);
        assert!(validate_parameters(&bytes, limits, 100, 6).is_err());
        for bad in [&[0xfd, 1, 0][..], &[0xff; 9][..]] {
            assert!(validate_parameters(bad, limits, 100, 6).is_err());
        }
    }
}
