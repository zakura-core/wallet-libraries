//! Strict decoding of a downloaded filter, before any result is used.
//!
//! This deliberately does not use the upstream reader's `match_any`. That API
//! returns as soon as it finds a match, so a filter whose head is well formed
//! and whose tail is garbage can yield a positive answer without the tail ever
//! being examined. A wallet that used such an answer to *advance coverage*
//! would be trusting bytes it never validated. Here the whole stream is decoded
//! and checked first, and matching runs against the decoded set.

use crate::error::FilterError;
use crate::profile::{M, P};

/// Caps applied before allocation and during decoding.
///
/// These are application limits, distinct from what the format permits. An
/// input that exceeds one is reported as an unsupported or incomplete update,
/// never as a negative match, so raising a cap can never turn a "no activity"
/// answer into a different one.
#[derive(Clone, Copy, Debug)]
pub struct FilterLimits {
    /// Maximum serialized filter size in bytes.
    pub max_bytes: usize,
    /// Maximum encoded element count.
    pub max_elements: u64,
}

impl FilterLimits {
    /// Limits sized for valid Zcash mainnet blocks.
    ///
    /// A Zcash block is capped at 2 MiB by consensus. Every filter element is a
    /// script that must appear in, or be spent by, that block, and the smallest
    /// script that can occupy an output is a few bytes, so the element count
    /// cannot approach `MAX_ELEMENTS` for any real block; the cap exists to
    /// bound a malicious count field before it is used for allocation, not to
    /// describe a typical block. Filter bytes are far smaller than the block
    /// they describe, so `max_bytes` is set at the block size limit rather than
    /// guessed from an observed median.
    pub const ZCASH_MAINNET: Self = Self {
        max_bytes: 2 * 1024 * 1024,
        max_elements: 1_000_000,
    };
}

impl Default for FilterLimits {
    fn default() -> Self {
        Self::ZCASH_MAINNET
    }
}

/// A filter whose entire byte stream has been decoded and checked.
///
/// Holding this type is the evidence that validation happened. Matching takes
/// it by reference so a caller cannot match against unvalidated bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedFilter {
    bytes: Vec<u8>,
    /// Decoded values, strictly ascending, each in `[0, n * M)`.
    values: Vec<u64>,
    range: u64,
}

impl ValidatedFilter {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn element_count(&self) -> usize {
        self.values.len()
    }
    pub fn values(&self) -> &[u64] {
        &self.values
    }
    /// The exclusive upper bound of the mapped range, `n * M`.
    pub fn range(&self) -> u64 {
        self.range
    }
}

/// Reads a big-endian bit stream, tracking whether the tail is zero padding.
struct BitReader<'a> {
    bytes: &'a [u8],
    bit: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit: 0 }
    }

    fn read_bit(&mut self) -> Result<u8, FilterError> {
        let byte = self
            .bytes
            .get(self.bit / 8)
            .ok_or_else(|| FilterError::Truncated("bit stream ended mid-value".into()))?;
        let value = (byte >> (7 - (self.bit % 8))) & 1;
        self.bit += 1;
        Ok(value)
    }

    fn read_bits(&mut self, count: u8) -> Result<u64, FilterError> {
        let mut value = 0u64;
        for _ in 0..count {
            value = (value << 1) | u64::from(self.read_bit()?);
        }
        Ok(value)
    }

    /// Consumed bytes, rounded up to the byte the reader stopped inside.
    fn consumed_bytes(&self) -> usize {
        self.bit.div_ceil(8)
    }

    /// Checks that the bits between the stop position and the end of that byte
    /// are zero.
    fn padding_is_zero(&self) -> Result<(), FilterError> {
        let remainder = self.bit % 8;
        if remainder == 0 {
            return Ok(());
        }
        let byte = self.bytes[self.bit / 8];
        let mask = 0xffu8 >> remainder;
        if byte & mask != 0 {
            return Err(FilterError::NonZeroPadding);
        }
        Ok(())
    }
}

/// Reads a CompactSize integer, rejecting noncanonical encodings.
fn read_compact_size(bytes: &[u8]) -> Result<(u64, usize), FilterError> {
    let first = *bytes
        .first()
        .ok_or_else(|| FilterError::Truncated("filter is empty".into()))?;
    let need = |width: usize| -> Result<&[u8], FilterError> {
        bytes
            .get(1..1 + width)
            .ok_or_else(|| FilterError::Truncated("CompactSize is truncated".into()))
    };
    match first {
        0xfd => {
            let value = u64::from(u16::from_le_bytes(need(2)?.try_into().expect("2 bytes")));
            if value < 0xfd {
                return Err(FilterError::NotCanonical(
                    "CompactSize used a 3-byte encoding for a 1-byte value".into(),
                ));
            }
            Ok((value, 3))
        }
        0xfe => {
            let value = u64::from(u32::from_le_bytes(need(4)?.try_into().expect("4 bytes")));
            if value <= 0xffff {
                return Err(FilterError::NotCanonical(
                    "CompactSize used a 5-byte encoding for a shorter value".into(),
                ));
            }
            Ok((value, 5))
        }
        0xff => {
            let value = u64::from_le_bytes(need(8)?.try_into().expect("8 bytes"));
            if value <= 0xffff_ffff {
                return Err(FilterError::NotCanonical(
                    "CompactSize used a 9-byte encoding for a shorter value".into(),
                ));
            }
            Ok((value, 9))
        }
        value => Ok((u64::from(value), 1)),
    }
}

/// Fully decodes and checks a serialized filter.
///
/// Every check runs before the result is usable, and the element count is
/// bounded before it is used to reserve memory, so a filter claiming an
/// enormous count cannot cause a large allocation.
pub fn validate_filter(bytes: &[u8], limits: FilterLimits) -> Result<ValidatedFilter, FilterError> {
    validate_parameters(bytes, limits, M, P)
}

/// Validates a range filter under the parameters of the profile it was
/// published with.
pub fn validate_range_filter(
    bytes: &[u8],
    limits: FilterLimits,
    profile: &crate::profile::RangeProfile,
) -> Result<ValidatedFilter, FilterError> {
    validate_parameters(bytes, limits, profile.m, profile.p)
}

/// Shared strict decoder; experimental profiles must keep their own parameter identity.
pub(crate) fn validate_parameters(
    bytes: &[u8],
    limits: FilterLimits,
    m: u64,
    p: u8,
) -> Result<ValidatedFilter, FilterError> {
    if m == 0 || m >= (1u64 << 32) || p > 31 {
        return Err(FilterError::Encoding("invalid GCS parameters".into()));
    }
    if bytes.len() > limits.max_bytes {
        return Err(FilterError::LimitExceeded(format!(
            "filter is {} bytes, limit is {}",
            bytes.len(),
            limits.max_bytes
        )));
    }

    let (count, header_len) = read_compact_size(bytes)?;
    if count > limits.max_elements {
        return Err(FilterError::LimitExceeded(format!(
            "filter claims {count} elements, limit is {}",
            limits.max_elements
        )));
    }
    // The count cannot exceed the bits available to encode it: every value
    // costs at least P + 1 bits, so this rejects a huge count against a short
    // body before any allocation.
    let body = &bytes[header_len..];
    let minimum_bits = count
        .checked_mul(u64::from(p) + 1)
        .ok_or_else(|| FilterError::LimitExceeded("element count overflows".into()))?;
    if minimum_bits > (body.len() as u64).saturating_mul(8) {
        return Err(FilterError::Truncated(format!(
            "filter claims {count} elements but has only {} body bytes",
            body.len()
        )));
    }

    if count == 0 {
        if !body.is_empty() {
            return Err(FilterError::TrailingBytes(body.len()));
        }
        return Ok(ValidatedFilter {
            bytes: bytes.to_vec(),
            values: Vec::new(),
            range: 0,
        });
    }

    let range = count
        .checked_mul(m)
        .ok_or_else(|| FilterError::LimitExceeded("mapped range overflows".into()))?;
    // Bounds the unary run: no legitimate quotient can exceed this, so a
    // malicious run of set bits terminates instead of spinning.
    let max_quotient = range >> p;

    let mut reader = BitReader::new(body);
    let mut values = Vec::with_capacity(count as usize);
    let mut last = 0u64;
    for index in 0..count {
        let mut quotient = 0u64;
        while reader.read_bit()? == 1 {
            quotient += 1;
            if quotient > max_quotient {
                return Err(FilterError::LimitExceeded(format!(
                    "unary run at element {index} exceeds the encodable range"
                )));
            }
        }
        let remainder = reader.read_bits(p)?;
        let delta = (quotient << p)
            .checked_add(remainder)
            .ok_or_else(|| FilterError::Encoding("delta overflows".into()))?;
        last = last
            .checked_add(delta)
            .ok_or_else(|| FilterError::Encoding("cumulative value overflows".into()))?;
        if last >= range {
            return Err(FilterError::Encoding(format!(
                "element {index} maps to {last}, outside the encoded range {range}"
            )));
        }
        values.push(last);
    }

    reader.padding_is_zero()?;
    let consumed = reader.consumed_bytes();
    if consumed < body.len() {
        return Err(FilterError::TrailingBytes(body.len() - consumed));
    }

    Ok(ValidatedFilter {
        bytes: bytes.to_vec(),
        values,
        range,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_filter::build_filter;
    use crate::hash::BlockHash;
    use crate::script::ScriptBytes;

    fn hash() -> BlockHash {
        BlockHash::from_internal_bytes([3u8; 32])
    }

    fn sample() -> Vec<u8> {
        let elements: Vec<_> = (0u8..20)
            .map(|index| ScriptBytes::new(vec![0x76, 0xa9, index]))
            .collect();
        build_filter(hash(), &elements).unwrap().0
    }

    #[test]
    fn a_built_filter_validates_and_reports_its_count() {
        let validated = validate_filter(&sample(), FilterLimits::default()).unwrap();
        assert_eq!(validated.element_count(), 20);
        assert!(validated.values().windows(2).all(|pair| pair[0] < pair[1]));
        assert!(validated
            .values()
            .iter()
            .all(|value| *value < validated.range()));
    }

    #[test]
    fn the_empty_filter_validates_to_no_elements() {
        let validated = validate_filter(&[0x00], FilterLimits::default()).unwrap();
        assert_eq!(validated.element_count(), 0);
        assert_eq!(validated.range(), 0);
    }

    #[test]
    fn an_empty_filter_with_trailing_bytes_is_rejected() {
        assert_eq!(
            validate_filter(&[0x00, 0x00], FilterLimits::default()),
            Err(FilterError::TrailingBytes(1))
        );
    }

    #[test]
    fn empty_input_is_truncated_not_empty() {
        assert!(matches!(
            validate_filter(&[], FilterLimits::default()),
            Err(FilterError::Truncated(_))
        ));
    }

    #[test]
    fn truncated_bit_streams_are_rejected() {
        let bytes = sample();
        for cut in 1..bytes.len() {
            assert!(
                validate_filter(&bytes[..cut], FilterLimits::default()).is_err(),
                "prefix of {cut} bytes validated"
            );
        }
    }

    #[test]
    fn trailing_bytes_after_a_valid_stream_are_rejected() {
        let mut bytes = sample();
        bytes.push(0x00);
        assert!(matches!(
            validate_filter(&bytes, FilterLimits::default()),
            Err(FilterError::TrailingBytes(1))
        ));
    }

    #[test]
    fn nonzero_padding_is_rejected() {
        let mut bytes = sample();
        // The final byte holds the tail of the last value plus zero padding.
        // Any set bit in the padding must be refused; find one that is padding
        // by confirming the unmodified filter is valid and the modified one is
        // rejected for padding specifically.
        let last = bytes.len() - 1;
        let original = bytes[last];
        let mut saw_padding_error = false;
        for bit in 0..8 {
            bytes[last] = original | (1 << bit);
            if bytes[last] == original {
                continue;
            }
            if matches!(
                validate_filter(&bytes, FilterLimits::default()),
                Err(FilterError::NonZeroPadding)
            ) {
                saw_padding_error = true;
            }
        }
        assert!(saw_padding_error, "no padding bit was checked");
    }

    #[test]
    fn noncanonical_compact_size_is_rejected() {
        for encoding in [
            vec![0xfd, 0x01, 0x00],
            vec![0xfe, 0x01, 0x00, 0x00, 0x00],
            vec![0xff, 0x01, 0, 0, 0, 0, 0, 0, 0],
        ] {
            assert!(matches!(
                validate_filter(&encoding, FilterLimits::default()),
                Err(FilterError::NotCanonical(_))
            ));
        }
    }

    #[test]
    fn truncated_compact_size_is_rejected() {
        assert!(matches!(
            validate_filter(&[0xfd, 0x01], FilterLimits::default()),
            Err(FilterError::Truncated(_))
        ));
    }

    #[test]
    fn a_huge_count_is_refused_before_allocation() {
        // 0xffffffffffffffff elements against an empty body.
        let bytes = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert!(matches!(
            validate_filter(&bytes, FilterLimits::default()),
            Err(FilterError::LimitExceeded(_))
        ));
    }

    #[test]
    fn a_count_larger_than_the_body_can_encode_is_refused() {
        let mut bytes = vec![0xfd, 0x00, 0x10]; // 4096 elements
        bytes.extend_from_slice(&[0x00; 8]);
        assert!(matches!(
            validate_filter(&bytes, FilterLimits::default()),
            Err(FilterError::Truncated(_))
        ));
    }

    #[test]
    fn a_long_unary_run_terminates_instead_of_spinning() {
        // One claimed element followed by all-ones: the quotient bound stops it.
        let mut bytes = vec![0x01];
        bytes.extend_from_slice(&[0xff; 4096]);
        assert!(matches!(
            validate_filter(&bytes, FilterLimits::default()),
            Err(FilterError::LimitExceeded(_))
        ));
    }

    #[test]
    fn oversize_filters_are_refused_by_byte_limit() {
        let limits = FilterLimits {
            max_bytes: 4,
            max_elements: 10,
        };
        assert!(matches!(
            validate_filter(&[0u8; 5], limits),
            Err(FilterError::LimitExceeded(_))
        ));
    }

    #[test]
    fn an_exceeded_element_cap_is_reported_as_a_limit_not_a_match() {
        let limits = FilterLimits {
            max_bytes: 1024,
            max_elements: 2,
        };
        let error = validate_filter(&sample(), limits).unwrap_err();
        assert!(matches!(error, FilterError::LimitExceeded(_)));
    }
}
