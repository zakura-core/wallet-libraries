// SPDX-License-Identifier: CC0-1.0
// Extracted from rust-bitcoin 0.32.102, src/bip158.rs (CC0-1.0).
// That module credits Tamas Blummer's murmel implementation, relicensed CC0.
// Only the GCS writer and its bit writer are retained. CompactSize encoding
// delegates to our existing envelope encoder; SipHash remains bitcoin_hashes.
// Keep the exact bytes: tests compare against the pinned upstream codec.

use bitcoin_hashes::siphash24;
use bitcoin_io::{self as io, Write};
use std::{cmp, collections::BTreeSet};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{validate::validate_parameters, FilterLimits};

    #[test]
    fn extracted_writer_matches_upstream_across_counts_keys_and_precisions() {
        for count in [0, 1, 2, 252, 253, 254, 1000] {
            let mut elements: Vec<_> = (0..count as u32)
                .map(|i| i.to_le_bytes().to_vec())
                .collect();
            // Both writers ignore empty elements and deduplicate before hashing.
            elements.push(Vec::new());
            elements.extend(elements.clone());
            for (k0, k1, m, p) in [
                (0, 0, 784931, 19),
                (u64::MAX, 1, 100, 6),
                (17, 89, 10000, 13),
            ] {
                let mut actual = Vec::new();
                let mut expected = Vec::new();
                let mut writer = GcsFilterWriter::new(&mut actual, k0, k1, m, p);
                let mut upstream =
                    bitcoin::bip158::GcsFilterWriter::new(&mut expected, k0, k1, m, p);
                for element in &elements {
                    writer.add_element(element);
                    upstream.add_element(element);
                }
                assert_eq!(writer.finish().unwrap(), upstream.finish().unwrap());
                assert_eq!(actual, expected, "count={count}, m={m}, p={p}");
                let query = elements.iter().filter(|e| !e.is_empty()).map(Vec::as_slice);
                assert!(bitcoin::bip158::GcsFilterReader::new(k0, k1, m, p)
                    .match_all(&mut actual.as_slice(), query)
                    .unwrap());
            }
        }
    }

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

/// Fast reduction of hash to [0, nm) range.
fn map_to_range(hash: u64, nm: u64) -> u64 {
    ((hash as u128 * nm as u128) >> 64) as u64
}

/// Golomb-Rice encoded filter writer.
pub struct GcsFilterWriter<'a, W> {
    filter: GcsFilter,
    writer: &'a mut W,
    elements: BTreeSet<Vec<u8>>,
    m: u64,
}

impl<'a, W: Write> GcsFilterWriter<'a, W> {
    /// Creates a new [`GcsFilterWriter`] wrapping a generic writer, with specific seed to siphash.
    pub fn new(writer: &'a mut W, k0: u64, k1: u64, m: u64, p: u8) -> GcsFilterWriter<'a, W> {
        GcsFilterWriter {
            filter: GcsFilter::new(k0, k1, p),
            writer,
            elements: BTreeSet::new(),
            m,
        }
    }

    /// Adds data to the filter.
    pub fn add_element(&mut self, element: &[u8]) {
        if !element.is_empty() {
            self.elements.insert(element.to_vec());
        }
    }

    /// Writes the filter to the wrapped writer.
    pub fn finish(&mut self) -> Result<usize, io::Error> {
        let nm = self.elements.len() as u64 * self.m;

        // map hashes to [0, n_elements * M)
        let mut mapped: Vec<_> = self
            .elements
            .iter()
            .map(|e| map_to_range(self.filter.hash(e.as_slice()), nm))
            .collect();
        mapped.sort_unstable();

        // write number of elements as varint
        let mut count = Vec::new();
        crate::envelope::write_compact_size(&mut count, mapped.len() as u64);
        self.writer.write_all(&count)?;
        let mut wrote = count.len();

        // write out deltas of sorted values into a Golonb-Rice coded bit stream
        let mut writer = BitStreamWriter::new(self.writer);
        let mut last = 0;
        for data in mapped {
            wrote += self.filter.golomb_rice_encode(&mut writer, data - last)?;
            last = data;
        }
        wrote += writer.flush()?;
        Ok(wrote)
    }
}

/// Golomb Coded Set Filter.
struct GcsFilter {
    k0: u64, // sip hash key
    k1: u64, // sip hash key
    p: u8,
}

impl GcsFilter {
    /// Creates a new [`GcsFilter`].
    fn new(k0: u64, k1: u64, p: u8) -> GcsFilter {
        GcsFilter { k0, k1, p }
    }

    /// Golomb-Rice encodes a number `n` to a bit stream (parameter 2^k).
    fn golomb_rice_encode<W>(
        &self,
        writer: &mut BitStreamWriter<'_, W>,
        n: u64,
    ) -> Result<usize, io::Error>
    where
        W: Write,
    {
        let mut wrote = 0;
        let mut q = n >> self.p;
        while q > 0 {
            let nbits = cmp::min(q, 64);
            wrote += writer.write(!0u64, nbits as u8)?;
            q -= nbits;
        }
        wrote += writer.write(0, 1)?;
        wrote += writer.write(n, self.p)?;
        Ok(wrote)
    }

    /// Hashes an arbitrary slice with siphash using parameters of this filter.
    fn hash(&self, element: &[u8]) -> u64 {
        siphash24::Hash::hash_to_u64_with_keys(self.k0, self.k1, element)
    }
}

/// Bitwise stream writer.
pub struct BitStreamWriter<'a, W> {
    buffer: [u8; 1],
    offset: u8,
    writer: &'a mut W,
}

impl<'a, W: Write> BitStreamWriter<'a, W> {
    /// Creates a new [`BitStreamWriter`] that writes bitwise to a given `writer`.
    pub fn new(writer: &'a mut W) -> BitStreamWriter<'a, W> {
        BitStreamWriter {
            buffer: [0u8],
            writer,
            offset: 0,
        }
    }

    /// Writes nbits bits from data.
    pub fn write(&mut self, data: u64, mut nbits: u8) -> Result<usize, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "can not write more than 64 bits at once",
            ));
        }
        let mut wrote = 0;
        while nbits > 0 {
            let bits = cmp::min(8 - self.offset, nbits);
            self.buffer[0] |= ((data << (64 - nbits)) >> (64 - 8 + self.offset)) as u8;
            self.offset += bits;
            nbits -= bits;
            if self.offset == 8 {
                wrote += self.flush()?;
            }
        }
        Ok(wrote)
    }

    /// flush bits not yet written.
    pub fn flush(&mut self) -> Result<usize, io::Error> {
        if self.offset > 0 {
            self.writer.write_all(&self.buffer)?;
            self.buffer[0] = 0u8;
            self.offset = 0;
            Ok(1)
        } else {
            Ok(0)
        }
    }
}
