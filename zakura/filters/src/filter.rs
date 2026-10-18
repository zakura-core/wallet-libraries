// SPDX-License-Identifier: CC0-1.0
// Extracted from rust-bitcoin 0.32.102, src/bip158.rs (CC0-1.0).
// Upstream credits Tamas Blummer's murmel implementation, relicensed CC0.

use bitcoin_hashes::siphash24;
use bitcoin_io::{self as io, Write};
use std::{cmp, collections::BTreeSet};

use crate::{bits::BitStreamWriter, write_compact_size};

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
    /// Creates a writer with the supplied SipHash keys and GCS parameters.
    ///
    /// `m` must be nonzero and `p` at most 63. Invalid parameters are reported by
    /// [`Self::finish`] before writing any bytes.
    pub fn new(writer: &'a mut W, k0: u64, k1: u64, m: u64, p: u8) -> GcsFilterWriter<'a, W> {
        GcsFilterWriter {
            filter: GcsFilter::new(k0, k1, p),
            writer,
            elements: BTreeSet::new(),
            m,
        }
    }

    /// Adds raw bytes to the set, ignoring empty items and deduplicating equal bytes.
    pub fn add_element(&mut self, element: &[u8]) {
        if !element.is_empty() {
            self.elements.insert(element.to_vec());
        }
    }

    /// Writes a CompactSize count followed by Golomb-Rice coded sorted deltas.
    ///
    /// Returns the number of bytes written. Invalid parameters or an overflowing
    /// `count * m` return `InvalidInput`; write failures are propagated. A write
    /// failure may leave a partial filter in the destination.
    pub fn finish(&mut self) -> Result<usize, io::Error> {
        if self.m == 0 || self.filter.p > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid GCS parameters",
            ));
        }
        let nm = (self.elements.len() as u64)
            .checked_mul(self.m)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "GCS hash range overflows")
            })?;

        // map hashes to [0, n_elements * M)
        let mut mapped: Vec<_> = self
            .elements
            .iter()
            .map(|e| map_to_range(self.filter.hash(e.as_slice()), nm))
            .collect();
        mapped.sort_unstable();

        // write number of elements as varint
        let mut wrote = write_compact_size(self.writer, mapped.len() as u64)?;

        // write out deltas of sorted values into a Golomb-Rice coded bit stream
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
