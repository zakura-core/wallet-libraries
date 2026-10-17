//! The server's half of Transparent's native profiles: admitting and parsing
//! uploads to a table, sizing its preprocessed segments, and laying out its
//! coefficients. The profile itself, which both sides derive the same way, is
//! [`TableProfile`].

pub mod batched_hint;

use zakura_pir_native::PREPARED_HEADER_BYTES;
pub use zakura_pir_native::{NativeKeys, NativePreprocessed};
use zakura_transparent_private_shared::native::TableProfile;

/// Admission, parsing and sizing for a table's uploads and segments.
pub trait TableServe {
    /// Whether an upload of `len` bytes, after the binding, has one of the two
    /// lengths this table accepts.
    fn accepts_request_len(&self, len: usize) -> bool;

    /// Whether an upload of `len` bytes, after the binding, selects every row
    /// or only the first `query_rows` at an accepted width.
    fn accepts_selection_len(&self, query_rows: usize, len: usize) -> bool;

    /// Parses an upload of either scheme into its key and lifted selection.
    /// The width is the one the exact length names; any other length is
    /// refused.
    fn parse(&self, bytes: &[u8]) -> Result<(NativeKeys, Vec<u64>), String>;

    /// Parses an upload of either scheme over every row or over only the
    /// first `query_rows`, whichever its exact length names, zero-filled back
    /// to every row.
    fn parse_selection(
        &self,
        bytes: &[u8],
        query_rows: usize,
    ) -> Result<(NativeKeys, Vec<u64>), String>;

    /// Bytes one segment's database occupies: one coefficient per entry.
    fn database_bytes(&self) -> u64;

    /// Upper bound on one segment's `prepared_native` encoding.
    fn prepared_max_bytes(&self) -> u64;

    /// Lower bound on one segment's `prepared_native` encoding.
    fn prepared_min_bytes(&self) -> u64;

    /// What one segment's `prepared_native` encoding plans to take: four-byte
    /// words for a two-digit key, eight-byte words for a one-digit key.
    fn prepared_planned_bytes(&self) -> u64;
}

impl TableServe for TableProfile {
    fn accepts_request_len(&self, len: usize) -> bool {
        self.native.accepted_query_bits(self.rows, len).is_some()
    }

    fn accepts_selection_len(&self, query_rows: usize, len: usize) -> bool {
        self.native
            .accepted_query_shape(self.rows, query_rows, len)
            .is_some()
    }

    fn parse(&self, bytes: &[u8]) -> Result<(NativeKeys, Vec<u64>), String> {
        self.native.parse_accepted(&self.setup, bytes, self.rows)
    }

    fn parse_selection(
        &self,
        bytes: &[u8],
        query_rows: usize,
    ) -> Result<(NativeKeys, Vec<u64>), String> {
        self.native
            .parse_selection(&self.setup, bytes, query_rows, self.rows)
    }

    fn database_bytes(&self) -> u64 {
        self.rows as u64 * self.cols as u64 * self.native.entry_bytes() as u64
    }

    fn prepared_max_bytes(&self) -> u64 {
        PREPARED_HEADER_BYTES + self.blocks() as u64 * self.native.prepared_block_max_bytes()
    }

    fn prepared_min_bytes(&self) -> u64 {
        PREPARED_HEADER_BYTES + self.blocks() as u64 * self.native.prepared_block_min_bytes()
    }

    fn prepared_planned_bytes(&self) -> u64 {
        PREPARED_HEADER_BYTES + self.blocks() as u64 * self.native.prepared_block_planned_bytes()
    }
}

/// Column-major u16 coefficients of a row-major table: coefficient `c` of row
/// `r` is the little-endian u16 at byte `r * row_bytes + 2 * c`, exactly the
/// bytes a client decodes. Rows shorter than `row_bytes` (never in practice)
/// read as zero.
pub fn row_coefficient(rows: &[u8], row_bytes: usize, row: usize, col: usize) -> u16 {
    let at = row * row_bytes + 2 * col;
    match rows.get(at..at + 2) {
        Some(bytes) => u16::from_le_bytes([bytes[0], bytes[1]]),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_coefficients_match_the_bit_reader() {
        let rows: Vec<u8> = (0..2 * 4_096).map(|i| (i * 37 % 251) as u8).collect();
        for (row, col) in [(0, 0), (0, 2_047), (1, 5), (1, 2_047)] {
            assert_eq!(
                row_coefficient(&rows, 4_096, row, col) as u64,
                ipir_sp::bits::read_bits(&rows[row * 4_096..(row + 1) * 4_096], col * 16, 16)
            );
        }
    }

    #[test]
    fn a_history_table_segment_is_one_byte_per_entry() {
        for table in ["directory", "pages"] {
            let p = TableProfile::new("s", "g", table, 2_048, 4_096).unwrap();
            assert_eq!(p.database_bytes(), 2_048 * 4_096);
        }
    }
}
