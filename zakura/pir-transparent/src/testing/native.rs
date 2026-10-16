//! Real native PIR evaluation of one published table segment, for the
//! in-process fixtures: the hint, two-mask preprocessing, published masks and
//! packed responses come from the library's canonical native operations, and
//! the table is scanned with a plain scalar loop. No admission, metrics, disk
//! cache or runtime scheduling: a fixture answers one query at a time.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use transparent_native::{NativeKeys, NativePreprocessed, P8, Q, TableProfile};

/// A segment's plaintext, column-major, at the profile's coefficient width.
enum Columns {
    /// 16-bit coefficients: [`transparent_native::P16`].
    Wide(Vec<Vec<u16>>),
    /// 8-bit coefficients: [`P8`].
    Bytes(Vec<Vec<u8>>),
}

/// One segment of one table, preprocessed and ready to answer queries.
pub struct Segment {
    profile: Arc<TableProfile>,
    columns: Columns,
    blocks: Vec<NativePreprocessed>,
    public: Vec<u8>,
    epoch: [u8; 8],
    public_sha256: String,
}

impl Segment {
    /// Preprocesses the row-major `rows` of one segment under `profile`. Rows
    /// past the end of `rows` read as zero.
    pub fn build(profile: Arc<TableProfile>, rows: &[u8]) -> Result<Self, String> {
        let (count, row_bytes, cols) = (profile.rows, profile.row_bytes, profile.cols);
        if rows.len() > count * row_bytes {
            return Err("segment larger than its table".into());
        }
        let (columns, hint) = if profile.native == P8 {
            let columns: Vec<Vec<u8>> = (0..cols)
                .map(|col| {
                    (0..count)
                        .map(|row| rows.get(row * row_bytes + col).copied().unwrap_or(0))
                        .collect()
                })
                .collect();
            let hint = transparent_native::hint(&profile.masks, count, cols, |col| {
                columns[col].as_slice()
            })?;
            (Columns::Bytes(columns), hint)
        } else {
            let columns: Vec<Vec<u16>> = (0..cols)
                .map(|col| {
                    (0..count)
                        .map(|row| transparent_native::row_coefficient(rows, row_bytes, row, col))
                        .collect()
                })
                .collect();
            let hint = transparent_native::hint(&profile.masks, count, cols, |col| {
                columns[col].as_slice()
            })?;
            (Columns::Wide(columns), hint)
        };
        let blocks = transparent_native::preprocess(&profile.setup, &hint)?;
        let public = profile.native.publish(&blocks)?;
        let digest = Sha256::digest(&public);
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&digest[..8]);
        Ok(Self {
            profile,
            columns,
            blocks,
            public,
            epoch,
            public_sha256: hex::encode(digest),
        })
    }

    /// The published two-mask material.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// Hex SHA-256 of [`Self::public`].
    pub fn public_sha256(&self) -> &str {
        &self.public_sha256
    }

    /// The first eight bytes of that digest: the epoch every answer carries.
    pub fn epoch(&self) -> [u8; 8] {
        self.epoch
    }

    /// The segment's reply to a parsed query: `binding`, the epoch, then the
    /// packed response body.
    pub fn answer(
        &self,
        binding: [u8; 8],
        keys: &NativeKeys,
        query: &[u64],
    ) -> Result<Vec<u8>, String> {
        if query.len() != self.profile.rows {
            return Err("query rows do not match the table".into());
        }
        fn scan<T: Copy + Into<u64>>(columns: &[Vec<T>], query: &[u64]) -> Vec<u64> {
            columns
                .iter()
                .map(|column| {
                    column.iter().zip(query).fold(0u64, |sum, (&x, &q)| {
                        sum.wrapping_add(x.into().wrapping_mul(q))
                    }) & (Q - 1)
                })
                .collect()
        }
        let intermediate = match &self.columns {
            Columns::Wide(columns) => scan(columns, query),
            Columns::Bytes(columns) => scan(columns, query),
        };
        let body = self.profile.native.pack(&self.blocks, keys, &intermediate)?;
        let mut reply = Vec::with_capacity(16 + body.len());
        reply.extend_from_slice(&binding);
        reply.extend_from_slice(&self.epoch);
        reply.extend_from_slice(&body);
        Ok(reply)
    }
}

/// Checks a query body's binding and length, then parses its key and
/// selection over every row or over only the first `query_rows`.
pub fn parse(
    profile: &TableProfile,
    binding: [u8; 8],
    body: &[u8],
    query_rows: usize,
) -> Result<(NativeKeys, Vec<u64>), String> {
    if body.get(..8) != Some(binding.as_slice()) {
        return Err("query does not name this revision and table".to_string());
    }
    if !profile.accepts_selection_len(query_rows, body.len() - 8) {
        return Err("query has the wrong fixed length".to_string());
    }
    profile.parse_selection(&body[8..], query_rows)
}
