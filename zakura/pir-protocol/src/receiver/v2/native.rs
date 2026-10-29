//! The v2 PIR profile: P8 tables, their public query masks, packing setups and
//! exact message sizes.
use super::{
    DIRECTORY_ROWS, Error, Hash, Kind, MAX_COMPANION_ROWS, QUERY_BLOCK_ROWS, ROW_BYTES, SCHEMA,
};
use crate::native::{NativeSetup, P8};
use crate::receiver::session::HEADER_BYTES;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Plaintext coefficients per row: two 2,048-coefficient packing blocks.
pub const COLS: usize = ROW_BYTES / P8.entry_bytes();
/// Leading bytes of every v2 request header, which responses echo.
pub const MAGIC: &[u8; 4] = b"RPQ2";

/// The public query masks and packing setup for one table kind and row count.
pub struct Profile {
    pub rows: usize,
    pub masks: Vec<Vec<u64>>,
    pub setup: NativeSetup,
}

/// Refuses a row count `kind` is never served at: a directory has exactly
/// [`DIRECTORY_ROWS`], a companion whole query blocks up to the policy limit.
fn validate_rows(kind: Kind, rows: u32) -> Result<(), Error> {
    match kind {
        Kind::Directory if rows == DIRECTORY_ROWS => Ok(()),
        Kind::Directory => Err(Error::Unsupported),
        Kind::Companion => super::validate_companion_rows(rows),
    }
}

/// The profile for `kind` at `rows`, derived once. Its seeds depend only on the
/// schema, the table kind and the row count, so every publication of a shape
/// shares them. A trimmed query uses a prefix of these masks.
pub fn profile(kind: Kind, rows: u32) -> Result<&'static Profile, Error> {
    validate_rows(kind, rows)?;
    const COUNT: usize = (MAX_COMPANION_ROWS / QUERY_BLOCK_ROWS) as usize + 1;
    static PROFILES: [OnceLock<Profile>; COUNT] = [const { OnceLock::new() }; COUNT];
    let index = match kind {
        Kind::Directory => 0,
        Kind::Companion => (rows / QUERY_BLOCK_ROWS) as usize,
    };
    Ok(PROFILES[index].get_or_init(|| {
        let seed = |purpose: &[u8]| -> Hash {
            Sha256::new()
                .chain_update(SCHEMA)
                .chain_update(b"/native-p8/")
                .chain_update(purpose)
                .chain_update(b"\0")
                .chain_update(kind.label())
                .chain_update(b"\0")
                .chain_update(rows.to_le_bytes())
                .finalize()
                .into()
        };
        Profile {
            rows: rows as usize,
            masks: P8
                .public_query_masks(seed(b"query-masks"), rows as usize, COLS)
                .expect("supported receiver v2 geometry"),
            setup: NativeSetup::new(P8.params(), seed(b"packing-setup")),
        }
    }))
}

/// Exact public setup length of either table.
pub fn public_bytes() -> usize {
    P8.public_len(COLS)
}

/// Exact request length, header included, for a query over `rows` rows: a
/// table's full rows, or a companion's `query_rows`.
pub fn query_bytes(rows: u32) -> usize {
    HEADER_BYTES + P8.request_len_bits(rows as usize, P8.dithered_bits)
}

/// Exact response length, header included, of either table.
pub fn response_bytes() -> usize {
    HEADER_BYTES + P8.response_len(COLS)
}
