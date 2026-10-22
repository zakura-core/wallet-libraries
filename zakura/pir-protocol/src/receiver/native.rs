//! The receiver PIR profile: public query masks, packing setup and exact message sizes.
use super::{
    Hash,
    session::{Error, HEADER_BYTES, MAX_ROWS, MIN_ROWS, PROTOCOL, validate_rows},
    snapshot,
};
use crate::native::{D, NativeSetup};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Plaintext coefficients per row: a row is exactly one packing block.
pub const COLS: usize = snapshot::ROW_BYTES / 2;
const _: () = assert!(COLS == D);

/// The public query masks and packing setup for `rows`-row publications.
pub struct Profile {
    pub rows: usize,
    pub masks: Vec<Vec<u64>>,
    pub setup: NativeSetup,
}

/// The profile for a directory of `rows` rows, derived once per size. Its seeds depend
/// only on the protocol and the row count, so every publication of a size shares them,
/// as Transparent's tables do.
pub fn profile(rows: u32) -> Result<&'static Profile, Error> {
    validate_rows(rows)?;
    const COUNT: usize = (MAX_ROWS / MIN_ROWS).ilog2() as usize + 1;
    static PROFILES: [OnceLock<Profile>; COUNT] = [const { OnceLock::new() }; COUNT];
    Ok(
        PROFILES[(rows / MIN_ROWS).ilog2() as usize].get_or_init(|| {
            let seed = |purpose: &[u8]| -> Hash {
                Sha256::new()
                    .chain_update(PROTOCOL)
                    .chain_update(b"/")
                    .chain_update(purpose)
                    .chain_update(b"\0")
                    .chain_update(rows.to_le_bytes())
                    .finalize()
                    .into()
            };
            Profile {
                rows: rows as usize,
                masks: crate::native::P16
                    .public_query_masks(seed(b"query-masks"), rows as usize, COLS)
                    .expect("supported receiver PIR geometry"),
                setup: NativeSetup::new(crate::native::params(), seed(b"packing-setup")),
            }
        }),
    )
}

/// Exact public setup length for a supported publication.
pub fn public_bytes(rows: u32) -> Result<usize, Error> {
    validate_rows(rows)?;
    Ok(crate::native::public_len(COLS))
}

/// Exact request length, including the session header and packing key.
pub fn query_bytes(rows: u32) -> Result<usize, Error> {
    validate_rows(rows)?;
    Ok(HEADER_BYTES + crate::native::request_len(rows as usize))
}

/// Exact response length for a supported publication.
pub fn response_bytes(rows: u32) -> Result<usize, Error> {
    validate_rows(rows)?;
    Ok(HEADER_BYTES + crate::native::response_len(COLS))
}
