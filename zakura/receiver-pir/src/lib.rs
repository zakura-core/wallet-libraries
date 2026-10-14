//! Encrypted row retrieval. Results are candidates for wallet validation, not chain proofs.
mod client;
#[cfg(feature = "server")]
pub mod server;
pub mod transport;

pub use client::{Client, Query};
use pir_native::profile::{D, NativeSetup};
use receiver_directory::Record;
use receiver_directory::{Hash, snapshot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// The session protocol: the shared `pir-native` two-mask profile, one row per
/// 2,048-coefficient packing block.
pub const PROTOCOL: &str = "ironwood-receiver-pir-v1-two-mask-m29";
pub use receiver_directory::snapshot::{MAX_ROWS, MIN_ROWS};
/// Request header length: [`MAGIC`], the session ID and a fresh nonce.
pub const HEADER_BYTES: usize = 52;
/// Leading bytes of every request header, which responses echo.
pub const MAGIC: &[u8; 4] = b"RPQ1";
/// Bound on a serialized directory or session manifest, read before parsing. A
/// session manifest over it, in the compact JSON that `/v1/receiver/init` serves, is
/// invalid (see [`Manifest::validate`]), so no server can publish one.
pub const MAX_MANIFEST_BYTES: usize = 16384;
/// Plaintext coefficients per row: a row is exactly one packing block.
const COLS: usize = snapshot::ROW_BYTES / 2;
const _: () = assert!(COLS == D);

/// Why a connection, lookup or evaluation failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Directory(#[from] receiver_directory::Error),
    #[error("unsupported receiver PIR protocol or geometry")]
    Unsupported,
    #[error("malformed receiver PIR message")]
    Malformed,
    #[error("receiver PIR operation failed")]
    Pir,
    #[error("receiver publication changed")]
    Revision,
    #[error("receiver transport failed: {0}")]
    Transport(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Both the directory and its PIR setup belong to one immutable session.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub protocol: String,
    pub directory: snapshot::Manifest,
    pub public_digest: Hash,
}

impl Manifest {
    /// Check the directory manifest, the protocol, the supported geometry and the
    /// serialized size, at most [`MAX_MANIFEST_BYTES`].
    pub fn validate(&self) -> Result<(), Error> {
        self.directory.validate()?;
        if self.protocol != PROTOCOL {
            return Err(Error::Unsupported);
        }
        validate_rows(self.directory.rows)?;
        if serde_json::to_vec(self)?.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// The session ID that pins every route and request to this manifest: a
    /// domain-separated SHA-256 of the protocol, the directory revision and the public
    /// setup digest.
    pub fn id(&self) -> Result<Hash, Error> {
        self.validate()?;
        let mut h = Sha256::new();
        h.update(b"ironwood-receiver-pir/v1/session\0");
        h.update((self.protocol.len() as u64).to_le_bytes());
        h.update(self.protocol.as_bytes());
        h.update(self.directory.revision()?);
        h.update(self.public_digest);
        Ok(h.finalize().into())
    }
}

/// Supply this from wallet chain validation, never by copying the directory manifest.
#[derive(Clone, Copy, Debug)]
pub struct AcceptedCoverage {
    pub genesis: Hash,
    pub required_start: u32,
    pub height: u32,
    pub hash: Hash,
}

impl AcceptedCoverage {
    /// Fail unless `m` ends at this anchor and covers the required history.
    pub fn check(&self, m: &snapshot::Manifest) -> Result<(), Error> {
        Ok(m.accept(self.genesis, self.required_start, self.height, self.hash)?)
    }
}

/// Validate the common publisher, server and client geometry contract.
pub fn validate_rows(rows: u32) -> Result<(), Error> {
    if !rows.is_power_of_two() || !(MIN_ROWS..=MAX_ROWS).contains(&rows) {
        return Err(Error::Unsupported);
    }
    Ok(())
}

/// The public query masks and packing setup for `rows`-row publications.
struct Profile {
    rows: usize,
    masks: Vec<Vec<u64>>,
    setup: NativeSetup,
}

/// The profile for a directory of `rows` rows, derived once per size. Its seeds depend
/// only on the protocol and the row count, so every publication of a size shares them,
/// as Transparent's tables do.
fn profile(rows: u32) -> Result<&'static Profile, Error> {
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
                masks: pir_native::profile::public_query_masks(
                    seed(b"query-masks"),
                    rows as usize,
                    COLS,
                )
                .expect("supported receiver PIR geometry"),
                setup: NativeSetup::new(pir_native::profile::params(), seed(b"packing-setup")),
            }
        }),
    )
}

/// Exact public setup length for a supported publication.
pub fn public_bytes(rows: u32) -> Result<usize, Error> {
    validate_rows(rows)?;
    Ok(pir_native::profile::public_len(COLS))
}

/// Exact request length, including the session header and packing key.
pub fn query_bytes(rows: u32) -> Result<usize, Error> {
    validate_rows(rows)?;
    Ok(HEADER_BYTES + pir_native::profile::request_len(rows as usize))
}

/// Exact response length for a supported publication.
pub fn response_bytes(rows: u32) -> Result<usize, Error> {
    validate_rows(rows)?;
    Ok(HEADER_BYTES + pir_native::profile::response_len(COLS))
}

/// Reject inconsistent continuation pages before exposing a complete history to a
/// wallet, by the rule publications are built and validated with
/// ([`snapshot::check_next`]).
fn check_next(previous: &Record, next: &Record) -> Result<(), Error> {
    snapshot::check_next(previous, next).map_err(|_| Error::Malformed)
}
