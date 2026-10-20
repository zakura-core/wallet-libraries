//! Encrypted row retrieval. Results are candidates for wallet validation, not chain proofs:
//! records and witness payloads are returned as untrusted bytes, which the wallet checks
//! cryptographically before use.
mod client;
pub mod inventory;
#[cfg(feature = "server")]
pub mod server;
pub mod transport;

pub use client::{Client, Query, WitnessClient, WitnessQuery};
use receiver_directory::{snapshot, witness, Hash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use zakura_pir_client::native::{NativeSetup, D};

/// The session protocol: the shared `pir-native` two-mask profile, one row per
/// 2,048-coefficient packing block.
pub const PROTOCOL: &str = "ironwood-receiver-pir-v1-two-mask-m29";
pub use receiver_directory::snapshot::{MAX_ROWS, MIN_ROWS};
/// Request header length: [`MAGIC`], the session ID and a fresh nonce.
pub const HEADER_BYTES: usize = 52;
/// Leading bytes of every request header, which responses echo.
pub const MAGIC: &[u8; 4] = b"RPQ1";
/// Bound on a serialized session manifest, segment or inventory head, read before
/// parsing. A session manifest over it in compact JSON is invalid (see
/// [`Manifest::validate`]), so no server can publish one.
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

/// A companion witness table's session: its manifest and PIR setup digest. It shares the
/// payment session's protocol and geometry rules.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessManifest {
    pub protocol: String,
    pub table: witness::Manifest,
    pub public_digest: Hash,
}

impl WitnessManifest {
    /// Check the table manifest, the protocol and the supported geometry.
    pub fn validate(&self) -> Result<(), Error> {
        self.table.validate()?;
        if self.protocol != PROTOCOL {
            return Err(Error::Unsupported);
        }
        validate_rows(self.table.rows)
    }

    /// The session ID that pins witness requests to this table: a domain-separated
    /// SHA-256 of the protocol, the table revision and the public setup digest.
    pub fn id(&self) -> Result<Hash, Error> {
        self.validate()?;
        let mut h = Sha256::new();
        h.update(b"ironwood-receiver-pir/v1/witness-session\0");
        h.update((self.protocol.len() as u64).to_le_bytes());
        h.update(self.protocol.as_bytes());
        h.update(self.table.revision()?);
        h.update(self.public_digest);
        Ok(h.finalize().into())
    }
}

/// One segment: a payment session and the companion witness session bound to it, as an
/// inventory lists them.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub payments: Manifest,
    pub witnesses: WitnessManifest,
}

impl Publication {
    /// Checks both sessions, that the witness table serves exactly this payment table, and
    /// the serialized size, at most [`MAX_MANIFEST_BYTES`].
    pub fn validate(&self) -> Result<(), Error> {
        self.payments.validate()?;
        self.witnesses.validate()?;
        self.witnesses
            .table
            .check_payments(&self.payments.directory)?;
        if serde_json::to_vec(self)?.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Malformed);
        }
        Ok(())
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
                masks: zakura_pir_client::native::P16
                    .public_query_masks(seed(b"query-masks"), rows as usize, COLS)
                    .expect("supported receiver PIR geometry"),
                setup: NativeSetup::new(
                    zakura_pir_client::native::params(),
                    seed(b"packing-setup"),
                ),
            }
        }),
    )
}

/// Exact public setup length for a supported publication.
pub fn public_bytes(rows: u32) -> Result<usize, Error> {
    validate_rows(rows)?;
    Ok(zakura_pir_client::native::public_len(COLS))
}

/// Exact request length, including the session header and packing key.
pub fn query_bytes(rows: u32) -> Result<usize, Error> {
    validate_rows(rows)?;
    Ok(HEADER_BYTES + zakura_pir_client::native::request_len(rows as usize))
}

/// Exact response length for a supported publication.
pub fn response_bytes(rows: u32) -> Result<usize, Error> {
    validate_rows(rows)?;
    Ok(HEADER_BYTES + zakura_pir_client::native::response_len(COLS))
}
