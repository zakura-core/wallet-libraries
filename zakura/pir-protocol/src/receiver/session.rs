//! Receiver PIR sessions: manifests, their IDs, and the geometry and size limits shared
//! by the client, the evaluator and publishers.
use super::{Hash, snapshot, witness};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The session protocol: the shared `pir-native` two-mask profile, one row per
/// 2,048-coefficient packing block.
pub const PROTOCOL: &str = "ironwood-receiver-pir-v1-two-mask-m29";
pub use super::snapshot::{MAX_ROWS, MIN_ROWS};
/// Request header length: [`MAGIC`], the session ID and a fresh nonce.
pub const HEADER_BYTES: usize = 52;
/// Leading bytes of every request header, which responses echo.
pub const MAGIC: &[u8; 4] = b"RPQ1";
/// Bound on a serialized session manifest, segment or inventory head, read before
/// parsing. A session manifest over it in compact JSON is invalid (see
/// [`Manifest::validate`]), so no server can publish one.
pub const MAX_MANIFEST_BYTES: usize = 16384;

/// Why a connection, lookup or evaluation failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Directory(super::Error),
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

/// A directory format a newer client supports is [`Error::Unsupported`], as an
/// unsupported protocol is, so the host reaches one upgrade outcome either way.
impl From<super::Error> for Error {
    fn from(error: super::Error) -> Self {
        match error {
            super::Error::Unsupported => Error::Unsupported,
            other => Error::Directory(other),
        }
    }
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
