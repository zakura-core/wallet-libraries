//! The errors and size limits Receiver PIR sessions share across the client, the
//! evaluator and publishers; the sessions themselves are [`super::Session`]s.

/// Request header length: the format's magic, the session ID and a fresh nonce.
pub const HEADER_BYTES: usize = 52;
/// Bound on a serialized segment publication or inventory head, read before parsing. A
/// publication over it in compact JSON is invalid (see [`super::Publication::validate`]), so
/// no server can publish one.
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
    /// The configured server base is not a supported HTTP(S) endpoint, or an
    /// operation would leave the receiver route namespace below it.
    #[cfg(feature = "http-endpoint")]
    #[error("invalid receiver PIR server endpoint: {0}")]
    Endpoint(#[from] crate::endpoint::InvalidEndpoint),
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
