//! What a transparent run can fail with.

use std::fmt;

/// A failure during private transparent recovery.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A transport could not deliver.
    Transport(String),
    /// The service answered, and the answer could not be believed.
    ///
    /// Distinct from a transport failure on purpose. A wallet retries the
    /// first; the second means the service and this build disagree about what
    /// the bytes mean, and retrying would only produce the same wrong answer.
    Invalid(String),
    /// The service serves a schema this build does not read.
    Schema {
        /// What the service said it serves.
        served: String,
        /// What this build reads.
        expected: &'static str,
    },
    /// The recovery itself failed.
    Sync(String),
    /// Storage failed.
    Store(zakura_wallet_store::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport(why) => write!(f, "transparent transport: {why}"),
            Error::Invalid(why) => write!(f, "the transparent service answered badly: {why}"),
            Error::Schema { served, expected } => write!(
                f,
                "the transparent service serves schema {served}, and this build \
                 reads {expected}; a row's meaning is entirely a function of its \
                 schema, so decoding it anyway would produce a plausible, wrong \
                 history"
            ),
            Error::Sync(why) => write!(f, "transparent recovery: {why}"),
            Error::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<zakura_wallet_store::Error> for Error {
    fn from(e: zakura_wallet_store::Error) -> Self {
        Error::Store(e)
    }
}

impl From<transparent_wallet::SyncError> for Error {
    fn from(e: transparent_wallet::SyncError) -> Self {
        use transparent_wallet::SyncError;
        match e {
            SyncError::Schema { served, expected } => Error::Schema { served, expected },
            SyncError::Transport(why) => Error::Transport(why),
            // Everything else means the service, the map, the manifest or the
            // store disagree with each other or with this build. The library
            // says which, and a retry would say it again.
            other => Error::Sync(other.to_string()),
        }
    }
}
