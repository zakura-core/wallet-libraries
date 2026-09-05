//! Errors the engine can return.

use std::fmt;

use zakura_wallet_scan::ScanError;
use zakura_wallet_store::TreeError;

use crate::source::SourceError;

/// A failure during synchronisation.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The chain source failed.
    Source(SourceError),
    /// Storage failed.
    Store(TreeError),
    /// A batch could not be interpreted, and rewinding did not help.
    ///
    /// The engine rewinds and retries on a continuity error, doubling the
    /// depth each time. This is what it returns once that has been exhausted:
    /// either the source is inconsistent, or the wallet needs a full rescan
    /// from its birthday, which is a decision for the caller rather than the
    /// engine.
    Unrecoverable {
        /// The scan error that could not be recovered from.
        cause: ScanError,
        /// How far the engine rewound before giving up.
        rewound_by: u32,
    },
    /// The source could not supply the chain state a range needed to start
    /// from.
    ///
    /// Every range must be anchored on the block below it: note positions are
    /// offsets into trees whose size at that block must be known. A source that
    /// has pruned that far back cannot serve this wallet.
    MissingAnchor {
        /// The height whose chain state was needed.
        height: zcash_protocol::consensus::BlockHeight,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Source(e) => write!(f, "{e}"),
            Error::Store(e) => write!(f, "{e}"),
            Error::Unrecoverable { cause, rewound_by } => write!(
                f,
                "scanning failed after rewinding {rewound_by} blocks: {cause}"
            ),
            Error::MissingAnchor { height } => write!(
                f,
                "the source could not supply the chain state at height {height}, \
                 which is needed to anchor the range above it"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Source(e) => Some(e),
            Error::Store(e) => Some(e),
            Error::Unrecoverable { cause, .. } => Some(cause),
            Error::MissingAnchor { .. } => None,
        }
    }
}

impl From<TreeError> for Error {
    fn from(e: TreeError) -> Self {
        Error::Store(e)
    }
}

impl From<zakura_wallet_store::Error> for Error {
    fn from(e: zakura_wallet_store::Error) -> Self {
        Error::Store(TreeError::Store(e))
    }
}
