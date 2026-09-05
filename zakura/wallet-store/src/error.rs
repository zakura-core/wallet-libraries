//! Errors the store can return.

use std::fmt;

use zcash_protocol::consensus::BlockHeight;

/// A failure reading or writing wallet storage.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A SQL statement failed.
    Query(rusqlite::Error),

    /// Stored tree data could not be decoded, or new data could not be encoded.
    Serialization(std::io::Error),

    /// A shard was inserted that would leave a hole in the shard sequence.
    ///
    /// Shards must form a contiguous run; a gap would mean the tree could not
    /// be walked from its root to the missing region, and witnesses beyond the
    /// gap would be unbuildable.
    ShardDiscontinuity {
        /// The range whose insertion was attempted.
        attempted: std::ops::Range<u64>,
        /// The range already present.
        existing: std::ops::Range<u64>,
    },

    /// A checkpoint was re-added at a height where a different one already
    /// exists.
    ///
    /// This means the chain moved without the wallet rewinding. Accepting it
    /// would leave the tree describing a chain that never existed, so it is an
    /// error rather than an overwrite.
    CheckpointConflict {
        /// The height at which the conflict occurred.
        checkpoint_id: BlockHeight,
    },

    /// An account with this viewing key already exists.
    ///
    /// The incoming viewing key is the account's identity: two accounts sharing
    /// one would see the same notes, and every balance would be doubled.
    AccountExists,

    /// No account with this identifier exists.
    NoSuchAccount {
        /// The identifier that was asked for.
        id: zakura_wallet_core::AccountId,
    },

    /// The database's schema version does not match this build's.
    ///
    /// The three versions carry different remedies: see
    /// [`crate::schema`].
    VersionMismatch {
        /// Which version disagreed.
        kind: VersionKind,
        /// The version found in the database.
        found: u32,
        /// The version this build expects.
        expected: u32,
    },
}

/// Which schema version failed to match, which determines the remedy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionKind {
    /// Detection changed: a full chain rescan is required.
    Detection,
    /// The derived layout changed: a local reindex is required.
    Layout,
    /// The tree encoding changed: subtree roots must be refetched.
    Tree,
}

impl VersionKind {
    /// Returns what recovering from this mismatch costs.
    pub fn remedy(self) -> &'static str {
        match self {
            VersionKind::Detection => "rescan the chain from each account's birthday",
            VersionKind::Layout => "rebuild the derived tables locally",
            VersionKind::Tree => "refetch subtree roots",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Query(e) => write!(f, "wallet database query failed: {e}"),
            Error::Serialization(e) => write!(f, "tree data could not be encoded or decoded: {e}"),
            Error::ShardDiscontinuity {
                attempted,
                existing,
            } => write!(
                f,
                "inserting shards {}..{} would leave a gap beside the existing {}..{}",
                attempted.start, attempted.end, existing.start, existing.end
            ),
            Error::AccountExists => f.write_str(
                "an account with that viewing key already exists; adding it again would \
                 count its notes twice",
            ),
            Error::NoSuchAccount { id } => write!(f, "there is no account {}", id.0),
            Error::CheckpointConflict { checkpoint_id } => write!(
                f,
                "a different checkpoint already exists at height {checkpoint_id}; \
                 the wallet should have rewound before re-adding it"
            ),
            Error::VersionMismatch {
                kind,
                found,
                expected,
            } => write!(
                f,
                "{kind:?} schema version is {found}, but this build expects {expected}; \
                 to recover, {}",
                kind.remedy()
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Query(e) => Some(e),
            Error::Serialization(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Query(e)
    }
}

/// A failure from an operation on a commitment tree.
///
/// Tree operations can fail either in storage or in the tree logic above it —
/// a witness for an unmarked position, a checkpoint out of order — and callers
/// need to tell those apart. This is a concrete type rather than a generic
/// parameter because the store itself is concrete: threading a caller's error
/// type through would buy nothing and cost a bound at every call site.
#[derive(Debug)]
pub enum TreeError {
    /// Reading or writing the tree's storage failed.
    Store(Error),
    /// The tree rejected the operation.
    Tree(shardtree::error::ShardTreeError<Error>),
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreeError::Store(e) => write!(f, "{e}"),
            TreeError::Tree(e) => write!(f, "commitment tree operation failed: {e}"),
        }
    }
}

impl std::error::Error for TreeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TreeError::Store(e) => Some(e),
            TreeError::Tree(e) => Some(e),
        }
    }
}

impl From<Error> for TreeError {
    fn from(e: Error) -> Self {
        TreeError::Store(e)
    }
}

impl From<rusqlite::Error> for TreeError {
    fn from(e: rusqlite::Error) -> Self {
        TreeError::Store(Error::Query(e))
    }
}

impl From<shardtree::error::ShardTreeError<Error>> for TreeError {
    fn from(e: shardtree::error::ShardTreeError<Error>) -> Self {
        TreeError::Tree(e)
    }
}
