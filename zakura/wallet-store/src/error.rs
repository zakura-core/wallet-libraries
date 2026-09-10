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

    /// A stored row does not mean anything the wallet can act on.
    ///
    /// The derived database is rebuildable, so this is recoverable by dropping
    /// it — but it must be reported rather than papered over, because guessing
    /// at what a corrupt row meant is how a wrong balance gets displayed
    /// confidently.
    Corrupt(String),

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

    /// An operation named an account the wallet does not hold.
    UnknownAccount(zakura_wallet_core::AccountId),

    /// No account with this identifier exists.
    NoSuchAccount {
        /// The identifier that was asked for.
        id: zakura_wallet_core::AccountId,
    },

    /// A batch's anchor contradicts what the wallet already recorded.
    ///
    /// A batch is inserted into the commitment trees at the absolute position
    /// its anchor names, so a wrong anchor silently misplaces every commitment
    /// in it and invalidates every witness built from that region — a failure
    /// that surfaces only when a spend proof is rejected, potentially months
    /// later.
    ///
    /// Under descending recovery the anchor usually comes from the source
    /// rather than from local data, so this is the check that keeps a faulty or
    /// hostile source from rewriting the wallet's view of the trees. It is not
    /// a reorg: the chain moving is what a continuity error reports, and it is
    /// handled by rewinding. This means the source disagreed with data the
    /// wallet holds, and asking it again would return the same answer.
    AnchorMismatch {
        /// The pool whose tree size disagreed.
        pool: zakura_wallet_core::pool::PoolId,
        /// The height whose recorded state was contradicted.
        at_height: BlockHeight,
        /// The tree size the wallet had recorded.
        stored: u32,
        /// The tree size the batch's anchor claimed.
        claimed: u32,
    },

    /// A batch's anchor names a block whose hash the wallet recorded
    /// differently.
    ///
    /// Distinct from [`Error::AnchorMismatch`] because it is caught before any
    /// tree size is compared, and because it means the source is describing a
    /// different chain rather than miscounting on this one.
    AnchorHashMismatch {
        /// The height whose recorded hash was contradicted.
        at_height: BlockHeight,
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
            Error::Corrupt(what) => {
                write!(f, "the derived database holds something unusable: {what}")
            }
            Error::ShardDiscontinuity {
                attempted,
                existing,
            } => write!(
                f,
                "inserting shards {}..{} would leave a gap beside the existing {}..{}",
                attempted.start, attempted.end, existing.start, existing.end
            ),
            Error::UnknownAccount(id) => write!(f, "there is no account {}", id.0),
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
            Error::AnchorMismatch {
                pool,
                at_height,
                stored,
                claimed,
            } => write!(
                f,
                "the batch anchored at height {at_height} claims the {pool:?} tree held \
                 {claimed} commitments there, but the wallet recorded {stored}; inserting \
                 it would place every commitment in the batch at the wrong position"
            ),
            Error::AnchorHashMismatch { at_height } => write!(
                f,
                "the batch's anchor at height {at_height} names a different block than the \
                 one the wallet scanned there"
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
