//! Domain types for the Zakura wallet core.
//!
//! This crate is the bottom of the wallet stack: it performs no I/O, spawns no
//! tasks, and knows nothing about SQL or the network. It exists so that the
//! layers that *do* those things can share one vocabulary — a pool abstraction,
//! compact-block types, and the scan-range queue model — without depending on
//! each other.
//!
//! It also owns the vocabulary the layers above share: [`AccountId`],
//! [`DetectedBatch`] and the compact-block types. Detection produces those and
//! storage consumes them, and putting the types here rather than in either
//! makes that a data boundary rather than a dependency between the two.
//!
//! The organising idea is [`pool::ShieldedPool`]. Ironwood is Orchard: it uses
//! the same note, nullifier, commitment and key types, and differs only in its
//! note-encryption domain, its activation height, and the fact that it has its
//! own commitment tree. Encoding that as one trait with two instantiations —
//! rather than two hand-written copies of every code path — is the reason this
//! crate exists.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod account;
pub mod block;
pub mod detected;
pub mod enhanced;
pub mod pool;
pub mod scanning;

pub use account::{AccountId, KeyScope};
pub use block::{BlockHash, CompactBlock, CompactTx};
pub use detected::{
    BlockAnchor, DetectedBatch, DetectedBlock, DetectedNote, DetectedSpend,
    DetectedTransparentOutput, DetectedTx, EnhanceCandidate, NullifierSnapshot, PoolCommitments,
};
pub use pool::{Ironwood, Orchard, PoolId, PoolVisitor, ShieldedPool, dispatch};

/// The ZIP 318 anchor grid this wallet retains checkpoints on.
///
/// A pool crossing proves against the tree state at a boundary of this grid
/// rather than at the tip, and the anonymity set a crossing gets is exactly the
/// set of transfers that chose the same boundary. So the interval is not a
/// tuning parameter: a wallet using a different one is alone in its own set,
/// and announces itself by anchoring somewhere nobody else did.
///
/// It lives here, in the crate both storage and transaction construction
/// depend on, because those two must agree. Storage retains boundary
/// checkpoints against pruning and construction anchors to them; a grid known
/// separately to each would let a wallet retain one set of heights and try to
/// prove against another, and the failure would appear as a crossing that
/// cannot be built rather than as a disagreement about a constant.
pub const ANCHOR_GRID: zcash_protocol::zip318::AnchorBucketInterval =
    zcash_protocol::zip318::AnchorBucketInterval::ZIP_318;

/// How far below the chain tip a retained anchor is still worth keeping.
///
/// A crossing's canonical expiry is at most this far above the height it
/// targets, so a boundary older than this can no longer back a transfer that
/// would still be valid when it was broadcast. Retaining beyond it would grow
/// the checkpoint table without bound and stop the tree ever pruning the marks
/// below — the retention would outlive every transfer it could serve.
pub const ANCHOR_RETENTION_DEPTH: u32 = zcash_protocol::zip318::EXPIRY_WINDOW;
