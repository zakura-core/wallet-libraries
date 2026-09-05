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
pub mod pool;
pub mod scanning;

pub use account::{AccountId, KeyScope};
pub use block::{BlockHash, CompactBlock, CompactTx};
pub use detected::{
    BlockAnchor, DetectedBatch, DetectedBlock, DetectedNote, DetectedSpend,
    DetectedTransparentOutput, DetectedTx, EnhanceCandidate, NullifierSnapshot, PoolCommitments,
};
pub use pool::{Ironwood, Orchard, PoolId, PoolVisitor, ShieldedPool, dispatch};
