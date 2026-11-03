//! Companion witness payloads: each payment's lower inclusion path.
#[cfg(feature = "receiver-crypto")]
mod paths;
#[cfg(feature = "receiver-crypto")]
pub use paths::{SHARD_LEAVES, ShardPaths, payloads};
