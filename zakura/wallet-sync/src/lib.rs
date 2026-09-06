//! The Zakura wallet synchronisation engine.
//!
//! One invariant holds the design together: a batch of blocks is fetched,
//! detected and applied as a single unit, and the scan queue entry recording it
//! as scanned is written in the same database transaction as its data.
//! Cancelling is therefore dropping the engine, and resuming is reading the
//! queue — there is no checkpoint file, no cursor, and no partially-applied
//! state.
//!
//! The engine is driven one batch at a time through [`SyncEngine::step`], with
//! [`SyncEngine::run`] as a loop over it. Recovery runs from the tip downwards,
//! because spendable value concentrates near the tip and Ironwood only exists
//! there.

#![deny(missing_docs)]
#![deny(unsafe_code)]

mod engine;
mod error;
mod progress;
mod source;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing;

pub use engine::{Step, SyncConfig, SyncEngine, SyncSummary, Timings, direction_for};
pub use error::Error;
pub use progress::{Ratio, SyncPhase, SyncStatus};
pub use source::{
    ByteBudget, ChainSource, ChainTip, Direction, FetchedTransaction, SourceError, SubtreeRoot,
    TransactionStatus, estimated_size,
};

pub use tokio_util::sync::CancellationToken;
