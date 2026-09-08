//! The wallet's private transparent ledger.
//!
//! Transparent funds reach this wallet one way: public activity filters
//! downloaded for every shard from the birthday forward and matched locally,
//! then private retrieval of history from the shards that matched, replayed
//! into a UTXO set. Nothing here names an address, a script, an outpoint or a
//! transaction to a server. See `docs/zakura_transparent_pir.md` for what that
//! does and does not hide.
//!
//! The protocol lives in `valargroup/enhance-pir` and is used, not reimplemented
//! here. What this crate adds is everything that needs the wallet: which
//! scripts to ask about, where each of them has already been read to, which
//! block hashes the wallet has actually accepted, and how a recovered ledger
//! becomes rows in `wallet.db`.
//!
//! # Two sources, never one
//!
//! [`FilterSource`](transparent_wallet::FilterSource) and
//! [`ShardTransport`](transparent_wallet::ShardTransport) are separate traits
//! upstream, and [`Endpoints`] keeps them pointed at separate hosts. Filter
//! bytes are identical for every wallet and reveal nothing; the private queries
//! do not have that property, and taking both from one service correlates them
//! whatever the protocol says.
//!
//! # The deployment
//!
//! Verified live on 2026-09-07, and the split is the one [`Endpoints`] requires
//! rather than a coincidence:
//!
//! - filters — `https://enhance-pir.valargroup.dev`, serving
//!   `GET /v1/filters/shards` and `GET /v1/filters/shards/{id}/filter`;
//! - shards — `https://transparent-pir.valargroup.dev`, serving
//!   `GET /v1/shards/init`, `GET /v1/shards/{id}/setup/{table}/{segment}` and
//!   `POST /v1/shards/{id}/query/{table}`.
//!
//! Neither is a default here. A wallet is told where to look, because a default
//! is a host it talks to because nobody chose otherwise, and the whole point of
//! two URLs is that the choice is made deliberately.
//!
//! The published set covers Ironwood activation to 3,473,474 in three shards,
//! the last of them a growing tail. `tests/live.rs` exercises all of it against
//! the real services, including one real private query.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod chain;
pub mod endpoints;
pub mod files;
#[cfg(feature = "https-client")]
pub mod http;
pub mod ledger;
pub mod scripts;
pub mod source;

pub use chain::AcceptedBlocks;
pub use endpoints::Endpoints;
pub use error::Error;
pub use ledger::into_ledger;
pub use scripts::{WatchedScripts, watched_scripts};
pub use source::TransparentPir;

mod error;

/// The protocol revision this build reads.
///
/// A shard's rows carry no version of their own — a fixed-width row has nowhere
/// to put one without spending the space on every row — so a wallet that
/// decoded whatever it was handed would read a newer layout as the one it knows
/// and reconstruct a plausible, wrong history. Every session is checked against
/// this.
pub const SCHEMA: &str = transparent_shard::SCHEMA;

/// The first height the published shard sets cover.
///
/// A wallet whose birthday is below this is not served: its earlier transparent
/// history is not in any shard, and a run that started at shard zero would
/// report coverage it does not have.
pub const START_HEIGHT: u64 = transparent_filter::START_HEIGHT;
