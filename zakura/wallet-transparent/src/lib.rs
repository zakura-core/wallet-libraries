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
//! here. What this crate adds is everything that needs the wallet: the durable
//! store the library syncs into, which scripts to ask about and from which
//! height each, which block hashes the wallet has actually accepted, and when
//! to ask again because the gap limit moved.
//!
//! # A returning wallet
//!
//! The library's [`sync_into`](transparent_wallet::sync_into) continues what an
//! earlier sync left in a [`WalletStore`](transparent_wallet::WalletStore).
//! This crate's [`store::PirStore`] is that store, over the wallet's own
//! database: every shard commits atomically with its projection into the
//! balance, a retry is idempotent, a retry that differs is refused, and the
//! wallet's own rewind rolls the ledger back with everything else. A sync that
//! stops short — a budget, an outage, a chain the wallet has not scanned to —
//! leaves its work pending and says so, and the interface must not call the
//! balance synchronized until a later sync completes it.
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
//! The split is the one [`Endpoints`] requires rather than a coincidence:
//!
//! - filters — `https://enhance-pir.valargroup.dev`, serving
//!   `GET /v1/filters/shards` and `GET /v1/filters/shards/{id}/filter`;
//! - shards — `https://transparent-pir.valargroup.dev`, serving
//!   `GET /v1/shards/init`, `GET /v1/shards/{id}/revisions/{digest}/manifest`,
//!   `GET /v1/shards/{id}/setup/{table}/{segment}` and
//!   `POST /v1/shards/{id}/query/{table}`.
//!
//! Neither is a default here. A wallet is told where to look, because a default
//! is a host it talks to because nobody chose otherwise, and the whole point of
//! two URLs is that the choice is made deliberately.
//!
//! `tests/live.rs` exercises all of it against the real services, including a
//! real private query.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod chain;
pub mod endpoints;
pub mod files;
pub mod scripts;
pub mod source;
pub mod stop;
pub mod store;

pub use chain::{AcceptedBlocks, ChainSnapshot};
pub use endpoints::Endpoints;
pub use error::Error;
pub use scripts::{WatchedScripts, watched_scripts};
pub use source::TransparentPir;
pub use stop::{StopSignal, Stoppable};
pub use store::PirStore;
pub use transparent_wallet::WorkLimits;

mod error;

/// The protocol revision this build reads.
///
/// A shard's rows carry no version of their own — a fixed-width row has nowhere
/// to put one without spending the space on every row — so a wallet that
/// decoded whatever it was handed would read a newer layout as the one it knows
/// and reconstruct a plausible, wrong history. Every session is checked against
/// this.
pub const SCHEMA: &str = transparent_shard::SCHEMA;

/// The private work one sync may do on a phone before it stops and keeps the
/// rest for later.
///
/// A directory query costs on the order of 150 KB up and down, so 256 of them
/// is tens of megabytes: enough to recover an ordinary history in one sync, and
/// a bound rather than a budget. Someone else can create a large history by
/// sending to a wallet, and a sync that reached this leaves its remaining work
/// pending rather than a balance that looks finished.
pub const MOBILE_LIMITS: WorkLimits = WorkLimits {
    max_queries: Some(256),
    max_private_bytes: Some(64 * 1024 * 1024),
};
