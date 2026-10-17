//! What a Transparent private-mode wallet and its publisher both need: the
//! event records and their codecs, the activity filter profile and its
//! validation, the shard and display publications' layout, manifests,
//! placement and row codecs, and each table's native PIR profile.
//!
//! Nothing here recovers a wallet's history or builds or serves a
//! publication: that is `zakura-transparent-private-wallet` and
//! `zakura-transparent-private-server`, which both build on this crate and
//! never on each other.

pub mod events;
pub mod filter;
pub mod native;
pub mod shard;
