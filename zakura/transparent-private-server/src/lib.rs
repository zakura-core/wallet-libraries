//! The publisher's side of Transparent private mode: building activity
//! filters and shards from chain events, sealing them, packing histories into
//! page rows, laying out txid display tables and splitting their map, and the
//! native operations a service answers queries with.
//!
//! The formats all of this produces, and the native profiles both sides
//! derive, are `zakura-transparent-private-shared`'s. Nothing here recovers a
//! wallet's history; that is `zakura-transparent-private-wallet`, which this
//! crate never depends on. Services, ingestion, deployment and storage stay
//! with their operators.
//!
//! Feature `testing` adds an in-process shard service over a synthetic
//! publication, for wallet and application tests. Never enable it in a
//! production build.

pub mod filter;
pub mod native;
pub mod shard;
#[cfg(feature = "testing")]
pub mod testing;
