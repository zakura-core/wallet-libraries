//! Test support for wallets and applications, with feature `testing`: a
//! publisher writing a synthetic shard set ([`service`]) and the shard service
//! answering it in process with real native PIR. Nothing here is for
//! production.

pub mod native;
mod publication;
pub mod service;
