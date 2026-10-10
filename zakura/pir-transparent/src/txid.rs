//! Txid display: the service that looks up a transaction's display entry privately, and
//! the translation of an entry into the wallet's display facts.

mod display_facts;
mod service;

pub use display_facts::{deferral, display_facts, map_sha256};
pub use service::TxidDisplayService;
