//! Txid display: the service that looks up a transaction's display entry privately, the
//! translation of an entry into the wallet's display facts, and the run that drives the
//! wallet's detail work through both.

#[cfg(feature = "wallet")]
mod display_facts;
#[cfg(feature = "wallet")]
mod run;
mod service;

#[cfg(feature = "wallet")]
pub use display_facts::{deferral, display_facts};

/// Decodes the display map digest in its client-facing hexadecimal representation.
pub fn map_sha256(hex: &str) -> Option<[u8; 32]> {
    hex::decode(hex).ok()?.try_into().ok()
}
#[cfg(feature = "wallet")]
pub use run::{
    DetailAnswer, DetailApplied, DetailRun, DetailStep, DetailWrite, MapCheck, MapChecked,
};
pub use service::{DisplayLookup, TxidDisplayService};
