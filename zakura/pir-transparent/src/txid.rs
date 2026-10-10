//! Txid display: the service that looks up a transaction's display entry privately, the
//! translation of an entry into the wallet's display facts, and the run that drives the
//! wallet's detail work through both.

mod display_facts;
mod run;
mod service;

pub use display_facts::{deferral, display_facts, map_sha256};
pub use run::{
    DetailAnswer, DetailApplied, DetailRun, DetailStep, DetailWrite, MapCheck, MapChecked,
};
pub use service::{DisplayLookup, TxidDisplayService};
