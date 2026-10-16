//! Cross-version checks between the Transparent private-mode crates and the
//! baseline release they replaced.
//!
//! `src/vectors.rs` and `src/scenario.rs` are written once against a module
//! named `api` and included by each implementation they compare: `capture`
//! includes them against the baseline to write the frozen files under
//! `baseline/`, and the tests include them against the current crates.

pub mod dump;
