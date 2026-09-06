//! Helpers for exercising the spend path.
//!
//! The proving and verifying keys moved to [`crate::circuit`], because a
//! release build needs them too. They are re-exported here so tests keep their
//! existing spelling.

pub use crate::circuit::{proving_key, verifying_key};
