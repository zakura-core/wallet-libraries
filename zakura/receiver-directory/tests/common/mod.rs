// Reuse the same public fixtures without requiring a test-only feature on this crate.
#[path = "../../src/test_support.rs"]
mod fixtures;
pub use fixtures::*;
