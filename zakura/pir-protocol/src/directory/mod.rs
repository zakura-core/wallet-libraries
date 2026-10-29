//! Directory primitives Transparent and Receiver share. Each format supplies
//! its own hash domains, keys and seed policy, and keeps its own row codec.
pub mod bucket;
pub mod choice;
pub mod tag;
