//! Receiver publication construction: segment tables and companion witness payloads.
//! Formats, sessions and inventories are shared with the other roles.
pub use zakura_pir_protocol::receiver::*;
mod segment;
pub use segment::*;
pub mod witness;
