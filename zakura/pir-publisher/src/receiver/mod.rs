//! Receiver publication construction: payment row placement and companion witness
//! tables. Formats, sessions and inventories are shared with the other roles.
pub use zakura_pir_protocol::receiver::*;
pub mod snapshot;
pub mod v2;
pub mod witness;
