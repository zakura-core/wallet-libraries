//! query-server operations, independent of wallet clients.
pub mod native;
#[cfg(feature = "enhance")]
pub mod enhance {
    pub use crate::native;
    pub use zakura_pir_protocol::enhance::*;
}
#[cfg(feature = "status")]
pub mod status {
    pub use crate::native;
    pub use zakura_pir_protocol::status::*;
}
#[cfg(feature = "transparent")]
pub mod transparent;
