//! A lightwalletd chain source.
//!
//! This is the only crate in the wallet core that knows the wire protocol
//! exists. Everything above it speaks [`zakura_wallet_core`]'s own compact-block
//! types, so a change to the protocol definition cannot ripple into the scanner
//! or the store, and the engine can be driven from a synthetic chain with no
//! network dependency at all.
//!
//! It is also the only crate with a build-time tool dependency (`protoc`),
//! which is a second reason for the separation.

#![deny(missing_docs)]
#![deny(unsafe_code)]

mod convert;
mod source;

/// The generated protocol types.
pub mod proto {
    #![allow(missing_docs)]
    #![allow(clippy::all)]
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing;

pub use source::{LightwalletdSource, LwdError};
