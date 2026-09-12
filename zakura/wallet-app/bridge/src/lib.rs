//! The foreign-function surface over the Zakura wallet facade.
//!
//! Nothing here decides anything. Every function in [`api`] converts arguments,
//! calls one facade method and converts the result, so that the code generator
//! has a flat surface of plain data to mirror and the logic stays where it can
//! be tested without a device.
//!
//! `frb_generated` is written by `flutter_rust_bridge_codegen`; see
//! `zakura/wallet-app/bindings/README.md` for how to regenerate it.

pub mod api;

#[allow(clippy::all, missing_docs, unused, unsafe_code)]
mod frb_generated;
