//! PQ transparent P2SH addresses and signed spends with fresh PQ change.
//!
//! Keys come from `transparent-pq-keys`, change keys from `transparent-pq-pool`, and
//! the script, signing context and verifier from Common's PQ P2SH rules. A
//! [`PqSigner`] signs each spend in one call that also refills the pool, so a hardware
//! signer can implement the same interface later. The README specifies the address
//! template, the scriptSig layout and the fee.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod script;
mod signer;
mod spend;
mod transaction;

pub use script::PqScript;
pub use signer::{PqSigner, SeedSigner, SeedSignerError, SigningRequest, SigningResponse};
pub use spend::{Payment, PqUtxo, SignedSpend, SpendError, build_spend};
pub use transaction::{UnsignedTransaction, VerifyError, verify_inputs};
