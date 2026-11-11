//! PQ transparent addresses and signed spends with fresh PQ change.
//!
//! Keys come from `transparent-pq-keys`, change keys from `transparent-pq-pool`, and the
//! output, the body, the signing context and the verifier from Common's PQ output rules.
//! A [`PqSigner`] signs each spend in one call that also refills the pool, so a hardware
//! signer can implement the same interface later. The README specifies the output, the
//! body, the scriptSig layout and the fee.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod address;
mod output;
mod signer;
mod spend;
mod transaction;

pub use address::{AddressError, pq_receiver, pq_recipient, with_pq_receiver};
pub use output::PqDestination;
pub use signer::{PqSigner, SeedSigner, SeedSignerError, SigningRequest, SigningResponse};
pub use spend::{
    Payment, PqUtxo, Quote, Recipient, SignedSpend, SpendError, build_spend, max_payment,
    quote_spend,
};
pub use transaction::{UnsignedTransaction, VerifyError, verify_inputs};
