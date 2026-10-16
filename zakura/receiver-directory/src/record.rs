//! Payment records and their fixed-width row encoding.
//!
//! Nothing in this crate checks cryptography. Receivers and Action fields are
//! untrusted bytes: a publisher validates every record before storing or publishing
//! it, and a wallet validates every record it retrieves, for example with
//! `zakura-receiver-crypto`, which reads the same encoding.
use crate::Error;
pub use zakura_receiver_crypto::wire::{Payment, RawRecord, RECORD_BYTES};

/// A receiver's 43 raw address bytes, not checked to be a valid address.
pub type ReceiverBytes = [u8; 43];

/// Encodes `record` after checking its page bounds.
pub(crate) fn encode(record: &RawRecord) -> Result<[u8; RECORD_BYTES], Error> {
    record.encode().map_err(|_| Error::Malformed)
}

/// Decodes one slot structurally. Only an entirely zero slot is empty; any other
/// malformed slot is an error, so corruption can never advance a gap limit.
pub(crate) fn decode(bytes: &[u8]) -> Result<Option<RawRecord>, Error> {
    RawRecord::decode(bytes).map_err(|_| Error::Malformed)
}
