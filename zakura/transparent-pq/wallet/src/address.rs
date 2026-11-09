use core::fmt;

use transparent_pq_keys::{ParameterSet, PublicKey};
use zcash_address::unified::PqScheme;
use zcash_keys::address::UnifiedAddress;

use crate::output::{PqDestination, common_parameters};
use crate::spend::Recipient;

/// The receiver a wallet publishes for one PQ key: its scheme and its commitment.
///
/// A PQ receiver carries the bare commitment, exactly as a P2PKH receiver carries a bare
/// key hash. Which scheme it names is decided when the key is derived and only reported
/// here; nothing in this function chooses anything.
pub fn pq_receiver(public_key: &PublicKey) -> (PqScheme, [u8; 32]) {
    let destination = PqDestination::single_signer(public_key);
    (
        common_parameters(public_key.parameters()).address_scheme(),
        *destination.commitment(),
    )
}

/// Publishes `public_key` as the PQ receiver of an existing Unified Address.
///
/// The address keeps the receivers it already had, so senders that do not know the PQ
/// typecode keep paying its shielded or legacy transparent receiver. A PQ receiver is a
/// transparent receiver type and may not stand alone in a Revision 0 address, which is why
/// this takes an address the wallet already publishes rather than minting one; and at most
/// one PQ receiver may appear, so attaching a second replaces the first.
///
/// The typecodes are provisional until the ZIP process assigns them, so an address issued
/// today is not durable.
pub fn with_pq_receiver(address: UnifiedAddress, public_key: &PublicKey) -> UnifiedAddress {
    let (scheme, commitment) = pq_receiver(public_key);
    address.with_pq_transparent_receiver(scheme, commitment)
}

/// Why an address cannot be paid as a PQ destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressError {
    /// The address publishes no PQ receiver.
    NoPqReceiver,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPqReceiver => f.write_str("the address has no post-quantum receiver"),
        }
    }
}

impl std::error::Error for AddressError {}

/// Reads the PQ receiver `address` publishes, as something this crate can pay.
///
/// A wallet that understands a PQ receiver pays it rather than the legacy transparent
/// receiver in the same address, because PQ sits above both in ZIP 316's preference order.
/// Failing to build a PQ output is an error here, never a reason to fall back to the
/// weaker receiver.
///
/// This reads the receiver directly instead of walking the address's understood receivers,
/// which omit PQ by design and would silently skip it.
pub fn pq_recipient(address: &UnifiedAddress) -> Result<Recipient, AddressError> {
    let (scheme, commitment) = address.pq_transparent().ok_or(AddressError::NoPqReceiver)?;
    Ok(Recipient::Pq {
        parameters: parameter_set(scheme),
        commitment: *commitment,
    })
}

/// The parameter set a receiver's scheme selects.
fn parameter_set(scheme: PqScheme) -> ParameterSet {
    match transparent::pq::ParameterSet::from_address_scheme(scheme) {
        transparent::pq::ParameterSet::Sha2_128f => ParameterSet::Sha2_128f,
        transparent::pq::ParameterSet::Sha2_192s => ParameterSet::Sha2_192s,
    }
}
