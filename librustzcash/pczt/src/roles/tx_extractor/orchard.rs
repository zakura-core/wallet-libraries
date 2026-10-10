use orchard::{Bundle, bundle::Authorized, circuit::VerifyingKey};
<<<<<<< HEAD
use rand::{rand_core::UnwrapErr, rngs::SysRng};
=======
use rand_core::CryptoRng;
>>>>>>> 9753b8d9b00f160dee2ed0b8aa7c977bf3c2b772
use zcash_protocol::value::ZatBalance;

pub(super) fn verify_bundle(
    rng: impl CryptoRng,
    bundle: &Bundle<Authorized, ZatBalance>,
    orchard_vk: Option<&VerifyingKey>,
    sighash: [u8; 32],
) -> Result<(), OrchardError> {
    match orchard_vk {
        Some(vk) => verify_bundle_with_key(rng, bundle, vk, sighash),
        // The circuit version is fixed by the bundle's own `BundleVersion`, which
        // `extract_tx_data` derives from the PCZT's consensus branch ID.
        None => verify_bundle_with_key(
            rng,
            bundle,
            &VerifyingKey::build(bundle.bundle_version().circuit_version()),
            sighash,
        ),
    }
}

fn verify_bundle_with_key(
    rng: impl CryptoRng,
    bundle: &Bundle<Authorized, ZatBalance>,
    vk: &VerifyingKey,
    sighash: [u8; 32],
) -> Result<(), OrchardError> {
    let mut validator = orchard::bundle::BatchValidator::new(vk);
    validator
        .add_bundle(bundle, sighash)
        .map_err(|_| OrchardError::InvalidProof)?;

<<<<<<< HEAD
    if validator.validate(UnwrapErr(SysRng)) {
=======
    if validator.validate(rng) {
>>>>>>> 9753b8d9b00f160dee2ed0b8aa7c977bf3c2b772
        Ok(())
    } else {
        Err(OrchardError::InvalidProof)
    }
}

#[derive(Debug)]
pub enum OrchardError {
    Extract(orchard::pczt::TxExtractorError),
    InvalidProof,
}
