<<<<<<< HEAD
use rand::{rand_core::UnwrapErr, rngs::SysRng};
=======
use rand_core::CryptoRng;
>>>>>>> 9753b8d9b00f160dee2ed0b8aa7c977bf3c2b772
use sapling::{
    BatchValidator, Bundle,
    bundle::Authorized,
    circuit::{OutputVerifyingKey, SpendVerifyingKey},
};
use zcash_protocol::value::ZatBalance;

pub(super) fn verify_bundle(
    rng: impl CryptoRng,
    bundle: &Bundle<Authorized, ZatBalance>,
    spend_vk: &SpendVerifyingKey,
    output_vk: &OutputVerifyingKey,
    sighash: [u8; 32],
) -> Result<(), SaplingError> {
    let mut validator = BatchValidator::new();

    if !validator.check_bundle(bundle.clone(), sighash) {
        return Err(SaplingError::ConsensusRuleViolation);
    }

<<<<<<< HEAD
    if !validator.validate(spend_vk, output_vk, UnwrapErr(SysRng)) {
=======
    if !validator.validate(spend_vk, output_vk, rng) {
>>>>>>> 9753b8d9b00f160dee2ed0b8aa7c977bf3c2b772
        return Err(SaplingError::InvalidProofsOrSignatures);
    }

    Ok(())
}

#[derive(Debug)]
pub enum SaplingError {
    ConsensusRuleViolation,
    Extract(sapling::pczt::TxExtractorError),
    InvalidProofsOrSignatures,
}
