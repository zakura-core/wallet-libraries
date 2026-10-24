//! Authenticated recovery with the public all-zero OVK. This never uses wallet keys.
use super::{Error, Hash, Receiver};
use orchard::{
    keys::OutgoingViewingKey,
    note::{ExtractedNoteCommitment, Nullifier},
    note_encryption::{CompactAction, IronwoodDomain},
    value::ValueCommitment,
};
use zcash_note_encryption::{EphemeralKeyBytes, ShieldedOutput, try_output_recovery_with_ovk};

/// The Ironwood Action fields that zero-OVK recovery reads.
pub struct Action {
    pub cv: Hash,
    pub nullifier: Hash,
    pub cmx: Hash,
    pub ephemeral_key: Hash,
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
}

impl ShieldedOutput<IronwoodDomain, 580> for Action {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.ephemeral_key)
    }
    fn cmstar_bytes(&self) -> Hash {
        self.cmx
    }
    fn enc_ciphertext(&self) -> &[u8; 580] {
        &self.enc_ciphertext
    }
}

impl Action {
    /// The receiver this Action pays, when it was sent with the zero outgoing viewing
    /// key. `None` means outside this recovery scheme, not an unused wallet address. A
    /// noncanonical nullifier, commitment or value commitment is [`Error::Malformed`].
    pub fn recover_receiver(&self) -> Result<Option<Receiver>, Error> {
        let nf = Option::from(Nullifier::from_bytes(&self.nullifier)).ok_or(Error::Malformed)?;
        let cmx =
            Option::from(ExtractedNoteCommitment::from_bytes(&self.cmx)).ok_or(Error::Malformed)?;
        let cv = Option::from(ValueCommitment::from_bytes(&self.cv)).ok_or(Error::Malformed)?;
        let compact = CompactAction::from_parts(
            nf,
            cmx,
            EphemeralKeyBytes(self.ephemeral_key),
            self.enc_ciphertext[..52].try_into().unwrap(),
        );
        try_output_recovery_with_ovk(
            &IronwoodDomain::for_compact_action(&compact),
            &OutgoingViewingKey::from([0; 32]),
            self,
            &cv,
            &self.out_ciphertext,
        )
        .map(|(_, address, _)| Receiver::from_bytes(address.to_raw_address_bytes()))
        .transpose()
    }
}
