//! Authentication of the notes a restore sweep retrieves, before wallet accounting.
//! Chain roots and spend-history coverage must come from the wallet independently.

use orchard::{
    keys::{FullViewingKey, Scope},
    note::{ExtractedNoteCommitment, Note, Nullifier},
    note_encryption::{CompactAction, IronwoodDomain},
    tree::{Anchor, MerklePath},
};
use zakura_one_time_ivk::KeyId;
use zcash_note_encryption::{COMPACT_NOTE_SIZE, EphemeralKeyBytes, try_compact_note_decryption};

/// Serialized encrypted context size, independent of the discovery transport.
pub const ENCRYPTED_NOTE_BYTES: usize = 96 + COMPACT_NOTE_SIZE;

/// A directory payment's compact Action, without trusted chain metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedNote([u8; ENCRYPTED_NOTE_BYTES]);

impl EncryptedNote {
    /// Joins the directory's compact fields. Construction does not authenticate the
    /// ciphertext or establish wallet ownership.
    pub fn from_parts(
        action_nullifier: [u8; 32],
        cmx: [u8; 32],
        ephemeral_key: [u8; 32],
        prefix: [u8; COMPACT_NOTE_SIZE],
    ) -> Self {
        let mut bytes = [0; ENCRYPTED_NOTE_BYTES];
        bytes[..32].copy_from_slice(&action_nullifier);
        bytes[32..64].copy_from_slice(&cmx);
        bytes[64..96].copy_from_slice(&ephemeral_key);
        bytes[96..].copy_from_slice(&prefix);
        Self(bytes)
    }

    /// Restores encrypted context. Call `decrypt` again after loading persisted data.
    pub fn from_bytes(bytes: [u8; ENCRYPTED_NOTE_BYTES]) -> Self {
        Self(bytes)
    }
    /// Action nullifier, commitment, ephemeral key, then the compact ciphertext prefix.
    pub fn to_bytes(&self) -> &[u8; ENCRYPTED_NOTE_BYTES] {
        &self.0
    }

    /// Public commitment bytes used to request the matching common witness.
    pub fn commitment(&self) -> [u8; 32] {
        self.0[32..64].try_into().unwrap()
    }

    /// Whether rediscovered compact data is the same Action.
    pub fn matches_compact(
        &self,
        nullifier: [u8; 32],
        commitment: [u8; 32],
        ephemeral_key: [u8; 32],
        prefix: [u8; COMPACT_NOTE_SIZE],
    ) -> bool {
        self.0[..32] == nullifier
            && self.0[32..64] == commitment
            && self.0[64..96] == ephemeral_key
            && self.0[96..] == prefix
    }

    /// Derives the expected key and authenticates the note as compact scanning does:
    /// trial decryption of the prefix must yield a note whose commitment is `cmx`.
    /// Returns `None` if derivation, decoding or authentication fails, or the note is
    /// not a v3 note to the key's address; that never shows the receiver is unused.
    ///
    /// No memo is recovered: one-time-key notes carry no memo the wallet reads; only
    /// internal change carries the refund marker.
    pub fn decrypt(&self, account: &FullViewingKey, key_id: KeyId) -> Option<RecoveredNote> {
        let key = key_id.derive(account).ok()?;
        let nf =
            Option::<Nullifier>::from(Nullifier::from_bytes(self.0[..32].try_into().unwrap()))?;
        let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
            self.0[32..64].try_into().unwrap(),
        ))?;
        let compact = CompactAction::from_parts(
            nf,
            cmx,
            EphemeralKeyBytes(self.0[64..96].try_into().unwrap()),
            self.0[96..].try_into().unwrap(),
        );
        let (note, recipient) = try_compact_note_decryption(
            &IronwoodDomain::for_compact_action(&compact),
            &key.to_ivk(Scope::External).prepare(),
            &compact,
        )?;
        // `IronwoodDomain` accepts only v3 plaintexts.
        if recipient != key.address_at(0u32, Scope::External) {
            return None;
        }
        Some(RecoveredNote {
            nullifier: note.nullifier(&key),
            note,
        })
    }
}
/// A note authenticated with its one-time key. Not yet safe to credit.
/// Viewing material and plaintext deliberately have no Debug implementation.
pub struct RecoveredNote {
    note: Note,
    nullifier: Nullifier,
}
impl RecoveredNote {
    /// Authenticated note plaintext.
    pub fn note(&self) -> &Note {
        &self.note
    }
    /// This received note's spend nullifier, computed locally from its derived FVK.
    pub fn nullifier(&self) -> &Nullifier {
        &self.nullifier
    }
    /// Whether `path` places this note's commitment at `position` under a
    /// wallet-accepted root. A root supplied by the same discovery service is not
    /// independent validation. This does not bind transaction metadata or establish
    /// that the note is unspent.
    #[must_use]
    pub fn verify_position(&self, position: u64, path: &MerklePath, accepted_root: Anchor) -> bool {
        position == u64::from(path.position())
            && path.root(self.note.commitment().into()) == accepted_root
    }
}

#[cfg(test)]
mod tests {
    use incrementalmerkletree::Hashable;
    use orchard::{
        keys::{FullViewingKey, Scope, SpendingKey},
        note::{Note, NoteVersion, RandomSeed, Rho},
        note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
        tree::{Anchor, MerkleHashOrchard, MerklePath},
        value::NoteValue,
    };
    use zakura_one_time_ivk::{KeyId, Purpose};
    use zcash_note_encryption::Domain;

    use super::EncryptedNote;

    #[test]
    fn authenticate_derived_key_and_bind_position() {
        let account = FullViewingKey::from(&SpendingKey::from_bytes([0; 32]).unwrap());
        for purpose in [Purpose::Refund, Purpose::Receive] {
            let id = KeyId::new(purpose, 7);
            let key = id.derive(&account).unwrap();
            let rho = Rho::from_bytes(&[9; 32]).unwrap();
            let note = Note::from_parts(
                key.address_at(0u32, Scope::External),
                NoteValue::from_raw(30_000),
                rho,
                RandomSeed::from_bytes([7; 32], &rho).unwrap(),
                NoteVersion::V3,
            )
            .unwrap();
            let encryptor = IronwoodNoteEncryption::new(None, note, [4; 512]);
            let bytes = encryptor.encrypt_note_plaintext();
            let encrypted = EncryptedNote::from_parts(
                [9; 32],
                orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
                IronwoodDomain::epk_bytes(encryptor.epk()).0,
                bytes[..52].try_into().unwrap(),
            );
            let restored = EncryptedNote::from_bytes(*encrypted.to_bytes());
            let recovered = restored.decrypt(&account, id).unwrap();
            assert_eq!(recovered.note(), &note);
            assert_eq!(recovered.nullifier(), &note.nullifier(&key));
            assert!(restored.decrypt(&account, KeyId::new(purpose, 8)).is_none());
            let other = FullViewingKey::from(&SpendingKey::from_bytes([1; 32]).unwrap());
            assert!(restored.decrypt(&other, id).is_none());
            // The action nullifier is the note's rho, so every byte is authenticated.
            for offset in [0, 31, 32, 63, 64, 95, 96, 147] {
                let mut bytes = *restored.to_bytes();
                bytes[offset] ^= 1;
                assert!(
                    EncryptedNote::from_bytes(bytes)
                        .decrypt(&account, id)
                        .is_none()
                );
            }
            let path = MerklePath::from_parts(
                2,
                std::array::from_fn(|i| MerkleHashOrchard::empty_root((i as u8).into())),
            );
            let root = path.root(note.commitment().into());
            assert!(recovered.verify_position(2, &path, root));
            assert!(!recovered.verify_position(3, &path, root));
            assert!(!recovered.verify_position((1u64 << 32) + 2, &path, root));
            assert!(!recovered.verify_position(2, &path, Anchor::empty_tree()));
        }
    }
}
