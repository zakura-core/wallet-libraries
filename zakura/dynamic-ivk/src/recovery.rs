//! Authenticate privately retrieved notes before wallet accounting.
//! Chain roots and spend-history coverage must come from the wallet independently.
use crate::KeyId;
use orchard::{
    keys::{FullViewingKey, Scope},
    note::{ExtractedNoteCommitment, Note, NoteVersion, Nullifier},
    note_encryption::{CompactAction, IronwoodDomain},
    tree::{Anchor, MerklePath},
};
use zcash_note_encryption::{EphemeralKeyBytes, ShieldedOutput, try_note_decryption};

/// Serialized encrypted context size, independent of the discovery transport.
pub const ENCRYPTED_NOTE_BYTES: usize = 676;

/// Compact Action context and the remaining ciphertext, without trusted chain metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedNote([u8; ENCRYPTED_NOTE_BYTES]);

impl EncryptedNote {
    /// Joins directory/compact fields with the suffix returned by enhancement.
    /// Construction does not authenticate ciphertext or establish wallet ownership.
    pub fn from_parts(
        action_nullifier: [u8; 32],
        cmx: [u8; 32],
        ephemeral_key: [u8; 32],
        prefix: [u8; 52],
        suffix: &[u8; 528],
    ) -> Self {
        let mut bytes = [0; ENCRYPTED_NOTE_BYTES];
        bytes[..32].copy_from_slice(&action_nullifier);
        bytes[32..64].copy_from_slice(&cmx);
        bytes[64..96].copy_from_slice(&ephemeral_key);
        bytes[96..148].copy_from_slice(&prefix);
        bytes[148..].copy_from_slice(suffix);
        Self(bytes)
    }

    /// Restores encrypted context. Call `decrypt` again after loading persisted data.
    pub fn from_bytes(bytes: [u8; ENCRYPTED_NOTE_BYTES]) -> Self {
        Self(bytes)
    }
    /// Action nullifier, commitment, ephemeral key, then the 580-byte ciphertext.
    pub fn to_bytes(&self) -> &[u8; ENCRYPTED_NOTE_BYTES] {
        &self.0
    }

    /// Public commitment bytes used to request the matching common witness.
    pub fn commitment(&self) -> [u8; 32] {
        self.0[32..64].try_into().unwrap()
    }

    /// Compare rediscovered compact data without discarding a saved ciphertext suffix.
    pub fn matches_compact(
        &self,
        nullifier: [u8; 32],
        commitment: [u8; 32],
        ephemeral_key: [u8; 32],
        prefix: [u8; 52],
    ) -> bool {
        self.0[..32] == nullifier
            && self.0[32..64] == commitment
            && self.0[64..96] == ephemeral_key
            && self.0[96..148] == prefix
    }

    /// Derives the expected key and authenticates the full note, including its memo.
    /// Returns `None` if derivation, decoding or authentication fails, or the note is
    /// not a v3 note to the key's address; that never shows the receiver is unused.
    /// This deliberately does not use the public zero OVK to establish ownership.
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
            self.ephemeral_key(),
            self.0[96..148].try_into().unwrap(),
        );
        let (note, recipient, memo) = try_note_decryption(
            &IronwoodDomain::for_compact_action(&compact),
            &key.to_ivk(Scope::External).prepare(),
            self,
        )?;
        if note.version() != NoteVersion::V3 || recipient != key.address_at(0u32, Scope::External) {
            return None;
        }
        Some(RecoveredNote {
            nullifier: note.nullifier(&key),
            note,
            memo,
        })
    }
}
impl ShieldedOutput<IronwoodDomain, 580> for EncryptedNote {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.0[64..96].try_into().unwrap())
    }
    fn cmstar_bytes(&self) -> [u8; 32] {
        self.0[32..64].try_into().unwrap()
    }
    fn enc_ciphertext(&self) -> &[u8; 580] {
        self.0[96..].try_into().unwrap()
    }
}

/// A note authenticated with its derived receiving key. Not yet safe to credit.
/// Viewing material and plaintext deliberately have no Debug implementation.
pub struct RecoveredNote {
    note: Note,
    memo: [u8; 512],
    nullifier: Nullifier,
}
impl RecoveredNote {
    /// Authenticated note plaintext.
    pub fn note(&self) -> &Note {
        &self.note
    }
    /// Authenticated memo plaintext.
    pub fn memo(&self) -> &[u8; 512] {
        &self.memo
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
