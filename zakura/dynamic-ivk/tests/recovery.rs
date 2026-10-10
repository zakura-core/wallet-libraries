use incrementalmerkletree::Hashable;
use orchard::{
    builder::{Builder, BundleType},
    bundle::{BundleVersion, Flags},
    keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendingKey},
    note::{Note, NoteVersion, RandomSeed, Rho},
    note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use rand::rng;
use zakura_dynamic_ivk::{KeyId, Purpose, recovery::EncryptedNote};
use zcash_note_encryption::Domain;

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
            bytes[52..].try_into().unwrap(),
        );
        let restored = EncryptedNote::from_bytes(*encrypted.to_bytes());
        let recovered = restored.decrypt(&account, id).unwrap();
        assert_eq!(recovered.note(), &note);
        assert_eq!(recovered.nullifier(), &note.nullifier(&key));
        assert!(restored.decrypt(&account, KeyId::new(purpose, 8)).is_none());
        let other = FullViewingKey::from(&SpendingKey::from_bytes([1; 32]).unwrap());
        assert!(restored.decrypt(&other, id).is_none());
        for offset in [0, 32, 64, 96, 148, 675] {
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

/// Why `RecoveredNote` has no memo: a provider that recovers a public-zero-OVK
/// output can re-encrypt the same note with another memo, and every chain-bound
/// field still matches while `decrypt` still accepts it.
#[test]
fn zero_ovk_recovery_allows_memo_substitution() {
    let account = FullViewingKey::from(&SpendingKey::from_bytes([0; 32]).unwrap());
    let id = KeyId::new(Purpose::Receive, 0);
    let key = id.derive(&account).unwrap();
    let public_ovk = OutgoingViewingKey::from([0; 32]);
    let mut builder = Builder::new(
        BundleType::DEFAULT,
        BundleVersion::ironwood_v3(),
        Flags::SPENDS_DISABLED,
        MerkleHashOrchard::empty_root(32.into()).into(),
    )
    .unwrap();
    builder
        .add_output(
            Some(public_ovk.clone()),
            key.address_at(0u32, Scope::External),
            NoteValue::from_raw(30_000),
            [4; 512],
        )
        .unwrap();
    let (bundle, metadata) = builder.build::<i64>(&mut rng()).unwrap().unwrap();
    let index = metadata.output_action_index(0).unwrap();
    let action = &bundle.actions()[index];
    let (nf, cmx) = (action.nullifier().to_bytes(), action.cmx().to_bytes());
    let transmitted = action.encrypted_note();
    let prefix: [u8; 52] = transmitted.enc_ciphertext[..52].try_into().unwrap();
    let chain = EncryptedNote::from_parts(
        nf,
        cmx,
        transmitted.epk_bytes,
        prefix,
        transmitted.enc_ciphertext[52..].try_into().unwrap(),
    );

    // The public OVK alone recovers the note, from which the provider re-encrypts it.
    let (note, _, memo) = bundle.recover_output_with_ovk(index, &public_ovk).unwrap();
    assert_eq!(memo, [4; 512]);
    let encryptor = IronwoodNoteEncryption::new(None, note, [5; 512]);
    let bytes = encryptor.encrypt_note_plaintext();
    let forged = EncryptedNote::from_parts(
        nf,
        cmx,
        IronwoodDomain::epk_bytes(encryptor.epk()).0,
        bytes[..52].try_into().unwrap(),
        bytes[52..].try_into().unwrap(),
    );

    assert!(forged.matches_compact(nf, cmx, transmitted.epk_bytes, prefix));
    assert_ne!(forged.to_bytes(), chain.to_bytes());
    for encrypted in [&chain, &forged] {
        assert_eq!(encrypted.decrypt(&account, id).unwrap().note(), &note);
    }
}
