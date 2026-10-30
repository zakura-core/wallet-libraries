use std::collections::HashSet;

use serde::Deserialize;
use transparent_pq_keys::{
    Branch, DerivedSigningKey, Error, KeyOrigin, Network, ORIGIN_BYTES, PUBLIC_KEY_BYTES,
    PublicKey, SIGNATURE_BYTES, WalletSeed,
};

#[derive(Deserialize)]
struct Vector {
    name: String,
    seed: String,
    origin: String,
    public_key: String,
}

#[derive(Deserialize)]
struct Vectors {
    vectors: Vec<Vector>,
}

fn vectors() -> Vec<Vector> {
    serde_json::from_str::<Vectors>(include_str!("vectors/derivation.json"))
        .unwrap()
        .vectors
}

fn origin(index: u32) -> KeyOrigin {
    KeyOrigin::new(Network::Mainnet, 0, Branch::Receive, index)
}

#[test]
fn restore_reproduces_independent_public_keys_and_public_seeds() {
    let mut public_keys = HashSet::new();
    let mut public_seeds = HashSet::new();
    for vector in vectors() {
        let seed_bytes = hex::decode(&vector.seed).unwrap();
        let saved_origin = hex::decode(&vector.origin).unwrap();
        let restored_origin = KeyOrigin::from_bytes(&saved_origin).unwrap();
        let original_public = {
            let seed = WalletSeed::from_bytes(&seed_bytes).unwrap();
            let key = seed.derive_key(restored_origin);
            assert_eq!(key.origin().to_bytes().as_slice(), saved_origin);
            key.public_key()
        };
        // The original seed object and derived private key are gone. Recovery
        // needs only the seed backup and the versioned origin.
        let restored_seed = WalletSeed::from_bytes(&seed_bytes).unwrap();
        let restored = restored_seed.derive_key(restored_origin);
        assert_eq!(restored.public_key(), original_public, "{}", vector.name);
        assert_eq!(
            hex::encode(original_public.to_bytes()),
            vector.public_key,
            "{}",
            vector.name
        );
        assert!(
            public_keys.insert(original_public),
            "repeated public key: {}",
            vector.name
        );
        assert!(
            public_seeds.insert(original_public.to_bytes()[..24].to_vec()),
            "repeated public seed: {}",
            vector.name
        );
        assert_eq!(
            PublicKey::from_bytes(&original_public.to_bytes()).unwrap(),
            original_public
        );
    }
}

#[test]
fn derived_signature_matches_and_verifies_the_openssl_reference() {
    let seed = WalletSeed::from_bytes(&(0..32).collect::<Vec<u8>>()).unwrap();
    let key = seed.derive_key(origin(0));
    let message = b"PQ wallet lifecycle vector";
    let context = b"zakura-pq-keys/test-v1";
    let reference = include_bytes!("vectors/derived_openssl.sig");
    let signature = key.sign(message, context).unwrap();
    assert_eq!(signature.len(), SIGNATURE_BYTES);
    assert_eq!(signature, reference);
    key.public_key()
        .verify(message, context, reference)
        .unwrap();
    // Reconstructing the key reproduces its signature, not a new signing identity.
    assert_eq!(
        seed.derive_key(origin(0)).sign(message, context).unwrap(),
        signature
    );
}

#[test]
fn signatures_bind_the_child_message_context_and_all_signature_bytes() {
    let seed = WalletSeed::from_bytes(&[42; 32]).unwrap();
    let key = seed.derive_key(origin(0));
    let public = key.public_key();
    let other_public = seed.derive_key(origin(1)).public_key();
    let message = b"first authorization";
    let context = b"wallet test context";
    let signature = key.sign(message, context).unwrap();
    public.verify(message, context, &signature).unwrap();
    assert_eq!(
        other_public.verify(message, context, &signature),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        public.verify(b"changed authorization", context, &signature),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        public.verify(message, b"other context", &signature),
        Err(Error::InvalidSignature)
    );
    for offset in [0, 24, SIGNATURE_BYTES / 2, SIGNATURE_BYTES - 1] {
        let mut changed = signature.clone();
        changed[offset] ^= 1;
        assert_eq!(
            public.verify(message, context, &changed),
            Err(Error::InvalidSignature)
        );
    }
    let mut changed_key = public.to_bytes();
    changed_key[PUBLIC_KEY_BYTES - 1] ^= 1;
    assert_eq!(
        PublicKey::from_bytes(&changed_key)
            .unwrap()
            .verify(message, context, &signature),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        public.verify(message, context, &vec![0; SIGNATURE_BYTES]),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn keys_support_repeated_signing_and_external_context_boundaries() {
    let seed = WalletSeed::from_bytes(&[7; 64]).unwrap();
    let key = seed.derive_key(KeyOrigin::new(
        Network::Regtest,
        u32::MAX,
        Branch::Change,
        u32::MAX,
    ));
    for (message, context) in [
        (b"".as_slice(), vec![]),
        (b"second message".as_slice(), vec![7; 255]),
    ] {
        let signature = key.sign(message, &context).unwrap();
        key.public_key()
            .verify(message, &context, &signature)
            .unwrap();
    }
    assert_eq!(
        key.sign(b"message", &[0; 256]),
        Err(Error::ContextTooLong(256))
    );
    assert_eq!(
        key.public_key().verify(b"message", &[0; 256], &[]),
        Err(Error::ContextTooLong(256))
    );
}

#[test]
fn seed_lengths_are_checked_before_copying() {
    for length in [0, 16, 24, 31, 65, 1024] {
        assert_eq!(
            WalletSeed::from_bytes(&vec![0; length]).err(),
            Some(Error::InvalidSeedLength(length))
        );
    }
    for length in [32, 33, 48, 63, 64] {
        assert!(WalletSeed::from_bytes(&vec![0; length]).is_ok());
    }
}

#[test]
fn origin_encoding_is_exact_and_does_not_mask_high_index_bits() {
    let path = KeyOrigin::new(Network::Testnet, 0x0102_0304, Branch::Change, 0x8000_0001);
    assert_eq!(hex::encode(path.to_bytes()), "0101010203040180000001");
    let recovered = KeyOrigin::from_bytes(&path.to_bytes()).unwrap();
    assert_eq!(recovered, path);
    assert_eq!(recovered.version(), 1);
    assert_eq!(recovered.network(), Network::Testnet);
    assert_eq!(recovered.account(), 0x0102_0304);
    assert_eq!(recovered.branch(), Branch::Change);
    assert_eq!(recovered.index(), 0x8000_0001);
    for index in [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
        assert_eq!(
            KeyOrigin::from_bytes(&origin(index).to_bytes())
                .unwrap()
                .index(),
            index
        );
    }
}

#[test]
fn malformed_origins_and_public_encodings_are_rejected() {
    for length in [0, ORIGIN_BYTES - 1, ORIGIN_BYTES + 1] {
        assert_eq!(
            KeyOrigin::from_bytes(&vec![0; length]),
            Err(Error::InvalidOriginLength(length))
        );
    }
    for version in [0, 2, 255] {
        let mut bytes = origin(0).to_bytes();
        bytes[0] = version;
        assert_eq!(
            KeyOrigin::from_bytes(&bytes),
            Err(Error::UnsupportedVersion(version))
        );
    }
    let mut bytes = origin(0).to_bytes();
    bytes[1] = 3;
    assert_eq!(
        KeyOrigin::from_bytes(&bytes),
        Err(Error::UnsupportedNetwork(3))
    );
    bytes = origin(0).to_bytes();
    bytes[6] = 2;
    assert_eq!(
        KeyOrigin::from_bytes(&bytes),
        Err(Error::UnsupportedBranch(2))
    );
    for length in [0, PUBLIC_KEY_BYTES - 1, PUBLIC_KEY_BYTES + 1] {
        assert_eq!(
            PublicKey::from_bytes(&vec![0; length]),
            Err(Error::InvalidPublicKeyLength(length))
        );
    }
    let public = PublicKey::from_bytes(&[0; PUBLIC_KEY_BYTES]).unwrap();
    for length in [0, SIGNATURE_BYTES - 1, SIGNATURE_BYTES + 1] {
        assert_eq!(
            public.verify(b"message", b"context", &vec![0; length]),
            Err(Error::InvalidSignatureLength(length))
        );
    }
}

#[test]
fn owned_secrets_require_drop_zeroization() {
    fn requires_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    requires_zeroize_on_drop::<slh_dsa::SigningKey<slh_dsa::Sha2_192s>>();
    requires_zeroize_on_drop::<WalletSeed>();
    requires_zeroize_on_drop::<DerivedSigningKey>();
}
