use alloc::vec::Vec;

use slh_dsa::Sha2_192s;
use zeroize::ZeroizeOnDrop;

use crate::{Error, KeyOrigin, derivation::KEY_MATERIAL_BYTES};

/// The public seed followed by the public root, each 24 bytes.
pub const PUBLIC_KEY_BYTES: usize = 48;
/// The exact SLH-DSA-SHA2-192s signature length, without a transaction hash selector.
pub const SIGNATURE_BYTES: usize = 16_224;

/// A complete SLH-DSA child signing key and its public recovery origin.
///
/// The key can sign repeatedly. It has no persistent signing counter and does
/// not enforce the parameter set's lifetime budget across devices or restores.
/// Secret fields are cleared on drop by the primitive's `zeroize` feature.
/// No debug formatting, cloning, or secret-key export is provided.
///
/// ```compile_fail
/// use transparent_pq_keys::{Branch, KeyOrigin, Network, WalletSeed};
/// let seed = WalletSeed::from_bytes(&[42; 32]).unwrap();
/// let key = seed.derive_key(KeyOrigin::new(Network::Testnet, 0, Branch::Receive, 0));
/// println!("{key:?}");
/// ```
pub struct DerivedSigningKey {
    origin: KeyOrigin,
    key: slh_dsa::SigningKey<Sha2_192s>,
}

impl DerivedSigningKey {
    pub(crate) fn from_material(origin: KeyOrigin, material: &[u8; KEY_MATERIAL_BYTES]) -> Self {
        Self {
            origin,
            key: slh_dsa::SigningKey::slh_keygen_internal(
                &material[..24],
                &material[24..48],
                &material[48..],
            ),
        }
    }

    /// Returns the origin needed to recover this key from the wallet seed.
    pub fn origin(&self) -> KeyOrigin {
        self.origin
    }

    /// Exports only the canonical public seed and public root.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.key.as_ref().to_bytes().into())
    }

    /// Signs exactly `message` with the supplied Pure SLH-DSA context.
    ///
    /// Uses the standardized deterministic external signing interface: the
    /// same key, message, and context produce the same signature. This is not
    /// HashSLH-DSA and does not define a transaction digest or protocol context.
    /// Callers must bind the message/context to their intended authorization.
    /// Rejects contexts longer than 255 bytes before cryptographic work.
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<Vec<u8>, Error> {
        check_context(context)?;
        self.key
            .try_sign_with_context(message, context, None)
            .map(|signature| signature.to_bytes().to_vec())
            .map_err(|_| Error::InvalidSignature)
    }
}

impl ZeroizeOnDrop for DerivedSigningKey {}

/// Public verification material; it grants neither signing nor child derivation.
///
/// Imported public keys must be authenticated by the caller. All 48-byte strings
/// are structurally valid encodings; successful parsing does not prove ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; PUBLIC_KEY_BYTES]);

impl PublicKey {
    /// Imports exactly 48 bytes, rejecting truncation and trailing data.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, Error> {
        encoded
            .try_into()
            .map(Self)
            .map_err(|_| Error::InvalidPublicKeyLength(encoded.len()))
    }

    /// Exports the 48-byte public seed and public root without any secret fields.
    pub fn to_bytes(self) -> [u8; PUBLIC_KEY_BYTES] {
        self.0
    }

    /// Verifies the exact message and context using the standardized external interface.
    ///
    /// Rejects non-exact signature lengths, including trailing data, and contexts
    /// longer than 255 bytes before cryptographic verification.
    pub fn verify(&self, message: &[u8], context: &[u8], signature: &[u8]) -> Result<(), Error> {
        check_context(context)?;
        if signature.len() != SIGNATURE_BYTES {
            return Err(Error::InvalidSignatureLength(signature.len()));
        }
        let key = slh_dsa::VerifyingKey::<Sha2_192s>::try_from(self.0.as_slice())
            .map_err(|_| Error::InvalidSignature)?;
        let signature = slh_dsa::Signature::<Sha2_192s>::try_from(signature)
            .map_err(|_| Error::InvalidSignature)?;
        key.try_verify_with_context(message, context, &signature)
            .map_err(|_| Error::InvalidSignature)
    }
}

fn check_context(context: &[u8]) -> Result<(), Error> {
    if context.len() > 255 {
        Err(Error::ContextTooLong(context.len()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Branch, Network};

    #[test]
    fn nist_key_and_openssl_signature_match_the_standardized_primitive() {
        let material = include_bytes!("../tests/vectors/sha2_192s_nist.seed");
        let expected_public = include_bytes!("../tests/vectors/sha2_192s_nist.pk");
        let expected_signature = include_bytes!("../tests/vectors/sha2_192s_openssl.sig");
        let origin = KeyOrigin::new(Network::Testnet, 0, Branch::Receive, 0);
        // This published NIST key-generation input deliberately bypasses wallet
        // derivation: it independently tests compatibility of the primitive.
        let key = DerivedSigningKey::from_material(origin, material);
        assert_eq!(&key.public_key().to_bytes(), expected_public);
        assert_eq!(
            key.sign(&[42; 32], b"common/slh-dsa/test").unwrap(),
            expected_signature
        );
        key.public_key()
            .verify(&[42; 32], b"common/slh-dsa/test", expected_signature)
            .unwrap();
    }
}
