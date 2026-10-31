use alloc::vec::Vec;

use slh_dsa::{Sha2_128f, Sha2_192s};
use zeroize::ZeroizeOnDrop;

use crate::{Error, KeyOrigin, ParameterSet};

enum SigningKey {
    Fast(slh_dsa::SigningKey<Sha2_128f>),
    Small(slh_dsa::SigningKey<Sha2_192s>),
}

/// A complete SLH-DSA child signing key and its public recovery origin.
///
/// The key can sign repeatedly. It has no persistent signing counter and does
/// not enforce the parameter set's lifetime budget across devices or restores.
/// Secret fields are cleared on drop by the primitive's `zeroize` feature.
/// No debug formatting, cloning, or secret-key export is provided.
///
/// ```compile_fail
/// use transparent_pq_keys::{Branch, KeyOrigin, Network, ParameterSet, WalletSeed};
/// let seed = WalletSeed::from_bytes(&[42; 32]).unwrap();
/// let key = seed.derive_key(KeyOrigin::new(parameters, Network::Testnet, 0, Branch::Receive, 0));
/// println!("{key:?}");
/// ```
pub struct DerivedSigningKey {
    origin: KeyOrigin,
    key: SigningKey,
}

impl DerivedSigningKey {
    pub(crate) fn from_material(origin: KeyOrigin, material: &[u8]) -> Self {
        let n = origin.parameters().seed_bytes();
        assert_eq!(material.len(), 3 * n);
        let key = match origin.parameters() {
            ParameterSet::Sha2_128f => SigningKey::Fast(slh_dsa::SigningKey::slh_keygen_internal(
                &material[..n],
                &material[n..2 * n],
                &material[2 * n..],
            )),
            ParameterSet::Sha2_192s => SigningKey::Small(slh_dsa::SigningKey::slh_keygen_internal(
                &material[..n],
                &material[n..2 * n],
                &material[2 * n..],
            )),
        };
        Self { origin, key }
    }

    /// Returns the origin needed to recover this key from the wallet seed.
    pub fn origin(&self) -> KeyOrigin {
        self.origin
    }

    /// Exports only the canonical public seed and public root.
    pub fn public_key(&self) -> PublicKey {
        let bytes = match &self.key {
            SigningKey::Fast(key) => PublicBytes::Fast(key.as_ref().to_bytes().into()),
            SigningKey::Small(key) => PublicBytes::Small(key.as_ref().to_bytes().into()),
        };
        PublicKey(bytes)
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
        match &self.key {
            SigningKey::Fast(key) => key
                .try_sign_with_context(message, context, None)
                .map(|signature| signature.to_bytes().to_vec()),
            SigningKey::Small(key) => key
                .try_sign_with_context(message, context, None)
                .map(|signature| signature.to_bytes().to_vec()),
        }
        .map_err(|_| Error::InvalidSignature)
    }
}

impl ZeroizeOnDrop for DerivedSigningKey {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum PublicBytes {
    Fast([u8; 32]),
    Small([u8; 48]),
}

/// Public verification material, including its explicit configuration.
/// Importing bytes does not authenticate their ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey(PublicBytes);

impl PublicKey {
    /// Imports exactly the selected configuration's canonical key bytes.
    pub fn from_bytes(parameters: ParameterSet, encoded: &[u8]) -> Result<Self, Error> {
        let invalid = |_| Error::InvalidPublicKeyLength(encoded.len());
        Ok(Self(match parameters {
            ParameterSet::Sha2_128f => PublicBytes::Fast(encoded.try_into().map_err(invalid)?),
            ParameterSet::Sha2_192s => PublicBytes::Small(encoded.try_into().map_err(invalid)?),
        }))
    }

    /// The configuration this public key authenticates signatures under.
    pub fn parameters(&self) -> ParameterSet {
        match self.0 {
            PublicBytes::Fast(_) => ParameterSet::Sha2_128f,
            PublicBytes::Small(_) => ParameterSet::Sha2_192s,
        }
    }

    /// Borrows the canonical public seed and public root, without a scheme tag.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            PublicBytes::Fast(bytes) => bytes,
            PublicBytes::Small(bytes) => bytes,
        }
    }

    /// Verifies the exact message and context using the standardized external interface.
    ///
    /// Rejects non-exact signature lengths, including trailing data, and contexts
    /// longer than 255 bytes before cryptographic verification.
    pub fn verify(&self, message: &[u8], context: &[u8], signature: &[u8]) -> Result<(), Error> {
        check_context(context)?;
        if signature.len() != self.parameters().signature_bytes() {
            return Err(Error::InvalidSignatureLength(signature.len()));
        }
        match self.0 {
            PublicBytes::Fast(bytes) => {
                let key = slh_dsa::VerifyingKey::<Sha2_128f>::try_from(bytes.as_slice())
                    .map_err(|_| Error::InvalidSignature)?;
                let signature = slh_dsa::Signature::<Sha2_128f>::try_from(signature)
                    .map_err(|_| Error::InvalidSignature)?;
                key.try_verify_with_context(message, context, &signature)
            }
            PublicBytes::Small(bytes) => {
                let key = slh_dsa::VerifyingKey::<Sha2_192s>::try_from(bytes.as_slice())
                    .map_err(|_| Error::InvalidSignature)?;
                let signature = slh_dsa::Signature::<Sha2_192s>::try_from(signature)
                    .map_err(|_| Error::InvalidSignature)?;
                key.try_verify_with_context(message, context, &signature)
            }
        }
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

    fn nist_key_and_openssl_signature_match_the_standardized_primitive(parameters: ParameterSet) {
        let (material, expected_public, expected_signature): (&[u8], &[u8], &[u8]) =
            match parameters {
                ParameterSet::Sha2_128f => (
                    include_bytes!("../tests/vectors/sha2_128f_nist.seed"),
                    include_bytes!("../tests/vectors/sha2_128f_nist.pk"),
                    include_bytes!("../tests/vectors/sha2_128f_openssl.sig"),
                ),
                ParameterSet::Sha2_192s => (
                    include_bytes!("../tests/vectors/sha2_192s_nist.seed"),
                    include_bytes!("../tests/vectors/sha2_192s_nist.pk"),
                    include_bytes!("../tests/vectors/sha2_192s_openssl.sig"),
                ),
            };
        let origin = KeyOrigin::new(parameters, Network::Testnet, 0, Branch::Receive, 0);
        // This published NIST key-generation input deliberately bypasses wallet
        // derivation: it independently tests compatibility of the primitive.
        let key = DerivedSigningKey::from_material(origin, material);
        assert_eq!(key.public_key().as_bytes(), expected_public);
        assert_eq!(
            key.sign(&[42; 32], b"common/slh-dsa/test").unwrap(),
            expected_signature
        );
        key.public_key()
            .verify(&[42; 32], b"common/slh-dsa/test", expected_signature)
            .unwrap();
    }
    #[test]
    fn independent_primitive_vectors() {
        for parameters in [ParameterSet::Sha2_128f, ParameterSet::Sha2_192s] {
            nist_key_and_openssl_signature_match_the_standardized_primitive(parameters);
        }
    }
}
