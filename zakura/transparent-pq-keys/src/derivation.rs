use alloc::vec::Vec;

use hkdf::Hkdf;
use hkdf::hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{DerivedSigningKey, Error, KeyOrigin};

/// Separates this wallet derivation from all other uses of the same wallet seed.
const DERIVATION_SALT: &[u8] = b"Zcash/PQWallet/SLH-DSA-SHA2-192s/v1";
/// First-level SLIP-0021 purpose shared with the firmware implementations.
const ROOT_LABEL: &[u8] = b"Zcash/TransparentPQ/v1";
/// Three distinct 24-byte inputs to SLH-DSA key generation.
pub(crate) const KEY_MATERIAL_BYTES: usize = 72;

/// Secret recovery material for every PQ key derived by this wallet.
///
/// Accepts 32..=64 bytes, compatible with common wallet seed lengths. Length is
/// not an entropy test: the caller supplies securely generated material and
/// preserves its backup. Passwords and mnemonic text are not wallet seed bytes.
/// The constructor copies its input; the caller must clear its own copy.
///
/// Stored bytes are cleared on drop. There is deliberately no `Debug`, `Clone`,
/// serialization, or secret export. HKDF's internal temporary state is not
/// guaranteed to be cleared; see the security discussion in the README.
///
/// Secret material cannot be logged through debug formatting:
///
/// ```compile_fail
/// use transparent_pq_keys::WalletSeed;
/// let seed = WalletSeed::from_bytes(&[42; 32]).unwrap();
/// println!("{seed:?}");
/// ```
pub struct WalletSeed(Zeroizing<Vec<u8>>);

impl WalletSeed {
    /// Copies valid-length seed bytes into storage cleared on drop.
    ///
    /// Invalid lengths are rejected before copying or performing derivation.
    pub fn from_bytes(seed: &[u8]) -> Result<Self, Error> {
        if !(32..=64).contains(&seed.len()) {
            return Err(Error::InvalidSeedLength(seed.len()));
        }
        Ok(Self(Zeroizing::new(seed.to_vec())))
    }

    /// Reconstructs the complete, distinct signing key for this origin.
    ///
    /// HKDF-SHA-512 expands to `SK.seed || SK.prf || PK.seed`; every component is
    /// derived privately for this origin. The temporary output is cleared after
    /// key generation. Only the public key and origin can be exported.
    ///
    /// This operation neither allocates an address index nor resets usage limits
    /// on previously derived keys. Multiple copies of this seed share authority.
    pub fn derive_key(&self, origin: KeyOrigin) -> DerivedSigningKey {
        let material = self.key_material(origin);
        DerivedSigningKey::from_material(origin, &material)
    }

    fn key_material(&self, origin: KeyOrigin) -> Zeroizing<[u8; KEY_MATERIAL_BYTES]> {
        let root = slip21_root(&self.0);
        let derivation = Hkdf::<Sha512>::new(Some(DERIVATION_SALT), &*root);
        let mut material = Zeroizing::new([0; KEY_MATERIAL_BYTES]);
        derivation
            .expand(&origin.to_bytes(), &mut *material)
            .expect("72 bytes is below HKDF-SHA-512's 16320-byte output limit");
        material
    }
}

impl ZeroizeOnDrop for WalletSeed {}

/// Returns Key(m / ROOT_LABEL), not the node's child-derivation half.
fn slip21_root(seed: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut extract = Hmac::<Sha512>::new_from_slice(b"Symmetric key seed")
        .expect("HMAC accepts keys of any length");
    extract.update(seed);
    let mut master = Zeroizing::new([0u8; 64]);
    master.copy_from_slice(&extract.finalize().into_bytes());
    let mut derive =
        Hmac::<Sha512>::new_from_slice(&master[..32]).expect("HMAC accepts keys of any length");
    derive.update(&[0]);
    derive.update(ROOT_LABEL);
    let mut node = Zeroizing::new([0u8; 64]);
    node.copy_from_slice(&derive.finalize().into_bytes());
    let mut root = Zeroizing::new([0u8; 32]);
    root.copy_from_slice(&node[32..]);
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_matches_independent_openssl_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/derivation.json")).unwrap();
        for vector in vectors["vectors"].as_array().unwrap() {
            let seed =
                WalletSeed::from_bytes(&hex::decode(vector["seed"].as_str().unwrap()).unwrap())
                    .unwrap();
            let origin =
                KeyOrigin::from_bytes(&hex::decode(vector["origin"].as_str().unwrap()).unwrap())
                    .unwrap();
            let expected = hex::decode(vector["material"].as_str().unwrap()).unwrap();
            use sha2::{Digest, Sha256};
            assert_eq!(
                hex::encode(Sha256::digest(*slip21_root(&seed.0))),
                vector["root_hash"]
            );
            assert_eq!(
                &seed.key_material(origin)[..],
                expected,
                "{}",
                vector["name"]
            );
        }
    }

    #[test]
    fn derivation_matches_keystone_and_ledger_public_vectors() {
        use sha2::{Digest, Sha256};
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/firmware.json")).unwrap();
        for vector in vectors["vectors"].as_array().unwrap() {
            let seed =
                WalletSeed::from_bytes(&hex::decode(vector["seed"].as_str().unwrap()).unwrap())
                    .unwrap();
            let origin =
                KeyOrigin::from_bytes(&hex::decode(vector["origin"].as_str().unwrap()).unwrap())
                    .unwrap();
            assert_eq!(
                hex::encode(Sha256::digest(*slip21_root(&seed.0))),
                vector["root_hash"]
            );
            assert_eq!(
                hex::encode(Sha256::digest(*seed.key_material(origin))),
                vector["material_hash"]
            );
            assert_eq!(
                hex::encode(seed.derive_key(origin).public_key().to_bytes()),
                vector["public_key"]
            );
        }
    }
}
