use ff::{FromUniformBytes, PrimeField};
use orchard::keys::FullViewingKey;
use pasta_curves::pallas;
use zeroize::Zeroizing;

/// First byte of the `PRF^expand` input that derives a dynamic key's `rivk`.
///
/// Unused by the protocol specification and ZIPs when chosen; it must be reserved
/// with the ZIP editors before any address goes live.
const RIVK_DOMAIN: u8 = 0x85;

/// Independent v1 receiving sequences under one account's spending authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// Return of funds from a Zcash-funded swap, recorded in its funding memo.
    Refund,
    /// Payment into Zcash, recovered through receiver lookahead.
    Receive,
}

/// A v1 key within one account's Ironwood receiving namespace.
///
/// Account and network are supplied by the owning wallet. This is not an
/// operation ID: multiple swaps may be associated with the same receiving key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyId {
    purpose: Purpose,
    index: u64,
}

impl KeyId {
    /// Identifies the v1 key at `index` in the selected purpose's sequence.
    pub fn new(purpose: Purpose, index: u64) -> Self {
        Self { purpose, index }
    }

    /// The independent sequence containing this key.
    pub fn purpose(self) -> Purpose {
        self.purpose
    }

    /// The index in that sequence.
    pub fn index(self) -> u64 {
        self.index
    }

    /// Derives this key's v1 FVK from the account's **external** FVK.
    ///
    /// The result keeps the account's `ak` and `nk` and replaces `rivk` with
    /// `ToScalar(PRF^expand_rivk([RIVK_DOMAIN] || ak || nk || [purpose] || index))`,
    /// where `purpose` is 0 for refund and 1 for incoming and `index` is little-endian.
    /// This is ZIP 32's internal-key derivation (first byte `0x83`, no suffix) with
    /// another domain byte and a suffix, so a ZIP 2005 recovery circuit can check
    /// it the same way.
    ///
    /// Use external diversifier index zero for the key's receiver. The account FVK
    /// is sufficient; this never needs a spending key. Network and pool belong to
    /// the caller's key identity, but are not inputs to the v1 KDF. The caller must
    /// reserve the index durably before exposing its address. With negligible
    /// probability the result is not a valid FVK, and that index has no key.
    pub fn derive(self, account: &FullViewingKey) -> Result<FullViewingKey, DerivationError> {
        let mut bytes = Zeroizing::new(account.to_bytes());
        let mut suffix = [0; 9];
        suffix[0] = self.purpose.code();
        suffix[1..].copy_from_slice(&self.index.to_le_bytes());
        let rivk = expand_rivk(&bytes, RIVK_DOMAIN, &suffix);
        bytes[64..].copy_from_slice(&rivk);
        // Parsing checks both external and derived internal IVKs.
        FullViewingKey::from_bytes(&bytes).ok_or(DerivationError)
    }
}

impl Purpose {
    /// The purpose byte in the v1 derivation input.
    fn code(self) -> u8 {
        match self {
            Self::Refund => 0,
            Self::Receive => 1,
        }
    }
}

/// The derived `rivk` does not give a valid viewing key, so the index has no key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivationError;

impl core::fmt::Display for DerivationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("dynamic IVK index has no valid viewing key")
    }
}

impl std::error::Error for DerivationError {}

/// `ToScalar^Orchard(PRF^expand_rivk([domain] || ak || nk || suffix))` over the raw
/// FVK encoding `ak || nk || rivk` (protocol §5.6.4.4), as ZIP 32 derives an
/// internal `rivk`.
fn expand_rivk(fvk: &[u8; 96], domain: u8, suffix: &[u8]) -> [u8; 32] {
    let wide = Zeroizing::new(
        *blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Zcash_ExpandSeed")
            .to_state()
            .update(&fvk[64..])
            .update(&[domain])
            .update(&fvk[..64])
            .update(suffix)
            .finalize()
            .as_array(),
    );
    // FromUniformBytes reduces a little-endian integer modulo the Pallas scalar
    // order, which is ToScalar^Orchard. pallas::Base would define a different KDF.
    pallas::Scalar::from_uniform_bytes(&wide).to_repr()
}

/// Checks whether two valid FVKs share `ak` and `nk`, permitting different `rivk`.
///
/// This checks the account relationship only. Signing still requires the usual
/// recipient, nullifier, randomized signing-key, value, and output checks.
pub fn has_same_spending_authority(account: &FullViewingKey, candidate: &FullViewingKey) -> bool {
    // Raw FVK encoding is ak || nk || rivk, each 32 bytes (protocol §5.6.4.4).
    let account = Zeroizing::new(account.to_bytes());
    let candidate = Zeroizing::new(candidate.to_bytes());
    account[..64] == candidate[..64]
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::{Scope, SpendingKey};

    /// The first Orchard key-component test vector's spending key, published in
    /// zakura-orchard's `src/test_vectors/keys.rs`. No wallet secrets are used.
    fn vector_account() -> FullViewingKey {
        let sk = hex::decode("5d7a8f739a2d9e945b0ce152a8049e294c4d6e66b164939daffa2ef6ee692148")
            .unwrap()
            .try_into()
            .unwrap();
        FullViewingKey::from(&SpendingKey::from_bytes(sk).unwrap())
    }

    #[test]
    fn matches_python_prf_expand_vectors() {
        let account = vector_account();
        for row in include_str!("../tests/vectors/rivk.csv").lines().skip(1) {
            let fields: Vec<_> = row.split(',').collect();
            let purpose = match fields[0] {
                "refund" => Purpose::Refund,
                "receive" => Purpose::Receive,
                _ => panic!("unknown vector purpose"),
            };
            let key = KeyId::new(purpose, fields[1].parse().unwrap())
                .derive(&account)
                .unwrap();
            assert_eq!(hex::encode(&key.to_bytes()[64..]), fields[2], "{row}");
        }
    }

    #[test]
    fn zip32_internal_byte_reproduces_the_orchard_internal_key() {
        let account = vector_account();
        let internal = expand_rivk(&account.to_bytes(), 0x83, &[]);
        assert_eq!(
            hex::encode(internal),
            "901a30b99ae1570cb80bb616aeef3bb916c640c4cc620f9b4b4499c74332eb2a"
        );
        let mut bytes = account.to_bytes();
        bytes[64..].copy_from_slice(&internal);
        assert_eq!(
            FullViewingKey::from_bytes(&bytes)
                .unwrap()
                .address_at(0u32, Scope::External),
            account.address_at(0u32, Scope::Internal)
        );
    }
}
