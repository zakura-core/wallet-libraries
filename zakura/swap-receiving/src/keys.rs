use ff::{FromUniformBytes, PrimeField};
use hmac::{Hmac, Mac};
use orchard::keys::FullViewingKey;
use pasta_curves::pallas;
use sha2::Sha512;
use zeroize::Zeroizing;

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

    /// Reconstructs this key from the account's external FVK.
    pub fn derive(self, account: &FullViewingKey) -> Result<FullViewingKey, DerivationError> {
        derive_full_viewing_key(account, self.purpose, self.index)
    }
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Refund => b"swap-refund-v1",
            Self::Receive => b"swap-receive-v1",
        }
    }
}

/// No valid viewing key was found in the v1 retry space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivationError;

impl core::fmt::Display for DerivationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("swap receiving key derivation exhausted its retry space")
    }
}

impl std::error::Error for DerivationError {}

/// Derives a v1 FVK from the account's **external** FVK, purpose, and index.
///
/// Use external diversifier index zero for the swap receiver. The account FVK
/// is sufficient; this function never needs a spending key. Network and pool
/// belong to the caller's key identity, but are not inputs to the v1 KDF.
/// The caller must reserve the index durably before exposing its address.
pub fn derive_full_viewing_key(
    account: &FullViewingKey,
    purpose: Purpose,
    index: u64,
) -> Result<FullViewingKey, DerivationError> {
    derive_with(
        account,
        purpose,
        index,
        u32::MAX,
        FullViewingKey::from_bytes,
    )
}

fn derive_with<T>(
    account: &FullViewingKey,
    purpose: Purpose,
    index: u64,
    last_attempt: u32,
    mut accept: impl FnMut(&[u8; 96]) -> Option<T>,
) -> Result<T, DerivationError> {
    let account_bytes = Zeroizing::new(account.to_bytes());
    let mut candidate = Zeroizing::new(*account_bytes);
    for attempt in 0..=last_attempt {
        candidate[64..].copy_from_slice(&derive_rivk(
            account_bytes[64..].try_into().expect("32-byte rivk"),
            purpose,
            index,
            attempt,
        ));
        // Parsing checks both external and derived internal IVKs. A retry must
        // keep ak/nk unchanged, since those bind spending and nullifier authority.
        if let Some(fvk) = accept(&candidate) {
            return Ok(fvk);
        }
    }
    Err(DerivationError)
}

fn derive_rivk(key: &[u8; 32], purpose: Purpose, index: u64, attempt: u32) -> [u8; 32] {
    let label = purpose.label();
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(&[label.len() as u8]);
    mac.update(label);
    mac.update(&index.to_le_bytes());
    mac.update(&attempt.to_le_bytes());
    let wide = Zeroizing::new(<[u8; 64]>::from(mac.finalize().into_bytes()));
    // FromUniformBytes reduces a little-endian integer modulo the Pallas
    // scalar order. Using pallas::Base here would define a different KDF.
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
    use orchard::keys::SpendingKey;

    #[test]
    fn matches_python_hmac_and_integer_reduction_vectors() {
        let key: [u8; 32] =
            hex::decode("021ccf89604f5f7cc6e034b32d338908b819fbe325fee6458b56b4ca71a7e43d")
                .unwrap()
                .try_into()
                .unwrap();
        for row in include_str!("../tests/vectors/rivk.csv").lines().skip(1) {
            let fields: Vec<_> = row.split(',').collect();
            let purpose = match fields[0] {
                "refund" => Purpose::Refund,
                "receive" => Purpose::Receive,
                _ => panic!("unknown vector purpose"),
            };
            let actual = derive_rivk(
                &key,
                purpose,
                fields[1].parse().unwrap(),
                fields[2].parse().unwrap(),
            );
            assert_eq!(hex::encode(actual), fields[3], "{row}");
        }
    }

    #[test]
    fn retries_keep_authority_and_stop_without_wrapping() {
        let account = FullViewingKey::from(&SpendingKey::from_bytes([0; 32]).unwrap());
        let bytes = account.to_bytes();
        let mut attempts = 0;
        let result = derive_with(&account, Purpose::Refund, u64::MAX, 1, |candidate| {
            assert_eq!(candidate[..64], bytes[..64]);
            assert_eq!(
                candidate[64..],
                derive_rivk(
                    bytes[64..].try_into().unwrap(),
                    Purpose::Refund,
                    u64::MAX,
                    attempts
                )
            );
            attempts += 1;
            None::<()>
        });
        assert_eq!(result, Err(DerivationError));
        assert_eq!(attempts, 2);

        let mut attempts = 0;
        let retried = derive_with(&account, Purpose::Receive, 0, 2, |candidate| {
            attempts += 1;
            (attempts == 2).then_some(*candidate)
        })
        .unwrap();
        assert_eq!(attempts, 2);
        assert_eq!(
            retried[64..],
            derive_rivk(bytes[64..].try_into().unwrap(), Purpose::Receive, 0, 1)
        );
    }
}
