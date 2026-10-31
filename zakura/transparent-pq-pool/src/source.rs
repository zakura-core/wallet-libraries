use alloc::vec::Vec;
use core::convert::Infallible;

use transparent_pq_keys::{KeyOrigin, PublicKey, WalletSeed};

use crate::KeyRange;

/// A signer that can produce public keys for requested indices.
///
/// A software wallet answers from its seed. A hardware signer would answer during
/// signing or an explicit refresh; that implementation is not part of this crate.
pub trait PublicKeySource {
    /// Why the source could not answer.
    type Error;

    /// Returns `(origin, public key)` pairs for the start of `range`, in index order.
    ///
    /// Returning fewer than requested is allowed; the pool asks again for the rest.
    fn public_keys(&mut self, range: KeyRange) -> Result<Vec<(KeyOrigin, PublicKey)>, Self::Error>;
}

/// Derives each requested key from the seed and keeps only its public half.
impl PublicKeySource for WalletSeed {
    type Error = Infallible;

    fn public_keys(&mut self, range: KeyRange) -> Result<Vec<(KeyOrigin, PublicKey)>, Self::Error> {
        Ok(range
            .origins()
            .map(|origin| (origin, self.derive_key(origin).public_key()))
            .collect())
    }
}
