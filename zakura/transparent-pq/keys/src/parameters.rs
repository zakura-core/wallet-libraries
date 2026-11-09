/// Explicit selection of a supported standardized SLH-DSA configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ParameterSet {
    /// SHA2-128f, encoded as 1.
    Sha2_128f = 1,
    /// SHA2-192s, encoded as 2.
    Sha2_192s = 2,
}
impl ParameterSet {
    /// Length of each private/public seed component.
    pub const fn seed_bytes(self) -> usize {
        match self {
            Self::Sha2_128f => 16,
            Self::Sha2_192s => 24,
        }
    }
    /// Exact canonical public-key length.
    pub const fn public_key_bytes(self) -> usize {
        2 * self.seed_bytes()
    }
    /// Exact signature length, without a transaction hash selector.
    pub const fn signature_bytes(self) -> usize {
        match self {
            Self::Sha2_128f => 17_088,
            Self::Sha2_192s => 16_224,
        }
    }
    pub(crate) fn salt(self) -> &'static [u8] {
        match self {
            Self::Sha2_128f => b"Zcash/PQWallet/SLH-DSA-SHA2-128f/v2",
            Self::Sha2_192s => b"Zcash/PQWallet/SLH-DSA-SHA2-192s/v2",
        }
    }
}
