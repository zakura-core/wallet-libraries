use core::fmt;

/// A block hash in the wallet's internal byte order.
///
/// Converting to or from a wallet hash copies the bytes without reversal. Display
/// uses reversed hexadecimal, matching block explorers and the existing wallet.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryBlockHash(pub [u8; 32]);

impl RecoveryBlockHash {
    /// Copies a hash from exactly 32 internal-order bytes; rejects other lengths.
    pub fn try_from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self(bytes.try_into().ok()?))
    }

    /// Copies exactly 32 internal-order bytes, panicking for any other length.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::try_from_slice(bytes).expect("a block hash contains exactly 32 bytes")
    }
}

impl fmt::Display for RecoveryBlockHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = self.0;
        bytes.reverse();
        formatter.write_str(&hex::encode(bytes))
    }
}

impl fmt::Debug for RecoveryBlockHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BlockHash")
            .field(&self.to_string())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::RecoveryBlockHash;

    #[test]
    fn internal_bytes_and_display_order_are_distinct() {
        let bytes = core::array::from_fn(|index| index as u8);
        let hash = RecoveryBlockHash::try_from_slice(&bytes).unwrap();
        assert_eq!(hash.0, bytes);
        assert_eq!(
            hash.to_string(),
            "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        );
        assert!(RecoveryBlockHash::try_from_slice(&bytes[..31]).is_none());
    }
}
