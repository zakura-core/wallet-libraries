//! Byte-preserving conversions between candidate recovery and wallet hash representations.
use zakura_pir_protocol::transparent::recovery::RecoveryBlockHash;

/// A block hash that can cross into candidate recovery without changing byte order.
///
/// Implementations must preserve all 32 internal-order bytes. Conversion alone
/// neither validates a block nor establishes that a wallet accepted it.
pub trait RecoveryHash: Copy {
    fn into_recovery_hash(self) -> RecoveryBlockHash;
}

impl RecoveryHash for RecoveryBlockHash {
    fn into_recovery_hash(self) -> RecoveryBlockHash {
        self
    }
}

#[cfg(feature = "transparent-wallet")]
impl RecoveryHash for zcash_primitives::block::BlockHash {
    fn into_recovery_hash(self) -> RecoveryBlockHash {
        RecoveryBlockHash(self.0)
    }
}

#[cfg(feature = "sqlite")]
pub(crate) fn wallet_block_hash(hash: RecoveryBlockHash) -> zcash_primitives::block::BlockHash {
    zcash_primitives::block::BlockHash(hash.0)
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;

    #[test]
    fn wallet_conversion_preserves_bytes_and_display() {
        let original =
            zcash_primitives::block::BlockHash(core::array::from_fn(|index| index as u8));
        let recovery = original.into_recovery_hash();
        assert_eq!(original.0, recovery.0);
        assert_eq!(original.to_string(), recovery.to_string());
        assert_eq!(wallet_block_hash(recovery), original);
    }
}
