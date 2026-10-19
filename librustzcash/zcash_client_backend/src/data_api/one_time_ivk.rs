//! Storage-neutral APIs for one-time IVKs.
//!
//! A one-time key retains its account's spending authority with a separate incoming
//! viewing key. Production sync uses [`recovery::OneTimeBlockScan`] and full transaction
//! enhancement uses [`recovery::OneTimeTransactionScan`]. Both fence new discoveries by
//! the account's setting generation while preserving known-note repair.
//!
//! The legacy batch scanning and restore interfaces remain temporarily for callers
//! undergoing cutover. They must not be used by the independent filter scheduler.

use zakura_one_time_ivk::KeyId;
use zcash_protocol::consensus::BlockHeight;

#[cfg(feature = "test-dependencies")]
use ambassador::delegatable_trait;

use super::{ScannedBlock, WalletRead, WalletWrite, chain::ChainState};
use crate::scanning::one_time_ivk::OneTimeScanningKey;

pub mod recovery;
pub mod restore;

/// One-time IVK reads: the keys to scan and decrypt with.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeIvkRead: WalletRead {
    /// Returns every open one-time key, across all accounts. Scanning uses
    /// [`Self::get_one_time_scanning_keys_for_range`] instead, so this suits checking
    /// whether a key is still scanned.
    fn get_one_time_scanning_keys(
        &self,
    ) -> Result<Vec<OneTimeScanningKey<Self::AccountId>>, Self::Error>;

    /// Returns the one-time keys to trial-decrypt in a scan batch covering `range`: the
    /// open keys active by its end, and keys with a scan hint inside it (see
    /// [`restore::OneTimeIvkRestoreWrite::record_one_time_lookup`]).
    fn get_one_time_scanning_keys_for_range(
        &self,
        range: std::ops::Range<BlockHeight>,
    ) -> Result<Vec<OneTimeScanningKey<Self::AccountId>>, Self::Error>;
}

/// One-time IVK writes: storing blocks scanned with one-time keys.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeIvkWrite: WalletWrite + OneTimeIvkRead {
    /// Persists scanned blocks together with the one-time keys that scanned them.
    ///
    /// `keys` must be the snapshot used for trial decryption, not a fresh lookup, so the
    /// store can requeue blocks that a key activated mid-batch missed. While a one-time
    /// key is open, a store may refuse blocks from [`WalletWrite::put_blocks`], which
    /// were scanned without it.
    fn put_blocks_with_one_time_ivks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<<Self as WalletRead>::AccountId>>,
        keys: &[(<Self as WalletRead>::AccountId, KeyId)],
    ) -> Result<(), <Self as WalletRead>::Error>;
}
