//! Storage-neutral APIs for one-time IVKs.
//!
//! A one-time key (see [`zakura_one_time_ivk`]) keeps its account's spending authority
//! with its own incoming viewing key, so the wallet trial-decrypts with a set of keys
//! that changes as keys open and close. A store that implements [`OneTimeIvkWrite`] is
//! scanned with
//! [`scan_cached_blocks_with_one_time_ivks`](super::chain::scan_cached_blocks_with_one_time_ivks)
//! and [`decrypt_and_store_transaction_with_one_time_ivks`], which try its open keys
//! alongside the account keys. Recovering keys from the seed after a restore is a
//! separate protocol, in [`restore`].
//!
//! [`decrypt_and_store_transaction_with_one_time_ivks`]: super::wallet::decrypt_and_store_transaction_with_one_time_ivks

use zakura_one_time_ivk::KeyId;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

#[cfg(feature = "test-dependencies")]
use ambassador::delegatable_trait;

use super::{ScannedBlock, WalletRead, WalletWrite, chain::ChainState};
use crate::scanning::one_time_ivk::OneTimeScanningKey;

pub mod restore;

/// One-time IVK reads: the keys to scan and decrypt with.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeIvkRead: WalletRead {
    /// Returns the one-time keys to trial-decrypt in every scan batch.
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

    /// Selects keys for full transaction decryption, retaining known-note ownership
    /// even after a key stops scanning. `receivers` come from ordinary authenticated
    /// decryption and preserve self-payments before compact scanning.
    /// Stores without a transaction index can conservatively return every registered key.
    fn get_one_time_transaction_keys(
        &self,
        txid: TxId,
        height: Option<BlockHeight>,
        receivers: &[orchard::Address],
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
