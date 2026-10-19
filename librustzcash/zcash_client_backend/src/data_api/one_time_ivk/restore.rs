//! The lookups and late payments of one-time key recovery (see [`super::coverage`]).
//!
//! A wallet cannot trial-decrypt public history with every key its seed may have used.
//! Instead it tests its receivers against a receiver directory's public paid sets, looks
//! the paid ones up over PIR, and turns each answer into a scan hint. A payment found after
//! the scan passed its block waits as a late candidate until the scan covers every block
//! from it on, then the spend journal decides whether it was spent. A store that
//! implements [`OneTimeIvkRestoreWrite`] keeps that state.
//!
//! A client derives receivers with [`OneTimeIvkRestoreRead::one_time_receivers`], applies
//! each lookup's pages with
//! [`OneTimeIvkCoverageWrite::record_one_time_lookup_page`](super::coverage::OneTimeIvkCoverageWrite::record_one_time_lookup_page),
//! backs a failed one off with [`OneTimeIvkRestoreWrite::defer_one_time_lookup`], and
//! records each late candidate's inclusion path with
//! [`OneTimeIvkRestoreWrite::record_one_time_witness`]. Each call commits atomically, so a
//! caller may stop between any two.

#[cfg(feature = "test-dependencies")]
use ambassador::delegatable_trait;
use zakura_one_time_ivk::{KeyId, Purpose};
use zcash_protocol::consensus::BlockHeight;

use super::{OneTimeIvkRead, OneTimeIvkWrite};
use crate::data_api::{WalletRead, transparent_ledger::ChainPoint};

pub mod recovery;

/// A key whose receiver recovery tests or looks up. Public metadata is not note
/// ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryWork {
    /// Derivation identity. Derive only when authenticating returned notes.
    pub key: KeyId,
    /// The key's receiver, as canonical address bytes.
    pub receiver: [u8; 43],
}

/// A payment the receiver directory reports for a receiver, from public block data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryPayment {
    /// Height of the block containing the payment.
    pub height: u32,
    /// Hash of that block.
    pub block_hash: [u8; 32],
    /// Transaction ID.
    pub txid: [u8; 32],
    /// Transaction index within the block.
    pub tx_index: u32,
    /// Action index within the transaction.
    pub action_index: u32,
    /// Note commitment tree position.
    pub position: u64,
    /// The action's input nullifier, not the received note's spend nullifier.
    pub action_nullifier: [u8; 32],
    /// Note commitment.
    pub cmx: [u8; 32],
    /// Ephemeral key.
    pub ephemeral_key: [u8; 32],
    /// The first 52 bytes of the note ciphertext.
    pub ciphertext_prefix: [u8; 52],
}

/// The end of a receiver-directory publication as its manifest declares it. The store
/// judges it against its own chain once the scan stores that block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationEnd {
    /// The last block the publication covers.
    pub height: BlockHeight,
    /// That block's hash, in internal byte order.
    pub hash: [u8; 32],
    /// The Ironwood note commitment tree size after that block.
    pub tree_size: u64,
}

/// A paid key whose history is due for a lookup, with where its paging resumes.
///
/// A receiver's records are ordered by commitment position. The lookup reads pages from
/// `applied`, after checking that the record just before it is still `last`, and applies
/// every record at or below `cutoff`. It is complete once it reads a record above the
/// cutoff or the last page, or page zero is absent. A record before the cursor that changed
/// restarts it from page zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupWork {
    /// The key and its receiver.
    pub work: DiscoveryWork,
    /// The last block whose records this lookup applies.
    pub cutoff: BlockHeight,
    /// How many of the receiver's records are applied.
    pub applied: u32,
    /// The commitment position and Action nullifier of the last applied record.
    pub last: Option<(u64, [u8; 32])>,
}

/// A late candidate waiting for its inclusion path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitnessRequest {
    /// The key the payment is to.
    pub key: KeyId,
    /// The note commitment's tree position.
    pub position: u32,
    /// The note commitment.
    pub cmx: [u8; 32],
}

/// One-time IVK recovery reads.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeIvkRestoreRead: OneTimeIvkRead {
    /// The receivers of `account`'s keys `from` through `from + count - 1` for
    /// `purpose`, without registering them.
    fn one_time_receivers(
        &self,
        account: Self::AccountId,
        purpose: Purpose,
        from: u64,
        count: u32,
    ) -> Result<Vec<DiscoveryWork>, Self::Error>;
}

/// One-time IVK recovery writes.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeIvkRestoreWrite: OneTimeIvkWrite + OneTimeIvkRestoreRead {
    /// Backs `key`'s due lookup off after a failed attempt at `now`.
    fn defer_one_time_lookup(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        key: KeyId,
        now: i64,
    ) -> Result<(), <Self as WalletRead>::Error>;

    /// Records the inclusion path of `key`'s late candidate at `position`, a path to the
    /// root at `anchor`, and admits it if the scan covers it. A path whose anchor is not on
    /// the wallet's chain, or more than the pruning depth below its scanned tip, is
    /// requested again. `now` is the caller's clock in seconds.
    fn record_one_time_witness(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        key: KeyId,
        position: u32,
        anchor: ChainPoint,
        siblings: [[u8; 32]; 32],
        now: i64,
    ) -> Result<(), <Self as WalletRead>::Error>;
}
