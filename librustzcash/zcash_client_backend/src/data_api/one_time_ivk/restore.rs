//! The one-time IVK restore protocol.
//!
//! A restored wallet cannot rescan public history for every key its seed may have
//! used, so it looks each recovered key up once in a receiver directory instead: a
//! restore sweep. A store that implements [`OneTimeIvkRestoreWrite`] runs one.
//!
//! A sweep takes each due [`DiscoveryWork`] item from
//! [`OneTimeIvkRestoreWrite::prepare_one_time_sweeps`] and leases it with
//! [`OneTimeIvkRestoreWrite::begin_one_time_sweep_attempt`]. Every attempt looks the
//! item's receiver up in the directory's current publication, then retrieves note
//! data for the positions [`OneTimeIvkRestoreRead::directory_note_data_needed`]
//! returns and queues it with [`OneTimeIvkRestoreWrite::queue_directory_lookup`], in
//! batches, until the lookup is done. Then it calls
//! [`OneTimeIvkRestoreWrite::apply_one_time_sweep`]. Each step commits atomically, so
//! a caller may stop between any two.

use std::{collections::BTreeMap, num::NonZeroU32};

#[cfg(feature = "test-dependencies")]
use ambassador::delegatable_trait;
use zakura_one_time_ivk::KeyId;
use zcash_protocol::consensus::BlockHeight;

use super::{OneTimeIvkRead, OneTimeIvkWrite};
use crate::data_api::{WalletRead, transparent_ledger::ChainPoint};

pub mod recovery;

/// A directory publication more than this many blocks behind the wallet's scanned tip
/// is stale: finishing sweeps at it would leave a long rescan behind.
pub const MAX_PUBLICATION_LAG: u32 = 100;

/// One recovered key's due restore sweep. Public metadata is not note ownership.
#[derive(Clone, PartialEq, Eq)]
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

/// Why a restore sweep step must wait for more scanning or a newer publication. The
/// step changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SweepDeferral {
    /// A block the step relies on is not on the wallet's scanned chain.
    UnknownAnchor,
    /// The publication is more than [`MAX_PUBLICATION_LAG`] blocks behind the wallet.
    StalePublication,
}

/// Why [`OneTimeIvkRestoreWrite::apply_one_time_sweep`] stopped. Incomplete work stays queued
/// and never contributes to wallet balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentApplication {
    /// The wallet must finish scanning its current accepted tip.
    AwaitingScan,
    /// No usable inclusion path exists at the accepted anchor.
    AwaitingWitness,
    /// Locally retained history cannot establish absence of a spend.
    AwaitingSpendHistory,
    /// The directory's claim failed a local check: the note's block or inclusion path,
    /// or its transaction identity against stored data. The key's queued lookup is
    /// discarded.
    Rejected,
    /// Note, witness, key identity, and any known spend were committed together, or the
    /// wallet already stored the note under another transaction, or the note predates
    /// the account's birthday and, as with any such note, is not tracked. No memo is
    /// stored (see [`EncryptedNote::decrypt`]).
    ///
    /// [`EncryptedNote::decrypt`]: recovery::EncryptedNote::decrypt
    Applied,
}

/// One-time IVK restore reads: sweep and recheck state.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeIvkRestoreRead: OneTimeIvkRead {
    /// The anchor of a directory publication covering blocks through `height`, as the
    /// wallet's own chain records it. `through` is the wallet's fully scanned tip. Defers
    /// a block the wallet has not scanned, and one more than [`MAX_PUBLICATION_LAG`]
    /// blocks below `through`.
    fn directory_publication_anchor(
        &self,
        height: BlockHeight,
        through: ChainPoint,
    ) -> Result<Result<ChainPoint, SweepDeferral>, Self::Error>;

    /// The commitment tree positions of `payments`, the directory's lookup for `key`,
    /// whose note data [`OneTimeIvkRestoreWrite::queue_directory_lookup`] needs.
    /// Payments already imported or queued unchanged need none. A payment that
    /// contradicts an imported output is an error; one that corrects a queued candidate
    /// needs data.
    fn directory_note_data_needed(
        &self,
        account: Self::AccountId,
        key: KeyId,
        payments: &[DirectoryPayment],
    ) -> Result<Vec<u64>, Self::Error>;

    /// Whether `account` still has restore sweeps or queued payments through `through`.
    /// Retry backoff never makes an unfinished restore appear complete.
    fn one_time_history_pending(
        &self,
        account: Self::AccountId,
        through: BlockHeight,
    ) -> Result<bool, Self::Error>;

    /// `account`'s closed keys with no known payment that no paid filter at or above
    /// `height` has checked, for [`OneTimeIvkRestoreWrite::record_paid_filter_check`].
    fn one_time_keys_to_recheck(
        &self,
        account: Self::AccountId,
        height: BlockHeight,
    ) -> Result<Vec<DiscoveryWork>, Self::Error>;
}

/// One-time IVK restore writes: key recovery, restore sweeps (see the
/// [module documentation](self)), and release of the spend evidence they retain.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeIvkRestoreWrite: OneTimeIvkWrite + OneTimeIvkRestoreRead {
    /// Keeps `account`'s one-time key recovery current. Call when each sync starts,
    /// before planning scan work, and again once it reaches the tip.
    ///
    /// Retains Ironwood spend evidence from the account's birthday until
    /// [`Self::finish_one_time_nullifier_recovery`] releases it; evidence pruned before
    /// the first call cannot be recovered without a rescan. Once scanning reaches the
    /// chain tip at or above Ironwood activation, it also registers refund keys from
    /// confirmed funding memos and keeps incoming lookahead keys above the highest
    /// restored index, each queued for one restore sweep.
    fn maintain_one_time_ivks(
        &mut self,
        account: <Self as WalletRead>::AccountId,
    ) -> Result<(), <Self as WalletRead>::Error>;

    /// Selects at most `limit` of `account`'s sweeps due at `now`, in seconds, through
    /// `through`, the wallet's fully scanned tip, without reconstructing historical keys.
    /// Attempts are leased separately just before I/O, so a stopped batch cannot starve
    /// its tail.
    fn prepare_one_time_sweeps(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        through: ChainPoint,
        now: i64,
        limit: NonZeroU32,
    ) -> Result<Result<Vec<DiscoveryWork>, SweepDeferral>, <Self as WalletRead>::Error>;

    /// Leases `key`'s sweep for an attempt at `now`, just before its network lookups.
    /// Every attempt, including one that fails or the process abandons, backs off the
    /// next.
    ///
    /// `seen` is whether a swap provider seen set in the current publication holds the
    /// key's receiver: the provider was given it as a payout address, so the key is never
    /// issued again and restore lookahead advances past it. A hit is stored with the
    /// lease, before any lookup or payment work, and is never cleared; `false` changes
    /// nothing.
    fn begin_one_time_sweep_attempt(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        key: KeyId,
        now: i64,
        seen: bool,
    ) -> Result<(), <Self as WalletRead>::Error>;

    /// Queues the new payments in `payments`, the directory's complete lookup of `key` at
    /// `anchor` (from [`OneTimeIvkRestoreRead::directory_publication_anchor`]), that have note
    /// data in `note_data`: the 528 ciphertext bytes after the directory's prefix, by
    /// position. Nothing is credited yet. Returns whether the lookup is done, which it is
    /// once no payment lacks note data; until then the next attempt looks the receiver
    /// up again and asks only for the rest. Queued candidates that `payments` no longer
    /// repeats unchanged, from an earlier answer the directory has since corrected, are
    /// dropped.
    fn queue_directory_lookup(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        key: KeyId,
        anchor: ChainPoint,
        payments: &[DirectoryPayment],
        note_data: &BTreeMap<u64, [u8; 528]>,
    ) -> Result<Result<bool, SweepDeferral>, <Self as WalletRead>::Error>;

    /// Applies `key`'s queued payments with inclusion paths at `publication`, then
    /// finishes its sweep at its lookup's anchor. `witness` returns the 32 sibling hashes
    /// for a commitment tree position and note commitment, or `None` when the publication
    /// has none. `through` is the wallet's fully scanned tip. Returns
    /// [`PaymentApplication::Applied`] once the sweep is finished, or why a payment must
    /// wait or was rejected; payments applied before it stay applied. A lookup a reorg
    /// removed defers the sweep to run again.
    ///
    /// `recent` is whether a current, complete swap provider recent set holds the key's
    /// receiver, so a swap may still pay it. A recent key then scans from the block after
    /// the lookup, rescanning blocks scanned without it, until the store's restore watch
    /// closes it. Any other key that was not already scanning closes at the lookup; a
    /// later payment to it is found by [`Self::record_paid_filter_check`].
    fn apply_one_time_sweep(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        key: KeyId,
        through: ChainPoint,
        publication: ChainPoint,
        recent: bool,
        witness: impl FnMut(u32, [u8; 32]) -> Option<[[u8; 32]; 32]>,
    ) -> Result<Result<PaymentApplication, SweepDeferral>, <Self as WalletRead>::Error>;

    /// Records a newer publication's paid filter against keys from
    /// [`OneTimeIvkRestoreRead::one_time_keys_to_recheck`]: `checked` pairs each key with whether
    /// the filter holds its receiver. A key it holds may have been paid after it stopped
    /// scanning, so a sweep of it is queued; any other has no payment through
    /// `publication`, which is recorded so the same publication is not checked again.
    /// Does nothing unless `publication` is on the wallet's chain.
    fn record_paid_filter_check(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        publication: ChainPoint,
        checked: &[(KeyId, bool)],
    ) -> Result<(), <Self as WalletRead>::Error>;

    /// Releases retained Ironwood nullifiers at `through`, a canonical scanned tip, once
    /// no restore sweep needs them. Missing memos, pending sweeps and queued payments
    /// protect their evidence. Returns true when release reaches the tip.
    ///
    /// Restore discovery (see [`Self::maintain_one_time_ivks`]) runs first, in the same
    /// transaction, so a payment at the lookahead's edge cannot race with pruning.
    fn finish_one_time_nullifier_recovery(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        through: ChainPoint,
    ) -> Result<bool, <Self as WalletRead>::Error>;
}
