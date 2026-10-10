//! Storage-neutral APIs for dynamic IVKs.
//!
//! A dynamic key (see [`zakura_dynamic_ivk`]) keeps its account's spending authority
//! with its own incoming viewing key, so the wallet trial-decrypts with a set of keys
//! that changes as keys open and close. A store that implements [`DynamicIvkWrite`] is
//! scanned with
//! [`scan_cached_blocks_with_dynamic_ivks`](super::chain::scan_cached_blocks_with_dynamic_ivks)
//! and [`decrypt_and_store_transaction_with_dynamic_ivks`], which try its open keys
//! alongside the account keys. A restored wallet cannot rescan public history for
//! every key its seed may have used, so it looks each recovered key up once in a
//! receiver directory instead: a restore sweep, run with the sweep steps of these
//! traits.
//!
//! [`decrypt_and_store_transaction_with_dynamic_ivks`]: super::wallet::decrypt_and_store_transaction_with_dynamic_ivks

use std::{collections::BTreeMap, num::NonZeroU32};

#[cfg(feature = "test-dependencies")]
use ambassador::delegatable_trait;
use zakura_dynamic_ivk::KeyId;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

use super::{
    ScannedBlock, WalletRead, WalletWrite, chain::ChainState, transparent_ledger::ChainPoint,
};
use crate::scanning::dynamic_ivk::DynamicScanningKey;

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
    /// A completed lookup whose payments are queued. Resume those first.
    pub lookup: Option<ChainPoint>,
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

/// What a publication's swap provider filters say about a swept key's receiver.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProviderView {
    /// A swap may still pay the receiver: the provider was given it within the wallet's
    /// restore watch, or the publication cannot rule that out.
    pub recent: bool,
    /// The provider was ever given the receiver as a payout address, so issuing it
    /// again would link two swaps.
    pub seen: bool,
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

/// Why [`DynamicIvkWrite::apply_dynamic_sweep`] stopped. Incomplete work stays queued
/// and never contributes to wallet balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentApplication {
    /// The wallet must finish scanning its current accepted tip.
    AwaitingScan,
    /// No usable inclusion path exists at the accepted anchor.
    AwaitingWitness,
    /// Locally retained history cannot establish absence of a spend.
    AwaitingSpendHistory,
    /// The authenticated note predates the account's birthday, so the wallet does not
    /// track it, as with any note before the birthday. Its inclusion is still checked
    /// against the wallet's chain; its key is then marked used, advancing and paid, so
    /// the index is never issued again and the lookahead and issuance bound move past it.
    BeforeBirthday,
    /// The directory's claim failed a local check: the note's block or inclusion path,
    /// or its transaction identity against stored data. The key's queued lookup is
    /// discarded, so its next attempt asks the directory again.
    Rejected,
    /// Note, witness, key identity, and any known spend were committed together, or the
    /// wallet already stored the note under another transaction. The retrieved memo is
    /// untrusted (see [`EncryptedNote::decrypt`]).
    ///
    /// [`EncryptedNote::decrypt`]: zakura_dynamic_ivk::recovery::EncryptedNote::decrypt
    Applied,
}

/// Dynamic IVK reads: the keys to scan with, and restore sweep state.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait DynamicIvkRead: WalletRead {
    /// Returns the dynamic keys to trial-decrypt in every scan batch.
    fn get_dynamic_scanning_keys(
        &self,
    ) -> Result<Vec<DynamicScanningKey<Self::AccountId>>, Self::Error>;

    /// Selects keys for full transaction decryption, retaining known-note ownership
    /// even after a key stops scanning. `receivers` come from ordinary authenticated
    /// decryption and preserve self-payments before compact scanning.
    /// Stores without a transaction index can conservatively return every registered key.
    fn get_dynamic_transaction_keys(
        &self,
        txid: TxId,
        height: Option<BlockHeight>,
        receivers: &[orchard::Address],
    ) -> Result<Vec<DynamicScanningKey<Self::AccountId>>, Self::Error>;

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
    /// whose note data [`DynamicIvkWrite::queue_directory_lookup`] needs.
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
    fn dynamic_history_pending(
        &self,
        account: Self::AccountId,
        through: BlockHeight,
    ) -> Result<bool, Self::Error>;
}

/// Dynamic IVK writes: storing blocks scanned with dynamic keys, and restore sweeps.
///
/// A restore sweep takes each due [`DiscoveryWork`] item from
/// [`Self::prepare_dynamic_sweeps`] and leases it with
/// [`Self::begin_dynamic_sweep_attempt`]. Unless its lookup is already queued, it looks
/// the item's receiver up in the directory, then retrieves note data for the positions
/// [`DynamicIvkRead::directory_note_data_needed`] returns and queues it with
/// [`Self::queue_directory_lookup`], in batches, until the lookup is done. Then it
/// calls [`Self::apply_dynamic_sweep`]. Each step commits atomically, so a caller may
/// stop between any two.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait DynamicIvkWrite: WalletWrite + DynamicIvkRead {
    /// Persists scanned blocks together with the dynamic keys that scanned them.
    ///
    /// `keys` must be the snapshot used for trial decryption, not a fresh lookup, so the
    /// store can requeue blocks that a key activated mid-batch missed. While a dynamic
    /// key is open, a store may refuse blocks from [`WalletWrite::put_blocks`], which
    /// were scanned without it.
    fn put_blocks_with_dynamic_ivks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<<Self as WalletRead>::AccountId>>,
        keys: &[(<Self as WalletRead>::AccountId, KeyId)],
    ) -> Result<(), <Self as WalletRead>::Error>;

    /// Keeps `account`'s dynamic key recovery current. Call when each sync starts,
    /// before planning scan work, and again once it reaches the tip.
    ///
    /// Retains Ironwood spend evidence from the account's birthday until
    /// [`Self::finish_dynamic_nullifier_recovery`] releases it; evidence pruned before
    /// the first call cannot be recovered without a rescan. Once scanning reaches the
    /// chain tip at or above Ironwood activation, it also registers refund keys from
    /// confirmed funding memos and keeps incoming lookahead keys above the highest
    /// restored index, each queued for one restore sweep.
    fn maintain_dynamic_ivks(
        &mut self,
        account: <Self as WalletRead>::AccountId,
    ) -> Result<(), <Self as WalletRead>::Error>;

    /// Selects at most `limit` of `account`'s sweeps due at `now`, in seconds, through
    /// `through`, the wallet's fully scanned tip, without reconstructing historical keys.
    /// Attempts are leased separately just before I/O, so a stopped batch cannot starve
    /// its tail.
    fn prepare_dynamic_sweeps(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        through: ChainPoint,
        now: i64,
        limit: NonZeroU32,
    ) -> Result<Result<Vec<DiscoveryWork>, SweepDeferral>, <Self as WalletRead>::Error>;

    /// Leases `key`'s sweep for an attempt at `now`, just before its network lookups.
    /// Every attempt, including one that fails or the process abandons, backs off the
    /// next.
    fn begin_dynamic_sweep_attempt(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        key: KeyId,
        now: i64,
    ) -> Result<(), <Self as WalletRead>::Error>;

    /// Queues the new payments in `payments`, the directory's complete lookup of `key` at
    /// `anchor` (from [`DynamicIvkRead::directory_publication_anchor`]), that have note
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
    /// `provider` is what the publication's provider filters say about the key's
    /// receiver. A recent key then scans from the block after the lookup until it closes,
    /// so a payment between the lookup and the tip is not missed. Any other key that was
    /// not already scanning closes at the lookup: no swap can still reach it, so nothing
    /// arrives in the publication's lag. A seen key is not issued again.
    fn apply_dynamic_sweep(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        key: KeyId,
        through: ChainPoint,
        publication: ChainPoint,
        provider: ProviderView,
        witness: impl FnMut(u32, [u8; 32]) -> Option<[[u8; 32]; 32]>,
    ) -> Result<Result<PaymentApplication, SweepDeferral>, <Self as WalletRead>::Error>;

    /// Releases retained Ironwood nullifiers at `through`, a canonical scanned tip, once
    /// no restore sweep needs them. Missing memos, pending sweeps and queued payments
    /// protect their evidence. Returns true when release reaches the tip.
    ///
    /// Restore discovery (see [`Self::maintain_dynamic_ivks`]) runs first, in the same
    /// transaction, so a payment at the lookahead's edge cannot race with pruning.
    fn finish_dynamic_nullifier_recovery(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        through: ChainPoint,
    ) -> Result<bool, <Self as WalletRead>::Error>;
}
