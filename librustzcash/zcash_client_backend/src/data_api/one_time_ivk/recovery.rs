//! Durable filter recovery, independent of ordinary scan progress.
//!
//! Each receiver owns a historical cursor. Advancing a cursor commits its positive
//! matches in the same transaction. Exact local scan evidence can settle individual
//! matches without erasing older work for that receiver. Callers validate archive
//! proofs and their connected-chain anchor before submitting judgments.
pub mod cache;

use super::restore::DiscoveryWork;
use crate::{
    data_api::{ScannedBlock, WalletRead, chain::ChainState, transparent_ledger::ChainPoint},
    scanning::one_time_ivk::OneTimeScanningKey,
};
use zakura_one_time_ivk::{KeyId, Purpose};
use zcash_protocol::consensus::BlockHeight;

/// The durable server history whose negative judgments the wallet accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct History {
    pub genesis: [u8; 32],
    pub archive: [u8; 32],
    pub epoch: u64,
}

/// Captured before async work and checked again at commit. Receiver additions change
/// `keys`; settings, reorgs and history resets change `work`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fence {
    pub history: History,
    pub keys: u64,
    pub work: u64,
}

/// A bounded group of receivers that need the same next block. Derivation itself
/// neither reserves nor exposes their addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterWork<AccountId> {
    pub account: AccountId,
    pub fence: Fence,
    pub next_height: BlockHeight,
    pub receivers: Vec<DiscoveryWork>,
}

/// One verified filter's positive matches, restricted to the captured receiver group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterJudgment {
    pub block: ChainPoint,
    pub hits: Vec<KeyId>,
}

/// A receiver/block obligation, retained until exact local scanning or compatible
/// complete PIR recovery settles it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingMatch {
    pub receiver: DiscoveryWork,
    pub block: ChainPoint,
}

/// Derivation progress for one purpose, with an exclusive upper index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub purpose: Purpose,
    pub end: u128,
    pub derived: u128,
}

/// Recovery status. Ordinary wallet scan height is deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryState {
    pub enabled: bool,
    pub needs_prepare: bool,
    pub history: Option<History>,
    pub keys: u64,
    pub work: u64,
    pub windows: [Window; 2],
    pub next_height: Option<BlockHeight>,
    pub pending_matches: u64,
}

#[cfg(feature = "test-dependencies")]
use ambassador::delegatable_trait;

/// Reads pending recovery without treating ordinary chain progress as discovery evidence.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeRecoveryRead: super::OneTimeIvkRead {
    /// Returns durable state, including paused work when discovery is disabled.
    fn one_time_recovery_state(
        &self,
        account: <Self as WalletRead>::AccountId,
    ) -> Result<Option<RecoveryState>, <Self as WalletRead>::Error>;
    /// Selects only keys with locally recorded operations inside their immutable watch limit.
    fn one_time_local_watch_keys(
        &self,
        range: std::ops::Range<BlockHeight>,
        now: i64,
    ) -> Result<Vec<OneTimeScanningKey<<Self as WalletRead>::AccountId>>, <Self as WalletRead>::Error>;
    /// Captures at most `limit` receivers at the earliest outstanding filter height.
    fn one_time_filter_work(
        &self,
        account: <Self as WalletRead>::AccountId,
        limit: u32,
    ) -> Result<Option<FilterWork<<Self as WalletRead>::AccountId>>, <Self as WalletRead>::Error>;
    /// Returns bounded outstanding positive matches in oldest-first order while enabled.
    fn one_time_pending_matches(
        &self,
        account: <Self as WalletRead>::AccountId,
        limit: u32,
    ) -> Result<Vec<PendingMatch>, <Self as WalletRead>::Error>;
}

/// Atomic state transitions for validated filter results. Proof validation belongs to
/// the recovery client; these writes recheck account, history and captured generations.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeRecoveryWrite: OneTimeRecoveryRead + super::OneTimeIvkWrite {
    /// Pauses or resumes this account's discovery without discarding pending work or known funds.
    fn set_one_time_recovery_enabled(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        enabled: bool,
    ) -> Result<(), <Self as WalletRead>::Error>;
    /// Recovers stored memo keys and derives at most `budget` window receivers while enabled.
    fn prepare_one_time_recovery(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        budget: u32,
        now: i64,
    ) -> Result<bool, <Self as WalletRead>::Error>;
    /// Accepts an independently anchored history. A new identity or increased epoch resets
    /// filter cursors but preserves exact chain-scan evidence. Same-identity rollback is refused.
    fn accept_one_time_history(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        history: History,
    ) -> Result<bool, <Self as WalletRead>::Error>;
    /// Commits contiguous judgments and all resulting matches together, or returns false
    /// without changes when disabled or the captured work is stale.
    fn record_one_time_filters(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        work: &FilterWork<<Self as WalletRead>::AccountId>,
        judgments: &[FilterJudgment],
    ) -> Result<bool, <Self as WalletRead>::Error>;
}

/// Ready public-filter hints for one exact downloaded block. Hints authorize trial
/// decryption only. They do not advance historical cursors or prove ownership.
#[derive(Clone, Debug)]
pub struct BlockHints<A> {
    pub block: ChainPoint,
    pub keys: Vec<(A, KeyId)>,
}

/// One account's discovery generation captured before local trial decryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanPermit<A> {
    pub account: A,
    pub key: KeyId,
    pub work: u64,
}

/// The exact keys and generation permits used to scan one canonical block. Keys with
/// no permit are for repairing already-known receipts only, including while disabled.
pub struct BlockScan<A> {
    pub block: ChainPoint,
    pub keys: Vec<OneTimeScanningKey<A>>,
    pub permits: Vec<ScanPermit<A>>,
}

/// Block-scoped scanning with a commit-time discovery fence. Network requests belong
/// to the independent recovery scheduler and cannot be part of either operation.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeBlockScan: OneTimeRecoveryWrite {
    /// Selects current own-swap watches, exact pending/ready matches and known receipt
    /// repair keys. A ready key outside the derived registry/window is refused.
    fn prepare_one_time_block_scan(
        &mut self,
        block: ChainPoint,
        ready: &[(<Self as WalletRead>::AccountId, KeyId)],
    ) -> Result<BlockScan<<Self as WalletRead>::AccountId>, <Self as WalletRead>::Error>;

    /// Stores normal chain progress even if discovery was paused during trial
    /// decryption. Stale permits may repair known receipts but cannot add new ones or
    /// record full scan evidence. Valid permits commit exact key/block evidence.
    fn put_blocks_with_recovery(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<<Self as WalletRead>::AccountId>>,
        scanned: &[BlockScan<<Self as WalletRead>::AccountId>],
    ) -> Result<(), <Self as WalletRead>::Error>;
}
