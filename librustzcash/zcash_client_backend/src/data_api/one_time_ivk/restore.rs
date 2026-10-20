//! Resumable private recovery of derived receiver histories.
//!
//! Network work carries a generation captured before the request. Stores recheck it,
//! publication coverage and note inclusion before advancing progress or crediting funds.

use zakura_one_time_ivk::KeyId;
use zcash_protocol::consensus::BlockHeight;

use crate::data_api::transparent_ledger::ChainPoint;

pub mod recovery;

pub use zakura_receiver_crypto::wire::{Payment as DirectoryPayment, RawRecord as DirectoryRecord};

/// Maximum records accepted from one network step.
pub const RECOVERY_PAGE_LIMIT: usize = 32;
/// The receive issuance and seed-recovery gap, justified only by confirmed payments.
pub const RECEIVE_GAP: u64 = 4;

/// Account-local cancellation and same-chain correction fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryToken {
    pub generation: u64,
    pub history_revision: u64,
}

/// The locally checked end of a receiver publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationEnd {
    pub height: BlockHeight,
    pub hash: [u8; 32],
    pub tree_size: u64,
}

/// Identity and full-history coverage of the session answering a lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryPublication {
    pub id: [u8; 32],
    pub history_revision: u64,
    pub start_height: BlockHeight,
    pub end: PublicationEnd,
}

/// A locally derived receiver. Its purpose and index never leave the wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryWork {
    pub key: KeyId,
    pub receiver: [u8; 43],
}

/// One pending address history, independent of why it was queued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupWork {
    pub token: RecoveryToken,
    pub work: DiscoveryWork,
    /// An answer below this height cannot complete the request.
    pub through: BlockHeight,
    /// Last accepted record. A new session must reproduce its payment before continuing.
    pub last: Option<DirectoryRecord>,
}

/// A bounded consecutive slice from one immutable PIR session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupPage {
    pub publication: RecoveryPublication,
    /// The new session's copy of the saved cursor, including its current total.
    pub previous: Option<DirectoryRecord>,
    pub records: Vec<DirectoryRecord>,
    /// True only for a genuine empty page zero or the final advertised page.
    pub complete: bool,
}

/// A candidate waiting for a proof against a locally known tree root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitnessRequest {
    pub key: KeyId,
    pub position: u32,
    pub cmx: [u8; 32],
}

/// Resumable explicit historical search. Refund indexes are only the known funded keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManualProgress {
    pub active: bool,
    pub refunds_done: bool,
    pub next: u64,
    /// Exclusive receive-index bound, never shortened by the ordinary four-empty rule.
    pub receive_end: u64,
}

/// One account's durable progress and a bounded batch of due work.
/// With discovery disabled, work is restricted to repairing already-owned receipts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryStatus {
    pub enabled: bool,
    pub token: RecoveryToken,
    pub filter_frontier: Option<ChainPoint>,
    /// Direct catch-up deliberately skipped completed old addresses through this height.
    pub skipped_through: Option<BlockHeight>,
    pub restore_next: u64,
    pub restore_gap: u8,
    pub restore_complete: bool,
    pub manual: Option<ManualProgress>,
    pub lookups: Vec<LookupWork>,
    pub witnesses: Vec<WitnessRequest>,
}
