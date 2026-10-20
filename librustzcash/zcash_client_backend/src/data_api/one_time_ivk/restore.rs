//! Resumable private recovery of derived receiver histories.
//!
//! Network work carries a generation captured before the request. Stores recheck it,
//! publication coverage and note inclusion before advancing progress or crediting funds.

use zakura_one_time_ivk::KeyId;
use zcash_protocol::consensus::BlockHeight;

use crate::data_api::transparent_ledger::ChainPoint;

pub mod recovery;

pub use zakura_receiver_crypto::wire::{
    PAYLOAD_BYTES as WITNESS_PAYLOAD_BYTES, Payment as DirectoryPayment,
    RawRecord as DirectoryRecord, decode_payload as decode_witness_payload,
    is_final as witness_is_final,
};

/// Maximum records accepted from one network step.
pub const RECOVERY_PAGE_LIMIT: usize = 32;
/// The receive issuance and seed-recovery gap, justified only by payments mined on the
/// wallet's current chain.
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
    /// The payment session.
    pub id: [u8; 32],
    /// The companion witness session captured with it, which candidates read under this
    /// publication must use.
    pub witnesses: [u8; 32],
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

/// A candidate waiting for its lower inclusion path. The ordinal is meaningful only in the
/// companion witness table of the payment table `payments` that returned the candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitnessRequest {
    pub key: KeyId,
    pub position: u32,
    pub cmx: [u8; 32],
    /// The identity of the payment session whose record carried `ordinal`.
    pub payments: [u8; 32],
    /// The companion witness session captured with that payment session. A witness-only
    /// replacement keeps `payments`, so this alone tells two companions apart.
    pub witnesses: [u8; 32],
    pub ordinal: u32,
}

/// An untrusted companion witness payload, with the witness revision and construction tree
/// it was served under. The wallet checks it against its own tree before crediting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessAnswer {
    /// The payment session the request named.
    pub payments: [u8; 32],
    /// The witness session that served `payload`.
    pub revision: [u8; 32],
    /// The block whose tree `payload` describes (see `decode_witness_payload`).
    pub context: PublicationEnd,
    pub payload: [u8; WITNESS_PAYLOAD_BYTES],
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
