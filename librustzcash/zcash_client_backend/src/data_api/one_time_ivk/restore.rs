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

/// One captured inventory: its identity and the history it covers. Every cursor and
/// completion is relative to the inventory it was captured under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryPublication {
    /// The inventory identity.
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

/// Where a request stopped inside one captured inventory: a shard, one of its segments,
/// and the last page read there. Meaningless under any other inventory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupCursor {
    pub inventory: [u8; 32],
    pub shard: u32,
    pub segment: u32,
    /// The last record read in that segment; pages are segment-local.
    pub last: Option<DirectoryRecord>,
}

/// One pending address history, independent of why it was queued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupWork {
    pub token: RecoveryToken,
    pub work: DiscoveryWork,
    /// History below this height is already checked for this request. A shard reaching
    /// it is read whole.
    pub from: BlockHeight,
    /// An answer below this height cannot complete the request.
    pub through: BlockHeight,
    pub cursor: Option<LookupCursor>,
}

/// The payment and witness sessions of the segment a step read, which bind its records'
/// ordinals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentRef {
    pub shard: u32,
    pub segment: u32,
    pub payments: [u8; 32],
    /// The segment's companion witness session, which its candidates must use.
    pub witnesses: [u8; 32],
}

/// One bounded step against one captured inventory: shards a negative filter excluded,
/// then consecutive pages of at most one segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupPage {
    pub publication: RecoveryPublication,
    /// The segment `records` come from, if the step read one.
    pub segment: Option<SegmentRef>,
    pub records: Vec<DirectoryRecord>,
    /// Every required shard ending at or below this height is covered: excluded by a
    /// validated filter of this inventory or read through its final page in every segment.
    pub checked_through: Option<BlockHeight>,
    /// Where the next step resumes; `None` once every required shard is covered.
    pub next: Option<LookupCursor>,
}

impl LookupPage {
    /// Whether every shard the request needs is covered through the inventory's end.
    pub fn complete(&self) -> bool {
        self.next.is_none()
    }
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
    /// The receiver service needs a newer client. No work is exposed until a capture this
    /// client supports begins recovery again; every pending request is kept.
    pub upgrade_required: bool,
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
