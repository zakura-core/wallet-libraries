//! Transparent txid enhancement: durable work to fetch a transaction's transparent details by
//! txid, validated display facts, and their read view.
//!
//! These facts are display only. They never change balances, spendability, history
//! classification, or `details_complete`; see `docs/transparent-txid-enhancement.md`.

use std::time::{Duration, SystemTime};

use transparent::address::TransparentAddress;
use zcash_primitives::transaction::TxId;
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use super::{TransactionMetadata, TransparentLedgerMode, WholeTransactionFee};

/// Why the wallet wants a transaction's transparent details, as a set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TransparentDetailReasons(u8);

impl TransparentDetailReasons {
    /// An owned transparent output was recovered without the transaction.
    pub const RECEIVE: Self = Self(1);
    /// An owned transparent output was spent by the transaction.
    pub const SPEND: Self = Self(2);
    /// A mixed transaction's transparent details are not available from Enhance PIR.
    pub const MIXED: Self = Self(4);

    /// Reasons from their stored bits; unknown bits are dropped.
    pub fn from_bits(bits: u8) -> Self {
        Self(bits & 7)
    }

    /// The stored bits.
    pub fn bits(self) -> u8 {
        self.0
    }

    /// Whether every reason in `other` is present.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for TransparentDetailReasons {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// A due lookup of one transaction's transparent details.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentDetailRequest {
    /// The transaction to look up.
    pub txid: TxId,
    /// Its mined height, which selects the covering display shard.
    pub mined_height: BlockHeight,
    /// Why the wallet wants it.
    pub reasons: TransparentDetailReasons,
}

/// The due lookups, with the policy they were listed under.
///
/// The mode and generation are read in the same snapshot as the requests. The caller fetches
/// publicly (lightwalletd `GetTransaction`) only when [`Self::public_transport`] holds and the
/// generation is still the wallet's current one; otherwise only through the txid display
/// service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentDetailWork {
    /// The wallet handle's resolved transparent ledger mode.
    pub mode: TransparentLedgerMode,
    /// The durable policy generation (`0` before any policy was applied).
    pub policy_generation: u64,
    /// The due lookups, in priority order.
    pub requests: Vec<TransparentDetailRequest>,
}

impl TransparentDetailWork {
    /// Whether these requests may be fetched over public transport.
    pub fn public_transport(&self) -> bool {
        self.mode.retains_public_authority()
    }
}

/// How often, at most, parked lookups ask the caller to re-check the display map.
pub const TRANSPARENT_DISPLAY_MAP_RECHECK: Duration = Duration::from_secs(6 * 3600);

/// Lookups held only until the display map changes or the backstop interval passes.
///
/// When nothing is due, `count > 0` and `refresh_at` has passed, the caller re-checks coverage
/// by refreshing its display map and listing again with the new map hash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransparentDetailParked {
    /// The number of lookups parked under the caller's map.
    pub count: u64,
    /// The map hash recorded by the longest-parked lookup, when it had one.
    pub oldest_map_sha256: Option<[u8; 32]>,
    /// When a map refresh could next change something: [`TRANSPARENT_DISPLAY_MAP_RECHECK`] after
    /// the later of the caller's last map check and the newest parked lookup. `None` when
    /// nothing is parked.
    pub refresh_at: Option<SystemTime>,
}

/// One transparent output as published, at its position in the transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentDisplayOutput {
    /// The output value.
    pub value: Zatoshis,
    /// The raw locking script.
    pub script: Vec<u8>,
}

/// Where display facts were looked up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentDisplayProvenance {
    /// The absolute id of the display shard that answered.
    pub shard_id: u64,
    /// That shard's revision.
    pub revision: u32,
    /// SHA-256 of the display map the lookup used.
    pub map_sha256: [u8; 32],
    /// The mined height the lookup selected the shard by.
    pub looked_up_height: BlockHeight,
}

/// A transaction's transparent facts from a trusted display publisher, before validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentDisplayFacts {
    /// The transaction.
    pub txid: TxId,
    /// Whether it is a coinbase transaction.
    pub coinbase: bool,
    /// Its fee, transparent input count and shielded bit.
    pub metadata: TransactionMetadata,
    /// Every transparent output, in transaction order.
    pub outputs: Vec<TransparentDisplayOutput>,
    /// Where they came from.
    pub provenance: TransparentDisplayProvenance,
}

/// Which wallet fact the display facts contradict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransparentDisplayContradiction {
    /// The coinbase flag disagrees with the transaction's known position or recovered events,
    /// or the metadata is not valid for it.
    Coinbase,
    /// An owned output is present with another value or script.
    OwnedOutput {
        /// The output index.
        index: u32,
    },
    /// An owned output's index is beyond the published outputs.
    OutputIndexOutOfRange {
        /// The output index.
        index: u32,
    },
    /// Recovered transaction metadata differs.
    Metadata,
    /// The stored fee differs.
    Fee,
    /// The shielded bit is clear while the wallet knows a shielded component.
    Shielded,
    /// A known spend's input index is not below the transparent input count.
    InputIndex {
        /// The input index.
        index: u32,
    },
    /// The wallet knows more distinct spent outpoints than the transparent input count.
    InputCount {
        /// The number of distinct outpoints the wallet knows the transaction spends.
        known: u32,
    },
}

/// The result of storing display facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransparentDisplayStore {
    /// The facts were validated and saved; the work is done.
    Stored,
    /// Raw bytes are already stored, or the wallet neither wants nor relates to the
    /// transaction; nothing was saved.
    Superseded,
    /// The facts contradict the wallet; nothing was saved. When the looked-up height still
    /// matches the transaction's mined height, the work is parked until the display map
    /// changes; otherwise retry state is unchanged.
    Contradiction(TransparentDisplayContradiction),
}

/// Why a lookup did not produce storable facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransparentDetailOutcome {
    /// Transport failure, overload or a stale revision; retried with capped exponential
    /// backoff, never sooner than `retry_after`.
    Unavailable {
        /// A server-advised minimum delay.
        retry_after: Option<Duration>,
    },
    /// The mined height is above the newest published shard: the transaction is newer than
    /// the publication. Retried after minutes; the view stays pending.
    NotYetPublished,
    /// The covering shard has no record for the txid; retried after hours.
    Absent,
    /// No display shard covers the mined height (it is below the publication); held until the
    /// map changes.
    NotCovered,
    /// The service does not offer display lookups; held until any display map is seen.
    Unsupported,
    /// The service answered with something unusable; retried like `Unavailable`.
    Protocol,
    /// The caller found the facts inconsistent; held until the map changes.
    Contradiction,
}

/// Where available details came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransparentDisplaySource {
    /// The wallet's stored raw transaction.
    RawTransaction,
    /// Validated facts from the display service.
    Display(TransparentDisplayProvenance),
}

/// One output of the detail view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentDisplayViewOutput {
    /// Its position in the transaction.
    pub index: u32,
    /// Its value.
    pub value: Zatoshis,
    /// Its raw locking script.
    pub script: Vec<u8>,
    /// The address, when the script is a standard P2PKH or P2SH script.
    pub address: Option<TransparentAddress>,
    /// Whether the viewing account received it.
    pub owned: bool,
}

/// A transaction's transparent details.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentDisplayDetails {
    /// Every transparent output, in order.
    pub outputs: Vec<TransparentDisplayViewOutput>,
    /// Whether it is a coinbase transaction.
    pub coinbase: bool,
    /// The whole-transaction fee.
    pub fee: WholeTransactionFee,
    /// Non-coinbase transparent inputs, including other parties'.
    pub input_count: u32,
    /// Whether any shielded component is present.
    pub shielded: bool,
    /// Where these details came from.
    pub source: TransparentDisplaySource,
}

/// The transaction detail view's transparent section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransparentDisplayView {
    /// Details are known.
    Available(TransparentDisplayDetails),
    /// A lookup is queued and has not failed, waits for the next publication, or public
    /// payload retrieval owns the transaction. Queued work counts only while the wallet would
    /// list it, now or once the transaction is mined again.
    Pending,
    /// A lookup failed and will be retried, or no source can supply the details.
    Unavailable,
    /// The display service does not cover the transaction.
    NotCovered,
}

/// Reads transparent txid enhancement work and the detail view.
pub trait TransparentDetailRead: super::TransparentLedgerRead {
    /// Returns up to `limit` due lookups at `now`, with the mode and policy generation read
    /// in the same snapshot.
    ///
    /// A transaction is due when it is mined, lacks raw bytes, is still related to the
    /// wallet, and either its mined height changed since the last attempt or its next
    /// attempt time has passed and it is not parked. A row whose last outcome was
    /// `NotCovered` or `Contradiction` is parked while `map_sha256` is absent or names the
    /// display map that produced it; an `Unsupported` row is parked while `map_sha256` is
    /// absent. Parked rows become due anyway seven days after their last attempt. Under a mode
    /// retaining public authority, transactions whose payload retrieval is already queued, or
    /// which are privately protected Ironwood transactions, are omitted.
    fn transparent_detail_work(
        &self,
        now: SystemTime,
        limit: usize,
        map_sha256: Option<[u8; 32]>,
    ) -> Result<TransparentDetailWork, Self::Error>;

    /// Returns the lookups that are parked at `now` under the caller's display map
    /// `map_sha256`: those [`Self::transparent_detail_work`] would list only once given a
    /// changed map hash.
    ///
    /// `map_checked_at` is when the caller last fetched (or tried to fetch) the display map,
    /// if ever; it bounds how often [`TransparentDetailParked::refresh_at`] asks for another.
    fn transparent_detail_parked(
        &self,
        now: SystemTime,
        map_sha256: Option<[u8; 32]>,
        map_checked_at: Option<SystemTime>,
    ) -> Result<TransparentDetailParked, Self::Error>;

    /// Returns the transparent detail view of `txid` for `account`, or `None` when the
    /// wallet does not hold the transaction.
    fn transparent_display_view(
        &self,
        account: Self::AccountId,
        txid: TxId,
    ) -> Result<Option<TransparentDisplayView>, Self::Error>;
}

/// Records transparent txid enhancement results.
pub trait TransparentDetailWrite: TransparentDetailRead {
    /// Validates `facts` against the wallet and stores them.
    ///
    /// Fails with a stale-policy error, changing nothing, when the durable policy generation
    /// is no longer `expected_generation`. See [`TransparentDisplayStore`] for the results.
    fn store_transparent_display(
        &mut self,
        facts: TransparentDisplayFacts,
        expected_generation: u64,
        now: SystemTime,
    ) -> Result<TransparentDisplayStore, Self::Error>;

    /// Records a failed lookup of `txid` and schedules the next attempt.
    ///
    /// `looked_up_height` is the mined height from the request, not a refreshed wallet height.
    /// `map_sha256` is the display map the lookup used, when one was fetched. Unknown
    /// transactions, transactions without work, and results whose mined height has changed
    /// (including transactions that are now unmined) are ignored without changing retry state.
    fn defer_transparent_detail(
        &mut self,
        txid: TxId,
        looked_up_height: BlockHeight,
        outcome: TransparentDetailOutcome,
        map_sha256: Option<[u8; 32]>,
        now: SystemTime,
    ) -> Result<(), Self::Error>;
}
