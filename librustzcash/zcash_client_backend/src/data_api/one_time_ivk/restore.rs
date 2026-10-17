//! Discovery of a restored account's one-time IVK history.
//!
//! A restored wallet cannot trial-decrypt public history with every key its seed may
//! have used. Instead it checks candidate receivers against a receiver directory's public
//! filters, looks the paid ones up over PIR, and turns each answer into a scan hint. A
//! payment found after the scan passed its block waits as a late candidate until the
//! scan covers every block from it on, then the spend journal decides whether it was
//! spent. A store that implements [`OneTimeIvkRestoreWrite`] keeps that state.
//!
//! A client reads [`OneTimeIvkRestoreRead::one_time_discovery`] for the work due, records
//! filter checks with [`OneTimeIvkRestoreWrite::record_one_time_filter_checks`], each
//! paid key's history with [`OneTimeIvkRestoreWrite::record_one_time_lookup`], and each
//! late candidate's inclusion path with [`OneTimeIvkRestoreWrite::record_one_time_witness`].
//! Each call commits atomically, so a caller may stop between any two.

#[cfg(feature = "test-dependencies")]
use ambassador::delegatable_trait;
use zakura_one_time_ivk::{KeyId, Purpose};
use zcash_protocol::consensus::BlockHeight;

use super::{OneTimeIvkRead, OneTimeIvkWrite};
use crate::data_api::{WalletRead, transparent_ledger::ChainPoint};

pub mod recovery;

/// A key whose receiver discovery checks or looks up. Public metadata is not note
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

/// What a publication's public filters say about one candidate key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilterCheck {
    /// The key.
    pub key: KeyId,
    /// A swap provider's seen set holds its receiver, so it is never issued again.
    pub seen: bool,
    /// The paid filter holds its receiver, so a lookup may find payments.
    pub paid: bool,
    /// A swap may still pay it, so the scan watches it after the publication.
    pub recent: bool,
}

/// Where a purpose's filter checks resume.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EnumerationCursor {
    /// The first key index not yet checked.
    pub next: u64,
    /// Checks continue while `next` is below this. Each used key raises it.
    pub reach: u64,
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

/// An account's discovery: what is done and what is due.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryStatus {
    /// The publication the current pass uses, if one has started and its publication was
    /// not rejected.
    pub publication: Option<PublicationEnd>,
    /// Whether every key the publication marks used is registered, every paid key's history
    /// recorded and every payment found admitted, against a publication that matched the
    /// wallet's chain (or ended before the account's birthday). New swap addresses wait for
    /// the first part, the registration.
    pub complete: bool,
    /// Where filter checks resume for each purpose, or `None` once the pass checked both.
    pub enumeration: Option<[(Purpose, EnumerationCursor); 2]>,
    /// The account's closed keys. A pass checks each against the filters wherever its
    /// search stops, so a payment after a key closed is found even past a gap of unused
    /// keys.
    pub closed: Vec<DiscoveryWork>,
    /// Paid keys whose history is due for a lookup. A key registered after the scan passed
    /// `publication` has a later cutoff, so its lookup waits for a revision that reaches it.
    pub lookups: Vec<LookupWork>,
    /// Late candidates whose inclusion path is due.
    pub witnesses: Vec<WitnessRequest>,
    /// The lowest block a late candidate's inclusion path may be anchored at: a path to an
    /// older root is too old for the wallet to check (see
    /// [`OneTimeIvkRestoreWrite::record_one_time_witness`]).
    pub witness_anchor_floor: BlockHeight,
}

/// One-time IVK discovery reads.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeIvkRestoreRead: OneTimeIvkRead {
    /// The account's discovery at `now`, or `None` if it has none to run: it was created
    /// from a fresh seed, it has no Orchard viewing key, or Ironwood is not active. An
    /// unknown account is an error.
    fn one_time_discovery(
        &self,
        account: Self::AccountId,
        now: i64,
    ) -> Result<Option<DiscoveryStatus>, Self::Error>;

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

/// One-time IVK discovery writes.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimeIvkRestoreWrite: OneTimeIvkWrite + OneTimeIvkRestoreRead {
    /// Records `purpose`'s filter checks against `publication`, which the store saves before
    /// its first scan batch needs it and judges against its chain once the scan stores
    /// that block. Seen and paid keys are registered so they are never issued again, each
    /// paid key's lookup becomes due, and recent incoming keys are watched from the
    /// publication's end. `cursor` is where checks resume, and `finished` ends the purpose's checks.
    ///
    /// A publication newer than the account's current one starts a new pass that checks
    /// from index zero again; keys whose lookups are done stay done. Returns false, and
    /// records nothing, for a publication above the wallet's chain tip or older than the
    /// current one.
    #[allow(clippy::too_many_arguments)]
    fn record_one_time_filter_checks(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        publication: PublicationEnd,
        purpose: Purpose,
        checked: &[FilterCheck],
        cursor: EnumerationCursor,
        finished: bool,
        now: i64,
    ) -> Result<bool, <Self as WalletRead>::Error>;

    /// Applies `records`, consecutive records of `key`'s history starting at `page`, read
    /// from the directory revision ending at `revision`, and advances its cursor (see
    /// [`LookupWork`]). `page` is the cursor's `applied`, or zero to restart it. `complete`
    /// ends the lookup. A payment whose block the scan has not stored becomes a scan hint;
    /// one it has becomes a late candidate.
    ///
    /// Returns false, applying nothing, if the lookup is not due, its cursor moved since it
    /// was read, or `revision` ends below the cutoff or was rejected. It also returns false
    /// when it refuses the page, because a record fails authentication or lies above the
    /// cutoff: that backs the lookup off.
    ///
    /// The store judges `revision` against its chain like a discovery publication. If it
    /// fails, every cursor that read from it restarts and its unadmitted candidates are
    /// dropped.
    #[allow(clippy::too_many_arguments)]
    fn record_one_time_lookup(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        key: KeyId,
        revision: PublicationEnd,
        page: u32,
        records: &[DirectoryPayment],
        complete: bool,
        now: i64,
    ) -> Result<bool, <Self as WalletRead>::Error>;

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
