//! Storage-neutral contract for transparent ledger configuration and financial authority.
//!
//! This is the preparatory surface of the private transparent ledger: explicit handle modes,
//! durable policy transitions, an honest balance-and-authority snapshot, candidate recovery,
//! per-account activation, and history completeness; see `docs/transparent-pir-ledger-architecture.md` and
//! `docs/transparent-pir-ledger-design-notes.md`.

#[cfg(feature = "test-dependencies")]
use ambassador::delegatable_trait;
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use super::{Balance, WalletRead, wallet::ConfirmationsPolicy};

mod activity;
pub use activity::*;

mod history;
pub use history::*;

mod details;
pub use details::*;

#[cfg(feature = "transparent-inputs")]
mod recovery;
#[cfg(feature = "transparent-inputs")]
pub use recovery::*;

/// A locally accepted block: its height and the hash the wallet holds for that height.
///
/// Coverage through `H` can support a transaction targeting `H + 1`; the future block has
/// no accepted hash to check. A publisher's asserted hash never substitutes for a local one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChainPoint {
    /// Height of the accepted block.
    pub height: BlockHeight,
    /// The wallet's hash for the block at `height`.
    pub hash: BlockHash,
}

/// Source authorization for transparent discovery and financial authority.
///
/// Every handle performing transparent discovery or financial authorization must be
/// configured explicitly. No mode is implied by an empty or newly created wallet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransparentLedgerMode {
    /// Public transparent discovery remains authoritative.
    Public,
    /// Public transparent discovery is forbidden, including while private recovery is
    /// unavailable or incomplete. Transparent inputs require private authority.
    PrivateRequired,
}

impl TransparentLedgerMode {
    /// Returns whether public discovery retains transparent financial authority.
    pub fn retains_public_authority(self) -> bool {
        match self {
            Self::Public => true,
            Self::PrivateRequired => false,
        }
    }
}

/// The durable transparent policy as last applied to the wallet.
///
/// `generation` increments by one on each mode change. Outstanding public follow-on work is
/// stamped with the generation that produced it; a mismatched generation is stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AppliedTransparentPolicy {
    /// The mode durably applied to the wallet.
    pub mode: TransparentLedgerMode,
    /// Monotonic counter of mode transitions; unchanged by same-mode reapplication.
    pub generation: u64,
}

/// A transparent follow-on detail that cannot be recovered over a public request under the
/// current policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrivateTransparentDetail {
    /// A parent-transaction retrieval queued for a transparent input, withheld from public
    /// enhancement dispatch.
    ParentTransaction {
        /// The parent transaction to retrieve.
        txid: TxId,
    },
    /// A mixed transaction whose Enhance response indicated transparent data; public LWD
    /// enhancement is forbidden while the transaction remains unresolved (no stored raw).
    /// The sticky route-2 marker is not itself completion; storing full data, or restoring
    /// public authority for newly stamped work, ends the pending private detail.
    MixedTransaction {
        /// The mixed transaction.
        txid: TxId,
    },
}

/// The source of current transparent financial authority for one account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransparentAuthority {
    /// Balances and inputs derive from public discovery.
    Public,
    /// Balances and inputs derive from the account's private ledger, which is active and
    /// complete through the chain tip.
    Private,
    /// No current authority can be established; transparent inputs are unavailable.
    Unavailable,
}

/// A transparent balance split by coinbase classification, using the existing confirmation
/// and lock categories of [`Balance`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransparentLedgerBalance {
    /// Non-coinbase outputs.
    pub regular: Balance,
    /// Coinbase outputs, subject to maturity.
    pub coinbase: Balance,
}

/// Where a last-known amount came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LastKnownSource {
    /// Rows admitted under public authority before private authority applied.
    LegacyPublic,
    /// Legacy public rows together with rows recorded by local transaction construction after
    /// private authority applied, such as a shielded-funded payment to an own transparent
    /// receiver.
    LegacyPublicAndLocal,
    /// The account's active private ledger, which is blocked or covered short of the chain tip,
    /// so it does not authorize a current spend. It is anchored at the covered point only when
    /// that point is the tip; while coverage lags, it may count placed events above it.
    PrivateLedger,
}

/// A prior amount that is informational only; it never authorizes a spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LastKnownBalance {
    /// The amount as last established.
    pub balance: TransparentLedgerBalance,
    /// Its provenance.
    pub source: LastKnownSource,
    /// The accepted point it was established at, when one was verified.
    pub at: Option<ChainPoint>,
}

/// Financial recovery progress for one account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecoveryCompletion {
    /// Public authority applies; private recovery completion is not required.
    NotApplicable,
    /// Private authority is established through the chain tip.
    Complete,
    /// Authority cannot be established until the listed blockers clear.
    Blocked,
}

/// Why candidate recovery for an account is not yet complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CandidateBlocker {
    /// No local target exists.
    ChainUnknown,
    /// Some watched address lacks continuous coverage from its required start to the target.
    IncompleteCoverage,
    /// Pages remain open.
    PendingPages,
    /// A mined spend consumes an output that has not been recovered.
    UnresolvedSpends,
    /// A range recorded as unsupported is not covered by any source.
    UnsupportedRanges,
    /// Activity near the end of a derived window needs addresses that this account's keys
    /// cannot derive, or reaches the last non-hardened index, which the wallet cannot store.
    WindowUnderivable,
}

/// A reason transparent financial authority is unavailable, or an account cannot be promoted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecoveryBlocker {
    /// This build or configuration cannot perform private recovery.
    PrivateRecoveryUnavailable,
    /// No accepted chain point is known locally.
    ChainUnknown,
    /// This build cannot read the wallet's transparent state.
    TransparentSupportUnavailable,
    /// The account's recovered ledger is incomplete at the local target.
    Recovery(CandidateBlocker),
    /// The account has not been promoted to private authority.
    NotActivated,
    /// An integrity failure quarantined the account or a source of its evidence.
    Quarantined,
    /// A revision that contributed the account's coverage or events is not qualified.
    UnqualifiedRevision,
    /// The wallet's own evidence, legacy public or local, disagrees with the complete candidate
    /// ledger: a mined output the candidate ledger lacks or holds with other content, or a
    /// legacy spend it does not confirm.
    LegacyDiscrepancy,
    /// The contiguously scanned local chain is behind the known chain tip.
    ChainBehindTip,
}

/// The single atomic balance-and-authority result for one account's transparent funds.
///
/// Every field comes from one database read. Unavailable is not zero: an absent
/// `authorized` balance means no current authority, never an empty wallet. This describes
/// transparent financial authority only, not whole-wallet history completeness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentLedgerSnapshot<AccountId> {
    /// The account described.
    pub account: AccountId,
    /// The handle's configured mode.
    pub mode: TransparentLedgerMode,
    /// The current source of financial authority.
    pub authority: TransparentAuthority,
    /// The spendable-authority balance; absent when authority cannot be established.
    pub authorized: Option<TransparentLedgerBalance>,
    /// A prior amount shown for context; never current or spendable.
    pub last_known: Option<LastKnownBalance>,
    /// Whether authority is established or blocked.
    pub completion: RecoveryCompletion,
    /// Reasons authority is unavailable.
    pub blockers: Vec<RecoveryBlocker>,
    /// Under a private mode, the local block through which every watched address is
    /// continuously covered from its required start.
    pub covered_through: Option<ChainPoint>,
    /// Under a private mode, the sum of recovered unspent outputs. It is unverified until
    /// recovery is complete, is neither authoritative nor a lower bound, and is absent when it
    /// exceeds `MAX_MONEY`.
    pub recovered_unverified: Option<Zatoshis>,
}

/// Reads transparent ledger configuration and financial authority.
///
/// Implementations reject unconfigured handles, including for an empty wallet, and must not
/// fabricate coverage or a spendable private balance from incomplete state.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait TransparentLedgerRead: WalletRead {
    /// Returns the mode this handle operates under.
    ///
    /// A durably applied `PrivateRequired` policy governs every handle: a handle configured
    /// with a weaker mode operates under `PrivateRequired`, even when another connection
    /// applied it after this handle was configured. Reading never changes the stored policy or
    /// the handle's configuration. Fails when the handle is unconfigured or the durable policy
    /// cannot be read.
    fn transparent_ledger_mode(&self) -> Result<TransparentLedgerMode, Self::Error>;

    /// Returns the durable policy applied to the wallet, including its generation.
    ///
    /// The handle must already be configured, with any mode: the durable policy is reported
    /// as stored, and never changed by this read.
    fn applied_transparent_policy(&self) -> Result<AppliedTransparentPolicy, Self::Error>;

    /// Confirms that the durable policy generation still equals `expected`.
    ///
    /// Used as the commit check for an operation that captured the generation at the start of
    /// its SQLite transaction. Fails when another connection has since applied a transition.
    fn check_transparent_policy_generation(&self, expected: u64) -> Result<(), Self::Error>;

    /// Returns transparent follow-on details withheld from public dispatch under the current
    /// policy, such as parent-transaction retrieval and mixed-transaction markers.
    fn pending_private_transparent_details(
        &self,
    ) -> Result<Vec<PrivateTransparentDetail>, Self::Error>;

    /// Returns the transparent balance-and-authority snapshot for `account`, from one read.
    ///
    /// `confirmations_policy` applies the existing confirmation rules to any authorized or
    /// last-known balance. A historical snapshot never authorizes a current spend.
    fn transparent_ledger_snapshot(
        &self,
        account: Self::AccountId,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<TransparentLedgerSnapshot<Self::AccountId>, Self::Error>;

    /// Returns `account`'s history view of each of `txids`, from one read.
    ///
    /// The result holds one entry, in request order, for each transaction in which the account
    /// has a recorded output or spend, including a spend its active ledger recovered before the
    /// output it consumes; other transactions are omitted. Every entry is derived from
    /// the facts the wallet currently holds, so rewinds, promotion, account changes, and later
    /// enhancement are reflected as soon as they are stored. An incomplete effect, unknown fee, or
    /// missing payment detail is reported as such; none of them authorizes public retrieval.
    ///
    /// The handle must be configured.
    fn transaction_history_details(
        &self,
        account: Self::AccountId,
        txids: &[TxId],
    ) -> Result<Vec<TransactionHistoryDetails>, Self::Error>;

    /// Returns the addresses candidate recovery must cover for `account`, the context a run
    /// captures, and the pages earlier runs left open, from one read.
    ///
    /// The handle must be configured. Addresses added later, such as by window growth or new
    /// receiving addresses, appear in the next read; a run repeats until the set is stable.
    #[cfg(feature = "transparent-inputs")]
    fn transparent_watch_set(
        &self,
        account: Self::AccountId,
    ) -> Result<TransparentWatchSet<Self::AccountId>, Self::Error>;

    /// Returns development diagnostics for `account`'s candidate ledger, from one read.
    ///
    /// Candidate amounts are unverified and never authorize a spend.
    #[cfg(feature = "transparent-inputs")]
    fn transparent_candidate_recovery(
        &self,
        account: Self::AccountId,
    ) -> Result<CandidateRecovery<Self::AccountId>, Self::Error>;
}

/// Writes transparent ledger policy transitions, recovery, and promotion.
///
/// Implementations typically also implement [`WalletWrite`](super::WalletWrite); the write trait
/// itself only requires the read contract so associated `Error` types stay unambiguous.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait TransparentLedgerWrite: TransparentLedgerRead {
    /// Durably applies `mode` as the wallet's transparent policy.
    ///
    /// A mode change increments `policy_generation` by one in the same SQLite transaction.
    /// Re-applying the current mode does not increment it and does not revoke work. An explicit
    /// later transition back to `Public` is allowed; reads still never weaken a stored
    /// `PrivateRequired` policy via a weaker handle configuration.
    ///
    /// Before applying [`TransparentLedgerMode::PrivateRequired`], callers must cancel and join
    /// every outstanding public transparent-discovery operation. A generation check immediately
    /// before dispatch prevents new public work from starting after a concurrent transition, but
    /// it cannot recall a network request that has already begun. Arbitrary older readers that do
    /// not implement this contract are not supported rollback targets.
    ///
    /// The handle must already be configured. Returns the policy after the write. Leaving
    /// `PrivateRequired` demotes every active account in the same transaction.
    fn apply_transparent_policy(
        &mut self,
        mode: TransparentLedgerMode,
    ) -> Result<AppliedTransparentPolicy, Self::Error>;

    /// Atomically applies one recovery pass to the account's ledger.
    ///
    /// The durable policy must still be at the captured generation and must be
    /// `PrivateRequired`, as must the handle. The account must exist with the captured lifecycle
    /// and without quarantine, the target and anchor must still be local blocks, and every
    /// address the commit names must still be watched by the account. Any failure applies none
    /// of the commit's facts; an integrity failure also quarantines the source and the accounts
    /// holding its evidence.
    ///
    /// A candidate account's state is isolated: its commits never change balances, spend
    /// links, locks, address use, receiving-address selection, or transaction history. An
    /// active account's commits require a qualified revision and project their events into the
    /// wallet's outputs and spends in the same transaction.
    #[cfg(feature = "transparent-inputs")]
    fn apply_transparent_ledger_commit(
        &mut self,
        commit: TransparentLedgerCommit<Self::AccountId>,
    ) -> Result<CommitOutcome, Self::Error>;

    /// Atomically qualifies `commit.revision` as trusted and applies `commit`.
    ///
    /// Requires `PrivateRequired` both on the handle and durably. In one transaction it makes
    /// every check of [`apply_transparent_ledger_commit`], qualifies the exact revision,
    /// withdraws older provisional evidence of the same source across the wallet, and applies
    /// the commit's facts. Any failure changes nothing, except that an integrity failure
    /// quarantines exactly as an ordinary commit does, without qualifying. Replaying a commit
    /// this method already applied changes nothing; resubmitting a commit applied only by
    /// [`apply_transparent_ledger_commit`] qualifies its revision and withdraws older provisional
    /// evidence as above.
    ///
    /// Qualification is the caller's trust decision: this does not verify the publication.
    ///
    /// [`apply_transparent_ledger_commit`]: Self::apply_transparent_ledger_commit
    #[cfg(feature = "transparent-inputs")]
    fn qualify_and_apply_transparent_ledger_commit(
        &mut self,
        commit: TransparentLedgerCommit<Self::AccountId>,
    ) -> Result<CommitOutcome, Self::Error>;

    /// Atomically promotes `account` to private transparent authority.
    ///
    /// Requires `PrivateRequired` both on the handle and durably. Promotion rechecks, in one
    /// transaction, that the account is not quarantined, that its ledger is complete through a
    /// local target equal to the chain tip, that every revision contributing its coverage or
    /// events is qualified, and that its legacy public evidence agrees with the ledger. It then
    /// adds the ledger's window addresses to the wallet, projects every recovered event into the
    /// wallet's outputs and spends, and records the account as active. Promoting an active
    /// account does nothing. Any failure changes nothing; a blocked promotion reports its
    /// [`RecoveryBlocker`]s.
    #[cfg(feature = "transparent-inputs")]
    fn promote_transparent_account(&mut self, account: Self::AccountId) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::TransparentLedgerMode;

    #[test]
    fn only_private_required_drops_public_authority() {
        assert!(TransparentLedgerMode::Public.retains_public_authority());
        assert!(!TransparentLedgerMode::PrivateRequired.retains_public_authority());
    }
}
