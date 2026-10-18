//! Wallet hash aliases for the shared candidate-recovery contract.

use zcash_primitives::block::BlockHash;

pub use zakura_transparent_recovery_types::{
    AccountLifecycle, AddressRange, CommitOutcome, CommitRejection, ForgottenTransparentLedger,
    IntegrityFailure, InvalidCommit, MAX_RECOVERY_IDENTIFIER_LEN, PageRequest, ReceiveEvent,
    RefusedCommit, SpendEvent, StaleCommit, WatchOrigin, WatchedAddress,
};

pub type TransparentRecoveryContext<AccountId> =
    zakura_transparent_recovery_types::TransparentRecoveryContext<AccountId, BlockHash>;
pub type TransparentAddressWatchSet<AccountId> =
    zakura_transparent_recovery_types::TransparentAddressWatchSet<AccountId, BlockHash>;
pub type PublicationAnchor = zakura_transparent_recovery_types::PublicationAnchor<BlockHash>;
pub type RecoveryRevision = zakura_transparent_recovery_types::RecoveryRevision<BlockHash>;
pub type PendingPage = zakura_transparent_recovery_types::PendingPage<BlockHash>;
pub type TransparentLedgerCommit<AccountId> =
    zakura_transparent_recovery_types::TransparentLedgerCommit<AccountId, BlockHash>;
pub type CandidateRecovery<AccountId> =
    zakura_transparent_recovery_types::CandidateRecovery<AccountId, BlockHash>;
