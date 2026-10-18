//! Wallet hash aliases for the shared candidate-recovery contract.

use zcash_primitives::block::BlockHash;

pub use zakura_pir_protocol::transparent::recovery::{
    AccountLifecycle, AddressRange, CommitOutcome, CommitRejection, ForgottenTransparentLedger,
    IntegrityFailure, InvalidCommit, MAX_RECOVERY_IDENTIFIER_LEN, PageRequest, ReceiveEvent,
    RefusedCommit, SpendEvent, StaleCommit, WatchOrigin, WatchedAddress,
};

pub type TransparentRecoveryContext<AccountId> =
    zakura_pir_protocol::transparent::recovery::TransparentRecoveryContext<AccountId, BlockHash>;
pub type TransparentAddressWatchSet<AccountId> =
    zakura_pir_protocol::transparent::recovery::TransparentAddressWatchSet<AccountId, BlockHash>;
pub type PublicationAnchor =
    zakura_pir_protocol::transparent::recovery::PublicationAnchor<BlockHash>;
pub type RecoveryRevision = zakura_pir_protocol::transparent::recovery::RecoveryRevision<BlockHash>;
pub type PendingPage = zakura_pir_protocol::transparent::recovery::PendingPage<BlockHash>;
pub type TransparentLedgerCommit<AccountId> =
    zakura_pir_protocol::transparent::recovery::TransparentLedgerCommit<AccountId, BlockHash>;
pub type CandidateRecovery<AccountId> =
    zakura_pir_protocol::transparent::recovery::CandidateRecovery<AccountId, BlockHash>;
