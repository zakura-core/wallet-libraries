//! Applying a ready batch to a SQLite wallet and acknowledging it, with feature `sqlite`.
//!
//! [`ReferenceRecovery::apply_and_acknowledge`] consumes the batch, so its commits cannot be
//! edited or dropped before its retirements are acknowledged. Each commit applies in its own
//! wallet transaction, exactly as the wallet's commit operations do on their own; the
//! companion is acknowledged afterwards, in its own database. Nothing makes the two databases
//! atomic: a failure or crash between them leaves the batch unacknowledged, and the next pass
//! exports the same revisions again, whose replay changes nothing the wallet already holds.

use rusqlite::Connection;
use zcash_client_backend::data_api::transparent_ledger::{
    CommitRejection, TransparentLedgerRead as _, TransparentLedgerWrite as _,
};
use zcash_client_sqlite::{AccountUuid, WalletDb, error::SqliteClientError};
use zcash_protocol::consensus;

use crate::catalog::{self, BatchState};
use crate::recovery::{Progress, RecoveryBatch, RecoveryError, ReferenceRecovery};

/// How the wallet treats the revisions of the commits it applies. The caller decides; the
/// adapter never infers trust from the publication, the batch, or the wallet's policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// Apply each commit as candidate evidence only
    /// (`TransparentLedgerWrite::apply_transparent_ledger_commit`). A batch listing
    /// [`RecoveryBatch::retired_revisions`] is refused before anything is applied: only trusted
    /// reconciliation withdraws their evidence.
    Observed,
    /// Qualify each commit's revision as it applies
    /// (`TransparentLedgerWrite::qualify_and_apply_transparent_ledger_commit`), which also
    /// withdraws the older provisional evidence of its source and so reconciles the batch's
    /// retirements. The wallet requires `PrivateRequired` on the handle and durably.
    /// Qualification grants no authority by itself: promotion and spending stay separate
    /// wallet operations.
    Trusted,
}

/// What the wallet applied of a batch, in order: on failure, the committed prefix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApplyStats {
    /// Commits whose wallet transaction committed.
    pub applied: usize,
    /// Of those, commits whose revision was qualified as it applied.
    pub qualified: usize,
    /// Whether any applied commit grew a derived window: read a fresh watch set and pass
    /// again at the same target.
    pub window_grew: bool,
}

/// A batch the wallet applied whole and the companion acknowledged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Applied {
    pub stats: ApplyStats,
    /// The batch's pass progress.
    pub progress: Progress,
    /// Retired revisions the trusted commits reconciled and the acknowledgment forgot.
    pub retired: usize,
}

/// Why a batch was not acknowledged.
///
/// Messages name only the variant: the wallet's and the companion's errors can quote
/// addresses, outpoints or pages, so the nested errors are for matching, never for logs.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The batch is [`BatchState::Pending`] or [`BatchState::Withdrawn`]. Nothing was applied.
    #[error("transparent PIR apply: the batch is not ready")]
    NotReady(BatchState),
    /// The batch is not this companion's latest unacknowledged pass. Nothing was applied.
    #[error("transparent PIR apply: the export receipt is stale")]
    StaleReceipt,
    /// The wallet connection is inside an explicit SQL transaction, whose rollback would
    /// discard what a commit made durable, including quarantine. Nothing was applied.
    #[error("transparent PIR apply: the wallet connection is inside a transaction")]
    OuterTransaction,
    /// The batch lists retired revisions and the trust is [`Trust::Observed`]. Nothing was
    /// applied.
    #[error("transparent PIR apply: retired revisions require trusted reconciliation")]
    Unreconciled,
    /// The wallet refused the commit at `index`. Commits before it stay applied. An
    /// integrity rejection's quarantine is durable.
    #[error("transparent PIR apply: the wallet refused a commit")]
    Rejected {
        index: usize,
        rejection: CommitRejection,
    },
    /// The wallet's policy generation changed after the pass read its watch set.
    #[error("transparent PIR apply: the transparent policy changed")]
    PolicyChanged,
    /// The handle or the durable policy does not permit this recovery: no private policy,
    /// or [`Trust::Trusted`] without `PrivateRequired`.
    #[error("transparent PIR apply: private recovery is not enabled")]
    NotEnabled,
    /// Any other wallet failure, including a failed transaction commit.
    #[error("transparent PIR apply: wallet failure")]
    Wallet(SqliteClientError),
    /// Every commit applied, but the companion did not record the acknowledgment.
    #[error("transparent PIR apply: acknowledgment failed")]
    Acknowledge(RecoveryError),
}

/// A batch that was not acknowledged, with what the wallet applied of it first.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct ApplyFailure {
    #[source]
    pub error: ApplyError,
    /// The committed prefix. Every listed commit stays applied.
    pub stats: ApplyStats,
    /// The batch's pass progress.
    pub progress: Progress,
}

impl ApplyError {
    fn from_wallet(index: usize, error: SqliteClientError) -> Self {
        match error {
            SqliteClientError::TransparentLedgerCommitRejected(rejection) => {
                ApplyError::Rejected { index, rejection }
            }
            SqliteClientError::StaleTransparentPolicy { .. } => ApplyError::PolicyChanged,
            SqliteClientError::TransparentRecoveryNotEnabled => ApplyError::NotEnabled,
            error => ApplyError::Wallet(error),
        }
    }
}

impl From<rusqlite::Error> for ApplyError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Wallet(error.into())
    }
}

impl ReferenceRecovery {
    /// Applies a ready batch's commits to `wallet` in order, then acknowledges the batch.
    ///
    /// The batch is consumed: whatever the outcome, the next acknowledgment needs a new pass.
    /// Before applying anything, the batch must be this companion's latest
    /// [`BatchState::Ready`] pass, `wallet` must not be inside an explicit SQL transaction,
    /// and a batch with [`RecoveryBatch::retired_revisions`] needs [`Trust::Trusted`].
    ///
    /// Each commit applies in its own wallet transaction, which commits before the next
    /// starts, so an integrity rejection's quarantine is durable when it is reported. The
    /// first refused or failed commit stops the batch; the companion is acknowledged only
    /// once every commit's transaction committed, and forgets exactly the retirements its
    /// pass recorded. An unacknowledged batch's revisions stay exported, so the next pass,
    /// also after a crash or a reopened companion, lists them and its retirements again, and
    /// replaying commits the wallet already applied changes nothing.
    ///
    /// A batch with commits checks the policy generation they were built under again
    /// after acquiring the companion's write transaction. A batch without commits, as
    /// for a watch set with nothing to watch, has neither facts nor retirements (a
    /// retirement always comes with its successor commit), so acknowledging it after a
    /// policy change changes nothing in the wallet and is not refused; it only lets
    /// the companion prune its catalog.
    ///
    /// The policy generation is checked again after acquiring the companion's write
    /// transaction. A short immediate wallet read transaction excludes policy writers
    /// until acknowledgment commits; it is rolled back, since all wallet facts are
    /// already durable. Companion lock waits do not hold a wallet SQL reservation.
    ///
    /// No network request is made here; run it under the wallet's write serialization if the
    /// application has one. It never promotes an account or authorizes spending.
    pub fn apply_and_acknowledge<P: consensus::Parameters, CL, R>(
        &mut self,
        batch: RecoveryBatch<AccountUuid>,
        wallet: &mut WalletDb<Connection, P, CL, R>,
        trust: Trust,
    ) -> Result<Applied, ApplyFailure> {
        let progress = batch.progress();
        let mut stats = ApplyStats::default();
        let failure = |error, stats| ApplyFailure {
            error,
            stats,
            progress,
        };
        if batch.state() != BatchState::Ready {
            return Err(failure(ApplyError::NotReady(batch.state()), stats));
        }
        if !self.is_pending_export(&batch) {
            return Err(failure(ApplyError::StaleReceipt, stats));
        }
        if !wallet.is_autocommit() {
            return Err(failure(ApplyError::OuterTransaction, stats));
        }
        let (commits, replaced) = batch.into_parts();
        let expected_generation = commits
            .first()
            .map(|commit| commit.context.policy_generation);
        if trust == Trust::Observed && !replaced.is_empty() {
            return Err(failure(ApplyError::Unreconciled, stats));
        }
        // From here on the receipt is spent: a failed batch is replayed by a new pass.
        self.clear_pending_export();
        for (index, commit) in commits.into_iter().enumerate() {
            let applied = match trust {
                Trust::Observed => wallet.apply_transparent_ledger_commit(commit),
                Trust::Trusted => wallet.qualify_and_apply_transparent_ledger_commit(commit),
            };
            match applied {
                Ok(outcome) => {
                    stats.applied += 1;
                    stats.qualified += usize::from(trust == Trust::Trusted);
                    stats.window_grew |= outcome.window_grew;
                }
                Err(error) => {
                    return Err(failure(ApplyError::from_wallet(index, error), stats));
                }
            }
        }
        let acknowledgment = catalog::acknowledgment_transaction(&mut self.catalog)
            .map_err(|error| failure(ApplyError::Acknowledge(error), stats))?;
        wallet
            .with_immediate_read_transaction(|snapshot| {
                if let Some(expected) = expected_generation {
                    snapshot
                        .check_transparent_policy_generation(expected)
                        .map_err(|error| ApplyError::from_wallet(stats.applied, error))?;
                }
                catalog::acknowledge_in_transaction(&acknowledgment, &replaced)
                    .map_err(ApplyError::Acknowledge)?;
                acknowledgment
                    .commit()
                    .map_err(|error| ApplyError::Acknowledge(crate::recovery::failure(error)))
            })
            .map_err(|error| failure(error, stats))?;
        Ok(Applied {
            stats,
            progress,
            retired: replaced.len(),
        })
    }
}
