//! The export receipt: what a ready batch's acknowledgment must present, and the
//! acknowledgment that spends it.

use sha2::{Digest, Sha256};
use transparent_wallet::WalletStore;
use zcash_client_backend::data_api::transparent_ledger::{
    RecoveryRevision, TransparentLedgerCommit,
};

use super::ReferenceRecovery;
use crate::batch::{BatchState, RecoveryBatch};
use crate::catalog;
use crate::error::{RecoveryError, ensure_valid, failure};
use crate::progress::Progress;

/// What an acknowledgment must present: the batch's binding, store position,
/// commits and replaced revisions.
fn receipt_token<A>(
    binding: &[u8; 32],
    last_commit: u64,
    commits: &[TransparentLedgerCommit<A>],
    replaced: &[RecoveryRevision],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"transparent-reference-export-v2");
    hash.update(binding);
    hash.update(last_commit.to_le_bytes());
    hash.update((commits.len() as u64).to_le_bytes());
    for commit in commits {
        hash.update(&commit.revision.source);
        hash.update(&commit.revision.revision);
    }
    for row in replaced {
        hash.update(&row.source);
        hash.update(&row.revision);
    }
    hash.finalize().into()
}

impl ReferenceRecovery {
    /// A ready batch, whose receipt the next acknowledgment must present.
    pub(crate) fn issue_ready_batch<A>(
        &mut self,
        commits: Vec<TransparentLedgerCommit<A>>,
        retired_revisions: Vec<RecoveryRevision>,
        progress: Progress,
    ) -> Result<RecoveryBatch<A>, RecoveryError> {
        let last_commit = self.store.last_commit().map_err(failure)?;
        let receipt = receipt_token(&self.binding, last_commit, &commits, &retired_revisions);
        self.outstanding_receipt = Some(receipt);
        Ok(RecoveryBatch {
            commits,
            progress,
            state: BatchState::Ready,
            retired_revisions,
            receipt,
        })
    }

    /// Acknowledge the latest batch, forgetting exactly the retired revisions
    /// its pass recorded, and prune the catalog.
    ///
    /// Until then the notifications are durable: after a failed reconciliation
    /// or a crash, the next pass reports them again, with any retirement found
    /// since, or is [`BatchState::Pending`] while it cannot export their
    /// successors, and replaying the trusted operation on its commits changes
    /// nothing. The one exception is [`RecoveryError::PublicationChanged`],
    /// which forgets those of sources the new map no longer names.
    pub(super) fn acknowledge<A>(&mut self, batch: &RecoveryBatch<A>) -> Result<(), RecoveryError> {
        ensure_valid(
            batch.state == BatchState::Ready,
            "only a ready batch is acknowledged",
        )?;
        ensure_valid(
            self.is_outstanding_receipt(batch),
            "export receipt is stale",
        )?;
        catalog::acknowledge(&mut self.catalog, &batch.retired_revisions)?;
        self.outstanding_receipt = None;
        Ok(())
    }

    /// Acknowledges a batch whose retirements a test reconciled by hand.
    #[cfg(test)]
    pub(crate) fn acknowledge_reconciled<A>(
        &mut self,
        batch: &RecoveryBatch<A>,
    ) -> Result<(), RecoveryError> {
        self.acknowledge(batch)
    }

    /// Whether `batch` is this companion's latest unacknowledged pass.
    pub(crate) fn is_outstanding_receipt<A>(&self, batch: &RecoveryBatch<A>) -> bool {
        self.outstanding_receipt == Some(batch.receipt)
    }

    /// Spends the latest pass's receipt.
    #[cfg(feature = "sqlite")]
    pub(crate) fn spend_outstanding_receipt(&mut self) {
        self.outstanding_receipt = None;
    }
}
