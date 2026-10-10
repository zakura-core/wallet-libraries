//! The error every recovery, catalog and display operation reports, and the helpers
//! that build it.

/// A failed pass grants no candidate progress or source authority.
///
/// The messages of [`RecoveryError::Invalid`] and [`RecoveryError::Failure`]
/// are diagnostics that may quote the wallet's transparent history (a txid or
/// outpoint from the companion's ledger) or the caller's transport errors.
/// Never log or report them; log the variant.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// Configuration, accepted-chain, context or source-content failure.
    #[error("transparent PIR recovery: {0}")]
    Invalid(String),
    /// Reference retrieval or companion persistence failure. Keep the companion
    /// and retry later.
    #[error("transparent PIR recovery: {0}")]
    Failure(String),
    /// The shard map a pass started from has a set identity that no longer
    /// continues the one the companion's store is bound to (another profile,
    /// start height, envelope or seal for a geometry in use). Only this check,
    /// made before the sync, reports it. A map ending below the store's anchor,
    /// while the caller's chain still accepts the anchor, is instead a replica
    /// that has not caught up, and the pass is [`BatchState::Pending`](crate::BatchState::Pending).
    ///
    /// Before returning it, the adapter reset the companion's store in one
    /// transaction and kept its catalog, so each source keeps its highest
    /// lineage. It forgot the export intents of sources the map no longer
    /// names, including [`RecoveryBatch::retired_revisions`](crate::RecoveryBatch::retired_revisions) a batch listed and
    /// nobody acknowledged: no successor can resolve them, and the wallet keeps
    /// their provisional evidence. Retry the pass once with the same companion;
    /// never recreate it.
    #[error("transparent PIR recovery: publication set changed; companion store reset, retry")]
    PublicationChanged,
}

pub(crate) fn failure(error: impl std::fmt::Display) -> RecoveryError {
    RecoveryError::Failure(error.to_string())
}

pub(crate) fn ensure_valid(ok: bool, message: &str) -> Result<(), RecoveryError> {
    if ok {
        Ok(())
    } else {
        Err(RecoveryError::Invalid(message.into()))
    }
}
