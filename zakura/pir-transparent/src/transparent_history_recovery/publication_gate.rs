//! Publications a pass cannot sync from as they are: a changed publication set, which
//! restarts the companion's store, and sealed history the sync refuses as rewritten.

use transparent_filter::ShardMap;
use transparent_wallet::{Acceptance, ChainView, SetIdentity, WalletStore};

use super::{SCHEMA, TransparentHistoryRecovery};
use crate::batch::{BatchState, RecoveryBatch, WithdrawnCause, behind_unread_batch, unready_batch};
use crate::catalog;
use crate::error::{RecoveryError, failure};
use crate::progress::{Outcome, Progress};

impl TransparentHistoryRecovery {
    /// The set check the sync would make when binding, made before it so that a
    /// changed publication restarts the store rather than stopping the sync.
    ///
    /// Returns `None` when the store is bound to no set, or to one `map`'s set
    /// continues: the pass may sync. When `map` is under another set but ends below the
    /// store's anchor while `chain` still accepts the anchor, returns a batch that waits
    /// for the replica to catch up. Otherwise resets the store, keeping the catalog, and
    /// fails with [`RecoveryError::PublicationChanged`].
    pub(super) fn gate_publication_set<A>(
        &mut self,
        map: &ShardMap,
        chain: &impl ChainView,
    ) -> Result<Option<RecoveryBatch<A>>, RecoveryError> {
        let set = SetIdentity::of_schema(map, SCHEMA);
        if !self
            .store
            .set_identity()
            .map_err(failure)?
            .is_some_and(|bound| !bound.continues(&set))
        {
            return Ok(None);
        }
        map.check_shape().map_err(failure)?;
        // As the reference client refuses a map ending below the anchor the
        // wallet's chain still accepts, a map under another set ending there
        // is a replica that has not caught up, perhaps still serving the
        // previous set. Wait for it: a reset would empty the store again
        // each time such replicas alternate.
        if let Some(anchor) = self.store.anchor().map_err(failure)?
            && map
                .shards
                .last()
                .is_none_or(|last| last.end_height < anchor.height)
            && chain.is_accepted(anchor.height, &anchor.hash) == Acceptance::Accepted
        {
            return Ok(Some(behind_unread_batch()));
        }
        let (published, declarations) = self.map_revisions(map, &set)?;
        let named: Vec<_> = published.into_iter().chain(declarations).collect();
        catalog::reset_store_keep_catalog(&mut self.catalog, &named)?;
        Err(RecoveryError::PublicationChanged)
    }

    /// The batch for a map the sync refused as a rewrite of sealed history the store
    /// holds.
    ///
    /// The map rewrites sealed history the store holds without declaring
    /// a re-cut, and the wallet's chain accepts both the block the stored
    /// range ends on and the block the map's sealed shard now covering
    /// its start ends on, at or below the target. The sync judges that
    /// only after rolling back any reorg the chain alone shows, and only
    /// for the ranges the rollback kept, and refuses it before reading
    /// anything; anything the chain cannot settle yet stops it as
    /// `ChainUnknown`.
    ///
    /// The sync keeps no re-cut epoch, so a replica still serving a map
    /// from before a re-cut the store followed looks the same to it. A
    /// map below the epoch this companion recorded is taken for one:
    /// `Pending`, behind, and a later pass syncs again. Otherwise the
    /// publisher contradicts the wallet's own chain, which no later pass
    /// over this history repairs: `Withdrawn(ChangedSealed)`. Either way
    /// nothing was read: the store keeps what it held, less any reorg the
    /// sync rolled back first, and the catalog is unchanged.
    pub(super) fn refused_rewrite_batch<A>(
        &self,
        map: &ShardMap,
    ) -> Result<RecoveryBatch<A>, RecoveryError> {
        if map.recut_epoch() < catalog::recut_epoch(&self.catalog)? {
            return Ok(behind_unread_batch());
        }
        Ok(unready_batch(
            BatchState::Withdrawn(WithdrawnCause::ChangedSealed),
            Progress {
                covered_through: 0,
                outcome: Outcome::Behind,
            },
        ))
    }
}
