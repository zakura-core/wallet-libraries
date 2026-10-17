//! The commits of one pass, built from the facts the companion's store holds.

use std::collections::BTreeMap;

use crate::engine::{Acceptance, ChainView};
use zcash_client_backend::data_api::transparent_ledger::{
    ChainPoint, RecoveryRevision, TransparentLedgerCommit, TransparentRecoveryContext,
};

use crate::catalog::{self, Published};
use crate::convert::{block_hash_from_display, block_height, height_u64};
use crate::error::{RecoveryError, ensure_valid};

/// A pass's commits, keyed by [`Published::key`]: the revision's start height and
/// manifest digest.
pub(super) type RevisionCommits<A> = BTreeMap<(u64, String), TransparentLedgerCommit<A>>;

/// The display hash of the wallet's block at `height`, where a shard's commit is
/// anchored. Fails when `chain` holds no block there, or does not accept it.
pub(super) fn accepted_shard_anchor(
    chain: &impl ChainView,
    height: u64,
) -> Result<String, RecoveryError> {
    let hash = chain
        .hash_at(height)
        .ok_or_else(|| RecoveryError::Invalid("missing independent shard anchor".into()))?;
    ensure_valid(
        chain.is_accepted(height, &hash) == Acceptance::Accepted,
        "shard anchor is not independently accepted",
    )?;
    Ok(hash)
}

/// A commit of `revision` anchored at `anchor` that carries nothing yet.
pub(super) fn empty_commit<A>(
    context: TransparentRecoveryContext<A>,
    revision: RecoveryRevision,
    anchor: ChainPoint,
) -> TransparentLedgerCommit<A> {
    TransparentLedgerCommit {
        context,
        revision,
        anchor,
        receives: vec![],
        spends: vec![],
        coverage: vec![],
        unsupported: vec![],
        opened_pages: vec![],
        completed_pages: vec![],
    }
}

/// The commits of one pass, and the revisions its stored facts may name.
///
/// The store records each fact with the shard id and manifest digest it was
/// read under. A digest the map publishes names that entry's commit. A digest a
/// re-cut declares superseded, sealed, names a commit under that revision's own
/// identity, which the wallet already holds; it is admitted on its first fact.
/// Any other digest defers the batch.
pub(super) struct CommitBuilder<'p, A> {
    pub(super) commits: RevisionCommits<A>,
    pub(super) published: BTreeMap<&'p str, &'p Published>,
    declared: BTreeMap<&'p str, &'p Published>,
    /// Declared revisions already looked at this pass, and whether they have a
    /// commit.
    admitted: BTreeMap<&'p str, bool>,
    /// The first height the map's newest re-cut changed, if it declares one.
    recut_from: Option<u64>,
    /// Whether a stored fact shows the store followed the map's re-cuts: one
    /// under a revision any of them declares superseded, or under a revision
    /// the map publishes that starts at or above the newest one's first
    /// height, which only a map at that re-cut publishes.
    pub(super) follows_recut: bool,
    context: TransparentRecoveryContext<A>,
}

impl<'p, A: Copy> CommitBuilder<'p, A> {
    pub(super) fn new(
        published: &'p [Published],
        declared: &'p [Published],
        recut_from: Option<u64>,
        context: TransparentRecoveryContext<A>,
    ) -> Self {
        Self {
            commits: BTreeMap::new(),
            published: published
                .iter()
                .map(|entry| (entry.digest.as_str(), entry))
                .collect(),
            declared: declared
                .iter()
                .map(|entry| (entry.digest.as_str(), entry))
                .collect(),
            admitted: BTreeMap::new(),
            recut_from,
            follows_recut: false,
            context,
        }
    }

    /// An empty commit for `entry`, anchored at `anchor`.
    pub(super) fn open_commit(&mut self, entry: &Published, anchor: ChainPoint) {
        self.commits.insert(
            entry.key(),
            empty_commit(self.context, entry.revision.clone(), anchor),
        );
    }

    /// The commit a stored fact over `[from, through]` belongs to, if this pass
    /// exports one for the revision it names.
    ///
    /// A published digest names its entry's commit, which exists only if the
    /// pass classified that entry as exportable. A sealed declared digest names
    /// a commit under the superseded revision, anchored like a published one at
    /// the lower of its end and the target; the fact must lie inside its range.
    /// A fact naming another shard id than its revision's, a declared revision
    /// whose range does not hold it or whose end the wallet's chain does not
    /// hold, or any other digest defers the batch.
    pub(super) fn commit_for(
        &mut self,
        pass: &mut catalog::CatalogPass<'_>,
        chain: &impl ChainView,
        shard_id: u64,
        digest: &str,
        (from, through): (u64, u64),
    ) -> Result<Option<&mut TransparentLedgerCommit<A>>, RecoveryError> {
        if let Some(entry) = self.published.get(digest).copied() {
            if entry.shard_id != shard_id {
                pass.defer();
                return Ok(None);
            }
            self.note_published(entry);
            return Ok(self.commits.get_mut(&entry.key()));
        }
        let Some((digest, entry)) = self.declared.get_key_value(digest) else {
            pass.defer();
            return Ok(None);
        };
        let (digest, entry) = (*digest, *entry);
        self.follows_recut = true;
        if entry.shard_id != shard_id || from < entry.start_height || through > entry.end_height {
            pass.defer();
            return Ok(None);
        }
        let admitted = match self.admitted.get(digest) {
            Some(admitted) => *admitted,
            None => {
                let admitted = self.open_declared(pass, chain, entry)?;
                self.admitted.insert(digest, admitted);
                admitted
            }
        };
        Ok(if admitted {
            self.commits.get_mut(&entry.key())
        } else {
            None
        })
    }

    /// Notes a stored fact under the published revision `entry`.
    pub(super) fn note_published(&mut self, entry: &Published) {
        if self
            .recut_from
            .is_some_and(|from| entry.start_height >= from)
        {
            self.follows_recut = true;
        }
    }

    /// Opens a commit under a declared revision on its first stored fact, if
    /// the wallet's chain still holds the block it ends on and the catalog
    /// agrees with the declaration.
    fn open_declared(
        &mut self,
        pass: &mut catalog::CatalogPass<'_>,
        chain: &impl ChainView,
        entry: &Published,
    ) -> Result<bool, RecoveryError> {
        let target = height_u64(self.context.target.height);
        let height = entry.end_height.min(target);
        let hash = accepted_shard_anchor(chain, height)?;
        if height == entry.end_height && hash != entry.terminal {
            // Facts resting on a block the wallet's chain no longer holds.
            pass.defer();
            return Ok(false);
        }
        if !pass.admit_declared(entry)? {
            return Ok(false);
        }
        let anchor = ChainPoint {
            height: block_height(height)?,
            hash: block_hash_from_display(&hash)?,
        };
        self.open_commit(entry, anchor);
        Ok(true)
    }
}
