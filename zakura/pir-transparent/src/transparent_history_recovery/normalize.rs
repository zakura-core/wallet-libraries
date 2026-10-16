//! Normalization: one catalog transaction that turns the companion's stored facts into
//! a batch of commits and decides whether the batch may reach the wallet.

use std::collections::{BTreeMap, BTreeSet};

use transparent::bundle::OutPoint;
use transparent_events::TransparentEvent;
use transparent_filter::ShardMap;
use transparent_wallet::{ChainView, SetIdentity, WalletStore};
use transparent_wallet_store::SqliteStore;
use zcash_client_backend::data_api::transparent_ledger::{
    AddressRange, ChainPoint, PageRequest, ReceiveEvent, SpendEvent, TransparentAddressWatchSet,
    TransparentLedgerCommit, WatchedAddress,
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use super::commit_builder::{CommitBuilder, RevisionCommits, accepted_shard_anchor};
use super::page_completion::{page_continuation_id, page_covered, stranded_page_completions};
use super::preflight::watch_floor;
use super::{SCHEMA, TransparentHistoryRecovery};
use crate::batch::{BatchState, RecoveryBatch, unready_batch};
use crate::catalog::{self, CatalogPass, Published};
use crate::convert::{
    address_script, block_hash_from_display, block_height, height_u64, ledger_metadata,
};
use crate::error::{RecoveryError, ensure_valid, failure};
use crate::progress::Progress;

/// The watch set's addresses, by the script a stored fact names.
type WatchedByScript<'w> = BTreeMap<Vec<u8>, &'w WatchedAddress>;

impl TransparentHistoryRecovery {
    /// One catalog transaction over `map`: classify its revisions, export the
    /// companion's facts as commits, and decide the batch's state.
    ///
    /// In order: check that the store is bound to `map`'s publication set; anchor
    /// the map's shards meeting the watch set's floor and target on `chain`; begin
    /// the catalog pass and open a commit for each revision it may export; place the
    /// store's events, coverage and unfinished pages under the revisions they were
    /// read under; complete the wallet's pages that coverage spans and hold back
    /// exported revisions that would reopen one; settle the catalog's exported rows
    /// and decide the batch's state.
    ///
    /// A batch that is not ready commits the pass without exporting anything. A
    /// ready one records its revisions as exported, prunes the catalog and the
    /// store's caches, and may raise the recorded re-cut epoch, all in the pass's
    /// transaction, before the batch is returned.
    pub(super) fn normalize<A: Copy>(
        &mut self,
        watch: &TransparentAddressWatchSet<A>,
        map: ShardMap,
        progress: Progress,
        chain: &impl ChainView,
    ) -> Result<RecoveryBatch<A>, RecoveryError> {
        let context = watch
            .context()
            .ok_or_else(|| RecoveryError::Invalid("no locally accepted recovery target".into()))?;

        // The publication set the store is bound to.
        let Some(bound) = self.store.set_identity().map_err(failure)? else {
            // The client stopped before binding this companion to a publication
            // (one behind the target, or an unknown target), so its store holds
            // no facts. A fresh companion has exported nothing either. One whose
            // store a publication change reset may have, and this pass read
            // nothing to check that against.
            if catalog::exported_any(&self.catalog)? {
                return Ok(unready_batch(BatchState::Pending, progress));
            }
            return self.issue_ready_batch(vec![], vec![], progress);
        };
        map.check_shape().map_err(failure)?;
        let set = SetIdentity::of_schema(&map, SCHEMA);
        if !bound.continues(&set) {
            // `recover` checked the set before its sync, which refreshes only to
            // maps continuing the first, so this is never the map a sync ended
            // with. Defer rather than export facts read under another set; the
            // next pass's set check resets the store.
            return Ok(unready_batch(BatchState::Pending, progress));
        }

        // The map's revisions, and the shards the wallet's chain anchors.
        let (published, all_declarations) = self.map_revisions(&map, &set)?;
        // The sealed revisions a re-cut superseded stay the wallet's history.
        // A superseded tail is not: its source's renumbered tail replaces it.
        let sealed_declarations: Vec<Published> = all_declarations
            .iter()
            .filter(|entry| entry.revision.sealed)
            .cloned()
            .collect();
        let target = height_u64(context.target.height);
        let floor = watch_floor(watch, target);
        let anchored = anchor_shards_in_window(&map, &published, floor, target, chain)?;

        // The catalog pass, and a commit for each revision it may export.
        let mut pass = CatalogPass::begin(&mut self.catalog, &published, &sealed_declarations)?;
        pass.check_declarations(&published, &all_declarations);
        if anchored.off_branch {
            pass.defer();
        }
        let recut_from = map.recuts.last().map(|recut| recut.from_height);
        let mut commit_builder =
            CommitBuilder::new(&published, &sealed_declarations, recut_from, context);
        // Highest first, so a withdrawal reports the newest contradiction.
        for (published, anchor) in anchored.shards.into_iter().rev() {
            if pass.classify(published)? {
                commit_builder.open_commit(published, anchor);
            }
        }

        // The store's facts and page work, under the revisions they were read under.
        let watched = watched_by_script(watch);
        place_stored_events(
            &self.store,
            self.config.events,
            &watched,
            target,
            &mut pass,
            &mut commit_builder,
            chain,
        )?;
        place_stored_coverage(
            &self.store,
            &watched,
            target,
            &mut pass,
            &mut commit_builder,
            chain,
        )?;
        let opened_pages = open_unfinished_pages(
            &self.store,
            &watched,
            target,
            &mut pass,
            &mut commit_builder,
        )?;
        let follows_recut = commit_builder.follows_recut;
        let mut commits = commit_builder.commits;

        // The wallet's pages these commits complete, and the revisions held back.
        complete_wallet_held_pages(watch, &opened_pages, &mut commits);
        hold_back_reopened_exports(watch, &pass, &mut commits)?;
        let commits = without_empty_commits(commits);

        // Settle the catalog's exported rows and decide the batch's state.
        let retired_revisions = pass.settle(&published, &highest_committed_lineages(&commits))?;
        let state = pass.state();
        let digests: Vec<&str> = map
            .shards
            .iter()
            .map(|entry| entry.manifest_digest.as_str())
            .collect();
        if state != BatchState::Ready {
            pass.finish(&digests, None)?;
            return Ok(unready_batch(state, progress));
        }

        // Export a ready batch.
        // Completions of pages no commit of their own revision settles follow
        // the commits that cover them. They carry no evidence, so they are not
        // recorded as exported: no later map could succeed their revisions.
        let mut commits = commits;
        let stranded = stranded_page_completions(
            watch,
            context,
            &published,
            &sealed_declarations,
            &commits,
            chain,
        )?;
        pass.export(commits.iter().map(|commit| &commit.revision))?;
        // Only a ready pass over a re-cut the store followed moves the epoch:
        // its facts name a revision one of the map's re-cuts superseded, or one
        // only a map at its newest re-cut publishes. A refused declaration, or
        // one naming nothing the store read, cannot hold other maps behind.
        pass.finish(&digests, follows_recut.then(|| map.recut_epoch()))?;
        commits.extend(stranded);
        self.issue_ready_batch(commits, retired_revisions, progress)
    }
}

/// The map's shards a pass may export, each with the anchor the wallet's chain holds
/// for it.
struct AnchoredShards<'p> {
    /// The published revisions of shards meeting `[floor, target]` whose end the
    /// wallet's chain holds, in map order, each anchored at the lower of its end and
    /// the target.
    shards: Vec<(&'p Published, ChainPoint)>,
    /// Whether a shard in the window ends on a block the wallet's chain does not
    /// hold, which defers the batch.
    off_branch: bool,
}

/// Anchors the shards of `map`, published as `published`, that meet `[floor,
/// target]`. One ending below the floor holds nothing the watch set requires, and the
/// wallet holds no hash for it.
///
/// Fails when `chain` has no accepted block where a shard in the window is anchored.
fn anchor_shards_in_window<'p>(
    map: &ShardMap,
    published: &'p [Published],
    floor: u64,
    target: u64,
    chain: &impl ChainView,
) -> Result<AnchoredShards<'p>, RecoveryError> {
    let mut shards = vec![];
    let mut off_branch = false;
    for (entry, published) in map.shards.iter().zip(published) {
        if entry.start_height > target || entry.end_height < floor {
            continue;
        }
        let height = entry.end_height.min(target);
        let hash = accepted_shard_anchor(chain, height)?;
        if height == entry.end_height && hash != entry.terminal_block_hash {
            // The shard ends on a block the wallet's chain does not hold, as
            // when the publication or the wallet has yet to follow a reorg.
            // Its facts rest on that branch: export none, and wait.
            off_branch = true;
            continue;
        }
        let anchor = ChainPoint {
            height: block_height(height)?,
            hash: block_hash_from_display(&hash)?,
        };
        shards.push((published, anchor));
    }
    Ok(AnchoredShards { shards, off_branch })
}

/// Stored facts are looked up by the revision they were read under, without assuming
/// the map still publishes it.
fn watched_by_script<A>(watch: &TransparentAddressWatchSet<A>) -> WatchedByScript<'_> {
    watch
        .addresses
        .iter()
        .map(|entry| (address_script(entry.address), entry))
        .collect()
}

/// Places the store's events at or above their address's required height and at or
/// below `target` in the commits of the revisions they were read under.
///
/// Refuses a store holding more than `event_limit` events.
fn place_stored_events<A: Copy>(
    store: &SqliteStore,
    event_limit: usize,
    watched: &WatchedByScript<'_>,
    target: u64,
    pass: &mut CatalogPass<'_>,
    commit_builder: &mut CommitBuilder<'_, A>,
    chain: &impl ChainView,
) -> Result<(), RecoveryError> {
    let events = store.events().map_err(failure)?;
    ensure_valid(
        events.len() <= event_limit,
        "candidate event export limit exceeded",
    )?;
    for stored in events {
        let Some(address) = watched.get(&stored.script) else {
            continue;
        };
        let height = u64::from(stored.event.height());
        if height < height_u64(address.required_from) || height > target {
            continue;
        }
        let Some(commit) = commit_builder.commit_for(
            pass,
            chain,
            stored.shard_id,
            &stored.revision_digest,
            (height, height),
        )?
        else {
            continue;
        };
        match stored.event {
            TransparentEvent::Receive(event) => commit.receives.push(ReceiveEvent {
                metadata: ledger_metadata(event.metadata)?,
                outpoint: OutPoint::new(event.txid.0, event.output_index),
                address: address.address,
                value: Zatoshis::from_u64(event.value).map_err(failure)?,
                coinbase: event.coinbase,
                mined_height: BlockHeight::from(event.height),
            }),
            TransparentEvent::Spend(event) => commit.spends.push(SpendEvent {
                metadata: ledger_metadata(event.metadata)?,
                spending_txid: TxId::from_bytes(event.spending_txid.0),
                input_index: event.input_index,
                prevout: OutPoint::new(event.spent_txid.0, event.spent_output_index),
                prevout_address: address.address,
                mined_height: BlockHeight::from(event.height),
            }),
        }
    }
    Ok(())
}

/// Places the store's coverage of each watched script, clipped to its required height
/// and `target`, in the commits of the revisions it was read under.
fn place_stored_coverage<A: Copy>(
    store: &SqliteStore,
    watched: &WatchedByScript<'_>,
    target: u64,
    pass: &mut CatalogPass<'_>,
    commit_builder: &mut CommitBuilder<'_, A>,
    chain: &impl ChainView,
) -> Result<(), RecoveryError> {
    for (script, address) in watched {
        for range in store.coverage(script).map_err(failure)? {
            let from = range.start_height.max(height_u64(address.required_from));
            let through = range.end_height.min(target);
            if from > through {
                continue;
            }
            let Some(commit) = commit_builder.commit_for(
                pass,
                chain,
                range.shard_id,
                &range.revision_digest,
                (range.start_height, range.end_height),
            )?
            else {
                continue;
            };
            commit.coverage.push(AddressRange {
                address: address.address,
                from: block_height(from)?,
                through: block_height(through)?,
            });
        }
    }
    Ok(())
}

/// Opens a page in its revision's commit for each of the store's unfinished pages of
/// a watched script, and returns the ids of the pages opened.
///
/// Only revisions the map publishes: the store retrieves no page of a superseded
/// revision, so a page opened under one could never complete. A page under any other
/// revision defers the batch.
fn open_unfinished_pages<A: Copy>(
    store: &SqliteStore,
    watched: &WatchedByScript<'_>,
    target: u64,
    pass: &mut CatalogPass<'_>,
    commit_builder: &mut CommitBuilder<'_, A>,
) -> Result<BTreeSet<Vec<u8>>, RecoveryError> {
    let mut opened = BTreeSet::new();
    for page in store.pending().map_err(failure)? {
        let Some(address) = watched.get(&page.script) else {
            continue;
        };
        let Some(entry) = commit_builder
            .published
            .get(page.revision_digest.as_str())
            .copied()
            .filter(|entry| entry.shard_id == page.shard_id)
        else {
            pass.defer();
            continue;
        };
        commit_builder.note_published(entry);
        let from = entry.start_height.max(height_u64(address.required_from));
        let through = entry.end_height.min(target);
        if from > through {
            continue;
        }
        let Some(commit) = commit_builder.commits.get_mut(&entry.key()) else {
            continue;
        };
        let id = page_continuation_id(page.shard_id, &page.revision_digest, &page.script);
        commit.opened_pages.push(PageRequest {
            page: id.clone(),
            addresses: vec![address.address],
            from: block_height(from)?,
            through: block_height(through)?,
        });
        opened.insert(id);
    }
    Ok(opened)
}

/// Completes in each commit the wallet's pending pages of its revision that this pass
/// did not open again and that the commit's coverage spans. Completion needs
/// coverage, not merely absence of pending work.
fn complete_wallet_held_pages<A>(
    watch: &TransparentAddressWatchSet<A>,
    opened_pages: &BTreeSet<Vec<u8>>,
    commits: &mut RevisionCommits<A>,
) {
    for page in &watch.pending_pages {
        for commit in commits.values_mut() {
            if page.revision == commit.revision
                && !opened_pages.contains(&page.request.page)
                && page_covered(&commit.coverage, &page.request)
            {
                commit.completed_pages.push(page.request.page.clone());
            }
        }
    }
}

/// Holds back each revision an earlier batch exported while its commit opens a page
/// the wallet does not hold.
///
/// Such a revision may already be covered in the wallet, as when the store retrieves
/// it again after a publication change, and the wallet refuses a page opened over its
/// own coverage. A later pass exports it once its page work is done.
fn hold_back_reopened_exports<A>(
    watch: &TransparentAddressWatchSet<A>,
    pass: &CatalogPass<'_>,
    commits: &mut RevisionCommits<A>,
) -> Result<(), RecoveryError> {
    let mut held_back = vec![];
    for (key, commit) in commits.iter() {
        let unheld = commit.opened_pages.iter().any(|opened| {
            !watch
                .pending_pages
                .iter()
                .any(|held| held.revision == commit.revision && held.request.page == opened.page)
        });
        if unheld && pass.was_exported(&commit.revision)? {
            held_back.push(key.clone());
        }
    }
    for key in held_back {
        commits.remove(&key);
    }
    Ok(())
}

/// The commits, in revision order, without those that carry nothing.
fn without_empty_commits<A>(commits: RevisionCommits<A>) -> Vec<TransparentLedgerCommit<A>> {
    commits
        .into_values()
        .filter(|commit| {
            !commit.receives.is_empty()
                || !commit.spends.is_empty()
                || !commit.coverage.is_empty()
                || !commit.opened_pages.is_empty()
                || !commit.completed_pages.is_empty()
        })
        .collect()
}

/// Each source with a commit, and the highest lineage committed for it.
///
/// A re-cut can leave a source with commits at two lineages: the sealed revision it
/// superseded, from stored facts, and its renumbered successor. The higher one is what
/// settles the source.
fn highest_committed_lineages<A>(commits: &[TransparentLedgerCommit<A>]) -> BTreeMap<&[u8], u64> {
    let mut committed: BTreeMap<&[u8], u64> = BTreeMap::new();
    for commit in commits {
        let lineage = committed
            .entry(commit.revision.source.as_slice())
            .or_default();
        *lineage = (*lineage).max(commit.revision.lineage);
    }
    committed
}
