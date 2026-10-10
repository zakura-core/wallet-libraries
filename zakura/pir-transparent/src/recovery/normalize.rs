//! Normalization: one catalog transaction that turns the companion's stored facts into
//! a batch of commits and decides whether the batch may reach the wallet.

use std::collections::{BTreeMap, BTreeSet};

use transparent::bundle::OutPoint;
use transparent_events::TransparentEvent;
use transparent_filter::ShardMap;
use transparent_wallet::{Acceptance, ChainView, SetIdentity, WalletStore};
use zcash_client_backend::data_api::transparent_ledger::{
    AddressRange, ChainPoint, PageRequest, ReceiveEvent, SpendEvent, TransparentWatchSet,
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use super::commit_builder::Facts;
use super::page_completion::{complete_stranded, page_id, spans};
use super::preflight::required_floor;
use super::{ReferenceRecovery, SCHEMA};
use crate::batch::{BatchState, RecoveryBatch, unready};
use crate::catalog::{self, Published};
use crate::convert::{address_script, block, block_hash, metadata};
use crate::error::{RecoveryError, failure, require};
use crate::progress::Progress;

impl ReferenceRecovery {
    /// One catalog transaction over `map`: classify its revisions, export the
    /// companion's facts as commits, and decide the batch's state.
    pub(super) fn normalize<A: Copy>(
        &mut self,
        watch: &TransparentWatchSet<A>,
        map: ShardMap,
        progress: Progress,
        chain: &impl ChainView,
    ) -> Result<RecoveryBatch<A>, RecoveryError> {
        let context = watch
            .context()
            .ok_or_else(|| RecoveryError::Invalid("no locally accepted recovery target".into()))?;
        let Some(bound) = self.store.set_identity().map_err(failure)? else {
            // The client stopped before binding this companion to a publication
            // (one behind the target, or an unknown target), so its store holds
            // no facts. A fresh companion has exported nothing either. One whose
            // store a publication change reset may have, and this pass read
            // nothing to check that against.
            if catalog::exported_any(&self.catalog)? {
                return Ok(unready(BatchState::Pending, progress));
            }
            return self.ready(vec![], vec![], progress);
        };
        map.check_shape().map_err(failure)?;
        let set = SetIdentity::of_schema(&map, SCHEMA);
        if !bound.continues(&set) {
            // `recover` checked the set before its sync, which refreshes only to
            // maps continuing the first, so this is never the map a sync ended
            // with. Defer rather than export facts read under another set; the
            // next pass's set check resets the store.
            return Ok(unready(BatchState::Pending, progress));
        }
        let (published, declarations) = self.revisions(&map, &set)?;
        // The sealed revisions a re-cut superseded stay the wallet's history.
        // A superseded tail is not: its source's renumbered tail replaces it.
        let declared: Vec<Published> = declarations
            .iter()
            .filter(|entry| entry.revision.sealed)
            .cloned()
            .collect();
        let target = u64::from(u32::from(context.target.height));
        let floor = required_floor(watch, target);
        // Only shards meeting [floor, target]. One ending below the floor holds
        // nothing the watch set requires, and the wallet holds no hash for it.
        let mut relevant = vec![];
        let mut off_branch = false;
        for (entry, published) in map.shards.iter().zip(&published) {
            if entry.start_height > target || entry.end_height < floor {
                continue;
            }
            let height = entry.end_height.min(target);
            let hash = chain
                .hash_at(height)
                .ok_or_else(|| RecoveryError::Invalid("missing independent shard anchor".into()))?;
            require(
                chain.is_accepted(height, &hash) == Acceptance::Accepted,
                "shard anchor is not independently accepted",
            )?;
            if height == entry.end_height && hash != entry.terminal_block_hash {
                // The shard ends on a block the wallet's chain does not hold, as
                // when the publication or the wallet has yet to follow a reorg.
                // Its facts rest on that branch: export none, and wait.
                off_branch = true;
                continue;
            }
            let anchor = ChainPoint {
                height: block(height)?,
                hash: block_hash(&hash)?,
            };
            relevant.push((published, anchor));
        }
        let mut pass = catalog::Pass::begin(&mut self.catalog, &published, &declared)?;
        pass.check_declarations(&published, &declarations);
        if off_branch {
            pass.defer();
        }
        let recut_from = map.recuts.last().map(|recut| recut.from_height);
        let mut facts = Facts::new(&published, &declared, recut_from, context);
        // Highest first, so a withdrawal reports the newest contradiction.
        for (published, anchor) in relevant.into_iter().rev() {
            if pass.classify(published)? {
                facts.open(published, anchor);
            }
        }
        // Stored facts, looked up by the revision they were read under, without
        // assuming the map still publishes it.
        let addresses: BTreeMap<_, _> = watch
            .addresses
            .iter()
            .map(|entry| (address_script(entry.address), entry))
            .collect();
        let events = self.store.events().map_err(failure)?;
        require(
            events.len() <= self.config.events,
            "candidate event export limit exceeded",
        )?;
        for stored in events {
            let Some(address) = addresses.get(&stored.script) else {
                continue;
            };
            let height = u64::from(stored.event.height());
            if height < u64::from(u32::from(address.required_from)) || height > target {
                continue;
            }
            let Some(commit) = facts.place(
                &mut pass,
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
                    metadata: metadata(event.metadata)?,
                    outpoint: OutPoint::new(event.txid.0, event.output_index),
                    address: address.address,
                    value: Zatoshis::from_u64(event.value).map_err(failure)?,
                    coinbase: event.coinbase,
                    mined_height: BlockHeight::from(event.height),
                }),
                TransparentEvent::Spend(event) => commit.spends.push(SpendEvent {
                    metadata: metadata(event.metadata)?,
                    spending_txid: TxId::from_bytes(event.spending_txid.0),
                    input_index: event.input_index,
                    prevout: OutPoint::new(event.spent_txid.0, event.spent_output_index),
                    prevout_address: address.address,
                    mined_height: BlockHeight::from(event.height),
                }),
            }
        }
        for (script, address) in &addresses {
            for range in self.store.coverage(script).map_err(failure)? {
                let from = range
                    .start_height
                    .max(u64::from(u32::from(address.required_from)));
                let through = range.end_height.min(target);
                if from > through {
                    continue;
                }
                let Some(commit) = facts.place(
                    &mut pass,
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
                    from: block(from)?,
                    through: block(through)?,
                });
            }
        }
        // The store's unfinished page work, only under revisions the map
        // publishes: the store retrieves no page of a superseded revision, so a
        // page opened under one could never complete.
        let mut opened = BTreeSet::new();
        for page in self.store.pending().map_err(failure)? {
            let Some(address) = addresses.get(&page.script) else {
                continue;
            };
            let Some(entry) = facts
                .published
                .get(page.revision_digest.as_str())
                .copied()
                .filter(|entry| entry.shard_id == page.shard_id)
            else {
                pass.defer();
                continue;
            };
            facts.saw(entry);
            let from = entry
                .start_height
                .max(u64::from(u32::from(address.required_from)));
            let through = entry.end_height.min(target);
            if from > through {
                continue;
            }
            let Some(commit) = facts.commits.get_mut(&entry.key()) else {
                continue;
            };
            let id = page_id(
                page.shard_id,
                &page.revision_digest,
                &page.script,
                page.first_page,
            );
            commit.opened_pages.push(PageRequest {
                page: id.clone(),
                addresses: vec![address.address],
                from: block(from)?,
                through: block(through)?,
            });
            opened.insert(id);
        }
        let follows_recut = facts.follows_recut;
        let mut commits = facts.commits;
        for page in &watch.pending_pages {
            for commit in commits.values_mut() {
                if page.revision == commit.revision && !opened.contains(&page.request.page) {
                    // Completion needs coverage, not merely absence of pending work.
                    if page.request.addresses.iter().all(|address| {
                        spans(
                            &commit.coverage,
                            *address,
                            page.request.from,
                            page.request.through,
                        )
                    }) {
                        commit.completed_pages.push(page.request.page.clone());
                    }
                }
            }
        }
        // A revision an earlier batch exported may already be covered in the
        // wallet, as when the store retrieves it again after a publication
        // change, and the wallet refuses a page opened over its own coverage.
        // Hold such a revision back while it opens a page the wallet does not
        // hold; a later pass exports it once its page work is done.
        let mut held_back = vec![];
        for (key, commit) in &commits {
            let unheld = commit.opened_pages.iter().any(|opened| {
                !watch.pending_pages.iter().any(|held| {
                    held.revision == commit.revision && held.request.page == opened.page
                })
            });
            if unheld && pass.was_exported(&commit.revision)? {
                held_back.push(key.clone());
            }
        }
        for key in held_back {
            commits.remove(&key);
        }
        let commits: Vec<_> = commits
            .into_values()
            .filter(|commit| {
                !commit.receives.is_empty()
                    || !commit.spends.is_empty()
                    || !commit.coverage.is_empty()
                    || !commit.opened_pages.is_empty()
                    || !commit.completed_pages.is_empty()
            })
            .collect();
        // A re-cut can leave a source with commits at two lineages: the sealed
        // revision it superseded, from stored facts, and its renumbered
        // successor. The higher one is what settles the source.
        let mut committed: BTreeMap<&[u8], u64> = BTreeMap::new();
        for commit in &commits {
            let lineage = committed
                .entry(commit.revision.source.as_slice())
                .or_default();
            *lineage = (*lineage).max(commit.revision.lineage);
        }
        let replaced = pass.settle(&published, &committed)?;
        let state = pass.state();
        let digests: Vec<&str> = map
            .shards
            .iter()
            .map(|entry| entry.manifest_digest.as_str())
            .collect();
        if state != BatchState::Ready {
            pass.finish(&digests, None)?;
            return Ok(unready(state, progress));
        }
        // Completions of pages no commit of their own revision settles follow
        // the commits that cover them. They carry no evidence, so they are not
        // recorded as exported: no later map could succeed their revisions.
        let mut commits = commits;
        let stranded = complete_stranded(watch, context, &published, &declared, &commits, chain)?;
        pass.export(commits.iter().map(|commit| &commit.revision))?;
        // Only a ready pass over a re-cut the store followed moves the epoch:
        // its facts name a revision one of the map's re-cuts superseded, or one
        // only a map at its newest re-cut publishes. A refused declaration, or
        // one naming nothing the store read, cannot hold other maps behind.
        pass.finish(&digests, follows_recut.then(|| map.recut_epoch()))?;
        commits.extend(stranded);
        self.ready(commits, replaced, progress)
    }
}
