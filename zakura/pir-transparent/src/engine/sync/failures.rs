use super::{
    Completion, FailedEntry, IncompleteReason, MAX_CONTENT_FAILURES, SyncError, SyncReport,
    WorkLimits, coverage_summary, provisional_of,
};
use crate::engine::adapters::{Acceptance, ChainView};
use crate::engine::store::{Anchor, WalletStore};
use crate::engine::transport::ByteCharges;
use transparent_filter::ShardMap;

/// Whether a budget has been reached.
pub(super) fn budget_stopped(
    charges: &ByteCharges,
    limits: &WorkLimits,
) -> Option<IncompleteReason> {
    if let Some(max) = limits.max_queries {
        if charges.queries() >= max {
            return Some(IncompleteReason::QueryBudget);
        }
    }
    if let Some(max) = limits.max_private_bytes {
        let private = charges.setup_bytes() + charges.query_upload() + charges.query_download();
        if private >= max {
            return Some(IncompleteReason::ByteBudget);
        }
    }
    None
}

/// A walk's failure, with the queries valid replies had already committed it
/// to: `dummies` of them, to page shard `child`.
pub(super) struct Failure {
    pub(super) error: SyncError,
    pub(super) child: u8,
    pub(super) dummies: u32,
}

impl From<SyncError> for Failure {
    fn from(error: SyncError) -> Self {
        Self {
            error,
            child: 0,
            dummies: 0,
        }
    }
}

/// A sync's content failures so far: the entries, and the dummy queries
/// failed walks still owe. A shard read retried after an overload sends what
/// is still owed before the walk ends.
#[derive(Default)]
pub(super) struct Failures {
    pub(super) entries: Vec<FailedEntry>,
    /// Shard id, script, page shard and the number of dummies owed.
    pub(super) owed: Vec<(u64, Vec<u8>, u8, u32)>,
}

impl Failures {
    /// The dummies the walk of `script`'s entry in `shard_id` still owes.
    pub(super) fn owes(&self, shard_id: u64, script: &[u8]) -> Option<(u8, u32)> {
        self.owed
            .iter()
            .find(|(shard, owner, ..)| *shard == shard_id && owner == script)
            .map(|&(_, _, child, count)| (child, count))
    }

    /// Records that the dummies `owes` names were sent.
    pub(super) fn settle(&mut self, shard_id: u64, script: &[u8]) {
        self.owed
            .retain(|(shard, owner, ..)| !(*shard == shard_id && owner == script));
    }
}

/// Whether `script`'s entry in shard `shard_id` is held out of this sync:
/// it failed on content earlier in the sync, or has failed
/// [`MAX_CONTENT_FAILURES`] times. A held entry's replies are not read; it
/// is queried again only by a shard read retried after an overload, which
/// asks what the first attempt asked.
pub(super) fn held<S: WalletStore>(
    store: &S,
    failed: &[FailedEntry],
    shard_id: u64,
    script: &[u8],
) -> Result<bool, SyncError> {
    Ok(failed
        .iter()
        .any(|entry| entry.shard_id == shard_id && entry.script == script)
        || store.entry_failures(shard_id, script)? >= MAX_CONTENT_FAILURES)
}

/// [`held`], listing an entry held for its failure count in the report the
/// first time this sync meets it.
pub(super) fn hold<S: WalletStore>(
    store: &S,
    failed: &mut Vec<FailedEntry>,
    shard_id: u64,
    script: &[u8],
) -> Result<bool, SyncError> {
    if failed
        .iter()
        .any(|entry| entry.shard_id == shard_id && entry.script == script)
    {
        return Ok(true);
    }
    let failures = store.entry_failures(shard_id, script)?;
    if failures < MAX_CONTENT_FAILURES {
        return Ok(false);
    }
    failed.push(FailedEntry {
        shard_id,
        script: script.to_vec(),
        failures,
    });
    Ok(true)
}

/// Lists an entry whose failure a commit just counted, with the store's count.
pub(super) fn record_failure<S: WalletStore>(
    store: &S,
    failed: &mut Vec<FailedEntry>,
    shard_id: u64,
    script: &[u8],
) -> Result<(), SyncError> {
    let failures = store.entry_failures(shard_id, script)?;
    match failed
        .iter_mut()
        .find(|entry| entry.shard_id == shard_id && entry.script == script)
    {
        Some(entry) => entry.failures = failures,
        None => failed.push(FailedEntry {
            shard_id,
            script: script.to_vec(),
            failures,
        }),
    }
    Ok(())
}

pub(crate) fn event_height(event: &transparent_events::TransparentEvent) -> u64 {
    match event {
        transparent_events::TransparentEvent::Receive(e) => u64::from(e.height),
        transparent_events::TransparentEvent::Spend(e) => u64::from(e.height),
    }
}

pub(super) fn accepted_at(
    chain: &impl ChainView,
    map: &ShardMap,
    height: u64,
) -> Result<Anchor, SyncError> {
    let hash = chain.hash_at(height).or_else(|| {
        map.shards.iter().find_map(|s| {
            if s.end_height == height {
                Some(s.terminal_block_hash.clone())
            } else if s.start_height.checked_sub(1) == Some(height) {
                Some(s.parent_block_hash.clone())
            } else {
                None
            }
        })
    });
    match hash {
        Some(hash) if chain.is_accepted(height, &hash) == Acceptance::Accepted => {
            Ok(Anchor { height, hash })
        }
        _ => Err(SyncError::Invalid(format!(
            "wallet has no accepted rollback hash at {height}"
        ))),
    }
}

/// The report of a sync stopped because the wallet's chain cannot confirm a
/// block at `height`: whatever was already rolled back, and nothing read.
#[allow(clippy::too_many_arguments)]
pub(super) fn chain_unknown<S: WalletStore>(
    store: &S,
    map: &ShardMap,
    target_anchor: &Anchor,
    charges: ByteCharges,
    height: u64,
    rolled_back_to: Option<u64>,
    replaced_revisions: Vec<String>,
    first_commit: u64,
) -> Result<SyncReport, SyncError> {
    let (covered, settled) = coverage_summary(store, target_anchor.height)?;
    Ok(SyncReport {
        ledger: store.ledger()?,
        charges,
        matched_shards: Vec::new(),
        unproductive_matches: 0,
        covered_through: covered,
        settled_through: settled,
        provisional: provisional_of(store, map)?,
        map_refreshes: 0,
        completion: Completion::Incomplete {
            reason: IncompleteReason::ChainUnknown { height },
            pending: store.pending()?.len(),
        },
        rolled_back_to,
        replaced_revisions,
        scripts_added: 0,
        commits: store.last_commit()? - first_commit,
        failed_entries: Vec::new(),
    })
}

pub(super) fn incomplete_at<S: WalletStore>(
    store: &S,
    reason: IncompleteReason,
) -> Result<SyncReport, SyncError> {
    let progress = crate::engine::progress::summary(store)?;
    Ok(SyncReport {
        ledger: store.ledger()?,
        charges: ByteCharges::default(),
        matched_shards: vec![],
        unproductive_matches: 0,
        covered_through: progress.covered_through,
        settled_through: progress.settled_through,
        provisional: progress.provisional,
        map_refreshes: 0,
        completion: Completion::Incomplete {
            reason,
            pending: store.pending()?.len(),
        },
        rolled_back_to: None,
        replaced_revisions: vec![],
        scripts_added: 0,
        commits: 0,
        failed_entries: Vec::new(),
    })
}
