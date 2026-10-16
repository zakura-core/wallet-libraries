use super::{
    Completion, Failure, Failures, Reply, RowRequest, RowSource, SyncError, event_height,
    record_failure,
};
use crate::engine::store::{
    Anchor, CachedRun, PendingPages, RunCursor, ShardCommit, StoreError, StoredEvent, WalletStore,
};
use transparent_events::TransparentEvent;
use transparent_filter::{BlockHash, ShardMap};
use transparent_shard::manifest::{PageChild, ShardManifest};
use transparent_shard::page_row::PageEntry;

/// The history cached below a run, and the page shard of the cached run it
/// starts from.
type CachedBelow = (u8, Vec<TransparentEvent>);

/// One script's chain walk in progress.
struct Walk {
    item: PendingPages,
    /// The first fragment of the run at the cursor, once read.
    head: Option<PageEntry>,
    /// Runs read and committed in this call, newest first, with their page
    /// shard: what the run cache is filled from once the walk ends.
    walked: Vec<(u8, Vec<TransparentEvent>)>,
    done: bool,
    /// After a content failure: the page shard and number of queries the
    /// walk had committed to and not sent, sent as dummies in the next round,
    /// after which the walk ends.
    dummies: Option<(u8, u32)>,
}

/// Walks the chains of runs `owed` describes, all scripts' rounds together,
/// newest run first, committing each run once it is read and checked.
///
/// A round reads each run's first fragment or a prefix of its remaining
/// fragments. Checked fragments are saved between passes, so a one-query
/// budget can advance even a long run. A complete run is committed before
/// checking the next request's budget. A walk reaching a cached sealed run
/// stops there and takes that history.
///
/// Refused, as content failures: a link to the same or a later page shard;
/// an `older_runs` that does not drop by exactly one per hop, which is how a
/// chain cut short or extended shows; fragments out of ordinal, count or
/// greedy boundary; events not strictly increasing from the oldest run into
/// the inline events; and an event in a page shard other than the one open
/// when it was pushed out — the event two places after it must lie in that
/// page shard's range.
///
/// A content failure fails its walk alone; the other walks finish. The failed
/// walk keeps its pending item, so a later sync retries it, and the failure is
/// counted against the entry. It still sends what valid replies had already
/// committed it to, the fragments of its current run not yet asked for, as
/// dummy queries to that run's page shard, and then nothing. A run whose link
/// names a page shard the manifest does not declare, or a row outside that
/// table, sends one dummy to its own page shard in the link's place, unless
/// the honest walk would not query a head after this run. Nothing that
/// depends on the bad reply is sent.
pub(super) fn walk_chains<S: WalletStore, R: RowSource>(
    store: &mut S,
    entry: &transparent_filter::ShardMapEntry,
    manifest: &ShardManifest,
    owed: &[PendingPages],
    rows: &mut R,
    target_anchor: &Anchor,
    failures: &mut Failures,
) -> Result<Option<Completion>, SyncError> {
    let geometry = transparent_shard::layout::by_name(&entry.geometry)
        .ok_or_else(|| SyncError::UnknownGeometry(entry.geometry.clone()))?;
    let identities: Vec<String> = manifest.child_digests().iter().map(hex::encode).collect();
    let salts = manifest
        .page_children
        .iter()
        .map(|child| {
            let terminal = BlockHash::from_display_hex(&child.terminal_block_hash)?;
            Ok(transparent_shard::page_tag_salt(
                manifest.shard_id,
                child.index,
                child.end_height,
                &terminal,
                child.tag_salt_counter,
            ))
        })
        .collect::<Result<Vec<[u8; 32]>, SyncError>>()?;
    let walker = Walker {
        entry,
        manifest,
        geometry,
        identities: &identities,
        salts: &salts,
        target_anchor,
    };
    let mut walks: Vec<Walk> = Vec::with_capacity(owed.len());
    for item in owed {
        let mut walk = Walk {
            item: item.clone(),
            head: None,
            walked: Vec::new(),
            done: false,
            dummies: None,
        };
        if let Some(owed) = failures.owes(entry.shard_id, &item.script) {
            // Failed earlier in this sync, before a retry: it still sends
            // what it owed.
            walk.dummies = Some(owed);
        } else if let Some(raw) = item.fragments.first() {
            let head = walker
                .fragment(
                    &item.script,
                    item.cursor.child,
                    std::slice::from_ref(raw),
                    0,
                    None,
                )
                .map_err(Failure::from)
                .and_then(|head| {
                    walker.check_located(
                        store,
                        &item.script,
                        &head,
                        &item.cursor,
                        item.fragments.len(),
                    )?;
                    Ok(head)
                });
            match head {
                Ok(head) => walk.head = Some(head),
                Err(failure) => walker.fail(store, &mut walk, failures, failure)?,
            }
        }
        walks.push(walk);
    }
    loop {
        // A walk at a run the store holds history for stops there.
        for walk in walks
            .iter_mut()
            .filter(|w| !w.done && w.dummies.is_none() && w.head.is_none())
        {
            let child = walk.item.cursor.child;
            let stopped = match walker.cached(store, &walk.item.script, child) {
                Ok(Some(older)) => walker.finish(store, walk, Vec::new(), Some((child, older))),
                Ok(None) => Ok(()),
                Err(error) => Err(error),
            };
            if let Err(error) = stopped {
                walker.fail(store, walk, failures, error.into())?;
            }
        }
        if walks.iter().all(|walk| walk.done) {
            return Ok(None);
        }
        if rows.stopped().is_some() {
            for walk in walks.iter_mut().filter(|w| !w.done && w.dummies.is_none()) {
                if walk
                    .head
                    .as_ref()
                    .is_some_and(|head| walk.item.fragments.len() == head.fragment_count as usize)
                {
                    if let Err(failure) = walker.complete(store, walk) {
                        walker.fail(store, walk, failures, failure)?;
                    }
                }
            }
            if walks.iter().all(|walk| walk.done) {
                return Ok(None);
            }
        }
        if let Some(reason) = rows.stopped() {
            return Ok(Some(Completion::Incomplete {
                reason,
                pending: store.pending()?.len(),
            }));
        }

        // This round's rows, every walk's together.
        let mut requests: Vec<RowRequest> = Vec::new();
        let mut spans: Vec<(usize, usize, Option<CachedBelow>)> = Vec::new();
        for walk in walks.iter_mut() {
            let start = requests.len();
            let mut older = None;
            if walk.dummies.is_none() && !walk.done {
                match walker.plan(store, walk) {
                    Ok((planned, below)) => {
                        requests.extend(planned);
                        older = below;
                    }
                    Err(error) => walker.fail(store, walk, failures, error.into())?,
                }
            }
            if let Some((child, count)) = walk.dummies {
                requests.extend((0..count).map(|_| rows.dummy(u32::from(child))));
            }
            spans.push((start, requests.len(), older));
        }
        let answers = rows.fetch(store, &requests)?;
        if answers.len() > requests.len()
            || answers.is_empty() && !requests.is_empty() && rows.stopped().is_none()
        {
            return Err(SyncError::Invalid("a round lost an answer".into()));
        }
        for (walk, (start, end, older)) in walks.iter_mut().zip(spans) {
            if walk.done {
                continue;
            }
            // A failed walk's dummies were this round's; their replies are
            // not read, and the walk ends.
            if walk.dummies.take().is_some() {
                failures.settle(entry.shard_id, &walk.item.script);
                walk.done = true;
                continue;
            }
            if start >= answers.len() && start != end {
                continue;
            }
            let available = if start == end {
                &[][..]
            } else {
                &answers[start..end.min(answers.len())]
            };
            if let Err(failure) = walker.advance(store, walk, available, older) {
                walker.fail(store, walk, failures, failure)?;
            }
        }
    }
}

/// What a walk checks against, for one directory shard revision.
struct Walker<'a> {
    entry: &'a transparent_filter::ShardMapEntry,
    manifest: &'a ShardManifest,
    geometry: &'static transparent_shard::layout::Geometry,
    /// Each page shard's chained identity, in hex: the run cache's key.
    identities: &'a [String],
    /// Each page shard's tag salt.
    salts: &'a [[u8; 32]],
    target_anchor: &'a Anchor,
}

/// Page shard `child` of a directory shard, which its manifest must declare.
fn page_child(manifest: &ShardManifest, shard_id: u64, child: u8) -> Result<&PageChild, SyncError> {
    manifest.child(u32::from(child)).ok_or_else(|| {
        SyncError::Content(format!(
            "shard {shard_id} names page shard {child}, which it does not declare"
        ))
    })
}

/// The request for `row` of page shard `child`, if the row is one a query of
/// that table can select. A pointer is a claim like any other.
pub(super) fn locate(
    manifest: &ShardManifest,
    geometry: &transparent_shard::layout::Geometry,
    shard_id: u64,
    child: u8,
    row: u64,
) -> Result<RowRequest, SyncError> {
    let page = page_child(manifest, shard_id, child)?;
    if page.page_segments.is_empty() {
        return Err(SyncError::Content(format!(
            "shard {shard_id} points into page shard {child}, which holds no rows"
        )));
    }
    let space = geometry.page_rows * page.page_segments.len() as u64;
    let (_, within) = transparent_shard::layout::split_row(row, geometry.page_rows);
    if row >= space || within >= page.query_rows() {
        return Err(SyncError::Content(format!(
            "shard {shard_id} page {row} is outside page shard {child}'s table"
        )));
    }
    Ok(RowRequest {
        child: u32::from(child),
        row,
    })
}

impl Walker<'_> {
    fn child(&self, child: u8) -> Result<&PageChild, SyncError> {
        page_child(self.manifest, self.entry.shard_id, child)
    }

    /// The request for `row` of page shard `child`; see [`locate`].
    fn locate(&self, child: u8, row: u64) -> Result<RowRequest, SyncError> {
        locate(
            self.manifest,
            self.geometry,
            self.entry.shard_id,
            child,
            row,
        )
    }

    /// Checks a run's first fragment, read at `cursor`, before the walk
    /// relies on it: every fragment it declares must be a row a page query
    /// can select, or the run is not located at all. Then its link: the
    /// older-run count its chain promised (see [`check_head`]) and a run to
    /// link to that starts at a row of an earlier, declared page shard. A
    /// link that fails any of these still leaves this run located, so the
    /// walk owes the queries for its fragments not yet held, of `held`, and
    /// one in the link's place unless the honest walk would not follow it,
    /// all as dummies: the round the honest walk would send.
    fn check_located<S: WalletStore>(
        &self,
        store: &S,
        script: &[u8],
        head: &PageEntry,
        cursor: &RunCursor,
        held: usize,
    ) -> Result<(), Failure> {
        let last = u64::from(cursor.row) + u64::from(head.fragment_count.max(1)) - 1;
        self.locate(cursor.child, last)?;
        let link = check_head(head, cursor).and_then(|()| match head.link.previous() {
            Some((child, row)) => self.locate(child, u64::from(row)).map(|_| ()),
            None => Ok(()),
        });
        let Err(error) = link else {
            return Ok(());
        };
        let link_query = self.owed_link_query(store, script, head, cursor)?;
        Err(Failure {
            error,
            child: cursor.child,
            dummies: head.fragment_count.saturating_sub(held.max(1) as u32) + link_query,
        })
    }

    /// Whether the honest walk would query a head after the run at `cursor`.
    ///
    /// It would not when this run is in page shard 0: that shard has no
    /// earlier one, so an honest run there never links backward. Nor when the
    /// chain already promised this run was the oldest, nor when this script's
    /// previous run is cached: a catch-up stops there and sends nothing for
    /// it. When the link still names an earlier, declared page shard (only its
    /// row or its older-run count is bad), that is the page shard the honest
    /// walk would look up in the cache. Otherwise the previous run is taken to
    /// be in the page shard just below. Either way a bad link must not add a
    /// query the honest walk omits.
    fn owed_link_query<S: WalletStore>(
        &self,
        store: &S,
        script: &[u8],
        head: &PageEntry,
        cursor: &RunCursor,
    ) -> Result<u32, SyncError> {
        if cursor.older_runs == Some(0) {
            return Ok(0);
        }
        let previous = match head.link.previous() {
            Some((child, _)) if child < cursor.child && self.child(child).is_ok() => child,
            _ => match cursor.child.checked_sub(1) {
                Some(below) => below,
                // No page shard is earlier than 0. Owing a query here would
                // tell the service that this row was read.
                None => return Ok(0),
            },
        };
        Ok(u32::from(self.cached(store, script, previous)?.is_none()))
    }

    /// One round's requests for a walk, and the history cached below its
    /// run when the walk will stop there.
    fn plan<S: WalletStore>(
        &self,
        store: &S,
        walk: &Walk,
    ) -> Result<(Vec<RowRequest>, Option<CachedBelow>), SyncError> {
        let cursor = walk.item.cursor;
        let Some(head) = &walk.head else {
            return Ok((
                vec![self.locate(cursor.child, u64::from(cursor.row))?],
                None,
            ));
        };
        let mut requests = Vec::new();
        for ordinal in walk.item.fragments.len() as u32..head.fragment_count {
            let row = u64::from(cursor.row) + u64::from(ordinal);
            requests.push(self.locate(cursor.child, row)?);
        }
        let mut older = None;
        if let Some((child, row)) = head.link.previous() {
            older = self
                .cached(store, &walk.item.script, child)?
                .map(|events| (child, events));
            if older.is_none() {
                requests.push(self.locate(child, u64::from(row))?);
            }
        }
        Ok((requests, older))
    }

    /// The history cached for `script` from its run in page shard `child`
    /// back to the start of the directory shard, when that page shard is
    /// sealed. Each cached run holds only its own events and names the cached
    /// run below it, so the history is put back together by following those
    /// names; a missing run anywhere along the way is a miss.
    fn cached<S: WalletStore>(
        &self,
        store: &S,
        script: &[u8],
        child: u8,
    ) -> Result<Option<Vec<TransparentEvent>>, SyncError> {
        if !self.child(child)?.sealed {
            return Ok(None);
        }
        let corrupt = |why: &str| SyncError::Store(StoreError::Corrupt(why.into()));
        let mut index = usize::from(child);
        let mut runs = Vec::new();
        loop {
            let Some(run) = store.cached_run(&self.identities[index], script)? else {
                return Ok(None);
            };
            if run.events.is_empty() {
                return Err(corrupt("a cached run holds no events"));
            }
            runs.push(run.events);
            let Some(older) = run.older else { break };
            // The identity of a page shard covers every older one, so the run
            // below must be in an earlier page shard of this directory shard.
            index = self.identities[..index]
                .iter()
                .position(|identity| *identity == older)
                .ok_or_else(|| {
                    corrupt("a cached run names a run outside the page shards below it")
                })?;
        }
        let mut history: Vec<TransparentEvent> = Vec::new();
        for run in runs.into_iter().rev() {
            if let (Some(last), Some(first)) = (history.last(), run.first()) {
                if last.sort_key() >= first.sort_key() {
                    return Err(corrupt("cached runs are not in order"));
                }
            }
            history.extend(run);
        }
        Ok(Some(history))
    }

    /// The one fragment of `script`'s run in page shard `child` with this
    /// ordinal, among every segment's row. Exactly one may claim it.
    fn fragment(
        &self,
        script: &[u8],
        child: u8,
        answers: &[Vec<u8>],
        ordinal: u32,
        count: Option<u32>,
    ) -> Result<PageEntry, SyncError> {
        let shard_id = self.entry.shard_id;
        let wanted = transparent_shard::script_tag(&self.salts[usize::from(child)], script);
        // A packed row also carries other scripts' histories. Those are
        // discarded, and deliberately not used: two of a wallet's own scripts
        // sharing a row still cost two fetches, so the request transcript does
        // not depend on which scripts share a row.
        let mut found = None;
        for raw in answers {
            let decoded = transparent_shard::page_row::decode_page_row(raw).map_err(|error| {
                SyncError::Content(format!("shard {shard_id} page shard {child}: {error}"))
            })?;
            for candidate in decoded {
                if candidate.tag != wanted || candidate.ordinal != ordinal {
                    continue;
                }
                if count.is_some_and(|count| candidate.fragment_count != count) {
                    return Err(SyncError::Content(format!(
                        "shard {shard_id} page shard {child}: fragment {ordinal} disagrees with \
                         its run's fragment count"
                    )));
                }
                if found.is_some() {
                    return Err(SyncError::Content(format!(
                        "shard {shard_id} page shard {child} holds fragment {ordinal} twice"
                    )));
                }
                found = Some(candidate);
            }
        }
        found.ok_or_else(|| {
            SyncError::Content(format!(
                "shard {shard_id} page shard {child}: the row a link located does not hold \
                 fragment {ordinal} of the run"
            ))
        })
    }

    /// Takes one walk through one round's replies.
    fn advance<S: WalletStore>(
        &self,
        store: &mut S,
        walk: &mut Walk,
        answers: &[Reply],
        older: Option<CachedBelow>,
    ) -> Result<(), Failure> {
        let cursor = walk.item.cursor;
        let script = walk.item.script.clone();
        if walk.head.is_none() {
            let [answer] = answers else {
                return Err(SyncError::Invalid("a round lost an answer".into()).into());
            };
            let head = self.fragment(&script, cursor.child, answer, 0, None)?;
            self.check_located(store, &script, &head, &cursor, 1)?;
            walk.item.fragments.push(encode_fragment(&head)?);
            walk.head = Some(head);
            return Ok(self.commit(
                store,
                &script,
                Vec::new(),
                Some(walk.item.clone()),
                None,
                Vec::new(),
            )?);
        }
        let head = walk.head.as_ref().expect("head decoded above").clone();
        let count = head.fragment_count as usize;
        if walk.item.fragments.len() > count {
            return Err(SyncError::Invalid("a run has too many fragments".into()).into());
        }
        let remaining = count - walk.item.fragments.len();
        let (answers, next) = answers.split_at(remaining.min(answers.len()));
        if next.len() > 1 {
            return Err(SyncError::Invalid("a round has extra answers".into()).into());
        }
        // The run's fragments this round asked for and a budget left unsent:
        // what the walk still owes if this run fails.
        let unsent = (remaining - answers.len()) as u32;
        let failing = |error: SyncError| Failure {
            error,
            child: cursor.child,
            dummies: unsent,
        };
        let mut boundary = validate_page_boundary(None, &head.events).map_err(failing)?;
        let mut run = head.events.clone();
        // Recheck saved boundaries before using them after a restart.
        for (ordinal, raw) in walk.item.fragments.iter().enumerate().skip(1) {
            let fragment = self
                .fragment(
                    &script,
                    cursor.child,
                    std::slice::from_ref(raw),
                    ordinal as u32,
                    Some(head.fragment_count),
                )
                .map_err(failing)?;
            boundary =
                validate_page_boundary(Some(&boundary), &fragment.events).map_err(failing)?;
            run.extend(fragment.events);
        }
        for answer in answers {
            let ordinal = walk.item.fragments.len() as u32;
            let fragment = self
                .fragment(
                    &script,
                    cursor.child,
                    answer,
                    ordinal,
                    Some(head.fragment_count),
                )
                .map_err(failing)?;
            boundary =
                validate_page_boundary(Some(&boundary), &fragment.events).map_err(failing)?;
            run.extend(fragment.events.iter().copied());
            walk.item.fragments.push(encode_fragment(&fragment)?);
        }
        if walk.item.fragments.len() < count {
            return Ok(self.commit(
                store,
                &script,
                Vec::new(),
                Some(walk.item.clone()),
                None,
                Vec::new(),
            )?);
        }
        check_run(self.child(cursor.child)?, &run, &walk.item.carried)?;
        walk.walked.push((cursor.child, run.clone()));
        match head.link.previous() {
            None => Ok(self.finish(store, walk, run, None)?),
            Some(_) if older.is_some() => Ok(self.finish(store, walk, run, older)?),
            Some((child, row)) => {
                let mut following = run.clone();
                following.extend(walk.item.carried.iter().copied());
                following.truncate(2);
                let mut progressed = walk.item.clone();
                progressed.cursor = RunCursor {
                    child,
                    row,
                    older_runs: Some(head.link.older_runs - 1),
                };
                progressed.carried = following;
                progressed.fragments.clear();
                // A bad head for the next run fails the walk, but not the run
                // already checked: that is committed, and the walk resumes at
                // the next run's head.
                let mut failure = None;
                let mut next_head = None;
                if let [answer] = next {
                    let checked = self
                        .fragment(&script, child, answer, 0, None)
                        .map_err(Failure::from)
                        .and_then(|head| {
                            self.check_located(store, &script, &head, &progressed.cursor, 1)?;
                            Ok(head)
                        });
                    match checked {
                        Ok(head) => {
                            progressed.fragments.push(encode_fragment(&head)?);
                            next_head = Some(head);
                        }
                        Err(error) => failure = Some(error),
                    }
                }
                progressed.attempts += 1;
                self.commit(
                    store,
                    &script,
                    run,
                    Some(progressed.clone()),
                    None,
                    Vec::new(),
                )?;
                walk.item = progressed;
                walk.head = next_head;
                failure.map_or(Ok(()), Err)
            }
        }
    }

    /// Takes a walk whose run is read in full through to its end, with no
    /// replies: what a stopped round still finishes.
    fn complete<S: WalletStore>(&self, store: &mut S, walk: &mut Walk) -> Result<(), Failure> {
        let older = match walk.head.as_ref().and_then(|head| head.link.previous()) {
            Some((child, _)) => self
                .cached(store, &walk.item.script, child)?
                .map(|events| (child, events)),
            None => None,
        };
        self.advance(store, walk, &[], older)
    }

    /// Ends a walk after `failure`. A content failure is counted against the
    /// walk's entry, which keeps its pending item for a later sync, and the
    /// walk sends the dummies it owes in the next round, if any; any other
    /// failure is the call's.
    fn fail<S: WalletStore>(
        &self,
        store: &mut S,
        walk: &mut Walk,
        failures: &mut Failures,
        failure: Failure,
    ) -> Result<(), SyncError> {
        let Failure {
            error,
            child,
            dummies,
        } = failure;
        let SyncError::Content(_) = error else {
            return Err(error);
        };
        let entry = self.entry;
        commit_bounded(
            store,
            self.target_anchor,
            ShardCommit {
                source_anchor: None,
                shard_id: entry.shard_id,
                revision_digest: entry.manifest_digest.clone(),
                sealed: entry.sealed,
                start_height: entry.start_height,
                end_height: entry.end_height,
                terminal_block_hash: entry.terminal_block_hash.clone(),
                failed_entries: vec![walk.item.script.clone()],
                ..Default::default()
            },
        )?;
        record_failure(
            store,
            &mut failures.entries,
            entry.shard_id,
            &walk.item.script,
        )?;
        if dummies > 0 {
            walk.dummies = Some((child, dummies));
            failures
                .owed
                .push((entry.shard_id, walk.item.script.clone(), child, dummies));
        } else {
            walk.done = true;
        }
        Ok(())
    }

    /// Ends a walk: `run` is the last run read, `older` the page shard and
    /// history cached below it, if the walk stopped at a cached run. Fills the
    /// run cache for every run this call read in a sealed page shard: each
    /// with its own events and the name of the cached run below it.
    fn finish<S: WalletStore>(
        &self,
        store: &mut S,
        walk: &mut Walk,
        run: Vec<TransparentEvent>,
        older: Option<CachedBelow>,
    ) -> Result<(), SyncError> {
        let (mut below, older) = match older {
            Some((child, events)) => (Some(self.identities[usize::from(child)].clone()), events),
            None => (None, Vec::new()),
        };
        let newer = run.first().or(walk.item.carried.first());
        if let (Some(last), Some(first)) = (older.last(), newer) {
            if last.sort_key() >= first.sort_key() {
                return Err(SyncError::Content(
                    "cached history is not older than the run that links to it".into(),
                ));
            }
        }
        let mut cached_runs = Vec::new();
        for (child, events) in walk.walked.iter().rev() {
            // Only the newest run can be in the open page shard, so every run
            // below a cached one is cached too.
            if !self.child(*child)?.sealed {
                break;
            }
            let identity = self.identities[usize::from(*child)].clone();
            cached_runs.push(CachedRun {
                child_digest: identity.clone(),
                script: walk.item.script.clone(),
                shard_id: self.entry.shard_id,
                events: events.clone(),
                older: below.replace(identity),
            });
        }
        let mut events = older;
        events.extend(run);
        let script = walk.item.script.clone();
        self.commit(store, &script, events, None, walk.item.id, cached_runs)?;
        walk.done = true;
        Ok(())
    }

    /// Commits a step of one walk: the events it read, and either the walk's
    /// next state or its end, with the script's coverage.
    fn commit<S: WalletStore>(
        &self,
        store: &mut S,
        script: &[u8],
        events: Vec<TransparentEvent>,
        progressed: Option<PendingPages>,
        finished: Option<u64>,
        cached_runs: Vec<CachedRun>,
    ) -> Result<(), SyncError> {
        let entry = self.entry;
        let done = progressed.is_none();
        commit_bounded(
            store,
            self.target_anchor,
            ShardCommit {
                source_anchor: None,
                shard_id: entry.shard_id,
                revision_digest: entry.manifest_digest.clone(),
                sealed: entry.sealed,
                start_height: entry.start_height,
                end_height: entry.end_height,
                terminal_block_hash: entry.terminal_block_hash.clone(),
                events: events
                    .into_iter()
                    .map(|event| StoredEvent {
                        script: script.to_vec(),
                        event,
                        shard_id: entry.shard_id,
                        revision_digest: entry.manifest_digest.clone(),
                    })
                    .collect(),
                covered_scripts: if done {
                    vec![script.to_vec()]
                } else {
                    Vec::new()
                },
                pending_upsert: progressed.into_iter().collect(),
                pending_complete: finished.into_iter().collect(),
                cached_runs,
                failed_entries: Vec::new(),
            },
        )?;
        Ok(())
    }
}

/// Checks a run's first fragment against the cursor that located it.
///
/// Its `older_runs` must be the one fewer the newer run promised — which is
/// what makes a chain cut short, or one that carries on past where it should
/// end, a refusal rather than a shorter or longer history. It may not claim
/// more older runs than there are earlier page shards, and its link must
/// point to an earlier page shard: never this one, never a later one.
pub(super) fn check_head(head: &PageEntry, cursor: &RunCursor) -> Result<(), SyncError> {
    let link = head.link;
    match cursor.older_runs {
        Some(expected) if link.older_runs != expected => {
            return Err(SyncError::Content(format!(
                "a run in page shard {} reports {} older runs where its chain promised {expected}",
                cursor.child, link.older_runs
            )));
        }
        _ if link.older_runs > cursor.child => {
            return Err(SyncError::Content(format!(
                "a run in page shard {} reports {} older runs",
                cursor.child, link.older_runs
            )));
        }
        _ => {}
    }
    if let Some((child, _)) = link.previous() {
        if child >= cursor.child {
            return Err(SyncError::Content(format!(
                "a run in page shard {} links to page shard {child}, which is not earlier",
                cursor.child
            )));
        }
    }
    Ok(())
}

/// Checks a run against the two events after it and its page shard.
///
/// Events strictly increase from the run into `carried`. Each of the run's
/// events was pushed out when the event two places after it arrived, into the
/// page shard open then, so that event's height lies in this page shard's
/// range. A run placed in any other page shard fails here.
pub(super) fn check_run(
    child: &PageChild,
    run: &[TransparentEvent],
    carried: &[TransparentEvent],
) -> Result<(), SyncError> {
    if run.is_empty() || carried.len() != transparent_shard::INLINE_EVENTS as usize {
        return Err(SyncError::Content(format!(
            "a run in page shard {} cannot be checked",
            child.index
        )));
    }
    let following: Vec<&TransparentEvent> = run.iter().chain(carried).collect();
    if following
        .windows(2)
        .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
    {
        return Err(SyncError::Content(format!(
            "a run in page shard {} is not older than the history after it",
            child.index
        )));
    }
    for (index, _) in run.iter().enumerate() {
        let height = event_height(following[index + 2]);
        if height < child.start_height || height > child.end_height {
            return Err(SyncError::Content(format!(
                "an event in page shard {} was pushed out at height {height}, when that page \
                 shard was not open",
                child.index
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_page_boundary(
    previous: Option<&crate::engine::store::PageBoundary>,
    events: &[transparent_events::TransparentEvent],
) -> Result<crate::engine::store::PageBoundary, SyncError> {
    let first = events
        .first()
        .ok_or_else(|| SyncError::Content("empty fragment".into()))?;
    if let Some(previous) = previous {
        if previous.last_event.sort_key() > first.sort_key()
            || previous.event_bytes as usize
                + transparent_shard::compact::event_len(first, Some(&previous.last_event))
                <= transparent_shard::packing::FRAGMENT_PAYLOAD
        {
            return Err(SyncError::Content("noncanonical fragment boundary".into()));
        }
    }
    Ok(crate::engine::store::PageBoundary {
        event_bytes: transparent_shard::compact::encoded_len(events) as u32,
        last_event: *events.last().expect("nonempty fragment"),
    })
}

pub(super) fn check_target_hash(map: &ShardMap, target: &Anchor) -> Result<(), SyncError> {
    if map
        .shard_for_height(target.height)
        .is_some_and(|s| s.end_height == target.height && s.terminal_block_hash != target.hash)
    {
        return Err(SyncError::Invalid(
            "publication endpoint disagrees with wallet-accepted target hash".into(),
        ));
    }
    Ok(())
}

/// Commits only the wallet-accepted prefix while retaining the publication identity.
pub(super) fn commit_bounded<S: WalletStore>(
    store: &mut S,
    target: &Anchor,
    mut commit: ShardCommit,
) -> Result<u64, SyncError> {
    let source = Anchor {
        height: commit.end_height,
        hash: commit.terminal_block_hash.clone(),
    };
    for event in commit
        .events
        .iter()
        .map(|e| &e.event)
        .chain(commit.pending_upsert.iter().flat_map(|p| p.carried.iter()))
    {
        let height = event_height(event);
        if height < commit.start_height || height > source.height {
            return Err(SyncError::Content(
                "event lies outside its published shard".into(),
            ));
        }
    }
    commit.source_anchor = Some(source);
    if commit.end_height >= target.height {
        commit.end_height = target.height;
        commit.terminal_block_hash = target.hash.clone();
    }
    // Events above the target are not kept. A walk's carried events are not
    // history but what it checks the next run against, so they stay whole.
    commit
        .events
        .retain(|e| event_height(&e.event) <= target.height);
    // What a reply carried contradicting what the store holds is the reply's
    // content failure, not the store's.
    store.commit_shard(commit).map_err(|error| match error {
        StoreError::Contradiction(why) => SyncError::Content(format!("contradiction: {why}")),
        other => SyncError::Store(other),
    })
}

/// A checked fragment, saved as a page row holding only it.
fn encode_fragment(fragment: &PageEntry) -> Result<Vec<u8>, SyncError> {
    Ok(transparent_shard::page_row::encode_page_row(
        std::slice::from_ref(fragment),
    )?)
}
