use super::{
    Clients, Completion, Failures, GeometryClients, IncompleteReason, MAX_OVERLOAD_ATTEMPTS,
    OVERLOAD_BACKOFF, OVERLOAD_BACKOFF_CAP, PirRows, Reply, ServiceGeometry, SyncError, WorkLimits,
    budget_stopped, commit_bounded, directory_choice, event_height, fetch_manifest, held, hold,
    holds_history, locate, open_table, record_failure, tag_salt_of, walk_chains,
};
use crate::engine::adapters::{Acceptance, ChainView};
use crate::engine::client::{ClientError, Table};
use crate::engine::store::{
    Anchor, PendingPages, RunCursor, SetupKey, ShardCommit, StoredEvent, WalletStore,
};
use crate::engine::transport::{ByteCharges, FilterSource, ShardTransport, StaleRevision};
use std::time::Duration;
use transparent_filter::{BlockHash, FilterLimits, ScriptBytes, ShardKey, ShardMap};
use transparent_shard::build::candidate_rows;
use transparent_shard::manifest::ShardManifest;
use transparent_shard::records::DirectoryEntry;

pub(super) enum ShardRead {
    /// Every script in scope was covered; `matched` names those with history.
    Done { matched: Vec<Vec<u8>> },
    /// The filter matched but nothing was found; coverage advanced anyway.
    Unproductive { count: u64 },
    /// A budget or refusal stopped the sync with the store consistent.
    Stopped(Completion),
}

/// Reads one shard for the scripts that need it, committing to the store.
#[allow(clippy::too_many_arguments)]
pub(super) fn read_shard_into<S: WalletStore>(
    store: &mut S,
    map: &ShardMap,
    entry: &transparent_filter::ShardMapEntry,
    previous_digest: &str,
    genesis: BlockHash,
    scripts: &[Vec<u8>],
    geometry: &ServiceGeometry,
    clients: &mut Clients,
    filters: &mut impl FilterSource,
    transport: &mut impl ShardTransport,
    charges: &mut ByteCharges,
    limits: &WorkLimits,
    target_anchor: &Anchor,
    chain: &impl ChainView,
    failures: &mut Failures,
) -> Result<ShardRead, SyncError> {
    let endpoint = endpoint_of(entry, target_anchor);
    match chain.is_accepted(endpoint.height, &endpoint.hash) {
        Acceptance::Accepted => {}
        Acceptance::Unknown => {
            return Ok(ShardRead::Stopped(Completion::Incomplete {
                reason: IncompleteReason::ChainUnknown {
                    height: endpoint.height,
                },
                pending: store.pending()?.len(),
            }));
        }
        Acceptance::Rejected => {
            return Err(SyncError::Invalid(
                "published coverage endpoint rejected by wallet chain".into(),
            ));
        }
    }
    // Ordinary sources download every filter in range. The explicit experiment
    // may establish a parent negative; both paths use the same bounded commit.
    let cached = store.filter(&entry.manifest_digest, &entry.filter_hash)?;
    let (parent_negative, parent_cost) = if cached.is_none() {
        filters
            .parent_negative(map, entry.shard_id, scripts, store)
            .map_err(|e| SyncError::Transport(e.to_string()))?
    } else {
        (false, 0)
    };
    charges.filter_bytes += parent_cost;
    let matches = if parent_negative {
        Vec::new()
    } else {
        let bytes = match cached {
            Some(bytes) => bytes,
            None => {
                let (bytes, cost) = filters.filter(entry.shard_id).map_err(|error| {
                    SyncError::Transport(crate::engine::transport::describe_error(error.as_ref()))
                })?;
                charges.filter_bytes += cost;
                // Bind the bytes to the map before believing anything they say.
                if transparent_filter::filter_hash(&bytes).to_display_hex() != entry.filter_hash {
                    // The public filter URL is shard-addressed: activation may
                    // have replaced it since this map was fetched. Never cache or
                    // match these bytes. The bounded stale-revision path requires
                    // a changed, validated map before retrying; an unchanged map
                    // still fails, including when the filter was simply corrupt.
                    return Err(SyncError::StaleRevision {
                        shard_id: entry.shard_id,
                        stale: StaleRevision {
                            shard_id: entry.shard_id,
                            revision: entry.manifest_digest.clone(),
                            map_sha256: None,
                        },
                        refreshes: 0,
                    });
                }
                store.put_filter(
                    &entry.manifest_digest,
                    &entry.filter_hash,
                    entry.sealed,
                    &bytes,
                )?;
                bytes
            }
        };
        charges.filters_checked += 1;
        match_filter(map, entry, genesis, scripts, &bytes)?
    };
    if matches.is_empty() {
        // A genuinely empty range for every script here: coverage advances
        // with no private request.
        commit_bounded(
            store,
            target_anchor,
            ShardCommit {
                source_anchor: None,
                shard_id: entry.shard_id,
                revision_digest: entry.manifest_digest.clone(),
                sealed: entry.sealed,
                start_height: entry.start_height,
                end_height: entry.end_height,
                terminal_block_hash: entry.terminal_block_hash.clone(),
                events: Vec::new(),
                covered_scripts: scripts.to_vec(),
                pending_upsert: Vec::new(),
                pending_complete: Vec::new(),
                cached_runs: Vec::new(),
                failed_entries: Vec::new(),
            },
        )?;
        return Ok(ShardRead::Done {
            matched: Vec::new(),
        });
    }
    // A geometry this build does not know is fatal the moment there is
    // something to fetch, whatever the manifest would say about it.
    if transparent_shard::layout::by_name(&entry.geometry).is_none() {
        return Err(SyncError::UnknownGeometry(entry.geometry.clone()));
    }
    let matched_all: Vec<Vec<u8>> = matches.iter().map(|&i| scripts[i].clone()).collect();
    let unmatched: Vec<Vec<u8>> = scripts
        .iter()
        .filter(|script| !matched_all.contains(script))
        .cloned()
        .collect();
    // An entry held out of this sync is not queried at all, and stays
    // uncovered over this shard.
    let mut matched_scripts = Vec::with_capacity(matched_all.len());
    for script in matched_all {
        if !hold(
            store,
            &mut failures.entries,
            entry.shard_id,
            &entry.manifest_digest,
            &script,
        )? {
            matched_scripts.push(script);
        }
    }
    if matched_scripts.is_empty() {
        if !unmatched.is_empty() {
            commit_bounded(
                store,
                target_anchor,
                ShardCommit {
                    source_anchor: None,
                    shard_id: entry.shard_id,
                    revision_digest: entry.manifest_digest.clone(),
                    sealed: entry.sealed,
                    start_height: entry.start_height,
                    end_height: entry.end_height,
                    terminal_block_hash: entry.terminal_block_hash.clone(),
                    covered_scripts: unmatched,
                    ..Default::default()
                },
            )?;
        }
        return Ok(ShardRead::Done {
            matched: Vec::new(),
        });
    }

    let outcome = with_refusals(
        store,
        map,
        entry,
        previous_digest,
        geometry,
        clients,
        transport,
        charges,
        limits,
        |store, prepared, transport, charges, manifest| {
            // Validated when the manifest was verified; decoded again here
            // rather than carried, since it is a few kilobytes.
            let choice = directory_choice(manifest)?;
            let salt = tag_salt_of(manifest)?;
            retrieve_shard_into(
                store,
                entry,
                manifest,
                &matched_scripts,
                &unmatched,
                choice.as_ref(),
                &salt,
                prepared,
                transport,
                charges,
                limits,
                target_anchor,
                chain,
                failures,
            )
        },
    )?;
    match outcome {
        Some(stopped) => Ok(ShardRead::Stopped(stopped)),
        None => {
            // Which matched scripts actually held history is what the
            // caller's gap-limit rule wants; the store knows.
            let mut found = Vec::new();
            let mut unproductive = 0u64;
            let events = store.events()?;
            for script in &matched_scripts {
                // Only a failure under this revision hides the script's
                // activity: one recorded under a withdrawn revision stays
                // reported, but does not suppress what its replacement found.
                if failures.entries.iter().any(|held| {
                    held.shard_id == entry.shard_id
                        && held.revision_digest == entry.manifest_digest
                        && held.script == *script
                }) {
                    continue;
                }
                if holds_history(&events, script, entry, target_anchor.height) {
                    found.push(script.clone());
                } else {
                    unproductive += 1;
                }
            }
            if found.is_empty() {
                Ok(ShardRead::Unproductive {
                    count: unproductive,
                })
            } else {
                Ok(ShardRead::Done { matched: found })
            }
        }
    }
}

/// The block a shard's coverage ends on for this sync: its own terminal
/// block, or the target when the shard runs past it.
pub(super) fn endpoint_of(
    entry: &transparent_filter::ShardMapEntry,
    target_anchor: &Anchor,
) -> Anchor {
    if entry.end_height > target_anchor.height {
        target_anchor.clone()
    } else {
        Anchor {
            height: entry.end_height,
            hash: entry.terminal_block_hash.clone(),
        }
    }
}

/// Which of `scripts` a shard's filter matches, by index.
pub(super) fn match_filter(
    map: &ShardMap,
    entry: &transparent_filter::ShardMapEntry,
    genesis: BlockHash,
    scripts: &[Vec<u8>],
    bytes: &[u8],
) -> Result<Vec<usize>, SyncError> {
    let profile = transparent_filter::range_profile(&map.profile)
        .ok_or_else(|| SyncError::UnknownProfile(map.profile.clone()))?;
    let validated =
        transparent_filter::validate_range_filter(bytes, FilterLimits::default(), profile)?;
    let terminal = BlockHash::from_display_hex(&entry.terminal_block_hash)?;
    let key = ShardKey::derive(
        &map.profile,
        genesis,
        entry.shard_id,
        entry.start_height,
        entry.end_height,
        terminal,
    );
    let owned: Vec<ScriptBytes> = scripts
        .iter()
        .map(|script| ScriptBytes::new(script.clone()))
        .collect();
    Ok(transparent_filter::match_range_scripts(
        &validated, key, &owned,
    )?)
}

/// Runs `work` against a shard, verifying the manifest first and lifting the
/// service's two refusals: a withdrawn revision propagates for the map
/// refresh, an overload is retried with backoff and then reported as an
/// incomplete sync with the store consistent.
#[allow(clippy::too_many_arguments)]
pub(super) fn with_refusals<S: WalletStore, T: ShardTransport, F>(
    store: &mut S,
    map: &ShardMap,
    entry: &transparent_filter::ShardMapEntry,
    previous_digest: &str,
    geometry: &ServiceGeometry,
    clients: &mut Clients,
    transport: &mut T,
    charges: &mut ByteCharges,
    limits: &WorkLimits,
    mut work: F,
) -> Result<Option<Completion>, SyncError>
where
    F: FnMut(
        &mut S,
        &mut GeometryClients,
        &mut T,
        &mut ByteCharges,
        &ShardManifest,
    ) -> Result<Option<Completion>, SyncError>,
{
    let _ = limits;
    let mut attempt = 1u32;
    let mut manifest: Option<ShardManifest> = None;
    loop {
        let verified = match &manifest {
            Some(verified) => verified,
            None => match fetch_manifest(entry, previous_digest, map, transport, charges) {
                Ok(verified) => {
                    if verified.schema != geometry.schema {
                        return Err(SyncError::ManifestMismatch {
                            shard_id: entry.shard_id,
                            field: "schema",
                        });
                    }
                    manifest.insert(verified)
                }
                Err(SyncError::Client(ClientError::Stale(stale))) => {
                    return Err(SyncError::StaleRevision {
                        shard_id: entry.shard_id,
                        stale,
                        refreshes: 0,
                    });
                }
                Err(SyncError::Client(ClientError::Overloaded(overloaded))) => {
                    if attempt >= MAX_OVERLOAD_ATTEMPTS {
                        return Ok(Some(Completion::Incomplete {
                            reason: IncompleteReason::Overloaded {
                                shard_id: entry.shard_id,
                            },
                            pending: store.pending()?.len(),
                        }));
                    }
                    std::thread::sleep(overload_backoff(attempt, overloaded.retry_after));
                    attempt += 1;
                    continue;
                }
                Err(other) => return Err(other),
            },
        };
        let prepared = clients.prepare(&verified.geometry, &geometry.geometries)?;
        match work(store, prepared, transport, charges, verified) {
            Ok(stopped) => return Ok(stopped),
            Err(SyncError::Client(ClientError::Stale(stale))) => {
                return Err(SyncError::StaleRevision {
                    shard_id: entry.shard_id,
                    stale,
                    refreshes: 0,
                });
            }
            Err(SyncError::Client(ClientError::Overloaded(overloaded))) => {
                if attempt >= MAX_OVERLOAD_ATTEMPTS {
                    return Ok(Some(Completion::Incomplete {
                        reason: IncompleteReason::Overloaded {
                            shard_id: entry.shard_id,
                        },
                        pending: store.pending()?.len(),
                    }));
                }
                // Nothing partial is lost: every commit so far stands, and
                // the work resumes from the store on the next attempt.
                std::thread::sleep(overload_backoff(attempt, overloaded.retry_after));
                attempt += 1;
            }
            Err(SyncError::Client(ClientError::SetupMismatch {
                revision,
                table,
                segment,
            })) => {
                // The setup held for that segment is not the one the service
                // answers under. It is forgotten, here and in the store, so
                // the next attempt fetches it again; this read still fails,
                // as any failed request does, and counts against no entry.
                let prepared = clients.prepare(&verified.geometry, &geometry.geometries)?;
                match table {
                    Table::Directory => prepared.directory.forget(&revision, table, segment),
                    Table::Pages(_) => prepared.pages.forget(&revision, table, segment),
                }
                let set_digest = store
                    .set_identity()?
                    .map(|identity| identity.digest())
                    .unwrap_or_default();
                store.drop_setup(&SetupKey {
                    set_digest,
                    revision_digest: revision.clone(),
                    table,
                    segment,
                })?;
                return Err(SyncError::Client(ClientError::SetupMismatch {
                    revision,
                    table,
                    segment,
                }));
            }
            Err(SyncError::Store(crate::engine::store::StoreError::PendingLimit { .. })) => {
                return Ok(Some(Completion::Incomplete {
                    reason: IncompleteReason::PendingLimit,
                    pending: store.pending()?.len(),
                }));
            }
            Err(other) => return Err(other),
        }
    }
}

/// How long to wait before re-asking an overloaded service.
///
/// The service's own figure is preferred, because it knows why it refused, but
/// it is capped: a delay a wallet cannot sanity-check is a delay a
/// misconfigured or hostile service could use to park a sync inside one call.
/// Either way the wait is jittered by up to half again, so wallets refused
/// together do not return together.
pub(super) fn overload_backoff(attempt: u32, asked: Option<Duration>) -> Duration {
    let wait = asked.unwrap_or_else(|| OVERLOAD_BACKOFF * 2u32.saturating_pow(attempt - 1));
    crate::engine::backoff::jittered(wait.min(OVERLOAD_BACKOFF_CAP))
}

/// The directory phase for one shard: the candidate rows for every matched
/// script, inline events committed, chain walks recorded; then the walks.
///
/// A script whose replies fail on content fails its entry alone: it gets no
/// coverage and no walk, as an entry with inline history or a false-positive
/// match sends no pages either. Other scripts' processed prefixes still land,
/// counting the failure. Every directory query planned for
/// a script is sent before any of its replies is decoded, so the queries sent
/// are the same whatever came back, and in the order a lookahead stashed them.
/// A retry after an overload sends them again for every script without a
/// saved walk, failed ones included, so it too is the honest retry.
#[allow(clippy::too_many_arguments)]
pub(super) fn retrieve_shard_into<S: WalletStore, T: ShardTransport>(
    store: &mut S,
    entry: &transparent_filter::ShardMapEntry,
    manifest: &ShardManifest,
    matched: &[Vec<u8>],
    unmatched: &[Vec<u8>],
    choice: Option<&transparent_shard::ChoiceTable>,
    salt: &[u8; 32],
    clients: &mut GeometryClients,
    transport: &mut T,
    charges: &mut ByteCharges,
    limits: &WorkLimits,
    target_anchor: &Anchor,
    chain: &impl ChainView,
    failures: &mut Failures,
) -> Result<Option<Completion>, SyncError> {
    let shard_id = entry.shard_id;
    let geometry = transparent_shard::layout::by_name(&entry.geometry)
        .ok_or_else(|| SyncError::UnknownGeometry(entry.geometry.clone()))?;
    let revision = entry.manifest_digest.as_str();
    // An overload can occur after the directory commit but before the walks
    // finish. with_refusals calls this function again on retry. Resume those
    // durable walks first: rediscovering their directories would enqueue
    // duplicate work and leave the original walks pending after the retry.
    let pending: Vec<_> = store
        .pending()?
        .into_iter()
        .filter(|p| p.shard_id == shard_id && p.revision_digest == revision)
        .collect();
    let mut resumed = Vec::with_capacity(pending.len());
    for item in &pending {
        if !held(store, &failures.entries, shard_id, revision, &item.script)?
            || failures.owes(shard_id, revision, &item.script).is_some()
        {
            resumed.push(item.clone());
        }
    }
    if !resumed.is_empty() {
        if let Some(stopped) = finish_pages(
            store,
            entry,
            manifest,
            &resumed,
            clients,
            transport,
            charges,
            limits,
            target_anchor,
            chain,
            failures,
        )? {
            return Ok(Some(stopped));
        }
    }
    // A retry after an overload asks again for every matched script without
    // a saved walk, as an honest retry does for inline entries and false
    // positives. An entry that already failed in this sync is asked again
    // too, so the queries do not show which entries failed, but its replies
    // are not read: it is not counted twice, covered, or walked.
    let mut unowed = Vec::with_capacity(matched.len());
    for script in matched {
        if !pending.iter().any(|p| &p.script == script) {
            let failed = held(store, &failures.entries, shard_id, revision, script)?;
            unowed.push((script, failed));
        }
    }
    let matched = unowed;
    if matched.is_empty() {
        // The earlier directory commit also covered all unmatched scripts.
        return Ok(None);
    }
    let set_digest = store
        .set_identity()?
        .map(|identity| identity.digest())
        .unwrap_or_default();
    if store.pending_limit() == 0 {
        return Ok(Some(Completion::Incomplete {
            reason: IncompleteReason::PendingLimit,
            pending: store.pending()?.len(),
        }));
    }
    if !open_table(
        store,
        &set_digest,
        shard_id,
        revision,
        Table::Directory,
        entry.directory_segments,
        &mut clients.directory,
        transport,
        charges,
        Some(limits),
    )? {
        return Ok(Some(Completion::Incomplete {
            reason: budget_stopped(charges, limits).expect("setup stopped at a budget"),
            pending: store.pending()?.len(),
        }));
    }

    let mut matched = matched.into_iter().peekable();
    let mut unmatched = unmatched.to_vec();
    while matched.peek().is_some() {
        // Any directory answer may start a page walk. Admit at most the free
        // pending capacity, commit that prefix, then drain it before asking
        // another group. A capacity-one store can therefore make progress.
        let available = store.pending_limit().saturating_sub(store.pending()?.len());
        if available == 0 {
            return Ok(Some(Completion::Incomplete {
                reason: IncompleteReason::PendingLimit,
                pending: store.pending()?.len(),
            }));
        }
        let mut stopped = None;
        let mut events: Vec<StoredEvent> = Vec::new();
        let mut covered: Vec<Vec<u8>> = std::mem::take(&mut unmatched);
        let mut pending_upsert: Vec<PendingPages> = Vec::new();
        let mut failed_here: Vec<Vec<u8>> = Vec::new();

        for _ in 0..available {
            if matched.peek().is_none() {
                break;
            }
            if let Some(reason) = budget_stopped(charges, limits) {
                stopped = Some(reason);
                break;
            }
            let (script, failed) = matched.next().expect("matched script remains");
            // With a published choice table, exactly the one candidate row it
            // names is queried. Without one, both candidate rows are. Either way
            // the query count per matched script is fixed for the shard: querying
            // the first and stopping on a hit would make it depend on where the
            // script landed, which is a function of the script. Candidates are
            // taken over the shard's whole logical row space; each names one row
            // within a segment, and every segment answers it.
            let wanted = transparent_shard::script_tag(salt, script);
            let rows = geometry.directory_rows * entry.directory_segments as u64;
            let candidates = candidate_rows(shard_id, script, rows);
            let queried: &[u64] = match choice {
                Some(table) => std::slice::from_ref(&candidates[table.choice(shard_id, script)]),
                None => &candidates,
            };
            let mut replies = Vec::with_capacity(queried.len());
            for &row in queried {
                let (_, within) =
                    transparent_shard::layout::split_row(row, geometry.directory_rows);
                let directory_rows = clients.directory.rows();
                let answer = clients.directory.fetch_row(
                    transport,
                    shard_id,
                    revision,
                    Table::Directory,
                    entry.directory_segments,
                    directory_rows,
                    within as usize,
                    charges,
                );
                replies.push((row, answer));
            }
            // Complete the fixed candidate group even if a reply failed. Neither
            // a hit nor a malformed/refused reply may select a shorter pattern.
            let replies = replies
                .into_iter()
                .map(|(row, answer)| Ok((row, answer?)))
                .collect::<Result<Vec<_>, SyncError>>()?;
            if failed {
                continue;
            }
            let found = match entry_in(entry, manifest, geometry, &wanted, &replies) {
                Ok(found) => found,
                Err(SyncError::Content(_)) => {
                    failed_here.push(script.clone());
                    continue;
                }
                Err(other) => return Err(other),
            };
            match found {
                // A filter match with no directory entry is either a false positive
                // or a script outside the private tables' coverage. Both are
                // wasted work rather than errors; coverage still advances.
                None => covered.push(script.clone()),
                Some(found) => {
                    for event in &found.inline {
                        events.push(StoredEvent {
                            script: script.clone(),
                            event: *event,
                            shard_id,
                            revision_digest: revision.to_string(),
                        });
                    }
                    match found.head() {
                        Some((child, row)) => pending_upsert.push(PendingPages {
                            id: None,
                            shard_id,
                            revision_digest: revision.to_string(),
                            script: script.clone(),
                            cursor: RunCursor {
                                child,
                                row,
                                older_runs: None,
                            },
                            fragments: Vec::new(),
                            carried: found.inline.clone(),
                            attempts: 0,
                            target_anchor: Some(target_anchor.clone()),
                        }),
                        None => covered.push(script.clone()),
                    }
                }
            }
        }

        // Only this processed prefix is committed: uncovered scripts remain
        // discoverable on the next call, and its walks can resume durably.
        let pending_ids_before: std::collections::BTreeSet<u64> =
            store.pending()?.iter().filter_map(|p| p.id).collect();
        let committed = commit_bounded(
            store,
            target_anchor,
            ShardCommit {
                source_anchor: None,
                shard_id,
                revision_digest: revision.to_string(),
                sealed: entry.sealed,
                start_height: entry.start_height,
                end_height: entry.end_height,
                terminal_block_hash: entry.terminal_block_hash.clone(),
                events,
                covered_scripts: covered,
                pending_upsert,
                pending_complete: Vec::new(),
                cached_runs: Vec::new(),
                failed_entries: failed_here.clone(),
            },
        );
        if let Err(SyncError::Store(crate::engine::store::StoreError::PendingLimit { .. })) =
            &committed
        {
            return Ok(Some(Completion::Incomplete {
                reason: IncompleteReason::PendingLimit,
                pending: store.pending()?.len(),
            }));
        }
        committed?;
        for script in &failed_here {
            record_failure(store, &mut failures.entries, shard_id, revision, script)?;
        }
        let owed: Vec<PendingPages> = store
            .pending()?
            .into_iter()
            .filter(|p| {
                p.shard_id == shard_id
                    && p.revision_digest == revision
                    && p.id.is_some_and(|id| !pending_ids_before.contains(&id))
            })
            .collect();
        if !owed.is_empty() {
            if let Some(stopped) = finish_pages(
                store,
                entry,
                manifest,
                &owed,
                clients,
                transport,
                charges,
                limits,
                target_anchor,
                chain,
                failures,
            )? {
                return Ok(Some(stopped));
            }
        }
        if let Some(reason) = stopped {
            return Ok(Some(Completion::Incomplete {
                reason,
                pending: store.pending()?.len(),
            }));
        }
    }
    Ok(None)
}

/// The entry tagged `wanted` among the replies to one script's candidate
/// rows, if there is one, checked as far as it can be before a page is read:
/// every reply decodes, the tag is in at most one row, the inline events lie
/// in the shard, and the run it points to is a row a page query can select.
/// Any of these failing is a content failure of the entry.
pub(super) fn entry_in(
    entry: &transparent_filter::ShardMapEntry,
    manifest: &ShardManifest,
    geometry: &transparent_shard::layout::Geometry,
    wanted: &[u8],
    replies: &[(u64, Reply)],
) -> Result<Option<DirectoryEntry>, SyncError> {
    let shard_id = entry.shard_id;
    let children = manifest.page_children.len() as u32;
    let mut found: Option<(u64, DirectoryEntry)> = None;
    for (row, reply) in replies {
        for raw in reply {
            let decoded = transparent_shard::records::decode_directory_row(raw, children)
                .map_err(|error| SyncError::Content(format!("shard {shard_id}: {error}")))?;
            for candidate in decoded {
                // The row is selected by a hash of the raw script. The tag
                // derived from this manifest's salt is what settles a hit.
                // A tag from any other salt does not match.
                if candidate.tag[..] != *wanted {
                    continue;
                }
                match &found {
                    // The two candidate hashes can name the same row. The row
                    // is still fetched twice, so the query count does not
                    // depend on the script, and the second sighting is the
                    // same entry, not a second.
                    Some((seen_row, _)) if seen_row == row => {}
                    Some(_) => {
                        return Err(SyncError::Content(format!(
                            "shard {shard_id} holds a script tag twice"
                        )));
                    }
                    None => found = Some((*row, candidate)),
                }
            }
        }
    }
    let Some((_, found)) = found else {
        return Ok(None);
    };
    if found.inline.iter().any(|event| {
        let height = event_height(event);
        height < entry.start_height || height > entry.end_height
    }) {
        return Err(SyncError::Content(format!(
            "shard {shard_id} holds an inline event outside its range"
        )));
    }
    if let Some((child, row)) = found.head() {
        locate(manifest, geometry, shard_id, child, u64::from(row))?;
    }
    Ok(Some(found))
}

/// Walks the chains still owed for one directory shard revision, privately.
///
/// Every query of `pages-<j>` selects among that page shard's first
/// [`PageChild::query_rows`]. See [`walk_chains`] for the walk itself.
#[allow(clippy::too_many_arguments)]
pub(super) fn finish_pages<S: WalletStore, T: ShardTransport>(
    store: &mut S,
    entry: &transparent_filter::ShardMapEntry,
    manifest: &ShardManifest,
    owed: &[PendingPages],
    clients: &mut GeometryClients,
    transport: &mut T,
    charges: &mut ByteCharges,
    limits: &WorkLimits,
    target_anchor: &Anchor,
    chain: &impl ChainView,
    failures: &mut Failures,
) -> Result<Option<Completion>, SyncError> {
    if entry.end_height < target_anchor.height {
        match chain.is_accepted(entry.end_height, &entry.terminal_block_hash) {
            Acceptance::Accepted => {}
            Acceptance::Unknown => {
                return Ok(Some(Completion::Incomplete {
                    reason: IncompleteReason::ChainUnknown {
                        height: entry.end_height,
                    },
                    pending: store.pending()?.len(),
                }));
            }
            Acceptance::Rejected => {
                return Err(SyncError::Invalid(
                    "pending shard endpoint rejected by wallet chain".into(),
                ));
            }
        }
    }
    let mut rows = PirRows {
        entry,
        manifest,
        client: &mut clients.pages,
        transport,
        charges,
        limits,
    };
    walk_chains(
        store,
        entry,
        manifest,
        owed,
        &mut rows,
        target_anchor,
        failures,
    )
}
