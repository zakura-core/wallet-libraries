//! Cross-shard request concurrency: the requests of a pass, sent together.
//!
//! The sequential walk reads one shard at a time: its filter, its manifest, its
//! directory setup, its directory queries, its pages. Each request waits for
//! the one before, so a restore spanning several matched shards pays one round
//! trip per request. Most of those requests do not depend on each other. Once
//! every uncached filter is local, which shards match and which scripts matched
//! them is known before any private request, and so are the manifests and
//! directory setups the walk will ask for. Once the manifests are verified, so
//! are the directory rows.
//!
//! [`look_ahead`] computes exactly those requests, hands them to the transport
//! as two batches, and stashes the outcome of every one that was sent where the
//! walk will look for it: manifests and setups in [`Staged`], filters in
//! [`StagedFilters`], queries in each directory
//! [`TableClient`](crate::engine::client::TableClient) with the secret that decodes
//! them. The walk then runs unchanged. A stashed outcome is consumed at most
//! once, at the point where the sequential walk would have made that request,
//! and a refusal or failure is handled there exactly as if the request had just
//! been made: a withdrawn revision refreshes the map, an overload backs off and
//! retries within the same attempt budget, anything else fails the sync with
//! the store as the sequential walk would have left it. An unsent request is
//! made by the walk in its place. The walk is still what verifies, commits,
//! retries and refreshes, so its semantics are the sequential walk's.
//!
//! # What stays the same
//!
//! - Which requests are made, per shard and per table: the lookahead derives
//!   them from the same filter bytes, script lists, choice table and setup
//!   cache the walk would use, and the walk consumes rather than repeats them.
//!   No query is skipped because another response mentioned a script.
//! - Charges: every dispatched query is charged immediately, including a
//!   failed reply or one the walk never consumes after an earlier failure.
//! - Commits: still per shard, in shard order, by the walk.
//!
//! # What changes
//!
//! When requests are sent. The service sees a pass's manifests and setups
//! together, then its directory queries together, instead of interleaved with
//! commits. Page work is not looked ahead: which pages a script needs is known
//! only after its directory entry decodes. The chain walk batches each of its
//! own rounds instead, across every script it walks.
//!
//! Requests the walk ends up not using are extra on the wire. If the walk stops
//! or restarts before a shard it looked ahead to — an exhausted overload
//! budget, a withdrawn revision and the refresh after it, a hard error — the
//! requests already sent for later shards were seen by the service and never
//! used. Those shards matched, so the next sync asks the same of them; a
//! refresh re-walks the rest of the pass in sequence. Likewise, requests
//! already in flight when a batch meets its first failure complete, and those
//! for the same shard after a refused query go unused, because the walk
//! retries that shard from its first query.
//!
//! The lookahead stops at the first shard whose endpoint, filter or manifest
//! does not check out, which is where the walk would stop too. A budgeted sync
//! never looks ahead, because whether a later shard's queries are sent at all
//! depends on page work only the walk discovers.

use super::{
    Clients, FailedEntry, ServiceGeometry, SyncError, directory_choice, endpoint_of, held,
    match_filter, previous_digest_of, verify_manifest,
};
use crate::engine::adapters::{Acceptance, ChainView};
use crate::engine::client::Table;
use crate::engine::store::{Anchor, SetupKey, WalletStore};
use crate::engine::transport::{
    BoxError, BudgetStop, FilterSource, ShardReply, ShardRequest, ShardTransport,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use zakura_transparent_private_shared::filter::{BlockHash, ShardMap, ShardMapEntry};
use zakura_transparent_private_shared::shard::manifest::ShardManifest;
use zakura_transparent_private_shared::shard::placement::candidate_rows;

/// The outcome of a request made ahead of the walk: its bytes and what they
/// cost, or its refusal or failure.
type Answer = Result<(Vec<u8>, u64), BoxError>;

/// Charge setup bytes at dispatch, even if a previous refusal means the walk
/// never uses this reply. The staged receipt then has no remaining byte cost;
/// its original cause still identifies refusals through the source chain.
fn prepay_setup(
    reply: Answer,
    table: Table,
    charges: &mut crate::engine::transport::ByteCharges,
) -> Answer {
    match reply {
        Ok((bytes, cost)) => {
            charges.add_setup_download(table, cost);
            Ok((bytes, 0))
        }
        Err(error) => {
            charges.add_failed_setup(table, &error);
            Err(crate::engine::transport::TransferFailure::boxed(0, error))
        }
    }
}

/// Pay manifest transfer costs before staged replies can be discarded.
fn prepay_manifest(reply: Answer, charges: &mut crate::engine::transport::ByteCharges) -> Answer {
    match reply {
        Ok((bytes, cost)) => {
            charges.add_manifest(cost);
            Ok((bytes, 0))
        }
        Err(error) => {
            charges.add_manifest(crate::engine::transport::TransferFailure::downloaded(
                &error,
            ));
            Err(crate::engine::transport::TransferFailure::boxed(0, error))
        }
    }
}

/// A shard transport with replies already in hand.
///
/// Once any reply, sent ahead or by the walk, is a [`BudgetStop`], nothing
/// more goes to the inner transport: replies already in hand are still
/// handed out, and every other request is answered with that stop.
pub(super) struct Staged<'a, T: ShardTransport> {
    inner: &'a mut T,
    manifests: HashMap<(u64, String), Answer>,
    setups: HashMap<(u64, String, Table, u32), Answer>,
    stopped: Option<BudgetStop>,
}

impl<'a, T: ShardTransport> Staged<'a, T> {
    pub(super) fn new(inner: &'a mut T) -> Self {
        Self {
            inner,
            manifests: HashMap::new(),
            setups: HashMap::new(),
            stopped: None,
        }
    }

    /// Records a budget stop in `reply`, and returns it.
    fn noted<R>(&mut self, reply: Result<R, BoxError>) -> Result<R, BoxError> {
        if let Err(error) = &reply {
            if let Some(stop) = BudgetStop::found_in(error) {
                self.stopped.get_or_insert(*stop);
            }
        }
        reply
    }

    /// The stop to answer a request with instead of sending it, if any.
    fn refused(&self) -> Result<(), BoxError> {
        match self.stopped {
            Some(stop) => Err(stop.boxed()),
            None => Ok(()),
        }
    }

    /// Sends `requests` to the inner transport together, unless a budget
    /// stop came first, in which case none is sent.
    fn send_batch(&mut self, requests: &[ShardRequest<'_>]) -> Vec<Option<ShardReply>> {
        if self.stopped.is_some() {
            return requests.iter().map(|_| None).collect();
        }
        let replies = self.inner.batch(requests);
        for reply in replies.iter().flatten() {
            if let Err(error) = reply {
                if let Some(stop) = BudgetStop::found_in(error) {
                    self.stopped.get_or_insert(*stop);
                }
            }
        }
        replies
    }

    pub(super) fn clear(&mut self) {
        self.manifests.clear();
        self.setups.clear();
    }
}

impl<T: ShardTransport> ShardTransport for Staged<'_, T> {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.inner.init()
    }

    fn manifest_prepaid(&self, shard_id: u64, revision: &str) -> bool {
        self.manifests
            .contains_key(&(shard_id, revision.to_string()))
            || self.inner.manifest_prepaid(shard_id, revision)
    }

    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        if let Some(reply) = self.manifests.remove(&(shard_id, revision.to_string())) {
            return reply;
        }
        self.refused()?;
        let reply = self.inner.manifest(shard_id, revision);
        self.noted(reply)
    }

    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        if let Some(reply) = self
            .setups
            .remove(&(shard_id, revision.to_string(), table, segment))
        {
            return reply;
        }
        self.refused()?;
        let reply = self.inner.setup(shard_id, revision, table, segment);
        self.noted(reply)
    }

    fn query(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        self.refused()?;
        let reply = self.inner.query(shard_id, revision, table, body);
        self.noted(reply)
    }

    fn page_round(&mut self, shard_id: u64, revision: &str, tables: &[u32]) {
        self.inner.page_round(shard_id, revision, tables)
    }

    fn concurrency(&self) -> usize {
        self.inner.concurrency()
    }

    fn batch(&mut self, requests: &[ShardRequest<'_>]) -> Vec<Option<ShardReply>> {
        self.send_batch(requests)
    }
}

/// A filter source with filters already in hand.
///
/// Keyed by shard id alone, as [`FilterSource::filter`] is, so the stash is
/// cleared whenever the walk refreshes the map: a filter fetched for a
/// withdrawn revision must not be handed out for the one that replaced it.
pub(super) struct StagedFilters<'a, F: FilterSource> {
    inner: &'a mut F,
    filters: HashMap<u64, Answer>,
}

impl<'a, F: FilterSource> StagedFilters<'a, F> {
    pub(super) fn new(inner: &'a mut F) -> Self {
        Self {
            inner,
            filters: HashMap::new(),
        }
    }

    pub(super) fn clear(&mut self) {
        self.filters.clear();
    }
}

impl<F: FilterSource> FilterSource for StagedFilters<'_, F> {
    fn uses_parents(&self) -> bool {
        self.inner.uses_parents()
    }

    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.inner.shard_map()
    }

    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        match self.filters.remove(&shard_id) {
            Some(reply) => reply,
            None => self.inner.filter(shard_id),
        }
    }

    fn prefetch(&mut self, shard_ids: &[u64]) {
        self.inner.prefetch(shard_ids)
    }
    fn prefetch_charged(&mut self, shard_ids: &[u64]) -> u64 {
        self.inner.prefetch_charged(shard_ids)
    }

    fn prepare_parents(
        &mut self,
        map: &ShardMap,
        uncached: &[u64],
        store: &mut dyn WalletStore,
    ) -> Result<u64, BoxError> {
        self.inner.prepare_parents(map, uncached, store)
    }

    fn parent_negative(
        &mut self,
        map: &ShardMap,
        shard_id: u64,
        scripts: &[Vec<u8>],
        store: &mut dyn WalletStore,
    ) -> Result<(bool, u64), BoxError> {
        self.inner.parent_negative(map, shard_id, scripts, store)
    }
}

/// Drops everything stashed, so the walk requests afresh from here on.
pub(super) fn clear<T: ShardTransport, F: FilterSource>(
    transport: &mut Staged<'_, T>,
    filters: &mut StagedFilters<'_, F>,
    clients: &mut Clients,
) {
    transport.clear();
    filters.clear();
    for prepared in clients.prepared.values_mut() {
        prepared.directory.clear_stash();
    }
}

/// A shard the walk will query, and the scripts it will query it for.
struct Planned<'m> {
    entry: &'m ShardMapEntry,
    matched: Vec<Vec<u8>>,
}

/// Sends the independent requests of one pass ahead of the walk.
///
/// `order` is the walk's shard order and `work` its scripts per shard. Only a
/// store failure is an error: anything else ends the lookahead early and
/// leaves the rest to the walk, which meets the same condition in its own
/// place and handles it as it always has.
#[allow(clippy::too_many_arguments)]
pub(super) fn look_ahead<S: WalletStore, F: FilterSource, T: ShardTransport>(
    store: &S,
    map: &ShardMap,
    genesis: BlockHash,
    order: &[usize],
    work: &BTreeMap<usize, Vec<Vec<u8>>>,
    geometry: &ServiceGeometry,
    clients: &mut Clients,
    filters: &mut StagedFilters<'_, F>,
    transport: &mut Staged<'_, T>,
    target_anchor: &Anchor,
    chain: &impl ChainView,
    failed: &[FailedEntry],
    charges: &mut crate::engine::transport::ByteCharges,
) -> Result<(), SyncError> {
    // Match every shard the walk will reach, as it would. Filters not in the
    // store are taken from the source here and stashed for the walk, which
    // still checks, caches and charges them.
    let pending = store.pending()?;
    let mut planned: Vec<Planned<'_>> = Vec::new();
    for &index in order {
        let Some(entry) = map.shards.get(index) else {
            break;
        };
        let endpoint = endpoint_of(entry, target_anchor);
        if chain.is_accepted(endpoint.height, &endpoint.hash) != Acceptance::Accepted {
            break;
        }
        let scripts = work.get(&index).map(Vec::as_slice).unwrap_or_default();
        let bytes = match store.filter(&entry.manifest_digest, &entry.filter_hash)? {
            Some(bytes) => bytes,
            None => {
                // Whatever came back is the walk's outcome for this fetch, a
                // failure or bytes that do not hash to the map included: its
                // own check of them is what starts a refresh.
                let reply = filters.inner.filter(entry.shard_id);
                let usable = match &reply {
                    Ok((bytes, _))
                        if zakura_transparent_private_shared::filter::filter_hash(bytes)
                            .to_display_hex()
                            == entry.filter_hash =>
                    {
                        Some(bytes.clone())
                    }
                    _ => None,
                };
                filters.filters.insert(entry.shard_id, reply);
                match usable {
                    Some(bytes) => bytes,
                    None => break,
                }
            }
        };
        let Ok(matches) = match_filter(map, entry, genesis, scripts, &bytes) else {
            break;
        };
        if matches.is_empty() {
            continue;
        }
        if zakura_transparent_private_shared::shard::layout::by_name(&entry.geometry).is_none() {
            break;
        }
        // Durable page work for this revision changes what the walk asks for
        // first; leave the shard to it.
        if pending
            .iter()
            .any(|p| p.shard_id == entry.shard_id && p.revision_digest == entry.manifest_digest)
        {
            continue;
        }
        // Entries the walk holds out of this sync are not queried.
        let mut matched = Vec::with_capacity(matches.len());
        for &i in &matches {
            if !held(
                store,
                failed,
                entry.shard_id,
                &entry.manifest_digest,
                &scripts[i],
            )? {
                matched.push(scripts[i].clone());
            }
        }
        if matched.is_empty() {
            continue;
        }
        planned.push(Planned { entry, matched });
    }
    if planned.is_empty() {
        return Ok(());
    }

    // First batch: every manifest, and every directory setup the walk would
    // fetch because neither the client nor the store holds it.
    let set_digest = store
        .set_identity()?
        .map(|identity| identity.digest())
        .unwrap_or_default();
    let mut requests: Vec<ShardRequest<'_>> = Vec::new();
    for shard in &planned {
        let entry = shard.entry;
        let revision = entry.manifest_digest.as_str();
        requests.push(ShardRequest::Manifest {
            shard_id: entry.shard_id,
            revision,
        });
        for segment in 0..entry.directory_segments {
            let open = clients
                .prepared
                .get(&entry.geometry)
                .is_some_and(|prepared| {
                    prepared
                        .directory
                        .is_open(revision, Table::Directory, segment)
                });
            let key = SetupKey {
                set_digest: set_digest.clone(),
                revision_digest: revision.to_string(),
                table: Table::Directory,
                segment,
            };
            if !open && store.setup(&key)?.is_none() {
                requests.push(ShardRequest::Setup {
                    shard_id: entry.shard_id,
                    revision,
                    table: Table::Directory,
                    segment,
                });
            }
        }
    }
    let replies = transport.send_batch(&requests);
    let mut manifests: HashMap<u64, ShardManifest> = HashMap::new();
    for (request, reply) in requests.iter().zip(replies) {
        // A sent request's outcome is kept whatever it was: a refusal reaches
        // the walk where the sequential walk would have met it, and is
        // handled there. An unsent one is simply made by the walk.
        let Some(reply) = reply else {
            continue;
        };
        match *request {
            ShardRequest::Manifest { shard_id, revision } => {
                if let (Ok((raw, _)), Some(shard)) = (
                    &reply,
                    planned.iter().find(|p| p.entry.shard_id == shard_id),
                ) {
                    let previous = previous_digest_of(map, shard_id);
                    if let Ok(manifest) = verify_manifest(raw, shard.entry, &previous, map) {
                        manifests.insert(shard_id, manifest);
                    }
                }
                let prepaid = prepay_manifest(reply, charges);
                transport
                    .manifests
                    .insert((shard_id, revision.to_string()), prepaid);
            }
            ShardRequest::Setup {
                shard_id,
                revision,
                table,
                segment,
            } => {
                transport.setups.insert(
                    (shard_id, revision.to_string(), table, segment),
                    prepay_setup(reply, table, charges),
                );
            }
            ShardRequest::Query { .. } => unreachable!("the first batch holds no queries"),
        }
    }

    // Second batch: the directory queries, in walk order, prepared by the
    // clients that will decode them. Rows are chosen exactly as the walk
    // chooses them: the published choice when there is a table, both
    // candidates when there is not.
    struct Ahead<'m> {
        entry: &'m ShardMapEntry,
        geometry: String,
        row: usize,
        query: crate::engine::client::PreparedQuery,
    }
    let mut queries: Vec<Ahead<'_>> = Vec::new();
    'shards: for shard in &planned {
        let entry = shard.entry;
        let Some(manifest) = manifests.get(&entry.shard_id) else {
            break;
        };
        let Ok(choice) = directory_choice(manifest) else {
            break;
        };
        let Ok(prepared) = clients.prepare(&manifest.geometry, &geometry.geometries) else {
            break;
        };
        let Some(layout) =
            zakura_transparent_private_shared::shard::layout::by_name(&entry.geometry)
        else {
            break;
        };
        let rows = layout.directory_rows * u64::from(entry.directory_segments);
        for script in &shard.matched {
            let candidates = candidate_rows(entry.shard_id, script, rows);
            let queried: &[u64] = match &choice {
                Some(table) => {
                    std::slice::from_ref(&candidates[table.choice(entry.shard_id, script)])
                }
                None => &candidates,
            };
            for &row in queried {
                let (_, within) = zakura_transparent_private_shared::shard::layout::split_row(
                    row,
                    layout.directory_rows,
                );
                let Ok(query) = prepared.directory.prepare(
                    &entry.manifest_digest,
                    Table::Directory,
                    within as usize,
                ) else {
                    break 'shards;
                };
                queries.push(Ahead {
                    entry,
                    geometry: manifest.geometry.clone(),
                    row: within as usize,
                    query,
                });
            }
        }
    }
    if queries.is_empty() {
        return Ok(());
    }
    let requests: Vec<ShardRequest<'_>> = queries
        .iter()
        .map(|ahead| ShardRequest::Query {
            shard_id: ahead.entry.shard_id,
            revision: &ahead.entry.manifest_digest,
            table: Table::Directory,
            body: &ahead.query.body,
        })
        .collect();
    let replies = transport.send_batch(&requests);
    for (request, reply) in requests.iter().zip(&replies) {
        if let Some(reply) = reply {
            charges.add_query_reply(Table::Directory, request.upload(), reply);
        }
    }
    drop(requests);
    // A revision's stash must be a prefix of what the walk will ask for it.
    // After an unsent query the walk prepares and sends that one and the rest
    // itself; after a refused or failed one it starts the shard over, so
    // nothing later of that revision would be used either.
    let mut ended: HashSet<&str> = HashSet::new();
    for (ahead, reply) in queries.into_iter().zip(replies) {
        let revision = ahead.entry.manifest_digest.as_str();
        if ended.contains(revision) {
            continue;
        }
        let Some(reply) = reply else {
            ended.insert(revision);
            continue;
        };
        if reply.is_err() {
            ended.insert(revision);
        }
        if let Some(prepared) = clients.prepared.get_mut(&ahead.geometry) {
            prepared.directory.stash(
                revision,
                Table::Directory,
                ahead.row,
                ahead.query,
                reply.map(|(bytes, _)| bytes),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::transport::{ByteCharges, Overloaded};

    #[test]
    fn prefetched_setup_bytes_are_charged_even_when_the_walk_drops_the_reply() {
        let table = Table::Directory;
        let mut charges = ByteCharges::default();
        let success = prepay_setup(Ok((vec![0; 23], 23)), table, &mut charges).unwrap();
        let error = prepay_setup(
            Err(crate::engine::transport::TransferFailure::boxed(
                17,
                Overloaded { retry_after: None }.boxed(),
            )),
            table,
            &mut charges,
        )
        .unwrap_err();
        assert_eq!(
            charges.setup_bytes(),
            40,
            "dispatch has paid both outcomes already"
        );
        assert!(Overloaded::found_in(&error).is_some());
        charges.add_setup(table, success.1);
        charges.add_failed_setup(table, &error);
        assert_eq!(
            charges.setup_bytes(),
            40,
            "consuming staged outcomes must not charge them twice"
        );
    }
    #[test]
    fn looked_ahead_manifests_are_paid_before_early_exit() {
        let mut charges = ByteCharges::default();
        let first = prepay_manifest(Ok((vec![0; 23], 23)), &mut charges).unwrap();
        let _unused = prepay_manifest(Ok((vec![0; 31], 31)), &mut charges).unwrap();
        let failure = prepay_manifest(
            Err(crate::engine::transport::TransferFailure::boxed(
                7,
                Overloaded { retry_after: None }.boxed(),
            )),
            &mut charges,
        )
        .unwrap_err();
        assert_eq!(charges.manifest_bytes, 61);
        assert_eq!(
            charges.manifests_checked, 3,
            "each delivered receipt is counted once"
        );
        charges.add_manifest_download(first.1);
        assert_eq!(charges.manifests_checked, 3);
        assert_eq!(
            charges.manifest_bytes, 61,
            "consumption cannot double charge"
        );
        assert_eq!(
            crate::engine::transport::TransferFailure::downloaded(&failure),
            0
        );
        assert!(Overloaded::found_in(&failure).is_some());
    }

    /// Answers the first setup of a batch with a byte budget stop and every
    /// other request with an empty success, counting what reaches it.
    struct Stopping {
        sent: usize,
    }

    impl ShardTransport for Stopping {
        fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
            Ok((Vec::new(), 0))
        }
        fn manifest(&mut self, _: u64, _: &str) -> Result<(Vec<u8>, u64), BoxError> {
            self.sent += 1;
            Ok((Vec::new(), 0))
        }
        fn setup(&mut self, _: u64, _: &str, _: Table, _: u32) -> Result<(Vec<u8>, u64), BoxError> {
            self.sent += 1;
            Err(BudgetStop::Bytes.boxed())
        }
        fn query(&mut self, _: u64, _: &str, _: Table, _: &[u8]) -> Result<Vec<u8>, BoxError> {
            self.sent += 1;
            Ok(Vec::new())
        }
        fn concurrency(&self) -> usize {
            2
        }
    }

    /// After a batch meets a budget stop, the staged transport sends nothing
    /// more: a later batch goes unsent, and later single requests are answered
    /// with the stop, while a reply already in hand is still handed out.
    #[test]
    fn nothing_is_sent_after_a_budget_stop() {
        let mut inner = Stopping { sent: 0 };
        let mut staged = Staged::new(&mut inner);
        let revision = "aa".to_string();
        staged
            .manifests
            .insert((1, revision.clone()), Ok((b"held".to_vec(), 4)));
        let first = staged.batch(&[
            ShardRequest::Manifest {
                shard_id: 0,
                revision: &revision,
            },
            ShardRequest::Setup {
                shard_id: 0,
                revision: &revision,
                table: Table::Directory,
                segment: 0,
            },
        ]);
        assert!(matches!(first[1], Some(Err(_))));
        let later = staged.batch(&[ShardRequest::Query {
            shard_id: 0,
            revision: &revision,
            table: Table::Directory,
            body: &[],
        }]);
        assert!(
            later.iter().all(Option::is_none),
            "the later batch is not sent"
        );
        let query = staged.query(0, &revision, Table::Directory, &[]);
        assert!(query.is_err_and(|error| BudgetStop::found_in(&error).is_some()));
        assert_eq!(staged.manifest(1, &revision).unwrap().0, b"held");
        drop(staged);
        assert_eq!(inner.sent, 2, "only the first batch reached the transport");
    }
}
