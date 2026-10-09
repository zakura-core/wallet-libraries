use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};
use transparent::{address::TransparentAddress, bundle::OutPoint};
use transparent_events::{FeeState, TransparentEvent};
use transparent_filter::{MAINNET_GENESIS_DISPLAY, NETWORK, ShardMap, wire::MAX_SUPERSEDED};
use transparent_wallet::transport::{BoxError, FilterSource, ShardTransport};
use transparent_wallet::{
    Acceptance, Anchor, ChainView, Completion, IncompleteReason, ScriptEntry, ScriptOrigin,
    SetIdentity, StaticScripts, SyncError, SyncReport, WalletStore, WorkLimits,
};
use transparent_wallet_store::SqliteStore;
use zcash_client_backend::data_api::transparent_ledger::{
    AddressRange, ChainPoint, PageRequest, ReceiveEvent, RecoveryRevision, SpendEvent,
    TransactionMetadata, TransparentLedgerCommit, TransparentRecoveryContext, TransparentWatchSet,
    WholeTransactionFee,
};
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use crate::catalog::{self, BatchState, Published, WithdrawnCause};

/// The only shard schema this adapter reads.
///
/// Every companion is bound to it, and a pass refuses a service whose init
/// names another schema before requesting any manifest or private query.
pub const SCHEMA: &str = "transparent-shard-v11";

/// Identity and finite resource bounds for one account's recovery passes.
///
/// The caller supplies the transports for each pass; nothing here is dialed.
#[derive(Clone, Debug)]
pub struct RecoveryConfig {
    /// Caller-chosen source identity, independent of a server's assertions.
    pub source: Vec<u8>,
    /// Stable wallet/account identity; use a different companion store per account.
    pub account_binding: Vec<u8>,
    /// Identity label bound into the companion: the origin whose publication the
    /// caller's transports retrieve. Transports are the caller's; this is not dialed.
    pub origin: String,
    /// Maximum watched scripts and retained companion scripts.
    pub scripts: usize,
    /// Maximum shard-map entries per pass.
    pub shards: usize,
    /// Maximum candidate event records exported per pass.
    pub events: usize,
    /// Private query budget. Exhaustion retains continuation and reports [`Outcome::More`].
    pub queries: u64,
    /// Private payload budget, including setup. One atomic response may cross it.
    pub private_bytes: u64,
}

/// Why a pass stopped. Only [`Outcome::Complete`] covers the whole target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every watched script is covered from its required height through the target.
    Complete,
    /// The publication ends below the target. The pass may still have covered
    /// through the publication's end; a later pass can finish once it catches up.
    Behind,
    /// A query, byte or pending-page budget stopped the pass. The companion keeps
    /// the continuation, so the next pass resumes.
    More,
    /// The service refused for capacity throughout its retry budget.
    Overloaded,
    /// Progress needs more than a retry: an unknown chain block, spends the
    /// watch set cannot resolve, or script discovery past its bound.
    Stalled,
}

/// How far a pass covered the watch set, independent of the commits it returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Height through which every watched script is covered from its required
    /// height, provisional tail coverage included.
    pub covered_through: u64,
    /// Why the pass stopped.
    pub outcome: Outcome,
}

/// When to pass an account again, from how its last pass stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    /// Every watched script is covered through the target. Pass again only
    /// for new work: a changed watch set or a grown window.
    Complete,
    /// A budget stopped the pass. Pass again at once; the companion resumes.
    More,
    /// The publication ends below the target, or the service refused for
    /// capacity. Pass again after the wait.
    After(Duration),
    /// Progress needs more than a retry. Pass again only for new work.
    Stalled,
}

impl Retry {
    /// The wait after a pass whose publication ends below the target.
    pub const BEHIND: Duration = Duration::from_secs(10);
    /// The wait after a pass the service refused for capacity.
    pub const OVERLOADED: Duration = Duration::from_secs(30);
}

impl Progress {
    /// When to pass the account again, from the outcome alone. A pass's
    /// [`RecoveryBatch::retry`] also weighs its state; prefer it.
    pub fn retry(&self) -> Retry {
        match self.outcome {
            Outcome::Complete => Retry::Complete,
            Outcome::More => Retry::More,
            Outcome::Behind => Retry::After(Retry::BEHIND),
            Outcome::Overloaded => Retry::After(Retry::OVERLOADED),
            Outcome::Stalled => Retry::Stalled,
        }
    }

    /// Blocks between `target` and the height the pass covered through.
    pub fn behind(&self, target: u64) -> u64 {
        target.saturating_sub(self.covered_through)
    }
}

/// Maps the reference client's report onto the adapter's narrower contract.
///
/// A `clamped` pass synced to the publication's end below the wallet's target,
/// so even its completion is [`Outcome::Behind`].
fn progress(report: &SyncReport, clamped: bool) -> Progress {
    let outcome = match &report.completion {
        Completion::Complete if clamped => Outcome::Behind,
        Completion::Complete => Outcome::Complete,
        Completion::Incomplete { reason, .. } => match reason {
            IncompleteReason::QueryBudget
            | IncompleteReason::ByteBudget
            | IncompleteReason::PendingLimit => Outcome::More,
            IncompleteReason::PublicationBehind { .. } => Outcome::Behind,
            IncompleteReason::Overloaded { .. } => Outcome::Overloaded,
            IncompleteReason::ChainUnknown { .. }
            | IncompleteReason::UnresolvedSpends
            | IncompleteReason::DiscoveryUnbounded => Outcome::Stalled,
        },
    };
    Progress {
        covered_through: report.covered_through,
        outcome,
    }
}

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
    /// that has not caught up, and the pass is [`BatchState::Pending`].
    ///
    /// Before returning it, the adapter reset the companion's store in one
    /// transaction and kept its catalog, so each source keeps its highest
    /// lineage. It forgot the export intents of sources the map no longer
    /// names, including [`RecoveryBatch::retired_revisions`] a batch listed and
    /// nobody acknowledged: no successor can resolve them, and the wallet keeps
    /// their provisional evidence. Retry the pass once with the same companion;
    /// never recreate it.
    #[error("transparent PIR recovery: publication set changed; companion store reset, retry")]
    PublicationChanged,
}
pub(crate) fn failure(error: impl std::fmt::Display) -> RecoveryError {
    RecoveryError::Failure(error.to_string())
}
pub(crate) fn require(ok: bool, message: &str) -> Result<(), RecoveryError> {
    if ok {
        Ok(())
    } else {
        Err(RecoveryError::Invalid(message.into()))
    }
}

/// Candidate observations and reference progress from one pass.
///
/// The batch is opaque: its commits can be read, never edited. A
/// [`BatchState::Ready`] batch is settled in one of two ways. With feature
/// `sqlite`, [`ReferenceRecovery::apply_and_acknowledge`] consumes it, applies
/// every commit to a SQLite wallet and acknowledges it, reconciling its
/// [`RecoveryBatch::retired_revisions`] when the caller trusts the commits.
/// Otherwise the caller applies [`RecoveryBatch::commits`] itself and
/// acknowledges with [`ReferenceRecovery::acknowledge_applied`], which refuses a
/// batch listing retirements. Neither the batch nor a server withdrawal is
/// authority to change local facts or promote an account.
pub struct RecoveryBatch<AccountId> {
    commits: Vec<TransparentLedgerCommit<AccountId>>,
    progress: Progress,
    state: BatchState,
    /// The retired revisions this batch's commits resolve, as its pass recorded
    /// them. Acknowledging the batch forgets them.
    replaced: Vec<RecoveryRevision>,
    token: [u8; 32],
}

impl<A> RecoveryBatch<A> {
    /// Source-bound normalized commits, including unfinished page work, in the
    /// order they apply. Empty unless [`Self::state`] is [`BatchState::Ready`].
    pub fn commits(&self) -> &[TransparentLedgerCommit<A>] {
        &self.commits
    }

    /// How far this pass covered the watch set, and why it stopped. Anything but
    /// [`Outcome::Complete`] is never synchronized.
    pub fn progress(&self) -> Progress {
        self.progress
    }

    /// Whether the commits may be applied: only a [`BatchState::Ready`] batch
    /// has commits or can be acknowledged.
    pub fn state(&self) -> BatchState {
        self.state
    }

    /// When to pass the account again. A [`BatchState::Withdrawn`] batch is
    /// [`Retry::Stalled`] whatever its progress, which can even be
    /// [`Outcome::Complete`]: the publication contradicts the catalog, and
    /// passing again on a timer reads the same contradiction. Keep the
    /// companion and pass again for new work. Otherwise this is
    /// [`Progress::retry`].
    pub fn retry(&self) -> Retry {
        match self.state {
            BatchState::Withdrawn(_) => Retry::Stalled,
            BatchState::Ready | BatchState::Pending => self.progress.retry(),
        }
    }

    /// Exactly the retired provisional revisions this batch resolves: each was
    /// exported by an earlier batch, is no longer published, and has a successor
    /// among [`Self::commits`] for the same source at a higher lineage. Empty
    /// unless [`Self::state`] is [`BatchState::Ready`].
    ///
    /// These are notifications, not authority to withdraw wallet evidence. The
    /// wallet resolves them when it applies every commit through its trusted
    /// operation, `TransparentLedgerWrite::qualify_and_apply_transparent_ledger_commit`,
    /// which qualifies each successor and withdraws its source's older
    /// provisional evidence in the same wallet transaction. Only
    /// [`ReferenceRecovery::apply_and_acknowledge`] with trusted commits
    /// acknowledges such a batch; [`ReferenceRecovery::acknowledge_applied`]
    /// refuses it. The trusted operation qualifies whatever it is given, so a
    /// caller that does not trust the batch's origin cannot use it and never
    /// acknowledges a batch with retirements.
    ///
    /// Until the batch is acknowledged the companion keeps them: the next pass
    /// lists them again, with any retirement found since, or is
    /// [`BatchState::Pending`] while it cannot export their successors. Only a
    /// publication change forgets them unacknowledged:
    /// [`RecoveryError::PublicationChanged`] drops those of sources the new map
    /// no longer names, which no successor can resolve, and the wallet keeps
    /// their provisional evidence.
    pub fn retired_revisions(&self) -> &[RecoveryRevision] {
        &self.replaced
    }

    /// The commits and recorded retirements, for the adapter's own settlement.
    #[cfg(feature = "sqlite")]
    pub(crate) fn into_parts(self) -> (Vec<TransparentLedgerCommit<A>>, Vec<RecoveryRevision>) {
        (self.commits, self.replaced)
    }

    /// A batch no companion issued, for [`crate::testing`].
    #[cfg(feature = "testing")]
    pub(crate) fn unissued(
        commits: Vec<TransparentLedgerCommit<A>>,
        progress: Progress,
        state: BatchState,
        replaced: Vec<RecoveryRevision>,
    ) -> Self {
        Self {
            commits,
            progress,
            state,
            replaced,
            token: [0; 32],
        }
    }
}

/// Durable reference retrieval and normalization for one wallet/account.
///
/// The companion store retains cache and page continuation. It is deliberately
/// separate from wallet financial state, whose writer independently validates each
/// normalized commit. No method here changes qualification, activation or spending.
pub struct ReferenceRecovery {
    config: RecoveryConfig,
    /// The companion binding every derived source includes.
    binding: [u8; 32],
    store: SqliteStore,
    pub(crate) catalog: Connection,
    pending_export: Option<[u8; 32]>,
}

/// A filter source that keeps the bytes of the last shard map it served.
///
/// A pass normalizes against that map, the one its sync finished with, and
/// never fetches another: a second fetch can see a newer publication than the
/// one whose facts the sync stored. It caches no filter: prefetching, and
/// dropping what an earlier prefetch left unused when the next one starts or
/// the map is fetched, as [`FilterSource`] requires, stay with the inner source.
struct Recorded<'a, F> {
    inner: &'a mut F,
    map: Vec<u8>,
}

impl<'a, F: FilterSource> Recorded<'a, F> {
    /// Fetches the map a pass starts from, with what it cost.
    fn fetch(inner: &'a mut F) -> Result<(Self, u64), BoxError> {
        let (map, cost) = inner.shard_map()?;
        Ok((Self { inner, map }, cost))
    }

    /// The last map served.
    fn map(&self) -> &[u8] {
        &self.map
    }
}

impl<F: FilterSource> FilterSource for Recorded<'_, F> {
    fn uses_parents(&self) -> bool {
        self.inner.uses_parents()
    }

    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        let (map, cost) = self.inner.shard_map()?;
        self.map.clone_from(&map);
        Ok((map, cost))
    }

    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        self.inner.filter(shard_id)
    }

    fn prefetch(&mut self, shard_ids: &[u64]) {
        self.inner.prefetch(shard_ids)
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

fn address_script(address: TransparentAddress) -> Vec<u8> {
    match address {
        TransparentAddress::PublicKeyHash(hash) => {
            [vec![0x76, 0xa9, 20], hash.to_vec(), vec![0x88, 0xac]].concat()
        }
        TransparentAddress::ScriptHash(hash) => {
            [vec![0xa9, 20], hash.to_vec(), vec![0x87]].concat()
        }
    }
}
pub(crate) fn block(height: u64) -> Result<BlockHeight, RecoveryError> {
    Ok(BlockHeight::from(u32::try_from(height).map_err(failure)?))
}
pub(crate) fn block_hash(display: &str) -> Result<BlockHash, RecoveryError> {
    let mut bytes = hex::decode(display).map_err(failure)?;
    require(bytes.len() == 32, "invalid publication block hash")?;
    bytes.reverse();
    Ok(BlockHash::from_slice(&bytes))
}
pub(crate) fn metadata(
    meta: Option<transparent_events::TransactionMetadata>,
) -> Result<Option<TransactionMetadata>, RecoveryError> {
    meta.map(|meta| {
        Ok(TransactionMetadata {
            fee: match meta.fee {
                FeeState::Exact(value) => {
                    WholeTransactionFee::Exact(Zatoshis::from_u64(value).map_err(failure)?)
                }
                FeeState::Unknown => WholeTransactionFee::Unknown,
                FeeState::NotApplicable => WholeTransactionFee::NotApplicable,
            },
            transparent_input_count: meta.transparent_input_count,
            has_shielded_components: meta.has_shielded_components,
        })
    })
    .transpose()
}
fn page_id(shard: u64, digest: &str, script: &[u8], first: u32) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"transparent-reference-page-v1");
    hash.update(shard.to_le_bytes());
    hash.update(digest.as_bytes());
    hash.update(script);
    hash.update(first.to_le_bytes());
    hash.finalize().to_vec()
}
/// The commits of one pass, and the revisions its stored facts may name.
///
/// The store records each fact with the shard id and manifest digest it was
/// read under. A digest the map publishes names that entry's commit. A digest a
/// re-cut declares superseded, sealed, names a commit under that revision's own
/// identity, which the wallet already holds; it is admitted on its first fact.
/// Any other digest defers the batch.
struct Facts<'p, A> {
    commits: BTreeMap<(u64, String), TransparentLedgerCommit<A>>,
    published: BTreeMap<&'p str, &'p Published>,
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
    follows_recut: bool,
    context: TransparentRecoveryContext<A>,
}

impl<'p, A: Copy> Facts<'p, A> {
    fn new(
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
    fn open(&mut self, entry: &Published, anchor: ChainPoint) {
        self.commits.insert(
            entry.key(),
            TransparentLedgerCommit {
                context: self.context,
                revision: entry.revision.clone(),
                anchor,
                receives: vec![],
                spends: vec![],
                coverage: vec![],
                unsupported: vec![],
                opened_pages: vec![],
                completed_pages: vec![],
            },
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
    fn place(
        &mut self,
        pass: &mut catalog::Pass<'_>,
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
            self.saw(entry);
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
                let admitted = self.admit(pass, chain, entry)?;
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
    fn saw(&mut self, entry: &Published) {
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
    fn admit(
        &mut self,
        pass: &mut catalog::Pass<'_>,
        chain: &impl ChainView,
        entry: &Published,
    ) -> Result<bool, RecoveryError> {
        let target = u64::from(u32::from(self.context.target.height));
        let height = entry.end_height.min(target);
        let hash = chain
            .hash_at(height)
            .ok_or_else(|| RecoveryError::Invalid("missing independent shard anchor".into()))?;
        require(
            chain.is_accepted(height, &hash) == Acceptance::Accepted,
            "shard anchor is not independently accepted",
        )?;
        if height == entry.end_height && hash != entry.terminal {
            // Facts resting on a block the wallet's chain no longer holds.
            pass.defer();
            return Ok(false);
        }
        if !pass.admit_declared(entry)? {
            return Ok(false);
        }
        let anchor = ChainPoint {
            height: block(height)?,
            hash: block_hash(&hash)?,
        };
        self.open(entry, anchor);
        Ok(true)
    }
}

/// A batch that is not [`BatchState::Ready`]: no commits, and nothing to
/// acknowledge.
fn unready<A>(state: BatchState, progress: Progress) -> RecoveryBatch<A> {
    RecoveryBatch {
        commits: vec![],
        progress,
        state,
        replaced: vec![],
        token: [0; 32],
    }
}

/// A [`BatchState::Pending`] batch for a pass that read nothing from a
/// publication it must wait for. Like the reference client stopping before it
/// reads anything, it claims no coverage.
fn behind_unread<A>() -> RecoveryBatch<A> {
    unready(
        BatchState::Pending,
        Progress {
            covered_through: 0,
            outcome: Outcome::Behind,
        },
    )
}

/// Whether `ranges` of `address` together cover every height from `from`
/// through `through`.
fn spans<'r>(
    ranges: impl IntoIterator<Item = &'r AddressRange>,
    address: TransparentAddress,
    from: BlockHeight,
    through: BlockHeight,
) -> bool {
    let mut ranges: Vec<(u32, u32)> = ranges
        .into_iter()
        .filter(|range| range.address == address)
        .map(|range| (u32::from(range.from), u32::from(range.through)))
        .collect();
    ranges.sort_unstable();
    // The lowest height not covered yet.
    let mut next = u32::from(from);
    for (start, end) in ranges {
        if start > next {
            break;
        }
        if end >= u32::from(through) {
            return true;
        }
        next = next.max(end + 1);
    }
    false
}

/// Completion-only commits for the wallet's pages that no commit of their own
/// revision covers by itself.
///
/// Every pending page blocks its account. A page under a source `published`
/// does not name, as after a set, origin or source-format change or a re-cut,
/// has no commit of its revision to follow, nor has one under a sealed
/// revision a re-cut declared superseded (in `declared`) whose source the map
/// still names, as a renumbered shard. A declared revision may also have a
/// commit of its own, from facts the store saved under it before the re-cut,
/// while the rest of its range was read again under the shard that now covers
/// it. Such a page is completed under its own revision once `commits` cover
/// each of its addresses over its whole range, in a completion-only commit the
/// caller places after `commits`, so the wallet applies the coverage first.
/// Its anchor is the wallet's block at the lower of the revision's publication
/// height and the target, which at the publication height must be the
/// publication's own block; a page whose anchor the wallet's chain does not
/// hold waits.
///
/// Any other page whose revision has a commit is left to that commit, which
/// completes it from its own coverage and otherwise reopens or keeps it, so no
/// page is completed twice. A named source's provisional revisions are left to
/// their successor, whose qualification withdraws them.
fn complete_stranded<A: Copy>(
    watch: &TransparentWatchSet<A>,
    context: TransparentRecoveryContext<A>,
    published: &[Published],
    declared: &[Published],
    commits: &[TransparentLedgerCommit<A>],
    chain: &impl ChainView,
) -> Result<Vec<TransparentLedgerCommit<A>>, RecoveryError> {
    let named: BTreeSet<&[u8]> = published
        .iter()
        .map(|entry| entry.revision.source.as_slice())
        .collect();
    let covers = |commits: &[TransparentLedgerCommit<A>], request: &PageRequest| {
        request.addresses.iter().all(|address| {
            spans(
                commits.iter().flat_map(|commit| &commit.coverage),
                *address,
                request.from,
                request.through,
            )
        })
    };
    let mut stranded: Vec<TransparentLedgerCommit<A>> = vec![];
    for page in &watch.pending_pages {
        let superseded = declared.iter().any(|entry| entry.revision == page.revision);
        if let Some(own) = commits
            .iter()
            .find(|commit| commit.revision == page.revision)
        {
            // Its own commit settles it, unless the re-cut superseded its
            // revision and the coverage that completes it is under others.
            let done = own.completed_pages.contains(&page.request.page)
                || own
                    .opened_pages
                    .iter()
                    .any(|opened| opened.page == page.request.page);
            if !superseded || done {
                continue;
            }
        } else if named.contains(page.revision.source.as_slice()) && !superseded {
            // A named source's own revisions settle its pages, except a sealed
            // revision a re-cut superseded, which no successor withdraws.
            continue;
        }
        let request = &page.request;
        if !covers(commits, request) {
            continue;
        }
        if let Some(commit) = stranded
            .iter_mut()
            .find(|commit| commit.revision == page.revision)
        {
            commit.completed_pages.push(request.page.clone());
            continue;
        }
        let publication = page.revision.publication;
        let height = publication.height.min(context.target.height);
        let Some(hash) = chain.hash_at(u64::from(u32::from(height))) else {
            continue;
        };
        if chain.is_accepted(u64::from(u32::from(height)), &hash) != Acceptance::Accepted {
            continue;
        }
        let hash = block_hash(&hash)?;
        if height == publication.height && hash != publication.hash {
            continue;
        }
        stranded.push(TransparentLedgerCommit {
            context,
            revision: page.revision.clone(),
            anchor: ChainPoint { height, hash },
            receives: vec![],
            spends: vec![],
            coverage: vec![],
            unsupported: vec![],
            opened_pages: vec![],
            completed_pages: vec![request.page.clone()],
        });
    }
    Ok(stranded)
}

/// What an acknowledgment must present: the batch's binding, store position,
/// commits and replaced revisions.
fn export_token<A>(
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

/// The lowest height a pass needs the wallet's chain for: the lowest required
/// height in `watch`, capped at `target`, or 0 when nothing is watched.
fn required_floor<A>(watch: &TransparentWatchSet<A>, target: u64) -> u64 {
    watch
        .addresses
        .iter()
        .map(|entry| u64::from(u32::from(entry.required_from)))
        .min()
        .map_or(0, |lowest| lowest.min(target))
}

/// The map entries a pass over a watch set with `floor` handles: every shard
/// the map publishes, and every revision its re-cuts declare superseded that
/// ends at or above the floor. Declarations are never dropped, so those wholly
/// below every watched script's required height, which no stored fact can
/// name, do not count against the limit; [`declarations`] bounds them.
fn entries(map: &ShardMap, floor: u64) -> usize {
    map.shards.len()
        + map
            .recuts
            .iter()
            .flat_map(|recut| &recut.superseded)
            .filter(|shard| shard.end_height >= floor)
            .count()
}

/// Every revision `map`'s re-cuts declare superseded, at any height.
///
/// A pass checks each declaration against the map and the others, and marks
/// those the catalog holds current, whatever the floor: the floor is the
/// current watch set's, and the wallet may hold a declared revision from an
/// earlier pass whose floor was lower. So the floor does not bound this work;
/// the total is held to [`MAX_SUPERSEDED`], the most the map's own shape check
/// accepts, before anything is retrieved.
fn declarations(map: &ShardMap) -> usize {
    map.recuts.iter().map(|recut| recut.superseded.len()).sum()
}

/// The caller's chain, accepting every block below the watch set's floor. Passed
/// to `sync_into` only.
///
/// A wallet holds no blocks below its birthday, while a publication may start far
/// below it (the live map starts at genesis). Leniency there is sound because, at
/// wallet-pir 06a972db, `sync_into` asks below the floor only for rollback
/// anchors and, in one case below, the end of a replacement shard:
///
/// - It plans only shards meeting `[required_from, target]` (`sync.rs:949-972`),
///   so every coverage endpoint it checks (`sync.rs:1471-1472`, `:2323-2324`,
///   `sync_ahead.rs:255-258`), every stored coverage end its reorg scan and
///   sealed-rewrite judgment ask about (`sync.rs:650-700`, `:702-749`, `:1284`),
///   and the earlier target unfinished page work was read for (`:1337-1339`)
///   is at or above the floor. Required heights only move earlier and targets
///   only rise, so no script the companion retains starts below the floor.
/// - The block a rollback rewinds to may lie below it: the reorg fallback
///   `map.start_height - 1` (`:669`, rolled back at `:686`), a replaced
///   revision (`:808-821`) or a revision withdrawn mid-sync (`:1110-1114`), each
///   just below a shard's start and each resolved by `accepted_at`
///   (`:2661-2681`), which takes the hash from the map when the view has none.
///   Only block 0 has no map entry, so [`Self::hash_at`] answers it with the
///   map's genesis hash.
/// - Judging an undeclared rewrite of a stored sealed range whose own end the
///   chain accepts, it asks about the end of the map's sealed shard now
///   covering that range's start (`:1288-1292`), which can lie below the floor
///   when the range starts below it. There the view accepts it, so such a
///   rewrite is refused as a contradiction (`SealedRewrite`, a withdrawn batch)
///   rather than left unsettled (`ChainUnknown`, a stalled pass). Either way
///   nothing is read, rolled back or exported, and a reorg the publisher
///   followed ahead of the wallet lies near the tip, far above any floor.
///
/// Nothing below the floor is exported or cataloged (see `normalize`), and the
/// target and every shard anchor are checked against the caller's chain alone.
/// Re-verify these call sites on every wallet-pir pin bump.
struct BelowFloor<'a, C> {
    chain: &'a C,
    /// The floor: every block below it is accepted.
    below: u64,
    /// The map's genesis hash, already checked to be mainnet's.
    genesis: &'a str,
}

impl<C: ChainView> ChainView for BelowFloor<'_, C> {
    fn is_accepted(&self, height: u64, hash_display_hex: &str) -> Acceptance {
        if height < self.below {
            Acceptance::Accepted
        } else {
            self.chain.is_accepted(height, hash_display_hex)
        }
    }

    fn tip(&self) -> Option<Anchor> {
        self.chain.tip()
    }

    fn hash_at(&self, height: u64) -> Option<String> {
        if height < self.below {
            (height == 0).then(|| self.genesis.to_owned())
        } else {
            self.chain.hash_at(height)
        }
    }
}

/// The anchor a pass syncs to, and whether it was clamped below `target`.
///
/// When the publication ends at `t` below the wallet's target, a pass to the
/// target can only report the publication behind. It syncs to the map's last end
/// instead, and so covers everything published, only when all of these hold:
/// `t` is at or above the `floor`; neither the companion's `stored` anchor nor a
/// `retained` event lies above `t`, so the client neither refuses a regressed
/// anchor nor a target below retained events (a lagging replica); and `chain`
/// accepts the map's terminal block at `t`. Otherwise it passes the target
/// unchanged.
fn sync_target(
    map: &ShardMap,
    target: &Anchor,
    floor: u64,
    stored: Option<&Anchor>,
    retained: u64,
    chain: &impl ChainView,
) -> (Anchor, bool) {
    let Some(last) = map.shards.last() else {
        return (target.clone(), false);
    };
    let t = last.end_height;
    if t < target.height
        && t >= floor
        && stored.is_none_or(|anchor| t >= anchor.height)
        && t >= retained
        && chain.is_accepted(t, &last.terminal_block_hash) == Acceptance::Accepted
    {
        let clamped = Anchor {
            height: t,
            hash: last.terminal_block_hash.clone(),
        };
        (clamped, true)
    } else {
        (target.clone(), false)
    }
}

impl ReferenceRecovery {
    /// Open a compatible companion store and fence its account, origin and schema binding.
    ///
    /// A new companion is created in format `transparent-reference-companion-v3`.
    /// A v2 companion, whose sources bound shard ids, has its catalog rebuilt
    /// empty in place and keeps its store, so the next pass exports its stored
    /// facts again under v3 sources without retrieving them. One in the v1
    /// format, whose lineage was a local counter no recreated companion can
    /// reproduce, is refused with `Invalid("companion format v1; recreate")`.
    pub fn open(path: impl AsRef<Path>, config: RecoveryConfig) -> Result<Self, RecoveryError> {
        require(
            !config.source.is_empty()
                && config.source.len() <= 256
                && !config.account_binding.is_empty()
                && config.account_binding.len() <= 256,
            "source/account binding must be nonempty and at most 256 bytes",
        )?;
        require(
            config.scripts > 0
                && config.shards > 0
                && config.events > 0
                && config.queries > 0
                && config.private_bytes > 0,
            "recovery bounds must be positive",
        )?;
        let url = url::Url::parse(&config.origin).map_err(failure)?;
        require(
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid explicit HTTP origin",
        )?;
        let store = SqliteStore::open(&path).map_err(failure)?;
        let mut catalog = Connection::open(path).map_err(failure)?;
        catalog
            .busy_timeout(Duration::from_secs(5))
            .map_err(failure)?;
        let binding = catalog::binding([
            &config.source,
            &config.account_binding,
            config.origin.as_bytes(),
            SCHEMA.as_bytes(),
        ]);
        catalog::prepare(&mut catalog, &binding)?;
        Ok(Self {
            config,
            binding,
            store,
            catalog,
            pending_export: None,
        })
    }

    /// Recover a finite pass through the caller's transports and independently
    /// accepted chain.
    ///
    /// `filters` and `transport` must reach the origin bound into this companion.
    /// Before any filter or private retrieval, in order: the watch set's target
    /// must be accepted by `chain`; the watch set and the companion's retained
    /// scripts must be within the script limit; `filters` must not use the parent
    /// filter experiment; the shard map, its shards and the revisions its re-cuts
    /// declare superseded at or above the watch set's floor counted together,
    /// must be within the shard limit, its declarations at any height within
    /// [`MAX_SUPERSEDED`], and it must name Zcash mainnet's network and
    /// genesis block; and the service's init must name
    /// [`SCHEMA`]. A failed check returns [`RecoveryError::Invalid`] without
    /// further requests. A watch set with no addresses needs nothing retrieved:
    /// once its target is accepted, the pass sends no request and returns a batch
    /// with no commits, [`Outcome::Complete`] at the target.
    ///
    /// `chain` answers for every block at or above the watch set's floor, its
    /// lowest required height; below it the pass needs no wallet hashes and
    /// exports nothing. When the publication ends below the target, the pass
    /// syncs to the publication's end if `chain` accepts it and the companion
    /// holds nothing above it; completing there reports [`Outcome::Behind`].
    /// Otherwise the pass is [`Outcome::Behind`] at once. Commits keep the watch
    /// set's context either way.
    ///
    /// The batch is built from the shard map the sync finished with, which is the
    /// first one fetched unless the sync refreshed it; no further map is fetched.
    /// Its [`BatchState`] says whether the commits may be applied.
    ///
    /// When the first map's set identity no longer continues the one the
    /// companion's store is bound to, the pass resets the store, keeps the
    /// catalog, and fails with [`RecoveryError::PublicationChanged`] before the
    /// sync; retry once with the same companion. If that map ends below the
    /// store's anchor while `chain` still accepts the anchor, the pass instead
    /// keeps the store and waits for the map to catch up. That, and any
    /// divergence the sync itself finds (a map refreshed mid-pass that does not
    /// continue the first), is a [`BatchState::Pending`] batch with
    /// [`Outcome::Behind`] that claims no coverage, keeping companion and
    /// catalog. A map that rewrites sealed history the store holds without
    /// declaring a re-cut, where `chain` accepts both the stored range's end
    /// block and the end block of the map's sealed shard now covering it, is
    /// refused by the sync before anything is read, after it rolled back any
    /// reorg the chain alone shows. The pass returns a [`BatchState::Withdrawn`]
    /// batch with [`WithdrawnCause::ChangedSealed`], claiming no coverage,
    /// unless the map declares fewer re-cuts (a lower epoch) than one this
    /// companion recorded: such a map is taken for a replica still serving the
    /// publication from before that re-cut, and the batch is `Pending` and
    /// behind.
    ///
    /// A re-cut the map declares keeps the wallet's history: facts the store
    /// read under a sealed revision the re-cut superseded are exported under
    /// that revision's own identity, which the wallet holds, and the renumbered
    /// shards and tail keep their sources. An undeclared change of sealed
    /// content never reaches the wallet: the sync refuses it, or the catalog
    /// withdraws it, either way as [`BatchState::Withdrawn`]. A ready pass over
    /// a re-cut map records its re-cut epoch once the store holds a fact under
    /// a revision any of its re-cuts superseded, or under one the map publishes
    /// at or above its newest re-cut's first height. The epoch never stops a
    /// sync: a map at a lower epoch that rewrites nothing the store has
    /// finished reading is synced normally, and only a refused `SealedRewrite`
    /// is classified by the epoch. It tells a lagging replica's refused map
    /// from a contradiction, so a forged epoch can at most soften a real
    /// contradiction to `Pending`, and an honest map that rewrites nothing the
    /// store holds is never held back.
    pub fn recover<A, C, F, T>(
        &mut self,
        watch: &TransparentWatchSet<A>,
        chain: &C,
        filters: &mut F,
        transport: &mut T,
    ) -> Result<RecoveryBatch<A>, RecoveryError>
    where
        A: Copy + std::fmt::Debug,
        C: ChainView,
        F: FilterSource,
        T: ShardTransport,
    {
        self.pending_export = None;
        let context = watch
            .context()
            .ok_or_else(|| RecoveryError::Invalid("no locally accepted recovery target".into()))?;
        let target = Anchor {
            height: u64::from(u32::from(context.target.height)),
            hash: context.target.hash.to_string(),
        };
        require(
            chain.is_accepted(target.height, &target.hash) == Acceptance::Accepted,
            "target is not independently accepted",
        )?;
        if watch.addresses.is_empty() {
            // Every watched script is covered, vacuously. A sync would need the
            // wallet's hash for every shard from the map's start, since nothing
            // raises the floor, and the reference client reports a sync with no
            // scripts as unbounded discovery.
            return self.ready(
                vec![],
                vec![],
                Progress {
                    covered_through: target.height,
                    outcome: Outcome::Complete,
                },
            );
        }
        require(
            watch.addresses.len() <= self.config.scripts
                && self.store.scripts().map_err(failure)?.len() <= self.config.scripts,
            "script limit exceeded",
        )?;
        let addresses: BTreeMap<Vec<u8>, _> = watch
            .addresses
            .iter()
            .map(|entry| (address_script(entry.address), entry))
            .collect();
        require(
            addresses.len() == watch.addresses.len(),
            "duplicate watch address",
        )?;
        // The parent experiment's selective child requests leak coarse activity.
        require(
            !filters.uses_parents(),
            "parent filter sources are not supported",
        )?;
        let (mut filters, map_bytes) = Recorded::fetch(filters).map_err(failure)?;
        let map: ShardMap = serde_json::from_slice(filters.map()).map_err(failure)?;
        let floor = required_floor(watch, target.height);
        self.check_limits(&map, floor)?;
        // The wallet's chain is mainnet's; another chain's map cannot cover it.
        require(
            map.network == NETWORK && map.genesis_hash == MAINNET_GENESIS_DISPLAY,
            "publication is not for Zcash mainnet",
        )?;
        let (raw_init, _) = transport.init().map_err(failure)?;
        let geometry = transparent_wallet::parse_init(&raw_init).map_err(failure)?;
        require(
            geometry.schema == SCHEMA,
            "service serves an unsupported shard schema",
        )?;
        // The set check the sync would make when binding, made here so that a
        // changed publication restarts the store rather than stopping the sync.
        let set = SetIdentity::of_schema(&map, SCHEMA);
        if self
            .store
            .set_identity()
            .map_err(failure)?
            .is_some_and(|bound| !bound.continues(&set))
        {
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
                return Ok(behind_unread());
            }
            let (published, declarations) = self.revisions(&map, &set)?;
            let named: Vec<_> = published.into_iter().chain(declarations).collect();
            catalog::reset(&mut self.catalog, &named)?;
            return Err(RecoveryError::PublicationChanged);
        }
        let stored = self.store.anchor().map_err(failure)?;
        let retained = self
            .store
            .events()
            .map_err(failure)?
            .iter()
            .map(|held| u64::from(held.event.height()))
            .max()
            .unwrap_or(0);
        let (sync_anchor, clamped) =
            sync_target(&map, &target, floor, stored.as_ref(), retained, chain);
        let below_floor = BelowFloor {
            chain,
            below: floor,
            genesis: &map.genesis_hash,
        };
        let mut scripts = StaticScripts(
            watch
                .addresses
                .iter()
                .map(|entry| ScriptEntry {
                    script: address_script(entry.address),
                    origin: ScriptOrigin::Derived,
                    required_from: u64::from(u32::from(entry.required_from)),
                })
                .collect(),
        );
        let limits = WorkLimits {
            max_queries: Some(self.config.queries),
            max_private_bytes: Some(self.config.private_bytes),
        };
        let report = match transparent_wallet::sync_into(
            &mut self.store,
            &map,
            map_bytes,
            &geometry,
            &below_floor,
            &mut scripts,
            &mut filters,
            transport,
            &limits,
            &sync_anchor,
        ) {
            Ok(report) => report,
            // The map rewrites sealed history the store holds without declaring
            // a re-cut, and the wallet's chain accepts both the block the stored
            // range ends on and the block the map's sealed shard now covering
            // its start ends on, at or below the target. The sync judges that
            // only after rolling back any reorg the chain alone shows, and only
            // for the ranges the rollback kept, and refuses it before reading
            // anything; anything the chain cannot settle yet stops it as
            // `ChainUnknown`.
            //
            // The sync keeps no re-cut epoch, so a replica still serving a map
            // from before a re-cut the store followed looks the same to it. A
            // map below the epoch this companion recorded is taken for one:
            // `Pending`, behind, and a later pass syncs again. Otherwise the
            // publisher contradicts the wallet's own chain, which no later pass
            // over this history repairs: `Withdrawn(ChangedSealed)`. Either way
            // nothing was read: the store keeps what it held, less any reorg the
            // sync rolled back first, and the catalog is unchanged.
            Err(SyncError::SealedRewrite { .. }) => {
                if map.recut_epoch() < catalog::recut_epoch(&self.catalog)? {
                    return Ok(behind_unread());
                }
                return Ok(unready(
                    BatchState::Withdrawn(WithdrawnCause::ChangedSealed),
                    Progress {
                        covered_through: 0,
                        outcome: Outcome::Behind,
                    },
                ));
            }
            // Not a set change, which was checked above: a map refreshed
            // mid-pass does not continue the first (another re-cut epoch, or a
            // resumed shard id moved to another start). A later pass starts
            // from the publication it then finds.
            Err(SyncError::MapDiverged(_)) => return Ok(behind_unread()),
            Err(other) => return Err(failure(other)),
        };
        // A stale revision may have refreshed the map mid-sync. The stored facts
        // are the ones that map described.
        let map: ShardMap = serde_json::from_slice(filters.map()).map_err(failure)?;
        self.check_limits(&map, floor)?;
        self.normalize(watch, map, progress(&report, clamped), chain)
    }

    /// Refuses a map with more shards and declarations at or above `floor`
    /// than the shard limit, or more declarations in all than
    /// [`MAX_SUPERSEDED`].
    fn check_limits(&self, map: &ShardMap, floor: u64) -> Result<(), RecoveryError> {
        require(
            entries(map, floor) <= self.config.shards,
            "publication shard limit exceeded",
        )?;
        require(
            declarations(map) <= MAX_SUPERSEDED,
            "publication declaration limit exceeded",
        )
    }

    /// Every revision `map`, under `set`, publishes, and every one its re-cuts
    /// declare superseded, the superseded tails included.
    fn revisions(
        &self,
        map: &ShardMap,
        set: &SetIdentity,
    ) -> Result<(Vec<Published>, Vec<Published>), RecoveryError> {
        let published = map
            .shards
            .iter()
            .map(|entry| Published::of(&self.binding, set, entry))
            .collect::<Result<Vec<_>, _>>()?;
        let declarations = map
            .recuts
            .iter()
            .flat_map(|recut| &recut.superseded)
            .map(|shard| Published::declared(&self.binding, set, shard))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((published, declarations))
    }

    /// One catalog transaction over `map`: classify its revisions, export the
    /// companion's facts as commits, and decide the batch's state.
    fn normalize<A: Copy>(
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

    /// A ready batch, whose token the next acknowledgment must present.
    pub(crate) fn ready<A>(
        &mut self,
        commits: Vec<TransparentLedgerCommit<A>>,
        replaced: Vec<RecoveryRevision>,
        progress: Progress,
    ) -> Result<RecoveryBatch<A>, RecoveryError> {
        let last_commit = self.store.last_commit().map_err(failure)?;
        let token = export_token(&self.binding, last_commit, &commits, &replaced);
        self.pending_export = Some(token);
        Ok(RecoveryBatch {
            commits,
            progress,
            state: BatchState::Ready,
            replaced,
            token,
        })
    }

    /// Acknowledge the latest batch after every wallet commit succeeded, when it
    /// lists no retired revision.
    ///
    /// Only a [`BatchState::Ready`] batch from this companion's latest pass, with
    /// no [`RecoveryBatch::retired_revisions`], is acknowledged. A batch with
    /// retirements is refused, even when its commits applied, and its durable
    /// notifications are left unchanged: only
    /// [`Self::apply_and_acknowledge`] with trusted commits reconciles them. A
    /// [`BatchState::Pending`] or [`BatchState::Withdrawn`] batch, or the receipt
    /// of an earlier pass, is refused too.
    ///
    /// The batch's own revisions were recorded as exported before it was
    /// returned, so a crash before this acknowledgment replays the same candidate
    /// facts. It never advances a wallet's qualification, coverage or financial
    /// authority.
    pub fn acknowledge_applied<A>(
        &mut self,
        batch: &RecoveryBatch<A>,
    ) -> Result<(), RecoveryError> {
        require(
            batch.retired_revisions().is_empty(),
            "retired revisions require trusted wallet reconciliation",
        )?;
        self.acknowledge(batch)
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
    fn acknowledge<A>(&mut self, batch: &RecoveryBatch<A>) -> Result<(), RecoveryError> {
        require(
            batch.state == BatchState::Ready,
            "only a ready batch is acknowledged",
        )?;
        require(self.is_pending_export(batch), "export receipt is stale")?;
        catalog::acknowledge(&mut self.catalog, &batch.replaced)?;
        self.pending_export = None;
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
    pub(crate) fn is_pending_export<A>(&self, batch: &RecoveryBatch<A>) -> bool {
        self.pending_export == Some(batch.token)
    }

    /// Spends the latest pass's receipt.
    #[cfg(feature = "sqlite")]
    pub(crate) fn clear_pending_export(&mut self) {
        self.pending_export = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_says_when_to_pass_again() {
        for (outcome, retry) in [
            (Outcome::Complete, Retry::Complete),
            (Outcome::More, Retry::More),
            (Outcome::Behind, Retry::After(Duration::from_secs(10))),
            (Outcome::Overloaded, Retry::After(Duration::from_secs(30))),
            (Outcome::Stalled, Retry::Stalled),
        ] {
            let progress = Progress {
                covered_through: 7,
                outcome,
            };
            assert_eq!(progress.retry(), retry, "{outcome:?}");
        }
        let progress = |covered_through| Progress {
            covered_through,
            outcome: Outcome::Behind,
        };
        assert_eq!(progress(100).behind(100), 0);
        assert_eq!(progress(93).behind(100), 7);
        // Coverage past the target never wraps.
        assert_eq!(progress(103).behind(100), 0);
        assert_eq!(progress(0).behind(u64::MAX), u64::MAX);
    }

    /// A withdrawn batch is never retried on a timer, whatever the sync
    /// reported; any other batch follows its progress.
    #[test]
    fn a_withdrawn_batch_waits_for_new_work() {
        let batch = |state, outcome| RecoveryBatch::<()> {
            commits: Vec::new(),
            progress: Progress {
                covered_through: 7,
                outcome,
            },
            state,
            replaced: Vec::new(),
            token: [0; 32],
        };
        for outcome in [
            Outcome::Complete,
            Outcome::More,
            Outcome::Behind,
            Outcome::Overloaded,
            Outcome::Stalled,
        ] {
            for cause in [
                WithdrawnCause::Regression,
                WithdrawnCause::Equivocation,
                WithdrawnCause::ChangedSealed,
                WithdrawnCause::Retired,
            ] {
                let withdrawn = batch(BatchState::Withdrawn(cause), outcome);
                assert_eq!(withdrawn.retry(), Retry::Stalled, "{cause:?} {outcome:?}");
            }
            for state in [BatchState::Ready, BatchState::Pending] {
                let progress = batch(state, outcome).progress();
                assert_eq!(batch(state, outcome).retry(), progress.retry());
            }
        }
    }
    use std::cell::Cell;
    use transparent_filter::{Recut, SealParameters, ShardMapEntry, SupersededShard};
    use transparent_wallet::client::Table;
    use transparent_wallet::{Ledger, PendingPages, SetupBlob, SetupKey, StaticChain, StoredEvent};
    use zcash_client_backend::data_api::transparent_ledger::{
        AccountLifecycle, PendingPage, WatchOrigin, WatchedAddress,
    };
    use zcash_client_backend::data_api::transparent_ledger::{PublicationAnchor, RecoveryRevision};

    const MORE: Progress = Progress {
        covered_through: 0,
        outcome: Outcome::More,
    };
    const MAP: &[u8] = include_bytes!("../tests/fixtures/shard-map.json");

    fn config() -> RecoveryConfig {
        RecoveryConfig {
            source: b"explicit-fixture-source".to_vec(),
            account_binding: vec![1],
            origin: "http://127.0.0.1:1".into(),
            scripts: 40,
            shards: 2000,
            events: 100_000,
            queries: 64,
            private_bytes: 64 * 1024 * 1024,
        }
    }
    fn map() -> ShardMap {
        serde_json::from_slice(MAP).unwrap()
    }
    fn watch() -> TransparentWatchSet<u32> {
        let map = map();
        let last = map.shards.last().unwrap();
        TransparentWatchSet {
            account: 1,
            lifecycle: AccountLifecycle::Candidate,
            policy_generation: 0,
            target: Some(ChainPoint {
                height: block(last.end_height).unwrap(),
                hash: block_hash(&last.terminal_block_hash).unwrap(),
            }),
            addresses: vec![WatchedAddress {
                address: TransparentAddress::PublicKeyHash([7; 20]),
                origin: WatchOrigin::Standalone,
                required_from: block(map.start_height).unwrap(),
            }],
            pending_pages: vec![],
        }
    }
    fn report(completion: Completion) -> SyncReport {
        SyncReport {
            ledger: Ledger::new(),
            charges: Default::default(),
            matched_shards: vec![],
            unproductive_matches: 0,
            covered_through: 0,
            settled_through: 0,
            provisional: vec![],
            map_refreshes: 0,
            completion,
            rolled_back_to: None,
            replaced_revisions: vec![],
            scripts_added: 0,
            commits: 0,
        }
    }

    /// A public filter source that counts every call and serves only a shard map,
    /// the fixture's by default.
    struct CountingFilters {
        map: Vec<u8>,
        parents: bool,
        parent_checks: Cell<usize>,
        maps: usize,
        filters: usize,
    }
    impl Default for CountingFilters {
        fn default() -> Self {
            Self::serving(MAP.to_vec())
        }
    }
    impl CountingFilters {
        fn serving(map: Vec<u8>) -> Self {
            Self {
                map,
                parents: false,
                parent_checks: Cell::new(0),
                maps: 0,
                filters: 0,
            }
        }
        fn calls(&self) -> usize {
            self.parent_checks.get() + self.maps + self.filters
        }
    }
    impl FilterSource for CountingFilters {
        fn uses_parents(&self) -> bool {
            self.parent_checks.set(self.parent_checks.get() + 1);
            self.parents
        }
        fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
            self.maps += 1;
            Ok((self.map.clone(), self.map.len() as u64))
        }
        fn filter(&mut self, _shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
            self.filters += 1;
            Err("the counting source serves no filters".into())
        }
    }

    /// A private shard transport that counts every call and serves only an init.
    #[derive(Default)]
    struct CountingShards {
        schema: &'static str,
        inits: usize,
        manifests: usize,
        setups: usize,
        queries: usize,
    }
    impl CountingShards {
        fn serving(schema: &'static str) -> Self {
            Self {
                schema,
                ..Default::default()
            }
        }
        fn calls(&self) -> usize {
            self.inits + self.manifests + self.setups + self.queries
        }
    }
    impl ShardTransport for CountingShards {
        fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
            self.inits += 1;
            let init = serde_json::to_vec(&serde_json::json!({
                "schema": self.schema,
                "geometries": [],
            }))?;
            let cost = init.len() as u64;
            Ok((init, cost))
        }
        fn manifest(
            &mut self,
            _shard_id: u64,
            _revision: &str,
        ) -> Result<(Vec<u8>, u64), BoxError> {
            self.manifests += 1;
            Err("the counting transport serves no manifests".into())
        }
        fn setup(
            &mut self,
            _shard_id: u64,
            _revision: &str,
            _table: Table,
            _segment: u32,
        ) -> Result<(Vec<u8>, u64), BoxError> {
            self.setups += 1;
            Err("the counting transport serves no setup".into())
        }
        fn query(
            &mut self,
            _shard_id: u64,
            _revision: &str,
            _table: Table,
            _body: &[u8],
        ) -> Result<Vec<u8>, BoxError> {
            self.queries += 1;
            Err("the counting transport answers no queries".into())
        }
    }

    #[test]
    fn companion_binding_rejects_account_and_origin_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("companion.sqlite");
        drop(ReferenceRecovery::open(&path, config()).unwrap());
        for which in 0..3 {
            let mut different = config();
            match which {
                0 => different.account_binding = vec![2],
                1 => different.origin.push_str("/different"),
                _ => different.source = b"another-fixture-source".to_vec(),
            }
            assert!(matches!(
                ReferenceRecovery::open(&path, different),
                Err(RecoveryError::Invalid(_))
            ));
        }
        ReferenceRecovery::open(&path, config()).unwrap();
    }

    #[test]
    fn a_companion_bound_to_another_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("companion.sqlite");
        drop(ReferenceRecovery::open(&path, config()).unwrap());
        let config = config();
        let rebind = |schema: &str| {
            Connection::open(&path)
                .unwrap()
                .execute(
                    "UPDATE pir_bridge_binding SET value=?1 WHERE key='account-source'",
                    [catalog::binding([
                        &config.source,
                        &config.account_binding,
                        config.origin.as_bytes(),
                        schema.as_bytes(),
                    ])
                    .to_vec()],
                )
                .unwrap()
        };
        assert_eq!(rebind("transparent-shard-v10"), 1);
        assert!(matches!(
            ReferenceRecovery::open(&path, config.clone()),
            Err(RecoveryError::Invalid(_))
        ));
        assert_eq!(rebind(SCHEMA), 1);
        ReferenceRecovery::open(&path, config).unwrap();
    }

    #[test]
    fn missing_or_unaccepted_targets_and_oversized_watch_sets_fail_before_retrieval() {
        let dir = tempfile::tempdir().unwrap();
        let mut adapter =
            ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
        let map = map();
        let unknown = StaticChain::default();
        let accepted = StaticChain::from_map(&map);
        let mut filters = CountingFilters::default();
        let mut shards = CountingShards::serving(SCHEMA);
        let mut missing = watch();
        missing.target = None;
        let mut oversized = watch();
        oversized.addresses = (0..=40)
            .map(|i| WatchedAddress {
                address: TransparentAddress::PublicKeyHash([i; 20]),
                ..oversized.addresses[0]
            })
            .collect();
        let mut duplicated = watch();
        duplicated.addresses.push(duplicated.addresses[0]);
        for (watch, chain) in [
            (&watch(), &unknown),
            (&missing, &accepted),
            (&oversized, &accepted),
            (&duplicated, &accepted),
        ] {
            assert!(matches!(
                adapter.recover(watch, chain, &mut filters, &mut shards),
                Err(RecoveryError::Invalid(_))
            ));
        }
        assert_eq!((filters.calls(), shards.calls()), (0, 0));

        // Scripts the companion already retains count against the same limit.
        let dir = tempfile::tempdir().unwrap();
        let mut crowded =
            ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
        crowded.store.bind_set(&SetIdentity::of(&map)).unwrap();
        crowded
            .store
            .add_scripts(
                &(0..=40)
                    .map(|i| ScriptEntry {
                        script: address_script(TransparentAddress::ScriptHash([i; 20])),
                        origin: ScriptOrigin::Imported,
                        required_from: map.start_height,
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        assert!(matches!(
            crowded.recover(&watch(), &accepted, &mut filters, &mut shards),
            Err(RecoveryError::Invalid(_))
        ));
        assert_eq!((filters.calls(), shards.calls()), (0, 0));

        // Once every check passes, the same pass reaches the caller's transports.
        assert!(matches!(
            adapter.recover(&watch(), &accepted, &mut filters, &mut shards),
            Err(RecoveryError::Failure(_))
        ));
        assert_eq!((filters.maps, shards.inits), (1, 1));
        assert!(filters.filters > 0);
    }

    #[test]
    fn parent_filter_sources_are_refused_before_retrieval() {
        let dir = tempfile::tempdir().unwrap();
        let mut adapter =
            ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
        let mut filters = CountingFilters {
            parents: true,
            ..Default::default()
        };
        let mut shards = CountingShards::serving(SCHEMA);
        assert!(matches!(
            adapter.recover(
                &watch(),
                &StaticChain::from_map(&map()),
                &mut filters,
                &mut shards
            ),
            Err(RecoveryError::Invalid(_))
        ));
        assert_eq!(filters.parent_checks.get(), 1);
        assert_eq!((filters.maps, filters.filters, shards.calls()), (0, 0, 0));
    }

    #[test]
    fn a_service_with_another_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut adapter =
            ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
        let mut filters = CountingFilters::default();
        let mut shards = CountingShards::serving("transparent-shard-v10");
        assert!(matches!(
            adapter.recover(
                &watch(),
                &StaticChain::from_map(&map()),
                &mut filters,
                &mut shards
            ),
            Err(RecoveryError::Invalid(_))
        ));
        assert_eq!((filters.maps, shards.inits), (1, 1));
        assert_eq!(
            (
                filters.filters,
                shards.manifests,
                shards.setups,
                shards.queries
            ),
            (0, 0, 0, 0)
        );
        // Nothing reached the companion: it is still bound to no publication.
        assert!(adapter.store.set_identity().unwrap().is_none());
    }

    #[test]
    fn report_outcomes_map_to_progress() {
        let incomplete = |reason| Completion::Incomplete { reason, pending: 3 };
        for (completion, outcome) in [
            (Completion::Complete, Outcome::Complete),
            (incomplete(IncompleteReason::QueryBudget), Outcome::More),
            (incomplete(IncompleteReason::ByteBudget), Outcome::More),
            (incomplete(IncompleteReason::PendingLimit), Outcome::More),
            (
                incomplete(IncompleteReason::PublicationBehind { height: 9 }),
                Outcome::Behind,
            ),
            (
                incomplete(IncompleteReason::Overloaded { shard_id: 1 }),
                Outcome::Overloaded,
            ),
            (
                incomplete(IncompleteReason::ChainUnknown { height: 9 }),
                Outcome::Stalled,
            ),
            (
                incomplete(IncompleteReason::UnresolvedSpends),
                Outcome::Stalled,
            ),
            (
                incomplete(IncompleteReason::DiscoveryUnbounded),
                Outcome::Stalled,
            ),
        ] {
            let mut report = report(completion);
            report.covered_through = 77;
            assert_eq!(
                progress(&report, false),
                Progress {
                    covered_through: 77,
                    outcome,
                }
            );
            // A pass clamped to the publication's end is behind even when it
            // completes; an incomplete one keeps its reason.
            let clamped = if outcome == Outcome::Complete {
                Outcome::Behind
            } else {
                outcome
            };
            assert_eq!(
                progress(&report, true),
                Progress {
                    covered_through: 77,
                    outcome: clamped,
                }
            );
        }
    }

    #[test]
    fn metadata_conversion_preserves_exact_zero_unknown_and_coinbase() {
        for fee in [
            FeeState::Exact(0),
            FeeState::Unknown,
            FeeState::NotApplicable,
        ] {
            let converted = metadata(Some(transparent_events::TransactionMetadata {
                fee,
                transparent_input_count: 0,
                has_shielded_components: true,
            }))
            .unwrap()
            .unwrap();
            assert!(converted.has_shielded_components);
            match fee {
                FeeState::Exact(_) => {
                    assert_eq!(converted.fee, WholeTransactionFee::Exact(Zatoshis::ZERO))
                }
                FeeState::Unknown => assert_eq!(converted.fee, WholeTransactionFee::Unknown),
                FeeState::NotApplicable => {
                    assert_eq!(converted.fee, WholeTransactionFee::NotApplicable)
                }
            }
        }
        assert_eq!(metadata(None).unwrap(), None);
        assert!(
            metadata(Some(transparent_events::TransactionMetadata {
                fee: FeeState::Exact(u64::MAX),
                transparent_input_count: 1,
                has_shielded_components: false
            }))
            .is_err()
        );
    }

    #[test]
    fn normalized_events_preserve_attribution_and_local_shard_anchor_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("companion.sqlite");
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        let map = map();
        let entry = &map.shards[0];
        let watch = watch();
        let script = address_script(watch.addresses[0].address);
        adapter.store.bind_set(&SetIdentity::of(&map)).unwrap();
        adapter
            .store
            .add_scripts(&[ScriptEntry {
                script: script.clone(),
                origin: ScriptOrigin::Imported,
                required_from: map.start_height,
            }])
            .unwrap();
        let parent_meta = transparent_events::TransactionMetadata {
            fee: FeeState::Exact(0),
            transparent_input_count: 3,
            has_shielded_components: true,
        };
        let spend_meta = transparent_events::TransactionMetadata {
            fee: FeeState::Exact(10),
            transparent_input_count: 1,
            has_shielded_components: false,
        };
        let receive = TransparentEvent::Receive(transparent_events::ReceiveEvent {
            metadata: Some(parent_meta),
            height: entry.start_height as u32,
            txid: transparent_events::Txid([1; 32]),
            transaction_index: 1,
            output_index: 0,
            value: 100,
            coinbase: false,
        });
        let spend = TransparentEvent::Spend(transparent_events::SpendEvent {
            metadata: Some(spend_meta),
            height: entry.start_height as u32 + 1,
            spending_txid: transparent_events::Txid([2; 32]),
            transaction_index: 2,
            input_index: 0,
            spent_txid: transparent_events::Txid([1; 32]),
            spent_output_index: 0,
        });
        adapter
            .store
            .commit_shard(transparent_wallet::ShardCommit {
                source_anchor: None,
                shard_id: entry.shard_id,
                revision_digest: entry.manifest_digest.clone(),
                sealed: entry.sealed,
                start_height: entry.start_height,
                end_height: entry.end_height,
                terminal_block_hash: entry.terminal_block_hash.clone(),
                events: [receive, spend]
                    .into_iter()
                    .map(|event| StoredEvent {
                        script: script.clone(),
                        event,
                        shard_id: entry.shard_id,
                        revision_digest: entry.manifest_digest.clone(),
                    })
                    .collect(),
                covered_scripts: vec![script],
                pending_upsert: vec![],
                pending_complete: vec![],
            })
            .unwrap();
        let first = adapter
            .normalize(&watch, map.clone(), MORE, &StaticChain::from_map(&map))
            .unwrap();
        assert_eq!(first.state, BatchState::Ready);
        assert_eq!(first.commits.len(), 1);
        let commit = &first.commits[0];
        assert_eq!(commit.anchor.height, block(entry.end_height).unwrap());
        assert!(commit.anchor.height < commit.context.target.height);
        assert_eq!(
            commit.receives[0].metadata.unwrap().fee,
            WholeTransactionFee::Exact(Zatoshis::ZERO)
        );
        assert!(commit.receives[0].metadata.unwrap().has_shielded_components);
        assert_eq!(
            commit.spends[0].metadata.unwrap().fee,
            WholeTransactionFee::Exact(Zatoshis::const_from_u64(10))
        );
        assert_eq!(
            commit.spends[0].metadata.unwrap().transparent_input_count,
            1
        );
        adapter.acknowledge_applied(&first).unwrap();
        assert!(adapter.acknowledge_applied(&first).is_err());
        drop(adapter);
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        let again = adapter
            .normalize(&watch, map.clone(), MORE, &StaticChain::from_map(&map))
            .unwrap();
        assert_eq!(again.commits, first.commits);
        adapter
            .store
            .rollback_above(
                &Anchor {
                    height: map.start_height - 1,
                    hash: map.shards[0].parent_block_hash.clone(),
                },
                "controlled fixture reorg",
            )
            .unwrap();
        // Other sealed content under the same revision number is withdrawn, and
        // stays withdrawn after a restart.
        let mut replacement = map.clone();
        replacement.shards[0].manifest_digest = "ab".repeat(32);
        let changed = adapter
            .normalize(
                &watch,
                replacement.clone(),
                MORE,
                &StaticChain::from_map(&replacement),
            )
            .unwrap();
        let withdrawn = BatchState::Withdrawn(WithdrawnCause::Equivocation);
        assert_eq!(changed.state, withdrawn);
        assert!(changed.commits.is_empty());
        drop(adapter);
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        let after_restart = adapter
            .normalize(
                &watch,
                replacement.clone(),
                MORE,
                &StaticChain::from_map(&replacement),
            )
            .unwrap();
        assert_eq!(after_restart.state, withdrawn);
        assert!(adapter.acknowledge_applied(&after_restart).is_err());
    }

    #[test]
    fn possible_wallet_export_survives_crash_before_ack_and_withdrawal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("companion.sqlite");
        let mut map = map();
        let mut adapter = covering(&path, &map);
        let batch = pass(&mut adapter, &map);
        assert_eq!(batch.state, BatchState::Ready);
        let possibly_applied = batch.commits[1].revision.clone();
        // The application may have applied this batch, then died before acknowledging it.
        drop(adapter);

        // The tail is republished. The companion withdrew its old coverage but has
        // not retrieved the successor, so nothing replaces what may be in the wallet.
        map.shards[1].revision = 1;
        map.shards[1].manifest_digest = "5a".repeat(32);
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        withdraw_tail(&mut adapter, &map);
        let pending = pass(&mut adapter, &map);
        assert_eq!(pending.state, BatchState::Pending);
        assert!(pending.commits.is_empty());
        assert!(adapter.acknowledge_applied(&pending).is_err());
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1)]);
        // The export intent survives a restart.
        drop(adapter);
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        assert_eq!(pass(&mut adapter, &map).state, BatchState::Pending);

        // Once the successor is retrieved it replaces the possibly applied tail.
        retrieve_tail(&mut adapter, &map);
        let ready = pass(&mut adapter, &map);
        assert_eq!(ready.state, BatchState::Ready);
        let successor = &ready.commits[1].revision;
        assert_eq!(successor.source, possibly_applied.source);
        assert_eq!(successor.lineage, possibly_applied.lineage + 1);
        // A crash before this acknowledgment replays the same batch.
        drop(adapter);
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        let replayed = pass(&mut adapter, &map);
        assert_eq!(replayed.state, BatchState::Ready);
        assert_eq!(replayed.commits, ready.commits);
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1), (TAIL, 2)]);
        // The possibly applied tail is a notification the wallet must reconcile.
        assert_eq!(
            replayed.retired_revisions(),
            std::slice::from_ref(&possibly_applied)
        );
        assert!(matches!(
            adapter.acknowledge_applied(&replayed),
            Err(RecoveryError::Invalid(_))
        ));
        // Rejection must preserve the notification even across another crash.
        drop(adapter);
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        let replayed = pass(&mut adapter, &map);
        assert_eq!(replayed.retired_revisions(), &[possibly_applied]);
        assert!(adapter.acknowledge_reconciled(&batch).is_err());
        adapter.acknowledge_reconciled(&replayed).unwrap();
        assert!(adapter.acknowledge_reconciled(&replayed).is_err());
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 2)]);
        assert_eq!(cataloged(&adapter), 2);
        let acknowledged = pass(&mut adapter, &map);
        assert_eq!(acknowledged.state, BatchState::Ready);
        assert!(acknowledged.retired_revisions().is_empty());
        adapter.acknowledge_applied(&acknowledged).unwrap();
    }

    #[test]
    fn empty_replacement_retains_notice_until_wallet_reconciliation_commits() {
        use zcash_client_backend::data_api::{
            Account as _,
            chain::ChainState,
            testing::{InitialChainState, TestBuilder, TestRng},
            transparent_ledger::{
                TransparentLedgerMode::PrivateRequired, TransparentLedgerRead as _,
                TransparentLedgerWrite as _,
            },
        };
        use zcash_client_sqlite::{
            WalletDb,
            testing::{BlockCache, db::TestDbFactory},
            util::SystemClock,
        };

        let mut publication = map();
        publication.shards.truncate(1);
        publication.shards[0].sealed = false;
        let start = publication.start_height;
        let parent = block_hash(&publication.shards[0].parent_block_hash).unwrap();
        let mut wallet = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::file_backed())
            .with_block_cache(BlockCache::new())
            .with_initial_chain_state(|_, _| InitialChainState {
                chain_state: ChainState::empty(block(start - 1).unwrap(), parent),
                prior_sapling_roots: vec![],
                prior_orchard_roots: vec![],
            })
            .with_account_having_current_birthday()
            .build();
        wallet.generate_and_scan_empty_blocks(2);
        let account = wallet.test_account().unwrap().id();
        wallet
            .wallet_mut()
            .db_mut()
            .apply_transparent_policy(PrivateRequired)
            .unwrap();
        wallet
            .wallet_mut()
            .db_mut()
            .set_transparent_ledger_mode(PrivateRequired);
        let watch = wallet.wallet().db().transparent_watch_set(account).unwrap();
        let target = watch.target.unwrap();
        publication.shards[0].end_height = u64::from(u32::from(target.height));
        publication.shards[0].terminal_block_hash = target.hash.to_string();
        let chain = StaticChain::from_map(&publication);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("companion.sqlite");
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        adapter
            .store
            .bind_set(&SetIdentity::of(&publication))
            .unwrap();
        let scripts: Vec<_> = watch
            .addresses
            .iter()
            .map(|a| address_script(a.address))
            .collect();
        adapter
            .store
            .add_scripts(
                &scripts
                    .iter()
                    .map(|script| ScriptEntry {
                        script: script.clone(),
                        origin: ScriptOrigin::Imported,
                        required_from: start,
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let entry = &publication.shards[0];
        adapter
            .store
            .commit_shard(transparent_wallet::ShardCommit {
                source_anchor: None,
                shard_id: entry.shard_id,
                revision_digest: entry.manifest_digest.clone(),
                sealed: false,
                start_height: start,
                end_height: entry.end_height,
                terminal_block_hash: entry.terminal_block_hash.clone(),
                events: vec![],
                covered_scripts: scripts.clone(),
                pending_upsert: vec![],
                pending_complete: vec![],
            })
            .unwrap();
        let first = adapter
            .normalize(&watch, publication.clone(), MORE, &chain)
            .unwrap();
        assert_eq!(first.state, BatchState::Ready);
        let retired = first.commits[0].revision.clone();
        for commit in &first.commits {
            wallet
                .wallet_mut()
                .db_mut()
                .apply_transparent_ledger_commit(commit.clone())
                .unwrap();
        }
        wallet
            .wallet_mut()
            .db_mut()
            .qualify_transparent_revision(&retired)
            .unwrap();
        let wallet_path = wallet.wallet().conn().path().unwrap().to_owned();
        // Coverage rows the wallet durably holds under `revision`.
        let coverage_of = |revision: &RecoveryRevision| -> u64 {
            Connection::open(&wallet_path)
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM tpir_coverage c JOIN tpir_revisions r ON r.id = c.revision_id
                     WHERE r.source = ?1 AND r.revision = ?2",
                    rusqlite::params![revision.source, revision.revision],
                    |row| row.get(0),
                )
                .unwrap()
        };
        let before = wallet
            .wallet()
            .db()
            .transparent_candidate_recovery(account)
            .unwrap();
        assert_eq!(before.covered_through, Some(target.height));
        // Crash after the wallet commits but before the companion acknowledges.
        drop(adapter);
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        adapter
            .store
            .rollback_above(
                &Anchor {
                    height: start - 1,
                    hash: publication.shards[0].parent_block_hash.clone(),
                },
                "fixture withdrawal",
            )
            .unwrap();
        publication.shards[0].revision += 1;
        publication.shards[0].manifest_digest = "ab".repeat(32);
        // Until the companion retrieves a successor, the empty replacement keeps
        // the possibly applied revision's notice and hands the wallet nothing.
        let replacement = adapter
            .normalize(&watch, publication.clone(), MORE, &chain)
            .unwrap();
        assert_eq!(replacement.state, BatchState::Pending);
        assert!(replacement.commits.is_empty());
        assert!(replacement.retired_revisions().is_empty());
        assert!(adapter.acknowledge_applied(&replacement).is_err());
        assert!(adapter.acknowledge_reconciled(&replacement).is_err());
        assert_eq!(
            wallet
                .wallet()
                .db()
                .transparent_candidate_recovery(account)
                .unwrap(),
            before
        );

        // Once retrieved, the successor resolves the retired revision.
        let entry = &publication.shards[0];
        adapter
            .store
            .commit_shard(transparent_wallet::ShardCommit {
                source_anchor: None,
                shard_id: entry.shard_id,
                revision_digest: entry.manifest_digest.clone(),
                sealed: false,
                start_height: start,
                end_height: entry.end_height,
                terminal_block_hash: entry.terminal_block_hash.clone(),
                events: vec![],
                covered_scripts: scripts,
                pending_upsert: vec![],
                pending_complete: vec![],
            })
            .unwrap();
        let replacement = adapter
            .normalize(&watch, publication.clone(), MORE, &chain)
            .unwrap();
        assert_eq!(replacement.state, BatchState::Ready);
        assert_eq!(
            replacement.retired_revisions(),
            std::slice::from_ref(&retired)
        );
        let successor = replacement.commits[0].clone();
        assert_eq!(successor.revision.source, retired.source);
        assert_eq!(successor.revision.lineage, retired.lineage + 1);
        assert!(adapter.acknowledge_applied(&replacement).is_err());

        // A trusted reconciliation that fails changes nothing, and the notice
        // survives a crash.
        wallet.wallet().conn().execute_batch("CREATE TEMP TRIGGER fail_reconciliation BEFORE DELETE ON tpir_coverage BEGIN SELECT RAISE(ABORT, 'fixture reconciliation failure'); END;").unwrap();
        assert!(
            wallet
                .wallet_mut()
                .db_mut()
                .qualify_transparent_revision(&successor.revision)
                .is_err()
        );
        assert_eq!(
            wallet
                .wallet()
                .db()
                .transparent_candidate_recovery(account)
                .unwrap(),
            before
        );
        drop(adapter);
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        let replacement = adapter
            .normalize(&watch, publication.clone(), MORE, &chain)
            .unwrap();
        assert_eq!(
            replacement.retired_revisions(),
            std::slice::from_ref(&retired)
        );
        assert!(adapter.acknowledge_applied(&replacement).is_err());

        wallet
            .wallet()
            .conn()
            .execute_batch("DROP TRIGGER fail_reconciliation")
            .unwrap();
        // This controlled fixture trusts the successor, standing in for the
        // wallet's trusted operation, which qualifies and applies it in one
        // transaction. A publication change alone is never authorization in an
        // application.
        wallet
            .wallet_mut()
            .db_mut()
            .qualify_transparent_revision(&successor.revision)
            .unwrap();
        wallet
            .wallet_mut()
            .db_mut()
            .apply_transparent_ledger_commit(successor.clone())
            .unwrap();
        // A reopened wallet must observe the committed reconciliation before
        // acknowledgement: the retired evidence is withdrawn, and the successor
        // covers the target.
        let reopened = WalletDb::from_connection(
            Connection::open(&wallet_path).unwrap(),
            *wallet.network(),
            SystemClock,
            TestRng::seed_from_u64(0),
        )
        .with_transparent_ledger_mode(PrivateRequired);
        assert_eq!(coverage_of(&retired), 0);
        assert!(coverage_of(&successor.revision) > 0);
        assert_eq!(
            reopened
                .transparent_candidate_recovery(account)
                .unwrap()
                .covered_through,
            Some(target.height)
        );
        adapter.acknowledge_reconciled(&replacement).unwrap();
        drop(adapter);
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        let final_batch = adapter
            .normalize(&watch, publication, MORE, &chain)
            .unwrap();
        assert_eq!(final_batch.state, BatchState::Ready);
        assert!(final_batch.retired_revisions().is_empty());
        adapter.acknowledge_applied(&final_batch).unwrap();
    }

    #[test]
    fn spans_needs_contiguous_coverage_of_the_address() {
        let (ours, theirs) = (
            TransparentAddress::PublicKeyHash([7; 20]),
            TransparentAddress::PublicKeyHash([8; 20]),
        );
        let range = |address, from: u64, through: u64| AddressRange {
            address,
            from: block(from).unwrap(),
            through: block(through).unwrap(),
        };
        let covers = |ranges: &[AddressRange], from, through| {
            spans(ranges, ours, block(from).unwrap(), block(through).unwrap())
        };
        // Adjacent ranges, in any order, cover their union.
        let adjacent = [range(ours, 20, 29), range(ours, 10, 19)];
        assert!(covers(&adjacent, 12, 25));
        assert!(covers(&adjacent, 10, 29));
        assert!(!covers(&adjacent, 9, 25));
        assert!(!covers(&adjacent, 12, 30));
        // A one-block gap, or another address's range filling it, does not.
        let gap = [
            range(ours, 10, 19),
            range(theirs, 20, 20),
            range(ours, 21, 29),
        ];
        assert!(!covers(&gap, 12, 25));
        assert!(covers(&gap, 21, 25));
        assert!(!covers(&[], 12, 12));
    }

    #[test]
    fn page_continuation_identity_binds_revision_script_shard_and_first_row() {
        let first = page_id(0, "aa", &[1], 2);
        for other in [
            page_id(1, "aa", &[1], 2),
            page_id(0, "bb", &[1], 2),
            page_id(0, "aa", &[2], 2),
            page_id(0, "aa", &[1], 3),
        ] {
            assert_ne!(first, other);
        }
    }

    /// A companion bound to the fixture map that retains `script` from `required_from`.
    fn seeded(dir: &tempfile::TempDir, script: &[u8], required_from: u64) -> ReferenceRecovery {
        let mut adapter =
            ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
        adapter.store.bind_set(&SetIdentity::of(&map())).unwrap();
        adapter
            .store
            .add_scripts(&[ScriptEntry {
                script: script.to_vec(),
                origin: ScriptOrigin::Imported,
                required_from,
            }])
            .unwrap();
        adapter
    }

    /// What a pass reading `entry` under `digest` through `end` commits for `script`.
    fn covered(
        entry: &ShardMapEntry,
        digest: &str,
        (end, terminal): (u64, &str),
        script: &[u8],
        events: Vec<TransparentEvent>,
    ) -> transparent_wallet::ShardCommit {
        transparent_wallet::ShardCommit {
            source_anchor: None,
            shard_id: entry.shard_id,
            revision_digest: digest.into(),
            sealed: entry.sealed,
            start_height: entry.start_height,
            end_height: end,
            terminal_block_hash: terminal.into(),
            events: events
                .into_iter()
                .map(|event| StoredEvent {
                    script: script.to_vec(),
                    event,
                    shard_id: entry.shard_id,
                    revision_digest: digest.into(),
                })
                .collect(),
            covered_scripts: vec![script.to_vec()],
            pending_upsert: vec![],
            pending_complete: vec![],
        }
    }

    #[test]
    fn below_floor_view_is_lenient_only_below_the_floor() {
        let floor = 1_000;
        let held = "11".repeat(32);
        let other = "22".repeat(32);
        let chain = StaticChain {
            hashes: BTreeMap::from([(floor, held.clone())]),
        };
        let view = BelowFloor {
            chain: &chain,
            below: floor,
            genesis: MAINNET_GENESIS_DISPLAY,
        };
        // Below the floor every block is accepted, and only block 0 has a hash.
        for height in [0, 1, floor - 1] {
            assert_eq!(view.is_accepted(height, &other), Acceptance::Accepted);
        }
        assert_eq!(view.hash_at(0).as_deref(), Some(MAINNET_GENESIS_DISPLAY));
        assert_eq!(view.hash_at(1), None);
        assert_eq!(view.hash_at(floor - 1), None);
        // From the floor up, the caller's chain alone answers.
        assert_eq!(view.is_accepted(floor, &held), Acceptance::Accepted);
        assert_eq!(view.is_accepted(floor, &other), Acceptance::Rejected);
        assert_eq!(view.is_accepted(floor + 1, &held), Acceptance::Unknown);
        assert_eq!(view.hash_at(floor), Some(held));
        assert_eq!(view.hash_at(floor + 1), None);
        assert_eq!(view.tip(), chain.tip());
        // A floor of 0, when nothing is watched, is never lenient.
        let strict = BelowFloor {
            chain: &chain,
            below: 0,
            genesis: MAINNET_GENESIS_DISPLAY,
        };
        assert_eq!(
            strict.is_accepted(0, MAINNET_GENESIS_DISPLAY),
            Acceptance::Unknown
        );
        assert_eq!(strict.hash_at(0), None);

        // The floor is the lowest required height, capped at the target.
        let mut watch = watch();
        let lowest = u64::from(u32::from(watch.addresses[0].required_from));
        watch.addresses.push(WatchedAddress {
            address: TransparentAddress::PublicKeyHash([8; 20]),
            required_from: block(lowest + 10).unwrap(),
            ..watch.addresses[0]
        });
        assert_eq!(required_floor(&watch, u64::MAX), lowest);
        assert_eq!(required_floor(&watch, lowest - 1), lowest - 1);
        watch.addresses.clear();
        assert_eq!(required_floor(&watch, u64::MAX), 0);
    }

    #[test]
    fn shards_ending_below_the_required_start_are_neither_exported_nor_cataloged() {
        let map = map();
        let (low, high) = (&map.shards[0], &map.shards[1]);
        let mut watch = watch();
        let address = watch.addresses[0].address;
        let script = address_script(address);
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = seeded(&dir, &script, map.start_height);
        // The companion also holds coverage and a receive in the shard below the floor.
        let receive = TransparentEvent::Receive(transparent_events::ReceiveEvent {
            metadata: None,
            height: low.start_height as u32,
            txid: transparent_events::Txid([1; 32]),
            transaction_index: 1,
            output_index: 0,
            value: 100,
            coinbase: false,
        });
        for (entry, events) in [(low, vec![receive]), (high, vec![])] {
            let end = (entry.end_height, entry.terminal_block_hash.as_str());
            adapter
                .store
                .commit_shard(covered(entry, &entry.manifest_digest, end, &script, events))
                .unwrap();
        }

        // The wallet's chain starts at the floor, so it has no hash for the low shard.
        watch.addresses[0].required_from = block(high.start_height).unwrap();
        let chain = StaticChain {
            hashes: BTreeMap::from([(high.end_height, high.terminal_block_hash.clone())]),
        };
        let batch = adapter
            .normalize(&watch, map.clone(), MORE, &chain)
            .unwrap();
        assert_eq!(batch.commits.len(), 1);
        let commit = &batch.commits[0];
        assert_eq!(commit.anchor.height, block(high.end_height).unwrap());
        assert!(commit.receives.is_empty());
        assert_eq!(
            commit.coverage,
            vec![AddressRange {
                address,
                from: block(high.start_height).unwrap(),
                through: block(high.end_height).unwrap(),
            }]
        );
        assert_eq!(cataloged(&adapter), 1);

        // With the floor at the map's start, the same companion exports and
        // catalogs both shards, the receive included.
        watch.addresses[0].required_from = block(map.start_height).unwrap();
        let batch = adapter
            .normalize(&watch, map.clone(), MORE, &StaticChain::from_map(&map))
            .unwrap();
        assert_eq!(batch.commits.len(), 2);
        assert_eq!(batch.commits[0].receives.len(), 1);
        assert_eq!(cataloged(&adapter), 2);
    }

    #[test]
    fn a_pass_watching_nothing_sends_no_request() {
        let map = map();
        let last = map.shards.last().unwrap();
        let mut watch = watch();
        watch.addresses.clear();
        let target = u64::from(u32::from(watch.target.unwrap().height));
        // The wallet holds only its target, far above block 0, the floor of an
        // empty watch set.
        assert_eq!(required_floor(&watch, target), 0);
        let chain = StaticChain {
            hashes: BTreeMap::from([(last.end_height, last.terminal_block_hash.clone())]),
        };
        let dir = tempfile::tempdir().unwrap();
        let mut adapter =
            ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
        let mut filters = CountingFilters::default();
        let mut shards = CountingShards::serving(SCHEMA);
        let batch = adapter
            .recover(&watch, &chain, &mut filters, &mut shards)
            .unwrap();
        assert_eq!(
            batch.progress,
            Progress {
                covered_through: target,
                outcome: Outcome::Complete,
            }
        );
        assert_eq!(batch.state, BatchState::Ready);
        assert!(batch.commits.is_empty());
        assert_eq!((filters.calls(), shards.calls()), (0, 0));
        assert!(adapter.store.set_identity().unwrap().is_none());
        assert_eq!(cataloged(&adapter), 0);
        adapter.acknowledge_applied(&batch).unwrap();
        // The target must still be accepted.
        assert!(matches!(
            adapter.recover(&watch, &StaticChain::default(), &mut filters, &mut shards),
            Err(RecoveryError::Invalid(_))
        ));
        assert_eq!((filters.calls(), shards.calls()), (0, 0));
    }

    #[test]
    fn sync_target_clamps_only_to_an_accepted_end_at_or_above_the_floor_and_anchor() {
        let map = map();
        let last = map.shards.last().unwrap();
        let t = last.end_height;
        let end = Anchor {
            height: t,
            hash: last.terminal_block_hash.clone(),
        };
        let accepted = StaticChain::from_map(&map);
        let floor = map.start_height;
        let target = Anchor {
            height: t + 10,
            hash: "99".repeat(32),
        };
        let unclamped = (target.clone(), false);

        // Behind, with every condition met: sync to the map's accepted end.
        assert_eq!(
            sync_target(&map, &target, floor, None, 0, &accepted),
            (end.clone(), true)
        );
        // A floor, companion anchor or retained event exactly at the end allows it.
        assert_eq!(
            sync_target(&map, &target, t, Some(&end), t, &accepted),
            (end.clone(), true)
        );
        // Ahead or level: the publication reaches the target.
        for reached in [t - 1, t] {
            let target = Anchor {
                height: reached,
                hash: "99".repeat(32),
            };
            assert_eq!(
                sync_target(&map, &target, floor, None, 0, &accepted),
                (target, false)
            );
        }
        // Below the floor: nothing the watch set requires is published yet.
        assert_eq!(
            sync_target(&map, &target, t + 1, None, 0, &accepted),
            unclamped
        );
        // An unaccepted terminal: the wallet's chain does not know the end.
        assert_eq!(
            sync_target(&map, &target, floor, None, 0, &StaticChain::default()),
            unclamped
        );
        // A map terminal on a stale branch: the wallet holds another block there.
        let mut stale = accepted.clone();
        stale.hashes.insert(t, "aa".repeat(32));
        assert_eq!(
            sync_target(&map, &target, floor, None, 0, &stale),
            unclamped
        );
        // A lagging replica: the companion already settled above the end, or
        // retains an event above it.
        let above = Anchor {
            height: t + 1,
            hash: "bb".repeat(32),
        };
        assert_eq!(
            sync_target(&map, &target, floor, Some(&above), 0, &accepted),
            unclamped
        );
        assert_eq!(
            sync_target(&map, &target, floor, None, t + 1, &accepted),
            unclamped
        );
    }

    #[test]
    fn a_pass_behind_the_publication_syncs_to_its_accepted_end() {
        let map = map();
        let last = map.shards.last().unwrap();
        let t = last.end_height;
        let mut watch = watch();
        let wallet_target = ChainPoint {
            height: block(t + 10).unwrap(),
            hash: BlockHash([9; 32]),
        };
        watch.target = Some(wallet_target);
        let mut chain = StaticChain::from_map(&map);
        chain.hashes.insert(t + 10, wallet_target.hash.to_string());
        let address = watch.addresses[0].address;
        let script = address_script(address);

        // A wallet born above the publication's end has nothing to clamp to.
        let dir = tempfile::tempdir().unwrap();
        let mut young =
            ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
        let mut born = watch.clone();
        born.addresses[0].required_from = block(t + 1).unwrap();
        let mut filters = CountingFilters::default();
        let mut shards = CountingShards::serving(SCHEMA);
        let batch = young
            .recover(&born, &chain, &mut filters, &mut shards)
            .unwrap();
        assert_eq!(batch.progress.outcome, Outcome::Behind);
        assert!(batch.commits.is_empty());
        assert_eq!(young.store.anchor().unwrap(), None);
        assert_eq!((filters.filters, shards.calls()), (0, 1));

        // A companion already covering the script through the end needs no retrieval.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = seeded(&dir, &script, map.start_height);
        for entry in &map.shards {
            let end = (entry.end_height, entry.terminal_block_hash.as_str());
            adapter
                .store
                .commit_shard(covered(entry, &entry.manifest_digest, end, &script, vec![]))
                .unwrap();
        }
        let mut filters = CountingFilters::default();
        let mut shards = CountingShards::serving(SCHEMA);
        let batch = adapter
            .recover(&watch, &chain, &mut filters, &mut shards)
            .unwrap();
        assert_eq!((filters.filters, shards.calls()), (0, 1));
        // The client completed through the map's end, which is still behind the wallet.
        assert_eq!(
            batch.progress,
            Progress {
                covered_through: t,
                outcome: Outcome::Behind,
            }
        );
        assert_eq!(
            adapter.store.anchor().unwrap(),
            Some(Anchor {
                height: t,
                hash: last.terminal_block_hash.clone(),
            })
        );
        // Commits keep the wallet's target, and each anchor stays at its shard's end.
        assert_eq!(batch.commits.len(), map.shards.len());
        for (commit, entry) in batch.commits.iter().zip(&map.shards) {
            assert_eq!(commit.context.target, wallet_target);
            assert_eq!(
                commit.anchor,
                ChainPoint {
                    height: block(entry.end_height).unwrap(),
                    hash: block_hash(&entry.terminal_block_hash).unwrap(),
                }
            );
            assert_eq!(
                commit.coverage,
                vec![AddressRange {
                    address,
                    from: block(entry.start_height).unwrap(),
                    through: block(entry.end_height).unwrap(),
                }]
            );
        }

        // After a reorg the wallet holds another block at the map's end. The pass
        // cannot clamp to it and is behind, and the tail's facts, which rest on
        // the old branch, wait for the publication to follow.
        let mut reorged = chain.clone();
        reorged.hashes.insert(t, "aa".repeat(32));
        let mut filters = CountingFilters::default();
        let mut shards = CountingShards::serving(SCHEMA);
        let batch = adapter
            .recover(&watch, &reorged, &mut filters, &mut shards)
            .unwrap();
        assert_eq!((filters.filters, shards.calls()), (0, 1));
        assert_eq!(batch.progress.outcome, Outcome::Behind);
        assert_eq!(batch.state, BatchState::Pending);
        assert!(batch.commits.is_empty());
    }

    #[test]
    fn a_replaced_tail_rolls_back_below_the_floor_without_a_wallet_hash() {
        let map = map();
        let tail = map.shards.last().unwrap();
        // The companion covered an older tail revision, ending at a block the wallet accepts.
        let old_end = (tail.end_height - 38, "ef".repeat(32));
        // The wallet holds no block below the tail's start, where the rollback lands.
        let chain = StaticChain {
            hashes: BTreeMap::from([
                old_end.clone(),
                (tail.end_height, tail.terminal_block_hash.clone()),
            ]),
        };
        for (required_from, lenient) in [(tail.start_height, true), (map.start_height, false)] {
            let mut watch = watch();
            watch.addresses[0].required_from = block(required_from).unwrap();
            let script = address_script(watch.addresses[0].address);
            let dir = tempfile::tempdir().unwrap();
            let mut adapter = seeded(&dir, &script, required_from);
            let old = (old_end.0, old_end.1.as_str());
            adapter
                .store
                .commit_shard(covered(tail, &"cd".repeat(32), old, &script, vec![]))
                .unwrap();
            let mut filters = CountingFilters::default();
            let mut shards = CountingShards::serving(SCHEMA);
            // Below the floor the rollback is accepted and the pass goes on to the
            // tail's filter, which the counting source refuses. At or above it the
            // wallet's missing hash stops the pass before any filter request.
            let Err(RecoveryError::Failure(stopped)) =
                adapter.recover(&watch, &chain, &mut filters, &mut shards)
            else {
                panic!("the pass must fail at the filter or at the rollback");
            };
            let cause = if lenient {
                "transport:"
            } else {
                "no accepted rollback hash"
            };
            assert!(stopped.contains(cause), "{stopped}");
            assert_eq!(adapter.store.provisional().unwrap().is_empty(), lenient);
            assert_eq!(filters.filters, usize::from(lenient));
        }
    }

    #[test]
    fn a_map_for_another_network_or_genesis_is_refused_before_retrieval() {
        let fixture: serde_json::Value = serde_json::from_slice(MAP).unwrap();
        let mut testnet = fixture.clone();
        testnet["network"] = "test".into();
        let mut forked = fixture;
        forked["genesis_hash"] = "11".repeat(32).into();
        for served in [testnet, forked] {
            let dir = tempfile::tempdir().unwrap();
            let mut adapter =
                ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
            let mut filters = CountingFilters::serving(serde_json::to_vec(&served).unwrap());
            let mut shards = CountingShards::serving(SCHEMA);
            assert!(matches!(
                adapter.recover(
                    &watch(),
                    &StaticChain::from_map(&map()),
                    &mut filters,
                    &mut shards
                ),
                Err(RecoveryError::Invalid(_))
            ));
            assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 0));
            assert!(adapter.store.set_identity().unwrap().is_none());
        }
    }

    /// A companion at `path` opened under `config` and bound to `map`, covering
    /// the watched script on every shard under the revision `map` publishes.
    fn covering_as(path: &Path, config: RecoveryConfig, map: &ShardMap) -> ReferenceRecovery {
        let mut adapter = ReferenceRecovery::open(path, config).unwrap();
        cover(&mut adapter, map);
        adapter
    }

    /// Binds the companion's store to `map` and covers the watched script on
    /// every shard under the revision `map` publishes, as a sync would.
    fn cover(adapter: &mut ReferenceRecovery, map: &ShardMap) {
        let script = address_script(watch().addresses[0].address);
        adapter.store.bind_set(&SetIdentity::of(map)).unwrap();
        adapter
            .store
            .add_scripts(&[ScriptEntry {
                script: script.clone(),
                origin: ScriptOrigin::Imported,
                required_from: map.start_height,
            }])
            .unwrap();
        for entry in &map.shards {
            let end = (entry.end_height, entry.terminal_block_hash.as_str());
            adapter
                .store
                .commit_shard(covered(entry, &entry.manifest_digest, end, &script, vec![]))
                .unwrap();
        }
    }

    /// Starts a pass from `map`, which must stop at the set check: before any
    /// filter or private request, with the store reset.
    fn publication_change(adapter: &mut ReferenceRecovery, map: &ShardMap) {
        let mut filters = CountingFilters::serving(serde_json::to_vec(map).unwrap());
        let mut shards = CountingShards::serving(SCHEMA);
        assert!(matches!(
            adapter.recover(
                &watch(),
                &StaticChain::from_map(map),
                &mut filters,
                &mut shards
            ),
            Err(RecoveryError::PublicationChanged)
        ));
        assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 1));
        assert_eq!(adapter.store.set_identity().unwrap(), None);
    }

    /// `(table, rows)` for every table of the companion's store, the catalog's
    /// excluded, by name.
    fn store_rows(adapter: &ReferenceRecovery) -> Vec<(String, u64)> {
        let mut statement = adapter
            .catalog
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table'
                 AND name NOT LIKE 'pir_bridge_%' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .unwrap();
        let tables: Vec<String> = statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        tables
            .into_iter()
            .map(|table| {
                let rows = adapter
                    .catalog
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                    .unwrap();
                (table, rows)
            })
            .collect()
    }

    fn covering(path: &Path, map: &ShardMap) -> ReferenceRecovery {
        covering_as(path, config(), map)
    }

    /// Normalizes the fixture watch set against `map`, accepted as the chain.
    fn pass(adapter: &mut ReferenceRecovery, map: &ShardMap) -> RecoveryBatch<u32> {
        adapter
            .normalize(&watch(), map.clone(), MORE, &StaticChain::from_map(map))
            .unwrap()
    }

    /// `map` with shard `index` republished as `revision` under `digest`.
    fn republished(map: &ShardMap, index: usize, revision: u32, digest: String) -> ShardMap {
        let mut map = map.clone();
        map.shards[index].revision = revision;
        map.shards[index].manifest_digest = digest;
        map
    }

    /// Rolls the companion's tail facts back, as a sync does when the tail it
    /// covered is replaced.
    fn withdraw_tail(adapter: &mut ReferenceRecovery, map: &ShardMap) {
        let tail = map.shards.last().unwrap();
        adapter
            .store
            .rollback_above(
                &Anchor {
                    height: tail.start_height - 1,
                    hash: tail.parent_block_hash.clone(),
                },
                "replaced tail",
            )
            .unwrap();
    }

    /// Replaces the companion's tail facts with coverage under `map`'s tail.
    fn retrieve_tail(adapter: &mut ReferenceRecovery, map: &ShardMap) {
        withdraw_tail(adapter, map);
        let tail = map.shards.last().unwrap();
        let script = address_script(watch().addresses[0].address);
        let end = (tail.end_height, tail.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(tail, &tail.manifest_digest, end, &script, vec![]))
            .unwrap();
    }

    /// The fixture map's start heights: its archive shard's and its tail's.
    const ARCHIVE: u64 = 3_499_739;
    const TAIL: u64 = 3_500_239;

    /// `(start_height, lineage)` of every catalog row recorded as exported.
    fn exported(adapter: &ReferenceRecovery) -> Vec<(u64, u64)> {
        let mut statement = adapter
            .catalog
            .prepare(
                "SELECT start_height, lineage FROM pir_bridge_catalog WHERE exported=1
                 ORDER BY start_height, lineage",
            )
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// Every catalog row as `(source, start_height, lineage, exported, current)`,
    /// so a test can tell that a call recorded nothing.
    fn catalog_rows(adapter: &ReferenceRecovery) -> Vec<(Vec<u8>, u64, u64, bool, bool)> {
        let mut statement = adapter
            .catalog
            .prepare(
                "SELECT source, start_height, lineage, exported, current FROM pir_bridge_catalog
                 ORDER BY source, lineage",
            )
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn cataloged(adapter: &ReferenceRecovery) -> u64 {
        adapter
            .catalog
            .query_row("SELECT COUNT(*) FROM pir_bridge_catalog", [], |r| r.get(0))
            .unwrap()
    }

    fn revisions(batch: &RecoveryBatch<u32>) -> Vec<RecoveryRevision> {
        batch
            .commits
            .iter()
            .map(|commit| commit.revision.clone())
            .collect()
    }

    #[test]
    fn source_identity_binds_account_origin_and_schema() {
        let map = map();
        let dir = tempfile::tempdir().unwrap();
        let sources = |name: &str, config: RecoveryConfig| -> Vec<Vec<u8>> {
            let mut adapter = covering_as(&dir.path().join(name), config, &map);
            let batch = pass(&mut adapter, &map);
            assert_eq!(batch.state, BatchState::Ready);
            batch
                .commits
                .iter()
                .map(|commit| commit.revision.source.clone())
                .collect()
        };
        let base = sources("base.sqlite", config());
        assert_eq!(base.len(), 2);
        assert_ne!(base[0], base[1]);
        // Reopening the companion derives the same sources.
        let mut reopened =
            ReferenceRecovery::open(dir.path().join("base.sqlite"), config()).unwrap();
        let again: Vec<_> = revisions(&pass(&mut reopened, &map))
            .into_iter()
            .map(|revision| revision.source)
            .collect();
        assert_eq!(again, base);
        // Another account or origin derives other sources for every shard.
        let mut account = config();
        account.account_binding = vec![2];
        let mut origin = config();
        origin.origin = "https://another-origin.test".into();
        let account = sources("account.sqlite", account);
        let origin = sources("origin.sqlite", origin);
        for other in [&account, &origin] {
            for (theirs, ours) in other.iter().zip(&base) {
                assert_ne!(theirs, ours);
            }
        }
        assert_ne!(account, origin);
        // So does another schema under the same account and origin.
        let config = config();
        let set = SetIdentity::of_schema(&map, SCHEMA);
        let schema = |schema: &str| {
            let binding = catalog::binding([
                &config.source,
                &config.account_binding,
                config.origin.as_bytes(),
                schema.as_bytes(),
            ]);
            let entry = &map.shards[1];
            catalog::source(&binding, &set, &entry.geometry, entry.start_height)
                .unwrap()
                .to_vec()
        };
        assert_eq!(schema(SCHEMA), base[1]);
        assert_ne!(schema("transparent-shard-v10"), base[1]);
    }

    #[test]
    fn source_identity_survives_a_new_geometry_tier() {
        let map = map();
        let mut grown = map.clone();
        grown.seal.insert(
            "recent-1k-2k".into(),
            SealParameters {
                max_scripts: 1,
                max_page_rows: 2,
                max_txids: 3,
            },
        );
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
        let before = pass(&mut adapter, &map);
        adapter.acknowledge_applied(&before).unwrap();
        // The bound companion continues into the grown set with the same sources.
        let after = pass(&mut adapter, &grown);
        assert_eq!(after.state, BatchState::Ready);
        assert_eq!(revisions(&after), revisions(&before));
        assert_eq!(cataloged(&adapter), 2);
        // A companion first bound after the tier appeared derives identical triples.
        let mut recreated = covering(&dir.path().join("recreated.sqlite"), &grown);
        assert_eq!(revisions(&pass(&mut recreated, &grown)), revisions(&before));
    }

    #[test]
    fn a_changed_seal_changes_only_its_geometrys_sources() {
        let map = map();
        let (archive, recent) = (&map.shards[0], &map.shards[1]);
        assert_ne!(archive.geometry, recent.geometry);
        let mut resealed = map.clone();
        resealed.seal.get_mut(&recent.geometry).unwrap().max_scripts += 1;
        let config = config();
        let binding = catalog::binding([
            &config.source,
            &config.account_binding,
            config.origin.as_bytes(),
            SCHEMA.as_bytes(),
        ]);
        let set = SetIdentity::of_schema(&map, SCHEMA);
        let reset = SetIdentity::of_schema(&resealed, SCHEMA);
        let source = |set: &SetIdentity, entry: &ShardMapEntry| {
            catalog::source(&binding, set, &entry.geometry, entry.start_height).unwrap()
        };
        assert_eq!(source(&set, archive), source(&reset, &resealed.shards[0]));
        assert_ne!(source(&set, recent), source(&reset, &resealed.shards[1]));
        // A bound companion does not continue into the resealed set.
        assert!(!set.continues(&reset));
    }

    #[test]
    fn a_recreated_companion_distinguishes_a_shifted_shard_boundary() {
        let original = map();
        let recent = &original.shards[1];
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("original.sqlite"), &original);
        let before = pass(&mut adapter, &original);
        assert_eq!(before.state, BatchState::Ready);
        let prior = revisions(&before)[1].clone();

        // Re-cutting the archive geometry can reuse a recent shard's id for a
        // different height range, without changing its geometry or revision
        // number. Both directions must give that range another source.
        for start in [recent.start_height - 1, recent.start_height + 1] {
            let mut recut = original.clone();
            recut
                .seal
                .get_mut(&original.shards[0].geometry)
                .unwrap()
                .max_scripts += 1;
            recut.shards[0].end_height = start - 1;
            recut.shards[1].start_height = start;
            recut.shards[1].manifest_digest = "77".repeat(32);
            recut.check_shape().unwrap();
            assert!(
                !SetIdentity::of_schema(&original, SCHEMA)
                    .continues(&SetIdentity::of_schema(&recut, SCHEMA))
            );

            let path = dir.path().join(format!("recut-{start}.sqlite"));
            let mut recreated = covering(&path, &recut);
            let batch = pass(&mut recreated, &recut);
            assert_eq!(batch.state, BatchState::Ready);
            let next = revisions(&batch)[1].clone();
            assert_eq!(next.lineage, prior.lineage);
            assert_ne!(next.revision, prior.revision);
            assert_ne!(next.source, prior.source);

            // Reopening unchanged data still reproduces the same identity.
            drop(recreated);
            let mut reopened = ReferenceRecovery::open(&path, config()).unwrap();
            assert_eq!(revisions(&pass(&mut reopened, &recut))[1], next);
        }
    }

    #[test]
    fn lineage_follows_the_published_revision() {
        let map = republished(&map(), 1, 7, map().shards[1].manifest_digest.clone());
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
        let batch = pass(&mut adapter, &map);
        assert_eq!(batch.state, BatchState::Ready);
        let lineages: Vec<_> = revisions(&batch)
            .iter()
            .map(|revision| revision.lineage)
            .collect();
        assert_eq!(lineages, vec![1, 8]);
        for (revision, entry) in revisions(&batch).iter().zip(&map.shards) {
            let mut identity = Sha256::new();
            identity.update(b"transparent-reference-revision-v2");
            identity.update(entry.manifest_digest.as_bytes());
            identity.update([u8::from(entry.sealed)]);
            assert_eq!(revision.revision, identity.finalize().to_vec());
            assert_eq!(revision.sealed, entry.sealed);
            assert_eq!(
                revision.publication.height,
                block(entry.end_height).unwrap()
            );
            assert_eq!(
                revision.publication.hash,
                block_hash(&entry.terminal_block_hash).unwrap()
            );
        }
        // A recreated companion reproduces identical triples.
        let mut recreated = covering(&dir.path().join("recreated.sqlite"), &map);
        assert_eq!(revisions(&pass(&mut recreated, &map)), revisions(&batch));
    }

    #[test]
    fn a_lagging_tail_is_pending_not_withdrawn() {
        let base = map();
        let ahead = republished(&base, 1, 5, "a5".repeat(32));
        let lagging = republished(&base, 1, 3, "a3".repeat(32));
        // A companion that covers only the sealed shard, so the lagging tail is the
        // only finding.
        let dir = tempfile::tempdir().unwrap();
        let script = address_script(watch().addresses[0].address);
        let mut adapter = seeded(&dir, &script, base.start_height);
        let sealed = &base.shards[0];
        let end = (sealed.end_height, sealed.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(
                sealed,
                &sealed.manifest_digest,
                end,
                &script,
                vec![],
            ))
            .unwrap();
        let first = pass(&mut adapter, &ahead);
        assert_eq!(first.state, BatchState::Ready);
        adapter.acknowledge_applied(&first).unwrap();
        assert_eq!(cataloged(&adapter), 2);
        // An unseen tail revision below the one recorded: a lagging replica.
        let batch = pass(&mut adapter, &lagging);
        assert_eq!(batch.state, BatchState::Pending);
        assert!(batch.commits.is_empty());
        assert_eq!(cataloged(&adapter), 2);
        assert!(adapter.acknowledge_applied(&batch).is_err());
        // Once the replica catches up the same companion is ready again.
        assert_eq!(pass(&mut adapter, &ahead).state, BatchState::Ready);

        // A map missing the newest shard, whose facts the companion exported.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
        let first = pass(&mut adapter, &base);
        assert_eq!(first.commits.len(), 2);
        adapter.acknowledge_applied(&first).unwrap();
        let mut behind = base.clone();
        behind.shards.pop();
        let batch = pass(&mut adapter, &behind);
        assert_eq!(batch.state, BatchState::Pending);
        assert!(batch.commits.is_empty());
        assert_eq!(cataloged(&adapter), 2);
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1)]);

        // A replica that has not caught up with the tail's seal: it still serves
        // the tail unsealed, below the sealed revision the companion exported.
        let mut sealed = republished(&base, 1, 1, "5e".repeat(32));
        sealed.shards[1].sealed = true;
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &sealed);
        let first = pass(&mut adapter, &sealed);
        assert_eq!(first.state, BatchState::Ready);
        adapter.acknowledge_applied(&first).unwrap();
        let batch = pass(&mut adapter, &base);
        assert_eq!(batch.state, BatchState::Pending);
        assert!(batch.commits.is_empty());
        assert_eq!(cataloged(&adapter), 2);
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 2)]);
        assert_eq!(pass(&mut adapter, &sealed).state, BatchState::Ready);
    }

    #[test]
    fn a_regressed_sealed_publication_is_withdrawn() {
        let mut sealed = map();
        sealed.shards[1].sealed = true;
        sealed.shards[1].revision = 4;
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &sealed);
        let first = pass(&mut adapter, &sealed);
        assert_eq!(revisions(&first)[1].lineage, 5);
        adapter.acknowledge_applied(&first).unwrap();
        let regressed = republished(&sealed, 1, 2, "b2".repeat(32));
        let batch = pass(&mut adapter, &regressed);
        assert_eq!(
            batch.state,
            BatchState::Withdrawn(WithdrawnCause::Regression)
        );
        assert!(batch.commits.is_empty());
        assert_eq!(cataloged(&adapter), 2);
        assert!(adapter.acknowledge_applied(&batch).is_err());
    }

    #[test]
    fn an_equivocating_revision_is_withdrawn() {
        let base = map();
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
        let first = pass(&mut adapter, &base);
        adapter.acknowledge_applied(&first).unwrap();
        let equivocation = BatchState::Withdrawn(WithdrawnCause::Equivocation);
        // Other content under the same revision number.
        let other = republished(&base, 1, 0, "e0".repeat(32));
        // The same content sealed under the same revision number.
        let mut resealed = base.clone();
        resealed.shards[1].sealed = true;
        // The same content and revision number ending at another block.
        let mut moved = base.clone();
        moved.shards[1].terminal_block_hash = "77".repeat(32);
        for map in [other, resealed, moved] {
            let batch = pass(&mut adapter, &map);
            assert_eq!(batch.state, equivocation);
            assert!(batch.commits.is_empty());
        }
        // Nothing equivocating was recorded: the original publication is still ready.
        assert_eq!(cataloged(&adapter), 2);
        assert_eq!(pass(&mut adapter, &base).state, BatchState::Ready);
    }

    #[test]
    fn a_changed_sealed_revision_is_withdrawn() {
        let base = map();
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
        let first = pass(&mut adapter, &base);
        adapter.acknowledge_applied(&first).unwrap();
        // The exported sealed shard is published again with other content.
        let changed = republished(&base, 0, 1, "c1".repeat(32));
        let batch = pass(&mut adapter, &changed);
        assert_eq!(
            batch.state,
            BatchState::Withdrawn(WithdrawnCause::ChangedSealed)
        );
        assert!(batch.commits.is_empty());
        assert!(adapter.acknowledge_applied(&batch).is_err());
    }

    #[test]
    fn an_exported_shard_under_another_geometry_is_retired() {
        let base = map();
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
        let first = pass(&mut adapter, &base);
        adapter.acknowledge_applied(&first).unwrap();
        // The tail is republished under the archive geometry, so another source.
        let mut regeometried = republished(&base, 1, 1, "f1".repeat(32));
        regeometried.shards[1].geometry = base.shards[0].geometry.clone();
        retrieve_tail(&mut adapter, &regeometried);
        let batch = pass(&mut adapter, &regeometried);
        assert_eq!(batch.state, BatchState::Withdrawn(WithdrawnCause::Retired));
        assert!(batch.commits.is_empty());
    }

    #[test]
    fn a_publication_change_resets_the_store_and_keeps_the_catalog() {
        let map = map();
        let mut resealed = map.clone();
        resealed
            .seal
            .get_mut(&map.shards[1].geometry)
            .unwrap()
            .max_scripts += 1;
        let (sealed, tail) = (&map.shards[0], &map.shards[1]);
        let script = address_script(watch().addresses[0].address);
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
        // Every store table holds something: a receive and its spend, a pending
        // page, cached filter and setup, and a committed anchor.
        let receive = TransparentEvent::Receive(transparent_events::ReceiveEvent {
            metadata: None,
            height: sealed.start_height as u32,
            txid: transparent_events::Txid([1; 32]),
            transaction_index: 1,
            output_index: 0,
            value: 100,
            coinbase: false,
        });
        let spend = TransparentEvent::Spend(transparent_events::SpendEvent {
            metadata: None,
            height: sealed.start_height as u32 + 1,
            spending_txid: transparent_events::Txid([2; 32]),
            transaction_index: 2,
            input_index: 0,
            spent_txid: transparent_events::Txid([1; 32]),
            spent_output_index: 0,
        });
        let end = (sealed.end_height, sealed.terminal_block_hash.as_str());
        let mut events = covered(
            sealed,
            &sealed.manifest_digest,
            end,
            &script,
            vec![receive, spend],
        );
        events.covered_scripts.clear();
        adapter.store.commit_shard(events).unwrap();
        let end = (tail.end_height, tail.terminal_block_hash.as_str());
        let mut open = covered(tail, &tail.manifest_digest, end, &script, vec![]);
        open.covered_scripts.clear();
        open.pending_upsert = vec![PendingPages {
            id: None,
            shard_id: tail.shard_id,
            revision_digest: tail.manifest_digest.clone(),
            script: script.clone(),
            first_page: 3,
            page_count: 0,
            inline: vec![],
            next_ordinal: 0,
            attempts: 0,
            validated_events: 0,
            boundary: None,
            target_anchor: None,
        }];
        adapter.store.commit_shard(open).unwrap();
        adapter
            .store
            .put_filter(&sealed.manifest_digest, "ff", true, b"filter")
            .unwrap();
        adapter
            .store
            .put_setup(
                &SetupKey {
                    set_digest: "set".into(),
                    revision_digest: sealed.manifest_digest.clone(),
                    table: Table::Directory,
                    segment: 0,
                },
                &SetupBlob {
                    public_params_base64: "AA==".into(),
                    public_params_sha256: "00".into(),
                },
            )
            .unwrap();
        let anchor = Anchor {
            height: tail.end_height,
            hash: tail.terminal_block_hash.clone(),
        };
        adapter
            .store
            .commit_anchor(&anchor, tail.end_height, tail.end_height)
            .unwrap();
        let first = pass(&mut adapter, &map);
        assert_eq!(first.state, BatchState::Ready);
        assert_eq!(first.commits[0].receives.len(), 1);
        assert_eq!(first.commits[1].opened_pages.len(), 1);
        adapter.acknowledge_applied(&first).unwrap();
        let original = revisions(&first);
        // Facts read under the bound set are never exported under another one.
        let deferred = adapter
            .normalize(
                &watch(),
                resealed.clone(),
                MORE,
                &StaticChain::from_map(&resealed),
            )
            .unwrap();
        assert_eq!(deferred.state, BatchState::Pending);
        assert!(deferred.commits.is_empty());
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1)]);
        let held = store_rows(&adapter);
        assert_eq!(held.len(), 9);
        for (table, rows) in held {
            assert!(rows > 0, "{table}");
        }

        // A pass starting from the resealed map stops at the set check, having
        // emptied every store table but the schema version.
        publication_change(&mut adapter, &resealed);
        let reset = store_rows(&adapter);
        assert_eq!(reset.len(), 9);
        for (table, rows) in reset {
            assert_eq!(rows, u64::from(table == "wallet_meta"), "{table}");
        }
        let kept: String = adapter
            .catalog
            .query_row("SELECT key FROM wallet_meta", [], |row| row.get(0))
            .unwrap();
        assert_eq!(kept, "schema_version");
        // The catalog keeps every row. Only the tail's revision, whose source the
        // resealed map no longer names, stops counting as exported.
        assert_eq!(cataloged(&adapter), 2);
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1)]);
        drop(adapter);

        // The retried pass, on the same companion reopened, gets past the check
        // and binds the store to the resealed set.
        let mut adapter =
            ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
        let mut filters = CountingFilters::serving(serde_json::to_vec(&resealed).unwrap());
        let mut shards = CountingShards::serving(SCHEMA);
        assert!(matches!(
            adapter.recover(
                &watch(),
                &StaticChain::from_map(&resealed),
                &mut filters,
                &mut shards
            ),
            Err(RecoveryError::Failure(_))
        ));
        assert!(filters.filters > 0);
        assert_eq!(
            adapter.store.set_identity().unwrap(),
            Some(SetIdentity::of_schema(&resealed, SCHEMA))
        );
        // Once the publication is retrieved again, the pass is ready. The
        // unchanged source reproduces its triple; the resealed geometry's shard
        // has a new source.
        cover(&mut adapter, &resealed);
        let retried = pass(&mut adapter, &resealed);
        assert_eq!(retried.state, BatchState::Ready);
        let retried_revisions = revisions(&retried);
        assert_eq!(retried_revisions[0], original[0]);
        assert_ne!(retried_revisions[1].source, original[1].source);
        adapter.acknowledge_applied(&retried).unwrap();
        // The changed source keeps its highest row, neither current nor exported.
        assert_eq!(cataloged(&adapter), 3);
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1)]);
    }

    #[test]
    fn an_unchanged_source_keeps_its_history_across_a_publication_change() {
        let base = map();
        let (archive, recent) = (&base.shards[0].geometry, &base.shards[1].geometry);
        // A publisher at sealed revision 4 and tail revision 6.
        let first = republished(&base, 0, 4, base.shards[0].manifest_digest.clone());
        let first = republished(&first, 1, 6, base.shards[1].manifest_digest.clone());
        let resealed = |geometry: &str| {
            let mut map = first.clone();
            map.seal.get_mut(geometry).unwrap().max_scripts += 1;
            map
        };
        let exporting = |dir: &tempfile::TempDir| {
            let mut adapter = covering(&dir.path().join("companion.sqlite"), &first);
            let batch = pass(&mut adapter, &first);
            adapter.acknowledge_applied(&batch).unwrap();
            assert_eq!(exported(&adapter), vec![(ARCHIVE, 5), (TAIL, 7)]);
            adapter
        };

        // A re-cut that reseals the tail's geometry and restarts revision
        // numbers. The sealed shard keeps its source, so its restarted revision
        // is a regression rather than a lineage that collides in the wallet.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = exporting(&dir);
        let recut = republished(&resealed(recent), 0, 0, "c0".repeat(32));
        publication_change(&mut adapter, &recut);
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 5)]);
        cover(&mut adapter, &recut);
        let batch = pass(&mut adapter, &recut);
        assert_eq!(
            batch.state,
            BatchState::Withdrawn(WithdrawnCause::Regression)
        );
        assert!(batch.commits.is_empty());

        // A re-cut that reseals the sealed shard's geometry. The tail keeps its
        // source, so its restarted revisions are pending below the old maximum,
        // equivocate at it, and replace the exported tail only above it.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = exporting(&dir);
        let recut = resealed(archive);
        let restarted =
            |revision: u32| republished(&recut, 1, revision, format!("{revision:064x}"));
        publication_change(&mut adapter, &restarted(2));
        assert_eq!(exported(&adapter), vec![(TAIL, 7)]);
        cover(&mut adapter, &restarted(2));
        let batch = pass(&mut adapter, &restarted(2));
        assert_eq!(batch.state, BatchState::Pending);
        assert!(batch.commits.is_empty());
        retrieve_tail(&mut adapter, &restarted(6));
        let batch = pass(&mut adapter, &restarted(6));
        assert_eq!(
            batch.state,
            BatchState::Withdrawn(WithdrawnCause::Equivocation)
        );
        assert!(batch.commits.is_empty());
        retrieve_tail(&mut adapter, &restarted(7));
        let batch = pass(&mut adapter, &restarted(7));
        assert_eq!(batch.state, BatchState::Ready);
        assert_eq!(revisions(&batch)[1].lineage, 8);
        let retired: Vec<_> = batch
            .retired_revisions()
            .iter()
            .map(|revision| revision.lineage)
            .collect();
        assert_eq!(retired, vec![7]);
        assert!(adapter.acknowledge_applied(&batch).is_err());
        adapter.acknowledge_reconciled(&batch).unwrap();
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 5), (TAIL, 8)]);
    }

    #[test]
    fn a_shard_id_reused_for_other_content_gets_a_new_source() {
        let before = map();
        // Resealing the archive geometry re-shards it: its shard ends later, and
        // shard id 1 names other content under the same geometry and seal.
        let mut after = before.clone();
        after
            .seal
            .get_mut(&before.shards[0].geometry)
            .unwrap()
            .max_scripts += 1;
        let moved = "3c".repeat(32);
        after.shards[0].end_height += 100;
        after.shards[0].terminal_block_hash = moved.clone();
        after.shards[0].manifest_digest = "a0".repeat(32);
        after.shards[1].start_height += 100;
        after.shards[1].parent_block_hash = moved;
        after.shards[1].manifest_digest = "a1".repeat(32);
        let config = config();
        let binding = catalog::binding([
            &config.source,
            &config.account_binding,
            config.origin.as_bytes(),
            SCHEMA.as_bytes(),
        ]);
        let source = |map: &ShardMap, entry: &ShardMapEntry| {
            let set = SetIdentity::of_schema(map, SCHEMA);
            catalog::source(&binding, &set, &entry.geometry, entry.start_height).unwrap()
        };
        assert_ne!(
            source(&before, &before.shards[1]),
            source(&after, &after.shards[1])
        );
        // The start height alone tells them apart.
        let mut unmoved = after.shards[1].clone();
        unmoved.start_height = before.shards[1].start_height;
        assert_eq!(source(&before, &before.shards[1]), source(&after, &unmoved));

        // So the new tail, at the revision number the companion exported for
        // the old one, is a new source after the publication change rather than
        // an equivocation.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &before);
        let first = pass(&mut adapter, &before);
        adapter.acknowledge_applied(&first).unwrap();
        publication_change(&mut adapter, &after);
        assert!(exported(&adapter).is_empty());
        cover(&mut adapter, &after);
        let batch = pass(&mut adapter, &after);
        assert_eq!(batch.state, BatchState::Ready);
        let (old, new) = (revisions(&first), revisions(&batch));
        assert_eq!(new[1].lineage, old[1].lineage);
        assert_ne!(new[1].revision, old[1].revision);
        assert_ne!(new[1].source, old[1].source);
    }

    /// Page work the store still owes for `script` on `entry`, from `first_page`.
    fn store_page(entry: &ShardMapEntry, script: &[u8], first_page: u32) -> PendingPages {
        PendingPages {
            id: None,
            shard_id: entry.shard_id,
            revision_digest: entry.manifest_digest.clone(),
            script: script.to_vec(),
            first_page,
            page_count: 0,
            inline: vec![],
            next_ordinal: 0,
            attempts: 0,
            validated_events: 0,
            boundary: None,
            target_anchor: None,
        }
    }

    /// `map` with the seal parameters of `shard`'s geometry changed.
    fn resealing(map: &ShardMap, shard: usize) -> ShardMap {
        let mut resealed = map.clone();
        resealed
            .seal
            .get_mut(&map.shards[shard].geometry)
            .unwrap()
            .max_scripts += 1;
        resealed
    }

    #[test]
    fn a_page_under_a_source_the_map_no_longer_names_is_completed_once_covered() {
        let map = map();
        let (sealed, tail) = (&map.shards[0], &map.shards[1]);
        let resealed = resealing(&map, 1);
        let script = address_script(watch().addresses[0].address);
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = seeded(&dir, &script, map.start_height);
        // The sealed shard is covered; a budget-limited pass left a page on the tail.
        let end = (sealed.end_height, sealed.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(
                sealed,
                &sealed.manifest_digest,
                end,
                &script,
                vec![],
            ))
            .unwrap();
        let end = (tail.end_height, tail.terminal_block_hash.as_str());
        let mut open = covered(tail, &tail.manifest_digest, end, &script, vec![]);
        open.covered_scripts.clear();
        open.pending_upsert = vec![store_page(tail, &script, 3)];
        adapter.store.commit_shard(open).unwrap();
        let first = pass(&mut adapter, &map);
        assert_eq!(first.state, BatchState::Ready);
        let opening = first.commits[1].clone();
        assert_eq!(opening.opened_pages.len(), 1);
        adapter.acknowledge_applied(&first).unwrap();
        // The wallet applied it and holds the page under the tail's revision.
        let mut holding = watch();
        holding.pending_pages = vec![PendingPage {
            request: opening.opened_pages[0].clone(),
            revision: opening.revision.clone(),
            target: opening.context.target,
        }];

        // Resealing the tail's geometry gives the tail a new source, so no
        // commit of the page's revision follows. While the retried retrieval
        // covers only the sealed shard, the page stays open.
        publication_change(&mut adapter, &resealed);
        adapter.store.bind_set(&SetIdentity::of(&resealed)).unwrap();
        adapter
            .store
            .add_scripts(&[ScriptEntry {
                script: script.clone(),
                origin: ScriptOrigin::Imported,
                required_from: map.start_height,
            }])
            .unwrap();
        let end = (sealed.end_height, sealed.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(
                sealed,
                &sealed.manifest_digest,
                end,
                &script,
                vec![],
            ))
            .unwrap();
        let chain = StaticChain::from_map(&resealed);
        let partial = adapter
            .normalize(&holding, resealed.clone(), MORE, &chain)
            .unwrap();
        assert_eq!(partial.state, BatchState::Ready);
        assert_eq!(revisions(&partial), vec![first.commits[0].revision.clone()]);
        adapter.acknowledge_applied(&partial).unwrap();

        // Once the batch covers the page's range under the new source, a
        // completion-only commit under the page's own revision follows the
        // commits that cover it, anchored at that revision's publication.
        let end = (tail.end_height, tail.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(
                &resealed.shards[1],
                &tail.manifest_digest,
                end,
                &script,
                vec![],
            ))
            .unwrap();
        let batch = adapter
            .normalize(&holding, resealed.clone(), MORE, &chain)
            .unwrap();
        assert_eq!(batch.state, BatchState::Ready);
        assert_eq!(batch.commits.len(), 3);
        assert_ne!(batch.commits[1].revision.source, opening.revision.source);
        let completion = &batch.commits[2];
        assert_eq!(
            completion,
            &TransparentLedgerCommit {
                context: opening.context,
                revision: opening.revision.clone(),
                anchor: ChainPoint {
                    height: block(tail.end_height).unwrap(),
                    hash: block_hash(&tail.terminal_block_hash).unwrap(),
                },
                receives: vec![],
                spends: vec![],
                coverage: vec![],
                unsupported: vec![],
                opened_pages: vec![],
                completed_pages: vec![opening.opened_pages[0].page.clone()],
            }
        );
        // It is not recorded as exported, so later passes never settle it
        // against the map, which publishes its shard under another source.
        let old_exported: bool = adapter
            .catalog
            .query_row(
                "SELECT exported FROM pir_bridge_catalog WHERE source=?1",
                [&opening.revision.source],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!old_exported);
        adapter.acknowledge_applied(&batch).unwrap();
        let after = pass(&mut adapter, &resealed);
        assert_eq!(after.state, BatchState::Ready);
        assert_eq!(revisions(&after), revisions(&batch)[..2].to_vec());

        // A page whose revision's publication block the wallet's chain does
        // not hold waits.
        let mut elsewhere = holding.clone();
        elsewhere.pending_pages[0].revision.publication.hash = BlockHash([0x55; 32]);
        let waiting = adapter
            .normalize(&elsewhere, resealed.clone(), MORE, &chain)
            .unwrap();
        assert_eq!(waiting.state, BatchState::Ready);
        assert_eq!(revisions(&waiting), revisions(&after));
    }

    #[test]
    fn a_page_under_a_source_the_map_names_is_left_to_its_revisions() {
        let map = map();
        let tail = &map.shards[1];
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
        let first = pass(&mut adapter, &map);
        adapter.acknowledge_applied(&first).unwrap();
        // The wallet holds a page under the tail's first revision, and the
        // companion covers the tail's successor over the page's range.
        let mut holding = watch();
        holding.pending_pages = vec![PendingPage {
            request: PageRequest {
                page: vec![1],
                addresses: vec![holding.addresses[0].address],
                from: block(tail.start_height).unwrap(),
                through: block(tail.end_height).unwrap(),
            },
            revision: first.commits[1].revision.clone(),
            target: holding.target.unwrap(),
        }];
        let successor = republished(&map, 1, 1, "5a".repeat(32));
        retrieve_tail(&mut adapter, &successor);
        // Qualifying the successor withdraws that page in the wallet, which
        // would refuse a completion under the superseded revision.
        let batch = adapter
            .normalize(
                &holding,
                successor.clone(),
                MORE,
                &StaticChain::from_map(&successor),
            )
            .unwrap();
        assert_eq!(batch.state, BatchState::Ready);
        assert_eq!(batch.commits.len(), 2);
        assert_eq!(batch.commits[1].revision.lineage, 2);
        assert!(
            batch
                .commits
                .iter()
                .all(|commit| commit.completed_pages.is_empty())
        );
    }

    #[test]
    fn a_reset_store_that_stops_before_binding_is_pending() {
        let map = map();
        let t = map.shards.last().unwrap().end_height;
        let resealed = resealing(&map, 1);
        // The wallet's target is above the resealed map's end, and its chain
        // holds another block at that end, so the pass cannot clamp and the
        // reference client stops before binding the store.
        let mut watch = watch();
        let target = ChainPoint {
            height: block(t + 10).unwrap(),
            hash: BlockHash([9; 32]),
        };
        watch.target = Some(target);
        let mut chain = StaticChain::from_map(&resealed);
        chain.hashes.insert(t + 10, target.hash.to_string());
        chain.hashes.insert(t, "aa".repeat(32));
        let behind = |adapter: &mut ReferenceRecovery| {
            let mut filters = CountingFilters::serving(serde_json::to_vec(&resealed).unwrap());
            let mut shards = CountingShards::serving(SCHEMA);
            let batch = adapter
                .recover(&watch, &chain, &mut filters, &mut shards)
                .unwrap();
            assert_eq!((filters.filters, shards.calls()), (0, 1));
            assert_eq!(batch.progress.outcome, Outcome::Behind);
            assert!(batch.commits.is_empty());
            assert_eq!(adapter.store.set_identity().unwrap(), None);
            batch
        };

        // A fresh companion has exported nothing, so nothing can disagree.
        let dir = tempfile::tempdir().unwrap();
        let mut fresh = ReferenceRecovery::open(dir.path().join("fresh.sqlite"), config()).unwrap();
        assert_eq!(behind(&mut fresh).state, BatchState::Ready);

        // A reset companion still holds exported revisions the pass never
        // checked against the publication.
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
        let first = pass(&mut adapter, &map);
        adapter.acknowledge_applied(&first).unwrap();
        publication_change(&mut adapter, &resealed);
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1)]);
        let batch = behind(&mut adapter);
        assert_eq!(batch.state, BatchState::Pending);
        assert!(adapter.acknowledge_applied(&batch).is_err());
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1)]);
    }

    #[test]
    fn a_revision_exported_before_a_reset_is_held_back_while_it_reopens_a_page() {
        let map = map();
        let (sealed, tail) = (&map.shards[0], &map.shards[1]);
        let resealed = resealing(&map, 1);
        let address = watch().addresses[0].address;
        let script = address_script(address);
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
        let first = pass(&mut adapter, &map);
        adapter.acknowledge_applied(&first).unwrap();
        let (sealed_revision, old_tail) = (&first.commits[0].revision, &first.commits[1].revision);

        // After the reset the store retrieves again. It covers the new tail,
        // but a budget-limited pass left page work on the sealed shard, whose
        // source is unchanged and which the wallet already covers.
        publication_change(&mut adapter, &resealed);
        adapter.store.bind_set(&SetIdentity::of(&resealed)).unwrap();
        adapter
            .store
            .add_scripts(&[ScriptEntry {
                script: script.clone(),
                origin: ScriptOrigin::Imported,
                required_from: map.start_height,
            }])
            .unwrap();
        let sealed_end = (sealed.end_height, sealed.terminal_block_hash.as_str());
        let mut open = covered(sealed, &sealed.manifest_digest, sealed_end, &script, vec![]);
        open.covered_scripts.clear();
        open.pending_upsert = vec![store_page(sealed, &script, 3)];
        adapter.store.commit_shard(open).unwrap();
        let end = (tail.end_height, tail.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(
                &resealed.shards[1],
                &tail.manifest_digest,
                end,
                &script,
                vec![],
            ))
            .unwrap();
        let chain = StaticChain::from_map(&resealed);
        // The wallet would refuse that page over its own coverage, so the
        // sealed shard's revision is held back; the new tail is exported.
        let batch = pass(&mut adapter, &resealed);
        assert_eq!(batch.state, BatchState::Ready);
        assert_eq!(batch.commits.len(), 1);
        let new_tail = &batch.commits[0].revision;
        assert!(new_tail.source != sealed_revision.source && new_tail.source != old_tail.source);
        assert!(batch.commits[0].opened_pages.is_empty());
        adapter.acknowledge_applied(&batch).unwrap();

        // A page the wallet holds for that revision is replayed instead.
        let mut holding = watch();
        holding.pending_pages = vec![PendingPage {
            request: PageRequest {
                page: page_id(sealed.shard_id, &sealed.manifest_digest, &script, 3),
                addresses: vec![address],
                from: block(sealed.start_height).unwrap(),
                through: block(sealed.end_height).unwrap(),
            },
            revision: sealed_revision.clone(),
            target: holding.target.unwrap(),
        }];
        let replayed = adapter
            .normalize(&holding, resealed.clone(), MORE, &chain)
            .unwrap();
        assert_eq!(replayed.state, BatchState::Ready);
        assert_eq!(&replayed.commits[0].revision, sealed_revision);
        assert_eq!(
            replayed.commits[0].opened_pages,
            vec![holding.pending_pages[0].request.clone()]
        );

        // Once the page work is done, the revision is exported again with its
        // coverage.
        let pending = adapter.store.pending().unwrap();
        let mut done = covered(sealed, &sealed.manifest_digest, sealed_end, &script, vec![]);
        done.pending_complete = vec![pending[0].id.unwrap()];
        adapter.store.commit_shard(done).unwrap();
        let batch = pass(&mut adapter, &resealed);
        assert_eq!(batch.state, BatchState::Ready);
        assert_eq!(&batch.commits[0].revision, sealed_revision);
        assert!(batch.commits[0].opened_pages.is_empty());
        assert_eq!(batch.commits[0].coverage, first.commits[0].coverage);
    }

    #[test]
    fn a_map_under_the_previous_set_below_the_anchor_does_not_reset_the_store() {
        let map = map();
        let tail = &map.shards[1];
        let t = tail.end_height;
        let resealed = resealing(&map, 1);
        // A companion bound to the new set, synced through the tail's end.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &resealed);
        let anchor = Anchor {
            height: t,
            hash: tail.terminal_block_hash.clone(),
        };
        adapter.store.commit_anchor(&anchor, t, t).unwrap();
        let first = pass(&mut adapter, &resealed);
        adapter.acknowledge_applied(&first).unwrap();
        let held = store_rows(&adapter);
        let catalog = (cataloged(&adapter), exported(&adapter));

        // A replica that has not caught up still serves the previous set and
        // ends below the anchor: the pass waits, keeping store and catalog.
        let mut lagging = map.clone();
        lagging.shards.pop();
        let mut filters = CountingFilters::serving(serde_json::to_vec(&lagging).unwrap());
        let mut shards = CountingShards::serving(SCHEMA);
        let batch = adapter
            .recover(
                &watch(),
                &StaticChain::from_map(&resealed),
                &mut filters,
                &mut shards,
            )
            .unwrap();
        assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 1));
        assert_eq!(batch.state, BatchState::Pending);
        assert_eq!(
            batch.progress,
            Progress {
                covered_through: 0,
                outcome: Outcome::Behind,
            }
        );
        assert!(batch.commits.is_empty());
        assert_eq!(
            adapter.store.set_identity().unwrap(),
            Some(SetIdentity::of_schema(&resealed, SCHEMA))
        );
        assert_eq!(store_rows(&adapter), held);
        assert_eq!((cataloged(&adapter), exported(&adapter)), catalog);

        // Once the wallet's chain no longer holds the anchor, as after a reorg,
        // the same map is a publication change.
        let mut watch = watch();
        let target = ChainPoint {
            height: block(t + 10).unwrap(),
            hash: BlockHash([9; 32]),
        };
        watch.target = Some(target);
        let mut reorged = StaticChain::from_map(&resealed);
        reorged.hashes.insert(t + 10, target.hash.to_string());
        reorged.hashes.insert(t, "aa".repeat(32));
        let mut filters = CountingFilters::serving(serde_json::to_vec(&lagging).unwrap());
        let mut shards = CountingShards::serving(SCHEMA);
        assert!(matches!(
            adapter.recover(&watch, &reorged, &mut filters, &mut shards),
            Err(RecoveryError::PublicationChanged)
        ));
        assert_eq!(adapter.store.set_identity().unwrap(), None);

        // So is a map under the previous set that reaches the anchor.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &resealed);
        adapter.store.commit_anchor(&anchor, t, t).unwrap();
        publication_change(&mut adapter, &map);
    }

    #[test]
    fn exported_rows_are_classified_by_the_first_matching_rule() {
        let base = map();
        let mut sealed = republished(&base, 1, 1, "5e".repeat(32));
        sealed.shards[1].sealed = true;

        // A sealed shard published under another source is retired, not changed.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
        let first = pass(&mut adapter, &base);
        adapter.acknowledge_applied(&first).unwrap();
        let mut moved = base.clone();
        moved.shards[0].geometry = base.shards[1].geometry.clone();
        let batch = pass(&mut adapter, &moved);
        assert_eq!(batch.state, BatchState::Withdrawn(WithdrawnCause::Retired));

        // A sealed shard beyond the map's last shard is pending, not changed.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &sealed);
        let first = pass(&mut adapter, &sealed);
        adapter.acknowledge_applied(&first).unwrap();
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 2)]);
        let mut behind = sealed.clone();
        behind.shards.pop();
        let batch = pass(&mut adapter, &behind);
        assert_eq!(batch.state, BatchState::Pending);

        // A changed sealed shard is withdrawn even when this batch commits its
        // source at a higher lineage, which would replace an unsealed one.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
        let first = pass(&mut adapter, &base);
        adapter.acknowledge_applied(&first).unwrap();
        let changed = republished(&base, 0, 1, "c1".repeat(32));
        adapter
            .store
            .rollback_above(
                &Anchor {
                    height: base.start_height - 1,
                    hash: base.shards[0].parent_block_hash.clone(),
                },
                "changed sealed shard",
            )
            .unwrap();
        cover(&mut adapter, &changed);
        let batch = pass(&mut adapter, &changed);
        assert_eq!(
            batch.state,
            BatchState::Withdrawn(WithdrawnCause::ChangedSealed)
        );
        assert!(batch.commits.is_empty());
        // The same row, settled against a commit of its source at a higher lineage.
        let set = SetIdentity::of_schema(&changed, SCHEMA);
        let published: Vec<_> = changed
            .shards
            .iter()
            .map(|entry| Published::of(&adapter.binding, &set, entry).unwrap())
            .collect();
        assert_eq!(published[0].revision.source, revisions(&first)[0].source);
        let committed = BTreeMap::from([(published[0].revision.source.as_slice(), 2)]);
        let mut settling = catalog::Pass::begin(&mut adapter.catalog, &published, &[]).unwrap();
        assert!(settling.settle(&published, &committed).unwrap().is_empty());
        assert_eq!(
            settling.state(),
            BatchState::Withdrawn(WithdrawnCause::ChangedSealed)
        );
        drop(settling);

        // Rows whose source the map no longer publishes are matched by height.
        // The publisher sealed part of the tail and started a new one above
        // it, and the companion exported both.
        let tail = &base.shards[1];
        let cut_at = tail.start_height + 250;
        let mut cut = base.clone();
        cut.shards[1].sealed = true;
        cut.shards[1].revision = 1;
        cut.shards[1].end_height = cut_at - 1;
        cut.shards[1].terminal_block_hash = "c7".repeat(32);
        cut.shards[1].manifest_digest = "c1".repeat(32);
        cut.shards.push(ShardMapEntry {
            shard_id: 2,
            start_height: cut_at,
            parent_block_hash: "c7".repeat(32),
            manifest_digest: "c2".repeat(32),
            ..tail.clone()
        });
        cut.check_shape().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &cut);
        let first = pass(&mut adapter, &cut);
        assert_eq!(first.state, BatchState::Ready);
        adapter.acknowledge_applied(&first).unwrap();
        let settled = |adapter: &mut ReferenceRecovery, map: &ShardMap| {
            let set = SetIdentity::of_schema(map, SCHEMA);
            let published: Vec<_> = map
                .shards
                .iter()
                .map(|entry| Published::of(&adapter.binding, &set, entry).unwrap())
                .collect();
            let mut settling = catalog::Pass::begin(&mut adapter.catalog, &published, &[]).unwrap();
            settling.settle(&published, &BTreeMap::new()).unwrap();
            settling.state()
        };
        // A replica still serving the tail uncut is behind: below the cut its
        // source is published unsealed at a lower lineage, and above it the
        // new tail's start lies inside that unsealed tail.
        assert_eq!(settled(&mut adapter, &base), BatchState::Pending);
        // The same heights inside a sealed shard under another geometry, which
        // no re-cut declared, are retired.
        let mut merged = base.clone();
        merged.shards[1].geometry = base.shards[0].geometry.clone();
        merged.shards[1].sealed = true;
        merged.shards[1].manifest_digest = "d1".repeat(32);
        assert_eq!(
            settled(&mut adapter, &merged),
            BatchState::Withdrawn(WithdrawnCause::Retired)
        );
    }

    #[test]
    fn retired_revisions_are_pruned_after_acknowledgment() {
        let mut map = map();
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
        let first = pass(&mut adapter, &map);
        adapter.acknowledge_applied(&first).unwrap();
        for revision in 1..=50u32 {
            map = republished(&map, 1, revision, format!("{revision:064x}"));
            retrieve_tail(&mut adapter, &map);
            let batch = pass(&mut adapter, &map);
            assert_eq!(batch.state, BatchState::Ready);
            assert_eq!(revisions(&batch)[1].lineage, u64::from(revision) + 1);
            assert_eq!(batch.retired_revisions().len(), 1);
            adapter.acknowledge_reconciled(&batch).unwrap();
            assert!(cataloged(&adapter) <= map.shards.len() as u64 + 2);
        }
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 51)]);
        assert_eq!(cataloged(&adapter), 2);
    }

    #[test]
    fn store_caches_keep_only_named_revisions() {
        let map = map();
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
        let retired = "0d".repeat(32);
        let setup = |digest: &str| SetupKey {
            set_digest: "set".into(),
            revision_digest: digest.into(),
            table: Table::Directory,
            segment: 0,
        };
        let named: Vec<&str> = map
            .shards
            .iter()
            .map(|entry| entry.manifest_digest.as_str())
            .collect();
        for digest in named.iter().copied().chain([retired.as_str()]) {
            adapter
                .store
                .put_filter(digest, "ff", false, b"filter")
                .unwrap();
            adapter
                .store
                .put_setup(
                    &setup(digest),
                    &SetupBlob {
                        public_params_base64: "AA==".into(),
                        public_params_sha256: "00".into(),
                    },
                )
                .unwrap();
        }
        let last = adapter.store.last_commit().unwrap();
        assert!(last > 1);
        assert_eq!(pass(&mut adapter, &map).state, BatchState::Ready);
        // Only revisions the map names keep their cached filters and setup.
        for digest in named {
            assert!(adapter.store.filter(digest, "ff").unwrap().is_some());
            assert!(adapter.store.setup(&setup(digest)).unwrap().is_some());
        }
        assert!(adapter.store.filter(&retired, "ff").unwrap().is_none());
        assert!(adapter.store.setup(&setup(&retired)).unwrap().is_none());
        // The commit log keeps only its last entry, the one the store reads.
        let commits: u64 = adapter
            .catalog
            .query_row("SELECT COUNT(*) FROM commits", [], |r| r.get(0))
            .unwrap();
        assert_eq!(commits, 1);
        assert_eq!(adapter.store.last_commit().unwrap(), last);
    }

    #[test]
    fn a_version_one_companion_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("companion.sqlite");
        let config = config();
        // A v1 companion: a binding with no format, beside the per-companion
        // revision table.
        drop(SqliteStore::open(&path).unwrap());
        let v1 = Connection::open(&path).unwrap();
        v1.execute_batch(
            "CREATE TABLE pir_bridge_binding (key TEXT PRIMARY KEY, value BLOB NOT NULL);
             CREATE TABLE pir_bridge_revisions (source BLOB NOT NULL);",
        )
        .unwrap();
        v1.execute(
            "INSERT INTO pir_bridge_binding VALUES ('account-source', ?1)",
            [catalog::binding([
                &config.source,
                &config.account_binding,
                config.origin.as_bytes(),
                SCHEMA.as_bytes(),
            ])
            .to_vec()],
        )
        .unwrap();
        let refused = |path: &Path| {
            matches!(
                ReferenceRecovery::open(path, config.clone()),
                Err(RecoveryError::Invalid(message)) if message == "companion format v1; recreate"
            )
        };
        assert!(refused(&path));
        // Either mark alone identifies the old format.
        v1.execute_batch("DROP TABLE pir_bridge_revisions").unwrap();
        assert!(refused(&path));
        v1.execute_batch(
            "INSERT INTO pir_bridge_binding VALUES ('format', 'transparent-reference-companion-v2');
             CREATE TABLE pir_bridge_revisions (source BLOB NOT NULL);",
        )
        .unwrap();
        assert!(refused(&path));
        // A recreated companion opens, records its format, and reopens.
        let fresh = dir.path().join("recreated.sqlite");
        drop(ReferenceRecovery::open(&fresh, config.clone()).unwrap());
        let format: String = Connection::open(&fresh)
            .unwrap()
            .query_row(
                "SELECT value FROM pir_bridge_binding WHERE key='format'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(format, "transparent-reference-companion-v3");
        ReferenceRecovery::open(&fresh, config).unwrap();
    }

    #[test]
    fn a_replaced_tail_is_ready_when_its_successor_is_exported() {
        let map = map();
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
        let first = pass(&mut adapter, &map);
        adapter.acknowledge_applied(&first).unwrap();
        let predecessor = revisions(&first)[1].clone();
        let successor = republished(&map, 1, 1, "5a".repeat(32));
        retrieve_tail(&mut adapter, &successor);
        let batch = pass(&mut adapter, &successor);
        assert_eq!(batch.state, BatchState::Ready);
        let replacing = &revisions(&batch)[1];
        assert_eq!(replacing.source, predecessor.source);
        assert_eq!(replacing.lineage, predecessor.lineage + 1);
        assert_eq!(
            batch.retired_revisions(),
            std::slice::from_ref(&predecessor)
        );
        // The predecessor stays recorded as exported until the wallet acknowledges
        // reconciling it, and is forgotten then, whatever the caller did to the
        // batch's commits.
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1), (TAIL, 2)]);
        let mut batch = batch;
        batch.commits.extend(first.commits.iter().cloned());
        assert!(adapter.acknowledge_applied(&batch).is_err());
        adapter.acknowledge_reconciled(&batch).unwrap();
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 2)]);
        assert_eq!(cataloged(&adapter), 2);
    }

    #[test]
    fn a_replaced_tail_without_a_retrieved_successor_is_pending() {
        let map = map();
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
        let first = pass(&mut adapter, &map);
        adapter.acknowledge_applied(&first).unwrap();
        let successor = republished(&map, 1, 1, "5a".repeat(32));
        withdraw_tail(&mut adapter, &successor);
        let batch = pass(&mut adapter, &successor);
        assert_eq!(batch.state, BatchState::Pending);
        assert!(batch.commits.is_empty());
        assert!(adapter.acknowledge_applied(&batch).is_err());
        // The successor is recorded, but the predecessor is still the export.
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1)]);
        assert_eq!(cataloged(&adapter), 3);
    }

    #[test]
    fn a_ready_batch_lists_exactly_the_retirements_its_commits_resolve() {
        let base = map();
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
        let first = pass(&mut adapter, &base);
        assert_eq!(first.state, BatchState::Ready);
        assert!(first.retired_revisions().is_empty());
        adapter.acknowledge_applied(&first).unwrap();
        let original = first.commits[1].revision.clone();

        // The tail is republished, and the batch exporting it is never
        // acknowledged.
        let next = republished(&base, 1, 1, "b1".repeat(32));
        retrieve_tail(&mut adapter, &next);
        let unacknowledged = pass(&mut adapter, &next);
        assert_eq!(unacknowledged.state, BatchState::Ready);
        let intermediate = unacknowledged.commits[1].revision.clone();

        // It is republished again, skipping revision numbers. Until the
        // successor is retrieved, the batch lists and exports nothing.
        let last = republished(&base, 1, 4, "b4".repeat(32));
        withdraw_tail(&mut adapter, &last);
        let pending = pass(&mut adapter, &last);
        assert_eq!(pending.state, BatchState::Pending);
        assert!(pending.commits.is_empty());
        assert!(pending.retired_revisions().is_empty());

        // Retrieved, the successor resolves both earlier tails, listed exactly
        // as the wallet holds them; the still published sealed shard is not.
        retrieve_tail(&mut adapter, &last);
        let batch = pass(&mut adapter, &last);
        assert_eq!(batch.state, BatchState::Ready);
        let successor = &batch.commits[1].revision;
        assert_eq!(successor.source, original.source);
        assert_eq!(successor.lineage, 5);
        let mut listed = batch.retired_revisions().to_vec();
        listed.sort_by_key(|revision| revision.lineage);
        assert_eq!(listed, vec![original, intermediate]);
        assert!(
            !batch
                .retired_revisions()
                .contains(&first.commits[0].revision)
        );

        // Ordinary acknowledgment refuses it and records nothing; the reconciled
        // one forgets the earlier tails.
        let recorded = catalog_rows(&adapter);
        assert!(matches!(
            adapter.acknowledge_applied(&batch),
            Err(RecoveryError::Invalid(_))
        ));
        assert_eq!(catalog_rows(&adapter), recorded);
        adapter.acknowledge_reconciled(&batch).unwrap();
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 5)]);

        // The next batch resolves nothing, and ordinary acknowledgment applies.
        let after = pass(&mut adapter, &last);
        assert_eq!(after.state, BatchState::Ready);
        assert_eq!(after.commits, batch.commits);
        assert!(after.retired_revisions().is_empty());
        adapter.acknowledge_applied(&after).unwrap();
    }

    #[test]
    fn pending_and_withdrawn_batches_list_nothing_and_refuse_both_acknowledgments() {
        let base = map();
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
        let first = pass(&mut adapter, &base);
        adapter.acknowledge_applied(&first).unwrap();
        let refused = |adapter: &mut ReferenceRecovery, batch: &RecoveryBatch<u32>| {
            assert!(batch.commits.is_empty());
            assert!(batch.retired_revisions().is_empty());
            let recorded = catalog_rows(adapter);
            assert!(adapter.acknowledge_applied(batch).is_err());
            assert!(adapter.acknowledge_reconciled(batch).is_err());
            assert_eq!(catalog_rows(adapter), recorded);
        };

        // The tail is republished, and its successor is not retrieved yet.
        let replaced = republished(&base, 1, 1, "5a".repeat(32));
        withdraw_tail(&mut adapter, &replaced);
        let pending = pass(&mut adapter, &replaced);
        assert_eq!(pending.state, BatchState::Pending);
        refused(&mut adapter, &pending);

        // Retrieved, the successor would resolve the old tail, but the sealed
        // shard equivocates.
        retrieve_tail(&mut adapter, &replaced);
        let equivocating = republished(&replaced, 0, 0, "e0".repeat(32));
        let withdrawn = pass(&mut adapter, &equivocating);
        assert_eq!(
            withdrawn.state,
            BatchState::Withdrawn(WithdrawnCause::Equivocation)
        );
        refused(&mut adapter, &withdrawn);

        // Neither forgot the old tail: without the equivocation it is listed.
        let ready = pass(&mut adapter, &replaced);
        assert_eq!(ready.state, BatchState::Ready);
        assert_eq!(
            ready.retired_revisions(),
            std::slice::from_ref(&first.commits[1].revision)
        );
    }

    #[test]
    fn retired_revisions_survive_until_reconciled_and_replay_identically() {
        let mut map = map();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("companion.sqlite");
        let mut adapter = covering(&path, &map);
        let first = pass(&mut adapter, &map);
        adapter.acknowledge_applied(&first).unwrap();
        let original = first.commits[1].revision.clone();
        map = republished(&map, 1, 1, "5a".repeat(32));
        retrieve_tail(&mut adapter, &map);
        let ready = pass(&mut adapter, &map);
        assert_eq!(ready.retired_revisions(), std::slice::from_ref(&original));
        let recorded = catalog_rows(&adapter);

        // Replaying the pass, before or after a crash, returns the same batch,
        // notifications and receipt, and records nothing new.
        let replayed = pass(&mut adapter, &map);
        drop(adapter);
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        let reopened = pass(&mut adapter, &map);
        for batch in [&replayed, &reopened] {
            assert_eq!(batch.state, BatchState::Ready);
            assert_eq!(batch.commits, ready.commits);
            assert_eq!(batch.retired_revisions(), ready.retired_revisions());
            assert_eq!(batch.token, ready.token);
        }
        assert_eq!(catalog_rows(&adapter), recorded);
        // Without trusted reconciliation the batch stays unacknowledged.
        assert!(adapter.acknowledge_applied(&reopened).is_err());
        assert_eq!(catalog_rows(&adapter), recorded);

        // The tail moves again before the wallet reconciled. The newer batch
        // lists both unacknowledged revisions, and the older receipt is stale.
        map = republished(&map, 1, 2, "5b".repeat(32));
        retrieve_tail(&mut adapter, &map);
        let newer = pass(&mut adapter, &map);
        assert_eq!(newer.state, BatchState::Ready);
        let mut lineages: Vec<_> = newer
            .retired_revisions()
            .iter()
            .map(|revision| revision.lineage)
            .collect();
        lineages.sort_unstable();
        assert_eq!(lineages, vec![1, 2]);
        assert!(newer.retired_revisions().contains(&original));
        assert!(adapter.acknowledge_reconciled(&reopened).is_err());
        adapter.acknowledge_reconciled(&newer).unwrap();
        // A receipt is acknowledged once.
        assert!(adapter.acknowledge_reconciled(&newer).is_err());
        assert!(adapter.acknowledge_applied(&newer).is_err());
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 3)]);

        // Once reconciled, replay lists nothing and is idempotent.
        let settled = pass(&mut adapter, &map);
        let recorded = catalog_rows(&adapter);
        let again = pass(&mut adapter, &map);
        assert_eq!(settled.commits, newer.commits);
        assert!(settled.retired_revisions().is_empty());
        assert!(again.retired_revisions().is_empty());
        assert_eq!(again.token, settled.token);
        assert_eq!(catalog_rows(&adapter), recorded);
        adapter.acknowledge_applied(&again).unwrap();
        // A batch without retirements may also be acknowledged as reconciled.
        let last = pass(&mut adapter, &map);
        adapter.acknowledge_reconciled(&last).unwrap();
    }

    #[test]
    fn a_publication_change_forgets_retirements_of_sources_it_drops() {
        let base = map();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("companion.sqlite");
        let mut adapter = covering(&path, &base);
        let first = pass(&mut adapter, &base);
        adapter.acknowledge_applied(&first).unwrap();
        let next = republished(&base, 1, 1, "5a".repeat(32));
        retrieve_tail(&mut adapter, &next);
        let listed = pass(&mut adapter, &next);
        assert_eq!(listed.state, BatchState::Ready);
        assert_eq!(
            listed.retired_revisions(),
            std::slice::from_ref(&first.commits[1].revision)
        );
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1), (TAIL, 2)]);

        // The wallet crashes before reconciling, and the tail's geometry is
        // resealed. The reset forgets the listed retirement unacknowledged: no
        // successor under the dropped source can resolve it.
        drop(adapter);
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        let resealed = resealing(&next, 1);
        publication_change(&mut adapter, &resealed);
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1)]);
        assert_eq!(cataloged(&adapter), 3);

        // No later batch lists it, and ordinary acknowledgment applies.
        cover(&mut adapter, &resealed);
        let retried = pass(&mut adapter, &resealed);
        assert_eq!(retried.state, BatchState::Ready);
        assert!(retried.retired_revisions().is_empty());
        assert_ne!(
            retried.commits[1].revision.source,
            listed.commits[1].revision.source
        );
        adapter.acknowledge_applied(&retried).unwrap();
        assert!(pass(&mut adapter, &resealed).retired_revisions().is_empty());
    }

    #[test]
    fn stale_store_facts_drop_their_shard_instead_of_failing() {
        let map = map();
        let (sealed, tail) = (&map.shards[0], &map.shards[1]);
        let script = address_script(watch().addresses[0].address);
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = seeded(&dir, &script, map.start_height);
        // Coverage and a receive on each shard, and an open page on the tail.
        let receive = |entry: &ShardMapEntry, txid| {
            TransparentEvent::Receive(transparent_events::ReceiveEvent {
                metadata: None,
                height: entry.start_height as u32,
                txid: transparent_events::Txid([txid; 32]),
                transaction_index: 1,
                output_index: 0,
                value: 100,
                coinbase: false,
            })
        };
        let end = (sealed.end_height, sealed.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(
                sealed,
                &sealed.manifest_digest,
                end,
                &script,
                vec![receive(sealed, 1)],
            ))
            .unwrap();
        let end = (tail.end_height, tail.terminal_block_hash.as_str());
        let mut open = covered(
            tail,
            &tail.manifest_digest,
            end,
            &script,
            vec![receive(tail, 2)],
        );
        open.pending_upsert = vec![PendingPages {
            id: None,
            shard_id: tail.shard_id,
            revision_digest: tail.manifest_digest.clone(),
            script: script.clone(),
            first_page: 3,
            page_count: 0,
            inline: vec![],
            next_ordinal: 0,
            attempts: 0,
            validated_events: 0,
            boundary: None,
            target_anchor: None,
        }];
        adapter.store.commit_shard(open).unwrap();
        let first = pass(&mut adapter, &map);
        assert_eq!(first.state, BatchState::Ready);
        assert_eq!(first.commits[1].opened_pages.len(), 1);
        adapter.acknowledge_applied(&first).unwrap();

        // The tail is replaced before the companion retrieves it again, and then
        // withdrawn from the map altogether: every tail fact is stale.
        let replaced = republished(&map, 1, 1, "5a".repeat(32));
        let mut behind = map.clone();
        behind.shards.pop();
        for map in [&replaced, &behind] {
            let batch = pass(&mut adapter, map);
            assert_eq!(batch.state, BatchState::Pending);
            assert!(batch.commits.is_empty());
            assert!(adapter.acknowledge_applied(&batch).is_err());
        }
        // Facts are placed by the revision they were read under: a published
        // one finds its commit, a stale one defers the batch, and so does a
        // published one naming another shard id.
        let set = SetIdentity::of_schema(&replaced, SCHEMA);
        let published: Vec<_> = replaced
            .shards
            .iter()
            .map(|entry| Published::of(&adapter.binding, &set, entry).unwrap())
            .collect();
        let chain = StaticChain::from_map(&replaced);
        let mut facts = Facts::new(&published, &[], None, watch().context().unwrap());
        facts.open(&published[0], first.commits[0].anchor);
        let mut stale = catalog::Pass::begin(&mut adapter.catalog, &published, &[]).unwrap();
        let range = (sealed.start_height, sealed.end_height);
        let placed = facts
            .place(&mut stale, &chain, 0, &sealed.manifest_digest, range)
            .unwrap();
        assert_eq!(
            placed.map(|commit| &commit.revision),
            Some(&published[0].revision)
        );
        assert_eq!(stale.state(), BatchState::Ready);
        let range = (tail.start_height, tail.end_height);
        assert!(
            facts
                .place(&mut stale, &chain, 1, &tail.manifest_digest, range)
                .unwrap()
                .is_none()
        );
        assert_eq!(stale.state(), BatchState::Pending);
        drop(stale);
        let mut renamed = catalog::Pass::begin(&mut adapter.catalog, &published, &[]).unwrap();
        let range = (sealed.start_height, sealed.end_height);
        assert!(
            facts
                .place(&mut renamed, &chain, 1, &sealed.manifest_digest, range)
                .unwrap()
                .is_none()
        );
        assert_eq!(renamed.state(), BatchState::Pending);
        drop(renamed);

        // Retrieving the replacement repairs the companion.
        retrieve_tail(&mut adapter, &replaced);
        assert_eq!(pass(&mut adapter, &replaced).state, BatchState::Ready);
    }

    /// A filter source that serves `maps` in turn and then repeats the last, and
    /// answers every filter request with bytes no map names, which the client
    /// reads as a revision withdrawn mid-sync.
    struct Republishing {
        maps: Vec<Vec<u8>>,
        served: usize,
        filters: usize,
    }
    impl FilterSource for Republishing {
        fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
            let map = self.maps[self.served.min(self.maps.len() - 1)].clone();
            self.served += 1;
            let cost = map.len() as u64;
            Ok((map, cost))
        }
        fn filter(&mut self, _shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
            self.filters += 1;
            Ok((b"withdrawn".to_vec(), 9))
        }
    }

    #[test]
    fn a_publication_diverging_from_the_sync_is_pending_and_keeps_the_companion() {
        let first = map();
        let behind_by_divergence = Progress {
            covered_through: 0,
            outcome: Outcome::Behind,
        };
        let script = address_script(watch().addresses[0].address);
        // A companion that exported the sealed shard; the tail is still to retrieve.
        let companion = |dir: &tempfile::TempDir| {
            let mut adapter = seeded(dir, &script, first.start_height);
            let sealed = &first.shards[0];
            let end = (sealed.end_height, sealed.terminal_block_hash.as_str());
            adapter
                .store
                .commit_shard(covered(
                    sealed,
                    &sealed.manifest_digest,
                    end,
                    &script,
                    vec![],
                ))
                .unwrap();
            let batch = pass(&mut adapter, &first);
            assert_eq!(batch.commits.len(), 1);
            adapter.acknowledge_applied(&batch).unwrap();
            adapter
        };
        // Reading the tail's withdrawn revision makes the sync refresh to `then`.
        let refreshing = |adapter: &mut ReferenceRecovery, then: &ShardMap| {
            let mut filters = Republishing {
                maps: [&first, then]
                    .map(|map| serde_json::to_vec(map).unwrap())
                    .to_vec(),
                served: 0,
                filters: 0,
            };
            let mut shards = CountingShards::serving(SCHEMA);
            let batch = adapter
                .recover(
                    &watch(),
                    &StaticChain::from_map(&first),
                    &mut filters,
                    &mut shards,
                )
                .unwrap();
            assert_eq!((filters.served, filters.filters), (2, 1));
            batch
        };

        // The refreshed map republishes the covered sealed shard with other
        // content under the same revision. The kept catalog sees the
        // equivocation a recreated one could not, and recovers if the
        // publisher reverts.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = companion(&dir);
        let equivocating = republished(&first, 0, 0, "e0".repeat(32));
        let batch = refreshing(&mut adapter, &equivocating);
        assert_eq!(batch.state, BatchState::Pending);
        assert_eq!(batch.progress, behind_by_divergence);
        assert!(batch.commits.is_empty());
        assert!(adapter.acknowledge_applied(&batch).is_err());
        assert_eq!(
            pass(&mut adapter, &equivocating).state,
            BatchState::Withdrawn(WithdrawnCause::Equivocation)
        );
        assert_eq!(pass(&mut adapter, &first).state, BatchState::Ready);

        // A refreshed map under another set identity leaves the store bound to
        // the first; the next pass, starting from it, resets the store.
        let mut resealed = first.clone();
        resealed
            .seal
            .get_mut(&first.shards[1].geometry)
            .unwrap()
            .max_scripts += 1;
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = companion(&dir);
        let batch = refreshing(&mut adapter, &resealed);
        assert_eq!(batch.state, BatchState::Pending);
        assert_eq!(batch.progress, behind_by_divergence);
        assert_eq!(
            adapter.store.set_identity().unwrap(),
            Some(SetIdentity::of_schema(&first, SCHEMA))
        );
        publication_change(&mut adapter, &resealed);
        assert_eq!(cataloged(&adapter), 2);

        // A budget-limited pass left a pending page on the tail, and a lagging
        // replica's map no longer has it. The pass clamps to that map's end,
        // and the sync drops the page work, which saved nothing, rather than
        // diverging: a later map that publishes the tail reads it again. The
        // batch covers what that map publishes and keeps the catalog.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = companion(&dir);
        let tail = &first.shards[1];
        let end = (tail.end_height, tail.terminal_block_hash.as_str());
        let mut open = covered(tail, &tail.manifest_digest, end, &script, vec![]);
        open.covered_scripts.clear();
        open.pending_upsert = vec![PendingPages {
            id: None,
            shard_id: tail.shard_id,
            revision_digest: tail.manifest_digest.clone(),
            script: script.clone(),
            first_page: 0,
            page_count: 0,
            inline: vec![],
            next_ordinal: 0,
            attempts: 0,
            validated_events: 0,
            boundary: None,
            target_anchor: None,
        }];
        adapter.store.commit_shard(open).unwrap();
        let catalog = (cataloged(&adapter), exported(&adapter));
        let mut behind = first.clone();
        behind.shards.pop();
        let mut filters = CountingFilters::serving(serde_json::to_vec(&behind).unwrap());
        let mut shards = CountingShards::serving(SCHEMA);
        let batch = adapter
            .recover(
                &watch(),
                &StaticChain::from_map(&first),
                &mut filters,
                &mut shards,
            )
            .unwrap();
        assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 1));
        assert_eq!(batch.state, BatchState::Ready);
        assert_eq!(
            batch.progress,
            Progress {
                covered_through: first.shards[0].end_height,
                outcome: Outcome::Behind,
            }
        );
        assert_eq!(revisions(&batch).len(), 1);
        assert!(batch.commits[0].opened_pages.is_empty());
        assert!(adapter.store.pending().unwrap().is_empty());
        assert_eq!(
            adapter.store.set_identity().unwrap(),
            Some(SetIdentity::of_schema(&first, SCHEMA))
        );
        assert_eq!((cataloged(&adapter), exported(&adapter)), catalog);
    }

    #[test]
    fn normalization_uses_the_map_the_sync_finished_with() {
        let first = map();
        // The refreshed publication no longer advertises the tail; a later one
        // republishes it.
        let mut refreshed = first.clone();
        refreshed.shards.pop();
        let later = republished(&first, 1, 1, "5a".repeat(32));
        // The companion covers the sealed shard; the tail is still to retrieve.
        let script = address_script(watch().addresses[0].address);
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = seeded(&dir, &script, first.start_height);
        let sealed = &first.shards[0];
        let end = (sealed.end_height, sealed.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(
                sealed,
                &sealed.manifest_digest,
                end,
                &script,
                vec![],
            ))
            .unwrap();
        let mut filters = Republishing {
            maps: [&first, &refreshed, &later]
                .map(|map| serde_json::to_vec(map).unwrap())
                .to_vec(),
            served: 0,
            filters: 0,
        };
        let mut shards = CountingShards::serving(SCHEMA);
        let batch = adapter
            .recover(
                &watch(),
                &StaticChain::from_map(&first),
                &mut filters,
                &mut shards,
            )
            .unwrap();
        // The tail's filter named a withdrawn revision, so the sync refreshed the
        // map once and stopped behind it. Nothing fetched another map.
        assert_eq!((filters.served, filters.filters), (2, 1));
        assert_eq!(batch.progress.outcome, Outcome::Behind);
        // The batch describes the refreshed map: the sealed shard only, with the
        // tail neither cataloged nor exported.
        assert_eq!(batch.state, BatchState::Ready);
        assert_eq!(batch.commits.len(), 1);
        assert_eq!(
            batch.commits[0].anchor.height,
            block(sealed.end_height).unwrap()
        );
        assert_eq!(cataloged(&adapter), 1);
    }

    /// Settlement checks made before any commit applies, against a real SQLite
    /// wallet. Commit application itself is covered end to end in
    /// `tests/private_recovery.rs`.
    #[cfg(feature = "sqlite")]
    mod apply {
        use super::*;
        use crate::apply::{ApplyError, Trust};
        use zcash_client_backend::data_api::testing::{TestBuilder, TestState};
        use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode;
        use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerWrite as _;
        use zcash_client_sqlite::{
            AccountUuid,
            testing::{
                BlockCache,
                db::{TestDb, TestDbFactory},
            },
        };
        use zcash_protocol::local_consensus::LocalNetwork;

        fn wallet() -> TestState<BlockCache, TestDb, LocalNetwork> {
            let mut st = TestBuilder::new()
                .with_data_store_factory(TestDbFactory::default())
                .with_block_cache(BlockCache::new())
                .build();
            let db = st.wallet_mut().db_mut();
            db.apply_transparent_policy(TransparentLedgerMode::PrivateRequired)
                .unwrap();
            db.set_transparent_ledger_mode(TransparentLedgerMode::PrivateRequired);
            st
        }

        fn retired() -> RecoveryRevision {
            RecoveryRevision {
                source: vec![1; 32],
                revision: vec![2; 32],
                lineage: 1,
                sealed: false,
                publication:
                    zcash_client_backend::data_api::transparent_ledger::PublicationAnchor {
                        height: block(1).unwrap(),
                        hash: BlockHash([3; 32]),
                    },
            }
        }

        #[test]
        fn an_empty_ready_batch_is_acknowledged_and_spends_its_receipt() {
            let dir = tempfile::tempdir().unwrap();
            let mut adapter =
                ReferenceRecovery::open(dir.path().join("c.sqlite"), config()).unwrap();
            let mut st = wallet();
            let batch = adapter.ready::<AccountUuid>(vec![], vec![], MORE).unwrap();
            let applied = adapter
                .apply_and_acknowledge(batch, st.wallet_mut().db_mut(), Trust::Observed)
                .unwrap();
            assert_eq!(applied.stats, Default::default());
            assert_eq!(applied.progress, MORE);
            assert_eq!(applied.retired, 0);
            assert_eq!(adapter.pending_export, None);
        }

        #[test]
        fn unready_and_stale_batches_apply_nothing() {
            let dir = tempfile::tempdir().unwrap();
            let mut adapter =
                ReferenceRecovery::open(dir.path().join("c.sqlite"), config()).unwrap();
            let mut st = wallet();
            for state in [
                BatchState::Pending,
                BatchState::Withdrawn(WithdrawnCause::Equivocation),
            ] {
                let failure = adapter
                    .apply_and_acknowledge(
                        unready::<AccountUuid>(state, MORE),
                        st.wallet_mut().db_mut(),
                        Trust::Trusted,
                    )
                    .unwrap_err();
                assert!(matches!(failure.error, ApplyError::NotReady(s) if s == state));
                assert_eq!(failure.stats, Default::default());
            }
            // A batch superseded by a later, different pass is a stale receipt; the later
            // one stays acknowledgeable.
            let earlier = adapter.ready::<AccountUuid>(vec![], vec![], MORE).unwrap();
            let later = adapter
                .ready::<AccountUuid>(vec![], vec![retired()], MORE)
                .unwrap();
            let failure = adapter
                .apply_and_acknowledge(earlier, st.wallet_mut().db_mut(), Trust::Trusted)
                .unwrap_err();
            assert!(matches!(failure.error, ApplyError::StaleReceipt));
            assert!(adapter.is_pending_export(&later));
        }

        #[test]
        fn a_surrounding_transaction_is_refused_before_anything_applies() {
            let dir = tempfile::tempdir().unwrap();
            let mut adapter =
                ReferenceRecovery::open(dir.path().join("c.sqlite"), config()).unwrap();
            let mut st = wallet();
            let batch = adapter
                .ready::<AccountUuid>(vec![], vec![retired()], MORE)
                .unwrap();
            st.wallet().conn().execute_batch("BEGIN").unwrap();
            let failure = adapter
                .apply_and_acknowledge(batch, st.wallet_mut().db_mut(), Trust::Trusted)
                .unwrap_err();
            assert!(matches!(failure.error, ApplyError::OuterTransaction));
            st.wallet().conn().execute_batch("ROLLBACK").unwrap();
            // Nothing was acknowledged: the receipt stands, though the batch is gone.
            assert!(adapter.pending_export.is_some());
        }

        #[test]
        fn observed_trust_refuses_retirements_before_applying() {
            let dir = tempfile::tempdir().unwrap();
            let mut adapter =
                ReferenceRecovery::open(dir.path().join("c.sqlite"), config()).unwrap();
            let mut st = wallet();
            let batch = adapter
                .ready::<AccountUuid>(vec![], vec![retired()], MORE)
                .unwrap();
            let failure = adapter
                .apply_and_acknowledge(batch, st.wallet_mut().db_mut(), Trust::Observed)
                .unwrap_err();
            assert!(matches!(failure.error, ApplyError::Unreconciled));
            assert!(adapter.pending_export.is_some());
            // This synthetic batch exercises the refusal only. A real Ready
            // retirement has a successor commit, so successful trusted
            // reconciliation belongs to the in-process service integration
            // tests in private_recovery.rs, including stale-prefix replay.
        }
    }

    /// The recent geometry the re-cut fixture's sealed shards and tail use.
    const NARROW: &str = "recent-4k";
    /// The geometry the re-cut fixture merges into, standing in for an
    /// archive geometry.
    const WIDE: &str = "recent-8k";

    /// The re-cut fixture's block at `height`: the fixture map's own at its
    /// archive shard's end, a synthetic one elsewhere.
    fn recut_hash(height: u64) -> String {
        let archive = &map().shards[0];
        if height == archive.end_height {
            archive.terminal_block_hash.clone()
        } else {
            format!("{height:064x}")
        }
    }

    /// A map entry over `[start, end]` whose manifest digest is `tag`.
    fn recut_entry(
        shard_id: u64,
        geometry: &str,
        (start, end): (u64, u64),
        (revision, sealed): (u32, bool),
        tag: u64,
    ) -> ShardMapEntry {
        ShardMapEntry {
            shard_id,
            geometry: geometry.into(),
            start_height: start,
            end_height: end,
            parent_block_hash: recut_hash(start - 1),
            terminal_block_hash: recut_hash(end),
            manifest_digest: format!("{tag:064x}"),
            revision,
            sealed,
            ..map().shards[1].clone()
        }
    }

    /// `entry` as a re-cut declares it superseded.
    fn superseded(entry: &ShardMapEntry) -> SupersededShard {
        SupersededShard {
            shard_id: entry.shard_id,
            geometry: entry.geometry.clone(),
            start_height: entry.start_height,
            end_height: entry.end_height,
            terminal_block_hash: entry.terminal_block_hash.clone(),
            manifest_digest: entry.manifest_digest.clone(),
            revision: entry.revision,
            sealed: entry.sealed,
        }
    }

    /// `shards` published under the fixture map's identity, with seal
    /// parameters for both re-cut geometries, declaring `recuts`.
    fn recut_map(shards: Vec<ShardMapEntry>, recuts: Vec<Recut>) -> ShardMap {
        let mut map = map();
        for geometry in [NARROW, WIDE] {
            map.seal.insert(
                geometry.into(),
                SealParameters {
                    max_scripts: 100,
                    max_page_rows: 10,
                    max_txids: 0,
                },
            );
        }
        map.shards = shards;
        map.recuts = recuts;
        map.check_shape().unwrap();
        map
    }

    /// A publication before and after a declared re-cut.
    ///
    /// Before: the fixture's archive shard S0, sealed shards S1–S3 and the tail
    /// T, all [`NARROW`]. After: S0 unchanged, S1–S2 re-cut into one [`WIDE`]
    /// shard W, and S3′ and T′ renumbered at the same heights one revision
    /// higher, declared at epoch 1.
    fn recut_pair() -> (ShardMap, ShardMap) {
        let s0 = map().shards[0].clone();
        let at = s0.end_height + 1;
        let span = |index: u64| (at + 100 * index, at + 100 * index + 99);
        let before = vec![
            s0.clone(),
            recut_entry(1, NARROW, span(0), (0, true), 0x11),
            recut_entry(2, NARROW, span(1), (0, true), 0x12),
            recut_entry(3, NARROW, span(2), (0, true), 0x13),
            recut_entry(4, NARROW, (at + 300, at + 340), (6, false), 0x14),
        ];
        let after = vec![
            s0,
            recut_entry(1, WIDE, (at, at + 199), (0, true), 0x21),
            recut_entry(2, NARROW, span(2), (1, true), 0x23),
            recut_entry(3, NARROW, (at + 300, at + 350), (7, false), 0x24),
        ];
        let recut = Recut {
            epoch: 1,
            from_height: at,
            superseded: before[1..].iter().map(superseded).collect(),
        };
        (recut_map(before, vec![]), recut_map(after, vec![recut]))
    }

    /// The fixture watch set, targeting the end of `map`.
    fn watching(map: &ShardMap) -> TransparentWatchSet<u32> {
        let last = map.shards.last().unwrap();
        TransparentWatchSet {
            target: Some(ChainPoint {
                height: block(last.end_height).unwrap(),
                hash: block_hash(&last.terminal_block_hash).unwrap(),
            }),
            ..watch()
        }
    }

    /// A chain accepting every block either map names.
    fn accepting(maps: &[&ShardMap]) -> StaticChain {
        let mut chain = StaticChain::default();
        for map in maps {
            chain.hashes.extend(StaticChain::from_map(map).hashes);
        }
        chain
    }

    /// A companion at `path` that covered `before` and exported every shard of
    /// it to the wallet, then followed the declared re-cut to `after` as the
    /// sync leaves the store: sealed coverage kept under the revisions it was
    /// read under, the tail retrieved again. Returns the first batch.
    fn recut_companion(
        path: &Path,
        before: &ShardMap,
        after: &ShardMap,
    ) -> (ReferenceRecovery, RecoveryBatch<u32>) {
        let (watch, chain) = (watching(after), accepting(&[before, after]));
        let mut adapter = covering(path, before);
        let first = adapter
            .normalize(&watch, before.clone(), MORE, &chain)
            .unwrap();
        assert_eq!(first.state, BatchState::Ready);
        assert_eq!(first.commits.len(), before.shards.len());
        adapter.acknowledge_applied(&first).unwrap();
        retrieve_tail(&mut adapter, after);
        (adapter, first)
    }

    fn recut_pass(
        adapter: &mut ReferenceRecovery,
        watch: &TransparentWatchSet<u32>,
        map: &ShardMap,
        chain: &StaticChain,
    ) -> RecoveryBatch<u32> {
        adapter.normalize(watch, map.clone(), MORE, chain).unwrap()
    }

    #[test]
    fn a_declared_re_cut_is_ready_and_keeps_the_exported_history() {
        let (before, after) = recut_pair();
        let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
        let dir = tempfile::tempdir().unwrap();
        let (mut adapter, first) =
            recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
        let tail = first.commits[4].revision.clone();

        // The sealed history is exported again exactly as the wallet holds it,
        // anchors and coverage included. W and S3′ hold no stored facts, so
        // nothing is exported under them, and the renumbered tail replaces the
        // old one in its source.
        let batch = recut_pass(&mut adapter, &watch, &after, &chain);
        assert_eq!(batch.state, BatchState::Ready);
        assert_eq!(batch.commits.len(), 5);
        assert_eq!(batch.commits[..4], first.commits[..4]);
        let renumbered = &batch.commits[4].revision;
        assert_eq!(renumbered.source, tail.source);
        assert_eq!(renumbered.lineage, tail.lineage + 1);
        assert_eq!(batch.retired_revisions(), std::slice::from_ref(&tail));
        assert!(adapter.acknowledge_applied(&batch).is_err());
        adapter.acknowledge_reconciled(&batch).unwrap();
        let starts: Vec<u64> = before
            .shards
            .iter()
            .map(|entry| entry.start_height)
            .collect();
        assert_eq!(
            exported(&adapter),
            vec![
                (starts[0], 1),
                (starts[1], 1),
                (starts[2], 1),
                (starts[3], 1),
                (starts[4], 8)
            ]
        );
        // W and S3′ are cataloged, so a later regression is still caught.
        assert_eq!(cataloged(&adapter), 7);
        assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 1);

        // A replay is ready, changes nothing and resolves nothing.
        let replay = recut_pass(&mut adapter, &watch, &after, &chain);
        assert_eq!(replay.state, BatchState::Ready);
        assert_eq!(replay.commits, batch.commits);
        assert!(replay.retired_revisions().is_empty());
        adapter.acknowledge_applied(&replay).unwrap();
    }

    #[test]
    fn a_renumbered_tail_succeeds_in_its_source_once_retrieved() {
        let (before, after) = recut_pair();
        let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &before);
        let first = recut_pass(&mut adapter, &watch, &before, &chain);
        adapter.acknowledge_applied(&first).unwrap();
        // Until the renumbered tail is retrieved, the old one has no successor.
        withdraw_tail(&mut adapter, &after);
        let pending = recut_pass(&mut adapter, &watch, &after, &chain);
        assert_eq!(pending.state, BatchState::Pending);
        assert!(pending.commits.is_empty());
        retrieve_tail(&mut adapter, &after);
        let ready = recut_pass(&mut adapter, &watch, &after, &chain);
        assert_eq!(ready.state, BatchState::Ready);
        assert_eq!(
            ready.retired_revisions(),
            std::slice::from_ref(&first.commits[4].revision)
        );
    }

    #[test]
    fn an_undeclared_re_cut_is_still_withdrawn() {
        let (before, after) = recut_pair();
        let mut undeclared = after.clone();
        undeclared.recuts.clear();
        let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
        let dir = tempfile::tempdir().unwrap();
        let (mut adapter, _) =
            recut_companion(&dir.path().join("companion.sqlite"), &before, &undeclared);
        // S3's source is published at another sealed revision.
        let batch = recut_pass(&mut adapter, &watch, &undeclared, &chain);
        assert_eq!(
            batch.state,
            BatchState::Withdrawn(WithdrawnCause::ChangedSealed)
        );
        assert!(batch.commits.is_empty());
        assert!(adapter.acknowledge_applied(&batch).is_err());

        // Merging the last sealed shards instead renumbers only the tail. Their
        // heights are published under another source.
        let s = &before.shards;
        let merged = recut_map(
            vec![
                s[0].clone(),
                s[1].clone(),
                recut_entry(
                    2,
                    WIDE,
                    (s[2].start_height, s[3].end_height),
                    (0, true),
                    0x32,
                ),
                recut_entry(
                    3,
                    NARROW,
                    (s[4].start_height, after.shards[3].end_height),
                    (7, false),
                    0x34,
                ),
            ],
            vec![],
        );
        let dir = tempfile::tempdir().unwrap();
        let (mut adapter, _) =
            recut_companion(&dir.path().join("companion.sqlite"), &before, &merged);
        let batch = recut_pass(
            &mut adapter,
            &watch,
            &merged,
            &accepting(&[&before, &merged]),
        );
        assert_eq!(batch.state, BatchState::Withdrawn(WithdrawnCause::Retired));
        assert!(batch.commits.is_empty());
    }

    #[test]
    fn a_sealed_rewrite_the_sync_refuses_is_withdrawn_before_any_retrieval() {
        let (before, after) = recut_pair();
        let mut undeclared = after.clone();
        undeclared.recuts.clear();
        let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &before);
        let first = recut_pass(&mut adapter, &watch, &before, &chain);
        adapter.acknowledge_applied(&first).unwrap();
        let held = (store_rows(&adapter), catalog_rows(&adapter));
        // The sync finds sealed coverage the map rewrites over blocks the
        // wallet's chain still accepts, and refuses it before reading.
        let mut filters = CountingFilters::serving(serde_json::to_vec(&undeclared).unwrap());
        let mut shards = CountingShards::serving(SCHEMA);
        let batch = adapter
            .recover(&watch, &chain, &mut filters, &mut shards)
            .unwrap();
        assert_eq!(
            batch.state,
            BatchState::Withdrawn(WithdrawnCause::ChangedSealed)
        );
        assert_eq!(
            batch.progress,
            Progress {
                covered_through: 0,
                outcome: Outcome::Behind,
            }
        );
        assert!(batch.commits.is_empty());
        assert!(adapter.acknowledge_applied(&batch).is_err());
        assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 1));
        assert_eq!((store_rows(&adapter), catalog_rows(&adapter)), held);
    }

    #[test]
    fn a_declaration_must_match_the_catalog() {
        let (before, mut after) = recut_pair();
        // S2 is declared at a revision number it was never published under.
        after.recuts[0].superseded[1].revision = 1;
        after.check_shape().unwrap();
        let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
        let dir = tempfile::tempdir().unwrap();
        let (mut adapter, _) =
            recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
        let recorded = catalog_rows(&adapter);
        let batch = recut_pass(&mut adapter, &watch, &after, &chain);
        assert_eq!(
            batch.state,
            BatchState::Withdrawn(WithdrawnCause::Equivocation)
        );
        assert!(batch.commits.is_empty());
        assert!(adapter.acknowledge_applied(&batch).is_err());
        // Only the published W, S3′ and T′ were recorded, not the revision the
        // declaration claimed for S2.
        let rows = catalog_rows(&adapter);
        assert_eq!(rows.len(), recorded.len() + 3);
        let s2 = before.shards[2].start_height;
        assert!(rows.iter().all(|row| row.1 != s2 || row.2 == 1));
    }

    #[test]
    fn a_successor_must_rise_above_its_declared_revision() {
        let (_, after) = recut_pair();
        // The map's own shape check refuses a renumbered shard that does not
        // take a higher revision, before any catalog transaction.
        let mut level = after.clone();
        level.shards[2].revision = 0;
        assert!(level.check_shape().is_err());
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &after);
        assert!(matches!(
            adapter.normalize(
                &watching(&after),
                level.clone(),
                MORE,
                &accepting(&[&after])
            ),
            Err(RecoveryError::Failure(_))
        ));

        // The catalog checks the same rule by source and lineage, with no
        // history: a fresh companion's pass, given such revisions directly.
        let set = SetIdentity::of_schema(&after, SCHEMA);
        let published = |map: &ShardMap| -> Vec<Published> {
            map.shards
                .iter()
                .map(|entry| Published::of(&adapter.binding, &set, entry).unwrap())
                .collect()
        };
        let declared = |map: &ShardMap| -> Vec<Published> {
            map.recuts
                .iter()
                .flat_map(|recut| &recut.superseded)
                .map(|shard| Published::declared(&adapter.binding, &set, shard).unwrap())
                .collect()
        };
        let mut lower = after.clone();
        lower.recuts[0].superseded[2].revision = 2;
        let mut conflicting = after.clone();
        let mut again = superseded(&after.shards[2]);
        again.revision = 0;
        again.manifest_digest = "ee".repeat(32);
        conflicting.recuts.push(Recut {
            epoch: 2,
            from_height: again.start_height,
            superseded: vec![again],
        });
        let fresh = tempfile::tempdir().unwrap();
        let mut fresh =
            ReferenceRecovery::open(fresh.path().join("fresh.sqlite"), config()).unwrap();
        for (map, cause) in [
            (&level, WithdrawnCause::Equivocation),
            (&lower, WithdrawnCause::Regression),
            (&conflicting, WithdrawnCause::Equivocation),
        ] {
            let (published, declared) = (published(map), declared(map));
            let mut pass = catalog::Pass::begin(&mut fresh.catalog, &published, &[]).unwrap();
            pass.check_declarations(&published, &declared);
            assert_eq!(pass.state(), BatchState::Withdrawn(cause));
        }
        // The well-formed declaration passes.
        let (published, declared) = (published(&after), declared(&after));
        let mut pass = catalog::Pass::begin(&mut fresh.catalog, &published, &[]).unwrap();
        pass.check_declarations(&published, &declared);
        assert_eq!(pass.state(), BatchState::Ready);
    }

    #[test]
    fn the_source_ignores_the_shard_id() {
        let (before, after) = recut_pair();
        let config = config();
        let binding = catalog::binding([
            &config.source,
            &config.account_binding,
            config.origin.as_bytes(),
            SCHEMA.as_bytes(),
        ]);
        let set = SetIdentity::of_schema(&after, SCHEMA);
        let source = |entry: &ShardMapEntry| {
            catalog::source(&binding, &set, &entry.geometry, entry.start_height).unwrap()
        };
        // Renumbered at the same heights: the same source.
        for (old, new) in [
            (&before.shards[3], &after.shards[2]),
            (&before.shards[4], &after.shards[3]),
        ] {
            assert_ne!(old.shard_id, new.shard_id);
            assert_eq!(source(old), source(new));
        }
        // Re-cut under another geometry from the same height: another source.
        assert_ne!(source(&before.shards[1]), source(&after.shards[1]));
        // A declared revision has the identity it had when published.
        let declared = Published::declared(&binding, &set, &after.recuts[0].superseded[2]).unwrap();
        let published = Published::of(
            &binding,
            &SetIdentity::of_schema(&before, SCHEMA),
            &before.shards[3],
        )
        .unwrap();
        assert_eq!(declared.revision, published.revision);
        // The formula, as documented.
        let entry = &after.shards[2];
        let seal = serde_json::to_vec(&set.seal[&entry.geometry]).unwrap();
        let lp = |hash: &mut Sha256, value: &[u8]| {
            hash.update((value.len() as u64).to_le_bytes());
            hash.update(value);
        };
        let mut hash = Sha256::new();
        hash.update(b"transparent-reference-source-v3");
        hash.update(binding);
        lp(&mut hash, SCHEMA.as_bytes());
        lp(&mut hash, set.network.as_bytes());
        lp(&mut hash, set.genesis_hash.as_bytes());
        lp(&mut hash, set.profile.as_bytes());
        hash.update(set.range_envelope_version.to_le_bytes());
        hash.update(set.start_height.to_le_bytes());
        lp(&mut hash, entry.geometry.as_bytes());
        lp(&mut hash, &seal);
        hash.update(entry.start_height.to_le_bytes());
        assert_eq!(<[u8; 32]>::from(hash.finalize()), source(entry));
    }

    #[test]
    fn a_lagging_replica_behind_a_re_cut_is_pending() {
        let (before, after) = recut_pair();
        let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
        let dir = tempfile::tempdir().unwrap();
        let (mut adapter, _) =
            recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
        let batch = recut_pass(&mut adapter, &watch, &after, &chain);
        adapter.acknowledge_reconciled(&batch).unwrap();
        assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 1);
        // The store has since read S3′ as well, as for a script added after
        // the re-cut: it holds sealed history only the re-cut map publishes.
        let script = address_script(watch.addresses[0].address);
        let s3 = &after.shards[2];
        let end = (s3.end_height, s3.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(s3, &s3.manifest_digest, end, &script, vec![]))
            .unwrap();
        let held = (store_rows(&adapter), catalog_rows(&adapter));

        // A replica still serving the map from before the re-cut. The sync
        // refuses it as a rewrite of that history before reading anything,
        // and the pass, seeing an epoch below the one it recorded, takes it
        // for a lagging replica: pending and behind, touching nothing.
        let mut filters = CountingFilters::serving(serde_json::to_vec(&before).unwrap());
        let mut shards = CountingShards::serving(SCHEMA);
        let lagging = adapter
            .recover(&watch, &chain, &mut filters, &mut shards)
            .unwrap();
        assert_eq!(lagging.state, BatchState::Pending);
        assert_eq!(
            lagging.progress,
            Progress {
                covered_through: 0,
                outcome: Outcome::Behind,
            }
        );
        assert!(lagging.commits.is_empty());
        assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 1));
        assert_eq!((store_rows(&adapter), catalog_rows(&adapter)), held);
        // A pass over the earlier map records no lower epoch.
        recut_pass(&mut adapter, &watch, &before, &chain);
        assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 1);

        // A publication change restarts the store, and with it the epoch.
        let resealed = resealing(&after, 1);
        let mut filters = CountingFilters::serving(serde_json::to_vec(&resealed).unwrap());
        assert!(matches!(
            adapter.recover(&watch, &accepting(&[&resealed]), &mut filters, &mut shards),
            Err(RecoveryError::PublicationChanged)
        ));
        assert_eq!(adapter.store.set_identity().unwrap(), None);
        assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 0);
    }

    #[test]
    fn a_page_under_a_declared_revision_is_completed_once() {
        let (before, after) = recut_pair();
        let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
        let script = address_script(watch.addresses[0].address);
        let s3 = &before.shards[3];
        // A companion that left page work on S3, which the wallet applied.
        let opened = |dir: &tempfile::TempDir| {
            let mut adapter = seeded(dir, &script, before.start_height);
            for entry in &before.shards {
                let end = (entry.end_height, entry.terminal_block_hash.as_str());
                let mut commit = covered(entry, &entry.manifest_digest, end, &script, vec![]);
                if entry.shard_id == s3.shard_id {
                    commit.covered_scripts.clear();
                    commit.pending_upsert = vec![store_page(entry, &script, 3)];
                }
                adapter.store.commit_shard(commit).unwrap();
            }
            let first = recut_pass(&mut adapter, &watch, &before, &chain);
            assert_eq!(first.state, BatchState::Ready);
            adapter.acknowledge_applied(&first).unwrap();
            let opening = first.commits[3].clone();
            assert_eq!(opening.opened_pages.len(), 1);
            let mut holding = watch.clone();
            holding.pending_pages = vec![PendingPage {
                request: opening.opened_pages[0].clone(),
                revision: opening.revision.clone(),
                target: opening.context.target,
            }];
            (adapter, holding, opening)
        };
        let completions = |batch: &RecoveryBatch<u32>, page: &[u8]| -> Vec<RecoveryRevision> {
            batch
                .commits
                .iter()
                .filter(|commit| commit.completed_pages.iter().any(|done| done == page))
                .map(|commit| commit.revision.clone())
                .collect()
        };

        // The sync dropped the store's page work under S3, which the map no
        // longer publishes, and retrieved S3′ in its place. No commit of S3
        // follows, so a completion under S3's own revision does, once S3′
        // covers the page.
        let dir = tempfile::tempdir().unwrap();
        let (mut adapter, holding, opening) = opened(&dir);
        adapter
            .store
            .rollback_above(
                &Anchor {
                    height: s3.start_height - 1,
                    hash: s3.parent_block_hash.clone(),
                },
                "superseded page work",
            )
            .unwrap();
        for entry in &after.shards[2..] {
            let end = (entry.end_height, entry.terminal_block_hash.as_str());
            adapter
                .store
                .commit_shard(covered(entry, &entry.manifest_digest, end, &script, vec![]))
                .unwrap();
        }
        let batch = recut_pass(&mut adapter, &holding, &after, &chain);
        assert_eq!(batch.state, BatchState::Ready);
        let page = &opening.opened_pages[0].page;
        assert_eq!(completions(&batch, page), vec![opening.revision.clone()]);
        let completion = batch.commits.last().unwrap();
        assert_eq!(
            completion.anchor,
            ChainPoint {
                height: block(s3.end_height).unwrap(),
                hash: block_hash(&s3.terminal_block_hash).unwrap(),
            }
        );
        assert!(completion.coverage.is_empty());
        // S3′, in S3's source, carries the coverage.
        assert!(
            batch
                .commits
                .iter()
                .any(|commit| commit.revision.source == opening.revision.source
                    && commit.revision.lineage == opening.revision.lineage + 1
                    && !commit.coverage.is_empty())
        );

        // The store finished the page under S3 before the re-cut, so S3's own
        // commit covers and completes it, and nothing completes it again.
        let dir = tempfile::tempdir().unwrap();
        let (mut adapter, holding, opening) = opened(&dir);
        let pending = adapter.store.pending().unwrap();
        let end = (s3.end_height, s3.terminal_block_hash.as_str());
        let mut done = covered(s3, &s3.manifest_digest, end, &script, vec![]);
        done.pending_complete = vec![pending[0].id.unwrap()];
        adapter.store.commit_shard(done).unwrap();
        retrieve_tail(&mut adapter, &after);
        let batch = recut_pass(&mut adapter, &holding, &after, &chain);
        assert_eq!(batch.state, BatchState::Ready);
        assert_eq!(completions(&batch, page), vec![opening.revision.clone()]);
        assert!(
            !batch
                .commits
                .iter()
                .find(|commit| commit.revision == opening.revision)
                .unwrap()
                .coverage
                .is_empty()
        );
    }

    #[test]
    fn a_recreated_companion_after_a_re_cut_collides_with_nothing() {
        let (before, after) = recut_pair();
        let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
        let dir = tempfile::tempdir().unwrap();
        let (mut adapter, first) =
            recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
        let kept = recut_pass(&mut adapter, &watch, &after, &chain);
        assert_eq!(kept.state, BatchState::Ready);
        adapter.acknowledge_reconciled(&kept).unwrap();

        // The companion is lost after the re-cut. Its replacement retrieves the
        // re-cut publication from scratch.
        let mut recreated = covering(&dir.path().join("recreated.sqlite"), &after);
        let healed = recut_pass(&mut recreated, &watch, &after, &chain);
        assert_eq!(healed.state, BatchState::Ready);
        assert!(healed.retired_revisions().is_empty());
        assert_eq!(healed.commits.len(), after.shards.len());
        // S0 and T′ reproduce what the wallet holds; S3′ rises in S3's source;
        // W is a new source.
        assert_eq!(healed.commits[0], kept.commits[0]);
        assert_eq!(healed.commits[3].revision, kept.commits[4].revision);
        assert_eq!(
            healed.commits[2].revision.source,
            first.commits[3].revision.source
        );
        assert_eq!(
            healed.commits[2].revision.lineage,
            first.commits[3].revision.lineage + 1
        );
        // The wallet's integrity rule: within a source, a lineage names one
        // revision, and a revision one lineage.
        let mut lineages: BTreeMap<(Vec<u8>, u64), RecoveryRevision> = BTreeMap::new();
        let mut revisions: BTreeMap<(Vec<u8>, Vec<u8>), u64> = BTreeMap::new();
        for commit in first
            .commits
            .iter()
            .chain(&kept.commits)
            .chain(&healed.commits)
        {
            let revision = &commit.revision;
            let named = lineages
                .entry((revision.source.clone(), revision.lineage))
                .or_insert_with(|| revision.clone());
            assert_eq!(named, revision);
            let lineage = revisions
                .entry((revision.source.clone(), revision.revision.clone()))
                .or_insert(revision.lineage);
            assert_eq!(*lineage, revision.lineage);
        }
    }

    #[test]
    fn a_version_two_companion_is_rebuilt_keeping_its_store() {
        let map = map();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("companion.sqlite");
        let mut adapter = covering(&path, &map);
        let first = pass(&mut adapter, &map);
        adapter.acknowledge_applied(&first).unwrap();
        let store = store_rows(&adapter);
        drop(adapter);
        // Back to the v2 layout: a catalog keyed by shard id, with a row.
        let v2 = Connection::open(&path).unwrap();
        v2.execute_batch(
            "DROP TABLE pir_bridge_catalog;
             CREATE TABLE pir_bridge_catalog (
                source BLOB NOT NULL CHECK(length(source)=32),
                shard_id INTEGER NOT NULL CHECK(shard_id>=0),
                digest TEXT NOT NULL,
                sealed INTEGER NOT NULL CHECK(sealed IN (0,1)),
                lineage INTEGER NOT NULL CHECK(lineage>0),
                revision BLOB NOT NULL CHECK(length(revision)=32),
                height INTEGER NOT NULL CHECK(height>=0 AND height<=4294967295),
                hash BLOB NOT NULL CHECK(length(hash)=32),
                exported INTEGER NOT NULL DEFAULT 0 CHECK(exported IN (0,1)),
                current INTEGER NOT NULL DEFAULT 0 CHECK(current IN (0,1)),
                PRIMARY KEY(source,digest,sealed), UNIQUE(source,lineage), UNIQUE(source,revision));
             INSERT INTO pir_bridge_catalog VALUES
                (zeroblob(32), 1, 'aa', 0, 1, zeroblob(32), 1, zeroblob(32), 1, 1);
             UPDATE pir_bridge_binding SET value='transparent-reference-companion-v2' WHERE key='format';
             DELETE FROM pir_bridge_binding WHERE key='recut-epoch';",
        )
        .unwrap();
        // Another account's companion is still refused, and changes nothing.
        let mut other = config();
        other.account_binding = vec![2];
        assert!(ReferenceRecovery::open(&path, other).is_err());
        let format = |conn: &Connection| -> String {
            conn.query_row(
                "SELECT value FROM pir_bridge_binding WHERE key='format'",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_eq!(format(&v2), "transparent-reference-companion-v2");

        // Opening rebuilds the catalog in place, empty, and keeps the store.
        let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
        assert_eq!(format(&v2), "transparent-reference-companion-v3");
        assert_eq!(cataloged(&adapter), 0);
        assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 0);
        assert_eq!(store_rows(&adapter), store);
        // The next pass exports the stored facts again, without retrieving.
        let again = pass(&mut adapter, &map);
        assert_eq!(again.state, BatchState::Ready);
        assert_eq!(again.commits, first.commits);
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1)]);
    }

    #[test]
    fn a_page_under_a_declared_revision_with_saved_events_completes_once() {
        let (before, after) = recut_pair();
        let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
        let script = address_script(watch.addresses[0].address);
        let s3 = &before.shards[3];
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = seeded(&dir, &script, before.start_height);
        // A budget-limited pass saved a receive under S3 and left the rest of
        // its pages, and the wallet holds both.
        let saved = TransparentEvent::Receive(transparent_events::ReceiveEvent {
            metadata: None,
            height: (s3.start_height + 10) as u32,
            txid: transparent_events::Txid([7; 32]),
            transaction_index: 1,
            output_index: 0,
            value: 100,
            coinbase: false,
        });
        for entry in &before.shards {
            let end = (entry.end_height, entry.terminal_block_hash.as_str());
            let mut commit = covered(entry, &entry.manifest_digest, end, &script, vec![]);
            if entry.shard_id == s3.shard_id {
                commit = covered(entry, &entry.manifest_digest, end, &script, vec![saved]);
                commit.covered_scripts.clear();
                commit.pending_upsert = vec![store_page(entry, &script, 3)];
            }
            adapter.store.commit_shard(commit).unwrap();
        }
        let first = recut_pass(&mut adapter, &watch, &before, &chain);
        assert_eq!(first.state, BatchState::Ready);
        adapter.acknowledge_applied(&first).unwrap();
        let opening = first.commits[3].clone();
        assert_eq!(opening.opened_pages.len(), 1);
        assert_eq!(opening.receives.len(), 1);
        let mut holding = watch.clone();
        holding.pending_pages = vec![PendingPage {
            request: opening.opened_pages[0].clone(),
            revision: opening.revision.clone(),
            target: opening.context.target,
        }];

        // Across the declared re-cut the sync drops the page work under S3,
        // whose last block the wallet's chain accepts, and keeps what it saved;
        // the tail is read again.
        let pending = adapter.store.pending().unwrap();
        adapter
            .store
            .commit_shard(transparent_wallet::ShardCommit {
                pending_complete: vec![pending[0].id.unwrap()],
                ..Default::default()
            })
            .unwrap();
        withdraw_tail(&mut adapter, &before);
        let read = |adapter: &mut ReferenceRecovery, entry: &ShardMapEntry| {
            let end = (entry.end_height, entry.terminal_block_hash.as_str());
            adapter
                .store
                .commit_shard(covered(entry, &entry.manifest_digest, end, &script, vec![]))
                .unwrap();
        };
        read(&mut adapter, &after.shards[3]);
        assert_eq!(adapter.store.events().unwrap().len(), 1);
        assert!(adapter.store.pending().unwrap().is_empty());
        let page = &opening.opened_pages[0].page;
        let completing = |batch: &RecoveryBatch<u32>| -> Vec<TransparentLedgerCommit<u32>> {
            batch
                .commits
                .iter()
                .filter(|commit| commit.completed_pages.contains(page))
                .cloned()
                .collect()
        };
        // Until the script's gap is read again, the page stays open.
        let batch = recut_pass(&mut adapter, &holding, &after, &chain);
        assert_eq!(batch.state, BatchState::Ready);
        assert!(completing(&batch).is_empty());
        adapter.acknowledge_reconciled(&batch).unwrap();

        // Once it is, under S3′, S3's own commit carries the saved receive and
        // S3′ the coverage. The page is completed once, under S3's revision,
        // in a completion-only commit after both, so the wallet applies the
        // coverage that completes it first.
        read(&mut adapter, &after.shards[2]);
        let batch = recut_pass(&mut adapter, &holding, &after, &chain);
        assert_eq!(batch.state, BatchState::Ready);
        let completing = completing(&batch);
        assert_eq!(completing.len(), 1);
        assert_eq!(completing[0].revision, opening.revision);
        assert_eq!(completing[0].completed_pages, vec![page.clone()]);
        assert!(completing[0].receives.is_empty() && completing[0].coverage.is_empty());
        assert_eq!(
            completing[0].anchor,
            ChainPoint {
                height: block(s3.end_height).unwrap(),
                hash: block_hash(&s3.terminal_block_hash).unwrap(),
            }
        );
        let position = |found: &dyn Fn(&TransparentLedgerCommit<u32>) -> bool| {
            batch.commits.iter().position(found).unwrap()
        };
        let saved_at = position(&|commit| {
            commit.revision == opening.revision && commit.receives == opening.receives
        });
        let covered_at = position(&|commit| {
            commit.revision.source == opening.revision.source
                && commit.revision.lineage == opening.revision.lineage + 1
                && !commit.coverage.is_empty()
        });
        let completed_at = position(&|commit| commit.completed_pages.contains(page));
        assert!(batch.commits[saved_at].completed_pages.is_empty());
        assert!(completed_at > saved_at && completed_at > covered_at);
    }

    #[test]
    fn a_declared_revision_never_reuses_a_pruned_exported_lineage() {
        let base = map();
        let tail = base.shards[1].clone();
        let script = address_script(watch().addresses[0].address);
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
        // The tail T, at lineage 1, is exported, then replaced and reconciled,
        // so the catalog prunes its row while the wallet keeps T for good.
        let first = pass(&mut adapter, &base);
        adapter.acknowledge_applied(&first).unwrap();
        let t = first.commits[1].revision.clone();
        let next = republished(&base, 1, 1, "5a".repeat(32));
        retrieve_tail(&mut adapter, &next);
        let replaced = pass(&mut adapter, &next);
        assert_eq!(replaced.retired_revisions(), std::slice::from_ref(&t));
        adapter.acknowledge_reconciled(&replaced).unwrap();
        assert_eq!(cataloged(&adapter), 2);
        assert!(
            catalog_rows(&adapter)
                .iter()
                .all(|row| row.1 != tail.start_height || row.2 != 1)
        );

        // A map declares a sealed revision at the tail's geometry and start, at
        // revision 0, so at T's source and lineage, under a digest the store
        // holds a fact under.
        let planted = "77".repeat(32);
        let end = tail.start_height + 50;
        let terminal = "ab".repeat(32);
        let mut forged = republished(&base, 1, 2, "5b".repeat(32));
        forged.recuts = vec![Recut {
            epoch: 1,
            from_height: tail.start_height,
            superseded: vec![SupersededShard {
                shard_id: tail.shard_id,
                geometry: tail.geometry.clone(),
                start_height: tail.start_height,
                end_height: end,
                terminal_block_hash: terminal.clone(),
                manifest_digest: planted.clone(),
                revision: 0,
                sealed: true,
            }],
        }];
        forged.check_shape().unwrap();
        retrieve_tail(&mut adapter, &forged);
        let receive = TransparentEvent::Receive(transparent_events::ReceiveEvent {
            metadata: None,
            height: (tail.start_height + 10) as u32,
            txid: transparent_events::Txid([9; 32]),
            transaction_index: 1,
            output_index: 0,
            value: 100,
            coinbase: false,
        });
        let mut planted_entry = tail.clone();
        planted_entry.end_height = end;
        planted_entry.sealed = true;
        let mut facts = covered(
            &planted_entry,
            &planted,
            (end, &terminal),
            &script,
            vec![receive],
        );
        facts.covered_scripts.clear();
        adapter.store.commit_shard(facts).unwrap();
        let mut chain = StaticChain::from_map(&forged);
        chain.hashes.insert(end, terminal);
        // The wallet would refuse it as an integrity failure and quarantine the
        // account, so the companion refuses it first.
        let batch = adapter
            .normalize(&watch(), forged.clone(), MORE, &chain)
            .unwrap();
        assert_eq!(
            batch.state,
            BatchState::Withdrawn(WithdrawnCause::Equivocation)
        );
        assert!(batch.commits.is_empty());
        // A published revision at that lineage is refused the same way.
        let colliding = republished(&base, 1, 0, "c0".repeat(32));
        retrieve_tail(&mut adapter, &colliding);
        assert_eq!(
            pass(&mut adapter, &colliding).state,
            BatchState::Withdrawn(WithdrawnCause::Equivocation)
        );
    }

    #[test]
    fn a_refused_declaration_does_not_raise_the_epoch() {
        let (before, after) = recut_pair();
        let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
        let dir = tempfile::tempdir().unwrap();
        let (mut adapter, _) =
            recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
        // A map misstating a declared revision at the highest epoch is refused,
        // and records no epoch.
        let mut forged = after.clone();
        forged.recuts[0].superseded[1].revision = 1;
        forged.recuts[0].epoch = u32::MAX;
        forged.check_shape().unwrap();
        let batch = recut_pass(&mut adapter, &watch, &forged, &chain);
        assert_eq!(
            batch.state,
            BatchState::Withdrawn(WithdrawnCause::Equivocation)
        );
        assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 0);
        // Nor does a ready map whose re-cut starts above everything the store
        // read and supersedes nothing it holds: such a map rewrites nothing the
        // store holds, so a store that read only below it needs no guard.
        let other = tempfile::tempdir().unwrap();
        let script = address_script(watch.addresses[0].address);
        let mut plain = seeded(&other, &script, before.start_height);
        for entry in &before.shards[..3] {
            let end = (entry.end_height, entry.terminal_block_hash.as_str());
            plain
                .store
                .commit_shard(covered(entry, &entry.manifest_digest, end, &script, vec![]))
                .unwrap();
        }
        let s3 = &before.shards[3];
        let mut ghost = superseded(&recut_entry(9, WIDE, (1, 2), (0, true), 0x99));
        ghost.start_height = s3.start_height;
        ghost.end_height = s3.end_height;
        let mut idle = before.clone();
        idle.recuts = vec![Recut {
            epoch: u32::MAX,
            from_height: s3.start_height,
            superseded: vec![ghost],
        }];
        idle.check_shape().unwrap();
        let ready = recut_pass(&mut plain, &watch, &idle, &chain);
        assert_eq!(ready.state, BatchState::Ready);
        assert_eq!(catalog::recut_epoch(&plain.catalog).unwrap(), 0);
        // The honest re-cut map is not held behind, and its ready pass, over
        // revisions the store holds, records its epoch.
        let honest = recut_pass(&mut adapter, &watch, &after, &chain);
        assert_eq!(honest.state, BatchState::Ready);
        assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 1);
        let mut filters = CountingFilters::serving(serde_json::to_vec(&after).unwrap());
        let mut shards = CountingShards::serving(SCHEMA);
        let synced = adapter
            .recover(&watch, &chain, &mut filters, &mut shards)
            .unwrap();
        assert_eq!(synced.state, BatchState::Ready);
        assert_eq!(filters.filters, 0);
    }

    #[test]
    fn a_companion_that_read_the_re_cut_map_holds_older_maps_behind() {
        let (before, after) = recut_pair();
        let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
        // A companion recreated after the re-cut, or one born above it, holds
        // nothing the re-cut superseded, only what the re-cut map publishes.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &after);
        let first = recut_pass(&mut adapter, &watch, &after, &chain);
        assert_eq!(first.state, BatchState::Ready);
        assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 1);
        adapter.acknowledge_applied(&first).unwrap();
        let held = (store_rows(&adapter), catalog_rows(&adapter));

        // A replica still serving the map from before the re-cut would rewrite
        // what the store read. The pass waits for it before the sync, and
        // touches nothing.
        let mut filters = CountingFilters::serving(serde_json::to_vec(&before).unwrap());
        let mut shards = CountingShards::serving(SCHEMA);
        let lagging = adapter
            .recover(&watch, &chain, &mut filters, &mut shards)
            .unwrap();
        assert_eq!(lagging.state, BatchState::Pending);
        assert_eq!(
            lagging.progress,
            Progress {
                covered_through: 0,
                outcome: Outcome::Behind,
            }
        );
        assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 1));
        assert_eq!((store_rows(&adapter), catalog_rows(&adapter)), held);
    }

    #[test]
    fn a_forged_epoch_never_holds_an_honest_map_back() {
        let base = map();
        let tail = base.shards[1].clone();
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
        let first = pass(&mut adapter, &base);
        assert_eq!(first.state, BatchState::Ready);
        adapter.acknowledge_applied(&first).unwrap();
        // The same shards, plus a re-cut at the tail's start at the highest
        // epoch, superseding a revision nobody published. It passes every
        // check, the store read the tail it starts at, and its epoch is
        // recorded.
        let mut forged = base.clone();
        forged.recuts = vec![Recut {
            epoch: u32::MAX,
            from_height: tail.start_height,
            superseded: vec![SupersededShard {
                shard_id: tail.shard_id,
                geometry: base.shards[0].geometry.clone(),
                start_height: tail.start_height,
                end_height: tail.end_height,
                terminal_block_hash: tail.terminal_block_hash.clone(),
                manifest_digest: "ee".repeat(32),
                revision: 0,
                sealed: false,
            }],
        }];
        forged.check_shape().unwrap();
        let batch = pass(&mut adapter, &forged);
        assert_eq!(batch.state, BatchState::Ready);
        adapter.acknowledge_applied(&batch).unwrap();
        assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), u32::MAX);

        // The honest map, served afterwards, rewrites nothing the store holds,
        // so it syncs and is ready.
        let recovered = |adapter: &mut ReferenceRecovery, map: &ShardMap| {
            let mut filters = CountingFilters::serving(serde_json::to_vec(map).unwrap());
            let mut shards = CountingShards::serving(SCHEMA);
            let batch = adapter
                .recover(
                    &watch(),
                    &StaticChain::from_map(map),
                    &mut filters,
                    &mut shards,
                )
                .unwrap();
            assert_eq!(filters.filters, 0);
            batch
        };
        let honest = recovered(&mut adapter, &base);
        assert_eq!(honest.state, BatchState::Ready);
        assert_eq!(honest.progress.outcome, Outcome::Complete);

        // The forged epoch can only soften a real contradiction: a map that
        // rewrites the sealed shard the store holds is taken for a lagging
        // replica, pending instead of withdrawn.
        let rewritten = republished(&base, 0, 0, "e0".repeat(32));
        let softened = recovered(&mut adapter, &rewritten);
        assert_eq!(softened.state, BatchState::Pending);
        assert_eq!(softened.progress.outcome, Outcome::Behind);
        // Without a recorded epoch the same map is withdrawn.
        let fresh = tempfile::tempdir().unwrap();
        let mut plain = covering(&fresh.path().join("companion.sqlite"), &base);
        let first = pass(&mut plain, &base);
        plain.acknowledge_applied(&first).unwrap();
        assert_eq!(
            recovered(&mut plain, &rewritten).state,
            BatchState::Withdrawn(WithdrawnCause::ChangedSealed)
        );
    }

    #[test]
    fn a_digest_declared_under_another_geometry_or_start_is_an_equivocation() {
        let (before, after) = recut_pair();
        let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
        // S2's digest declared under the wide geometry, which gives it another
        // source; or S2 declared from a height after its start, with S1 ending
        // there.
        let mut moved = after.clone();
        moved.recuts[0].superseded[1].geometry = WIDE.into();
        let mut shifted = after.clone();
        shifted.recuts[0].superseded[0].end_height += 1;
        shifted.recuts[0].superseded[0].terminal_block_hash =
            recut_hash(shifted.recuts[0].superseded[0].end_height);
        shifted.recuts[0].superseded[1].start_height += 1;
        let mut chain = chain;
        let shifted_end = shifted.recuts[0].superseded[0].end_height;
        chain.hashes.insert(shifted_end, recut_hash(shifted_end));
        for map in [moved, shifted] {
            map.check_shape().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let (mut adapter, _) =
                recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
            let batch = recut_pass(&mut adapter, &watch, &map, &chain);
            assert_eq!(
                batch.state,
                BatchState::Withdrawn(WithdrawnCause::Equivocation)
            );
            assert!(batch.commits.is_empty());
        }
    }

    #[test]
    fn a_fact_under_a_declared_revision_must_fit_it() {
        let (before, after) = recut_pair();
        let watch = watching(&after);
        let script = address_script(watch.addresses[0].address);
        let (s1, s2) = (&before.shards[1], &before.shards[2]);
        let chain = accepting(&[&before, &after]);
        let fresh = |dir: &tempfile::TempDir| {
            let (adapter, _) =
                recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
            adapter
        };
        // The wallet's chain holds another block where S1 ended, which no
        // published shard ends on: S1's facts rest on a branch the wallet
        // left, so the batch waits.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = fresh(&dir);
        let mut elsewhere = chain.clone();
        elsewhere.hashes.insert(s1.end_height, "e1".repeat(32));
        let batch = recut_pass(&mut adapter, &watch, &after, &elsewhere);
        assert_eq!(batch.state, BatchState::Pending);
        assert!(batch.commits.is_empty());

        // A fact outside S2's declared range does not fit it.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = fresh(&dir);
        let outside = TransparentEvent::Receive(transparent_events::ReceiveEvent {
            metadata: None,
            height: (s2.end_height + 1) as u32,
            txid: transparent_events::Txid([3; 32]),
            transaction_index: 1,
            output_index: 0,
            value: 100,
            coinbase: false,
        });
        let end = (s2.end_height, s2.terminal_block_hash.as_str());
        let mut stray = covered(s2, &s2.manifest_digest, end, &script, vec![outside]);
        stray.covered_scripts.clear();
        adapter.store.commit_shard(stray).unwrap();
        let batch = recut_pass(&mut adapter, &watch, &after, &chain);
        assert_eq!(batch.state, BatchState::Pending);
        assert!(batch.commits.is_empty());

        // Nor does coverage under S2's digest that names another shard id.
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = fresh(&dir);
        let mut renamed = s2.clone();
        renamed.shard_id = 7;
        adapter
            .store
            .commit_shard(covered(&renamed, &s2.manifest_digest, end, &script, vec![]))
            .unwrap();
        let batch = recut_pass(&mut adapter, &watch, &after, &chain);
        assert_eq!(batch.state, BatchState::Pending);
        assert!(batch.commits.is_empty());
    }

    #[test]
    fn only_declarations_at_or_above_the_floor_count_against_the_shard_limit() {
        let (_, after) = recut_pair();
        let declared = after.recuts[0].superseded.len();
        assert_eq!(entries(&after, 0), after.shards.len() + declared);
        // A floor above S1 and S2 leaves S3 and the tail.
        let floor = after.recuts[0].superseded[2].start_height;
        assert_eq!(entries(&after, floor), after.shards.len() + 2);
        assert_eq!(entries(&after, u64::MAX), after.shards.len());
    }

    /// The pairwise scan the indexed declaration check replaced, kept as its
    /// oracle.
    fn pairwise_conflict(
        published: &[Published],
        declarations: &[Published],
    ) -> Option<WithdrawnCause> {
        for (index, declared) in declarations.iter().enumerate() {
            let ours = &declared.revision;
            for entry in published {
                let theirs = &entry.revision;
                if theirs.source != ours.source {
                    continue;
                }
                if theirs.lineage == ours.lineage {
                    return Some(WithdrawnCause::Equivocation);
                } else if theirs.lineage < ours.lineage {
                    return Some(WithdrawnCause::Regression);
                }
            }
            if declarations[index + 1..].iter().any(|other| {
                other.revision.source == ours.source
                    && other.revision.lineage == ours.lineage
                    && other.revision != *ours
            }) {
                return Some(WithdrawnCause::Equivocation);
            }
        }
        None
    }

    #[test]
    fn the_declaration_check_finds_what_a_pairwise_scan_finds() {
        // A fixed xorshift sequence over few sources, lineages and contents,
        // so revisions collide often, published ones included.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % bound
        };
        let mut revision = || Published {
            shard_id: 0,
            start_height: 0,
            end_height: 0,
            digest: String::new(),
            terminal: String::new(),
            revision: RecoveryRevision {
                source: vec![next(4) as u8],
                revision: vec![next(3) as u8],
                lineage: 1 + next(4),
                sealed: next(2) == 0,
                publication: PublicationAnchor {
                    height: BlockHeight::from(0),
                    hash: BlockHash([0; 32]),
                },
            },
        };
        let mut seen = [0usize; 3];
        for case in 0..20_000 {
            let published: Vec<_> = (0..case % 4).map(|_| revision()).collect();
            let declarations: Vec<_> = (0..case % 9).map(|_| revision()).collect();
            let cause = catalog::declaration_conflict(&published, &declarations);
            assert_eq!(
                cause,
                pairwise_conflict(&published, &declarations),
                "case {case}"
            );
            seen[match cause {
                None => 0,
                Some(WithdrawnCause::Equivocation) => 1,
                _ => 2,
            }] += 1;
        }
        assert!(seen.iter().all(|count| *count > 1_000), "{seen:?}");
    }

    /// The re-cut fixture's `after`, with a forged re-cut before its own that
    /// declares sealed one-block revisions from height 0, far below the
    /// fixture map and any floor, bringing the map's declarations to `total`.
    fn forged(total: usize) -> ShardMap {
        let (_, mut after) = recut_pair();
        let mut own = after.recuts.pop().unwrap();
        own.epoch = 2;
        let count = (total - own.superseded.len()) as u64;
        let forged = Recut {
            epoch: 1,
            from_height: 0,
            superseded: (0..count)
                .map(|height| SupersededShard {
                    shard_id: height,
                    geometry: NARROW.into(),
                    start_height: height,
                    end_height: height,
                    terminal_block_hash: format!("{height:064x}"),
                    manifest_digest: format!("{:064x}", (1u64 << 40) + height),
                    revision: 0,
                    sealed: true,
                })
                .collect(),
        };
        after.recuts = vec![forged, own];
        after
    }

    #[test]
    fn a_full_declaration_set_is_checked_quickly() {
        let map = forged(MAX_SUPERSEDED);
        map.check_shape().unwrap();
        let (binding, set) = ([7; 32], SetIdentity::of_schema(&map, SCHEMA));
        let published: Vec<_> = map
            .shards
            .iter()
            .map(|entry| Published::of(&binding, &set, entry).unwrap())
            .collect();
        let declarations: Vec<_> = map
            .recuts
            .iter()
            .flat_map(|recut| &recut.superseded)
            .map(|shard| Published::declared(&binding, &set, shard).unwrap())
            .collect();
        assert_eq!(declarations.len(), MAX_SUPERSEDED);
        // A pairwise scan of this many takes seconds; the indexed check, a few
        // milliseconds. Each contradiction involves the last declaration, so
        // nothing short of indexing every one finds it.
        let check = |declarations: &[Published]| {
            let started = std::time::Instant::now();
            let cause = catalog::declaration_conflict(&published, declarations);
            let elapsed = started.elapsed();
            assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
            cause
        };
        assert_eq!(check(&declarations), None);
        let last = declarations.len() - 1;
        // The superseded tail T at T′'s lineage, then above it.
        let tail = published.last().unwrap().revision.lineage;
        let mut level = declarations.clone();
        level[last].revision.lineage = tail;
        assert_eq!(check(&level), Some(WithdrawnCause::Equivocation));
        let mut above = declarations.clone();
        above[last].revision.lineage = tail + 1;
        assert_eq!(check(&above), Some(WithdrawnCause::Regression));
        // The first forged revision declared again, last, with other content.
        let mut again = declarations.clone();
        again[last] = declarations[0].clone();
        again[last].revision.revision = vec![0xee; 32];
        assert_eq!(check(&again), Some(WithdrawnCause::Equivocation));
    }

    #[test]
    fn declarations_below_the_floor_count_against_a_separate_limit() {
        let (before, after) = recut_pair();
        let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
        let floor = required_floor(&watch, u64::MAX);
        let at_limit = forged(MAX_SUPERSEDED);
        at_limit.check_shape().unwrap();
        let over = forged(MAX_SUPERSEDED + 1);
        // None of the forged declarations reaches the floor, so the shard
        // limit alone would admit any number of them.
        assert_eq!(entries(&over, floor), entries(&after, floor));
        let dir = tempfile::tempdir().unwrap();
        let mut adapter =
            ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
        adapter.check_limits(&at_limit, floor).unwrap();
        let mut filters = CountingFilters::serving(serde_json::to_vec(&over).unwrap());
        let mut shards = CountingShards::serving(SCHEMA);
        assert!(matches!(
            adapter.recover(&watch, &chain, &mut filters, &mut shards),
            Err(RecoveryError::Invalid(message))
                if message == "publication declaration limit exceeded"
        ));
        assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 0));
        assert!(adapter.store.set_identity().unwrap().is_none());

        // At the limit, a pass exports what it would without the forged
        // re-cut, and quickly.
        let (mut plain, _) = recut_companion(&dir.path().join("plain.sqlite"), &before, &after);
        let expected = recut_pass(&mut plain, &watch, &after, &chain);
        let (mut adapter, _) =
            recut_companion(&dir.path().join("forged.sqlite"), &before, &at_limit);
        let started = std::time::Instant::now();
        let batch = recut_pass(&mut adapter, &watch, &at_limit, &chain);
        let elapsed = started.elapsed();
        assert_eq!(batch.state, BatchState::Ready);
        assert_eq!(batch.commits, expected.commits);
        assert_eq!(batch.replaced, expected.replaced);
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    }
}
