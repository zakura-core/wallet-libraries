//! Interruption around every persistence boundary, and every way the service
//! can fail a running wallet: a store that errors before or after a commit, a
//! panic, a tampered manifest, setup segment, directory or page answer, a
//! connection lost between queries, a service that vanishes, overload that
//! passes and overload that does not, a 503 that names no delay, a
//! publication replaced under a running wallet, and a stop at every request
//! boundary there is.
//!
//! What every case must hold: nothing committed is lost, nothing is accepted
//! as complete, the anchor does not move, the projection the wallet shows
//! agrees with the ledger it holds, and the next unfaulted run converges to
//! the exact ledger, asking no more than a fresh wallet would.
//!
//! The store-fault cases drive one pass of the library directly — the body of
//! `TransparentPir::run` for one pass, without its completion bookkeeping —
//! because the store is built inside the run and cannot be wrapped from
//! outside. They therefore cover the persistence boundaries and not the
//! completion word; the transport and service cases go through the run and
//! cover both.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Instant;

use common::blocks::*;
use common::catalogue::*;
use common::*;
use transparent_events::TransparentEvent;
use transparent_filter::{BlockHash, ScriptBytes, ShardMap};
use transparent_wallet::client::Table;
use transparent_wallet::transport::{BoxError, FilterSource, ShardTransport};
use transparent_wallet::{
    Anchor, CoverageRange, PendingPages, ScriptEntry, SetIdentity, SetupBlob, SetupKey,
    ShardCommit, StaticScripts, StoreError, StoredEvent, SyncError, WalletStore, WorkLimits,
    sync_into,
};
use zakura_wallet_core::AccountId;
use zakura_wallet_store::WalletDb;
use zakura_wallet_sync::TransparentCompletion;
use zakura_wallet_transparent::{ChainSnapshot, PirStore, watched_scripts};

// ------------------------------------------------------- a faulty store

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Boundary {
    CommitShard,
    CommitAnchor,
    PutFilter,
    PutSetup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum How {
    /// Fail before anything is written.
    ErrBefore,
    /// Write, then report failure: the commit landed and the caller never
    /// heard.
    ErrAfter,
    /// Die.
    PanicBefore,
}

#[derive(Debug, Clone, Copy)]
struct FaultPlan {
    at: Boundary,
    /// Which call to fault, counting from 1.
    when: u32,
    how: How,
}

/// The wallet's store with one planned fault.
struct Faulty<'a> {
    inner: PirStore<'a>,
    plan: FaultPlan,
    calls: u32,
    /// The commit the fault landed on, kept so the test can repeat it.
    pub faulted_commit: Option<ShardCommit>,
    pub fired: bool,
}

impl<'a> Faulty<'a> {
    fn new(inner: PirStore<'a>, plan: FaultPlan, calls: u32) -> Self {
        Self {
            inner,
            plan,
            calls,
            faulted_commit: None,
            fired: false,
        }
    }

    fn arm(&mut self, at: Boundary) -> Option<How> {
        if self.plan.at != at || self.fired {
            return None;
        }
        self.calls += 1;
        if self.calls == self.plan.when {
            self.fired = true;
            Some(self.plan.how)
        } else {
            None
        }
    }

    fn injected() -> StoreError {
        StoreError::Io("injected store failure".into())
    }
}

impl<'a> WalletStore for Faulty<'a> {
    fn set_identity(&self) -> Result<Option<SetIdentity>, StoreError> {
        self.inner.set_identity()
    }
    fn bind_set(&mut self, identity: &SetIdentity) -> Result<(), StoreError> {
        self.inner.bind_set(identity)
    }
    fn anchor(&self) -> Result<Option<Anchor>, StoreError> {
        self.inner.anchor()
    }
    fn scripts(&self) -> Result<Vec<ScriptEntry>, StoreError> {
        self.inner.scripts()
    }
    fn add_scripts(&mut self, entries: &[ScriptEntry]) -> Result<usize, StoreError> {
        self.inner.add_scripts(entries)
    }
    fn coverage(&self, script: &[u8]) -> Result<Vec<CoverageRange>, StoreError> {
        self.inner.coverage(script)
    }
    fn provisional(&self) -> Result<Vec<CoverageRange>, StoreError> {
        self.inner.provisional()
    }
    fn events(&self) -> Result<Vec<StoredEvent>, StoreError> {
        self.inner.events()
    }
    fn commit_shard(&mut self, commit: ShardCommit) -> Result<u64, StoreError> {
        match self.arm(Boundary::CommitShard) {
            Some(How::ErrBefore) => {
                self.faulted_commit = Some(commit);
                Err(Self::injected())
            }
            Some(How::PanicBefore) => panic!("injected panic before a shard commit"),
            Some(How::ErrAfter) => {
                self.faulted_commit = Some(commit.clone());
                self.inner.commit_shard(commit)?;
                Err(Self::injected())
            }
            None => self.inner.commit_shard(commit),
        }
    }
    fn commit_anchor(
        &mut self,
        anchor: &Anchor,
        settled_through: u64,
        covered_through: u64,
    ) -> Result<u64, StoreError> {
        match self.arm(Boundary::CommitAnchor) {
            Some(How::ErrBefore) => Err(Self::injected()),
            Some(How::PanicBefore) => panic!("injected panic before the anchor commit"),
            Some(How::ErrAfter) => {
                self.inner
                    .commit_anchor(anchor, settled_through, covered_through)?;
                Err(Self::injected())
            }
            None => self
                .inner
                .commit_anchor(anchor, settled_through, covered_through),
        }
    }
    fn rollback_above(&mut self, anchor: &Anchor, reason: &str) -> Result<u64, StoreError> {
        self.inner.rollback_above(anchor, reason)
    }
    fn promote_provisional(
        &mut self,
        shard_id: u64,
        revision_digest: &str,
    ) -> Result<(), StoreError> {
        self.inner.promote_provisional(shard_id, revision_digest)
    }
    fn pending(&self) -> Result<Vec<PendingPages>, StoreError> {
        self.inner.pending()
    }
    fn pending_limit(&self) -> usize {
        self.inner.pending_limit()
    }
    fn setup(&self, key: &SetupKey) -> Result<Option<SetupBlob>, StoreError> {
        self.inner.setup(key)
    }
    fn put_setup(&mut self, key: &SetupKey, blob: &SetupBlob) -> Result<(), StoreError> {
        match self.arm(Boundary::PutSetup) {
            Some(How::ErrBefore) => Err(Self::injected()),
            Some(How::PanicBefore) => panic!("injected panic before a setup is kept"),
            Some(How::ErrAfter) => {
                self.inner.put_setup(key, blob)?;
                Err(Self::injected())
            }
            None => self.inner.put_setup(key, blob),
        }
    }
    fn filter(
        &self,
        revision_digest: &str,
        filter_hash: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.filter(revision_digest, filter_hash)
    }
    fn put_filter(
        &mut self,
        revision_digest: &str,
        filter_hash: &str,
        sealed: bool,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        match self.arm(Boundary::PutFilter) {
            Some(How::ErrBefore) => Err(Self::injected()),
            Some(How::PanicBefore) => panic!("injected panic before a filter is kept"),
            Some(How::ErrAfter) => {
                self.inner
                    .put_filter(revision_digest, filter_hash, sealed, bytes)?;
                Err(Self::injected())
            }
            None => self
                .inner
                .put_filter(revision_digest, filter_hash, sealed, bytes),
        }
    }
    fn last_commit(&self) -> Result<u64, StoreError> {
        self.inner.last_commit()
    }
}

/// The library's passes over the wallet, through a faulty store: the body
/// of `TransparentPir::run` — widen the window, read every script, repeat
/// while the window moved — without its completion word. The fault's count
/// carries across passes, so a plan can name the second anchor commit.
fn run_pass_with_store(
    db: &mut WalletDb,
    plan: FaultPlan,
    filters: &mut impl FilterSource,
    transport: &mut impl ShardTransport,
) -> (Result<(), SyncError>, Option<ShardCommit>, bool) {
    let (map_bytes, map_cost) = filters.shard_map().unwrap();
    let map: ShardMap = serde_json::from_slice(&map_bytes).unwrap();
    let (_, scanned) = db.block_height_extrema().unwrap().unwrap();
    let hash = db.accepted_block_hash(scanned).unwrap().unwrap();
    let target = Anchor {
        height: u64::from(u32::from(scanned)),
        hash: BlockHash::from_internal_bytes(hash.0).to_display_hex(),
    };
    let (init_bytes, _) = transport.init().unwrap();
    let geometry = transparent_wallet::parse_init(&init_bytes).unwrap();
    let limits = zakura_wallet_store::GapLimits::default();
    let mut calls = 0;
    let mut asked: std::collections::BTreeSet<Vec<u8>> = Default::default();
    for _pass in 0..=16 {
        for account in db.accounts(&params()).unwrap() {
            db.maintain_transparent_addresses(&params(), account.id, &limits)
                .unwrap();
        }
        let watched = watched_scripts(db, &params(), map.start_height).unwrap();
        let now: std::collections::BTreeSet<Vec<u8>> =
            watched.entries.iter().map(|e| e.script.clone()).collect();
        if now == asked {
            break;
        }
        asked = now;
        let snapshot = ChainSnapshot::load_at(db, &map, &target).unwrap();
        let mut store = Faulty::new(PirStore::new(db, watched.owners), plan, calls);
        let mut provider = StaticScripts(watched.entries);
        let result = sync_into(
            &mut store,
            &map,
            map_cost,
            &geometry,
            &snapshot,
            &mut provider,
            filters,
            transport,
            &WorkLimits::UNLIMITED,
            &target,
        );
        calls = store.calls;
        let fired = store.fired;
        let commit = store.faulted_commit.take();
        match result {
            Ok(report) => {
                if fired {
                    return (Ok(()), commit, true);
                }
                if report.completion != transparent_wallet::Completion::Complete {
                    return (Ok(()), None, false);
                }
            }
            Err(error) => return (Err(error), commit, fired),
        }
    }
    (Ok(()), None, false)
}

// ------------------------------------------------------------ fixtures

struct Fixture {
    db: WalletDb,
    account: AccountId,
    chain: Chain,
    cast: Cast,
    map: ShardMap,
    dir: tempfile::TempDir,
    home: Option<tempfile::TempDir>,
}

/// The catalogue on a fresh wallet, published and ready to serve.
fn fixture(on_disk: bool) -> Fixture {
    let home = on_disk.then(|| tempfile::tempdir().unwrap());
    let (mut db, account) = match &home {
        Some(home) => wallet_on_disk(home.path()),
        None => wallet(),
    };
    let (chain, cast) = catalogue(&mut db, account);
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    let dir = tempfile::tempdir().unwrap();
    let map = publish_layout(
        dir.path(),
        &extract(&chain),
        DEFAULT_LAYOUT,
        tiers,
        0,
        "",
        chain.hash_fn(),
    );
    Fixture {
        db,
        account,
        chain,
        cast,
        map,
        dir,
        home,
    }
}

impl Fixture {
    fn expected(&self) -> Expected {
        reduce(&self.chain, &self.cast.all, FIRST, self.chain.last())
    }

    /// What a fresh wallet with the same scripts asks to read the whole set.
    async fn fresh(&self) -> Counting {
        let (mut db, account) = wallet();
        let (chain, _) = catalogue(&mut db, account);
        accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
        let base = serve(self.dir.path()).await;
        let (_, whole, progress) =
            recover(db, base, self.dir.path(), &self.map, WorkLimits::UNLIMITED).await;
        complete(&progress.unwrap());
        whole
    }
}

/// Everything held is true, nothing is complete, the anchor did not move.
fn assert_kept(before: &Snapshot, db: &mut WalletDb, account: AccountId, expected: &Expected) {
    let after = Snapshot::of(db);
    assert_progress_kept(before, &after);
    for (script, event) in stored_events(db) {
        let fact = Fact::of(&script, &event);
        assert!(
            expected.events.contains(&fact),
            "an event the chain never produced was committed: {fact:?}"
        );
    }
    assert_projection_matches_ledger(db, account);
}

/// The next unfaulted run finishes, exactly, asking no more than a fresh wallet.
async fn assert_converges(mut fx: Fixture, fresh: &Counting) -> Fixture {
    let base = serve(fx.dir.path()).await;
    let owed: u64 = fx
        .db
        .transparent_pending()
        .unwrap()
        .iter()
        .map(|p| u64::from(p.page_count - p.next_ordinal))
        .sum();
    let db = std::mem::replace(&mut fx.db, test_db_placeholder());
    let (mut db, second, progress) =
        recover(db, base, fx.dir.path(), &fx.map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    assert!(db.transparent_pending().unwrap().is_empty());
    assert!(
        second.queries <= fresh.queries,
        "resuming ({}) cost more than starting over ({})",
        second.queries,
        fresh.queries
    );
    assert!(
        second.queries >= owed,
        "every owed page ({owed}) was fetched, in {} queries",
        second.queries
    );
    compare_blocks(&mut db, fx.account, &fx.expected());
    assert_projection_matches_ledger(&mut db, fx.account);
    assert_eq!(
        state(&db, fx.account).completion.as_deref(),
        Some("complete")
    );
    fx.db = db;
    fx
}

fn test_db_placeholder() -> WalletDb {
    zakura_wallet_store::testing::test_db().unwrap()
}

// -------------------------------------------- store faults, one pass

async fn store_fault(
    plan: FaultPlan,
    on_disk: bool,
) -> (
    Fixture,
    Snapshot,
    Result<(), SyncError>,
    Option<ShardCommit>,
    Counting,
) {
    let mut fx = fixture(on_disk);
    let base = serve(fx.dir.path()).await;
    fx.db
        .put_transparent_completion("sync-in-progress")
        .unwrap();
    let before = Snapshot::of(&fx.db);
    let db = std::mem::replace(&mut fx.db, test_db_placeholder());
    let dir = fx.dir.path().to_path_buf();
    let map = fx.map.clone();
    let (db, transport, result, commit, fired) = tokio::task::spawn_blocking(move || {
        let mut db = db;
        let mut filters = Filters::load(&dir, &map);
        let mut transport = Counting::new(&base);
        let (result, commit, fired) =
            run_pass_with_store(&mut db, plan, &mut filters, &mut transport);
        (db, transport, result, commit, fired)
    })
    .await
    .unwrap();
    assert!(fired, "the planned fault was reached: {plan:?}");
    fx.db = db;
    (fx, before, result, commit, transport)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_store_failure_before_a_shard_commit_leaves_the_prior_state_exactly() {
    let plan = FaultPlan {
        at: Boundary::CommitShard,
        when: 2,
        how: How::ErrBefore,
    };
    let (mut fx, before, result, commit, _) = store_fault(plan, false).await;
    let error = result.expect_err("the injected failure ends the pass");
    assert!(format!("{error}").contains("injected"), "{error}");
    let refused = commit.expect("the second commit was refused before it was written");
    let after = Snapshot::of(&fx.db);
    assert_eq!(after.last_commit, 1, "exactly the first commit landed");
    assert!(
        after.events.iter().all(|e| e.shard_id != refused.shard_id),
        "nothing from the refused commit's shard was written"
    );
    assert_eq!(
        after.completion.as_deref(),
        Some("sync-in-progress"),
        "one pass without the run's bookkeeping leaves the word it started with"
    );
    let expected = fx.expected();
    assert_kept(&before, &mut fx.db, fx.account, &expected);
    let fresh = fx.fresh().await;
    assert_converges(fx, &fresh).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_landed_commit_the_caller_never_heard_of_is_not_repeated() {
    // The first commit is the first shard's, whose scripts owe no pages and
    // whose directory nothing later re-reads.
    let plan = FaultPlan {
        at: Boundary::CommitShard,
        when: 1,
        how: How::ErrAfter,
    };
    let (mut fx, before, result, commit, _) = store_fault(plan, false).await;
    result.expect_err("the pass ends on the reported failure");
    let landed = commit.expect("the first commit landed before the failure was reported");
    assert_eq!(landed.shard_id, 0);
    assert!(
        landed.pending_upsert.is_empty(),
        "the first shard owes no pages"
    );
    let after = Snapshot::of(&fx.db);
    assert_eq!(after.last_commit, 1, "the commit that landed is counted");
    assert!(after.events.iter().any(|e| e.shard_id == landed.shard_id) || landed.events.is_empty());
    let expected = fx.expected();
    assert_kept(&before, &mut fx.db, fx.account, &expected);

    // The contract's idempotence, directly: the same commit again writes
    // only a commit record.
    let events_before = after.events.clone();
    {
        let owners = fx
            .db
            .transparent_watch()
            .unwrap()
            .addresses
            .into_iter()
            .map(|a| (a.script, a.account))
            .collect();
        let mut store = PirStore::new(&mut fx.db, owners);
        store
            .commit_shard(landed.clone())
            .expect("an identical retry is accepted");
    }
    let again = Snapshot::of(&fx.db);
    assert_eq!(again.events, events_before, "a retry writes no event");
    assert_eq!(again.last_commit, 2, "and one commit record");

    // The resume does not query the landed shard's directory again.
    let faults = Faults::none();
    let (base, _) = serve_with(fx.dir.path(), faults.clone()).await;
    let db = std::mem::replace(&mut fx.db, test_db_placeholder());
    let (mut db, second, progress) =
        recover(db, base, fx.dir.path(), &fx.map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    let directory_queries = faults
        .lock()
        .unwrap()
        .arrivals
        .get(&(landed.shard_id, "directory".to_owned()))
        .copied()
        .unwrap_or(0);
    assert_eq!(
        directory_queries, 0,
        "the landed directory commit is not re-read"
    );
    assert!(second.queries > 0);
    compare_blocks(&mut db, fx.account, &expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_panic_in_a_run_leaves_no_completion_and_no_partial_shard() {
    let plan = FaultPlan {
        at: Boundary::CommitShard,
        when: 2,
        how: How::PanicBefore,
    };
    let fx = fixture(true);
    let home = fx.home.as_ref().unwrap().path().to_path_buf();
    let base = serve(fx.dir.path()).await;
    let mut fx = fx;
    fx.db
        .put_transparent_completion("sync-in-progress")
        .unwrap();
    let before = Snapshot::of(&fx.db);
    let db = std::mem::replace(&mut fx.db, test_db_placeholder());
    let dir = fx.dir.path().to_path_buf();
    let map = fx.map.clone();
    let joined = tokio::task::spawn_blocking(move || {
        let mut db = db;
        let mut filters = Filters::load(&dir, &map);
        let mut transport = Counting::new(&base);
        let _ = run_pass_with_store(&mut db, plan, &mut filters, &mut transport);
        // The wallet is dropped with the panic; nothing hands it back.
    })
    .await;
    assert!(joined.unwrap_err().is_panic(), "the pass died");

    // The files outlive the process that died on them.
    let mut db = reopen(&home);
    for file in ["wallet.db", "cache.db"] {
        let ok: String = db
            .connection()
            .query_row(
                &format!(
                    "PRAGMA {}.integrity_check",
                    if file == "wallet.db" { "main" } else { "cache" }
                ),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ok, "ok", "{file} is intact");
    }
    let after = Snapshot::of(&db);
    assert_eq!(after.last_commit, 1);
    assert_eq!(after.anchor, None);
    assert_eq!(
        after.completion.as_deref(),
        Some("sync-in-progress"),
        "a dead run cannot write its reason; the facade turns this into `interrupted` on open"
    );
    let expected = fx.expected();
    assert_kept(&before, &mut db, fx.account, &expected);
    fx.db = db;
    let fresh = fx.fresh().await;
    assert_converges(fx, &fresh).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failure_at_the_anchor_commit_keeps_every_shard_and_no_anchor() {
    // The first pass completes and commits an anchor; the window it widened
    // is read by the second, whose anchor commit is the one that fails.
    let plan = FaultPlan {
        at: Boundary::CommitAnchor,
        when: 2,
        how: How::ErrBefore,
    };
    let (mut fx, before, result, _, first) = store_fault(plan, false).await;
    result.expect_err("the anchor commit failed");
    let after = Snapshot::of(&fx.db);
    assert_eq!(
        after.anchor.as_ref().map(|a| a.height),
        Some(h(fx.chain.last())),
        "the first pass's anchor stands; the second pass's was refused"
    );
    assert!(
        after.pending.is_empty(),
        "every page was fetched before the anchor was attempted"
    );
    let expected = fx.expected();
    let facts: std::collections::BTreeSet<Fact> = stored_events(&fx.db)
        .iter()
        .map(|(s, e)| Fact::of(s, e))
        .collect();
    assert_eq!(
        facts, expected.events,
        "every event is held; only the second anchor is missing"
    );
    assert!(after.last_commit > before.last_commit);
    assert_ne!(after.completion.as_deref(), Some("complete"));
    assert_projection_matches_ledger(&mut fx.db, fx.account);

    let base = serve(fx.dir.path()).await;
    let db = std::mem::replace(&mut fx.db, test_db_placeholder());
    let (mut db, second, progress) =
        recover(db, base, fx.dir.path(), &fx.map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    assert_eq!(second.queries, 0, "nothing is asked again");
    assert!(second.opened.is_empty());
    let commits: Vec<(String, String)> = db
        .connection()
        .prepare("SELECT kind, detail FROM cache.transparent_commits WHERE id > ?1 ORDER BY id")
        .unwrap()
        .query_map([after.last_commit], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(
        commits.iter().any(|(kind, _)| kind == "anchor"),
        "the anchor is committed: {commits:?}"
    );
    assert_eq!(
        Snapshot::of(&db).events,
        after.events,
        "no event is written again: {commits:?}"
    );
    assert!(first.queries > 0);
    compare_blocks(&mut db, fx.account, &expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_filter_kept_before_a_failure_is_not_read_again() {
    let plan = FaultPlan {
        at: Boundary::PutFilter,
        when: 1,
        how: How::ErrAfter,
    };
    let (mut fx, before, result, _, _) = store_fault(plan, false).await;
    result.expect_err("the pass ends on the reported failure");
    let kept: i64 = fx
        .db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.transparent_filter_cache",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kept, 1, "the filter that was written stays written");
    let expected = fx.expected();
    assert_kept(&before, &mut fx.db, fx.account, &expected);

    let base = serve(fx.dir.path()).await;
    let filters = SharedFilters::new(Filters::load(fx.dir.path(), &fx.map));
    let db = std::mem::replace(&mut fx.db, test_db_placeholder());
    let (mut db, filters, _, progress) =
        recover_through(db, filters.clone(), move || Counting::new(&base), pir()).await;
    complete(&progress.unwrap());
    assert_eq!(
        filters.filter_reads(),
        SHARDS - 1,
        "the kept filter is served from the store; the others are read once"
    );
    compare_blocks(&mut db, fx.account, &expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_kept_before_a_failure_is_not_fetched_again() {
    let plan = FaultPlan {
        at: Boundary::PutSetup,
        when: 1,
        how: How::ErrAfter,
    };
    let (mut fx, before, result, _, first) = store_fault(plan, false).await;
    result.expect_err("the pass ends on the reported failure");
    let kept: i64 = fx
        .db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.transparent_setup_cache",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kept, 1, "the setup that was written stays written");
    let opened_first = first.opened.clone();
    assert_eq!(
        opened_first.len(),
        1,
        "the failure came during the first shard's setup"
    );
    let expected = fx.expected();
    assert_kept(&before, &mut fx.db, fx.account, &expected);

    let base = serve(fx.dir.path()).await;
    let db = std::mem::replace(&mut fx.db, test_db_placeholder());
    let (mut db, second, progress) =
        recover(db, base, fx.dir.path(), &fx.map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    // The kept segment is not fetched again; the shard has more than one
    // segment only if its geometry needs it, so count setups rather than
    // shards.
    let fresh = fx.fresh().await;
    assert_eq!(
        second.setups_by_shard.values().sum::<u64>() + 1,
        fresh.setups_by_shard.values().sum::<u64>(),
        "one setup segment fewer than a fresh wallet fetches"
    );
    compare_blocks(&mut db, fx.account, &expected);
}

// ---------------------------------------------- service faults, whole run

/// A run through a faulted service: the wallet, the transport, the result.
async fn faulted_run(
    fx: &mut Fixture,
    faults: Arc<Mutex<Faults>>,
) -> (
    Counting,
    Result<zakura_wallet_sync::TransparentProgress, zakura_wallet_transparent::Error>,
    ServerHandle,
) {
    let (base, handle) = serve_with(fx.dir.path(), faults).await;
    let db = std::mem::replace(&mut fx.db, test_db_placeholder());
    let (db, transport, result) =
        recover(db, base, fx.dir.path(), &fx.map, WorkLimits::UNLIMITED).await;
    fx.db = db;
    (transport, result, handle)
}

async fn tampered(
    tamper: Tamper,
) -> (
    Fixture,
    Snapshot,
    Counting,
    Result<zakura_wallet_sync::TransparentProgress, zakura_wallet_transparent::Error>,
    Arc<Mutex<Faults>>,
) {
    let mut fx = fixture(false);
    let before = Snapshot::of(&fx.db);
    let faults = Faults::tamper(tamper);
    let (transport, result, _) = faulted_run(&mut fx, faults.clone()).await;
    assert_eq!(faults.lock().unwrap().tampered, 1, "the tamper landed");
    (fx, before, transport, result, faults)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_setup_segment_is_refused_before_it_is_kept() {
    let (mut fx, before, _, result, _) = tampered(Tamper::Setup {
        shard: 1,
        segment: 0,
    })
    .await;
    let error =
        result.expect_err("published parameters that do not digest to the manifest are refused");
    assert!(!error.is_stopped());
    let after = Snapshot::of(&fx.db);
    assert_eq!(after.completion.as_deref(), Some("failed"));
    let kept: i64 = fx
        .db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.transparent_setup_cache WHERE revision_digest = ?1",
            [&fx.map.shards[1].manifest_digest],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kept, 0, "nothing of the tampered setup was kept");
    assert!(
        after.events.iter().all(|e| e.shard_id != 1),
        "nothing from the shard was read"
    );
    let expected = fx.expected();
    assert_kept(&before, &mut fx.db, fx.account, &expected);
    let fresh = fx.fresh().await;
    assert_converges(fx, &fresh).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_manifest_is_refused_and_nothing_from_the_shard_is_read() {
    let (mut fx, before, transport, result, _) = tampered(Tamper::Manifest { shard: 1 }).await;
    let error = result.expect_err("a manifest that does not digest to the map is refused");
    assert!(
        format!("{error}").to_lowercase().contains("manifest")
            || format!("{error}").to_lowercase().contains("digest"),
        "{error}"
    );
    assert!(
        !transport.queried.contains(&1),
        "no private query went to the shard"
    );
    assert_eq!(Snapshot::of(&fx.db).completion.as_deref(), Some("failed"));
    let expected = fx.expected();
    assert_kept(&before, &mut fx.db, fx.account, &expected);
    let fresh = fx.fresh().await;
    assert_converges(fx, &fresh).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_page_answer_is_never_committed() {
    // Shard 1 holds the paged history. The first page answer is corrupted
    // in flight. Whatever the run does with it — refuse it, stop short —
    // nothing the chain did not produce may reach the ledger.
    let (mut fx, before, _, result, _) = tampered(Tamper::Page { shard: 1, nth: 1 }).await;
    let expected = fx.expected();
    match &result {
        Ok(progress) => assert_ne!(
            progress.completion,
            TransparentCompletion::Complete,
            "a corrupted answer cannot complete a run"
        ),
        Err(error) => assert!(!error.is_stopped(), "{error}"),
    }
    assert_ne!(Snapshot::of(&fx.db).completion.as_deref(), Some("complete"));
    assert_kept(&before, &mut fx.db, fx.account, &expected);
    let fresh = fx.fresh().await;
    assert_converges(fx, &fresh).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_directory_answer_is_never_committed() {
    let (mut fx, before, _, result, _) = tampered(Tamper::Directory { shard: 0, nth: 1 }).await;
    let expected = fx.expected();
    match &result {
        Ok(progress) => assert_ne!(progress.completion, TransparentCompletion::Complete),
        Err(error) => assert!(!error.is_stopped(), "{error}"),
    }
    assert_ne!(Snapshot::of(&fx.db).completion.as_deref(), Some("complete"));
    assert_kept(&before, &mut fx.db, fx.account, &expected);
    let fresh = fx.fresh().await;
    assert_converges(fx, &fresh).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_lost_between_queries_fails_the_run_and_resumes_exactly() {
    let mut fx = fixture(false);
    let before = Snapshot::of(&fx.db);
    let base = serve(fx.dir.path()).await;
    let filters = Filters::load(fx.dir.path(), &fx.map);
    let db = std::mem::replace(&mut fx.db, test_db_placeholder());
    let (db, _, cut, result) =
        recover_through(db, filters, move || Cut::new(&base, 3), pir()).await;
    fx.db = db;
    let error = result.expect_err("a lost connection fails the run");
    assert!(!error.is_stopped());
    assert!(cut.inner.queries >= 3);
    let after = Snapshot::of(&fx.db);
    assert_eq!(after.completion.as_deref(), Some("failed"));
    assert!(
        after.last_commit > 0 || cut.inner.queries < 4,
        "what was committed before the cut is kept"
    );
    let expected = fx.expected();
    assert_kept(&before, &mut fx.db, fx.account, &expected);
    let fresh = fx.fresh().await;
    assert_converges(fx, &fresh).await;
}

/// A transport that stops the service after a number of private queries.
struct Vanishing {
    inner: Counting,
    handle: Arc<ServerHandle>,
    after: u64,
}

impl ShardTransport for Vanishing {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.inner.init()
    }
    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        self.inner.manifest(shard_id, revision)
    }
    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        self.inner.setup(shard_id, revision, table, segment)
    }
    fn query(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        let answer = self.inner.query(shard_id, revision, table, body)?;
        if self.inner.queries >= self.after {
            self.handle.stop();
        }
        Ok(answer)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_service_that_vanishes_mid_run_leaves_the_wallet_resumable() {
    let mut fx = fixture(false);
    let before = Snapshot::of(&fx.db);
    let (base, handle) = serve_with(fx.dir.path(), Faults::none()).await;
    let handle = Arc::new(handle);
    let filters = Filters::load(fx.dir.path(), &fx.map);
    let db = std::mem::replace(&mut fx.db, test_db_placeholder());
    let (db, _, gone, result) = recover_through(
        db,
        filters,
        move || Vanishing {
            inner: Counting::new(&base),
            handle,
            after: 3,
        },
        pir(),
    )
    .await;
    fx.db = db;
    let error = result.expect_err("a service that is gone fails the run");
    assert!(!error.is_stopped());
    assert!(
        gone.inner.queries >= 3 && gone.inner.queries < 8,
        "the run ended at the next request, after {} queries",
        gone.inner.queries
    );
    assert_eq!(Snapshot::of(&fx.db).completion.as_deref(), Some("failed"));
    let expected = fx.expected();
    assert_kept(&before, &mut fx.db, fx.account, &expected);
    let fresh = fx.fresh().await;
    assert_converges(fx, &fresh).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_brief_overload_is_waited_out_and_the_run_completes_exactly() {
    let mut fx = fixture(false);
    let unfaulted = Instant::now();
    let fresh = fx.fresh().await;
    let unfaulted = unfaulted.elapsed();
    let faults = Faults::overload(2, Some("0"));
    let started = Instant::now();
    let (transport, result, _) = faulted_run(&mut fx, faults.clone()).await;
    let waited = started.elapsed();
    let progress = result.expect("a refusal that names a delay is waited out");
    complete(&progress);
    assert_eq!(faults.lock().unwrap().refused, 2);
    assert!(
        transport.queries >= fresh.queries,
        "the refused queries are re-asked: {} against a fresh {}",
        transport.queries,
        fresh.queries
    );
    // Two refusals naming no wait cost two re-asked queries, not a backoff:
    // the run is not much slower than one nobody refused, allowing for a
    // machine that is running the rest of this suite at the same time.
    assert!(
        waited < unfaulted * 3 + std::time::Duration::from_secs(10),
        "a named delay of zero is not a long wait: {waited:?} against {unfaulted:?} unfaulted"
    );
    let expected = fx.expected();
    compare_blocks(&mut fx.db, fx.account, &expected);
    assert_eq!(
        state(&fx.db, fx.account).completion.as_deref(),
        Some("complete")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unrelenting_overload_is_named_and_keeps_pending_work_durable() {
    let mut fx = fixture(false);
    let before = Snapshot::of(&fx.db);
    let faults = Faults::overload(u64::MAX, Some("0"));
    let (transport, result, _) = faulted_run(&mut fx, faults.clone()).await;
    let progress = result.expect("overload is a reason, not a failure");
    let reason = match &progress.completion {
        TransparentCompletion::Incomplete(reason) => reason.clone(),
        other => panic!("{other:?}"),
    };
    assert!(reason.starts_with("overloaded:"), "{reason}");
    let shard: u64 = reason.split(':').next_back().unwrap().parse().unwrap();
    assert!(transport.queried.contains(&shard));
    assert_eq!(
        faults.lock().unwrap().refused,
        4,
        "one attempt per bounded retry, then the run stops and says why"
    );
    let after = Snapshot::of(&fx.db);
    assert_eq!(after.completion.as_deref(), Some(reason.as_str()));
    assert_eq!(after.anchor, None);
    let expected = fx.expected();
    assert_kept(&before, &mut fx.db, fx.account, &expected);
    let fresh = fx.fresh().await;
    assert_converges(fx, &fresh).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_503_without_a_delay_fails_the_run_rather_than_spinning() {
    let mut fx = fixture(false);
    let before = Snapshot::of(&fx.db);
    let faults = Faults::overload(1, None);
    let started = Instant::now();
    let (_, result, _) = faulted_run(&mut fx, faults.clone()).await;
    let error = result.expect_err("a 503 that names no delay is not an overload to wait out");
    assert!(!error.is_stopped());
    assert!(
        started.elapsed().as_secs() < 10,
        "no backoff was spent on it"
    );
    assert_eq!(faults.lock().unwrap().refused, 1);
    assert_eq!(Snapshot::of(&fx.db).completion.as_deref(), Some("failed"));
    let expected = fx.expected();
    assert_kept(&before, &mut fx.db, fx.account, &expected);
    let fresh = fx.fresh().await;
    assert_converges(fx, &fresh).await;
}

/// The catalogue's tail republished with one more receive, superseding the
/// tail the wallet is reading.
fn replaced_tail(fx: &Fixture) -> (Chain, tempfile::TempDir, ShardMap) {
    let mut chain_b = fx.chain.clone();
    let late = shard_bounds(3).0 + 170;
    chain_b.pay(late, fx.cast.ext[1].clone(), 600);
    let dir_b = tempfile::tempdir().unwrap();
    let map_b = publish_layout(
        dir_b.path(),
        &extract(&chain_b),
        DEFAULT_LAYOUT,
        tiers,
        1,
        &fx.map.shards[3].manifest_digest,
        chain_b.hash_fn(),
    );
    assert_ne!(
        map_b.shards[3].manifest_digest,
        fx.map.shards[3].manifest_digest
    );
    (chain_b, dir_b, map_b)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tail_replaced_between_queries_is_refreshed_and_re_derived_in_the_same_run() {
    let mut fx = fixture(false);
    let (chain_b, dir_b, map_b) = replaced_tail(&fx);
    let base_a = serve(fx.dir.path()).await;
    let base_b = serve(dir_b.path()).await;
    let filters = SharedFilters::new(Filters::load(fx.dir.path(), &fx.map));
    let shared = filters.clone();
    let replacement = (dir_b.path().to_path_buf(), map_b.clone());
    let db = std::mem::replace(&mut fx.db, test_db_placeholder());
    let (mut db, filters, transport, result) = recover_through(
        db,
        filters,
        move || SwitchAfter {
            a: Counting::new(&base_a),
            b: Counting::new(&base_b),
            after: 3,
            filters: shared,
            replacement,
            switched: false,
        },
        pir(),
    )
    .await;
    let progress = result.expect("a replaced tail is refreshed within the run");
    complete(&progress);
    assert!(transport.switched, "the switch happened mid-run");
    assert_eq!(
        progress.rolled_back_to,
        Some(h(shard_bounds(3).0 - 1)),
        "coverage from the old tail is truncated"
    );
    assert!(
        filters.map_reads() >= 2 && filters.map_reads() <= 5,
        "the map was refreshed, within the library's bound: {} reads",
        filters.map_reads()
    );
    let expected = reduce(&chain_b, &fx.cast.all, FIRST, chain_b.last());
    assert!(expected.utxos.values().any(|(_, v, _, _)| *v == 600));
    compare_blocks(&mut db, fx.account, &expected);
    assert!(
        db.transparent_provisional_coverage()
            .unwrap()
            .iter()
            .all(|r| r.revision_digest == map_b.shards[3].manifest_digest)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_work_for_a_replaced_revision_is_discarded_not_fetched() {
    // Pages owed in the tail belong to a revision; when the tail is replaced
    // before they are fetched, they go with it and no query names them.
    let mut fx = fixture(false);
    let tail_start = shard_bounds(3).0;
    for i in 0..long_history() {
        fx.chain
            .pay(tail_start + 60 + i % 100, fx.cast.ext[8].clone(), 13);
    }
    // Republish A with the paged tail.
    let dir_a = tempfile::tempdir().unwrap();
    fx.map = publish_layout(
        dir_a.path(),
        &extract(&fx.chain),
        DEFAULT_LAYOUT,
        tiers,
        0,
        "",
        fx.chain.hash_fn(),
    );
    fx.dir = dir_a;
    let base_a = serve(fx.dir.path()).await;
    let old_digest = fx.map.shards[3].manifest_digest.clone();

    let mut found = false;
    for budget in [12u64, 16, 20, 24, 28, 32, 40, 48, 64] {
        let db = std::mem::replace(&mut fx.db, test_db_placeholder());
        let (db, _, progress) = recover(
            db,
            base_a.clone(),
            fx.dir.path(),
            &fx.map,
            WorkLimits {
                max_queries: Some(budget),
                max_private_bytes: None,
            },
        )
        .await;
        fx.db = db;
        let progress = progress.unwrap();
        if fx
            .db
            .transparent_pending()
            .unwrap()
            .iter()
            .any(|p| p.shard_id == 3)
        {
            found = true;
            break;
        }
        if progress.completion == TransparentCompletion::Complete {
            break;
        }
    }
    assert!(found, "a budget left pages owed in the tail");
    assert!(
        fx.db
            .transparent_pending()
            .unwrap()
            .iter()
            .any(|p| p.revision_digest == old_digest)
    );

    let (chain_b, dir_b, map_b) = replaced_tail(&fx);
    let base_b = serve(dir_b.path()).await;
    let filters = SharedFilters::new(Filters::load(dir_b.path(), &map_b));
    let db = std::mem::replace(&mut fx.db, test_db_placeholder());
    let (mut db, _, transport, result) =
        recover_through(db, filters, move || Counting::new(&base_b), pir()).await;
    let progress = result.unwrap();
    complete(&progress);
    assert!(
        !transport.revisions.contains(&old_digest),
        "no query names the replaced revision"
    );
    assert!(db.transparent_pending().unwrap().is_empty());
    let expected = reduce(&chain_b, &fx.cast.all, FIRST, chain_b.last());
    compare_blocks(&mut db, fx.account, &expected);
}

// ------------------------------------------------- stops and repetition

#[tokio::test(flavor = "multi_thread")]
async fn a_stop_at_every_request_boundary_never_commits_completion() {
    let probe = fixture(false);
    let fresh = probe.fresh().await;
    let total = fresh.queries;
    assert!(
        total >= 8,
        "the catalogue takes at least a few queries: {total}"
    );
    let expected = probe.expected();
    for n in 1..=total {
        let mut fx = fixture(false);
        let before = Snapshot::of(&fx.db);
        let base = serve(probe.dir.path()).await;
        let signal = zakura_wallet_transparent::StopSignal::new();
        let stopper = signal.clone();
        let base_for_run = base.clone();
        let filters = Filters::load(probe.dir.path(), &probe.map);
        let db = std::mem::replace(&mut fx.db, test_db_placeholder());
        let (db, _, stopped, result) = recover_through(
            db,
            filters,
            move || StopAfter {
                inner: Counting::new(&base_for_run),
                signal: stopper,
                after: n,
            },
            pir().with_stop(signal),
        )
        .await;
        fx.db = db;
        let error = result.expect_err("a stopped run reports no completion");
        assert!(error.is_stopped(), "stop after {n}: {error}");
        assert!(
            stopped.inner.queries >= n && stopped.inner.queries <= n + 1,
            "stop after {n} landed at the next request: {}",
            stopped.inner.queries
        );
        let after = Snapshot::of(&fx.db);
        assert_eq!(
            after.completion.as_deref(),
            Some("stopped"),
            "stop after {n}"
        );
        // A stop that lands after the last query of a complete pass leaves
        // that pass's anchor: every script then in scope was read to the
        // target. The word beside it is still `stopped`, because the pass
        // the widened window needed never ran.
        match &after.anchor {
            None => {}
            Some(anchor) => assert_eq!(anchor.height, h(probe.chain.last()), "stop after {n}"),
        }
        for (script, event) in stored_events(&fx.db) {
            assert!(
                expected.events.contains(&Fact::of(&script, &event)),
                "stop after {n}"
            );
        }
        assert!(after.last_commit >= before.last_commit);
        assert_projection_matches_ledger(&mut fx.db, fx.account);
        // Resume on the same service.
        let db = std::mem::replace(&mut fx.db, test_db_placeholder());
        let (mut db, second, progress) = recover(
            db,
            base,
            probe.dir.path(),
            &probe.map,
            WorkLimits::UNLIMITED,
        )
        .await;
        complete(&progress.unwrap());
        assert!(
            second.queries <= total,
            "stop after {n}: resuming cost {} against {total}",
            second.queries
        );
        compare_blocks(&mut db, fx.account, &expected);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_partial_runs_converge_to_one_ledger_without_duplicates() {
    let mut fx = fixture(false);
    let expected = fx.expected();
    let base = serve(fx.dir.path()).await;
    let mut last_commit = 0;
    let mut runs = 0;
    let mut total_queries = 0;
    for budget in [1u64, 2, 3, 5].iter().cycle() {
        let db = std::mem::replace(&mut fx.db, test_db_placeholder());
        let (db, transport, progress) = recover(
            db,
            base.clone(),
            fx.dir.path(),
            &fx.map,
            WorkLimits {
                max_queries: Some(*budget),
                max_private_bytes: None,
            },
        )
        .await;
        fx.db = db;
        runs += 1;
        total_queries += transport.queries;
        let progress = progress.unwrap();
        let commit = fx.db.transparent_last_commit().unwrap();
        assert!(commit >= last_commit, "commits are monotone");
        last_commit = commit;
        assert_projection_matches_ledger(&mut fx.db, fx.account);
        if progress.completion == TransparentCompletion::Complete {
            break;
        }
        assert!(runs < 200, "the runs converge");
    }
    let fresh = fx.fresh().await;
    assert!(runs > 3, "the budgets made it take several runs: {runs}");
    assert!(
        total_queries <= fresh.queries + runs * (SHARDS + 2),
        "each run re-reads at most a directory row per matched shard: {total_queries} over {runs} runs against {}",
        fresh.queries
    );
    compare_blocks(&mut fx.db, fx.account, &expected);
    // Every event once: the store keys events by identity, and the count
    // agrees with the reducer's.
    assert_eq!(
        stored_events(&fx.db)
            .iter()
            .filter(|(s, _)| fx.cast.all.iter().any(|m| m.as_slice() == s.as_slice()))
            .count(),
        expected.events.len()
    );
    let _ = ScriptBytes::new(vec![]);
    let _: Option<TransparentEvent> = None;
}
