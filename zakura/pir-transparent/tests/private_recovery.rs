//! Private recovery end to end: a wallet recovers its transparent history from a
//! transparent shard service running in process, over loopback HTTP and real
//! PIR, through `TransparentHistoryRecovery` and the wallet's trusted commit operation.
//!
//! The service records every request it receives, so the tests also check what
//! a private pass discloses: only the service's routes, no script of the
//! account's in any path, query, header or body, and no request for a shard
//! wholly below the account's birthday.

mod fixture;

use std::{
    collections::{BTreeSet, HashSet},
    path::PathBuf,
    sync::{Mutex, PoisonError},
    time::Duration,
};

use fixture::{GEOMETRY, Loopback, SEAL, Server, ShardSpec, WIDE, synthetic};
use regex::Regex;
use rusqlite::{Connection, OpenFlags, types::Value};
use transparent::{
    address::TransparentAddress,
    bundle::OutPoint,
    keys::{IncomingViewingKey as _, NonHardenedChildIndex, TransparentKeyScope},
};
use transparent_events::{ReceiveEvent, SpendEvent, TransparentEvent, Txid};
use transparent_filter::{Recut, ScriptBytes, SealParameters, ShardMap};
use transparent_wallet::http::{HttpOptions, HttpShardTransport};
use zakura_pir_transparent::{
    ApplyAction, ApplyError, BatchState, Companion, CompanionDir, ForgetError, HoldCause,
    Interrupted, Outcome, PassError, PassLimits, PassPlan, PassReport, Progress, RecoveryBatch,
    Retry, ShardTransport, Step, TransparentHistoryRecoveryConfig, Trust, Ungated, WalletChain,
    WithdrawnCause, WriteGate, forget_private_recovery,
};
use zcash_client_backend::data_api::{
    Account as _, CoinbaseFilter, InputSource as _, WalletRead as _,
    chain::ChainState,
    testing::{InitialChainState, TestBuilder, TestState},
    transparent_ledger::{
        AccountLifecycle, CommitRejection, ForgottenTransparentLedger, RecoveryRevision,
        StaleCommit, TransparentAddressWatchSet, TransparentAuthority, TransparentLedgerCommit,
        TransparentLedgerMode::{self, PrivateRequired},
        TransparentLedgerRead as _, TransparentLedgerWrite as _, WatchOrigin,
    },
    wallet::{
        ConfirmationsPolicy, TargetHeight,
        input_selection::{LockFilter, LockedInputPolicy},
    },
};
use zcash_client_sqlite::{
    AccountUuid,
    error::{AuthorityRefusal, SqliteClientError},
    testing::{
        BlockCache,
        db::{TestDb, TestDbFactory},
    },
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork};

type State = TestState<BlockCache, TestDb, LocalNetwork>;

/// The first height the fixture publishes, a mainnet height.
const H0: u64 = 3_428_143;

/// The identity origin every companion is bound to. Each publication has its own
/// loopback server; the transports reach it, and the origin never changes.
const ORIGIN: &str = "https://fixture.test";

/// Every route the service serves a wallet, with its method: queries are the
/// only uploads. Page tables are named per page shard, `pages-<j>`.
const ROUTES: &str = r"^(GET /v2/(filters/shards(/[0-9]+/filter)?|shards/init|shards/[0-9]+/revisions/[0-9a-f]{64}/(manifest|setup/(directory|pages-(0|[1-9][0-9]?))/[0-9]+))|POST /v2/shards/[0-9]+/revisions/[0-9a-f]{64}/query/(directory|pages-(0|[1-9][0-9]?)))$";

/// The shard a request's path names: its filter, manifest, tables or queries.
const SHARD: &str = r"^/v2/(filters/)?shards/([0-9]+)/";

/// A pages query's revision and page shard.
const PAGES_QUERY: &str = r"^/v2/shards/[0-9]+/revisions/([0-9a-f]{64})/query/pages-([0-9]+)$";

/// What a pass over a map that rewrites sealed history the companion's store
/// holds, without declaring a re-cut, returns: wallet-pir refuses it before
/// reading anything, and no later pass repairs it.
const UNDECLARED_REWRITE: BatchState = BatchState::Withdrawn(WithdrawnCause::ChangedSealed);

/// The largest successful response body a pass accepts.
const RESPONSE_LIMIT: usize = 64 << 20;

/// Each test runs a PIR service and wallet; one at a time keeps memory and CPU
/// bounded.
static HEAVY: Mutex<()> = Mutex::new(());

/// Vizor's per-pass limits.
fn config(account: AccountUuid) -> TransparentHistoryRecoveryConfig {
    TransparentHistoryRecoveryConfig {
        source: b"fixture/transparent-pir/v1".to_vec(),
        account_binding: account.expose_uuid().as_bytes().to_vec(),
        origin: ORIGIN.into(),
        scripts: 10_000,
        shards: 1_024,
        events: 500_000,
        queries: 256,
        private_bytes: 96 << 20,
    }
}

fn pubkey_hash(address: TransparentAddress) -> [u8; 20] {
    match address {
        TransparentAddress::PublicKeyHash(hash) => hash,
        TransparentAddress::ScriptHash(_) => panic!("derived addresses pay to public key hashes"),
    }
}

fn script(address: TransparentAddress) -> ScriptBytes {
    ScriptBytes::new([&[0x76, 0xa9, 20][..], &pubkey_hash(address), &[0x88, 0xac]].concat())
}

/// A script no account derives.
fn unrelated(tag: u32) -> ScriptBytes {
    let mut bytes = vec![0x76, 0xa9, 20];
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&[0xee; 16]);
    bytes.extend_from_slice(&[0x88, 0xac]);
    ScriptBytes::new(bytes)
}

fn txid(tag: u64) -> Txid {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&tag.to_le_bytes());
    bytes[31] = 0x77;
    Txid(bytes)
}

fn receive(height: u64, txid: Txid, output_index: u32, value: u64) -> TransparentEvent {
    TransparentEvent::Receive(ReceiveEvent {
        metadata: None,
        height: height as u32,
        txid,
        transaction_index: 1,
        output_index,
        value,
        coinbase: false,
    })
}

fn spend(height: u64, spending: Txid, spent: (Txid, u32)) -> TransparentEvent {
    TransparentEvent::Spend(SpendEvent {
        metadata: None,
        height: height as u32,
        spending_txid: spending,
        transaction_index: 2,
        input_index: 0,
        spent_txid: spent.0,
        spent_output_index: spent.1,
    })
}

/// The wallet's identity for a published output.
fn outpoint(txid: Txid, index: u32) -> OutPoint {
    OutPoint::new(txid.0, index)
}

/// Receives to scripts no account derives, spread over `[start, end]`, so that
/// the account's scripts are not alone in any shard.
fn noise(start: u64, end: u64, salt: u32) -> Vec<(ScriptBytes, TransparentEvent)> {
    (0..40u32)
        .map(|n| {
            let tag = salt * 1_000 + n;
            let height = start + u64::from(n * 7) % (end - start + 1);
            (
                unrelated(tag),
                receive(height, txid(u64::from(tag) + 100_000), 0, 1),
            )
        })
        .collect()
}

/// A sealed shard, revision zero.
fn sealed(start: u64, end: u64, events: Vec<(ScriptBytes, TransparentEvent)>) -> ShardSpec {
    ShardSpec {
        start,
        end,
        geometry: GEOMETRY,
        sealed: true,
        revision: 0,
        supersedes: String::new(),
        page_span: 0,
        events,
    }
}

/// The tail at `revision`, ending at `end`.
fn tail(end: u64, revision: u32, events: Vec<(ScriptBytes, TransparentEvent)>) -> ShardSpec {
    ShardSpec {
        start: H0 + 600,
        end,
        geometry: GEOMETRY,
        sealed: false,
        revision,
        supersedes: String::new(),
        page_span: 0,
        events,
    }
}

/// What a pass's batch held, read before it was settled.
struct Seen {
    state: BatchState,
    progress: Progress,
    commits: Vec<TransparentLedgerCommit<AccountUuid>>,
    retired: Vec<RecoveryRevision>,
}

impl Seen {
    /// The batch `report` describes, which the companion holds exactly when the
    /// pass was ready.
    fn of(report: &PassReport, held: Option<&RecoveryBatch<AccountUuid>>) -> Self {
        assert_eq!(held.is_some(), report.state == BatchState::Ready);
        let seen = Self {
            state: report.state,
            progress: report.progress,
            commits: held.map_or(vec![], |batch| batch.commits().to_vec()),
            retired: held.map_or(vec![], |batch| batch.retired_revisions().to_vec()),
        };
        assert_eq!(
            (seen.commits.len(), seen.retired.len()),
            (report.commits, report.retired)
        );
        if let Some(batch) = held {
            assert_eq!(
                (batch.state(), batch.progress()),
                (report.state, report.progress)
            );
        }
        seen
    }
}

/// A pass: what it reported, its batch, whether settling it grew the account's
/// window, whether it left work for the next sync, and the step its plan takes next.
struct Pass {
    report: PassReport,
    batch: Seen,
    grew: bool,
    /// Settling grew the window or changed the watched addresses: the next sync
    /// passes over addresses this pass did not.
    new_work: bool,
    step: Step,
}

/// A wallet with one account, the in-process service it recovers from, and the
/// account's companion.
struct Fixture {
    st: State,
    account: AccountUuid,
    birthday: u64,
    server: Server,
    dir: tempfile::TempDir,
    publications: usize,
    url: Option<String>,
    companion: Option<Companion>,
    /// The public key hash of every address any watch set named.
    watched: BTreeSet<[u8; 20]>,
    /// Retired revisions acknowledged through trusted settlement.
    reconciled: Vec<RecoveryRevision>,
    /// Whether passes settle batches as trusted.
    trusted: bool,
}

impl Fixture {
    /// A wallet whose only account was born at `birthday`, scanned through
    /// `through`, under a durable `PrivateRequired` policy, and its companion.
    /// Its passes do not trust the service until [`Fixture::trust_service`].
    fn new(birthday: u64, through: u64) -> Self {
        Self::with_factory(birthday, through, TestDbFactory::default())
    }

    fn with_factory(birthday: u64, through: u64, factory: TestDbFactory) -> Self {
        let st = TestBuilder::new()
            .with_data_store_factory(factory)
            .with_block_cache(BlockCache::new())
            .with_initial_chain_state(|_, _| InitialChainState {
                chain_state: ChainState::empty(
                    height(birthday - 1),
                    BlockHash(synthetic(birthday - 1).0),
                ),
                prior_sapling_roots: vec![],
                prior_orchard_roots: vec![],
            })
            .with_account_having_current_birthday()
            .build();
        let account = st.test_account().unwrap().id();
        let mut fixture = Self {
            st,
            account,
            birthday,
            server: Server::start(),
            dir: tempfile::tempdir().unwrap(),
            publications: 0,
            url: None,
            companion: None,
            watched: BTreeSet::new(),
            reconciled: Vec::new(),
            trusted: false,
        };
        fixture.scan_to(through);
        fixture.set_policy(PrivateRequired);
        fixture.open();
        fixture
    }

    /// Mines empty blocks through `through` and scans them.
    fn scan_to(&mut self, through: u64) {
        let from = self.tip() + 1;
        for _ in from..=through {
            self.st.generate_empty_block();
        }
        self.st
            .scan_cached_blocks(height(from), (through + 1 - from) as usize);
        assert_eq!(self.tip(), through);
    }

    fn tip(&self) -> u64 {
        self.st
            .wallet()
            .chain_height()
            .unwrap()
            .map_or(self.birthday - 1, |tip| u64::from(u32::from(tip)))
    }

    fn set_policy(&mut self, mode: TransparentLedgerMode) {
        let db = self.st.wallet_mut().db_mut();
        db.apply_transparent_policy(mode).unwrap();
        db.set_transparent_ledger_mode(mode);
    }

    /// The wallet's hash at `height`, from the birthday on; a synthetic one
    /// below, where the wallet holds no blocks.
    fn block(&self, at: u64) -> transparent_filter::BlockHash {
        if at < self.birthday {
            return synthetic(at);
        }
        let hash = self
            .st
            .wallet()
            .get_block_hash(height(at))
            .unwrap()
            .expect("a scanned block");
        transparent_filter::BlockHash::from_internal_bytes(hash.0)
    }

    /// Publishes `shards` over the wallet's chain and serves the publication.
    fn publish(&mut self, shards: &[ShardSpec], seal: SealParameters) -> ShardMap {
        self.publish_recut(shards, seal, vec![])
    }

    /// Publishes `shards` declaring `recuts`, and serves the publication.
    fn publish_recut(
        &mut self,
        shards: &[ShardSpec],
        seal: SealParameters,
        recuts: Vec<Recut>,
    ) -> ShardMap {
        self.publications += 1;
        let dir = self
            .dir
            .path()
            .join(format!("publication-{}", self.publications));
        let map = fixture::publish(&dir, shards, seal, |at| self.block(at), recuts);
        self.url = Some(self.server.serve(&dir));
        map
    }

    /// Removes the companion's database, as when an application loses it.
    fn lose_companion(&mut self) {
        self.companion = None;
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.companion_path().into_os_string();
            path.push(suffix);
            let _ = std::fs::remove_file(path);
        }
    }

    /// The directory holding the wallet's companions.
    fn companions(&self) -> CompanionDir {
        CompanionDir::new(self.dir.path().join("companions"))
    }

    /// The account's name in companion files.
    fn account_name(&self) -> String {
        self.account.expose_uuid().to_string()
    }

    fn companion_path(&self) -> PathBuf {
        self.companions()
            .companion_path(&self.account_name(), ORIGIN)
    }

    /// Opens the account's companion, holding its lock until it is closed or reopened.
    fn open(&mut self) {
        self.companion = None;
        let account = self.account_name();
        self.companion = Some(
            self.companions()
                .open(
                    &account,
                    config(self.account),
                    || Ok(BTreeSet::from([account.clone()])),
                    &|| false,
                )
                .unwrap(),
        );
    }

    fn watch(&self) -> TransparentAddressWatchSet<AccountUuid> {
        self.st
            .wallet()
            .db()
            .transparent_watch_set(self.account)
            .unwrap()
    }

    /// The account's derived address at `index` in `scope`.
    fn derived(&self, scope: TransparentKeyScope, index: u32) -> TransparentAddress {
        self.watch()
            .addresses
            .iter()
            .find(|watched| {
                matches!(watched.origin, WatchOrigin::Derived { scope: s, index: i }
                    if s == scope && i.index() == index)
            })
            .expect("a derived address")
            .address
    }

    /// The highest external index the account's own window derives.
    fn last_external(&self) -> TransparentAddress {
        self.watch()
            .addresses
            .iter()
            .filter_map(|watched| match watched.origin {
                WatchOrigin::Derived { scope, index } if scope == TransparentKeyScope::EXTERNAL => {
                    Some((index.index(), watched.address))
                }
                _ => None,
            })
            .max_by_key(|(index, _)| *index)
            .unwrap()
            .1
    }

    /// Records every address `watch` names, for [`Fixture::assert_private`].
    fn note_watched(&mut self, watch: &TransparentAddressWatchSet<AccountUuid>) {
        self.watched.extend(
            watch
                .addresses
                .iter()
                .map(|watched| pubkey_hash(watched.address)),
        );
    }

    /// The exchange reaching the current server.
    fn exchange(&self) -> Loopback {
        Loopback::new(self.url.as_deref().expect("a served publication"))
    }

    /// One pass over the current watch set and the wallet's chain through its
    /// target, its ready batch taken rather than settled.
    fn recover(&mut self) -> Result<RecoveryBatch<AccountUuid>, PassError> {
        let watch = self.watch();
        self.note_watched(&watch);
        let exchange = self.exchange();
        let companion = self.companion.as_mut().expect("an open companion");
        let chain = WalletChain::new(self.st.wallet().db(), watch.target.unwrap());
        let report = companion.pass(&watch, &chain, &exchange, RESPONSE_LIMIT, &|| false)?;
        let batch = companion.take_latest::<AccountUuid>();
        Ok(batch.unwrap_or_else(|| panic!("a ready pass, not {:?}", report.state)))
    }

    /// The library's pass alone over the current watch set, through `exchange` and with
    /// `should_stop`, settling nothing.
    fn bare_pass(
        &mut self,
        exchange: &Loopback,
        should_stop: &dyn Fn() -> bool,
    ) -> Result<PassReport, PassError> {
        let watch = self.watch();
        let companion = self.companion.as_mut().expect("an open companion");
        let chain = WalletChain::new(self.st.wallet().db(), watch.target.unwrap());
        companion.pass(&watch, &chain, exchange, RESPONSE_LIMIT, should_stop)
    }

    /// Applies `batch` to the wallet and acknowledges it with `trust`.
    fn settle(
        &mut self,
        batch: RecoveryBatch<AccountUuid>,
        trust: Trust,
    ) -> Result<zakura_pir_transparent::Applied, zakura_pir_transparent::ApplyFailure> {
        let companion = self.companion.as_mut().expect("an open companion");
        companion.apply_and_acknowledge_gated(
            batch,
            self.st.wallet_mut().db_mut(),
            trust,
            &mut Ungated,
        )
    }

    /// Settles `batch` through `gate`, one wallet write at a time.
    fn settle_gated(
        &mut self,
        batch: RecoveryBatch<AccountUuid>,
        trust: Trust,
        gate: &mut impl WriteGate,
    ) -> Result<zakura_pir_transparent::Applied, zakura_pir_transparent::ApplyFailure> {
        let companion = self.companion.as_mut().expect("an open companion");
        companion.apply_and_acknowledge_gated(batch, self.st.wallet_mut().db_mut(), trust, gate)
    }

    /// Trusts the service from the next pass on: its commits qualify their
    /// revisions.
    fn trust_service(&mut self) {
        self.trusted = true;
    }

    /// The trust a coordinator states for this fixture's origin.
    fn trust(&self) -> Trust {
        if self.trusted {
            Trust::Trusted
        } else {
            Trust::Observed
        }
    }

    /// One pass as a coordinator runs it, under a plan of its own.
    fn pass(&mut self) -> Result<Pass, PassError> {
        let mut plan = PassPlan::new(self.watch(), PassLimits::default());
        self.pass_in(&mut plan)
    }

    /// One pass of `plan`: the library's pass over the plan's watch set, then its
    /// held batch read and settled as `settle_latest` settles it, trusted once the
    /// service is. A pass that held nothing is settled through `settle_latest`.
    /// Until then a batch with retirements is refused unsettled, and the plan holds
    /// the account: only trusted reconciliation resolves them.
    fn pass_in(&mut self, plan: &mut PassPlan<AccountUuid>) -> Result<Pass, PassError> {
        self.note_watched(plan.watch());
        let (exchange, trust) = (self.exchange(), self.trust());
        let companion = self.companion.as_mut().expect("an open companion");
        let chain = WalletChain::new(self.st.wallet().db(), plan.watch().target.unwrap());
        let report = companion.pass(plan.watch(), &chain, &exchange, RESPONSE_LIMIT, &|| false)?;
        let held = companion.take_latest::<AccountUuid>();
        let batch = Seen::of(&report, held.as_ref());
        let wallet = self.st.wallet_mut().db_mut();
        let settled = match held {
            Some(held) => companion
                .apply_and_acknowledge_gated(held, wallet, trust, &mut Ungated)
                .map(Some),
            None => companion.settle_latest(wallet, trust, &mut Ungated),
        };
        let grew = match &settled {
            Ok(Some(applied)) => {
                assert_eq!(applied.stats.applied, batch.commits.len());
                assert_eq!(applied.retired, batch.retired.len());
                self.reconciled.extend(batch.retired.iter().cloned());
                applied.stats.window_grew
            }
            Ok(None) => false,
            Err(failure) => {
                assert_eq!(
                    failure.action(),
                    ApplyAction::Reconcile,
                    "the wallet applies every commit: {}",
                    failure.error
                );
                assert_eq!(failure.stats.applied, 0);
                assert!(trust == Trust::Observed && !batch.retired.is_empty());
                false
            }
        };
        assert!(companion.take_latest::<AccountUuid>().is_none());
        let fresh = self.watch();
        let new_work = grew || fresh.addresses != plan.watch().addresses;
        let step = plan.next(&report, &settled, fresh);
        if settled.is_err() {
            assert_eq!(step, Step::Hold(HoldCause::Unreconciled));
        }
        Ok(Pass {
            report,
            batch,
            grew,
            new_work,
            step,
        })
    }

    /// One sync: passes as a fresh plan says until it stops, treating a wait as the
    /// end of the sync. Only refreshes pass again; a counted pass ends the sync.
    fn drive(&mut self) -> Pass {
        let mut plan = PassPlan::new(self.watch(), PassLimits::default());
        assert_eq!(plan.first(), Step::Pass);
        loop {
            let pass = self.pass_in(&mut plan).expect("a pass");
            if pass.step != Step::Refresh {
                assert_ne!(pass.step, Step::Pass, "a counted pass ends the sync");
                return pass;
            }
        }
    }

    /// Syncs until one ends [`Retry::Complete`] and leaves no new work, returning its
    /// last pass and the number of syncs it took. Panics after `max` syncs.
    fn sync_until_complete(&mut self, max: usize) -> (Pass, usize) {
        for syncs in 1..=max {
            let pass = self.drive();
            if pass.step == Step::Done(Some(Retry::Complete)) && !pass.new_work {
                return (pass, syncs);
            }
        }
        panic!("recovery did not complete within {max} syncs")
    }

    fn activate(&mut self) {
        self.st
            .wallet_mut()
            .db_mut()
            .activate_transparent_ledger(self.account)
            .unwrap();
    }

    fn authority(&self) -> TransparentAuthority {
        self.st
            .wallet()
            .db()
            .transparent_ledger_snapshot(self.account, ConfirmationsPolicy::MIN)
            .unwrap()
            .authority
    }

    /// The outputs the wallet would select to spend from every watched address
    /// at the next block.
    fn spendable(&self) -> Result<Vec<OutPoint>, SqliteClientError> {
        let addresses: Vec<_> = self
            .watch()
            .addresses
            .iter()
            .map(|watched| watched.address)
            .collect();
        let next = TargetHeight::from(self.st.wallet().chain_height().unwrap().unwrap() + 1);
        let mut selected: Vec<OutPoint> = self
            .st
            .wallet()
            .db()
            .get_spendable_transparent_outputs_for_addresses(
                &addresses,
                next,
                ConfirmationsPolicy::MIN,
                CoinbaseFilter::AllTransparentOutputs,
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )?
            .iter()
            .map(|output| output.outpoint().clone())
            .collect();
        selected.sort_by_key(|outpoint| (*outpoint.hash(), outpoint.n()));
        Ok(selected)
    }

    fn count(&self, table: &str) -> i64 {
        self.st
            .wallet()
            .conn()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    /// The wallet's coverage rows under `revision`.
    fn coverage_of(&self, revision: &RecoveryRevision) -> i64 {
        self.st
            .wallet()
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM tpir_coverage WHERE revision_id IN (
                     SELECT id FROM tpir_revisions WHERE source = ?1 AND revision = ?2
                 )",
                rusqlite::params![revision.source, revision.revision],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// `(source, revision)` of every unsealed revision the wallet holds coverage
    /// under.
    fn provisional_coverage(&self) -> BTreeSet<(Vec<u8>, Vec<u8>)> {
        self.coverage_sealed(false)
    }

    /// `(source, revision)` of every revision with `sealed` the wallet holds
    /// coverage under.
    fn coverage_sealed(&self, sealed: bool) -> BTreeSet<(Vec<u8>, Vec<u8>)> {
        self.st
            .wallet()
            .conn()
            .prepare(
                "SELECT DISTINCT r.source, r.revision FROM tpir_coverage c
                 JOIN tpir_revisions r ON r.id = c.revision_id WHERE r.sealed = ?1",
            )
            .unwrap()
            .query_map([sealed], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// The shard ids named by the requests the service received from the
    /// `from`th on.
    fn shards_requested(&self, from: usize) -> BTreeSet<u64> {
        let named = Regex::new(SHARD).unwrap();
        self.server.requests()[from..]
            .iter()
            .filter_map(|request| {
                named
                    .captures(&request.path)
                    .map(|captures| captures[2].parse::<u64>().unwrap())
            })
            .collect()
    }

    /// Every row of the wallet's tables, those named `tpir_` excluded unless
    /// `ledger`, in a canonical order.
    fn dump(&self, ledger: bool) -> Vec<(String, Vec<String>)> {
        let conn = self.st.wallet().conn();
        let tables: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table'
                 AND name NOT LIKE 'sqlite!_%' ESCAPE '!' ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        tables
            .into_iter()
            .filter(|table| ledger || !table.starts_with("tpir_"))
            .map(|table| {
                let mut statement = conn.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
                let columns = statement.column_count();
                let mut rows: Vec<String> = statement
                    .query_map([], |row| {
                        (0..columns)
                            .map(|i| row.get::<_, Value>(i))
                            .collect::<Result<Vec<_>, _>>()
                            .map(|values| format!("{values:?}"))
                    })
                    .unwrap()
                    .collect::<Result<_, _>>()
                    .unwrap();
                rows.sort();
                (table, rows)
            })
            .collect()
    }

    /// A read-only connection to the companion's database.
    fn companion_db(&self) -> Connection {
        Connection::open_with_flags(self.companion_path(), OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap()
    }

    /// `(start_height, lineage, exported)` of every catalog row.
    fn catalog(&self) -> Vec<(u64, u64, bool)> {
        self.companion_db()
            .prepare("SELECT start_height, lineage, exported FROM pir_bridge_catalog ORDER BY 1, 2")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// The revisions whose filters the companion's store caches.
    fn cached_filters(&self) -> BTreeSet<String> {
        self.companion_db()
            .prepare("SELECT revision_digest FROM filter_cache")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// The query body lengths the current service accepts: the 8-byte
    /// binding, then each table scheme's upload. The history tables publish
    /// one scheme each, the 8-bit profile's 28-bit dithered query.
    fn query_lengths(&self) -> HashSet<usize> {
        let url = self.url.as_deref().expect("a served publication");
        let mut transport = HttpShardTransport::new(url, &HttpOptions::default()).unwrap();
        let (init, _) = transport.init().unwrap();
        let service = transparent_wallet::parse_init(&init).unwrap();
        let mut lengths = HashSet::new();
        for geometry in &service.geometries {
            for (scheme, dq44) in [
                (&geometry.directory_scheme, &geometry.directory_scheme_dq44),
                (&geometry.pages_scheme, &geometry.pages_scheme_dq44),
            ] {
                assert!(dq44.is_none(), "an 8-bit table publishes one scheme");
                assert_eq!(scheme.query_bits, 28);
                lengths.insert(8 + scheme.request_bytes);
            }
        }
        lengths
    }

    /// The body length of a 28-bit query to page shard `child` of one shard
    /// revision, the 8-byte binding then a selection over the rows its
    /// manifest fixes for that page shard, and whether those rows are fewer
    /// than a whole segment. Read from the published manifest, which stays on
    /// disk after a later publication stops serving the revision.
    fn pages_query_len(&self, revision: &str, child: u32) -> (usize, bool) {
        let raw = (1..=self.publications)
            .map(|n| {
                self.dir
                    .path()
                    .join(format!("publication-{n}"))
                    .join(revision)
                    .join("manifest.json")
            })
            .find_map(|path| std::fs::read(path).ok())
            .expect("a published revision");
        let manifest: transparent_shard::manifest::ShardManifest =
            serde_json::from_slice(&raw).unwrap();
        let child = manifest.child(child).expect("a declared page shard");
        let rows = child.query_rows();
        (
            8 + transparent_native::profile_for("pages").request_len_bits(rows as usize, 28),
            rows < child.page_segments[0].rows,
        )
    }

    /// Asserts that every request the service received used one of its routes
    /// with that route's method, carried none of the account's scripts in its
    /// path, query, headers or body, and named no shard in `below_floor`; and
    /// that every query went at 28 dithered bits, a pages query selecting over
    /// exactly the rows its revision's manifest fixes. Returns how many pages
    /// queries selected over fewer rows than a whole segment.
    fn assert_private(&self, below_floor: &[u64]) -> usize {
        let requests = self.server.requests();
        assert!(!requests.is_empty());
        let routes = Regex::new(ROUTES).unwrap();
        let named = Regex::new(SHARD).unwrap();
        let shard = |path: &str| {
            named
                .captures(path)
                .map(|captures| captures[2].parse::<u64>().unwrap())
        };
        // Every watched script holds its public key hash, so a request carrying
        // a script, in bytes or hex, carries the hash.
        let hashes: HashSet<Vec<u8>> = self.watched.iter().map(|hash| hash.to_vec()).collect();
        let hexes: HashSet<Vec<u8>> = self
            .watched
            .iter()
            .flat_map(|hash| [hex::encode(hash), hex::encode_upper(hash)])
            .map(String::into_bytes)
            .collect();
        let carries = |bytes: &[u8]| {
            bytes.windows(20).any(|window| hashes.contains(window))
                || bytes.windows(40).any(|window| hexes.contains(window))
        };
        // Positive controls: the passes made private queries, the floor check
        // reads the shard from filter and manifest paths, and a watched script
        // in bytes or hex would be caught.
        assert!(
            requests
                .iter()
                .any(|request| request.method == "POST" && !request.body.is_empty())
        );
        for kind in ["/filter", "/manifest"] {
            assert!(
                requests
                    .iter()
                    .any(|request| request.path.ends_with(kind) && shard(&request.path).is_some())
            );
        }
        // Every query uses the table's one scheme. A directory query selects
        // over the whole table; a pages query over the rows its manifest
        // fixes, fewer than a segment for a growing tail.
        let lengths = self.query_lengths();
        let pages = Regex::new(PAGES_QUERY).unwrap();
        let mut prefixes = 0;
        for request in requests.iter().filter(|request| request.method == "POST") {
            match pages.captures(&request.path) {
                Some(captures) => {
                    let (len, prefix) =
                        self.pages_query_len(&captures[1], captures[2].parse().unwrap());
                    assert_eq!(request.body.len(), len, "a pages query to {}", request.path);
                    prefixes += usize::from(prefix);
                }
                None => assert!(
                    lengths.contains(&request.body.len()),
                    "a {}-byte query to {}",
                    request.body.len(),
                    request.path
                ),
            }
        }
        let probe = self.watched.first().expect("a watched address");
        assert!(carries(
            &[&[0x76, 0xa9, 20][..], probe, &[0x88, 0xac]].concat()
        ));
        assert!(carries(format!("/{}", hex::encode_upper(probe)).as_bytes()));
        for request in &requests {
            let line = format!("{} {}", request.method, request.path);
            assert!(routes.is_match(&line), "unexpected route {line}");
            assert_eq!(request.query, None, "a query string on {line}");
            assert!(!carries(request.path.as_bytes()), "a script in {line}");
            assert!(!carries(&request.body), "a script in the body of {line}");
            for (name, value) in &request.headers {
                assert!(
                    !carries(name.as_bytes()) && !carries(value),
                    "a script in a header of {line}"
                );
            }
            assert!(
                shard(&request.path).is_none_or(|id| !below_floor.contains(&id)),
                "a below-floor shard: {line}"
            );
        }
        prefixes
    }
}

fn height(at: u64) -> BlockHeight {
    BlockHeight::from(u32::try_from(at).unwrap())
}

/// The addresses the lifecycle's events pay.
struct Owned {
    a0: TransparentAddress,
    a1: TransparentAddress,
    last: TransparentAddress,
}

/// The lifecycle's publication: three sealed shards and a tail through
/// `tail_end` at `tail_revision`.
///
/// e0 pays A0 below the birthday, in S0, which no pass reads. r1 pays A0 in S1,
/// r2 the last address of A's external window in S2, and s1 spends r1 in the
/// tail; r3 pays A1 once the tail reaches it. `changed` adds an unrelated
/// receive to S2 without changing its revision number.
fn lifecycle(owned: &Owned, tail_end: u64, tail_revision: u32, changed: bool) -> Vec<ShardSpec> {
    let mut s2 = noise(H0 + 400, H0 + 599, 2);
    s2.push((script(owned.last), receive(H0 + 450, txid(3), 1, 7_000)));
    if changed {
        s2.push((unrelated(9_999), receive(H0 + 500, txid(9_999), 0, 1)));
    }
    let mut tail_events = noise(H0 + 600, tail_end, 3);
    tail_events.push((script(owned.a0), spend(H0 + 620, txid(4), (txid(2), 0))));
    if tail_end >= H0 + 655 {
        tail_events.push((script(owned.a1), receive(H0 + 655, txid(5), 0, 30_000)));
    }
    vec![
        sealed(H0, H0 + 199, {
            let mut events = noise(H0, H0 + 199, 0);
            events.push((script(owned.a0), receive(H0 + 50, txid(1), 0, 11_000)));
            events
        }),
        sealed(H0 + 200, H0 + 399, {
            let mut events = noise(H0 + 200, H0 + 399, 1);
            events.push((script(owned.a0), receive(H0 + 300, txid(2), 0, 50_000)));
            events
        }),
        sealed(H0 + 400, H0 + 599, s2),
        tail(tail_end, tail_revision, tail_events),
    ]
}

/// The unsealed revision among a batch's commits.
fn tail_revision(batch: &Seen) -> RecoveryRevision {
    let mut unsealed = batch
        .commits
        .iter()
        .filter(|commit| !commit.revision.sealed)
        .map(|commit| commit.revision.clone());
    let revision = unsealed.next().expect("a tail commit");
    assert!(unsealed.next().is_none());
    revision
}

#[test]
fn private_mode_lifecycle_against_an_in_process_shard_service() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let birthday = H0 + 250;
    let (t1, t2, t3) = (H0 + 649, H0 + 669, H0 + 674);
    let mut f = Fixture::new(birthday, t1);
    let owned = Owned {
        a0: f.derived(TransparentKeyScope::EXTERNAL, 0),
        a1: f.derived(TransparentKeyScope::EXTERNAL, 1),
        last: f.last_external(),
    };
    let (r1, r2, r3) = (
        outpoint(txid(2), 0),
        outpoint(txid(3), 1),
        outpoint(txid(5), 0),
    );

    // Untrusted: the commits are observed, never trusted, and the account stays
    // an isolated candidate. Its last external address received, so its window
    // grew and the next sync recovered the new addresses too.
    f.publish(&lifecycle(&owned, t1, 0, false), SEAL);
    let (observed, syncs) = f.sync_until_complete(3);
    assert_eq!(syncs, 2);
    assert_eq!(observed.batch.state, BatchState::Ready);
    assert_eq!(observed.batch.progress.outcome, Outcome::Complete);
    assert_eq!(observed.batch.progress.covered_through, t1);
    let candidate =
        f.st.wallet()
            .db()
            .transparent_candidate_recovery(f.account)
            .unwrap();
    assert_eq!(candidate.blockers, vec![]);
    // e0, below the birthday, is not among them.
    let received: BTreeSet<_> = candidate
        .receives
        .iter()
        .map(|event| (*event.outpoint.hash(), event.outpoint.n()))
        .collect();
    assert_eq!(
        received,
        BTreeSet::from([(*r1.hash(), r1.n()), (*r2.hash(), r2.n())])
    );
    assert_eq!(candidate.spends.len(), 1);
    assert_eq!(candidate.spends[0].prevout, r1);
    assert_eq!(*candidate.spends[0].spending_txid.as_ref(), txid(4).0);
    assert!(
        f.watch()
            .addresses
            .iter()
            .any(|watched| matches!(watched.origin, WatchOrigin::CandidateWindow { .. }))
    );
    assert_eq!(f.count("tpir_qualified_revisions"), 0);
    assert_eq!(f.count("tpir_active_accounts"), 0);
    assert_eq!(f.count("transparent_received_outputs"), 0);
    assert_eq!(f.watch().lifecycle, AccountLifecycle::Candidate);
    // S0 lies wholly below the birthday: no commit, and no catalog row.
    let catalog = f.catalog();
    assert_eq!(
        catalog.iter().map(|row| row.0).collect::<Vec<_>>(),
        vec![H0 + 200, H0 + 400, H0 + 600]
    );
    assert!(catalog.iter().all(|row| row.2));

    // Trusted: the same publication qualifies every revision, and activation
    // grants private authority over exactly r2.
    f.trust_service();
    let trusted = f.drive();
    assert_eq!(trusted.batch.state, BatchState::Ready);
    let first_tail = tail_revision(&trusted.batch);
    assert_eq!(first_tail.lineage, 1);
    assert_eq!(f.count("tpir_qualified_revisions"), 3);
    f.activate();
    assert_eq!(f.watch().lifecycle, AccountLifecycle::Active);
    assert_eq!(f.authority(), TransparentAuthority::Private);
    assert_eq!(f.spendable().unwrap(), vec![r2.clone()]);

    // The tail moves: until a pass covers the new blocks, nothing is spendable.
    // Its successor withdraws the replaced tail's provisional coverage.
    f.scan_to(t2);
    assert!(matches!(
        f.spendable(),
        Err(SqliteClientError::TransparentAuthorityUnavailable(
            AuthorityRefusal::Pending { accounts }
        )) if accounts == vec![f.account]
    ));
    let moved_map = f.publish(&lifecycle(&owned, t2, 1, false), SEAL);
    let moved = f.drive();
    assert_eq!(moved.batch.state, BatchState::Ready);
    assert_eq!(moved.batch.progress.outcome, Outcome::Complete);
    let second_tail = tail_revision(&moved.batch);
    assert_eq!(second_tail.lineage, 2);
    assert_eq!(second_tail.source, first_tail.source);
    assert_eq!(f.coverage_of(&first_tail), 0);
    assert!(f.coverage_of(&second_tail) > 0);
    // The replaced tail was resolved through explicit, trusted reconciliation.
    assert!(f.reconciled.contains(&first_tail));
    assert_eq!(f.authority(), TransparentAuthority::Private);
    let mut both = vec![r2.clone(), r3.clone()];
    both.sort_by_key(|outpoint| (*outpoint.hash(), outpoint.n()));
    assert_eq!(f.spendable().unwrap(), both);
    // The acknowledgment forgot the replaced tail, and the store caches only
    // what the map names.
    assert_eq!(f.catalog().len(), 3);
    let named: BTreeSet<String> = moved_map
        .shards
        .iter()
        .map(|entry| entry.manifest_digest.clone())
        .collect();
    let cached = f.cached_filters();
    assert!(!cached.is_empty());
    assert!(cached.is_subset(&named));

    // Lag: the wallet moves past the publication. The pass covers what is
    // published and reports it behind, and nothing grants authority above it.
    f.scan_to(t3);
    let lagging = f.pass().unwrap();
    assert_eq!(lagging.batch.state, BatchState::Ready);
    assert_eq!(lagging.batch.progress.outcome, Outcome::Behind);
    // The plan waits for the publication rather than passing again at once.
    assert_eq!(lagging.step, Step::Wait(Retry::BEHIND));
    assert_eq!(lagging.batch.progress.covered_through, t2);
    assert!(!lagging.batch.commits.is_empty());
    assert!(
        lagging
            .batch
            .commits
            .iter()
            .all(|commit| u64::from(u32::from(commit.anchor.height)) <= t2)
    );
    assert_ne!(f.authority(), TransparentAuthority::Private);

    // Catch-up, through a reopened companion. A replayed pass changes nothing.
    f.publish(&lifecycle(&owned, t3, 2, false), SEAL);
    f.open();
    let caught_up = f.drive();
    assert_eq!(caught_up.batch.progress.outcome, Outcome::Complete);
    let third_tail = tail_revision(&caught_up.batch);
    assert_eq!(third_tail.lineage, 3);
    assert_eq!(f.authority(), TransparentAuthority::Private);
    let production = f.dump(false);
    let replay = f.pass().unwrap();
    assert_eq!(replay.batch.state, BatchState::Ready);
    assert!(!replay.grew);
    assert_eq!(f.dump(false), production);

    // Companion loss: a recreated companion derives the triples the wallet
    // holds, so recovery heals without recovery suspension.
    f.lose_companion();
    f.open();
    assert!(f.catalog().is_empty());
    let healed = f.drive();
    assert_eq!(healed.batch.state, BatchState::Ready);
    assert_eq!(tail_revision(&healed.batch), third_tail);
    assert_eq!(f.count("tpir_quarantined_sources"), 0);
    assert_eq!(f.count("tpir_quarantined_accounts"), 0);
    assert_eq!(f.authority(), TransparentAuthority::Private);
    assert_eq!(
        f.provisional_coverage(),
        BTreeSet::from([(third_tail.source.clone(), third_tail.revision.clone())])
    );

    // A publication change: another seal for the geometry gives every shard a
    // new source, and the publisher restarts the tail's revision numbers. The
    // pass's first attempt resets the store and keeps the catalog, and the pass
    // retries at once with the same companion, recovering under the new sources.
    let resealed = SealParameters {
        max_scripts: SEAL.max_scripts * 2,
        ..SEAL
    };
    f.publish(&lifecycle(&owned, t3, 0, false), resealed);
    let before = f.catalog();
    let seen = f.server.requests().len();
    let reset = f.pass().unwrap();
    assert!(reset.report.publication_changed);
    assert_eq!(reset.batch.state, BatchState::Ready);
    // Both attempts fetched the map.
    let maps = f.server.requests()[seen..]
        .iter()
        .filter(|request| request.method == "GET" && request.path == "/v2/filters/shards")
        .count();
    assert_eq!(maps, 2);
    // The old rows are kept, with their export marks cleared; the retry's are
    // exported.
    let kept: Vec<_> = f
        .catalog()
        .into_iter()
        .filter(|row| !row.2)
        .map(|row| (row.0, row.1))
        .collect();
    assert_eq!(
        kept,
        before.iter().map(|row| (row.0, row.1)).collect::<Vec<_>>()
    );
    // The retry is inside the pass: the plan never passes again at once.
    assert_eq!(reset.step, Step::Done(Some(Retry::Complete)));
    let retried = reset;
    assert_eq!(retried.batch.state, BatchState::Ready);
    assert_eq!(retried.batch.progress.outcome, Outcome::Complete);
    let new_tail = tail_revision(&retried.batch);
    assert_ne!(new_tail.source, third_tail.source);
    assert_eq!(new_tail.lineage, 1);
    assert!(
        retried
            .batch
            .commits
            .iter()
            .all(|commit| commit.revision.source != third_tail.source)
    );
    assert_eq!(f.count("tpir_quarantined_sources"), 0);
    assert_eq!(f.count("tpir_quarantined_accounts"), 0);
    assert_eq!(f.authority(), TransparentAuthority::Private);
    // Nothing supersedes the changed tail source's old provisional coverage.
    assert_eq!(
        f.provisional_coverage(),
        BTreeSet::from([
            (third_tail.source.clone(), third_tail.revision.clone()),
            (new_tail.source.clone(), new_tail.revision.clone()),
        ])
    );
    assert_eq!(f.catalog().len(), before.len() + 3);

    // A sealed shard changes under its revision number, and the tail it parents
    // is republished. The pass refuses the rewrite of history the companion
    // holds, nothing reaches the wallet, and the batch cannot be acknowledged.
    // Reopening does not change that.
    f.publish(&lifecycle(&owned, t3, 1, true), resealed);
    let wallet = f.dump(true);
    let changed = f.pass().unwrap();
    assert_eq!(changed.batch.state, UNDECLARED_REWRITE);
    assert!(changed.batch.commits.is_empty());
    assert_eq!(
        changed.step,
        Step::Hold(HoldCause::Withdrawn(WithdrawnCause::ChangedSealed))
    );
    // Nothing was held to settle or acknowledge.
    assert!(
        f.companion
            .as_mut()
            .unwrap()
            .take_latest::<AccountUuid>()
            .is_none()
    );
    assert_eq!(f.dump(true), wallet);
    f.open();
    let reopened = f.pass().unwrap();
    assert_eq!(reopened.batch.state, UNDECLARED_REWRITE);
    assert_eq!(f.dump(true), wallet);

    // Privacy, over every request of every pass: the service's routes only, no
    // watched script, and never a filter for S0, which lies below the floor.
    f.assert_private(&[0]);
}

/// Every request the service received from `from` on, as (method, path, query, body
/// length), with revision digests masked: what the service sees of a sync's shape.
fn transcript(f: &Fixture, from: usize) -> Vec<(String, String, Option<String>, usize)> {
    let digest = Regex::new("[0-9a-f]{64}").unwrap();
    f.server.requests()[from..]
        .iter()
        .map(|request| {
            (
                request.method.clone(),
                digest.replace_all(&request.path, "<digest>").into_owned(),
                request.query.clone(),
                request.body.len(),
            )
        })
        .collect()
}

/// A service that forges a receive at the last address of the wallet's window learns
/// nothing from the sync it answers: the wallet sends the same requests as it does to
/// a service without the receive, and covers the grown window only at the next sync.
///
/// Both services hold one receive for that address in S1, which straddles the
/// birthday, so its filter matches and its directory row is read alike. The forged
/// one lies above the birthday; the other below, where the wallet ignores it. No
/// other event pays the wallet, so the honest window never grows, and the forged
/// wallet's grown window would cost another pass's requests if it started one.
#[test]
fn a_forged_receive_does_not_start_another_pass() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (birthday, t1) = (H0 + 250, H0 + 649);
    let sync = |forged: bool| {
        let mut f = Fixture::new(birthday, t1);
        // Nobody's addresses: the lifecycle pays the wallet nothing itself.
        let owned = Owned {
            a0: TransparentAddress::PublicKeyHash([0xec; 20]),
            a1: TransparentAddress::PublicKeyHash([0xed; 20]),
            last: TransparentAddress::PublicKeyHash([0xee; 20]),
        };
        let mut shards = lifecycle(&owned, t1, 0, false);
        let at = if forged { birthday + 60 } else { birthday - 40 };
        shards[1]
            .events
            .push((script(f.last_external()), receive(at, txid(3), 1, 7_000)));
        f.publish(&shards, SEAL);
        let seen = f.server.requests().len();
        let pass = f.drive();
        let requests = transcript(&f, seen);
        (f, pass, requests)
    };
    let (mut forged, forged_pass, forged_requests) = sync(true);
    let (honest, honest_pass, honest_requests) = sync(false);

    // One pass each, and the service sees the same requests.
    assert_eq!(forged_pass.step, Step::Done(Some(Retry::Complete)));
    assert_eq!(honest_pass.step, Step::Done(Some(Retry::Complete)));
    assert!(!forged_requests.is_empty());
    assert_eq!(forged_requests, honest_requests);

    // The forged receive at the last address grows the forged wallet's window by a
    // whole gap, which only its next sync covers; the honest window stays empty.
    let window = |f: &Fixture| -> BTreeSet<_> {
        f.watch()
            .addresses
            .iter()
            .filter(|watched| matches!(watched.origin, WatchOrigin::CandidateWindow { .. }))
            .map(|watched| watched.address)
            .collect()
    };
    let (forged_window, honest_window) = (window(&forged), window(&honest));
    assert!(honest_window.is_empty());
    assert!(!forged_window.is_empty());
    assert!(
        forged_window
            .iter()
            .all(|address| !forged.watched.contains(&pubkey_hash(*address)))
    );
    let seen = forged.server.requests().len();
    let next = forged.drive();
    assert!(forged.server.requests().len() > seen);
    assert_eq!(next.step, Step::Done(Some(Retry::Complete)));
    assert!(!next.new_work);
    assert_eq!(next.report.progress.covered_through, t1);
    assert!(
        forged_window
            .iter()
            .all(|address| forged.watched.contains(&pubkey_hash(*address)))
    );
}

/// A pass behind the publication waits, and the pass after the wait, in the same
/// sync and plan, covers what the publication has since caught up to.
#[test]
fn a_wait_passes_again_within_the_sync() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (birthday, t1, t2) = (H0 + 250, H0 + 649, H0 + 669);
    let mut f = Fixture::new(birthday, t2);
    let owned = Owned {
        a0: f.derived(TransparentKeyScope::EXTERNAL, 0),
        a1: f.derived(TransparentKeyScope::EXTERNAL, 1),
        last: f.last_external(),
    };
    // Trusted, so the replaced tail reconciles rather than holding the account.
    f.trust_service();
    f.publish(&lifecycle(&owned, t1, 0, false), SEAL);
    let mut plan = PassPlan::new(f.watch(), PassLimits::default());
    assert_eq!(plan.first(), Step::Pass);
    let lagging = f.pass_in(&mut plan).expect("a pass");
    assert_eq!(lagging.batch.progress.outcome, Outcome::Behind);
    assert_eq!(lagging.batch.progress.covered_through, t1);
    assert_eq!(lagging.step, Step::Wait(Retry::BEHIND));

    f.publish(&lifecycle(&owned, t2, 1, false), SEAL);
    let caught_up = f.pass_in(&mut plan).expect("a pass");
    assert_eq!(caught_up.batch.progress.outcome, Outcome::Complete);
    assert_eq!(caught_up.batch.progress.covered_through, t2);
    assert_eq!(caught_up.step, Step::Done(Some(Retry::Complete)));
}

/// Restore latency at one pass per sync: receives at external indices 0, 9, 18 and
/// 25 under the default external gap of 10 take one sync per window step.
#[test]
fn restore_needs_one_sync_per_window_step() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let t1 = H0 + 649;
    let mut f = Fixture::new(H0 + 250, t1);
    let external =
        f.st.test_account()
            .unwrap()
            .usk()
            .transparent()
            .to_account_pubkey()
            .derive_external_ivk()
            .unwrap();
    let at = |index: u32| {
        external
            .derive_address(NonHardenedChildIndex::from_index(index).unwrap())
            .unwrap()
    };
    assert_eq!(f.last_external(), at(9));
    let mut s1 = noise(H0 + 200, H0 + 399, 1);
    s1.push((script(at(0)), receive(H0 + 300, txid(1), 0, 10_000)));
    s1.push((script(at(9)), receive(H0 + 350, txid(2), 0, 20_000)));
    let mut s2 = noise(H0 + 400, H0 + 599, 2);
    s2.push((script(at(18)), receive(H0 + 450, txid(3), 0, 30_000)));
    let mut tail_events = noise(H0 + 600, t1, 3);
    tail_events.push((script(at(25)), receive(H0 + 620, txid(4), 0, 40_000)));
    f.publish(
        &[
            sealed(H0, H0 + 199, noise(H0, H0 + 199, 0)),
            sealed(H0 + 200, H0 + 399, s1),
            sealed(H0 + 400, H0 + 599, s2),
            tail(t1, 0, tail_events),
        ],
        SEAL,
    );
    let (last, syncs) = f.sync_until_complete(8);
    assert_eq!(syncs, 4);
    assert_eq!(last.report.progress.covered_through, t1);
    let received =
        f.st.wallet()
            .db()
            .transparent_candidate_recovery(f.account)
            .unwrap()
            .receives
            .len();
    assert_eq!(received, 4);
}

/// Through a real pass: a caller that is stopping is not retried after a publication change,
/// and a service that cannot be reached is an outage, before anything is retrieved.
#[test]
fn a_stopping_pass_is_not_retried_and_an_unreachable_service_is_an_outage() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let t1 = H0 + 649;
    let mut f = Fixture::new(H0 + 250, t1);
    let owned = Owned {
        a0: f.derived(TransparentKeyScope::EXTERNAL, 0),
        a1: f.derived(TransparentKeyScope::EXTERNAL, 1),
        last: f.last_external(),
    };
    f.publish(&lifecycle(&owned, t1, 0, false), SEAL);
    assert_eq!(f.drive().batch.state, BatchState::Ready);

    // Another seal: the first attempt resets the store, and a stopping caller gets the change
    // back instead of a retry.
    let resealed = SealParameters {
        max_scripts: SEAL.max_scripts * 2,
        ..SEAL
    };
    f.publish(&lifecycle(&owned, t1, 0, false), resealed);
    let seen = f.server.requests().len();
    let exchange = f.exchange();
    assert!(matches!(
        f.bare_pass(&exchange, &|| true),
        Err(PassError::PublicationChanged)
    ));
    let maps = f.server.requests()[seen..]
        .iter()
        .filter(|request| request.method == "GET" && request.path == "/v2/filters/shards")
        .count();
    assert_eq!(maps, 1);
    let companion = f.companion.as_mut().unwrap();
    assert!(companion.take_latest::<AccountUuid>().is_none());
    // The reset store is bound to no set: the next pass binds the new one.
    let next = f.bare_pass(&exchange, &|| false).unwrap();
    assert!(!next.publication_changed);
    assert_eq!(next.state, BatchState::Ready);

    // Nothing listens on the discard port: the map request fails and the pass is an outage.
    let seen = f.server.requests().len();
    let unreachable = Loopback::new("http://127.0.0.1:9");
    assert!(matches!(
        f.bare_pass(&unreachable, &|| false),
        Err(PassError::Outage)
    ));
    assert_eq!(f.server.requests().len(), seen);
}

#[test]
fn young_wallet_rolls_back_below_its_birthday() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    // The birthday lies inside the tail, which starts below it.
    let birthday = H0 + 610;
    let target = H0 + 640;
    let mut f = Fixture::new(birthday, target);
    f.trust_service();
    let a0 = f.derived(TransparentKeyScope::EXTERNAL, 0);
    let received = outpoint(txid(1), 0);
    let shards = |end: u64, revision: u32| {
        let mut events = noise(H0 + 600, end, 3);
        events.push((script(a0), receive(H0 + 620, txid(1), 0, 20_000)));
        vec![
            sealed(H0, H0 + 199, noise(H0, H0 + 199, 0)),
            sealed(H0 + 200, H0 + 399, noise(H0 + 200, H0 + 399, 1)),
            // Below the birthday: never read.
            sealed(H0 + 400, H0 + 599, {
                let mut events = noise(H0 + 400, H0 + 599, 2);
                events.push((script(a0), receive(H0 + 500, txid(2), 0, 9_000)));
                events
            }),
            tail(end, revision, events),
        ]
    };

    // The publication ends below the wallet's target but above the birthday:
    // the pass syncs to the publication's end and commits through it.
    f.publish(&shards(H0 + 630, 0), SEAL);
    let clamped = f.drive();
    assert_eq!(clamped.batch.state, BatchState::Ready);
    assert_eq!(clamped.batch.progress.outcome, Outcome::Behind);
    assert_eq!(clamped.batch.progress.covered_through, H0 + 630);
    assert_eq!(clamped.batch.commits.len(), 1);
    assert_eq!(
        u64::from(u32::from(clamped.batch.commits[0].anchor.height)),
        H0 + 630
    );
    assert_eq!(clamped.batch.commits[0].receives.len(), 1);
    assert_eq!(clamped.batch.commits[0].receives[0].outpoint, received);

    // Two tail republications. Each replaces the companion's provisional tail,
    // rolling it back to just below the tail's start, under the birthday.
    for (end, revision) in [(H0 + 635, 1), (target, 2)] {
        f.publish(&shards(end, revision), SEAL);
        let pass = f.drive();
        assert_eq!(pass.batch.state, BatchState::Ready);
        assert_eq!(pass.batch.progress.covered_through, end);
    }

    // A reorg replaces the wallet's last two blocks. The companion's coverage
    // ends on a block the wallet no longer holds, so it rolls back below the
    // birthday, where the wallet holds no hash, and recovers the new branch.
    let replaced = f.block(target - 1);
    f.st.truncate_to_height(height(target - 2));
    f.scan_to(target);
    assert_ne!(f.block(target - 1), replaced);
    f.publish(&shards(target, 3), SEAL);
    let rewound = f.drive();
    assert_eq!(rewound.batch.state, BatchState::Ready);
    assert_eq!(rewound.batch.progress.outcome, Outcome::Complete);
    assert_eq!(tail_revision(&rewound.batch).lineage, 4);
    f.activate();
    assert_eq!(f.authority(), TransparentAuthority::Private);
    assert_eq!(f.spendable().unwrap(), vec![received]);

    // No pass read a shard ending below the birthday.
    f.assert_private(&[0, 1, 2]);
}

/// An address with more events than its directory entry holds inline has them
/// read from pages. The tail is unsealed and in one segment, so its pages
/// queries select over only the page rows it holds, and recovery still finds
/// every receive.
#[test]
fn growing_tail_pages_queries_select_only_its_rows() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let birthday = H0 + 610;
    let target = H0 + 640;
    let mut f = Fixture::new(birthday, target);
    f.trust_service();
    let a0 = f.derived(TransparentKeyScope::EXTERNAL, 0);
    let receives = transparent_shard::INLINE_EVENTS as u64 + 2;
    let mut events = noise(H0 + 600, target, 3);
    for n in 1..=receives {
        events.push((script(a0), receive(H0 + 610 + n, txid(n), 0, 10_000 * n)));
    }
    f.publish(
        &[
            sealed(H0, H0 + 199, noise(H0, H0 + 199, 0)),
            sealed(H0 + 200, H0 + 399, noise(H0 + 200, H0 + 399, 1)),
            sealed(H0 + 400, H0 + 599, noise(H0 + 400, H0 + 599, 2)),
            tail(target, 0, events),
        ],
        SEAL,
    );
    let (pass, _) = f.sync_until_complete(3);
    assert_eq!(pass.batch.state, BatchState::Ready);
    assert_eq!(pass.batch.progress.outcome, Outcome::Complete);
    f.activate();
    let spendable: BTreeSet<OutPoint> = f.spendable().unwrap().into_iter().collect();
    let expected: BTreeSet<OutPoint> = (1..=receives).map(|n| outpoint(txid(n), 0)).collect();
    assert_eq!(spendable, expected);

    assert!(f.assert_private(&[0, 1, 2]) > 0);
}

/// The decoupled tests' page shards: ten blocks each from the tail's start, so a
/// grown tail keeps its earlier page shards byte for byte.
const PAGE_SPAN: u64 = 10;

/// The decoupled tests' publication: three sealed shards below the birthday and a
/// tail from `H0 + 600` through `tail_end` at `revision`, in page shards of
/// [`PAGE_SPAN`] blocks, holding `a0`'s history at the offsets in `offsets` from
/// `H0 + 600` through `tail_end`. Each is a receive of 10,000 times its position,
/// from one, except that the fifth event spends the first receive.
///
/// The two newest events stay in the directory; each older one is pushed into
/// the page shard open when the event two places after it arrives:
///
/// | Block | Arrives | Pushed out | Into |
/// |---|---|---|---|
/// | +3 | e3 | e1 | pages-0 |
/// | +11 | e4 | e2 | pages-1 |
/// | +12 | e5 | e3 | pages-1 |
/// | +21 | e6 | e4 | pages-2 |
fn decoupled(a0: TransparentAddress, tail_end: u64, revision: u32) -> Vec<ShardSpec> {
    // Unrelated activity over the first revision's blocks alone, so a grown
    // tail changes none of its earlier blocks.
    let mut events = noise(H0 + 600, H0 + 619, 3);
    for (n, offset) in DECOUPLED_OFFSETS.iter().enumerate() {
        let (n, at) = (n as u64 + 1, H0 + 600 + offset);
        if at > tail_end {
            break;
        }
        let event = if n == 5 {
            spend(at, txid(n), (txid(1), 0))
        } else {
            receive(at, txid(n), 0, 10_000 * n)
        };
        events.push((script(a0), event));
    }
    vec![
        sealed(H0, H0 + 199, noise(H0, H0 + 199, 0)),
        sealed(H0 + 200, H0 + 399, noise(H0 + 200, H0 + 399, 1)),
        sealed(H0 + 400, H0 + 599, noise(H0 + 400, H0 + 599, 2)),
        ShardSpec {
            page_span: PAGE_SPAN,
            ..tail(tail_end, revision, events)
        },
    ]
}

/// Offsets from `H0 + 600` of `a0`'s events in [`decoupled`].
const DECOUPLED_OFFSETS: [u64; 6] = [1, 2, 3, 11, 12, 21];

impl Fixture {
    /// Pages queries the service received from the `from`th request on, by the
    /// page shard each addressed.
    fn pages_queries(&self, from: usize) -> Vec<u32> {
        let pages = Regex::new(PAGES_QUERY).unwrap();
        self.server.requests()[from..]
            .iter()
            .filter(|request| request.method == "POST")
            .filter_map(|request| {
                pages
                    .captures(&request.path)
                    .map(|captures| captures[2].parse().unwrap())
            })
            .collect()
    }

    /// Rows in the companion's run cache.
    fn cached_runs(&self) -> i64 {
        self.companion_db()
            .query_row("SELECT COUNT(*) FROM run_cache", [], |row| row.get(0))
            .unwrap()
    }
}

/// A history pushed into two page shards of the tail comes back exactly: the
/// walk reads the newest run, in the open page shard, then the older run in the
/// sealed one it points to, and caches that sealed run. Once the tail grows, the
/// catch-up reads the runs that changed and stops at the cached run, where a fresh
/// wallet walks the whole chain; both settle the same spendable outputs.
#[test]
fn a_history_across_page_shards_recovers_and_catch_up_stops_at_the_cached_run() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let birthday = H0 + 600;
    let (first_end, grown_end) = (H0 + 619, H0 + 629);
    let mut f = Fixture::new(birthday, first_end);
    f.trust_service();
    let a0 = f.derived(TransparentKeyScope::EXTERNAL, 0);
    let map = f.publish(&decoupled(a0, first_end, 0), SEAL);
    // pages-0 sealed over +0..=+9, pages-1 open over +10..=+19.
    assert_eq!(map.shards[3].page_segments, 2, "two page shards");

    let (pass, _) = f.sync_until_complete(3);
    assert_eq!(pass.batch.state, BatchState::Ready);
    assert_eq!(pass.batch.progress.outcome, Outcome::Complete);
    f.activate();
    // Runs pages-1 [e2, e3] and pages-0 [e1]; e4 and e5 inline, e5 spending e1.
    let expected: Vec<OutPoint> = {
        let mut outpoints: Vec<OutPoint> = [2, 3, 4].map(|n| outpoint(txid(n), 0)).to_vec();
        outpoints.sort_by_key(|outpoint| (*outpoint.hash(), outpoint.n()));
        outpoints
    };
    assert_eq!(f.spendable().unwrap(), expected);
    assert_eq!(
        f.pages_queries(0),
        vec![1, 0],
        "the head run, then the older one"
    );
    // Only the run in the sealed page shard is final, so only it is cached.
    assert_eq!(f.cached_runs(), 1);
    f.assert_private(&[0, 1, 2]);

    // The tail grows: pages-1 seals, pages-2 opens, and e6 pushes e4 into it.
    f.scan_to(grown_end);
    let seen = f.server.requests().len();
    f.publish(&decoupled(a0, grown_end, 1), SEAL);
    let pass = f.drive();
    assert_eq!(pass.batch.state, BatchState::Ready);
    assert_eq!(pass.batch.progress.outcome, Outcome::Complete);
    let expected: Vec<OutPoint> = {
        let mut outpoints: Vec<OutPoint> = [2, 3, 4, 6].map(|n| outpoint(txid(n), 0)).to_vec();
        outpoints.sort_by_key(|outpoint| (*outpoint.hash(), outpoint.n()));
        outpoints
    };
    assert_eq!(f.spendable().unwrap(), expected);
    // pages-2's head and pages-1's run, now sealed; pages-0's is cached.
    assert_eq!(
        f.pages_queries(seen),
        vec![2, 1],
        "the walk stops at the cached run"
    );
    assert_eq!(f.cached_runs(), 2);
    f.assert_private(&[0, 1, 2]);

    // A fresh wallet on the same chain pays for every run.
    let mut fresh = Fixture::new(birthday, grown_end);
    fresh.trust_service();
    let a0 = fresh.derived(TransparentKeyScope::EXTERNAL, 0);
    fresh.publish(&decoupled(a0, grown_end, 1), SEAL);
    let (pass, _) = fresh.sync_until_complete(3);
    assert_eq!(pass.batch.state, BatchState::Ready);
    assert_eq!(pass.batch.progress.outcome, Outcome::Complete);
    fresh.activate();
    assert_eq!(fresh.spendable().unwrap(), expected);
    assert_eq!(fresh.pages_queries(0), vec![2, 1, 0]);
    fresh.assert_private(&[0, 1, 2]);
}

/// A real page lookup respects small query and byte budgets and resumes from
/// SQLite after every pass, including midway through a run with many fragments.
#[test]
fn small_page_budgets_recover_a_long_history_across_restarts() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    for (queries, private_bytes) in [(1, 96 << 20), (256, 1)] {
        let birthday = H0 + 600;
        let mut f = Fixture::new(birthday, H0 + 619);
        f.trust_service();
        let address = f.derived(TransparentKeyScope::EXTERNAL, 0);
        let mut shards = decoupled(address, H0 + 619, 0);
        shards[3]
            .events
            .retain(|(owner, _)| *owner != script(address));
        shards[3].events.extend((0..200).map(|index| {
            (
                script(address),
                receive(birthday + 1, txid(500), index, 10_000),
            )
        }));
        f.publish(&shards, SEAL);
        // First retrieve only the directory, leaving an uncached page walk.
        f.companion = None;
        let mut bounded = config(f.account);
        bounded.queries = 1;
        let account = f.account_name();
        f.companion = Some(
            f.companions()
                .open(
                    &account,
                    bounded,
                    || Ok(BTreeSet::from([account.clone()])),
                    &|| false,
                )
                .unwrap(),
        );
        f.pass().unwrap();
        let mut complete = false;
        let mut saved_fragments = false;
        for _ in 0..40 {
            f.companion = None;
            let mut bounded = config(f.account);
            bounded.queries = queries;
            bounded.private_bytes = private_bytes;
            f.companion = Some(
                f.companions()
                    .open(
                        &account,
                        bounded,
                        || Ok(BTreeSet::from([account.clone()])),
                        &|| false,
                    )
                    .unwrap(),
            );
            let seen = f.server.requests().len();
            let pass = f.pass().unwrap();
            assert!(
                f.pages_queries(seen).len() <= 1,
                "a one-query or one-byte pass dispatched more than one page query"
            );
            saved_fragments |= f
                .companion_db()
                .query_row(
                    "SELECT COUNT(*) FROM pending_work WHERE length(fragments) > 0",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
                > 0;
            if pass.batch.progress.outcome == Outcome::Complete {
                complete = true;
                break;
            }
        }
        assert!(saved_fragments, "a partial run was saved across a restart");
        assert!(
            complete,
            "small-budget passes finish rather than repeat the head"
        );
        f.activate();
        let mut expected: Vec<_> = (0..200).map(|index| outpoint(txid(500), index)).collect();
        expected.sort_by_key(|outpoint| (*outpoint.hash(), outpoint.n()));
        assert_eq!(f.spendable().unwrap(), expected);
        f.assert_private(&[0, 1, 2]);
    }
}

/// The last height the re-cut tests publish, and the wallet's tip.
const RECUT_TIP: u64 = H0 + 549;

/// The re-cut tests' publication before the re-cut: sealed S0–S3 and the tail,
/// all in the usual geometry. `a0` receives in each of S1, S2 and S3; the tail
/// holds none of the account's events, so replacing it changes no wallet
/// output.
fn before_recut(a0: TransparentAddress) -> Vec<ShardSpec> {
    let paid = |start: u64, salt: u32| {
        let mut events = noise(start, start + 99, salt);
        let tag = u64::from(salt);
        events.push((script(a0), receive(start + 50, txid(tag), 0, 10_000 * tag)));
        events
    };
    vec![
        sealed(H0, H0 + 199, noise(H0, H0 + 199, 0)),
        sealed(H0 + 200, H0 + 299, paid(H0 + 200, 1)),
        sealed(H0 + 300, H0 + 399, paid(H0 + 300, 2)),
        sealed(H0 + 400, H0 + 499, paid(H0 + 400, 3)),
        ShardSpec {
            start: H0 + 500,
            end: RECUT_TIP,
            geometry: GEOMETRY,
            sealed: false,
            revision: 0,
            supersedes: String::new(),
            page_span: 0,
            events: noise(H0 + 500, RECUT_TIP, 4),
        },
    ]
}

/// The same chain re-cut: S1 and S2 merged into one wide shard W, and S3 and
/// the tail renumbered at their heights, one revision higher.
fn after_recut(a0: TransparentAddress) -> Vec<ShardSpec> {
    let mut shards = before_recut(a0).into_iter();
    let (s0, s1, s2, s3, tail) = (
        shards.next().unwrap(),
        shards.next().unwrap(),
        shards.next().unwrap(),
        shards.next().unwrap(),
        shards.next().unwrap(),
    );
    vec![
        s0,
        ShardSpec {
            start: s1.start,
            end: s2.end,
            geometry: WIDE,
            sealed: true,
            revision: 0,
            supersedes: String::new(),
            page_span: 0,
            events: [s1.events, s2.events].concat(),
        },
        ShardSpec { revision: 1, ..s3 },
        ShardSpec {
            revision: 1,
            ..tail
        },
    ]
}

/// A activated account that recovered the publication before the re-cut under
/// `PrivateRequired`: the fixture, the account's paid address, the map, the
/// tail revision the wallet holds, and the outputs it can spend.
fn recovered_before_recut() -> (
    Fixture,
    TransparentAddress,
    ShardMap,
    RecoveryRevision,
    Vec<OutPoint>,
) {
    let mut f = Fixture::new(H0 + 100, RECUT_TIP);
    f.set_policy(PrivateRequired);
    // Its passes qualify their revisions, so the account can be activated and a
    // re-cut's retired tail is reconciled through the trusted operation.
    f.trust_service();
    let a0 = f.derived(TransparentKeyScope::EXTERNAL, 0);
    let map = f.publish(&before_recut(a0), SEAL);
    let (first, _) = f.sync_until_complete(3);
    assert_eq!(first.batch.state, BatchState::Ready);
    assert_eq!(first.batch.progress.outcome, Outcome::Complete);
    let tail = tail_revision(&first.batch);
    f.activate();
    assert_eq!(f.authority(), TransparentAuthority::Private);
    let mut received: Vec<OutPoint> = (1..=3).map(|tag| outpoint(txid(tag), 0)).collect();
    received.sort_by_key(|outpoint| (*outpoint.hash(), outpoint.n()));
    assert_eq!(f.spendable().unwrap(), received);
    (f, a0, map, tail, received)
}

#[test]
fn a_declared_re_cut_keeps_the_wallets_history() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut f, a0, before, old_tail, received) = recovered_before_recut();
    let history = f.dump(false);
    let sealed = f.coverage_sealed(true);
    let seen = f.server.requests().len();

    // The publisher re-cuts S1–S2 into one wide shard behind the same origin,
    // and declares every entry it superseded.
    let recut = Recut {
        epoch: 1,
        from_height: H0 + 200,
        superseded: before.shards[1..].iter().map(fixture::superseded).collect(),
    };
    let after = f.publish_recut(&after_recut(a0), SEAL, vec![recut]);
    let recut_pass = f.pass().expect("a pass");
    assert_eq!(recut_pass.batch.state, BatchState::Ready);
    assert_eq!(recut_pass.batch.progress.outcome, Outcome::Complete);
    // The wallet's sealed history needed nothing: only the renumbered tail was
    // retrieved.
    assert_eq!(
        f.shards_requested(seen),
        BTreeSet::from([after.shards.last().unwrap().shard_id])
    );
    // Its successor replaced the old tail in the same source, through the
    // trusted reconciliation.
    let new_tail = tail_revision(&recut_pass.batch);
    assert_eq!(new_tail.source, old_tail.source);
    assert_eq!(new_tail.lineage, old_tail.lineage + 1);
    assert_eq!(recut_pass.batch.retired, vec![old_tail.clone()]);
    assert!(f.reconciled.contains(&old_tail));
    // Apart from the tail, the wallet is unchanged.
    assert_eq!(f.dump(false), history);
    assert_eq!(f.coverage_sealed(true), sealed);
    assert_eq!(
        f.provisional_coverage(),
        BTreeSet::from([(new_tail.source.clone(), new_tail.revision.clone())])
    );
    assert_eq!(f.count("tpir_quarantined_sources"), 0);
    assert_eq!(f.count("tpir_quarantined_accounts"), 0);
    assert_eq!(f.authority(), TransparentAuthority::Private);
    assert_eq!(f.spendable().unwrap(), received);

    // Companion loss after the re-cut: the recreated companion retrieves the
    // re-cut publication, and nothing it derives collides with what the
    // wallet holds.
    f.lose_companion();
    f.open();
    let healed = f.drive();
    assert_eq!(healed.batch.state, BatchState::Ready);
    assert_eq!(tail_revision(&healed.batch), new_tail);
    assert_eq!(f.count("tpir_quarantined_sources"), 0);
    assert_eq!(f.count("tpir_quarantined_accounts"), 0);
    assert_eq!(f.authority(), TransparentAuthority::Private);
    assert_eq!(f.spendable().unwrap(), received);

    f.assert_private(&[]);
}

#[test]
fn a_lagging_pre_re_cut_map_after_the_re_cut_changes_nothing() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut f, a0, before, _, received) = recovered_before_recut();
    let recut = Recut {
        epoch: 1,
        from_height: H0 + 200,
        superseded: before.shards[1..].iter().map(fixture::superseded).collect(),
    };
    f.publish_recut(&after_recut(a0), SEAL, vec![recut.clone()]);
    let recut_pass = f.pass().expect("a pass");
    assert_eq!(recut_pass.batch.state, BatchState::Ready);
    let new_tail = tail_revision(&recut_pass.batch);
    let history = f.dump(false);
    let ledger = f.dump(true);

    // A replica still serving the publication from before the re-cut. The
    // store finished reading nothing it rewrites, only the tail, so the pass
    // syncs normally, reads the old tail again, and finds it behind the one
    // the wallet holds: pending, every time, with nothing applied.
    let lagging_map = f.publish(&before_recut(a0), SEAL);
    assert_eq!(lagging_map, before);
    let seen = f.server.requests().len();
    for _ in 0..2 {
        let lagging = f.pass().expect("a pass");
        assert_eq!(lagging.batch.state, BatchState::Pending);
        assert!(lagging.batch.commits.is_empty());
        assert!(lagging.batch.retired.is_empty());
        assert_eq!(f.dump(true), ledger);
    }
    assert_eq!(
        f.shards_requested(seen),
        BTreeSet::from([lagging_map.shards.last().unwrap().shard_id])
    );
    assert_eq!(f.dump(false), history);
    assert_eq!(f.count("tpir_quarantined_sources"), 0);
    assert_eq!(f.count("tpir_quarantined_accounts"), 0);
    assert_eq!(f.spendable().unwrap(), received);

    // The re-cut map again: the renumbered tail is read once more and is
    // the one the wallet holds.
    f.publish_recut(&after_recut(a0), SEAL, vec![recut]);
    let back = f.pass().expect("a pass");
    assert_eq!(back.batch.state, BatchState::Ready);
    assert_eq!(tail_revision(&back.batch), new_tail);
    assert_eq!(f.dump(false), history);
    assert_eq!(f.count("tpir_quarantined_sources"), 0);
    assert_eq!(f.count("tpir_quarantined_accounts"), 0);
    assert_eq!(f.authority(), TransparentAuthority::Private);
    assert_eq!(f.spendable().unwrap(), received);
}

#[test]
fn an_undeclared_re_cut_reaches_nothing_in_the_wallet() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut f, a0, _, _, received) = recovered_before_recut();
    let wallet = f.dump(true);
    let seen = f.server.requests().len();

    // The same re-cut without a declaration rewrites sealed history the
    // wallet holds: the pass reads no shard, and nothing reaches the wallet,
    // before or after a reopen.
    f.publish(&after_recut(a0), SEAL);
    for reopen in [false, true] {
        if reopen {
            f.open();
        }
        let undeclared = f.pass().expect("a pass");
        assert_eq!(undeclared.batch.state, UNDECLARED_REWRITE);
        assert!(undeclared.batch.commits.is_empty());
        assert_eq!(f.dump(true), wallet);
    }
    assert!(f.shards_requested(seen).is_empty());
    assert_eq!(f.spendable().unwrap(), received);
}

/// The txid display service in process: a recent-replica worker serving one
/// recent shard of `records` over `[start, end]`, reached through its router.
struct DisplayService {
    runtime: tokio::runtime::Runtime,
    router: axum::Router,
    _root: tempfile::TempDir,
}

impl DisplayService {
    fn start(start: u64, end: u64, records: &[zakura_pir_transparent::DisplayEntry]) -> Self {
        use transparent_shard::display::{DisplaySealParams, TXID_4K8};
        use transparent_shard_server::{
            display::{
                DisplayRole,
                live::{DisplayCommand, DisplayLive, DisplayPublication},
                service::DisplayRuntime,
                synth,
            },
            service::{ReadinessMode, ServiceConfig},
        };
        let root = tempfile::tempdir().unwrap();
        let shard = synth::write_shard(
            root.path(),
            &synth::ShardSpec {
                shard_id: 0,
                start_height: start,
                end_height: end,
                sealed: false,
                revision: 0,
                supersedes: String::new(),
                parent_manifest_digest: String::new(),
                n_buckets: 1,
                archive_target: 1,
                geometry: &TXID_4K8,
            },
            records,
        )
        .unwrap();
        let params = DisplaySealParams {
            n_archive: 1,
            n_recent: 1,
            archive_target: 1,
            recent_window: 1,
            reorg_margin: 1,
        };
        let (directory, map_sha256) =
            synth::write_candidate(root.path(), &params, &[shard], "p0").unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let live = DisplayLive::new(
            DisplayRuntime::new(
                ServiceConfig {
                    cache_bytes: 2 << 30,
                    readiness: ReadinessMode::Warm,
                    ..ServiceConfig::default()
                },
                None,
            ),
            DisplayRole::RecentReplica,
            3,
            root.path().join("recent.active.json"),
            Vec::new(),
            None,
        )
        .unwrap();
        runtime.block_on(async {
            let expected = live.expected();
            live.command(DisplayCommand::Prepare {
                expected: expected.clone(),
                publication: DisplayPublication {
                    directory,
                    map_sha256: map_sha256.clone(),
                },
            })
            .await
            .unwrap();
            live.command(DisplayCommand::Activate {
                expected,
                map_sha256,
            })
            .await
            .unwrap();
        });
        Self {
            router: live.router(),
            runtime,
            _root: root,
        }
    }
}

/// A transport to the in-process display service that records every request
/// and can answer 503 in its place.
struct DisplayTransport<'a> {
    service: &'a DisplayService,
    unavailable: bool,
    sent: Vec<(String, Vec<u8>)>,
}

impl zakura_pir_transparent::TxidTransport for DisplayTransport<'_> {
    fn send(
        &mut self,
        request: zakura_pir_transparent::TxidRequest,
    ) -> Result<zakura_pir_transparent::TxidReply, zakura_pir_transparent::TransportError> {
        use tower::ServiceExt as _;
        self.sent
            .push((request.path().to_string(), request.body.clone()));
        if self.unavailable {
            return Ok(zakura_pir_transparent::TxidReply {
                status: 503,
                retry_after: Some("120".into()),
                ..Default::default()
            });
        }
        let mut builder = axum::http::Request::builder()
            .method(request.method.as_str())
            .uri(request.path())
            .header("content-length", request.body.len());
        if let Some(content_type) = request.content_type() {
            builder = builder.header("content-type", content_type);
        }
        let http = builder
            .body(axum::body::Body::from(request.body.clone()))
            .unwrap();
        let router = self.service.router.clone();
        self.service.runtime.block_on(async move {
            let response = router.oneshot(http).await.unwrap();
            let header = |name: &str| {
                response
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string)
            };
            let (status, retry_after, map_sha256) = (
                response.status().as_u16(),
                header("retry-after"),
                header("x-txid-map-sha256"),
            );
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .map_err(|e| zakura_pir_transparent::TransportError(e.to_string()))?;
            Ok(zakura_pir_transparent::TxidReply {
                status,
                retry_after,
                map_sha256,
                body: body.to_vec(),
            })
        })
    }
}

#[test]
fn private_details_end_to_end() {
    use std::time::{SystemTime, UNIX_EPOCH};
    use transparent_shard::txid::{DisplayFacts, DisplayOutput};
    use zakura_pir_transparent::{
        TxidDisplayClient, TxidLookup, deferral, display_facts, map_sha256,
    };
    use zcash_client_backend::data_api::transparent_ledger::{
        TransparentDetailRead as _, TransparentDetailWrite as _, TransparentDisplaySource,
        TransparentDisplayStore, TransparentDisplayView, TransparentDisplayViewSender,
    };
    use zcash_primitives::transaction::TxId;

    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let birthday = H0 + 610;
    let target = H0 + 640;
    let mut f = Fixture::new(birthday, target);
    f.trust_service();
    let a0 = f.derived(TransparentKeyScope::EXTERNAL, 0);
    // r1 is published by the display service; r2 is mined above its recent shard.
    let (r1, r2) = (txid(1), txid(6));
    let mut tail_events = noise(H0 + 600, target, 3);
    tail_events.push((script(a0), receive(H0 + 620, r1, 0, 20_000)));
    tail_events.push((script(a0), receive(H0 + 625, r2, 1, 5_000)));
    f.publish(
        &[
            sealed(H0, H0 + 199, noise(H0, H0 + 199, 0)),
            sealed(H0 + 200, H0 + 399, noise(H0 + 200, H0 + 399, 1)),
            sealed(H0 + 400, H0 + 599, noise(H0 + 400, H0 + 599, 2)),
            tail(target, 0, tail_events),
        ],
        SEAL,
    );
    assert_eq!(f.sync_until_complete(3).0.batch.state, BatchState::Ready);
    f.activate();
    // Both receives are projected; spendability is unchanged by what follows.
    let spendable = f.spendable().unwrap();
    assert!(spendable.contains(&outpoint(r1, 0)), "{spendable:?}");

    // Loop 4's work: both recovered transactions lack raw bytes. The listing's snapshot
    // forbids public transport.
    let now = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    let due = |f: &Fixture, at: SystemTime| -> Vec<(TxId, u64)> {
        let work =
            f.st.wallet()
                .db()
                .transparent_detail_work(at, 10, &[], None)
                .unwrap();
        assert!(!work.public_transport());
        work.requests
            .into_iter()
            .map(|r| (r.txid, u64::from(u32::from(r.mined_height))))
            .collect()
    };
    let work = due(&f, now);
    assert_eq!(
        work.iter()
            .map(|(t, _)| *t.as_ref())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([r1.0, r2.0])
    );

    // r1 pays a0 from one input of someone else's; the publisher derives its entry from the
    // spent output. Every other entry is noise.
    let sender = unrelated(999);
    let mut records = vec![
        DisplayFacts {
            txid: r1,
            coinbase: false,
            fee: 1_000,
            has_shielded_components: false,
            spent: vec![DisplayOutput {
                value: 21_000,
                script: sender.as_slice().to_vec(),
            }],
            outputs: vec![DisplayOutput {
                value: 20_000,
                script: script(a0).as_slice().to_vec(),
            }],
        }
        .entry()
        .unwrap(),
    ];
    records.extend((0..40u64).map(|n| {
        DisplayFacts {
            txid: txid(500 + n),
            coinbase: false,
            fee: 1_000,
            has_shielded_components: n % 2 == 0,
            spent: vec![DisplayOutput {
                value: n + 1_000,
                script: unrelated(n as u32).as_slice().to_vec(),
            }],
            outputs: vec![DisplayOutput {
                value: n,
                script: unrelated(n as u32).as_slice().to_vec(),
            }],
        }
        .entry()
        .unwrap()
    }));
    let service = DisplayService::start(H0 + 600, H0 + 622, &records);
    // What a public `GetTransaction` would have fetched; it must never be called.
    let public_fetches = std::cell::Cell::new(0usize);
    // The published recent shard holds a handful of txids, below the client's own floor.
    let mut client = TxidDisplayClient::new().with_min_recent_floor(1);
    let mut transport = DisplayTransport {
        service: &service,
        unavailable: true,
        sent: Vec::new(),
    };
    let view = |f: &Fixture, txid: Txid| {
        f.st.wallet()
            .db()
            .transparent_display_view(f.account, TxId::from_bytes(txid.0))
            .unwrap()
            .unwrap()
    };
    // Every table but the display work and facts.
    let wallet_state = |f: &Fixture| -> Vec<_> {
        f.dump(true)
            .into_iter()
            .filter(|(table, _)| {
                table != "transparent_detail_work" && !table.starts_with("transparent_tx_display")
            })
            .collect()
    };
    let before = wallet_state(&f);
    let lookup_all = |f: &mut Fixture,
                      client: &mut TxidDisplayClient,
                      transport: &mut DisplayTransport,
                      work: &[(TxId, u64)],
                      at: SystemTime| {
        // As the app dispatches: public transport only under a public snapshot whose generation
        // is still current, otherwise the private display service.
        let snapshot =
            f.st.wallet()
                .db()
                .transparent_detail_work(at, 10, &[], None)
                .unwrap();
        let current =
            f.st.wallet()
                .db()
                .applied_transparent_policy()
                .unwrap()
                .generation;
        for (txid, height) in work {
            if snapshot.public_transport() && snapshot.policy_generation == current {
                public_fetches.set(public_fetches.get() + 1);
                continue;
            }
            let result = client.lookup(transport, *txid.as_ref(), *height, &|| false);
            let map = client.map_sha256().and_then(map_sha256);
            let db = f.st.wallet_mut().db_mut();
            match (&result, deferral(&result)) {
                (Ok(TxidLookup::Found { entry, provenance }), None) => {
                    let facts =
                        display_facts(*txid, entry, provenance, BlockHeight::from(*height as u32))
                            .unwrap();
                    let generation = db.applied_transparent_policy().unwrap().generation;
                    assert_eq!(
                        db.store_transparent_display(facts, generation, at).unwrap(),
                        TransparentDisplayStore::Stored
                    );
                }
                (_, Some(outcome)) => db
                    .defer_transparent_detail(
                        *txid,
                        BlockHeight::from(*height as u32),
                        outcome,
                        map,
                        current,
                        at,
                    )
                    .unwrap(),
                (other, None) => panic!("unexpected lookup result {other:?}"),
            }
        }
    };

    // The service is down: both lookups are deferred, nothing else changes, and
    // the details show as unavailable. There is no public fallback.
    lookup_all(&mut f, &mut client, &mut transport, &work, now);
    assert_eq!(view(&f, r1), TransparentDisplayView::Unavailable);
    assert_eq!(view(&f, r2), TransparentDisplayView::Unavailable);
    assert_eq!(due(&f, now), vec![]);
    assert_eq!(f.spendable().unwrap(), spendable);
    assert_eq!(f.authority(), TransparentAuthority::Private);

    // The service is back after the advised delay: r1 reconciles; r2 is newer than the
    // publication, so it stays pending and is retried within minutes.
    transport.unavailable = false;
    let later = now + Duration::from_secs(3_600);
    let work = due(&f, later);
    assert_eq!(work.len(), 2);
    lookup_all(&mut f, &mut client, &mut transport, &work, later);
    let TransparentDisplayView::Available(details) = view(&f, r1) else {
        panic!("expected available details for r1");
    };
    assert!(matches!(
        details.source,
        TransparentDisplaySource::Display(_)
    ));
    assert_eq!(details.outputs.len(), 1);
    assert!(details.outputs[0].owned);
    assert_eq!(
        details.outputs[0].address.as_ref().map(|a| a.address),
        Some(a0)
    );
    assert_eq!(details.input_count, 1);
    // The sender is the spent output's address, which is not the account's.
    let TransparentDisplayViewSender::Address { address, owned } = &details.sender else {
        panic!("expected a sender address, got {:?}", details.sender);
    };
    assert_eq!(
        Some(address.address),
        zcash_client_backend::data_api::transparent_ledger::transparent_display_address(
            sender.as_slice()
        )
    );
    assert!(!owned);
    assert!(details.is_complete());
    assert_eq!(view(&f, r2), TransparentDisplayView::Pending);
    let pending = due(&f, later + Duration::from_secs(6 * 60));
    assert_eq!(
        pending.iter().map(|(t, _)| *t.as_ref()).collect::<Vec<_>>(),
        vec![r2.0]
    );
    assert_eq!(due(&f, later), vec![]);
    let parked =
        f.st.wallet()
            .db()
            .transparent_detail_parked(later, client.map_sha256().and_then(map_sha256), None)
            .unwrap();
    assert_eq!(parked.count, 0);
    // A coverage re-check fetches only the map, which is the one r1 was found through.
    let sent = transport.sent.len();
    let refreshed = client.refresh_map(&mut transport, &|| false).unwrap();
    assert_eq!(transport.sent.len(), sent + 1);
    let TransparentDisplaySource::Display(provenance) = &details.source else {
        unreachable!()
    };
    assert_eq!(refreshed, provenance.map_sha256);

    // Display facts never touch wallet state outside their own tables.
    let after = wallet_state(&f);
    assert_eq!(after, before);
    assert_eq!(f.spendable().unwrap(), spendable);

    // Privacy: no public fetch, only the display routes, and no request names either txid.
    assert_eq!(public_fetches.get(), 0);
    assert!(!transport.sent.is_empty());
    for (path, body) in &transport.sent {
        assert!(path.starts_with("/v2/txid/"), "{path}");
        for txid in [r1, r2] {
            let mut display = txid.0;
            display.reverse();
            for needle in [hex::encode(txid.0), hex::encode(display)] {
                assert!(!path.contains(&needle), "{path}");
            }
            assert!(
                !body.windows(32).any(|w| w == txid.0),
                "a body carries the txid"
            );
        }
    }

    // Positive control: the same dispatch, under a mode that retains public authority, fetches
    // r2 publicly and sends nothing to the display service.
    f.set_policy(TransparentLedgerMode::Public);
    let at = later + Duration::from_secs(6 * 60);
    let public =
        f.st.wallet()
            .db()
            .transparent_detail_work(at, 10, &[], None)
            .unwrap();
    assert!(public.public_transport());
    let work: Vec<(TxId, u64)> = public
        .requests
        .into_iter()
        .map(|r| (r.txid, u64::from(u32::from(r.mined_height))))
        .collect();
    assert_eq!(
        work.iter().map(|(t, _)| *t.as_ref()).collect::<Vec<_>>(),
        vec![r2.0]
    );
    let sent = transport.sent.len();
    lookup_all(&mut f, &mut client, &mut transport, &work, at);
    assert_eq!(public_fetches.get(), 1);
    assert_eq!(transport.sent.len(), sent);
}

/// Installs a trigger on the wallet's own connection that runs `action` once,
/// inside the transaction of the first commit that registers a new revision.
fn once_after_new_revision(f: &Fixture, action: &str) {
    f.st.wallet()
        .conn()
        .execute_batch(&format!(
            "CREATE TEMP TABLE IF NOT EXISTS fired (x);
             DELETE FROM temp.fired;
             CREATE TEMP TRIGGER inject AFTER INSERT ON main.tpir_revisions
             WHEN NOT EXISTS (SELECT 1 FROM temp.fired)
             BEGIN
                 INSERT INTO fired VALUES (1);
                 {action};
             END;"
        ))
        .unwrap();
}

fn remove_injection(f: &Fixture) {
    f.st.wallet()
        .conn()
        .execute_batch("DROP TRIGGER IF EXISTS temp.inject")
        .unwrap();
}

/// A wallet under `PrivateRequired` with the lifecycle's first publication
/// served, and nothing recovered yet.
fn private_fixture() -> (Fixture, Owned) {
    private_fixture_with_factory(TestDbFactory::default())
}

fn private_fixture_with_factory(factory: TestDbFactory) -> (Fixture, Owned) {
    let birthday = H0 + 250;
    let mut f = Fixture::with_factory(birthday, H0 + 649, factory);
    let owned = Owned {
        a0: f.derived(TransparentKeyScope::EXTERNAL, 0),
        a1: f.derived(TransparentKeyScope::EXTERNAL, 1),
        last: f.last_external(),
    };
    f.publish(&lifecycle(&owned, H0 + 649, 0, false), SEAL);
    f.trust_service();
    (f, owned)
}

#[test]
fn a_policy_change_while_acknowledgment_waits_keeps_the_batch_unacknowledged() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut f, _) = private_fixture_with_factory(TestDbFactory::file_backed());
    let batch = f.recover().unwrap();
    assert_eq!(batch.state(), BatchState::Ready);
    let commits = batch.commits().len();
    assert!(commits > 0);
    let wallet_path = f.st.wallet().conn().path().unwrap().to_owned();
    assert!(
        !wallet_path.is_empty(),
        "this race requires a shared database file"
    );
    // Allow all wallet commits but pause the companion acknowledgment. This
    // places a real second-connection generation change after the final wallet
    // commit and before the companion can commit its receipt.
    let companion = Connection::open(f.companion_path()).unwrap();
    companion.execute_batch("BEGIN IMMEDIATE").unwrap();
    let second = Connection::open(wallet_path).unwrap();
    let run = std::thread::spawn(move || {
        let result = f.settle(batch, Trust::Trusted);
        (f, result)
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let qualified: usize = second
            .query_row("SELECT COUNT(*) FROM tpir_qualified_revisions", [], |r| {
                r.get(0)
            })
            .unwrap();
        if qualified == commits {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "wallet commits did not finish"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    second
        .execute(
            "UPDATE tpir_meta SET policy_generation = policy_generation + 1",
            [],
        )
        .unwrap();
    companion.execute_batch("ROLLBACK").unwrap();
    let (mut f, result) = run.join().unwrap();
    let failure = result.expect_err("the policy changed before acknowledgment committed");
    assert_eq!(failure.stats.applied, commits);
    assert!(
        matches!(failure.error, ApplyError::PolicyChanged),
        "{failure:?}"
    );
    assert_eq!(failure.action(), ApplyAction::PolicyChanged);
    assert_eq!(failure.stats.qualified, commits);
    assert!(f.st.wallet().db().is_autocommit());
    let facts = f.dump(true);
    f.open();
    let replay = f.recover().unwrap();
    assert_eq!(replay.state(), BatchState::Ready);
    assert_eq!(replay.commits().len(), commits);
    let applied = f.settle(replay, Trust::Trusted).unwrap();
    assert_eq!(applied.stats.applied, commits);
    assert_eq!(
        f.count("tpir_qualified_revisions"),
        i64::try_from(commits).unwrap()
    );
    // The first pass grew the address window. A fresh watch set may extend
    // coverage on replay, but it must keep every committed row and must not
    // change the financial facts or their qualification.
    for ((table, before), (after_table, after)) in facts.into_iter().zip(f.dump(true)) {
        assert_eq!(table, after_table);
        if table == "tpir_coverage" {
            assert!(
                before.iter().all(|row| after.contains(row)),
                "coverage shrank"
            );
        } else {
            assert!(before == after, "{table} changed during replay");
        }
    }
}

/// Both settlements check the policy generation again after the last commit:
/// a change inside the last commit's own transaction leaves every commit
/// applied and is still reported, with or without a companion.
#[cfg(feature = "testing")]
#[test]
fn a_policy_change_in_the_last_commit_is_reported_by_both_settlements() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    for companion in [true, false] {
        let (mut f, _) = private_fixture();
        let batch = f.recover().unwrap();
        assert_eq!(batch.state(), BatchState::Ready);
        let commits = batch.commits().len();
        assert!(commits > 0);
        f.st.wallet()
            .conn()
            .execute_batch(&format!(
                "CREATE TEMP TRIGGER inject AFTER INSERT ON main.tpir_qualified_revisions
                 WHEN (SELECT COUNT(*) FROM main.tpir_qualified_revisions) = {commits}
                 BEGIN
                     UPDATE tpir_meta SET policy_generation = policy_generation + 1;
                 END;"
            ))
            .unwrap();
        let failure = if companion {
            f.settle(batch, Trust::Trusted)
        } else {
            zakura_pir_transparent::testing::apply(
                batch,
                f.st.wallet_mut().db_mut(),
                Trust::Trusted,
            )
        }
        .expect_err("the policy changed in the last commit");
        remove_injection(&f);
        assert!(
            matches!(failure.error, ApplyError::PolicyChanged),
            "companion {companion}: {failure:?}"
        );
        assert_eq!(failure.stats.applied, commits, "companion {companion}");
        assert_eq!(
            f.count("tpir_qualified_revisions"),
            i64::try_from(commits).unwrap()
        );
    }
}

#[test]
fn acknowledgment_does_not_add_a_wallet_commit_after_the_facts_are_durable() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut f, _) = private_fixture_with_factory(TestDbFactory::file_backed());
    let batch = f.recover().unwrap();
    assert_eq!(batch.state(), BatchState::Ready);
    let commits = batch.commits().len();
    let wallet_commits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = wallet_commits.clone();
    f.st.wallet().conn().commit_hook(Some(move || {
        seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        false
    }));
    let applied = f.settle(batch, Trust::Trusted).unwrap();
    f.st.wallet().conn().commit_hook(None::<fn() -> bool>);
    assert_eq!(applied.stats.applied, commits);
    assert_eq!(
        wallet_commits.load(std::sync::atomic::Ordering::SeqCst),
        commits
    );
    assert!(f.st.wallet().db().is_autocommit());
}

#[test]
fn apply_and_acknowledge_keeps_the_committed_prefix_and_replays_idempotently() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut f, _) = private_fixture();

    // Another connection changes the policy while the batch applies: the first
    // commit's transaction stays committed, the next is refused, and nothing is
    // acknowledged.
    let batch = f.recover().unwrap();
    let commits = batch.commits().len();
    assert!(commits >= 3, "the publication has three shards: {commits}");
    once_after_new_revision(
        &f,
        "UPDATE tpir_meta SET policy_generation = policy_generation + 1",
    );
    let failure = f.settle(batch, Trust::Trusted).unwrap_err();
    remove_injection(&f);
    assert!(
        matches!(failure.error, ApplyError::PolicyChanged),
        "{:?}",
        failure.error
    );
    assert_eq!(failure.stats.applied, 1);
    assert_eq!(failure.stats.qualified, 1);
    assert!(f.st.wallet().db().is_autocommit());
    assert_eq!(f.count("tpir_qualified_revisions"), 1);

    // A crash before acknowledgment: the reopened companion exports the same
    // revisions. A stale middle commit then stops the replay after the commit
    // that registered the next revision.
    f.open();
    let batch = f.recover().unwrap();
    assert_eq!(batch.state(), BatchState::Ready);
    assert_eq!(batch.commits().len(), commits);
    once_after_new_revision(
        &f,
        "INSERT INTO tpir_active_accounts (account_id) SELECT id FROM main.accounts",
    );
    let failure = f.settle(batch, Trust::Trusted).unwrap_err();
    remove_injection(&f);
    f.st.wallet()
        .conn()
        .execute("DELETE FROM tpir_active_accounts", [])
        .unwrap();
    assert!(
        matches!(
            failure.error,
            ApplyError::Rejected {
                index: 2,
                rejection: CommitRejection::Stale(StaleCommit::LifecycleChanged),
            }
        ),
        "{:?}",
        failure.error
    );
    assert_eq!(failure.stats.applied, 2);
    assert_eq!(f.count("tpir_qualified_revisions"), 2);

    // A wallet transaction that fails to commit stops the batch at that commit.
    let batch = f.recover().unwrap();
    let commits_seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let seen = commits_seen.clone();
        f.st.wallet().conn().commit_hook(Some(move || {
            // Roll back the second commit's transaction.
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1
        }));
    }
    let failure = f.settle(batch, Trust::Trusted).unwrap_err();
    f.st.wallet().conn().commit_hook(None::<fn() -> bool>);
    assert!(
        matches!(failure.error, ApplyError::Wallet(_)),
        "{:?}",
        failure.error
    );
    assert_eq!(failure.stats.applied, 1);

    // The next pass applies every commit and acknowledges; replaying it again
    // changes nothing.
    let batch = f.recover().unwrap();
    let applied = f.settle(batch, Trust::Trusted).unwrap();
    assert_eq!(applied.stats.applied, commits);
    assert_eq!(applied.stats.qualified, commits);
    assert_eq!(f.count("tpir_qualified_revisions"), 3);
    let settled = f.dump(true);
    let batch = f.recover().unwrap();
    let replayed = f.settle(batch, Trust::Trusted).unwrap();
    assert!(!replayed.stats.window_grew);
    assert_eq!(f.dump(true), settled);
    // Nothing above activated the account or granted authority.
    assert_eq!(f.watch().lifecycle, AccountLifecycle::Candidate);
    assert_ne!(f.authority(), TransparentAuthority::Private);
}

/// A [`WriteGate`] that runs the first `allow` wallet writes and declines the
/// next, counting what it ran.
struct AllowWrites {
    allow: usize,
    ran: usize,
}

impl WriteGate for AllowWrites {
    fn write<T>(&mut self, write: impl FnOnce() -> T) -> Result<T, Interrupted> {
        if self.ran == self.allow {
            return Err(Interrupted);
        }
        self.ran += 1;
        Ok(write())
    }
}

#[test]
fn a_gate_runs_each_wallet_write_and_can_stop_the_batch_between_them() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut f, _) = private_fixture();
    let batch = f.recover().unwrap();
    let commits = batch.commits().len();
    assert!(commits >= 3, "the publication has three shards: {commits}");

    // Declined before the second commit: the first stays applied and nothing is
    // acknowledged.
    let mut gate = AllowWrites { allow: 1, ran: 0 };
    let failure = f
        .settle_gated(batch, Trust::Trusted, &mut gate)
        .unwrap_err();
    assert!(
        matches!(failure.error, ApplyError::Interrupted),
        "{:?}",
        failure.error
    );
    assert_eq!(failure.action(), ApplyAction::Interrupted);
    assert_eq!(failure.stats.applied, 1);
    assert_eq!(f.count("tpir_qualified_revisions"), 1);
    assert!(f.st.wallet().db().is_autocommit());

    // Declined at the acknowledgment: every commit applied, and the next pass
    // exports the batch again.
    let batch = f.recover().unwrap();
    assert_eq!(batch.state(), BatchState::Ready);
    assert_eq!(batch.commits().len(), commits);
    let mut gate = AllowWrites {
        allow: commits,
        ran: 0,
    };
    let failure = f
        .settle_gated(batch, Trust::Trusted, &mut gate)
        .unwrap_err();
    assert!(
        matches!(failure.error, ApplyError::Interrupted),
        "{:?}",
        failure.error
    );
    assert_eq!(failure.stats.applied, commits);
    assert!(f.st.wallet().db().is_autocommit());

    // A gate that runs everything sees one write per commit and one for the
    // acknowledgment, and settles exactly as the ungated operation replays.
    let batch = f.recover().unwrap();
    assert_eq!(batch.commits().len(), commits);
    let mut gate = AllowWrites {
        allow: usize::MAX,
        ran: 0,
    };
    let applied = f.settle_gated(batch, Trust::Trusted, &mut gate).unwrap();
    assert_eq!(gate.ran, commits + 1);
    assert_eq!(applied.stats.applied, commits);
    assert_eq!(f.count("tpir_qualified_revisions"), 3);
    let settled = f.dump(true);
    let batch = f.recover().unwrap();
    f.settle(batch, Trust::Trusted).unwrap();
    assert_eq!(f.dump(true), settled);
}

#[test]
fn retirements_are_acknowledged_only_after_trusted_reconciliation_commits() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut f, owned) = private_fixture();
    let first = f.drive();
    let first_tail = tail_revision(&first.batch);
    f.scan_to(H0 + 669);
    f.publish(&lifecycle(&owned, H0 + 669, 1, false), SEAL);

    // Observed trust refuses the batch before applying anything.
    let before = f.dump(true);
    let batch = f.recover().unwrap();
    assert_eq!(batch.retired_revisions(), &[first_tail.clone()][..]);
    let failure = f.settle(batch, Trust::Observed).unwrap_err();
    assert!(matches!(failure.error, ApplyError::Unreconciled));
    assert_eq!(failure.stats, Default::default());
    assert_eq!(f.dump(true), before);

    // Every commit applies, but the companion cannot record the acknowledgment.
    let batch = f.recover().unwrap();
    assert_eq!(batch.retired_revisions(), &[first_tail.clone()][..]);
    let commits = batch.commits().len();
    let companion = Connection::open(f.companion_path()).unwrap();
    companion
        .execute_batch(
            "CREATE TRIGGER refuse_ack BEFORE UPDATE OF exported ON pir_bridge_catalog
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .unwrap();
    let failure = f.settle(batch, Trust::Trusted).unwrap_err();
    companion.execute_batch("DROP TRIGGER refuse_ack").unwrap();
    assert!(
        matches!(failure.error, ApplyError::Acknowledge(_)),
        "{:?}",
        failure.error
    );
    assert_eq!(failure.stats.applied, commits);
    // The wallet's trusted operation withdrew the replaced tail's coverage.
    assert_eq!(f.coverage_of(&first_tail), 0);
    let reconciled = f.dump(true);

    // Unacknowledged, the retirement is listed again; the replay changes
    // nothing in the wallet and is acknowledged.
    let batch = f.recover().unwrap();
    assert_eq!(batch.retired_revisions(), &[first_tail.clone()][..]);
    let applied = f.settle(batch, Trust::Trusted).unwrap();
    assert_eq!(applied.retired, 1);
    assert_eq!(f.dump(true), reconciled);
    let batch = f.recover().unwrap();
    assert!(batch.retired_revisions().is_empty());
}

/// A trusted successor can retire old evidence in the committed prefix, but
/// a stale middle commit still leaves the whole batch's catalog unacknowledged.
#[test]
fn stale_middle_retirement_batch_preserves_reconciliation_across_reopen() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut f, owned) = private_fixture();
    let first = f.drive();
    let retired = tail_revision(&first.batch);
    let target = H0 + 1049;
    f.scan_to(target);
    let mut shards = lifecycle(&owned, H0 + 799, 1, false);
    // The old unsealed source has a sealed successor, followed by two more
    // sources. The next refusal is in the middle, with a later commit unreached.
    let successor = shards.last_mut().unwrap();
    successor.sealed = true;
    successor.revision = 1;
    shards.push(sealed(H0 + 800, H0 + 999, noise(H0 + 800, H0 + 999, 4)));
    shards.push(ShardSpec {
        start: H0 + 1000,
        end: target,
        geometry: GEOMETRY,
        sealed: false,
        revision: 0,
        supersedes: String::new(),
        page_span: 0,
        events: noise(H0 + 1000, target, 5),
    });
    f.publish(&shards, SEAL);
    let batch = f.recover().unwrap();
    assert_eq!(batch.state(), BatchState::Ready);
    assert_eq!(batch.retired_revisions(), &[retired.clone()][..]);
    let commits = batch.commits().len();
    assert_eq!(commits, 5);
    once_after_new_revision(
        &f,
        "INSERT INTO tpir_active_accounts (account_id) SELECT id FROM main.accounts",
    );
    let failure = f.settle(batch, Trust::Trusted).unwrap_err();
    remove_injection(&f);
    f.st.wallet()
        .conn()
        .execute("DELETE FROM tpir_active_accounts", [])
        .unwrap();
    assert!(
        matches!(
            failure.error,
            ApplyError::Rejected {
                index: 3,
                rejection: CommitRejection::Stale(StaleCommit::LifecycleChanged),
            }
        ),
        "{failure:?}"
    );
    assert_eq!(failure.stats.applied, 3);
    assert_eq!(failure.stats.qualified, 3);
    assert_eq!(
        f.coverage_of(&retired),
        0,
        "the prefix reconciled its successor"
    );
    assert!(f.st.wallet().db().is_autocommit());
    assert_eq!(f.watch().lifecycle, AccountLifecycle::Candidate);

    // Simulate interruption before acknowledgement, then reopen both the
    // catalog and reference state. The retirement remains listed until the
    // complete replay reaches durable wallet storage and acknowledges it.
    f.open();
    let replay = f.recover().unwrap();
    assert_eq!(replay.state(), BatchState::Ready);
    assert_eq!(replay.retired_revisions(), &[retired.clone()][..]);
    assert_eq!(replay.commits().len(), commits);
    let applied = f.settle(replay, Trust::Trusted).unwrap();
    assert_eq!(applied.stats.applied, commits);
    assert_eq!(applied.retired, 1);
    assert_eq!(f.coverage_of(&retired), 0);
    let settled = f.dump(true);
    let again = f.recover().unwrap();
    assert!(again.retired_revisions().is_empty());
    f.settle(again, Trust::Trusted).unwrap();
    assert_eq!(f.dump(true), settled);
    assert_eq!(f.watch().lifecycle, AccountLifecycle::Candidate);
    assert_ne!(f.authority(), TransparentAuthority::Private);
}

#[test]
fn an_integrity_rejection_records_recovery_suspension_for_durably_without_acknowledgment() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let birthday = H0 + 250;
    let mut f = Fixture::new(birthday, H0 + 649);
    let owned = Owned {
        a0: f.derived(TransparentKeyScope::EXTERNAL, 0),
        a1: f.derived(TransparentKeyScope::EXTERNAL, 1),
        last: f.last_external(),
    };
    f.publish(&lifecycle(&owned, H0 + 649, 0, false), SEAL);
    // Untrusted recovery observes the publication.
    f.drive();
    // The wallet's stored receives now disagree with what the source exports.
    f.st.wallet()
        .conn()
        .execute(
            "UPDATE tpir_receive_events SET value_zat = value_zat + 1",
            [],
        )
        .unwrap();
    let batch = f.recover().unwrap();
    assert!(
        batch
            .commits()
            .iter()
            .any(|commit| !commit.receives.is_empty())
    );
    let failure = f.settle(batch, Trust::Observed).unwrap_err();
    assert!(
        matches!(
            failure.error,
            ApplyError::Rejected {
                rejection: CommitRejection::Integrity(_),
                ..
            }
        ),
        "{:?}",
        failure.error
    );
    // The recovery suspension committed with its commit's own transaction.
    assert!(f.st.wallet().db().is_autocommit());
    assert!(f.count("tpir_quarantined_sources") >= 1);
    assert_eq!(f.count("tpir_quarantined_accounts"), 1);
    // A later batch is refused by the durable recovery suspension.
    let batch = f.recover().unwrap();
    let failure = f.settle(batch, Trust::Observed).unwrap_err();
    assert!(
        matches!(
            failure.error,
            ApplyError::Rejected {
                index: 0,
                rejection: CommitRejection::Refused(_),
            }
        ),
        "{:?}",
        failure.error
    );
    assert_eq!(failure.stats.applied, 0);
}

impl Fixture {
    /// Forgets private recovery through `gate`, waiting for no companion.
    fn forget(
        &mut self,
        gate: &mut impl WriteGate,
    ) -> Result<ForgottenTransparentLedger, ForgetError> {
        forget_private_recovery(
            &self.companions(),
            self.st.wallet_mut().db_mut(),
            gate,
            Duration::ZERO,
        )
    }

    /// The private ledger facts the wallet holds: recovered events and coverage.
    fn ledger_facts(&self) -> i64 {
        self.count("tpir_receive_events")
            + self.count("tpir_spend_events")
            + self.count("tpir_coverage")
    }
}

#[test]
fn forgetting_private_recovery_deletes_companions_before_the_facts() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut f, _) = private_fixture();
    f.drive();
    let facts = f.ledger_facts();
    assert!(facts > 0);
    f.companion = None;

    // A wallet still recovering privately keeps its facts and its companions.
    assert!(matches!(
        f.forget(&mut Ungated),
        Err(ForgetError::NotPublic)
    ));
    assert!(f.companion_path().exists());
    assert_eq!(f.ledger_facts(), facts);

    // A companion in use defers forgetting: the facts stay with it.
    f.set_policy(TransparentLedgerMode::Public);
    f.open();
    assert!(matches!(
        f.forget(&mut Ungated),
        Err(ForgetError::CompanionBusy)
    ));
    assert!(f.companion_path().exists());
    assert_eq!(f.ledger_facts(), facts);

    // A declined write forgets nothing, but the companions are gone already.
    f.companion = None;
    assert!(matches!(
        f.forget(&mut AllowWrites { allow: 0, ran: 0 }),
        Err(ForgetError::Interrupted)
    ));
    assert!(!f.companion_path().exists());
    assert_eq!(f.ledger_facts(), facts);

    let forgotten = f.forget(&mut Ungated).unwrap();
    assert!(!forgotten.removed_nothing());
    assert_eq!(f.ledger_facts(), 0);
    // Forgetting again finds nothing.
    assert!(f.forget(&mut Ungated).unwrap().removed_nothing());

    // A later private run starts afresh, from a new companion, and recovers the facts again.
    f.set_policy(PrivateRequired);
    f.open();
    f.drive();
    assert!(f.ledger_facts() > 0);
}

/// A [`WriteGate`] that raises the wallet's durable policy to `PrivateRequired` through
/// another connection before running the write.
struct RaisePolicy {
    wallet: Connection,
}

impl WriteGate for RaisePolicy {
    fn write<T>(&mut self, write: impl FnOnce() -> T) -> Result<T, Interrupted> {
        self.wallet
            .execute(
                "UPDATE tpir_meta SET applied_mode = 2,
                 policy_generation = policy_generation + 1",
                [],
            )
            .unwrap();
        Ok(write())
    }
}

#[test]
fn a_policy_raised_after_the_companions_are_deleted_forgets_nothing() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut f, _) = private_fixture_with_factory(TestDbFactory::file_backed());
    f.drive();
    let facts = f.ledger_facts();
    assert!(facts > 0);
    f.companion = None;
    f.set_policy(TransparentLedgerMode::Public);
    let wallet_path = f.st.wallet().conn().path().unwrap().to_owned();
    let mut gate = RaisePolicy {
        wallet: Connection::open(wallet_path).unwrap(),
    };
    assert!(matches!(
        f.forget(&mut gate),
        Err(ForgetError::PolicyChanged)
    ));
    assert!(!f.companion_path().exists());
    assert_eq!(f.ledger_facts(), facts);
    assert_eq!(
        f.st.wallet()
            .db()
            .applied_transparent_policy()
            .unwrap()
            .mode,
        PrivateRequired
    );
    // A retry finds the policy private before deleting anything.
    assert!(matches!(
        f.forget(&mut Ungated),
        Err(ForgetError::NotPublic)
    ));
    assert_eq!(f.ledger_facts(), facts);
}

/// A [`WriteGate`] that, before running the write, takes the wallet's durable policy to
/// `PrivateRequired` through another connection, creates the account's companion as a
/// private pass would, and returns the policy to `Public`.
struct PolicyRoundTrip {
    wallet: Connection,
    companions: CompanionDir,
    account: AccountUuid,
}

impl WriteGate for PolicyRoundTrip {
    fn write<T>(&mut self, write: impl FnOnce() -> T) -> Result<T, Interrupted> {
        let set_mode = |mode: i64| {
            self.wallet
                .execute(
                    "UPDATE tpir_meta SET applied_mode = ?1,
                     policy_generation = policy_generation + 1",
                    [mode],
                )
                .unwrap();
        };
        set_mode(2);
        let account = self.account.expose_uuid().to_string();
        self.companions
            .open(
                &account,
                config(self.account),
                || Ok(BTreeSet::from([account.clone()])),
                &|| false,
            )
            .unwrap();
        set_mode(0);
        Ok(write())
    }
}

#[test]
fn a_policy_round_trip_after_the_companions_are_deleted_forgets_nothing() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut f, _) = private_fixture_with_factory(TestDbFactory::file_backed());
    f.drive();
    let facts = f.ledger_facts();
    assert!(facts > 0);
    f.companion = None;
    f.set_policy(TransparentLedgerMode::Public);
    let wallet_path = f.st.wallet().conn().path().unwrap().to_owned();
    let mut gate = PolicyRoundTrip {
        wallet: Connection::open(wallet_path).unwrap(),
        companions: f.companions(),
        account: f.account,
    };
    // The policy is public again at the write, but a companion created while it was
    // private survives, so the facts stay with it.
    assert!(matches!(
        f.forget(&mut gate),
        Err(ForgetError::PolicyChanged)
    ));
    assert!(f.companion_path().exists());
    assert_eq!(f.ledger_facts(), facts);

    // A retry deletes that companion before forgetting.
    assert!(!f.forget(&mut Ungated).unwrap().removed_nothing());
    assert!(!f.companion_path().exists());
    assert_eq!(f.ledger_facts(), 0);
}
