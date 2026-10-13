//! `DetailRun` over a SQLite wallet and the fake txid display publication: which lookups a run
//! lists, when it checks the display map, and what each result writes.
//!
//! The fake publication holds no record, so a covered lookup is `Absent` and one below its
//! shard is not covered. Found facts are built by hand.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
    keys::TransparentKeyScope,
};
use transparent_txid_client::Tag;
use zakura_pir_transparent::{
    AddressKind, DetailAnswer, DetailApplied, DetailRun, DetailStep, DetailWrite, DisplayEntry,
    DisplayLookup, EntryAddress, EntryOutput, HttpExchange, HttpFailure, HttpReply, HttpRequest,
    MapChecked, Provenance, Tier, TxidDisplayService, TxidError, TxidLookup,
    testing::TxidPublication,
};
use zcash_client_backend::{
    data_api::{
        Account as _, WalletRead as _, WalletWrite as _,
        testing::{TestBuilder, TestState},
        transparent_ledger::{
            TRANSPARENT_DISPLAY_MAP_RECHECK, TransparentDetailOutcome, TransparentDetailRead as _,
            TransparentDisplayStore, TransparentDisplayView, TransparentLedgerMode,
            TransparentLedgerRead as _, TransparentLedgerWrite as _,
        },
    },
    wallet::WalletTransparentOutput,
};
use zcash_client_sqlite::{
    AccountUuid,
    testing::db::{TestDb, TestDbFactory},
};
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis};

type State = TestState<(), TestDb, LocalNetwork>;

const VALUE: u64 = 2_000_000;
/// Past a not-covered lookup's backoff of a day and up to a quarter.
const PAST_BACKOFF: Duration = Duration::from_secs(31 * 3600);
const MAP_PATH: &str = "/v2/txid/map";

fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(2_000_000_000)
}

struct Fixture {
    st: State,
    account: AccountUuid,
    address: TransparentAddress,
    /// A height above the birthday, where receipts are mined.
    height: u32,
}

/// A wallet with one account, under a durable `PrivateRequired` policy.
fn wallet() -> Fixture {
    let st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    let account = st.test_account().unwrap().id();
    let birthday = st.test_account().unwrap().birthday().height();
    let address = *st
        .wallet()
        .db()
        .get_transparent_receivers(account, false, false)
        .unwrap()
        .keys()
        .next()
        .expect("the account has a transparent receiver");
    let mut f = Fixture {
        st,
        account,
        address,
        height: u32::from(birthday) + 100,
    };
    let tip = BlockHeight::from_u32(f.height + 100);
    f.st.wallet_mut().db_mut().update_chain_tip(tip).unwrap();
    f.set_policy(TransparentLedgerMode::PrivateRequired);
    f
}

impl Fixture {
    fn set_policy(&mut self, mode: TransparentLedgerMode) {
        let db = self.st.wallet_mut().db_mut();
        db.apply_transparent_policy(mode).unwrap();
        db.set_transparent_ledger_mode(mode);
    }

    /// A receive of the account's in transaction `[tag; 32]`, mined at `height`, recorded
    /// without its raw bytes and with detail work.
    fn receipt(&mut self, tag: u8, height: u32) -> TxId {
        let mode = self
            .st
            .wallet()
            .db()
            .applied_transparent_policy()
            .unwrap()
            .mode;
        self.set_policy(TransparentLedgerMode::Public);
        let utxo = WalletTransparentOutput::from_parts(
            OutPoint::new([tag; 32], 0),
            TxOut::new(
                Zatoshis::const_from_u64(VALUE),
                self.address.script().into(),
            ),
            Some(BlockHeight::from_u32(height)),
            Some(self.account),
            Some(TransparentKeyScope::EXTERNAL),
            None,
        )
        .unwrap();
        self.st
            .wallet_mut()
            .db_mut()
            .put_received_transparent_utxo(&utxo)
            .unwrap();
        let txid = TxId::from_bytes([tag; 32]);
        let conn = self.st.wallet().conn();
        conn.execute(
            "DELETE FROM tx_retrieval_queue WHERE txid = ?1",
            [txid.as_ref().as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transparent_detail_work (transaction_id, reasons)
             SELECT id_tx, 1 FROM transactions WHERE txid = ?1",
            [txid.as_ref().as_slice()],
        )
        .unwrap();
        self.set_policy(mode);
        txid
    }

    /// The work row's attempts, last outcome code and last map.
    fn work_row(&self, txid: TxId) -> Option<(u32, Option<i64>, Option<[u8; 32]>)> {
        self.st
            .wallet()
            .conn()
            .query_row(
                "SELECT w.attempts, w.last_outcome, w.last_map_sha256
                 FROM transparent_detail_work w JOIN transactions t ON t.id_tx = w.transaction_id
                 WHERE t.txid = ?1",
                [txid.as_ref().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok()
    }

    /// The work row's content failures at its last placement.
    fn content_failures(&self, txid: TxId) -> u32 {
        self.st
            .wallet()
            .conn()
            .query_row(
                "SELECT w.content_failures
                 FROM transparent_detail_work w JOIN transactions t ON t.id_tx = w.transaction_id
                 WHERE t.txid = ?1",
                [txid.as_ref().as_slice()],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// When the work row is next due.
    fn next_attempt_at(&self, txid: TxId) -> SystemTime {
        let secs: u64 = self
            .st
            .wallet()
            .conn()
            .query_row(
                "SELECT w.next_attempt_at
                 FROM transparent_detail_work w JOIN transactions t ON t.id_tx = w.transaction_id
                 WHERE t.txid = ?1",
                [txid.as_ref().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn view(&self, txid: TxId) -> Option<TransparentDisplayView> {
        self.st
            .wallet()
            .db()
            .transparent_display_view(self.account, txid)
            .unwrap()
    }

    fn plan<'a>(
        &self,
        service: &'a TxidDisplayService,
        now: SystemTime,
        limit: usize,
        prefer: &[TxId],
    ) -> DetailRun<'a> {
        DetailRun::plan(self.st.wallet().db(), Some(service), now, limit, prefer).unwrap()
    }

    /// Runs `run` to its end as a private caller: every lookup through `service`, every map
    /// check fetched and relisted. Returns the transactions it looked up.
    fn drive(
        &mut self,
        mut run: DetailRun<'_>,
        service: &TxidDisplayService,
        exchange: &Service,
        now: SystemTime,
    ) -> Vec<TxId> {
        let mut looked_up = vec![];
        while let Some(step) = run.next() {
            match step {
                DetailStep::RefreshMap(check) => {
                    let checked = check.fetch(service, exchange, &|| false);
                    run.relist(self.st.wallet().db(), checked, now).unwrap();
                }
                DetailStep::Lookup(request) => {
                    looked_up.push(request.txid);
                    let found = service.lookup(
                        exchange,
                        *request.txid.as_ref(),
                        u32::from(request.mined_height).into(),
                        &|| false,
                    );
                    if let Some(write) =
                        run.record::<()>(&request, DetailAnswer::Display(Box::new(found)))
                    {
                        write.apply(self.st.wallet_mut().db_mut(), now).unwrap();
                    }
                }
            }
        }
        looked_up
    }
}

/// How the fake service answers map requests.
#[derive(Clone, Copy)]
enum MapAnswer {
    Serve,
    Status(u16),
    Unreachable,
}

/// The fake service: one of its publications at a time, map failures and malformed private
/// replies on demand, and every request's path.
struct Service {
    publications: Vec<TxidPublication>,
    serving: AtomicUsize,
    map: Mutex<MapAnswer>,
    malformed: AtomicBool,
    paths: Mutex<Vec<String>>,
}

impl Service {
    fn new(publications: Vec<TxidPublication>) -> Self {
        Self {
            publications,
            serving: AtomicUsize::new(0),
            map: Mutex::new(MapAnswer::Serve),
            malformed: AtomicBool::new(false),
            paths: Mutex::default(),
        }
    }

    fn serve(&self, index: usize) {
        self.serving.store(index, Ordering::SeqCst);
    }

    fn map_answer(&self, answer: MapAnswer) {
        *self.map.lock().unwrap() = answer;
    }

    /// Flips a payload byte of every private reply from now on.
    fn malform_replies(&self) {
        self.malformed.store(true, Ordering::SeqCst);
    }

    fn map_sha256(&self, index: usize) -> [u8; 32] {
        self.publications[index].map_sha256()
    }

    fn sent(&self) -> usize {
        self.paths.lock().unwrap().len()
    }

    fn paths_since(&self, sent: usize) -> Vec<String> {
        self.paths.lock().unwrap()[sent..].to_vec()
    }
}

impl HttpExchange for Service {
    fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
        self.paths.lock().unwrap().push(request.path.clone());
        if request.path == MAP_PATH {
            match *self.map.lock().unwrap() {
                MapAnswer::Serve => {}
                MapAnswer::Status(status) => {
                    return Ok(HttpReply {
                        status,
                        ..HttpReply::default()
                    });
                }
                MapAnswer::Unreachable => return Err(HttpFailure::Unreachable),
            }
        }
        let publication = &self.publications[self.serving.load(Ordering::SeqCst)];
        let mut reply = publication.answer(request.method, &request.path, &request.body);
        // The last byte is a reply's payload, past every frame's binding and epoch: the reply
        // fails to decode, the one validation failure about the row.
        if self.malformed.load(Ordering::SeqCst) && request.path.contains("/query/") {
            *reply.body.last_mut().unwrap() ^= 1;
        }
        Ok(reply)
    }
}

/// A service whose publication 0 starts above `height`, and whose publication 1 covers it.
fn not_covering_then_covering(height: u32) -> Service {
    let height = u64::from(height);
    Service::new(vec![
        TxidPublication::new(height + 1, height + 10),
        TxidPublication::new(height - 5, height + 5),
    ])
}

const PROTOCOL: i64 = 4;
const NOT_COVERED: i64 = 2;
const ABSENT: i64 = 1;
const UNAVAILABLE: i64 = 0;
/// Past a first `Unavailable` deferral's backoff of 30 seconds and up to a quarter.
const PAST_UNAVAILABLE: Duration = Duration::from_secs(40);

/// Holds `txid` as not covered under publication 0's map at `t0`, and returns when it is past
/// its backoff.
fn hold(f: &mut Fixture, service: &TxidDisplayService, exchange: &Service, txid: TxId) {
    let run = f.plan(service, t0(), 8, &[]);
    assert_eq!(f.drive(run, service, exchange, t0()), [txid]);
    assert_eq!(
        f.work_row(txid),
        Some((1, Some(NOT_COVERED), Some(exchange.map_sha256(0))))
    );
    assert_eq!(f.view(txid), Some(TransparentDisplayView::NotCovered));
}

/// A lookup parked on the display map it saw becomes due once a refreshed map differs, within
/// the same run.
#[test]
fn parked_work_relists_after_map_refresh() {
    let mut f = wallet();
    let txid = f.receipt(0x70, f.height);
    let exchange = not_covering_then_covering(f.height);
    let service = TxidDisplayService::new();
    hold(&mut f, &service, &exchange, txid);

    // A day later, on the same map: the map is checked, and nothing is looked up.
    let t1 = t0() + PAST_BACKOFF;
    let sent = exchange.sent();
    let run = f.plan(&service, t1, 8, &[]);
    assert!(f.drive(run, &service, &exchange, t1).is_empty());
    assert_eq!(exchange.paths_since(sent), [MAP_PATH]);

    // A new publication: the next check releases the work, which is looked up and deferred
    // under the new map.
    exchange.serve(1);
    let t2 = t1 + TRANSPARENT_DISPLAY_MAP_RECHECK;
    let run = f.plan(&service, t2, 8, &[]);
    assert_eq!(f.drive(run, &service, &exchange, t2), [txid]);
    assert_eq!(
        f.work_row(txid),
        Some((1, Some(ABSENT), Some(exchange.map_sha256(1))))
    );
}

/// Preferred transactions are looked up first, even outside the listing's window.
#[test]
fn prioritized_transactions_are_served_first() {
    let mut f = wallet();
    // Newest first in the wallet's order, so the first receipt is last.
    let txids: Vec<TxId> = (0..12u8)
        .map(|tag| f.receipt(0x60 + tag, f.height + u32::from(tag)))
        .collect();
    let wanted = txids[0];
    let service = TxidDisplayService::new();
    let lookups = |run: DetailRun<'_>| -> Vec<TxId> {
        run.map(|step| match step {
            DetailStep::Lookup(request) => request.txid,
            DetailStep::RefreshMap(_) => panic!("work is due"),
        })
        .collect()
    };
    let all = lookups(f.plan(&service, t0(), 8, &[wanted]));
    assert_eq!(all.len(), 9);
    assert_eq!(all[0], wanted);
    assert_eq!(
        &all[1..],
        &txids.iter().rev().take(8).copied().collect::<Vec<_>>()
    );
    // Outside a one-row window.
    assert_eq!(
        lookups(f.plan(&service, t0(), 1, &[wanted])),
        [wanted, txids[11]]
    );
    // Without a preference, the wallet's order.
    assert_eq!(lookups(f.plan(&service, t0(), 1, &[])), [txids[11]]);
}

/// An unchanged map keeps held work held. Consecutive runs on one service share the re-check
/// interval; a restarted service, without a map, checks it again at once.
#[test]
fn held_work_stays_held_while_the_map_is_unchanged() {
    let mut f = wallet();
    let txid = f.receipt(0x42, f.height);
    let exchange = not_covering_then_covering(f.height);
    let held = Some((1, Some(NOT_COVERED), Some(exchange.map_sha256(0))));
    {
        let service = TxidDisplayService::new();
        hold(&mut f, &service, &exchange, txid);
        let t1 = t0() + PAST_BACKOFF;
        let sent = exchange.sent();
        let run = f.plan(&service, t1, 8, &[]);
        assert!(f.drive(run, &service, &exchange, t1).is_empty());
        assert_eq!(exchange.paths_since(sent), [MAP_PATH]);

        // The next runs on this service wait out the re-check interval.
        let sent = exchange.sent();
        for at in [
            t1,
            t1 + TRANSPARENT_DISPLAY_MAP_RECHECK - Duration::from_secs(1),
        ] {
            let mut run = f.plan(&service, at, 8, &[]);
            assert!(run.next().is_none());
        }
        assert!(exchange.paths_since(sent).is_empty());
        let at = t1 + TRANSPARENT_DISPLAY_MAP_RECHECK;
        let run = f.plan(&service, at, 8, &[]);
        assert!(f.drive(run, &service, &exchange, at).is_empty());
        assert_eq!(exchange.paths_since(sent), [MAP_PATH]);
    }
    // A restart: a service without a map lists the work as parked and checks the map first.
    let service = TxidDisplayService::new();
    let at = t0() + PAST_BACKOFF + Duration::from_secs(1);
    let sent = exchange.sent();
    let run = f.plan(&service, at, 8, &[]);
    assert!(f.drive(run, &service, &exchange, at).is_empty());
    assert_eq!(exchange.paths_since(sent), [MAP_PATH]);
    assert_eq!(f.work_row(txid), held);
    assert_eq!(f.view(txid), Some(TransparentDisplayView::NotCovered));
}

/// A map request that fails leaves held work held under the map it was held for, and counts
/// as a check: failed checks are bounded too.
#[test]
fn held_work_stays_held_when_the_map_cannot_be_fetched() {
    let mut f = wallet();
    let txid = f.receipt(0x44, f.height);
    // Behind the failing map, the service covers the receipt.
    let exchange = not_covering_then_covering(f.height);
    let held = Some((1, Some(NOT_COVERED), Some(exchange.map_sha256(0))));
    let service = TxidDisplayService::new();
    hold(&mut f, &service, &exchange, txid);
    exchange.serve(1);
    let mut at = t0() + PAST_BACKOFF;
    for failure in [
        MapAnswer::Status(503),
        MapAnswer::Status(404),
        MapAnswer::Unreachable,
    ] {
        exchange.map_answer(failure);
        let sent = exchange.sent();
        let run = f.plan(&service, at, 8, &[]);
        assert!(f.drive(run, &service, &exchange, at).is_empty());
        assert_eq!(exchange.paths_since(sent), [MAP_PATH]);
        assert_eq!(f.work_row(txid), held);

        let sent = exchange.sent();
        let mut run = f.plan(&service, at, 8, &[]);
        assert!(run.next().is_none(), "failed checks are bounded too");
        assert!(exchange.paths_since(sent).is_empty());
        at += TRANSPARENT_DISPLAY_MAP_RECHECK;
    }
    // A dropped check counts as well.
    let mut run = f.plan(&service, at, 8, &[]);
    assert!(matches!(run.next(), Some(DetailStep::RefreshMap(_))));
    drop(run);
    let mut run = f.plan(&service, at, 8, &[]);
    assert!(run.next().is_none());
    assert_eq!(f.work_row(txid), held);
}

/// Holds `txid`, then plans past its backoff while the service serves publication 1, and
/// fetches the changed map the run's only step asks for.
fn plan_relist<'a>(
    f: &mut Fixture,
    service: &'a TxidDisplayService,
    exchange: &Service,
    txid: TxId,
    at: SystemTime,
) -> (DetailRun<'a>, MapChecked) {
    hold(f, service, exchange, txid);
    exchange.serve(1);
    let mut run = f.plan(service, at, 8, &[]);
    let Some(DetailStep::RefreshMap(check)) = run.next() else {
        panic!("a map check");
    };
    let checked = check.fetch(service, exchange, &|| false);
    assert_eq!(checked.changed(), Some(exchange.map_sha256(1)));
    (run, checked)
}

/// A relisting under another mode than the run's lists nothing.
#[test]
fn a_relisting_under_another_mode_lists_nothing() {
    let mut f = wallet();
    let txid = f.receipt(0x45, f.height);
    let exchange = not_covering_then_covering(f.height);
    let service = TxidDisplayService::new();
    let at = t0() + PAST_BACKOFF;
    let (mut run, checked) = plan_relist(&mut f, &service, &exchange, txid, at);
    let generation = run.policy_generation();
    f.set_policy(TransparentLedgerMode::Public);
    run.relist(f.st.wallet().db(), checked, at).unwrap();
    assert!(run.next().is_none());
    assert_eq!(run.policy_generation(), generation);
    assert_eq!(run.mode(), TransparentLedgerMode::PrivateRequired);
}

/// A relisting under the run's mode but a newer policy generation lists nothing, though the
/// changed map made the work due: its facts would be stored under a stale generation.
#[test]
fn a_relisting_under_another_generation_of_the_same_mode_lists_nothing() {
    let mut f = wallet();
    let txid = f.receipt(0x49, f.height);
    let exchange = not_covering_then_covering(f.height);
    let service = TxidDisplayService::new();
    let at = t0() + PAST_BACKOFF;
    let (mut run, checked) = plan_relist(&mut f, &service, &exchange, txid, at);
    // Away and back: the mode is unchanged, the generation is not.
    f.set_policy(TransparentLedgerMode::Public);
    f.set_policy(TransparentLedgerMode::PrivateRequired);
    let current = f.st.wallet().db().applied_transparent_policy().unwrap();
    assert_eq!(current.mode, TransparentLedgerMode::PrivateRequired);
    assert_ne!(current.generation, run.policy_generation());
    run.relist(f.st.wallet().db(), checked, at).unwrap();
    assert!(run.next().is_none());
    assert_eq!(run.mode(), TransparentLedgerMode::PrivateRequired);
    // The next run, under the current generation, lists the work.
    let mut next = f.plan(&service, at, 8, &[]);
    assert_eq!(next.policy_generation(), current.generation);
    assert!(matches!(next.next(), Some(DetailStep::Lookup(r)) if r.txid == txid));
}

/// A deferral names the map its lookup used, though the shared service holds a newer one by
/// the time it is recorded: the work parks under the map that did not cover it, and the newer
/// map releases it.
#[test]
fn a_deferral_names_the_map_its_lookup_used() {
    let mut f = wallet();
    let txid = f.receipt(0x4a, f.height);
    let exchange = not_covering_then_covering(f.height);
    let service = TxidDisplayService::new();
    let mut run = f.plan(&service, t0(), 8, &[]);
    let Some(DetailStep::Lookup(request)) = run.next() else {
        panic!("a lookup");
    };
    let found = service.lookup(
        &exchange,
        *request.txid.as_ref(),
        u32::from(request.mined_height).into(),
        &|| false,
    );
    assert_eq!(found.map_sha256, Some(exchange.map_sha256(0)));
    // Another run's map check, between this lookup and its record.
    exchange.serve(1);
    assert_eq!(
        service.refresh_map(&exchange, &|| false),
        Ok(exchange.map_sha256(1))
    );
    assert_eq!(service.map_sha256(), Some(exchange.map_sha256(1)));
    let write = run
        .record::<()>(&request, DetailAnswer::Display(Box::new(found)))
        .unwrap();
    assert!(matches!(
        &write,
        DetailWrite::Defer { outcome: TransparentDetailOutcome::NotCovered, map_sha256, .. }
            if *map_sha256 == Some(exchange.map_sha256(0))
    ));
    write.apply(f.st.wallet_mut().db_mut(), t0()).unwrap();
    assert_eq!(
        f.work_row(txid),
        Some((1, Some(NOT_COVERED), Some(exchange.map_sha256(0))))
    );
    let at = t0() + PAST_BACKOFF;
    let mut next = f.plan(&service, at, 8, &[]);
    assert!(matches!(next.next(), Some(DetailStep::Lookup(r)) if r.txid == txid));
}

/// Only a caller that is exiting writes nothing: the work stays due. A lookup the service
/// reports cancelled is an attempt, because the service cannot say whether the caller is
/// exiting or out of time, and forwarding it unchanged must not starve later runs.
#[test]
fn only_an_exiting_caller_writes_nothing() {
    let mut f = wallet();
    let txid = f.receipt(0x46, f.height);
    let exchange = not_covering_then_covering(f.height);
    exchange.serve(1);
    let service = TxidDisplayService::new();
    let mut run = f.plan(&service, t0(), 8, &[]);
    let Some(DetailStep::Lookup(request)) = run.next() else {
        panic!("a lookup");
    };
    assert!(
        run.record::<()>(&request, DetailAnswer::Cancelled)
            .is_none()
    );
    assert_eq!(f.work_row(txid), Some((0, None, None)));
    assert_eq!(f.view(txid), Some(TransparentDisplayView::Pending));
    let mut again = f.plan(&service, t0(), 8, &[]);
    assert!(matches!(again.next(), Some(DetailStep::Lookup(r)) if r.txid == txid));

    let found = service.lookup(
        &exchange,
        *request.txid.as_ref(),
        u32::from(request.mined_height).into(),
        &|| true,
    );
    assert_eq!(found.found, Err(TxidError::Cancelled));
    let write = run
        .record::<()>(&request, DetailAnswer::Display(Box::new(found)))
        .expect("an attempt");
    assert!(matches!(
        write,
        DetailWrite::Defer {
            outcome: TransparentDetailOutcome::Unavailable { retry_after: None },
            ..
        }
    ));
    write.apply(f.st.wallet_mut().db_mut(), t0()).unwrap();
    assert_eq!(f.work_row(txid).map(|(attempts, ..)| attempts), Some(1));
    let mut later = f.plan(&service, t0(), 8, &[]);
    assert!(later.next().is_none());
}

/// A lookup that finishes after a policy change writes nothing under the new policy: its
/// deferral fails as stale, and the caller ends the run.
#[test]
fn a_deferral_after_a_policy_change_is_stale() {
    let mut f = wallet();
    let txid = f.receipt(0x4d, f.height);
    let exchange = not_covering_then_covering(f.height);
    let service = TxidDisplayService::new();
    let mut run = f.plan(&service, t0(), 8, &[]);
    let Some(DetailStep::Lookup(request)) = run.next() else {
        panic!("a lookup");
    };
    let found = service.lookup(
        &exchange,
        *request.txid.as_ref(),
        u32::from(request.mined_height).into(),
        &|| false,
    );
    // The user turns private queries off while the lookup is in flight.
    f.set_policy(TransparentLedgerMode::Public);
    let before = f.work_row(txid);
    let write = run
        .record::<()>(&request, DetailAnswer::Display(Box::new(found)))
        .expect("a deferral");
    assert!(matches!(write, DetailWrite::Defer { .. }));
    assert!(matches!(
        write.apply(f.st.wallet_mut().db_mut(), t0()),
        Err(zcash_client_sqlite::error::SqliteClientError::StaleTransparentPolicy { .. })
    ));
    assert_eq!(f.work_row(txid), before);
}

/// A lookup the run's budget stopped is an attempt: it is deferred as `Unavailable`, so it
/// backs off instead of staying first in the listing and taking every run, preferred or not.
#[test]
fn a_timed_out_lookup_is_deferred() {
    let mut f = wallet();
    let older = f.receipt(0x4b, f.height);
    let newer = f.receipt(0x4c, f.height + 1);
    let exchange = not_covering_then_covering(f.height);
    exchange.serve(1);
    let service = TxidDisplayService::new();
    let first = |f: &Fixture, at, prefer: &[TxId]| match f.plan(&service, at, 1, prefer).next() {
        Some(DetailStep::Lookup(request)) => request.txid,
        step => panic!("a lookup, not {step:?}"),
    };
    // Newest first in the wallet's order.
    assert_eq!(first(&f, t0(), &[]), newer);

    // The budget runs out during the lookup.
    let mut run = f.plan(&service, t0(), 1, &[newer]);
    let Some(DetailStep::Lookup(request)) = run.next() else {
        panic!("a lookup");
    };
    assert_eq!(request.txid, newer);
    let found = service.lookup(
        &exchange,
        *request.txid.as_ref(),
        u32::from(request.mined_height).into(),
        &|| true,
    );
    assert_eq!(found.found, Err(TxidError::Cancelled));
    let write = run
        .record::<()>(&request, DetailAnswer::TimedOut)
        .expect("a timed-out lookup is written");
    assert!(matches!(
        &write,
        DetailWrite::Defer {
            outcome: TransparentDetailOutcome::Unavailable { retry_after: None },
            map_sha256: None,
            ..
        }
    ));
    assert_eq!(
        write.apply(f.st.wallet_mut().db_mut(), t0()).unwrap(),
        DetailApplied::Deferred(TransparentDetailOutcome::Unavailable { retry_after: None })
    );
    assert_eq!(f.work_row(newer), Some((1, Some(UNAVAILABLE), None)));
    assert_eq!(f.view(newer), Some(TransparentDisplayView::Unavailable));

    // The next run starts with the other lookup, preferred or not.
    let soon = t0() + Duration::from_secs(1);
    assert_eq!(first(&f, soon, &[]), older);
    assert_eq!(first(&f, soon, &[newer]), older);

    // Once its backoff passes it is due again: first when preferred, and otherwise after
    // never-attempted work.
    let later = t0() + PAST_UNAVAILABLE;
    assert_eq!(first(&f, later, &[newer]), newer);
    let lookups: Vec<TxId> = f
        .plan(&service, later, 8, &[])
        .map(|step| match step {
            DetailStep::Lookup(request) => request.txid,
            DetailStep::RefreshMap(_) => panic!("work is due"),
        })
        .collect();
    assert_eq!(lookups, [older, newer]);
}

/// Found facts are stored under the listing's generation, and resolve the work.
#[test]
fn found_facts_are_stored() {
    let mut f = wallet();
    let txid = f.receipt(0x47, f.height);
    let service = TxidDisplayService::new();
    let mut run = f.plan(&service, t0(), 8, &[]);
    let Some(DetailStep::Lookup(request)) = run.next() else {
        panic!("a lookup");
    };
    let TransparentAddress::PublicKeyHash(hash) = f.address else {
        panic!("a P2PKH receiver");
    };
    let entry = DisplayEntry {
        tag: Tag::of(&transparent_events::Txid(*txid.as_ref())),
        coinbase: false,
        shielded_components: false,
        multiple_source_scripts: false,
        shielded_and_transparent_funding: false,
        fee: 1_000,
        input_count: 1,
        output_count: 1,
        source: EntryAddress {
            kind: AddressKind::P2pkh,
            hash: [0x99; 20],
        },
        outputs: [
            Some(EntryOutput {
                value: VALUE,
                address: EntryAddress {
                    kind: AddressKind::P2pkh,
                    hash,
                },
            }),
            None,
        ],
    };
    let provenance = Provenance {
        map_sha256: "ab".repeat(32),
        shard_id: 0,
        revision: 1,
        manifest_digest: "cd".repeat(32),
        tier: Tier::Recent,
    };
    let write = run
        .record::<()>(
            &request,
            DetailAnswer::Display(Box::new(DisplayLookup {
                found: Ok(TxidLookup::Found { entry, provenance }),
                map_sha256: Some([0xab; 32]),
            })),
        )
        .unwrap();
    assert!(matches!(
        &write,
        DetailWrite::Store { expected_generation, .. }
            if *expected_generation == run.policy_generation()
    ));
    assert_eq!(
        write.apply(f.st.wallet_mut().db_mut(), t0()).unwrap(),
        DetailApplied::Stored(TransparentDisplayStore::Stored)
    );
    assert_eq!(f.work_row(txid), None);
    assert!(matches!(
        f.view(txid),
        Some(TransparentDisplayView::Available(_))
    ));
}

/// A public transaction is handed back unwritten only under public transport; a public failure
/// is deferred without a map, and never counts towards giving the lookup up. Under
/// `PrivateRequired` any public answer is the caller racing a mode change, deferred as
/// unavailable.
#[test]
fn public_answers() {
    let mut f = wallet();
    let txid = f.receipt(0x48, f.height);
    let service = TxidDisplayService::new();
    let mut run = f.plan(&service, t0(), 8, &[]);
    assert!(!run.public_transport());
    let Some(DetailStep::Lookup(request)) = run.next() else {
        panic!("a lookup");
    };
    // Under PrivateRequired a public answer is refused, and says nothing about the row.
    for answer in [
        Ok(vec![1u8]),
        Err(TransparentDetailOutcome::Absent),
        Err(TransparentDetailOutcome::Protocol),
    ] {
        assert!(matches!(
            run.record(&request, DetailAnswer::Public(answer)),
            Some(DetailWrite::Defer {
                outcome: TransparentDetailOutcome::Unavailable { retry_after: None },
                map_sha256: None,
                ..
            })
        ));
    }

    f.set_policy(TransparentLedgerMode::Public);
    let mut run = DetailRun::plan(f.st.wallet().db(), None, t0(), 8, &[]).unwrap();
    assert!(run.public_transport());
    let Some(DetailStep::Lookup(request)) = run.next() else {
        panic!("a lookup");
    };
    assert_eq!(request.txid, txid);
    let write = run
        .record(&request, DetailAnswer::Public(Ok(vec![1u8, 2, 3])))
        .unwrap();
    assert_eq!(
        write.apply(f.st.wallet_mut().db_mut(), t0()).unwrap(),
        DetailApplied::Raw(vec![1, 2, 3])
    );
    assert_eq!(f.work_row(txid), Some((0, None, None)));

    let write = run
        .record::<Vec<u8>>(
            &request,
            DetailAnswer::Public(Err(TransparentDetailOutcome::Absent)),
        )
        .unwrap();
    assert_eq!(
        write.apply(f.st.wallet_mut().db_mut(), t0()).unwrap(),
        DetailApplied::Deferred(TransparentDetailOutcome::Absent)
    );
    assert_eq!(f.work_row(txid), Some((1, Some(ABSENT), None)));
    // Public absences keep the daily retry: none counts, however many there are.
    for attempts in 2..=4 {
        let write = run
            .record::<Vec<u8>>(
                &request,
                DetailAnswer::Public(Err(TransparentDetailOutcome::Absent)),
            )
            .unwrap();
        let _ = write.apply(f.st.wallet_mut().db_mut(), t0()).unwrap();
        assert_eq!(f.work_row(txid), Some((attempts, Some(ABSENT), None)));
    }
    assert_eq!(f.content_failures(txid), 0);
    let far = t0() + Duration::from_secs(30 * 24 * 3600);
    let mut run = DetailRun::plan(f.st.wallet().db(), None, far, 8, &[]).unwrap();
    assert!(matches!(run.next(), Some(DetailStep::Lookup(r)) if r.txid == txid));
}

/// A service that answers malformed for the wallet's row and one that answers "not in the
/// table" move the wallet alike: with the same random source, both wallets store the same
/// next-attempt times, and both stop after the third lookup.
#[test]
fn malformed_and_absent_replies_share_one_schedule_and_stop_after_three() {
    let lookups = |malformed: bool| -> (Vec<SystemTime>, Option<i64>) {
        let mut f = wallet();
        let txid = f.receipt(0x50, f.height);
        let height = u64::from(f.height);
        let exchange = Service::new(vec![TxidPublication::new(height - 5, height + 5)]);
        if malformed {
            exchange.malform_replies();
        }
        let service = TxidDisplayService::new();
        let mut at = t0();
        let mut due = vec![];
        for _ in 0..3 {
            let run = f.plan(&service, at, 8, &[]);
            assert_eq!(f.drive(run, &service, &exchange, at), [txid]);
            at = f.next_attempt_at(txid);
            due.push(at);
        }
        // Given up: a month later nothing is looked up, nor any request sent.
        let at = at + Duration::from_secs(30 * 24 * 3600);
        let sent = exchange.sent();
        let run = f.plan(&service, at, 8, &[]);
        assert!(f.drive(run, &service, &exchange, at).is_empty());
        assert!(exchange.paths_since(sent).is_empty());
        assert_eq!(f.view(txid), Some(TransparentDisplayView::Unavailable));
        (due, f.work_row(txid).and_then(|(_, outcome, _)| outcome))
    };
    let (malformed, outcome) = lookups(true);
    assert_eq!(outcome, Some(PROTOCOL));
    let (absent, outcome) = lookups(false);
    assert_eq!(outcome, Some(ABSENT));
    assert_eq!(malformed, absent);
}

/// A map request the service answers with a redirect is chosen without the row: the lookup
/// backs off like an outage, never counts towards giving up, and is still made once the map is
/// served again.
#[test]
fn a_redirected_map_never_gives_the_lookup_up() {
    let mut f = wallet();
    let txid = f.receipt(0x52, f.height);
    let height = u64::from(f.height);
    let exchange = Service::new(vec![TxidPublication::new(height - 5, height + 5)]);
    exchange.map_answer(MapAnswer::Status(302));
    let service = TxidDisplayService::new();
    let mut at = t0();
    for attempts in 1..=4 {
        let run = f.plan(&service, at, 8, &[]);
        assert_eq!(f.drive(run, &service, &exchange, at), [txid]);
        assert_eq!(
            f.work_row(txid)
                .map(|(attempts, outcome, _)| (attempts, outcome)),
            Some((attempts, Some(UNAVAILABLE)))
        );
        assert_eq!(f.content_failures(txid), 0);
        at = f.next_attempt_at(txid);
    }
    // No private query was sent.
    assert!(
        exchange
            .paths_since(0)
            .iter()
            .all(|path| !path.contains("/query/"))
    );
    assert_eq!(f.view(txid), Some(TransparentDisplayView::Unavailable));

    exchange.map_answer(MapAnswer::Serve);
    let run = f.plan(&service, at, 8, &[]);
    assert_eq!(f.drive(run, &service, &exchange, at), [txid]);
    assert_eq!(
        f.work_row(txid).map(|(_, outcome, _)| outcome),
        Some(Some(ABSENT))
    );
    assert_eq!(f.content_failures(txid), 1);
}
