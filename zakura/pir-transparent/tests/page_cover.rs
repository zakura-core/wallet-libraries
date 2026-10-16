//! Page cover end to end: recovery passes against a transparent shard service
//! running in process, over loopback HTTP and real PIR, with no wallet.
//!
//! Every exchange is recorded with its request and reply sizes, so the tests
//! check what the service sees of a wallet's page work in a directory shard:
//! which page tables it queries, how many times, in what order and at what
//! lengths, and which setups it fetches.

// Shared with the recovery tests, which use helpers this file does not.
#[allow(dead_code, unused_imports)]
mod fixture;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::{Mutex, PoisonError};

use fixture::{GEOMETRY, Loopback, SEAL, Server, ShardSpec, synthetic};
use regex::Regex;
use rusqlite::{Connection, OpenFlags};
use transparent::address::TransparentAddress;
use transparent_events::{ReceiveEvent, TransparentEvent, Txid};
use transparent_filter::ScriptBytes;
use zakura_pir_transparent::engine::{Acceptance, Anchor, ChainView};
use zakura_pir_transparent::{
    HttpExchange, HttpFailure, HttpMethod, HttpReply, HttpRequest, Outcome, PassReport,
    TransparentHistoryRecovery, TransparentHistoryRecoveryConfig,
};
use zcash_client_backend::data_api::transparent_ledger::{
    AccountLifecycle, ChainPoint, TransparentAddressWatchSet, WatchOrigin, WatchedAddress,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

/// The first height the fixture publishes, a mainnet height.
const H0: u64 = 3_428_143;

/// The largest successful response body a pass accepts.
const RESPONSE_LIMIT: usize = 64 << 20;

/// A shard route's shard and table: `directory`, or `pages-<j>`.
const SHARD_ROUTE: &str = r"^/v2/shards/([0-9]+)/revisions/[0-9a-f]{64}/(query|setup)/(directory|pages-([0-9]+))(/[0-9]+)?$";

/// Each test runs a PIR service; one at a time keeps memory and CPU bounded.
static HEAVY: Mutex<()> = Mutex::new(());

fn address(tag: u8) -> TransparentAddress {
    TransparentAddress::PublicKeyHash([tag; 20])
}

fn script(address: TransparentAddress) -> ScriptBytes {
    let TransparentAddress::PublicKeyHash(hash) = address else {
        panic!("the fixture pays to public key hashes");
    };
    ScriptBytes::new([&[0x76, 0xa9, 20][..], &hash, &[0x88, 0xac]].concat())
}

/// A script no wallet here watches.
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

fn receive(height: u64, txid: Txid, output_index: u32) -> TransparentEvent {
    TransparentEvent::Receive(ReceiveEvent {
        metadata: None,
        height: height as u32,
        txid,
        transaction_index: 1,
        output_index,
        value: 50_000,
        coinbase: false,
    })
}

/// `count` receives to `owner`, one per block from `from`: the two newest stay
/// in the directory, and each older one is pushed into the page table open when
/// the event two places after it arrives.
fn history(owner: u8, from: u64, count: u64) -> Vec<(ScriptBytes, TransparentEvent)> {
    (0..count)
        .map(|n| {
            let tag = u64::from(owner) << 32 | (from + n);
            (script(address(owner)), receive(from + n, txid(tag), 0))
        })
        .collect()
}

/// `count` receives to `owner` in the block at `at`: one run of
/// `count - 2` events in the page table open there, a page row per
/// 86 of them.
fn burst(owner: u8, at: u64, count: u32) -> Vec<(ScriptBytes, TransparentEvent)> {
    (0..count)
        .map(|index| {
            (
                script(address(owner)),
                receive(at, txid(u64::from(owner) * 1_000), index),
            )
        })
        .collect()
}

/// Receives to scripts no wallet watches, spread over `[start, end]`, one each,
/// so no watched script is alone in a shard and none of them uses a page.
fn noise(start: u64, end: u64, salt: u32) -> Vec<(ScriptBytes, TransparentEvent)> {
    (0..40u32)
        .map(|n| {
            let tag = salt * 1_000 + n;
            let height = start + u64::from(n * 7) % (end - start + 1);
            (
                unrelated(tag),
                receive(height, txid(u64::from(tag) + 100_000), 0),
            )
        })
        .collect()
}

/// A sealed directory shard over `[start, end]` in page tables of `page_span`
/// blocks (one table for zero), holding `events`, some noise, and a short run
/// in every page table.
fn shard(
    start: u64,
    end: u64,
    page_span: u64,
    mut events: Vec<(ScriptBytes, TransparentEvent)>,
) -> ShardSpec {
    let span = page_span;
    let salt = start as u32 % 997;
    events.extend(noise(start, end, salt));
    // A history of three receives to an unrelated script in each page table,
    // which pushes one event into it: every table holds rows, as in production.
    let span = if span == 0 { end - start + 1 } else { span };
    for (j, table_start) in (start..=end).step_by(span as usize).enumerate() {
        let filler = unrelated(500_000 + salt * 100 + j as u32);
        for n in 0..3 {
            let tag = 700_000 + u64::from(salt) * 10_000 + j as u64 * 10 + n;
            events.push((filler.clone(), receive(table_start + n, txid(tag), 0)));
        }
    }
    ShardSpec {
        start,
        end,
        geometry: GEOMETRY,
        sealed: true,
        revision: 0,
        supersedes: String::new(),
        page_span,
        events,
        malformed_entries: Vec::new(),
    }
}

/// The wallet's chain: every published block, hashed as the publisher hashes it.
struct Chain {
    tip: u64,
}

impl ChainView for Chain {
    fn is_accepted(&self, height: u64, hash: &str) -> Acceptance {
        if height > self.tip {
            Acceptance::Unknown
        } else if synthetic(height).to_display_hex() == hash {
            Acceptance::Accepted
        } else {
            Acceptance::Rejected
        }
    }

    fn tip(&self) -> Option<Anchor> {
        Some(Anchor {
            height: self.tip,
            hash: synthetic(self.tip).to_display_hex(),
        })
    }

    fn hash_at(&self, height: u64) -> Option<String> {
        (height <= self.tip).then(|| synthetic(height).to_display_hex())
    }
}

/// One exchange as the wallet sent it: method, path, and the bytes each way.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Sent {
    method: HttpMethod,
    path: String,
    upload: usize,
    download: usize,
}

/// The loopback exchange, recording every exchange.
struct Recording {
    inner: Loopback,
    sent: RefCell<Vec<Sent>>,
}

impl HttpExchange for Recording {
    fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
        let reply = self.inner.send(request);
        self.sent.borrow_mut().push(Sent {
            method: request.method,
            path: request.path.clone(),
            upload: request.body.len(),
            download: reply.as_ref().map_or(0, |reply| reply.body.len()),
        });
        reply
    }
}

/// A shard request a transcript names: its shard, whether it is a query or a
/// setup, and its page table, `None` for the directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Routed {
    shard: u64,
    query: bool,
    page: Option<u32>,
    upload: usize,
}

fn routed(sent: &[Sent]) -> Vec<Routed> {
    let route = Regex::new(SHARD_ROUTE).unwrap();
    sent.iter()
        .filter_map(|sent| {
            let captures = route.captures(&sent.path)?;
            Some(Routed {
                shard: captures[1].parse().unwrap(),
                query: &captures[2] == "query",
                page: captures.get(4).map(|table| table.as_str().parse().unwrap()),
                upload: sent.upload,
            })
        })
        .collect()
}

/// The page queries in `sent` to `shard`, as (table, upload) in order.
fn page_queries(sent: &[Sent], shard: u64) -> Vec<(u32, usize)> {
    routed(sent)
        .into_iter()
        .filter(|routed| routed.shard == shard && routed.query)
        .filter_map(|routed| routed.page.map(|table| (table, routed.upload)))
        .collect()
}

/// The page tables whose setup `sent` fetched in `shard`, in order.
fn page_setups(sent: &[Sent], shard: u64) -> Vec<u32> {
    routed(sent)
        .into_iter()
        .filter(|routed| routed.shard == shard && !routed.query)
        .filter_map(|routed| routed.page)
        .collect()
}

/// `queries` split into sweeps of `cover`'s size, each checked to query every
/// table of `cover` once.
fn sweeps(queries: &[(u32, usize)], cover: &BTreeSet<u32>) -> Vec<Vec<(u32, usize)>> {
    assert!(!cover.is_empty());
    assert_eq!(
        queries.len() % cover.len(),
        0,
        "page queries {queries:?} are whole sweeps over {cover:?}"
    );
    let sweeps: Vec<Vec<(u32, usize)>> = queries.chunks(cover.len()).map(<[_]>::to_vec).collect();
    for sweep in &sweeps {
        let tables: BTreeSet<u32> = sweep.iter().map(|(table, _)| *table).collect();
        assert_eq!(&tables, cover, "sweep {sweep:?} covers {cover:?} once");
    }
    sweeps
}

/// The tables `queries` addressed.
fn tables(queries: &[(u32, usize)]) -> BTreeSet<u32> {
    queries.iter().map(|(table, _)| *table).collect()
}

/// Private bytes `sent` carried: setups, query uploads and query replies.
fn bytes_sent(sent: &[Sent]) -> usize {
    let route = Regex::new(SHARD_ROUTE).unwrap();
    sent.iter()
        .filter(|sent| route.is_match(&sent.path))
        .map(|sent| sent.upload + sent.download)
        .sum()
}

/// Private queries `sent` carried, directory and pages.
fn queries_sent(sent: &[Sent]) -> usize {
    routed(sent).iter().filter(|routed| routed.query).count()
}

/// A byte budget that fits a pass's setups and two sweeps of the budget test,
/// but not the third with its padding.
const BUDGET_BYTES: u64 = 420_000;

/// The per-pass limits the tests run under unless they say otherwise.
fn config(tag: u8, queries: u64, private_bytes: u64) -> TransparentHistoryRecoveryConfig {
    TransparentHistoryRecoveryConfig {
        source: b"fixture/page-cover/v1".to_vec(),
        account_binding: vec![tag],
        origin: "https://fixture.test".into(),
        scripts: 10_000,
        shards: 1_024,
        events: 500_000,
        queries,
        private_bytes,
    }
}

/// Generous limits: nothing here stops on its budget unless a test says so.
const QUERIES: u64 = 4_096;
const PRIVATE_BYTES: u64 = 1 << 30;

/// One watched address's recovery companion, synced to `tip`.
struct Wallet {
    dir: tempfile::TempDir,
    tag: u8,
    /// Other owners' addresses the wallet also watches.
    also: Vec<u8>,
    tip: u64,
    config: TransparentHistoryRecoveryConfig,
    recovery: Option<TransparentHistoryRecovery>,
}

impl Wallet {
    fn open(tag: u8, tip: u64, seed: u64, config: TransparentHistoryRecoveryConfig) -> Self {
        let mut wallet = Self {
            dir: tempfile::tempdir().unwrap(),
            tag,
            also: Vec::new(),
            tip,
            config,
            recovery: None,
        };
        wallet.reopen(seed);
        wallet
    }

    /// Opens the companion again, a new session, drawing page cover from `seed`.
    fn reopen(&mut self, seed: u64) {
        self.recovery = None;
        let mut recovery = TransparentHistoryRecovery::open(
            self.dir.path().join("companion.sqlite"),
            self.config.clone(),
        )
        .unwrap();
        recovery.seed_page_cover(seed);
        self.recovery = Some(recovery);
    }

    fn watch(&self) -> TransparentAddressWatchSet<u32> {
        TransparentAddressWatchSet {
            account: u32::from(self.tag),
            lifecycle: AccountLifecycle::Candidate,
            policy_generation: 0,
            target: Some(ChainPoint {
                height: BlockHeight::from_u32(self.tip as u32),
                hash: BlockHash(synthetic(self.tip).0),
            }),
            addresses: std::iter::once(self.tag)
                .chain(self.also.iter().copied())
                .map(|tag| WatchedAddress {
                    address: address(tag),
                    origin: WatchOrigin::Standalone,
                    required_from: BlockHeight::from_u32(H0 as u32),
                })
                .collect(),
            pending_pages: vec![],
        }
    }

    /// What the companion holds of `owner`'s history: the receives it
    /// recovered, and the bytes of fragments its unfinished walks saved. A
    /// pass that reads anything of a history raises one or the other.
    fn recovered(&self, owner: u8) -> (i64, i64) {
        let db = Connection::open_with_flags(
            self.dir.path().join("companion.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let owner = script(address(owner)).as_slice().to_vec();
        let receives = db
            .query_row(
                "SELECT COUNT(*) FROM receives WHERE script = ?1",
                [&owner],
                |row| row.get(0),
            )
            .unwrap();
        let fragments = db
            .query_row(
                "SELECT COALESCE(SUM(length(fragments)), 0) FROM pending_work WHERE script = ?1",
                [&owner],
                |row| row.get(0),
            )
            .unwrap();
        (receives, fragments)
    }

    /// One pass through the service at `url`, with every exchange it sent.
    fn pass(&mut self, url: &str) -> (PassReport, Vec<Sent>) {
        let exchange = Recording {
            inner: Loopback::new(url),
            sent: RefCell::default(),
        };
        let watch = self.watch();
        let chain = Chain { tip: self.tip };
        let report = self
            .recovery
            .as_mut()
            .unwrap()
            .pass(&watch, &chain, &exchange, RESPONSE_LIMIT, &|| false)
            .expect("a pass");
        (report, exchange.sent.into_inner())
    }

    /// Passes until one completes, returning every pass's exchanges.
    fn sync(&mut self, url: &str, max: usize) -> Vec<Vec<Sent>> {
        let mut passes = Vec::new();
        for _ in 0..max {
            let (report, sent) = self.pass(url);
            passes.push(sent);
            if report.progress.outcome == Outcome::Complete {
                return passes;
            }
            assert_eq!(report.progress.outcome, Outcome::More, "{report:?}");
        }
        panic!("no complete pass in {max}");
    }
}

/// Publishes `shards` and serves them, returning the server and its URL.
fn serve(shards: &[ShardSpec]) -> (Server, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    fixture::publish(dir.path(), shards, SEAL, synthetic, vec![]);
    let mut server = Server::start();
    let url = server.serve(dir.path());
    (server, url, dir)
}

/// The tests, named under `page_cover` so a test-name filter selects them.
mod page_cover {
    use super::*;

    /// A shard of three page tables. Wallet A's history is in the first, wallet B's
    /// in the last. With the same seed, both send the same requests: every page
    /// table's setup, then one sweep over all three tables, the same tables at the
    /// same lengths in the same order. Without cover, A queries only `pages-0`.
    #[test]
    fn a_small_shard_sends_the_same_requests_whichever_table_holds_the_history() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        let end = H0 + 29;
        let mut events = history(1, H0 + 1, 3);
        events.extend(history(2, H0 + 21, 3));
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, events)]);

        let mut transcripts = Vec::new();
        for tag in [1, 2] {
            let mut wallet = Wallet::open(tag, end, 7, config(tag, QUERIES, PRIVATE_BYTES));
            let (report, sent) = wallet.pass(&url);
            assert_eq!(report.progress.outcome, Outcome::Complete);
            transcripts.push(sent);
        }
        let (a, b) = (&transcripts[0], &transcripts[1]);

        let queries = page_queries(a, 0);
        assert_eq!(
            tables(&queries),
            BTreeSet::from([0, 1, 2]),
            "wallet A's one page query is a sweep over every page table: {queries:?}"
        );
        sweeps(&queries, &BTreeSet::from([0, 1, 2]));
        assert_eq!(page_setups(a, 0), [0, 1, 2], "every page table's setup");
        let shape = |sent: &[Sent]| -> Vec<(HttpMethod, String, usize)> {
            sent.iter()
                .map(|sent| (sent.method, sent.path.clone(), sent.upload))
                .collect()
        };
        assert_eq!(
            shape(a),
            shape(b),
            "the service sees the same requests from both wallets"
        );
    }

    /// A shard of ten page tables. Wallet A needs `pages-1` and wallet B `pages-7`.
    /// With the same seed, both sweep a cover of the same size, the same number of
    /// times, at the same length in every slot; each fetches every page table's
    /// setup. Without cover, each queries only its own table.
    #[test]
    fn a_large_shard_sends_the_same_shape_whichever_table_holds_the_history() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        let end = H0 + 99;
        let mut events = history(1, H0 + 11, 3);
        events.extend(history(2, H0 + 71, 3));
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, events)]);

        let mut shapes = Vec::new();
        for (tag, real) in [(1, 1), (2, 7)] {
            let mut wallet = Wallet::open(tag, end, 11, config(tag, QUERIES, PRIVATE_BYTES));
            let (report, sent) = wallet.pass(&url);
            assert_eq!(report.progress.outcome, Outcome::Complete);
            let queries = page_queries(&sent, 0);
            let cover = tables(&queries);
            assert!(
                cover.contains(&real) && cover.len() >= 3,
                "the real table is one of at least three: {queries:?}"
            );
            let sweeps = sweeps(&queries, &cover);
            assert_eq!(
                page_setups(&sent, 0),
                (0..10).collect::<Vec<_>>(),
                "every page table's setup, in table order"
            );
            let lengths: Vec<Vec<usize>> = sweeps
                .iter()
                .map(|sweep| sweep.iter().map(|(_, upload)| *upload).collect())
                .collect();
            shapes.push((cover.len(), lengths));
        }
        assert_eq!(
            shapes[0], shapes[1],
            "the same cover size, sweeps and lengths"
        );
    }

    /// Histories of 1, 2, 3 and 5 page queries in a shard of one page table send
    /// 1, 2, 4 and 8 sweeps. Without padding they send 1, 2, 3 and 5 queries.
    #[test]
    fn page_sweeps_pad_to_a_power_of_two() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        let end = H0 + 29;
        // One run each, of 10, 100, 200 and 340 events beyond the two the
        // directory keeps, which the walk reads in 1, 2, 3 and 5 page queries.
        let runs = [(1u8, 12u32, 1usize), (2, 102, 2), (3, 202, 4), (4, 342, 8)];
        let mut events = Vec::new();
        for (tag, count, _) in runs {
            events.extend(burst(tag, H0 + u64::from(tag), count));
        }
        let (_server, url, _dir) = serve(&[shard(H0, end, 0, events)]);

        let mut sent_sweeps = Vec::new();
        for (tag, _, _) in runs {
            let mut wallet = Wallet::open(tag, end, 3, config(tag, QUERIES, PRIVATE_BYTES));
            let (report, sent) = wallet.pass(&url);
            assert_eq!(report.progress.outcome, Outcome::Complete);
            let queries = page_queries(&sent, 0);
            sent_sweeps.push(sweeps(&queries, &BTreeSet::from([0])).len());
        }
        assert_eq!(
            sent_sweeps,
            runs.map(|(_, _, sweeps)| sweeps),
            "each shard's sweeps pad to the next power of two"
        );
    }

    /// A chain of three single-fragment runs, in `pages-8`, `pages-6` and
    /// `pages-4`: e7 to e9 and e1 to e6 of the history below in runs, the newest
    /// two inline. Each run is one round of one page query.
    fn chain(at: [u64; 3]) -> Vec<(ScriptBytes, TransparentEvent)> {
        at.into_iter()
            .flat_map(|from| history(1, from, 3))
            .collect()
    }

    /// A walk stopped by its budget and resumed by the next pass of the same
    /// session sweeps the cover the stopped pass ended with, grown by the resumed
    /// run's table if it lacked it; a reopened companion draws a new one. With a
    /// fresh draw at every pass, the resumed pass would sweep the resumed run's
    /// table and a fresh random two or more.
    #[test]
    fn a_resumed_walk_sweeps_the_same_cover_until_the_companion_is_reopened() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        let end = H0 + 99;
        let events = chain([H0 + 41, H0 + 61, H0 + 81]);
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, events)]);

        // A seed whose first pass stops on the budget before the last run.
        let (seed, session) = (0..32)
            .find_map(|seed| {
                let mut wallet = Wallet::open(1, end, seed, config(1, 16, PRIVATE_BYTES));
                let passes = wallet.sync(&url, 4);
                (passes.len() > 1).then_some((seed, passes))
            })
            .expect("a seed whose first pass stops");
        assert_eq!(session.len(), 2, "seed {seed}: the second pass completes");
        let stopped = tables(&page_queries(&session[0], 0));
        let resumed = tables(&page_queries(&session[1], 0));
        assert!(stopped.is_superset(&BTreeSet::from([6, 8])), "{stopped:?}");
        let mut expected = stopped.clone();
        expected.insert(4);
        assert_eq!(
            resumed, expected,
            "the resumed pass sweeps the session's cover and the resumed run's table"
        );

        let mut wallet = Wallet::open(1, end, seed, config(1, 16, PRIVATE_BYTES));
        let (report, sent) = wallet.pass(&url);
        assert_eq!(report.progress.outcome, Outcome::More);
        assert_eq!(tables(&page_queries(&sent, 0)), stopped);
        wallet.reopen(seed + 1);
        let (_, sent) = wallet.pass(&url);
        let reopened = tables(&page_queries(&sent, 0));
        assert!(reopened.contains(&4));
        assert_ne!(reopened, expected, "a reopened companion draws again");
    }

    /// A shard where the wallet's history stays in the directory gets no page
    /// request at all, while the next shard, which holds a run, gets its sweeps.
    #[test]
    fn a_shard_without_page_work_gets_no_page_request() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        let end = H0 + 59;
        let (_server, url, _dir) = serve(&[
            shard(H0, H0 + 29, 10, history(1, H0 + 1, 2)),
            shard(H0 + 30, end, 10, history(1, H0 + 31, 3)),
        ]);
        let mut wallet = Wallet::open(1, end, 1, config(1, QUERIES, PRIVATE_BYTES));
        let (report, sent) = wallet.pass(&url);
        assert_eq!(report.progress.outcome, Outcome::Complete);
        let first: Vec<Routed> = routed(&sent)
            .into_iter()
            .filter(|routed| routed.shard == 0)
            .collect();
        assert!(
            first
                .iter()
                .any(|routed| routed.query && routed.page.is_none()),
            "the first shard's directory is queried"
        );
        assert!(
            first.iter().all(|routed| routed.page.is_none()),
            "and none of its page tables: {first:?}"
        );
        assert_eq!(tables(&page_queries(&sent, 1)), BTreeSet::from([0, 1, 2]));
    }

    /// A chain whose older run lies in a table outside the cover adds exactly that
    /// table: the first sweep covers `C`, the second `C` and the link's table.
    #[test]
    fn a_link_outside_the_cover_adds_exactly_its_table() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        let end = H0 + 99;
        // Runs `pages-7` [e2, e3] and `pages-2` [e1]; e4 and e5 inline.
        let mut events = history(1, H0 + 21, 3);
        events.extend(history(1, H0 + 71, 2));
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, events)]);

        for seed in 0..16 {
            let mut wallet = Wallet::open(1, end, seed, config(1, QUERIES, PRIVATE_BYTES));
            let (report, sent) = wallet.pass(&url);
            assert_eq!(report.progress.outcome, Outcome::Complete);
            // Two sweeps, padded to two: the head run's in `pages-7`, then the
            // link's to `pages-2`. A cover that lacked `pages-2` grew by one table.
            let queries = page_queries(&sent, 0);
            if queries.len().is_multiple_of(2) {
                assert!(tables(&queries).contains(&2), "{queries:?}");
                continue;
            }
            let (head, link) = queries.split_at(queries.len() / 2);
            let (head, link) = (tables(head), tables(link));
            assert!(head.contains(&7) && !head.contains(&2), "{queries:?}");
            assert_eq!(
                link.difference(&head).copied().collect::<Vec<_>>(),
                [2],
                "the link's table, and nothing else, joins the cover: {queries:?}"
            );
            assert!(link.is_superset(&head));
            return;
        }
        panic!("no seed drew a cover without pages-2");
    }

    /// Budgets that stop a walk midway through a shard stop it between sweeps, and
    /// no pass sends more queries or private bytes than its limits. The shard has
    /// three page tables, so every sweep covers all three.
    #[test]
    fn a_budget_stop_falls_between_sweeps_within_the_limits() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        let end = H0 + 29;
        let events = chain([H0 + 1, H0 + 11, H0 + 21]);
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, events)]);
        for (queries, private_bytes) in [(12, PRIVATE_BYTES), (QUERIES, BUDGET_BYTES)] {
            let mut wallet = Wallet::open(1, end, 5, config(1, queries, private_bytes));
            let passes = wallet.sync(&url, 4);
            assert_eq!(passes.len(), 2, "the budget stops the first pass only");
            for sent in &passes {
                assert!(queries_sent(sent) as u64 <= queries, "{queries} queries");
                assert!(
                    bytes_sent(sent) as u64 <= private_bytes,
                    "{} of {private_bytes} private bytes",
                    bytes_sent(sent)
                );
                sweeps(&page_queries(sent, 0), &BTreeSet::from([0, 1, 2]));
            }
        }
    }

    /// Discovering another table must leave the already reserved padding intact
    /// when the larger sweep does not fit the pass's remaining query allowance.
    #[test]
    fn refused_growth_preserves_the_reserved_padding() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        let end = H0 + 99;
        let events = [21, 41, 61, 81]
            .into_iter()
            .flat_map(|offset| history(1, H0 + offset, 3))
            .collect();
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, events)]);

        // This seed covers the three newest runs, but not the oldest in pages-2.
        // Two directory queries leave twelve slots for four three-table sweeps.
        let mut wallet = Wallet::open(1, end, 120, config(1, 14, PRIVATE_BYTES));
        let (report, sent) = wallet.pass(&url);
        let queries = page_queries(&sent, 0);
        let cover = BTreeSet::from([4, 6, 8]);
        assert_eq!(report.progress.outcome, Outcome::More);
        assert_eq!(tables(&queries), cover, "the refused table is not sent");
        assert_eq!(
            sweeps(&queries, &cover).len(),
            4,
            "three real sweeps retain room for their fourth padding sweep: {} total queries",
            queries_sent(&sent)
        );
        assert_eq!(queries_sent(&sent), 14, "the whole pass fits its budget");
    }

    /// Passes `wallet` until one completes, and returns how many it took.
    /// Every pass stays within the companion's query and byte limits, sends
    /// whole sweeps over every page table of shard 0, and reads more of the
    /// owners' histories than the pass before: no owner loses ground and one
    /// gains. The companion is reopened, a new session, before each pass
    /// `reopen` names.
    fn finish(
        wallet: &mut Wallet,
        url: &str,
        owners: &[u8],
        reopen: &dyn Fn(usize) -> bool,
        max: usize,
    ) -> usize {
        let cover = BTreeSet::from([0, 1, 2]);
        let mut read: Vec<Vec<(i64, i64)>> = Vec::new();
        for pass in 1..=max {
            if reopen(pass) {
                wallet.reopen(pass as u64);
            }
            let (report, sent) = wallet.pass(url);
            assert!(
                queries_sent(&sent) as u64 <= wallet.config.queries,
                "pass {pass}: {} queries",
                queries_sent(&sent)
            );
            assert!(
                bytes_sent(&sent) as u64 <= wallet.config.private_bytes,
                "pass {pass}: {} private bytes",
                bytes_sent(&sent)
            );
            sweeps(&page_queries(&sent, 0), &cover);
            let now: Vec<(i64, i64)> = owners
                .iter()
                .map(|owner| wallet.recovered(*owner))
                .collect();
            if let Some(before) = read.last() {
                assert!(
                    now.iter().zip(before).all(|(now, before)| now >= before) && now != *before,
                    "pass {pass} read nothing more: {read:?} then {now:?}"
                );
            }
            read.push(now);
            if report.progress.outcome == Outcome::Complete {
                return pass;
            }
            assert_eq!(
                report.progress.outcome,
                Outcome::More,
                "pass {pass}: {report:?}"
            );
        }
        panic!("no complete pass in {max}: {read:?}");
    }

    /// A run of eight fragments in a shard of three page tables, which the walk
    /// reads as its head and then one round of the other seven. A pass's query
    /// budget fits two directory queries and two sweeps, never the round: each
    /// pass keeps the fragments it read and the next resumes after them, also
    /// in a reopened companion, until the whole history is recovered. Before a
    /// budget stop kept the replies of the round it cut short, every pass sent
    /// the round's first sweeps again and saved none of them.
    #[test]
    fn a_round_longer_than_a_pass_finishes_across_passes_and_restarts() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        let end = H0 + 29;
        // A run of 642 events beyond the two the directory keeps: eight rows.
        let count = 644;
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, burst(1, H0 + 5, count))]);
        let mut wallet = Wallet::open(1, end, 9, config(1, 2 + 2 * 3, PRIVATE_BYTES));
        let passes = finish(&mut wallet, &url, &[1], &|pass| pass == 3, 12);
        assert!(passes >= 4, "the run takes several passes: {passes}");
        assert_eq!(
            wallet.recovered(1),
            (i64::from(count), 0),
            "every receive is recovered and no walk is left"
        );
    }

    /// Two scripts with runs of four fragments in different page tables share
    /// each round: first both heads, then the six other fragments together.
    /// After the directory pass, each pass, in a reopened companion, has bytes
    /// for every page table's setup and three and a half sweeps, so two sweeps
    /// at a time: the passes split the shared round, each keeping what it read,
    /// and both histories are recovered whole.
    #[test]
    fn scripts_sharing_a_round_finish_it_across_passes_within_the_byte_budget() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        let end = H0 + 29;
        // Runs of 266 events, four rows each, in pages-0 and pages-2.
        let count = 268;
        let mut events = burst(1, H0 + 5, count);
        events.extend(burst(2, H0 + 25, count));
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, events)]);

        // An unlimited pass measures what the budget is made of: the directory
        // queries, every page table's setup, and one sweep.
        let mut probe = Wallet::open(1, end, 4, config(1, QUERIES, PRIVATE_BYTES));
        probe.also = vec![2];
        let (report, sent) = probe.pass(&url);
        assert_eq!(report.progress.outcome, Outcome::Complete);
        let route = Regex::new(SHARD_ROUTE).unwrap();
        let mut directory_queries = 0;
        let mut setups = 0;
        let mut pages = Vec::new();
        for sent in &sent {
            let Some(captures) = route.captures(&sent.path) else {
                continue;
            };
            match (&captures[2], captures.get(4)) {
                ("query", None) => directory_queries += 1,
                ("setup", Some(_)) => setups += sent.upload + sent.download,
                ("query", Some(_)) => pages.push(sent.upload + sent.download),
                _ => {}
            }
        }
        let sweep: usize = pages[..3].iter().sum();

        // The directory pass: its queries, and no room for a sweep.
        let mut wallet = Wallet::open(1, end, 4, config(1, directory_queries, PRIVATE_BYTES));
        wallet.also = vec![2];
        let (report, sent) = wallet.pass(&url);
        assert_eq!(report.progress.outcome, Outcome::More);
        assert!(page_queries(&sent, 0).is_empty());

        // The setups, with room for the envelope page cover admits them at,
        // and three and a half sweeps.
        wallet.config.queries = QUERIES;
        wallet.config.private_bytes = (setups + 3 * 1024 + 3 * sweep + sweep / 2) as u64;
        let passes = finish(&mut wallet, &url, &[1, 2], &|_| true, 12);
        // Both heads; then the other six fragments, two a pass.
        assert_eq!(passes, 4, "two sweeps a pass");
        for owner in [1, 2] {
            assert_eq!(
                wallet.recovered(owner),
                (i64::from(count), 0),
                "owner {owner}"
            );
        }
    }

    /// A run of three fragments under a query budget of exactly one sweep after
    /// the directory pass: each pass reads one fragment, the head and then one
    /// of the round of two, and the history finishes. One query fewer fits no
    /// sweep: those passes send no page query and read nothing, as a budget too
    /// small for a sweep must. Before a budget stop kept a round's replies, the
    /// one-sweep passes repeated the round's first fragment without end.
    #[test]
    fn a_budget_of_exactly_one_sweep_reads_a_fragment_per_pass() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        let end = H0 + 29;
        // A run of 182 events beyond the two the directory keeps: three rows.
        let count = 184;
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, burst(1, H0 + 5, count))]);

        // The directory pass: two directory queries, and no room for a sweep.
        let mut wallet = Wallet::open(1, end, 2, config(1, 2, PRIVATE_BYTES));
        let (report, sent) = wallet.pass(&url);
        assert_eq!(report.progress.outcome, Outcome::More);
        assert_eq!(queries_sent(&sent), 2);
        assert!(page_queries(&sent, 0).is_empty());
        let directory = wallet.recovered(1);
        for _ in 0..2 {
            let (report, sent) = wallet.pass(&url);
            assert_eq!(report.progress.outcome, Outcome::More);
            assert_eq!(queries_sent(&sent), 0, "two queries fit no sweep");
            assert_eq!(wallet.recovered(1), directory, "and read nothing");
        }

        wallet.config.queries = 3;
        wallet.reopen(2);
        let passes = finish(&mut wallet, &url, &[1], &|_| false, 6);
        assert_eq!(passes, 3, "one fragment per pass");
        assert_eq!(wallet.recovered(1), (i64::from(count), 0));
    }

    /// A pass whose byte budget fits the directory but not the page setups
    /// stops at that boundary: it fetches no page setup and sends no page
    /// query, keeps the directory's work, and reports a budget stop. The next
    /// pass, with room for the setups and a sweep, starts at the pages without
    /// asking the directory again, and finishes.
    #[test]
    fn a_pass_stops_at_the_page_setup_boundary_and_the_next_resumes() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        let end = H0 + 29;
        let count = 100;
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, burst(1, H0 + 5, count))]);
        let mut probe = Wallet::open(1, end, 6, config(1, QUERIES, PRIVATE_BYTES));
        let (_, sent) = probe.pass(&url);
        let route = Regex::new(SHARD_ROUTE).unwrap();
        let directory: usize = sent
            .iter()
            .filter(|sent| {
                route
                    .captures(&sent.path)
                    .is_some_and(|captures| captures.get(4).is_none())
            })
            .map(|sent| sent.upload + sent.download)
            .sum();

        let mut wallet = Wallet::open(1, end, 6, config(1, QUERIES, directory as u64 + 1_000));
        let (report, sent) = wallet.pass(&url);
        assert_eq!(report.progress.outcome, Outcome::More, "{report:?}");
        assert!(page_setups(&sent, 0).is_empty(), "no page setup");
        assert!(page_queries(&sent, 0).is_empty(), "no page query");
        let after_directory = wallet.recovered(1);
        assert_eq!(
            after_directory.0, 2,
            "the directory's inline receives are kept"
        );

        wallet.config.private_bytes = PRIVATE_BYTES;
        wallet.reopen(7);
        let (report, sent) = wallet.pass(&url);
        assert_eq!(report.progress.outcome, Outcome::Complete);
        assert!(
            routed(&sent).iter().all(|routed| routed.page.is_some()),
            "the next pass resumes at the pages"
        );
        assert_eq!(wallet.recovered(1), (i64::from(count), 0));
    }

    /// A service refusing page queries for capacity, or failing one, stays that:
    /// the pass reports the overload, or fails, rather than a budget stop, and
    /// keeps every round finished before it. A later pass against a healthy
    /// service finishes the history.
    #[test]
    fn service_overload_and_failure_are_not_budget_stops() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        /// Answers the `from`th page query on, counted from zero, with `status`.
        struct Refusing {
            inner: Loopback,
            status: u16,
            from: usize,
            pages: std::cell::Cell<usize>,
        }
        impl HttpExchange for Refusing {
            fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
                if request.method == HttpMethod::Post && request.path.contains("/query/pages-") {
                    let page = self.pages.get();
                    self.pages.set(page + 1);
                    if page >= self.from {
                        return Ok(HttpReply {
                            status: self.status,
                            retry_after: Some("0".into()),
                            ..HttpReply::default()
                        });
                    }
                }
                self.inner.send(request)
            }
        }
        let end = H0 + 29;
        let count = 644;
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, burst(1, H0 + 5, count))]);
        for status in [503, 500] {
            let mut wallet = Wallet::open(1, end, 8, config(1, QUERIES, PRIVATE_BYTES));
            // The head's sweep and a sweep of the next round get through.
            let exchange = Refusing {
                inner: Loopback::new(&url),
                status,
                from: 6,
                pages: std::cell::Cell::new(0),
            };
            let watch = wallet.watch();
            let chain = Chain { tip: end };
            let result = wallet.recovery.as_mut().unwrap().pass(
                &watch,
                &chain,
                &exchange,
                RESPONSE_LIMIT,
                &|| false,
            );
            match (status, result) {
                (503, Ok(report)) => {
                    assert_eq!(report.progress.outcome, Outcome::Overloaded, "{report:?}")
                }
                (500, Err(_)) => {}
                (status, other) => panic!("{status}: {other:?}"),
            }
            let (receives, fragments) = wallet.recovered(1);
            assert_eq!(receives, 2, "{status}: the directory's inline receives");
            assert!(fragments > 0, "{status}: the head round is kept");
            let (report, _) = wallet.pass(&url);
            assert_eq!(report.progress.outcome, Outcome::Complete, "{status}");
            assert_eq!(wallet.recovered(1), (i64::from(count), 0), "{status}");
        }
    }

    /// A service answering page queries with replies longer than their table's
    /// scheme fixes gets one such reply through: the sweep fails on it before
    /// sending its next query, sends no padding after it, and the pass stays
    /// within its byte budget. Before, every slot of the sweep, and the cover
    /// sweeps padding it, fetched an oversized reply, past the budget.
    #[test]
    fn an_oversized_page_reply_ends_the_sweep_before_its_next_query() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        /// Replaces each page query's reply with 400,000 bytes, below the
        /// response limit, counting the private bytes delivered and the page
        /// queries sent after the first oversized reply.
        struct Oversized {
            inner: Loopback,
            bytes: std::cell::Cell<u64>,
            after: std::cell::Cell<Option<usize>>,
        }
        impl HttpExchange for Oversized {
            fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
                let page =
                    request.method == HttpMethod::Post && request.path.contains("/query/pages-");
                if page && let Some(after) = self.after.get() {
                    self.after.set(Some(after + 1));
                }
                let mut reply = self.inner.send(request)?;
                if page {
                    reply.body = vec![0; 400_000];
                    self.after.set(self.after.get().or(Some(0)));
                }
                if Regex::new(SHARD_ROUTE).unwrap().is_match(&request.path) {
                    let delivered = reply.body.len().min(request.limit);
                    self.bytes
                        .set(self.bytes.get() + (request.body.len() + delivered) as u64);
                }
                if reply.body.len() > request.limit {
                    return Err(HttpFailure::TooLarge);
                }
                Ok(reply)
            }
        }
        let end = H0 + 29;
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, history(1, H0 + 1, 3))]);
        let budget = 1 << 20;
        let mut wallet = Wallet::open(1, end, 7, config(1, QUERIES, budget));
        let exchange = Oversized {
            inner: Loopback::new(&url),
            bytes: std::cell::Cell::new(0),
            after: std::cell::Cell::new(None),
        };
        let watch = wallet.watch();
        let chain = Chain { tip: end };
        let result = wallet.recovery.as_mut().unwrap().pass(
            &watch,
            &chain,
            &exchange,
            RESPONSE_LIMIT,
            &|| false,
        );
        assert!(result.is_err(), "the malformed reply fails the pass");
        assert_eq!(
            exchange.after.get(),
            Some(0),
            "no page query follows the oversized reply"
        );
        assert!(
            exchange.bytes.get() <= budget,
            "{} bytes exceeded a {budget}-byte pass",
            exchange.bytes.get()
        );
    }

    /// A service that corrupts the header of one page reply learns nothing from
    /// the wallet's reaction about whether that slot was real: whichever slot
    /// of the sweep it hits, the pass fails there and sends no other page query.
    /// Before, a corrupted dummy reply went unread and the walk carried on.
    #[test]
    fn a_tagged_page_reply_fails_the_pass_whichever_slot_it_hits() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        /// Flips the first byte of page reply `tagged`, counted from zero, and
        /// counts the page queries sent.
        struct Tagging {
            inner: Loopback,
            tagged: usize,
            pages: std::cell::Cell<usize>,
        }
        impl HttpExchange for Tagging {
            fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
                let mut reply = self.inner.send(request)?;
                if request.method == HttpMethod::Post && request.path.contains("/query/pages-") {
                    if self.pages.get() == self.tagged {
                        reply.body[0] ^= 0xff;
                    }
                    self.pages.set(self.pages.get() + 1);
                }
                Ok(reply)
            }
        }
        let end = H0 + 29;
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, history(1, H0 + 1, 3))]);
        // One sweep over the three tables; every slot takes its turn.
        for tagged in 0..3 {
            let mut wallet = Wallet::open(1, end, 7, config(1, QUERIES, PRIVATE_BYTES));
            let exchange = Tagging {
                inner: Loopback::new(&url),
                tagged,
                pages: std::cell::Cell::new(0),
            };
            let watch = wallet.watch();
            let chain = Chain { tip: end };
            let result = wallet.recovery.as_mut().unwrap().pass(
                &watch,
                &chain,
                &exchange,
                RESPONSE_LIMIT,
                &|| false,
            );
            assert!(result.is_err(), "slot {tagged}: the pass fails");
            assert_eq!(
                exchange.pages.get(),
                tagged + 1,
                "slot {tagged}: no page query after the tagged reply"
            );
        }
    }

    /// Two scripts whose heads the same directory lookup finds, in `pages-1` and
    /// `pages-7` of a shard of ten tables, are covered from the first sweep: the
    /// first round names both tables before anything is sent, so the cover holds
    /// both and never grows. Before, the cover was drawn from the first query's
    /// table alone, and the other head's table often joined it visibly.
    #[test]
    fn heads_found_together_share_the_first_cover() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        let end = H0 + 99;
        let mut events = history(1, H0 + 11, 3);
        events.extend(history(2, H0 + 71, 3));
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, events)]);
        for seed in 0..8 {
            let mut wallet = Wallet::open(1, end, seed, config(1, QUERIES, PRIVATE_BYTES));
            wallet.also = vec![2];
            let (report, sent) = wallet.pass(&url);
            assert_eq!(report.progress.outcome, Outcome::Complete);
            let queries = page_queries(&sent, 0);
            let cover = tables(&queries);
            assert!(
                cover.is_superset(&BTreeSet::from([1, 7])),
                "seed {seed}: {queries:?}"
            );
            // Whole sweeps over one cover: no sweep added a table.
            sweeps(&queries, &cover);
            for owner in [1, 2] {
                assert_eq!(
                    wallet.recovered(owner),
                    (3, 0),
                    "seed {seed}, owner {owner}"
                );
            }
        }
    }

    /// A service that sends one page table a setup whose parameters do not hash
    /// to its declared digest learns nothing about which table is real: whichever
    /// table it picks, the pass fails before any page query. Before, a bad setup
    /// for a table only covered went unchecked and the sweeps went ahead, while
    /// one for the real table stopped the walk.
    #[test]
    fn a_bad_setup_for_any_table_stops_the_pass_before_its_sweeps() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        /// Corrupts the declared digest of page table `table`'s setup, and
        /// counts the page queries sent.
        struct BadSetup {
            inner: Loopback,
            table: u32,
            pages: std::cell::Cell<usize>,
        }
        impl HttpExchange for BadSetup {
            fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
                let mut reply = self.inner.send(request)?;
                if request.method == HttpMethod::Post && request.path.contains("/query/pages-") {
                    self.pages.set(self.pages.get() + 1);
                }
                if request
                    .path
                    .contains(&format!("/setup/pages-{}/", self.table))
                {
                    let mut setup: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
                    setup["public_params_sha256"] = serde_json::Value::String("00".repeat(32));
                    reply.body = serde_json::to_vec(&setup).unwrap();
                }
                Ok(reply)
            }
        }
        let end = H0 + 29;
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, history(1, H0 + 1, 3))]);
        // The history's run is in pages-0; every table is covered.
        for table in 0..3 {
            let mut wallet = Wallet::open(1, end, 7, config(1, QUERIES, PRIVATE_BYTES));
            let exchange = BadSetup {
                inner: Loopback::new(&url),
                table,
                pages: std::cell::Cell::new(0),
            };
            let watch = wallet.watch();
            let chain = Chain { tip: end };
            let result = wallet.recovery.as_mut().unwrap().pass(
                &watch,
                &chain,
                &exchange,
                RESPONSE_LIMIT,
                &|| false,
            );
            assert!(result.is_err(), "table {table}: the pass fails");
            assert_eq!(exchange.pages.get(), 0, "table {table}: no page query");
        }
    }

    /// Evidence for the payload-corruption leak (PR #211 review thread
    /// r4290377076): a service keeps every segment header of one table's page
    /// reply in the first sweep and garbles the payload behind it. The same
    /// wallet, seed and chain of three runs (pages-2, then pages-1, then
    /// pages-0) is run twice, once with the real slot corrupted and once with a
    /// dummy slot corrupted. The service must not be able to tell the two apart
    /// from what it receives.
    #[test]
    #[ignore = "known leak: fails until the page schedule stops depending on the walk (PR #211, r4290377076)"]
    fn payload_corruption_in_the_real_or_a_dummy_slot_sends_the_same_requests() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        /// Garbles everything after the 16-byte header of the first page reply
        /// to `pages-<table>`, and records every exchange.
        struct Garbling {
            inner: Recording,
            table: u32,
            done: std::cell::Cell<bool>,
        }
        impl HttpExchange for Garbling {
            fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
                let mut reply = self.inner.send(request)?;
                let target = format!("/query/pages-{}", self.table);
                if !self.done.get()
                    && request.method == HttpMethod::Post
                    && request.path.ends_with(&target)
                {
                    self.done.set(true);
                    for byte in reply.body.iter_mut().skip(16) {
                        *byte ^= 0x5a;
                    }
                }
                Ok(reply)
            }
        }
        let end = H0 + 29;
        let events = chain([H0 + 1, H0 + 11, H0 + 21]);
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, events)]);
        let mut seen = Vec::new();
        for table in [2, 0] {
            let mut wallet = Wallet::open(1, end, 7, config(1, QUERIES, PRIVATE_BYTES));
            let exchange = Garbling {
                inner: Recording {
                    inner: Loopback::new(&url),
                    sent: RefCell::default(),
                },
                table,
                done: std::cell::Cell::new(false),
            };
            let watch = wallet.watch();
            let chain = Chain { tip: end };
            let result = wallet.recovery.as_mut().unwrap().pass(
                &watch,
                &chain,
                &exchange,
                RESPONSE_LIMIT,
                &|| false,
            );
            let outcome = result.map(|report| report.progress.outcome);
            let sent = exchange.inner.sent.into_inner();
            eprintln!(
                "garbled pages-{table}: outcome {outcome:?}, page queries {:?}",
                page_queries(&sent, 0)
            );
            seen.push(
                sent.iter()
                    .map(|sent| (sent.method, sent.path.clone(), sent.upload))
                    .collect::<Vec<_>>(),
            );
        }
        assert_eq!(
            seen[0], seen[1],
            "the service sees the same requests whether the garbled slot was real or a dummy"
        );
    }

    /// A directory setup reply padded past the size its scheme allows, here with
    /// a field the setup's reader would ignore, fails the pass before any
    /// directory query instead of being kept, as a page setup's would.
    #[test]
    fn an_oversized_directory_setup_fails_the_pass() {
        let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
        /// Pads every directory setup reply with an extra field, and counts the
        /// directory queries sent.
        struct Padded {
            inner: Loopback,
            queries: std::cell::Cell<usize>,
        }
        impl HttpExchange for Padded {
            fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
                let mut reply = self.inner.send(request)?;
                if request.path.contains("/query/directory") {
                    self.queries.set(self.queries.get() + 1);
                }
                if request.path.contains("/setup/directory/") {
                    let mut setup: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
                    setup["padding"] = serde_json::Value::String("x".repeat(64 << 10));
                    reply.body = serde_json::to_vec(&setup).unwrap();
                }
                Ok(reply)
            }
        }
        let end = H0 + 29;
        let (_server, url, _dir) = serve(&[shard(H0, end, 10, history(1, H0 + 1, 3))]);
        let mut wallet = Wallet::open(1, end, 7, config(1, QUERIES, PRIVATE_BYTES));
        let exchange = Padded {
            inner: Loopback::new(&url),
            queries: std::cell::Cell::new(0),
        };
        let watch = wallet.watch();
        let chain = Chain { tip: end };
        let result = wallet.recovery.as_mut().unwrap().pass(
            &watch,
            &chain,
            &exchange,
            RESPONSE_LIMIT,
            &|| false,
        );
        assert!(result.is_err(), "the oversized setup fails the pass");
        assert_eq!(exchange.queries.get(), 0, "no directory query follows it");
    }
}
