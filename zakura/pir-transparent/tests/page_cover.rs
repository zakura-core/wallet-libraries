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
    tip: u64,
    config: TransparentHistoryRecoveryConfig,
    recovery: Option<TransparentHistoryRecovery>,
}

impl Wallet {
    fn open(tag: u8, tip: u64, seed: u64, config: TransparentHistoryRecoveryConfig) -> Self {
        let mut wallet = Self {
            dir: tempfile::tempdir().unwrap(),
            tag,
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
            addresses: vec![WatchedAddress {
                address: address(self.tag),
                origin: WatchOrigin::Standalone,
                required_from: BlockHeight::from_u32(H0 as u32),
            }],
            pending_pages: vec![],
        }
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
}
