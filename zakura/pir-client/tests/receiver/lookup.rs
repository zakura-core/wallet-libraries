//! Lookup steps against synthetic segments served in process over real PIR: the queries
//! each case sends, the floor, failures and cursors.
mod common;
use common::receiver as target;
use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};
use zakura_pir_client::receiver::{
    Client, Companion, Coverage, Directory, Hash, Pace, Payment, Publication, ReceiverBytes, Tree,
    initial_salt,
    inventory::{Inventory, Shard},
    lookup, lookup_with,
    session::{Error, HEADER_BYTES},
    tag,
    transport::{InventoryClient, Transport},
};
use zakura_pir_publisher::receiver::{OPEN_SEED_ATTEMPTS, Paid, Projection, build, query_rows};
use zakura_pir_query_server::receiver::server::Server;
use zcash_client_backend::data_api::one_time_ivk::restore::{
    DiscoveryWork, LookupPage, LookupWork, RecoveryToken,
};
use zcash_client_sqlite::wallet::one_time_ivk::{KeyId, Purpose};

const ORIGIN: &str = "https://receiver.test";

/// The fixture chain's hash at `height`.
fn hash(height: u32) -> Hash {
    let mut h = [0x33; 32];
    h[..4].copy_from_slice(&height.to_le_bytes());
    h
}

/// Receiver `i` other than [`target`]; never queried, so it needs no valid address.
fn other(i: u32) -> ReceiverBytes {
    let mut r = [0x5a; 43];
    r[..4].copy_from_slice(&i.to_le_bytes());
    r
}

/// `n` payments to `to` at `height`.
fn paid(to: ReceiverBytes, height: u32, n: usize) -> Vec<(ReceiverBytes, u32)> {
    vec![(to, height); n]
}

/// One shard of the fixture chain: heights `start..=end` and each segment's payments, in
/// chain order.
struct Plan {
    start: u32,
    end: u32,
    sealed: bool,
    segments: Vec<Vec<(ReceiverBytes, u32)>>,
}

/// One inventory's routes: head and chunks are not served, since tests hand the client
/// the inventory; choice objects, setups and query evaluation are.
struct Routes {
    inventory: Inventory,
    directories: Vec<Server<Directory>>,
    companions: Vec<Server<Companion>>,
    choices: Vec<(Hash, Vec<u8>)>,
}

/// The coverage of a shard of `plan` whose positions start at `start_position`.
fn coverage(plan: &Plan, start_position: u64) -> Coverage {
    let count: usize = plan.segments.iter().map(Vec::len).sum();
    Coverage {
        genesis: [1; 32],
        history_revision: 0,
        start_height: plan.start,
        start_parent: hash(plan.start - 1),
        start_position,
        end_height: plan.end,
        end_hash: hash(plan.end),
        end_position: start_position + count as u64,
    }
}

/// Segment `index` over `coverage` holding `payments` from position `*position` on, which
/// it advances, with its companion built at `tree`.
fn segment(
    coverage: &Coverage,
    index: u32,
    payments: &[(ReceiverBytes, u32)],
    position: &mut u64,
    tree: Tree,
) -> zakura_pir_publisher::receiver::Segment {
    let paid: Vec<Paid> = payments
        .iter()
        .map(|&(to, height)| {
            let mut txid = [7; 32];
            txid[..8].copy_from_slice(&position.to_le_bytes());
            let payment = Payment {
                height,
                block_hash: hash(height),
                txid,
                tx_index: *position as u32 + 1,
                action_index: 0,
                position: *position,
                action_nullifier: [5; 32],
                cmx: [6; 32],
                ephemeral_key: [7; 32],
                ciphertext_prefix: [8; 52],
            };
            *position += 1;
            (to, payment, [0; 512])
        })
        .collect();
    let mut projection = Projection::new(initial_salt(&coverage.start_parent, index));
    let mut heights: Vec<_> = paid.iter().map(|p| p.1.height).collect();
    heights.dedup();
    for height in heights {
        let block: Vec<_> = paid
            .iter()
            .filter(|p| p.1.height == height)
            .map(|p| p.0)
            .collect();
        projection.project(&block, &hash(height)).unwrap();
    }
    let rows = query_rows(paid.len() as u32);
    let seed = coverage.end_hash;
    build(
        &projection,
        coverage.clone(),
        &seed,
        OPEN_SEED_ATTEMPTS,
        rows,
        tree,
        &paid,
    )
    .unwrap()
}

/// Publishes `plans` with every companion built at `tree_at`.
fn publish(plans: &[Plan], tree_at: u32) -> Routes {
    let total: usize = plans.iter().flat_map(|p| &p.segments).map(Vec::len).sum();
    let tree = Tree {
        height: tree_at,
        hash: hash(tree_at),
        size: total as u64,
    };
    let (mut directories, mut companions, mut choices, mut shards) =
        (vec![], vec![], vec![], vec![]);
    let mut position = 0u64;
    for plan in plans {
        let coverage = coverage(plan, position);
        let mut segments = vec![];
        for (index, payments) in (0..).zip(&plan.segments) {
            let built = segment(&coverage, index, payments, &mut position, tree);
            let manifest = built.directory.manifest.clone();
            choices.push((manifest.choice.digest, built.directory.choice.clone()));
            let (directory, entries) = Server::directory(built.directory).unwrap();
            let companion = Server::companion(built.companion, &manifest, &entries).unwrap();
            segments.push(Publication {
                directory: directory.session().clone(),
                companion: companion.session().clone(),
            });
            directories.push(directory);
            companions.push(companion);
        }
        shards.push(Shard {
            index: 0,
            sealed: plan.sealed,
            start_height: plan.start,
            start_parent: coverage.start_parent,
            start_position: coverage.start_position,
            end_height: plan.end,
            end_hash: coverage.end_hash,
            end_position: coverage.end_position,
            segments,
            filter: None,
        });
    }
    Routes {
        inventory: Inventory::build([1; 32], 0, shards).unwrap(),
        directories,
        companions,
        choices,
    }
}

/// What the network does to the next query.
#[derive(Clone, Copy)]
enum Fault {
    /// It fails in transport before the server sees it.
    Drop,
    /// Its session is gone (HTTP 410).
    Gone,
}

/// Serves [`Routes`] in process, logging every request and applying queued faults to
/// queries in order (`None` passes one through).
struct Net {
    routes: Mutex<Routes>,
    log: Mutex<Vec<(String, Vec<u8>)>>,
    faults: Mutex<VecDeque<Option<Fault>>>,
}

impl Net {
    /// Serves `routes`.
    fn new(routes: Routes) -> Self {
        Self {
            routes: Mutex::new(routes),
            log: Mutex::new(vec![]),
            faults: Mutex::new(VecDeque::new()),
        }
    }

    /// A client for the served inventory, reading every segment blind.
    fn client(&self) -> InventoryClient<&Self> {
        let inventory = self.routes.lock().unwrap().inventory.clone();
        InventoryClient::new(ORIGIN, self, inventory, false)
    }

    /// Queues `faults` for the next queries.
    fn fail(&self, faults: impl IntoIterator<Item = Option<Fault>>) {
        self.faults.lock().unwrap().extend(faults);
    }

    /// Logged requests whose name starts with `prefix`.
    fn count(&self, prefix: &str) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n.starts_with(prefix))
            .count()
    }
}

impl Transport for Net {
    /// Serves setups and choice objects.
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, Error> {
        let path = url.strip_prefix(&format!("{ORIGIN}/receiver/v1/")).unwrap();
        let routes = self.routes.lock().unwrap();
        let body = match path.split_once('/').unwrap() {
            ("public", id) => {
                let d = routes
                    .directories
                    .iter()
                    .find(|s| hex::encode(s.id()) == id);
                let c = routes.companions.iter().find(|s| hex::encode(s.id()) == id);
                d.map(|s| s.public())
                    .or(c.map(|s| s.public()))
                    .ok_or(Error::Revision)?
                    .to_vec()
            }
            ("choice", digest) => routes
                .choices
                .iter()
                .find(|(d, _)| hex::encode(d) == digest)
                .map(|(_, b)| b.clone())
                .ok_or(Error::Transport("HTTP 404".into()))?,
            other => panic!("unexpected route {other:?}"),
        };
        self.log
            .lock()
            .unwrap()
            .push((path.split('/').next().unwrap().into(), vec![]));
        assert!(body.len() <= limit);
        Ok(body)
    }

    /// Evaluates a query, after any queued fault.
    async fn post(&self, url: &str, body: Vec<u8>, limit: usize) -> Result<Vec<u8>, Error> {
        assert_eq!(url, format!("{ORIGIN}/receiver/v1/query"));
        let fault = self.faults.lock().unwrap().pop_front().flatten();
        let routes = self.routes.lock().unwrap();
        let id = &body[4..36];
        let d = routes.directories.iter().find(|s| s.id()[..] == *id);
        let c = routes.companions.iter().find(|s| s.id()[..] == *id);
        let name = match (d, c) {
            (Some(_), _) => "D".to_owned(),
            (_, Some(c)) => format!("C {}", hex::encode(c.id())),
            _ => "gone".to_owned(),
        };
        self.log.lock().unwrap().push((name, body.clone()));
        let respond = || match (d, c) {
            (Some(d), _) => d.respond(&body),
            (_, Some(c)) => c.respond(&body),
            _ => Err(Error::Revision),
        };
        let response = match fault {
            Some(Fault::Drop) => Err(Error::Transport("dropped".into())),
            Some(Fault::Gone) => Err(Error::Revision),
            None => respond(),
        }?;
        assert!(response.len() <= limit);
        Ok(response)
    }
}

/// [`target`]'s work from `from` with the account birthday `birthday`, at no cursor.
fn work(from: u32, birthday: u32) -> LookupWork {
    LookupWork {
        token: RecoveryToken {
            generation: 0,
            history_revision: 0,
        },
        work: DiscoveryWork {
            key: KeyId::new(Purpose::Receive, 0),
            receiver: target(),
        },
        from: from.into(),
        through: 100.into(),
        birthday: birthday.into(),
        cursor: None,
    }
}

/// A pace reading up to `records` records.
fn pace(records: usize) -> Pace {
    Pace {
        records: NonZeroUsize::new(records).unwrap(),
    }
}

/// Moves `work` past `page`, as the wallet records it.
fn advance(work: &mut LookupWork, page: &LookupPage) {
    if let Some(checked) = page.checked_through {
        work.from = checked + 1;
    }
    work.cursor = page.next.clone();
}

/// Runs default steps from `work` until the request completes, returning their pages.
async fn walk(net: &Net, work: LookupWork) -> Vec<LookupPage> {
    walk_with(&net.client(), work).await
}

/// [`walk`] with `client`.
async fn walk_with(client: &InventoryClient<&Net>, mut work: LookupWork) -> Vec<LookupPage> {
    let mut pages = vec![];
    loop {
        let page = lookup(client, &work).await.unwrap();
        advance(&mut work, &page);
        let done = page.next.is_none();
        pages.push(page);
        if done {
            return pages;
        }
    }
}

/// One sealed shard at heights 100 to 109 with `segments`, then an empty recent tier.
fn sealed(segments: Vec<Vec<(ReceiverBytes, u32)>>) -> Vec<Plan> {
    vec![
        Plan {
            start: 100,
            end: 109,
            sealed: true,
            segments,
        },
        Plan {
            start: 110,
            end: 110,
            sealed: false,
            segments: vec![vec![]],
        },
    ]
}

/// The S2.1 traces: a miss, a hit whose last payment is below `from`, and one below the
/// birthday each send one directory query and no companion query. A hit at the floor
/// reads one companion query per record, whether the wallet already holds them (a stale
/// or correction re-read, or a pending payment with a witness) or not (a new payment).
#[tokio::test]
async fn each_trace_sends_the_planned_queries() {
    let mut payments = paid(other(1), 103, 1);
    payments.extend(paid(target(), 105, 2));
    let net = Net::new(publish(&sealed(vec![payments]), 110));
    // Directory and companion queries per segment read, for a lookup of the sealed shard.
    let trace = |from, birthday| {
        let net = &net;
        async move {
            let (d, c) = (net.count("D"), net.count("C"));
            let page = lookup(&net.client(), &work(from, birthday)).await.unwrap();
            (net.count("D") - d, net.count("C") - c, page.records.len())
        }
    };
    assert_eq!(trace(106, 100).await, (1, 0, 0), "below from");
    assert_eq!(trace(100, 106).await, (1, 0, 0), "below the birthday");
    assert_eq!(trace(105, 100).await, (1, 2, 2), "at the floor");
    assert_eq!(trace(100, 105).await, (1, 2, 2), "at the birthday");
    let miss = Net::new(publish(&sealed(vec![paid(other(1), 103, 1)]), 110));
    let page = lookup(&miss.client(), &work(100, 100)).await.unwrap();
    assert_eq!(
        (miss.count("D"), miss.count("C"), page.records.len()),
        (1, 0, 0)
    );
}

/// Every alignment of a receiver's first slot within a five-slot companion row sends
/// exactly one companion query per record, for 2, 5, 6, 32 and 33 records.
#[tokio::test]
async fn every_alignment_sends_one_query_per_record() {
    // Receivers whose tags sort before the target's take the slots ahead of it.
    let salt = initial_salt(&hash(99), 0);
    let ahead: Vec<_> = (0..)
        .map(other)
        .filter(|r| tag(&salt, r) < tag(&salt, &target()))
        .take(4)
        .collect();
    for n in [2, 5, 6, 32, 33] {
        for first in 0..5 {
            let mut payments: Vec<_> = ahead[..first].iter().map(|r| (*r, 101)).collect();
            payments.extend(paid(target(), 105, n));
            let net = Net::new(publish(&sealed(vec![payments]), 110));
            let pages = walk(&net, work(100, 100)).await;
            assert_eq!(pages[0].records[0].record.ordinal, first as u32);
            let records: usize = pages.iter().map(|p| p.records.len()).sum();
            assert_eq!(
                (records, net.count("C")),
                (n, n),
                "{n} records from slot {first}"
            );
        }
    }
}

/// [`target`] paid `n` times at height 105 in the sealed shard, after another receiver.
fn history(n: usize) -> Vec<Plan> {
    let mut payments = paid(other(1), 103, 1);
    payments.extend(paid(target(), 105, n));
    sealed(vec![payments])
}

/// The session ID of companion `index` that `net` serves.
fn companion_id(net: &Net, index: usize) -> String {
    hex::encode(net.routes.lock().unwrap().companions[index].id())
}

/// A step stopped at the 32-record boundary resumes under the same inventory, reading the
/// receiver's entry again with one directory query and then only the records left. Under
/// a newer inventory the cursor is never reinterpreted, so the segment starts again at
/// page 0.
#[tokio::test]
async fn a_step_boundary_resumes_only_under_the_same_inventory() {
    let plans = history(40);
    let net = Net::new(publish(&plans, 110));
    let mut w = work(100, 100);
    let first = lookup(&net.client(), &w).await.unwrap();
    assert_eq!(
        (net.count("D"), net.count("C"), first.records.len()),
        (1, 32, 32)
    );
    advance(&mut w, &first);
    let same = lookup(&net.client(), &w).await.unwrap();
    assert_eq!((net.count("D"), net.count("C")), (2, 40));
    assert_eq!(same.records[0].record.page, 32);
    assert_eq!(same.checked_through, Some(109.into()));

    let rebuilt = Net::new(publish(&plans, 111));
    let restarted = lookup(&rebuilt.client(), &w).await.unwrap();
    assert_eq!((rebuilt.count("D"), rebuilt.count("C")), (1, 32));
    assert_eq!(restarted.records[0].record.page, 0);
}

/// A resumed cursor's last record must leave pages of the entry it continues: a total that
/// disagrees with the entry, a last page at the entry's end, or a next record that doesn't
/// follow it fails the step closed.
#[tokio::test]
async fn a_tampered_cursor_fails_closed() {
    let net = Net::new(publish(&history(40), 110));
    let mut w = work(100, 100);
    let first = lookup(&net.client(), &w).await.unwrap();
    advance(&mut w, &first);
    let edit = |change: fn(&mut zakura_pir_client::receiver::RawRecord)| {
        let mut w = w.clone();
        change(w.cursor.as_mut().unwrap().last.as_mut().unwrap());
        w
    };
    for tampered in [
        edit(|r| r.total += 1),
        edit(|r| r.page = 39),
        edit(|r| r.payment.position = u64::MAX),
    ] {
        assert!(matches!(
            lookup(&net.client(), &tampered).await,
            Err(Error::Malformed | Error::Directory(_))
        ));
    }
}

/// Two encryptions of one row differ in their upload, yet decode to the same row.
#[test]
fn two_encryptions_of_one_row_decode_alike() {
    let net = Net::new(publish(&history(3), 110));
    let routes = net.routes.lock().unwrap();
    let server = &routes.companions[0];
    let public = Arc::new(server.public().to_vec());
    let client = Client::new(server.session().clone(), public).unwrap();
    let (first, second) = (client.prepare(0).unwrap(), client.prepare(0).unwrap());
    assert_ne!(first.body()[HEADER_BYTES..], second.body()[HEADER_BYTES..]);
    let first_answer = server.respond(first.body()).unwrap();
    let second_answer = server.respond(second.body()).unwrap();
    assert_eq!(
        client.decode(first, &first_answer).unwrap(),
        client.decode(second, &second_answer).unwrap()
    );
}

/// A step is all or nothing. A later companion request that fails in transport after an
/// earlier one succeeded fails the whole step, as does a 410, so the wallet
/// records nothing and the next step reads the segment again from its start.
#[tokio::test]
async fn a_failed_request_fails_the_step() {
    let net = Net::new(publish(&history(3), 110));
    let client = net.client();
    let w = work(100, 100);
    net.fail([None, None, Some(Fault::Drop)]);
    assert!(matches!(
        lookup_with(&client, &w, pace(32)).await,
        Err(Error::Transport(_))
    ));
    net.fail([Some(Fault::Gone)]);
    assert!(matches!(lookup(&client, &w).await, Err(Error::Revision)));
    let done = lookup(&client, &w).await.unwrap();
    assert_eq!(done.records.len(), 3);
    assert_eq!(done.checked_through, Some(109.into()));
}

/// 129 records in an open segment complete in one round, five steps of at most 32 records
/// under one inventory, each reading the receiver's entry with one directory query.
#[tokio::test]
async fn an_open_segment_of_129_records_completes_in_one_round() {
    let plans = [Plan {
        start: 100,
        end: 110,
        sealed: false,
        segments: vec![paid(target(), 105, 129)],
    }];
    let net = Net::new(publish(&plans, 110));
    let pages = walk(&net, work(100, 100)).await;
    assert_eq!(pages.len(), 5);
    assert_eq!((net.count("D"), net.count("C")), (5, 129));
}

/// A miss in the first segments, then a hit in a later one: every segment of the shard is
/// read with one directory query, and companion queries name only the hit's companion.
#[tokio::test]
async fn a_miss_then_a_hit_in_a_later_segment() {
    let mut hit = paid(target(), 106, 2);
    hit.push((other(3), 107));
    let net = Net::new(publish(
        &sealed(vec![paid(other(1), 101, 1), paid(other(2), 103, 1), hit]),
        110,
    ));
    let pages = walk(&net, work(100, 100)).await;
    assert_eq!(pages.iter().map(|p| p.records.len()).sum::<usize>(), 2);
    assert_eq!(net.count("D"), 3 + 1);
    assert_eq!(net.count(&format!("C {}", companion_id(&net, 2))), 2);
    assert_eq!(net.count("C"), 2);
}

/// Choice objects are kept within their own budget: a walk across more segments than fit
/// evicts them, and walking again fetches them again.
#[tokio::test]
async fn choice_objects_are_evicted_and_fetched_again() {
    let shard = |i: u32| Plan {
        start: 100 + 10 * i,
        end: 109 + 10 * i,
        sealed: true,
        segments: vec![paid(other(i), 101 + 10 * i, 1)],
    };
    let mut plans: Vec<_> = (0..3).map(shard).collect();
    plans.push(Plan {
        start: 130,
        end: 130,
        sealed: false,
        segments: vec![vec![]],
    });
    let net = Net::new(publish(&plans, 130));
    let largest = net
        .routes
        .lock()
        .unwrap()
        .choices
        .iter()
        .map(|(_, c)| c.len())
        .max()
        .unwrap();
    let client = net.client().with_choice_budget(largest);
    walk_with(&client, work(100, 100)).await;
    assert_eq!(net.count("choice"), 4);
    walk_with(&client, work(100, 100)).await;
    assert_eq!(net.count("choice"), 8, "evicted objects are fetched again");
}

/// A cached choice object is checked against the directory reading it on every use: a
/// directory naming the same digest with another length or key count fails closed, with no
/// fetch, while the directory it belongs to still reads it from the cache.
#[tokio::test]
async fn a_cached_choice_object_is_checked_against_each_directory() {
    let net = Net::new(publish(&history(3), 110));
    let client = net.client();
    let directory = net.routes.lock().unwrap().directories[0]
        .session()
        .manifest
        .clone();
    client.choice(&directory).await.unwrap();
    for edit in [
        |d: &mut Directory| d.choice.keys += 1,
        |d: &mut Directory| d.choice.bytes += 1,
    ] {
        let mut other = directory.clone();
        edit(&mut other);
        assert!(client.choice(&other).await.is_err());
    }
    client.choice(&directory).await.unwrap();
    assert_eq!(net.count("choice"), 1);
}
