//! Import-time discovery end to end: candidate addresses checked against a
//! transparent shard service running in process, over loopback HTTP and real
//! PIR, with no wallet.
//!
//! The service records every request it receives, so the tests also check what
//! a discovery discloses: only the service's routes, no candidate's script in
//! any path, query, header or body, and no request for a shard wholly below the
//! floor.

// Shared with the recovery tests, which use the re-cut helpers this file does not.
#[allow(dead_code)]
mod fixture;

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use fixture::{GEOMETRY, Recorded, SEAL, Server, ShardSpec, synthetic};
use regex::Regex;
use transparent::address::TransparentAddress;
use transparent_events::{ReceiveEvent, SpendEvent, TransparentEvent, Txid};
use transparent_filter::{
    BlockHash, FilterLimits, ScriptBytes, ShardKey, ShardMap, match_range_scripts, range_profile,
    validate_range_filter,
};
use transparent_wallet::http::{HttpFilterSource, HttpOptions, HttpShardTransport};
use zakura_pir_transparent::{Discovery, DiscoveryLimits, Outcome, discover_active_addresses};

/// The first height the fixture publishes, a mainnet height.
const H0: u64 = 3_428_143;

/// The publication's end: the tail's last block.
const END: u64 = H0 + 700;

/// Vizor's per-discovery limits.
const LIMITS: DiscoveryLimits = DiscoveryLimits {
    scripts: 20,
    shards: 1_024,
    queries: 256,
    private_bytes: 96 << 20,
};

/// Every route the service serves a wallet, with its method: queries are the
/// only uploads.
const ROUTES: &str = r"^(GET /v1/(filters/shards(/[0-9]+/filter)?|shards/init|shards/[0-9]+/revisions/[0-9a-f]{64}/(manifest|setup/(directory|pages)/[0-9]+))|POST /v1/shards/[0-9]+/revisions/[0-9a-f]{64}/query/(directory|pages))$";

/// The shard a request's path names: its filter, manifest, tables or queries.
const SHARD: &str = r"^/v1/(filters/)?shards/([0-9]+)/";

/// Each test runs a PIR service; one at a time keeps memory and CPU bounded.
static HEAVY: Mutex<()> = Mutex::new(());

/// A candidate: the first address of some account.
fn candidate(tag: u8) -> TransparentAddress {
    TransparentAddress::PublicKeyHash([tag; 20])
}

fn script(address: TransparentAddress) -> ScriptBytes {
    let TransparentAddress::PublicKeyHash(hash) = address else {
        panic!("candidates pay to public key hashes");
    };
    ScriptBytes::new([&[0x76, 0xa9, 20][..], &hash, &[0x88, 0xac]].concat())
}

/// A script no candidate derives.
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

fn receive(height: u64, txid: Txid) -> TransparentEvent {
    TransparentEvent::Receive(ReceiveEvent {
        metadata: None,
        height: height as u32,
        txid,
        transaction_index: 1,
        output_index: 0,
        value: 50_000,
        coinbase: false,
    })
}

fn spend(height: u64, spending: Txid, spent: Txid) -> TransparentEvent {
    TransparentEvent::Spend(SpendEvent {
        metadata: None,
        height: height as u32,
        spending_txid: spending,
        transaction_index: 2,
        input_index: 0,
        spent_txid: spent,
        spent_output_index: 0,
    })
}

/// Receives to scripts no candidate derives, spread over `[start, end]`, so
/// that no candidate is alone in a shard.
fn noise(start: u64, end: u64, salt: u32) -> Vec<(ScriptBytes, TransparentEvent)> {
    (0..40u32)
        .map(|n| {
            let tag = salt * 1_000 + n;
            let height = start + u64::from(n * 7) % (end - start + 1);
            (
                unrelated(tag),
                receive(height, txid(u64::from(tag) + 100_000)),
            )
        })
        .collect()
}

fn shard(
    start: u64,
    end: u64,
    sealed: bool,
    mut events: Vec<(ScriptBytes, TransparentEvent)>,
    salt: u32,
) -> ShardSpec {
    events.extend(noise(start, end, salt));
    ShardSpec {
        start,
        end,
        geometry: GEOMETRY,
        sealed,
        revision: 0,
        events,
    }
}

/// The candidates' history, published as two sealed shards and a tail:
///
/// - `paid_sealed` receives in the second sealed shard;
/// - `paid_tail` receives in the tail;
/// - `idle` has no history;
/// - `paid_early` receives only at `H0 + 100`, in the first shard;
/// - `spent_late` receives at `H0 + 50` and spends it at `H0 + 400`.
struct Publication {
    server: Server,
    url: String,
    map: ShardMap,
    _dir: tempfile::TempDir,
}

const PAID_SEALED: u8 = 0x11;
const PAID_TAIL: u8 = 0x12;
const IDLE: u8 = 0x13;
const PAID_EARLY: u8 = 0x14;
const SPENT_LATE: u8 = 0x15;

impl Publication {
    fn start() -> Self {
        let paid = |tag, height, id| (script(candidate(tag)), receive(height, txid(id)));
        let shards = [
            shard(
                H0,
                H0 + 299,
                true,
                vec![paid(PAID_EARLY, H0 + 100, 1), paid(SPENT_LATE, H0 + 50, 2)],
                1,
            ),
            shard(
                H0 + 300,
                H0 + 599,
                true,
                vec![
                    paid(PAID_SEALED, H0 + 350, 3),
                    (
                        script(candidate(SPENT_LATE)),
                        spend(H0 + 400, txid(4), txid(2)),
                    ),
                ],
                2,
            ),
            shard(H0 + 600, END, false, vec![paid(PAID_TAIL, H0 + 650, 5)], 3),
        ];
        let dir = tempfile::tempdir().unwrap();
        let map = fixture::publish(dir.path(), &shards, SEAL, synthetic, vec![]);
        let mut server = Server::start();
        let url = server.serve(dir.path());
        Self {
            server,
            url,
            map,
            _dir: dir,
        }
    }

    fn discover(
        &self,
        tags: &[u8],
        floor: u64,
    ) -> Result<Discovery, zakura_pir_transparent::RecoveryError> {
        let candidates: Vec<_> = tags.iter().copied().map(candidate).collect();
        self.discover_addresses(&candidates, floor)
    }

    fn discover_addresses(
        &self,
        candidates: &[TransparentAddress],
        floor: u64,
    ) -> Result<Discovery, zakura_pir_transparent::RecoveryError> {
        self.discover_within(candidates, floor, &LIMITS)
    }

    fn discover_within(
        &self,
        candidates: &[TransparentAddress],
        floor: u64,
        limits: &DiscoveryLimits,
    ) -> Result<Discovery, zakura_pir_transparent::RecoveryError> {
        let options = HttpOptions {
            timeout: Duration::from_secs(60),
            ..HttpOptions::default()
        };
        let mut filters = HttpFilterSource::new(&self.url, &options).unwrap();
        let mut transport = HttpShardTransport::new(&self.url, &options).unwrap();
        discover_active_addresses(candidates, floor, limits, &mut filters, &mut transport)
    }

    /// The requests the service received since the last call.
    fn take_requests(&self, seen: &mut usize) -> Vec<Recorded> {
        let all = self.server.requests();
        let new = all[*seen..].to_vec();
        *seen = all.len();
        new
    }
}

fn shard_of(path: &str) -> Option<u64> {
    Regex::new(SHARD)
        .unwrap()
        .captures(path)
        .map(|captures| captures[2].parse().unwrap())
}

/// Asserts that every request used one of the service's routes with its
/// method and no query string, carried none of `candidates`' public key hashes,
/// in bytes or hex, in its path, headers or body, and named no shard in
/// `below_floor`.
fn assert_private(requests: &[Recorded], candidates: &[TransparentAddress], below_floor: &[u64]) {
    assert!(!requests.is_empty());
    let routes = Regex::new(ROUTES).unwrap();
    let hashes: Vec<[u8; 20]> = candidates
        .iter()
        .map(|address| match address {
            TransparentAddress::PublicKeyHash(hash) => *hash,
            TransparentAddress::ScriptHash(_) => unreachable!(),
        })
        .collect();
    let hexes: Vec<Vec<u8>> = hashes
        .iter()
        .flat_map(|hash| [hex::encode(hash), hex::encode_upper(hash)])
        .map(String::into_bytes)
        .collect();
    let carries = |bytes: &[u8]| {
        bytes
            .windows(20)
            .any(|window| hashes.iter().any(|hash| window == hash))
            || bytes
                .windows(40)
                .any(|window| hexes.iter().any(|hex| window == hex.as_slice()))
    };
    // Positive control: a candidate's script, in bytes or hex, would be caught.
    assert!(carries(script(candidates[0]).as_slice()));
    assert!(carries(
        format!("/{}", hex::encode_upper(hashes[0])).as_bytes()
    ));
    for request in requests {
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
            shard_of(&request.path).is_none_or(|id| !below_floor.contains(&id)),
            "a below-floor shard: {line}"
        );
    }
}

/// The ids of the shards whose filters `requests` downloaded.
fn filters_fetched(requests: &[Recorded]) -> Vec<u64> {
    let mut ids: Vec<u64> = requests
        .iter()
        .filter(|request| request.path.ends_with("/filter"))
        .filter_map(|request| shard_of(&request.path))
        .collect();
    ids.sort_unstable();
    ids
}

#[test]
fn discovery_reports_exactly_the_candidates_with_history_from_the_floor() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let publication = Publication::start();
    let mut seen = 0;
    let tags = [PAID_SEALED, PAID_TAIL, IDLE, PAID_EARLY, SPENT_LATE];
    let candidates: Vec<_> = tags.iter().copied().map(candidate).collect();

    // From the publication's start: every candidate with history, sealed or in
    // the tail, and none without.
    let discovery = publication.discover(&tags, H0).unwrap();
    assert_eq!(discovery.active, vec![0, 1, 3, 4]);
    assert_eq!(discovery.progress.outcome, Outcome::Complete);
    assert_eq!(discovery.progress.covered_through, END);
    let requests = publication.take_requests(&mut seen);
    assert!(
        requests
            .iter()
            .any(|request| request.method == "POST" && !request.body.is_empty()),
        "matches were confirmed by private queries"
    );
    assert_eq!(filters_fetched(&requests), vec![0, 1, 2]);
    assert_private(&requests, &candidates, &[]);

    // From inside the first shard, above `paid_early`'s only receive: the shard
    // is read, but history below the floor is not reported. `spent_late`'s
    // receive lies below the floor too, and its spend above it is history.
    let discovery = publication.discover(&tags, H0 + 200).unwrap();
    assert_eq!(discovery.active, vec![0, 1, 4]);
    assert_eq!(discovery.progress.outcome, Outcome::Complete);
    let requests = publication.take_requests(&mut seen);
    assert_eq!(filters_fetched(&requests), vec![0, 1, 2]);
    assert_private(&requests, &candidates, &[]);

    // From the second shard: the first is never named, so `spent_late`'s
    // receive is never read and its spend stays unresolved. The reference
    // client reports that only once every candidate is covered through the
    // target, and it is history from the floor on: complete, not stalled.
    let discovery = publication.discover(&tags, H0 + 300).unwrap();
    assert_eq!(discovery.active, vec![0, 1, 4]);
    assert_eq!(discovery.progress.outcome, Outcome::Complete);
    assert_eq!(discovery.progress.covered_through, END);
    let requests = publication.take_requests(&mut seen);
    assert_eq!(filters_fetched(&requests), vec![1, 2]);
    assert_private(&requests, &candidates, &[0]);

    // From the tail: the sealed shards wholly below the floor are never named.
    let discovery = publication.discover(&tags, H0 + 600).unwrap();
    assert_eq!(discovery.active, vec![1]);
    assert_eq!(discovery.progress.outcome, Outcome::Complete);
    let requests = publication.take_requests(&mut seen);
    assert_eq!(filters_fetched(&requests), vec![2]);
    assert_private(&requests, &candidates, &[0, 1]);

    // Above the publication: behind, with only the map fetched.
    let discovery = publication.discover(&tags, END + 1).unwrap();
    assert_eq!(discovery.active, Vec::<usize>::new());
    assert_eq!(discovery.progress.outcome, Outcome::Behind);
    let requests = publication.take_requests(&mut seen);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/filters/shards");
}

/// A candidate whose script the shard's filter matches although it holds no
/// history there: found by searching scripts against the published filter.
fn false_positive(map: &ShardMap, shard_id: u64, filter: &[u8]) -> TransparentAddress {
    let entry = &map.shards[shard_id as usize];
    let profile = range_profile(&map.profile).unwrap();
    let validated = validate_range_filter(filter, FilterLimits::default(), profile).unwrap();
    let key = ShardKey::derive(
        &map.profile,
        BlockHash::from_display_hex(&map.genesis_hash).unwrap(),
        entry.shard_id,
        entry.start_height,
        entry.end_height,
        BlockHash::from_display_hex(&entry.terminal_block_hash).unwrap(),
    );
    let hash = |n: u32| {
        let mut hash = [0xdd; 20];
        hash[..4].copy_from_slice(&n.to_le_bytes());
        hash
    };
    const BATCH: u32 = 200_000;
    for batch in 0..100u32 {
        let first = batch * BATCH;
        let scripts: Vec<ScriptBytes> = (first..first + BATCH)
            .map(|n| script(TransparentAddress::PublicKeyHash(hash(n))))
            .collect();
        if let Some(index) = match_range_scripts(&validated, key, &scripts)
            .unwrap()
            .first()
        {
            return TransparentAddress::PublicKeyHash(hash(first + *index as u32));
        }
    }
    panic!("no false positive within the search bound");
}

#[test]
fn a_filter_match_without_history_is_not_reported() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let publication = Publication::start();
    let tail = &publication.map.shards[2];
    let filter = std::fs::read(
        publication
            ._dir
            .path()
            .join(&tail.manifest_digest)
            .join("filter.bin"),
    )
    .unwrap();
    let matched = false_positive(&publication.map, 2, &filter);
    let candidates = [matched, candidate(IDLE)];
    let mut seen = 0;

    let discovery = publication
        .discover_addresses(&candidates, H0 + 600)
        .unwrap();
    assert_eq!(discovery.active, Vec::<usize>::new());
    assert_eq!(discovery.progress.outcome, Outcome::Complete);
    let requests = publication.take_requests(&mut seen);
    // Positive control: the filter did match, and the match was checked.
    assert!(requests.iter().any(|request| {
        request.method == "POST" && shard_of(&request.path) == Some(tail.shard_id)
    }));
    assert_private(&requests, &candidates, &[0, 1]);
}

#[test]
fn a_pass_stopped_by_its_budget_is_incomplete_and_keeps_what_it_confirmed() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let publication = Publication::start();
    // History in the second sealed shard and in the tail: one private query
    // confirms the first, and the budget stops the pass before the second.
    let candidates = [candidate(PAID_SEALED), candidate(PAID_TAIL)];
    let one_query = DiscoveryLimits {
        queries: 1,
        ..LIMITS
    };

    let discovery = publication
        .discover_within(&candidates, H0, &one_query)
        .unwrap();

    assert_eq!(discovery.progress.outcome, Outcome::More);
    assert!(discovery.progress.covered_through < END);
    // What it confirmed is real; the rest is unknown, which only the outcome says.
    assert_eq!(discovery.active, vec![0]);
}
