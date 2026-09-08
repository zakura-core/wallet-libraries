//! A real recovery against the deployed transparent PIR services.
//!
//! Ignored by default: these need the network, a published shard set, and both
//! services reachable from wherever they run. Run them with
//!
//! ```text
//! ZAKURA_TRANSPARENT_FILTERS=https://enhance-pir.valargroup.dev \
//! ZAKURA_TRANSPARENT_SHARDS=https://transparent-pir.valargroup.dev \
//!   cargo test -p zakura-wallet-transparent --test live -- --ignored --nocapture
//! ```
//!
//! Both variables are required and neither is defaulted. A default would be a
//! host this wallet talks to because nobody chose otherwise, and the two are
//! meant to be chosen separately — see [`Endpoints`]. They are two hosts in the
//! deployment, and the test says so if they are not.
//!
//! What these establish, in order, is what a wallet has to be able to do before
//! any of it is worth anything: the map parses and is internally consistent;
//! the service's geometry is the one this build reads; and a real account, with
//! real derived scripts, recovers to a balance and a coverage height without
//! anything crossing the wire that names it.

use transparent_wallet::client::{Table, TableClient};
use transparent_wallet::http::{HttpFilterSource, HttpOptions, HttpShardTransport};
use transparent_wallet::transport::{ByteCharges, FilterSource, ShardTransport};
use zakura_wallet_store::{WalletDb, testing::test_db};
use zakura_wallet_sync::{TransparentCompletion, TransparentSource};
use zakura_wallet_transparent::{Endpoints, TransparentPir, WorkLimits};
use zcash_protocol::consensus::{BlockHeight, Network};

fn endpoints() -> Endpoints {
    let filters = std::env::var("ZAKURA_TRANSPARENT_FILTERS")
        .expect("set ZAKURA_TRANSPARENT_FILTERS to the filter service");
    let shards = std::env::var("ZAKURA_TRANSPARENT_SHARDS")
        .expect("set ZAKURA_TRANSPARENT_SHARDS to the shard service");
    let endpoints = Endpoints::new(filters, shards);
    if endpoints.shares_a_host() {
        println!("note: both halves are being read from one host; the deployment uses two");
    }
    endpoints
}

/// A realistic birthday for a wallet of this generation: Ironwood activation.
/// The published set may begin far below it; a wallet reads from its birthday.
const BIRTHDAY: u64 = 3_428_143;

fn options() -> HttpOptions {
    HttpOptions {
        timeout: std::time::Duration::from_secs(120),
        ..HttpOptions::default()
    }
}

/// A wallet with one account, born at the first covered height.
fn wallet() -> (WalletDb, zakura_wallet_core::AccountId) {
    let mut db = test_db().unwrap();
    let id = db
        .create_account(
            &Network::MainNetwork,
            &[11u8; 32],
            zip32::AccountId::try_from(0).unwrap(),
            BlockHeight::from_u32(BIRTHDAY as u32),
        )
        .unwrap();
    (db, id)
}

#[test]
#[ignore = "requires a deployed transparent PIR service"]
fn the_published_shard_map_is_internally_consistent() {
    let mut filters = HttpFilterSource::new(&endpoints().filters_url, &options()).unwrap();
    let (bytes, cost) = filters
        .shard_map()
        .expect("the filter service serves a map");
    let map: transparent_filter::ShardMap = serde_json::from_slice(&bytes).expect("the map parses");

    println!(
        "map: {} bytes, {} shards, {}..={}, profile {}, geometries {:?}",
        cost,
        map.shards.len(),
        map.start_height,
        map.shards.last().map(|s| s.end_height).unwrap_or(0),
        map.profile,
        map.seal.keys().collect::<Vec<_>>(),
    );

    // Gaplessness and the hash chain. A wallet that skipped this could sync a
    // map with a hole in it and call the result complete coverage.
    map.check_shape().expect("the published map is well formed");
    assert!(
        map.start_height <= BIRTHDAY,
        "the set begins at {} and this wallet's birthday is {BIRTHDAY}",
        map.start_height
    );
}

#[test]
#[ignore = "requires a deployed transparent PIR service"]
fn every_published_filter_matches_the_digest_the_map_commits_to() {
    // The map is public and shared, so this is what stops a service handing
    // different filter bytes to different wallets.
    let mut filters = HttpFilterSource::new(&endpoints().filters_url, &options()).unwrap();
    let (bytes, _) = filters.shard_map().unwrap();
    let map: transparent_filter::ShardMap = serde_json::from_slice(&bytes).unwrap();

    let mut total = 0u64;
    for entry in &map.shards {
        let (bytes, cost) = filters
            .filter(entry.shard_id)
            .unwrap_or_else(|e| panic!("shard {} has no filter: {e}", entry.shard_id));
        total += cost;
        assert_eq!(
            transparent_filter::filter_hash(&bytes).to_display_hex(),
            entry.filter_hash,
            "shard {} served bytes the map does not commit to",
            entry.shard_id
        );
    }
    println!(
        "{} filters, {total} bytes: the floor every wallet pays",
        map.shards.len()
    );
}

#[test]
#[ignore = "requires a deployed transparent PIR service"]
fn the_service_serves_the_schema_this_build_reads_and_verifiable_manifests() {
    let mut shards = HttpShardTransport::new(&endpoints().shards_url, &options()).unwrap();
    let geometry = shards.geometry().expect("init parses");
    assert_eq!(geometry.schema, zakura_wallet_transparent::SCHEMA);
    println!(
        "schema {}, geometries {:?}",
        geometry.schema,
        geometry
            .geometries
            .iter()
            .map(|g| g.name.as_str())
            .collect::<Vec<_>>()
    );

    let mut filters = HttpFilterSource::new(&endpoints().filters_url, &options()).unwrap();
    let (bytes, _) = filters.shard_map().unwrap();
    let map: transparent_filter::ShardMap = serde_json::from_slice(&bytes).unwrap();
    for entry in &map.shards {
        let (raw, cost) = shards
            .manifest(entry.shard_id, &entry.manifest_digest)
            .unwrap_or_else(|e| panic!("shard {} has no manifest: {e}", entry.shard_id));
        let manifest: transparent_shard::manifest::ShardManifest =
            serde_json::from_slice(&raw).expect("the manifest parses");
        assert_eq!(
            manifest.digest(),
            entry.manifest_digest,
            "shard {} served a manifest that is not the one the map names",
            entry.shard_id
        );
        println!(
            "shard {}: manifest {} bytes, geometry {}, sealed {}, revision {}",
            entry.shard_id, cost, manifest.geometry, manifest.sealed, manifest.revision
        );
    }
}

#[test]
#[ignore = "requires a deployed transparent PIR service"]
fn a_fresh_wallet_recovers_from_its_birthday() {
    // The whole path, against the real thing: map, filters, local matching,
    // private retrieval of whatever matched, and a committed ledger.
    //
    // A fresh seed is expected to match nothing, so this ordinarily costs no
    // private query. That is the case the design exists to make cheap, and it
    // is still the case that has to work: coverage must advance, and it must
    // advance to the end of what the wallet could verify.
    let (mut db, id) = wallet();

    // The map's own shards are what the wallet checks against its accepted
    // chain, and a fresh test wallet has scanned nothing. Accept the published
    // boundaries so the run has something to work with; a real wallet reaches
    // this state by scanning, which is why the engine runs this step after
    // scanning rather than before.
    let mut filters = HttpFilterSource::new(&endpoints().filters_url, &options()).unwrap();
    let (bytes, _) = filters.shard_map().unwrap();
    let map: transparent_filter::ShardMap = serde_json::from_slice(&bytes).unwrap();
    // Only what a real wallet would have: nothing below its birthday.
    for entry in &map.shards {
        if entry.start_height >= BIRTHDAY {
            accept(&db, entry.start_height - 1, &entry.parent_block_hash);
        }
        if entry.end_height >= BIRTHDAY {
            accept(&db, entry.end_height, &entry.terminal_block_hash);
        }
    }

    let pir =
        TransparentPir::new(endpoints(), Network::MainNetwork).with_limits(WorkLimits::UNLIMITED);
    let began = std::time::Instant::now();
    let progress = pir.recover(&mut db).expect("a recovery completes");

    println!(
        "recovered in {:?}: {} outputs, {} spends, {} unresolved, {} pending, covered through {:?}, {}",
        began.elapsed(),
        progress.outputs,
        progress.spends,
        progress.unresolved,
        progress.pending,
        progress.covered_through,
        progress.completion,
    );

    let last = map.shards.last().expect("the map has shards").end_height;
    assert_eq!(progress.completion, TransparentCompletion::Complete);
    assert_eq!(
        progress.covered_through,
        Some(BlockHeight::from_u32(last as u32)),
        "coverage reaches the end of the published map"
    );
    assert_eq!(
        progress.unresolved, 0,
        "a wallet with no history has nothing to fail to resolve"
    );
    assert_eq!(progress.pending, 0);

    let state = db
        .transparent_state(id, BlockHeight::from_u32(BIRTHDAY as u32))
        .unwrap();
    println!(
        "settled through {:?}, {} provisional shards, anchor {:?}, last sync {:?}",
        state.settled_through, state.provisional_shards, state.anchor, state.completion
    );
    assert_eq!(state.anchor.map(|a| u32::from(a.height)), Some(last as u32));

    // Again: everything is held, and the filters are cached, so the second run
    // pays for the map and nothing else.
    let began = std::time::Instant::now();
    let again = pir.recover(&mut db).expect("a second recovery completes");
    println!("second run in {:?}: {}", began.elapsed(), again.completion);
    assert_eq!(again.completion, TransparentCompletion::Complete);
}

/// Records the wallet as having accepted the block the map names at `height`.
fn accept(db: &WalletDb, height: u64, display_hash: &str) {
    let hash = transparent_filter::BlockHash::from_display_hex(display_hash).unwrap();
    db.connection()
        .execute(
            "INSERT OR REPLACE INTO cache.blocks
                (height, hash, time, orchard_tree_size, ironwood_tree_size,
                 orchard_action_count, ironwood_action_count)
             VALUES (?1, ?2, 0, 0, 0, 0, 0)",
            rusqlite::params![height as u32, &hash.internal_bytes()[..]],
        )
        .unwrap();
}

/// One segment's published setup, as the shard service returns it.
#[derive(serde::Deserialize)]
struct Setup {
    segments: u32,
    public_params: String,
    public_params_sha256: String,
}

#[test]
#[ignore = "requires a deployed transparent PIR service"]
fn a_real_private_query_returns_a_row_this_build_can_decode() {
    // The half a fresh wallet never reaches. A new seed matches no filter, so
    // the recovery above spends no private query and proves nothing about the
    // private path — which is most of the protocol, and the part that would
    // fail silently if the served geometry and this build's had drifted apart.
    //
    // So: open a shard's directory segment for real and retrieve one row by
    // its index. Which row is arbitrary; that it decodes to the width the
    // verified manifest states, against parameters re-derived here rather
    // than adopted from the service, is the whole assertion.
    let endpoints = endpoints();
    let mut shards = HttpShardTransport::new(&endpoints.shards_url, &options()).unwrap();
    let geometry = shards.geometry().expect("init parses");
    assert_eq!(geometry.schema, zakura_wallet_transparent::SCHEMA);

    let mut filters = HttpFilterSource::new(&endpoints.filters_url, &options()).unwrap();
    let (bytes, _) = filters.shard_map().unwrap();
    let map: transparent_filter::ShardMap = serde_json::from_slice(&bytes).unwrap();
    // `ZAKURA_LIVE_SHARD` picks the shard; the first one by default, which in
    // the two-tier set is the archive tier.
    let picked: usize = std::env::var("ZAKURA_LIVE_SHARD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let entry = &map.shards[picked];
    println!(
        "probing shard {} ({}, {} directory segments)",
        entry.shard_id, entry.geometry, entry.directory_segments
    );
    let params = geometry
        .geometries
        .iter()
        .find(|g| g.name == entry.geometry)
        .expect("the service declares the geometry shard 0 was built with");

    let mut client = TableClient::new(
        Table::Directory,
        params.directory_rows,
        params.directory_row_bytes,
        params.directory_setup_seed,
        &params.directory_scheme,
    )
    .expect("the served geometry reproduces");

    let (setup_bytes, setup_cost) = shards
        .setup(entry.shard_id, &entry.manifest_digest, Table::Directory, 0)
        .expect("shard 0 publishes a directory setup");
    let setup: Setup = serde_json::from_slice(&setup_bytes).expect("setup parses");
    client
        .open_segment(
            &entry.manifest_digest,
            0,
            &setup.public_params,
            &setup.public_params_sha256,
        )
        .expect("the published parameters match their digest");

    // Step by step rather than `fetch_row`, so a wrong-sized answer is
    // reported with its size and its first bytes rather than as a bare
    // mismatch: the difference between a worker that changed its wire format
    // and an edge that answered with something else entirely.
    let query = client
        .prepare(&entry.manifest_digest, 7)
        .expect("a query prepares");
    let upload = query.body.len() as u64;
    let began = std::time::Instant::now();
    let response = shards
        .query(
            entry.shard_id,
            &entry.manifest_digest,
            Table::Directory,
            &query.body,
        )
        .expect("a private query is answered");
    let elapsed = began.elapsed();
    let mut charges = ByteCharges::default();
    charges.add_query(Table::Directory, upload, response.len() as u64);
    let rows = match client.decode(
        &entry.manifest_digest,
        setup.segments as u32,
        query,
        &response,
    ) {
        Ok(rows) => rows,
        Err(error) => panic!(
            "the answer could not be decoded ({error}): {} bytes for {} segments, starts {:?}",
            response.len(),
            setup.segments,
            String::from_utf8_lossy(&response[..response.len().min(120)]),
        ),
    };

    assert_eq!(rows.len(), setup.segments as usize, "one row per segment");
    for row in &rows {
        assert_eq!(
            row.len(),
            params.directory_row_bytes as usize,
            "a decoded row is exactly the declared width"
        );
    }

    println!(
        "one directory row in {elapsed:?}: setup {setup_cost} B, up {} B, down {} B",
        charges.query_upload(),
        charges.query_download(),
    );
}
