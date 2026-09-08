//! A real recovery against a deployed transparent PIR service.
//!
//! Ignored by default: these need the network, a published shard set, and a
//! service reachable from wherever they run. Run them with
//!
//! ```text
//! ZAKURA_TRANSPARENT_FILTERS=https://transparent-pir.valargroup.dev \
//! ZAKURA_TRANSPARENT_SHARDS=https://transparent-pir.valargroup.dev \
//!   cargo test -p zakura-wallet-transparent --test live -- --ignored --nocapture
//! ```
//!
//! Both variables are required and neither is defaulted. A default would be a
//! host this wallet talks to because nobody chose otherwise, and the two are
//! meant to be chosen separately — see [`Endpoints`].
//!
//! What these establish, in order, is what a wallet has to be able to do before
//! any of it is worth anything: the map parses and is internally consistent;
//! the service's geometry is the one this build reads; and a real account, with
//! real derived scripts, recovers to a balance and a coverage height without
//! anything crossing the wire that names it.

use serde::Deserialize;
use transparent_wallet::client::{Table, TableClient};
use transparent_wallet::transport::{ByteCharges, FilterSource, ShardTransport};
use zakura_wallet_store::{WalletDb, testing::test_db};
use zakura_wallet_sync::TransparentSource;
use zakura_wallet_transparent::{Endpoints, TransparentPir, http::HttpFilters};
use zcash_protocol::consensus::{BlockHeight, Network};

fn endpoints() -> Endpoints {
    let filters = std::env::var("ZAKURA_TRANSPARENT_FILTERS")
        .expect("set ZAKURA_TRANSPARENT_FILTERS to the filter service");
    let shards = std::env::var("ZAKURA_TRANSPARENT_SHARDS")
        .expect("set ZAKURA_TRANSPARENT_SHARDS to the shard service");
    Endpoints::new(filters, shards)
}

/// A wallet with one account, born at the first covered height.
fn wallet() -> (WalletDb, zakura_wallet_core::AccountId) {
    let mut db = test_db().unwrap();
    let id = db
        .create_account(
            &Network::MainNetwork,
            &[11u8; 32],
            zip32::AccountId::try_from(0).unwrap(),
            BlockHeight::from_u32(zakura_wallet_transparent::START_HEIGHT as u32),
        )
        .unwrap();
    (db, id)
}

#[test]
#[ignore = "requires a deployed transparent PIR service"]
fn the_published_shard_map_is_internally_consistent() {
    let mut filters = HttpFilters::new(&endpoints().filters_url).unwrap();
    let (bytes, cost) = filters.shard_map().expect("the filter service serves a map");
    let map: transparent_filter::ShardMap =
        serde_json::from_slice(&bytes).expect("the map parses");

    println!(
        "map: {} bytes, {} shards, {}..={}, profile {}",
        cost,
        map.shards.len(),
        map.start_height,
        map.shards.last().map(|s| s.end_height).unwrap_or(0),
        map.profile,
    );

    // Gaplessness and the hash chain. A wallet that skipped this could sync a
    // map with a hole in it and call the result complete coverage.
    map.check_shape().expect("the published map is well formed");
    assert_eq!(
        map.start_height,
        zakura_wallet_transparent::START_HEIGHT,
        "coverage begins at Ironwood activation"
    );
}

#[test]
#[ignore = "requires a deployed transparent PIR service"]
fn every_published_filter_matches_the_digest_the_map_commits_to() {
    // The map is public and shared, so this is what stops a service handing
    // different filter bytes to different wallets.
    let mut filters = HttpFilters::new(&endpoints().filters_url).unwrap();
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
    println!("{} filters, {total} bytes: the floor every wallet pays", map.shards.len());
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
    let mut filters = HttpFilters::new(&endpoints().filters_url).unwrap();
    let (bytes, _) = filters.shard_map().unwrap();
    let map: transparent_filter::ShardMap = serde_json::from_slice(&bytes).unwrap();
    for entry in &map.shards {
        accept(&db, entry.start_height - 1, &entry.parent_block_hash);
        accept(&db, entry.end_height, &entry.terminal_block_hash);
    }

    let pir = TransparentPir::new(endpoints(), Network::MainNetwork);
    let began = std::time::Instant::now();
    let progress = pir.recover(&mut db).expect("a recovery completes");

    println!(
        "recovered in {:?}: {} outputs, {} spends, {} unresolved, covered through {:?}",
        began.elapsed(),
        progress.outputs,
        progress.spends,
        progress.unresolved,
        progress.covered_through,
    );

    let last = map.shards.last().expect("the map has shards").end_height;
    assert_eq!(
        progress.covered_through,
        Some(BlockHeight::from_u32(last as u32)),
        "coverage reaches the end of the published map"
    );
    assert_eq!(
        progress.unresolved, 0,
        "a wallet with no history has nothing to fail to resolve"
    );

    let state = db
        .transparent_state(id, BlockHeight::from_u32(zakura_wallet_transparent::START_HEIGHT as u32))
        .unwrap();
    println!(
        "settled through {:?}, {} provisional shards",
        state.settled_through, state.provisional_shards
    );
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
#[derive(Deserialize)]
struct Setup {
    segments: u32,
    public_params: String,
    public_params_sha256: String,
}

/// What the shard service declares about itself.
#[derive(Deserialize)]
struct Init {
    schema: String,
    directory_scheme: ipir_sp::YpirSchemeParams,
    directory_setup_seed: u64,
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
    // its index. Which row is arbitrary; that it decodes to the pinned width,
    // against parameters re-derived here rather than adopted from the service,
    // is the whole assertion.
    let endpoints = endpoints();
    let mut shards = zakura_wallet_transparent::http::HttpShards::new(&endpoints.shards_url).unwrap();

    let (init_bytes, _) = shards.init().expect("the shard service serves init");
    let init: Init = serde_json::from_slice(&init_bytes).expect("init parses");
    assert_eq!(
        init.schema,
        zakura_wallet_transparent::SCHEMA,
        "the service serves a schema this build does not read"
    );

    let mut client = TableClient::new(
        Table::Directory,
        transparent_shard::DIRECTORY_ROWS as u64,
        transparent_shard::DIRECTORY_ROW_BYTES as u32,
        init.directory_setup_seed,
        &init.directory_scheme,
    )
    .expect("the served geometry is the pinned one");

    let (setup_bytes, setup_cost) = shards
        .setup(0, Table::Directory, 0)
        .expect("shard 0 publishes a directory setup");
    let setup: Setup = serde_json::from_slice(&setup_bytes).expect("setup parses");
    client
        .open_segment(0, 0, &setup.public_params, &setup.public_params_sha256)
        .expect("the published parameters match their digest");

    let mut charges = ByteCharges::default();
    let began = std::time::Instant::now();
    let rows = client
        .fetch_row(&mut shards, 0, setup.segments, 7, &mut charges)
        .expect("a private query is answered");
    let elapsed = began.elapsed();

    assert_eq!(rows.len(), setup.segments as usize, "one row per segment");
    for row in &rows {
        assert_eq!(
            row.len(),
            transparent_shard::DIRECTORY_ROW_BYTES,
            "a decoded row is exactly the pinned width"
        );
    }

    println!(
        "one directory row in {elapsed:?}: setup {setup_cost} B, up {} B, down {} B",
        charges.query_upload(),
        charges.query_download(),
    );
}
