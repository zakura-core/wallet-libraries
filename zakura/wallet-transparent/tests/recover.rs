//! Everything on this side of the protocol: which shards a wallet will read,
//! which scripts it asks about, and what a run leaves in the database.
//!
//! The private retrieval itself is upstream's, and upstream tests it end to end
//! against a real server with real PIR. What is only testable here is the part
//! that needs a wallet — and it is the part where being wrong is invisible, so
//! the cases below are the ones a plausible implementation gets wrong quietly:
//! a shard placed on a chain this wallet is not on, a script that inherits
//! coverage it never earned, and coverage advancing over a range nothing read.
//!
//! The filters here deliberately match nothing, which is what lets these run
//! without a PIR service: a shard with no match costs no private query, and the
//! transport asserts that by refusing to answer one.

use transparent_filter::{
    BlockHash, ScriptBytes, SealParameters, ShardKey, ShardMap, ShardMapEntry, build_range_filter,
    filter_hash,
};
use transparent_wallet::client::Table;
use transparent_wallet::transport::{BoxError, FilterSource, ShardTransport};
use zakura_wallet_store::{WalletDb, testing::test_db};
use zakura_wallet_transparent::{Endpoints, TransparentPir};
use zcash_protocol::consensus::{BlockHeight, Network};

const START: u64 = zakura_wallet_transparent::START_HEIGHT;
const SPAN: u64 = 100;
const SHARDS: u64 = 3;

fn params() -> Network {
    Network::MainNetwork
}

/// A deterministic, distinct block hash for a height.
fn hash_at(height: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&height.to_le_bytes());
    BlockHash::from_internal_bytes(bytes)
}

fn shard_bounds(id: u64) -> (u64, u64) {
    (START + id * SPAN, START + (id + 1) * SPAN - 1)
}

/// A published map of [`SHARDS`] shards, each carrying one decoy script.
///
/// The decoys are not the wallet's, so every filter is a true negative and the
/// run needs no private query to be correct.
fn published() -> (ShardMap, Vec<Vec<u8>>) {
    let genesis = BlockHash::from_display_hex(transparent_filter::MAINNET_GENESIS_DISPLAY).unwrap();
    let mut shards = Vec::new();
    let mut filters = Vec::new();

    for id in 0..SHARDS {
        let (start, end) = shard_bounds(id);
        let terminal = hash_at(end);
        let key = ShardKey::derive(
            transparent_filter::RANGE_PROFILE,
            genesis,
            id,
            start,
            end,
            terminal,
        );
        let decoy = ScriptBytes::new(vec![0x76, 0xa9, 0x14, id as u8, 0x88, 0xac]);
        let bytes = build_range_filter(key, &[decoy]).unwrap();

        shards.push(ShardMapEntry {
            shard_id: id,
            start_height: start,
            end_height: end,
            parent_block_hash: hash_at(start - 1).to_display_hex(),
            terminal_block_hash: terminal.to_display_hex(),
            filter_hash: filter_hash(bytes.as_slice()).to_display_hex(),
            scripts: 1,
            page_rows: 0,
            txids: 0,
            directory_segments: 1,
            page_segments: 1,
            manifest_digest: format!("{id:064x}"),
            revision: 0,
            sealed: true,
        });
        filters.push(bytes.as_slice().to_vec());
    }

    (
        ShardMap {
            genesis_hash: transparent_filter::MAINNET_GENESIS_DISPLAY.to_owned(),
            network: transparent_filter::NETWORK.to_owned(),
            profile: transparent_filter::RANGE_PROFILE.to_owned(),
            range_envelope_version: transparent_filter::RANGE_ENVELOPE_VERSION,
            start_height: START,
            seal: SealParameters {
                max_scripts: 1,
                max_page_rows: 1,
                max_txids: 1,
            },
            shards,
        },
        filters,
    )
}

struct Filters {
    map: Vec<u8>,
    filters: Vec<Vec<u8>>,
}

impl FilterSource for Filters {
    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        Ok((self.map.clone(), self.map.len() as u64))
    }

    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        let bytes = self
            .filters
            .get(shard_id as usize)
            .ok_or("no such shard")?
            .clone();
        let len = bytes.len() as u64;
        Ok((bytes, len))
    }
}

/// A shard service that will answer its init document and nothing else.
///
/// Refusing the rest is the assertion: a wallet whose filters matched nothing
/// must spend no private query, and a wallet that asked anyway would be
/// telling the service which ranges it cares about for no reason at all.
struct NoQueries {
    init: Vec<u8>,
}

impl ShardTransport for NoQueries {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        Ok((self.init.clone(), self.init.len() as u64))
    }

    fn setup(&mut self, _: u64, _: Table, _: u32) -> Result<(Vec<u8>, u64), BoxError> {
        panic!("a shard nothing matched must not be opened");
    }

    fn query(&mut self, _: u64, _: Table, _: &[u8]) -> Result<Vec<u8>, BoxError> {
        panic!("a shard nothing matched must not be queried");
    }
}

/// The init document a correctly configured service would publish.
fn init_doc(map: &ShardMap) -> Vec<u8> {
    let scheme = |rows: u64, row_bytes: u64| {
        ipir_sp::params_for_simplepir(rows, row_bytes * 8)
            .expect("the pinned geometry has parameters")
            .1
    };
    serde_json::to_vec(&serde_json::json!({
        "schema": zakura_wallet_transparent::SCHEMA,
        "profile": map.profile,
        "network": map.network,
        "genesis_hash": map.genesis_hash,
        "directory_scheme": scheme(
            transparent_shard::DIRECTORY_ROWS as u64,
            transparent_shard::DIRECTORY_ROW_BYTES as u64,
        ),
        "directory_setup_seed": 1u64,
        "pages_scheme": scheme(
            transparent_shard::PAGE_ROWS as u64,
            transparent_shard::PAGE_ROW_BYTES as u64,
        ),
        "pages_setup_seed": 2u64,
    }))
    .unwrap()
}

/// A wallet with one account, born at the first covered height.
fn wallet() -> (WalletDb, zakura_wallet_core::AccountId) {
    let mut db = test_db().unwrap();
    let id = db
        .create_account(
            &params(),
            &[7u8; 32],
            zip32::AccountId::try_from(0).unwrap(),
            BlockHeight::from_u32(START as u32),
        )
        .unwrap();
    (db, id)
}

/// Records the wallet as having accepted `hash` at `height`.
fn accept(db: &WalletDb, height: u64, hash: BlockHash) {
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

/// Accepts every boundary of the first `count` shards.
fn accept_through(db: &WalletDb, count: u64) {
    accept(db, START - 1, hash_at(START - 1));
    for id in 0..count {
        let (start, end) = shard_bounds(id);
        accept(db, start - 1, hash_at(start - 1));
        accept(db, end, hash_at(end));
    }
}

fn pir() -> TransparentPir<Network> {
    TransparentPir::new(
        Endpoints::new("https://filters.invalid", "https://shards.invalid"),
        params(),
    )
}

#[test]
fn a_run_over_shards_that_match_nothing_still_advances_coverage() {
    // The case the whole design is meant to make cheap, so it must not
    // accidentally cost a query — or, worse, fail and leave the wallet
    // re-reading the same range forever.
    let (mut db, id) = wallet();
    let (map, filters) = published();
    accept_through(&db, SHARDS);

    let mut source = Filters {
        map: serde_json::to_vec(&map).unwrap(),
        filters,
    };
    let mut transport = NoQueries {
        init: init_doc(&map),
    };

    let progress = pir()
        .recover_with(&mut db, &mut source, &mut transport)
        .expect("a run with no matches succeeds");

    assert_eq!(progress.outputs, 0);
    assert_eq!(progress.spends, 0);
    assert_eq!(progress.unresolved, 0);

    let (_, last) = shard_bounds(SHARDS - 1);
    assert_eq!(
        progress.covered_through,
        Some(BlockHeight::from_u32(last as u32)),
        "every watched script has been read to the end of the map"
    );
    assert_eq!(
        progress.settled_through, progress.covered_through,
        "a map of sealed shards leaves no provisional coverage"
    );

    let state = db
        .transparent_state(id, BlockHeight::from_u32(START as u32))
        .unwrap();
    assert_eq!(state.provisional_shards, 0);
    assert_eq!(state.unresolved_spends, 0);
}

#[test]
fn coverage_stops_where_the_wallet_stopped_scanning() {
    // A shard whose boundaries the wallet has not accepted cannot be checked
    // against anything, and a map is gapless, so it also makes every later
    // shard unreachable. Reading past it would mean believing a service about
    // where its own data sits.
    let (mut db, id) = wallet();
    let (map, filters) = published();
    accept_through(&db, 1);

    let mut source = Filters {
        map: serde_json::to_vec(&map).unwrap(),
        filters,
    };
    let mut transport = NoQueries {
        init: init_doc(&map),
    };

    let progress = pir()
        .recover_with(&mut db, &mut source, &mut transport)
        .expect("a truncated map is not an error");

    let (_, first_end) = shard_bounds(0);
    assert_eq!(
        progress.covered_through,
        Some(BlockHeight::from_u32(first_end as u32)),
        "coverage stops at the last shard the wallet could confirm"
    );
    let _ = id;
}

#[test]
fn a_wallet_that_has_scanned_nothing_reads_nothing_and_does_not_fail() {
    let (mut db, id) = wallet();
    let (map, filters) = published();

    let mut source = Filters {
        map: serde_json::to_vec(&map).unwrap(),
        filters,
    };
    let mut transport = NoQueries {
        init: init_doc(&map),
    };

    let progress = pir()
        .recover_with(&mut db, &mut source, &mut transport)
        .expect("nothing to check against is not a failure");
    assert_eq!(progress.covered_through, None);

    let state = db
        .transparent_state(id, BlockHeight::from_u32(START as u32))
        .unwrap();
    assert_eq!(
        state.covered_through,
        Some(BlockHeight::from_u32(START as u32 - 1)),
        "reported as uncovered, never as an empty balance"
    );
}

#[test]
fn a_map_on_a_different_chain_is_refused_rather_than_truncated() {
    // The wallet has scanned this height and accepted a different block there.
    // That is not a shard it cannot check; it is a shard it has checked and
    // rejected, and every later shard in the map chains to it.
    let (mut db, _) = wallet();
    let (map, filters) = published();
    accept_through(&db, SHARDS);
    let (_, end) = shard_bounds(0);
    accept(&db, end, BlockHash::from_internal_bytes([0xab; 32]));

    let mut source = Filters {
        map: serde_json::to_vec(&map).unwrap(),
        filters,
    };
    let mut transport = NoQueries {
        init: init_doc(&map),
    };

    let err = pir()
        .recover_with(&mut db, &mut source, &mut transport)
        .expect_err("a map on another chain must be refused");
    assert!(
        format!("{err}").contains("not on"),
        "the error should say the map is for another chain, got: {err}"
    );
}

#[test]
fn a_service_serving_another_schema_is_refused_before_anything_is_decoded() {
    let (mut db, _) = wallet();
    let (map, filters) = published();
    accept_through(&db, SHARDS);

    let mut init: serde_json::Value = serde_json::from_slice(&init_doc(&map)).unwrap();
    init["schema"] = serde_json::json!("transparent-shard-v99");

    let mut source = Filters {
        map: serde_json::to_vec(&map).unwrap(),
        filters,
    };
    let mut transport = NoQueries {
        init: serde_json::to_vec(&init).unwrap(),
    };

    let err = pir()
        .recover_with(&mut db, &mut source, &mut transport)
        .expect_err("a schema this build does not read must be refused");
    assert!(format!("{err}").contains("transparent-shard-v99"), "got: {err}");
}

#[test]
fn a_filter_that_does_not_match_its_published_digest_is_refused() {
    let (mut db, _) = wallet();
    let (map, mut filters) = published();
    accept_through(&db, SHARDS);
    filters[1] = filters[0].clone();

    let mut source = Filters {
        map: serde_json::to_vec(&map).unwrap(),
        filters,
    };
    let mut transport = NoQueries {
        init: init_doc(&map),
    };

    let err = pir()
        .recover_with(&mut db, &mut source, &mut transport)
        .expect_err("bytes that are not what the map committed to must be refused");
    assert!(format!("{err}").contains("digest"), "got: {err}");
}

/// A transport that records the shards a run opened, and refuses to serve them.
///
/// Refusing is the point of the second assertion: a run that fails part way
/// through must leave coverage exactly where it was, because the alternative
/// records a range as read when it was not, and nothing later re-reads it.
struct RecordingShards {
    init: Vec<u8>,
    opened: std::cell::RefCell<Vec<u64>>,
}

impl ShardTransport for RecordingShards {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        Ok((self.init.clone(), self.init.len() as u64))
    }

    fn setup(&mut self, shard_id: u64, _: Table, _: u32) -> Result<(Vec<u8>, u64), BoxError> {
        self.opened.borrow_mut().push(shard_id);
        Err("the shard service is unreachable".into())
    }

    fn query(&mut self, _: u64, _: Table, _: &[u8]) -> Result<Vec<u8>, BoxError> {
        panic!("a shard that could not be opened must not be queried");
    }
}

#[test]
fn a_matching_script_opens_exactly_the_shard_it_matched_and_no_other() {
    // The leak this design accepts, stated as a test: the service learns which
    // ranges had probable activity, and it must learn no more than that. A
    // wallet that opened every shard would pay for nothing; one that opened a
    // shard it did not match would be disclosing a range for no reason.
    let (mut db, id) = wallet();
    accept_through(&db, SHARDS);

    // The wallet's own first script, placed in the middle shard's filter.
    let mine = db.transparent_watch().unwrap().addresses[0].script.clone();
    let genesis = BlockHash::from_display_hex(transparent_filter::MAINNET_GENESIS_DISPLAY).unwrap();
    let (mut map, mut filters) = published();

    let matched = 1u64;
    let (start, end) = shard_bounds(matched);
    let key = ShardKey::derive(
        transparent_filter::RANGE_PROFILE,
        genesis,
        matched,
        start,
        end,
        hash_at(end),
    );
    let bytes = build_range_filter(key, &[ScriptBytes::new(mine)]).unwrap();
    map.shards[matched as usize].filter_hash = filter_hash(bytes.as_slice()).to_display_hex();
    filters[matched as usize] = bytes.as_slice().to_vec();

    let mut source = Filters {
        map: serde_json::to_vec(&map).unwrap(),
        filters,
    };
    let mut transport = RecordingShards {
        init: init_doc(&map),
        opened: std::cell::RefCell::new(Vec::new()),
    };

    let err = pir()
        .recover_with(&mut db, &mut source, &mut transport)
        .expect_err("an unreachable shard service fails the run");
    assert!(format!("{err}").contains("unreachable"), "got: {err}");

    assert_eq!(
        transport.opened.borrow().as_slice(),
        &[matched],
        "only the shard whose filter matched is opened"
    );

    let state = db
        .transparent_state(id, BlockHeight::from_u32(START as u32))
        .unwrap();
    assert_eq!(
        state.covered_through,
        Some(BlockHeight::from_u32(START as u32 - 1)),
        "a run that failed part way through advances no coverage at all"
    );
}
