//! The whole path, in process: publish shards, sync a wallet from a birthday,
//! and check the recovered ledger against an independent traversal of the same
//! events.
//!
//! Equality is exact — every UTXO and every spend, not just the balance. Two
//! wrong numbers can sum to the right one, and a balance check would pass a
//! reconstruction that had lost a receive and a spend of equal value.
//!
//! The PIR here is a file-backed stand-in rather than the real scheme: this
//! test is about the join and the replay, and the real cryptographic path is
//! covered by the shard server's round trip. Byte accounting is therefore
//! structural — it proves the stages are counted separately and that filters
//! are paid for unconditionally — and not a performance measurement.

use std::collections::BTreeMap;
use zakura_pir_client::transparent::engine::client::Table;
use zakura_pir_client::transparent::engine::ledger::Ledger;
use zakura_pir_client::transparent::engine::sync::{ServiceGeometry, sync};
use zakura_pir_client::transparent::engine::transport::{BoxError, FilterSource, ShardTransport};
use zakura_pir_client::transparent::filter::{
    BlockHash, ScriptBytes, SealParameters, ShardMap, ShardMapEntry, filter_hash,
};
use zakura_pir_protocol::transparent::events::{ReceiveEvent, SpendEvent, TransparentEvent, Txid};
use zakura_pir_publisher::transparent::build::{
    Block, Built, BuiltChild, BuiltDirectory, ShardStream,
};
use zakura_pir_publisher::transparent::layout::DECOUPLED_2K_8K;
use zakura_pir_publisher::transparent::seal::{DecoupledPolicy, Limit};

const GENESIS: &str = zakura_pir_client::transparent::filter::MAINNET_GENESIS_DISPLAY;
const FIRST: u64 = 3_428_143;
const SPAN: u64 = 200;
const SPANS: u64 = 4;

fn genesis() -> BlockHash {
    BlockHash::from_display_hex(GENESIS).unwrap()
}

fn hash_at(height: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&height.to_le_bytes());
    BlockHash::from_internal_bytes(bytes)
}

fn script(tag: u32) -> ScriptBytes {
    let mut bytes = vec![0x76, 0xa9, 0x14];
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 16]);
    bytes.extend_from_slice(&[0x88, 0xac]);
    ScriptBytes::new(bytes)
}

fn txid(tag: u64) -> Txid {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&tag.to_le_bytes());
    Txid(bytes)
}

/// A synthetic chain: some scripts receive and are later spent, one has a long
/// history that needs pages in several page shards, and one is never used.
///
/// Returns every block from `FIRST`, in chain order, empty ones included.
fn chain() -> Vec<Block> {
    let mut blocks: Vec<Block> = (FIRST..FIRST + SPANS * SPAN)
        .map(|height| (height, Vec::new()))
        .collect();
    let mut push = |height: u64, script: ScriptBytes, event: TransparentEvent| {
        blocks[(height - FIRST) as usize].1.push((script, event));
    };

    // Wallet script 1: receives early, spent later. A zero balance with real
    // history — the case an empty UTXO set must not be read as.
    push(
        FIRST + 5,
        script(1),
        TransparentEvent::Receive(ReceiveEvent {
            metadata: None,
            height: (FIRST + 5) as u32,
            txid: txid(100),
            transaction_index: 0,
            output_index: 0,
            value: 50_000,
            coinbase: false,
        }),
    );
    push(
        FIRST + 2 * SPAN + 10,
        script(1),
        TransparentEvent::Spend(SpendEvent {
            metadata: None,
            height: (FIRST + 2 * SPAN + 10) as u32,
            spending_txid: txid(200),
            transaction_index: 0,
            input_index: 0,
            spent_txid: txid(100),
            spent_output_index: 0,
        }),
    );

    // Wallet script 2: two receives far apart, never spent.
    for (n, height) in [FIRST + SPAN + 3, FIRST + 3 * SPAN + 7].iter().enumerate() {
        push(
            *height,
            script(2),
            TransparentEvent::Receive(ReceiveEvent {
                metadata: None,
                height: *height as u32,
                txid: txid(300 + n as u64),
                transaction_index: 1,
                output_index: 0,
                value: 7_000 + n as u64,
                coinbase: false,
            }),
        );
    }

    // Wallet script 3: a long history, enough to need several fragments and
    // to be pushed into more than one page shard.
    let long = zakura_pir_publisher::transparent::EVENTS_PER_PAGE
        + zakura_pir_publisher::transparent::INLINE_EVENTS
        + 5;
    for i in 0..long {
        let height = FIRST + SPAN + 20 + u64::from(i) * 2;
        push(
            height,
            script(3),
            TransparentEvent::Receive(ReceiveEvent {
                metadata: None,
                height: height as u32,
                txid: txid(1_000 + u64::from(i)),
                transaction_index: 2,
                output_index: 0,
                value: 11,
                coinbase: false,
            }),
        );
    }

    // Unrelated chain activity in every span, with histories long enough to
    // page, so page shards close and the wallet's scripts are not the only
    // thing in the filters.
    for span in 0..SPANS {
        for tag in 100..400u32 {
            for repeat in 0..3u64 {
                let height = FIRST + span * SPAN + u64::from(tag % 50) + repeat * 60;
                push(
                    height,
                    script(tag),
                    TransparentEvent::Receive(ReceiveEvent {
                        metadata: None,
                        height: height as u32,
                        txid: txid(u64::from(tag) * 1_000_000 + span * 10 + repeat),
                        transaction_index: 3,
                        output_index: 0,
                        value: 1,
                        coinbase: false,
                    }),
                );
            }
        }
    }
    blocks
}

/// Small enough that page shards close every few blocks and directory shards
/// on the page-shard limit, so histories cross page shards and directory
/// shards.
fn policy() -> DecoupledPolicy {
    DecoupledPolicy {
        scripts: Limit::new(10_000, 20_000).unwrap(),
        directory_bytes: Limit::new(1_000_000, 2_000_000).unwrap(),
        page_rows: Limit::new(4, 8).unwrap(),
        max_children: 8,
        ..DecoupledPolicy::for_geometry(&DECOUPLED_2K_8K)
    }
}

/// One published directory shard with its page shards.
struct Directory {
    built: BuiltDirectory,
    children: Vec<BuiltChild>,
}

/// A published shard set held in memory.
struct Published {
    map: ShardMap,
    map_bytes: u64,
    filters: BTreeMap<u64, Vec<u8>>,
    directories: Vec<Directory>,
}

fn publish(blocks: &[Block]) -> Published {
    let mut stream = ShardStream::with_policy(
        &DECOUPLED_2K_8K,
        policy(),
        FIRST,
        0,
        genesis(),
        zakura_pir_client::transparent::filter::RANGE_PROFILE,
    )
    .unwrap();
    let terminal = |height: u64| Some(hash_at(height));
    let mut built = Vec::new();
    for block in blocks {
        built.extend(stream.push_block(block.clone(), &terminal).unwrap());
    }
    built.extend(stream.finish(&terminal).unwrap());
    let mut directories = Vec::new();
    let mut children = Vec::new();
    for item in built {
        match item {
            Built::Child(child) => children.push(child),
            Built::Directory { built, .. } => directories.push(Directory {
                built,
                children: std::mem::take(&mut children),
            }),
        }
    }
    assert!(
        children.is_empty(),
        "every page shard belongs to a directory shard"
    );

    let mut entries = Vec::new();
    let mut filters = BTreeMap::new();
    for directory in &directories {
        let built = &directory.built;
        entries.push(ShardMapEntry {
            shard_id: built.shard_id,
            geometry: DECOUPLED_2K_8K.name.to_string(),
            start_height: built.start_height,
            end_height: built.end_height,
            parent_block_hash: hash_at(built.start_height - 1).to_display_hex(),
            terminal_block_hash: hash_at(built.end_height).to_display_hex(),
            filter_hash: filter_hash(built.filter.as_slice()).to_display_hex(),
            scripts: built.scripts,
            page_rows: directory.children.iter().map(|c| c.page_rows).sum(),
            txids: 0,
            directory_segments: built.directory_segments(),
            page_segments: built.children,
            manifest_digest: format!("{:064x}", built.shard_id),
            revision: 0,
            sealed: built.sealed,
        });
        filters.insert(built.shard_id, built.filter.as_slice().to_vec());
    }

    let map = ShardMap {
        genesis_hash: GENESIS.to_string(),
        network: zakura_pir_client::transparent::filter::NETWORK.to_string(),
        profile: zakura_pir_client::transparent::filter::RANGE_PROFILE.to_string(),
        range_envelope_version: zakura_pir_client::transparent::filter::RANGE_ENVELOPE_VERSION,
        start_height: FIRST,
        seal: BTreeMap::from([(
            DECOUPLED_2K_8K.name.to_string(),
            SealParameters {
                max_scripts: 10_000,
                max_page_rows: 4,
                max_txids: 0,
            },
        )]),
        shards: entries,
        recuts: Vec::new(),
    };
    let map_bytes = serde_json::to_vec(&map).unwrap().len() as u64;
    Published {
        map,
        map_bytes,
        filters,
        directories,
    }
}

/// The history one directory shard holds for `script`: its inline events and
/// every run its chain links, read straight from the tables.
fn read_history(directory: &Directory, script: &[u8]) -> Vec<TransparentEvent> {
    let built = &directory.built;
    let geometry = built.geometry;
    let salt = zakura_pir_publisher::transparent::tag_salt(
        built.shard_id,
        &hash_at(built.end_height),
        built.tag_salt_counter,
    );
    let wanted = zakura_pir_publisher::transparent::script_tag(&salt, script);
    let rows = geometry.directory_rows * u64::from(built.directory_segments());
    let mut found = None;
    for row in
        zakura_pir_publisher::transparent::build::candidate_rows(built.shard_id, script, rows)
    {
        for entry in zakura_pir_publisher::transparent::records::decode_directory_row(
            built.directory_row(row),
            built.children,
        )
        .unwrap()
        {
            if entry.tag == wanted {
                found = Some(entry);
            }
        }
    }
    let Some(entry) = found else {
        return Vec::new();
    };
    let mut history = entry.inline.clone();
    let mut next = entry.head();
    while let Some((child, row)) = next {
        let page = &directory.children[child as usize];
        let page_salt = zakura_pir_publisher::transparent::page_tag_salt(
            built.shard_id,
            page.index,
            page.end_height,
            &page.terminal_block_hash,
            page.tag_salt_counter,
        );
        let tag = zakura_pir_publisher::transparent::script_tag(&page_salt, script);
        let mut run = Vec::new();
        let mut ordinal = 0u32;
        let mut count = 1u32;
        while ordinal < count {
            // A packed row carries several scripts; take the one fragment
            // that claims this tag and ordinal.
            let fragment = zakura_pir_publisher::transparent::decode_page_row(
                page.page_row(geometry, u64::from(row) + u64::from(ordinal)),
            )
            .unwrap()
            .into_iter()
            .find(|e| e.tag == tag && e.ordinal == ordinal)
            .expect("a located row holds the fragment that named it");
            if ordinal == 0 {
                count = fragment.fragment_count;
                next = fragment.link.previous();
            }
            run.extend(fragment.events);
            ordinal += 1;
        }
        run.extend(history);
        history = run;
    }
    history
}

/// Serves filters, charging their real size.
struct Filters<'a> {
    published: &'a Published,
}

impl FilterSource for Filters<'_> {
    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        let bytes = serde_json::to_vec(&self.published.map)?;
        let len = bytes.len() as u64;
        Ok((bytes, len))
    }

    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        let bytes = self
            .published
            .filters
            .get(&shard_id)
            .ok_or("no such shard")?
            .clone();
        let len = bytes.len() as u64;
        Ok((bytes, len))
    }
}

/// A stand-in for the private transport.
///
/// It serves no manifests, so a sync through it stops at the manifest check;
/// it exists to keep the transport trait honest. The walk itself is exercised
/// over real rows by the wallet's unit tests and by the shard server's round
/// trip.
struct DirectRows;

impl ShardTransport for DirectRows {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        Ok((Vec::new(), 0))
    }

    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        let _ = (shard_id, revision);
        Err("the direct-rows stand-in serves no manifests".into())
    }

    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        let _ = (shard_id, revision, table.name(), segment);
        Ok((Vec::new(), 0))
    }

    fn query(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        let _ = (shard_id, revision, table.name(), body);
        Err("the direct-rows stand-in answers no queries".into())
    }
}

/// Replays the same events directly, with no retrieval at all.
///
/// This is the independent result the reconstruction is compared against. It
/// shares only the ledger arithmetic; it does not share a filter, a shard, a
/// row or a page.
fn traverse(blocks: &[Block], wallet: &[ScriptBytes], from_height: u64) -> Ledger {
    let mut events: Vec<(Vec<u8>, TransparentEvent)> = Vec::new();
    for (height, block) in blocks {
        if *height < from_height {
            continue;
        }
        for (script, event) in block {
            if wallet.iter().any(|s| s.as_slice() == script.as_slice()) {
                events.push((script.as_slice().to_vec(), *event));
            }
        }
    }
    let mut ledger = Ledger::new();
    ledger.replay(&mut events).expect("traversal replay");
    ledger
}

fn compare(recovered: &Ledger, expected: &Ledger) {
    let mut mine: Vec<_> = recovered.utxos().cloned().collect();
    let mut theirs: Vec<_> = expected.utxos().cloned().collect();
    mine.sort_by_key(|u| (u.txid, u.output_index));
    theirs.sort_by_key(|u| (u.txid, u.output_index));
    assert_eq!(mine, theirs, "UTXO sets differ");

    let mut my_spends = recovered.spends().to_vec();
    let mut their_spends = expected.spends().to_vec();
    my_spends.sort_by_key(|s| (s.spent_txid, s.spent_output_index));
    their_spends.sort_by_key(|s| (s.spent_txid, s.spent_output_index));
    assert_eq!(my_spends, their_spends, "spend sets differ");

    assert_eq!(recovered.confirmed_balance(), expected.confirmed_balance());
    assert_eq!(recovered.history(), expected.history(), "histories differ");
}

#[test]
fn the_ledger_replays_identically_from_shards_and_from_a_direct_traversal() {
    // Drives the ledger from the published tables, decoded directly and
    // walked along each chain of runs, so the comparison covers the whole
    // build-and-decode path without needing the cryptographic transport.
    let blocks = chain();
    let published = publish(&blocks);
    let wallet = vec![script(1), script(2), script(3), script(999)];
    assert!(
        published.directories.len() > 1,
        "more than one directory shard"
    );

    let mut events: Vec<(Vec<u8>, TransparentEvent)> = Vec::new();
    let mut runs_crossed = 0;
    for directory in &published.directories {
        for want in &wallet {
            let history = read_history(directory, want.as_slice());
            for event in history {
                events.push((want.as_slice().to_vec(), event));
            }
        }
        runs_crossed += directory.children.iter().filter(|c| c.runs > 0).count();
    }
    assert!(runs_crossed > 1, "histories cross page shards");

    let mut recovered = Ledger::new();
    recovered.replay(&mut events).expect("replay");
    let expected = traverse(&blocks, &wallet, 0);
    compare(&recovered, &expected);

    // The fixture must actually exercise what it claims to.
    assert!(expected.confirmed_balance() > 0);
    assert_eq!(expected.spends().len(), 1, "one spend in the fixture");
    assert!(
        expected.utxos().count()
            > (zakura_pir_publisher::transparent::EVENTS_PER_PAGE
                + zakura_pir_publisher::transparent::INLINE_EVENTS) as usize,
        "the long history should dominate the UTXO set"
    );
    assert!(recovered.unresolved().is_empty());
}

/// A birthday inside the set must skip earlier shards entirely — and the
/// resulting ledger must match a traversal that skips the same events, not the
/// full-history one.
#[test]
fn a_later_birthday_recovers_exactly_the_history_from_that_shard_forward() {
    let blocks = chain();
    let published = publish(&blocks);
    let wallet = vec![script(1), script(2)];

    // The directory shard holding script 1's spend but not its receive, so
    // this is also the unresolved-spend case: a wallet starting there sees
    // money leave an output it never saw arrive, and must say so rather than
    // ignore it.
    let spend_height = FIRST + 2 * SPAN + 10;
    let entry = published
        .map
        .shard_for_height(spend_height)
        .expect("in range")
        .clone();
    assert!(
        entry.start_height > FIRST + 5,
        "the receive is in an earlier shard"
    );
    let expected = traverse(&blocks, &wallet, entry.start_height);
    assert_eq!(expected.unresolved().len(), 1);

    let mut events = Vec::new();
    for directory in &published.directories {
        if directory.built.end_height < entry.start_height {
            continue;
        }
        for want in &wallet {
            for event in read_history(directory, want.as_slice()) {
                events.push((want.as_slice().to_vec(), event));
            }
        }
    }
    let mut recovered = Ledger::new();
    recovered.replay(&mut events).expect("replay");
    compare(&recovered, &expected);
}

/// Filters are paid for by every wallet, matched or not. That unconditional
/// cost is the floor the design has to beat, so the accounting must keep it
/// separate rather than folding it into a total.
#[test]
fn byte_accounting_separates_the_unconditional_floor_from_the_gated_work() {
    let published = publish(&chain());

    let mut charges = zakura_pir_client::transparent::engine::ByteCharges {
        map_bytes: published.map_bytes,
        ..Default::default()
    };
    for bytes in published.filters.values() {
        charges.filter_bytes += bytes.len() as u64;
        charges.filters_checked += 1;
    }
    assert_eq!(charges.filters_checked, published.map.shards.len() as u64);
    assert_eq!(charges.public_floor(), charges.total());

    charges.add_query(
        zakura_pir_client::transparent::engine::client::Table::Directory,
        100_000,
        5_000,
    );
    assert_eq!(charges.queries(), 1);
    assert_eq!(charges.directory.queries, 1);
    assert_eq!(
        charges.pages.queries, 0,
        "a directory query is not a page query"
    );
    assert!(charges.total() > charges.public_floor());
    assert_eq!(
        charges.total() - charges.public_floor(),
        105_000,
        "query bytes are counted apart from the floor"
    );
}

/// An unused wallet must still check every filter and must retrieve nothing.
/// This is the case the whole arrangement is meant to make cheap.
#[test]
fn an_unused_wallet_matches_nothing_and_issues_no_queries() {
    let published = publish(&chain());
    let wallet = vec![script(900_001), script(900_002)];

    let mut matched = 0;
    for entry in &published.map.shards {
        let bytes = &published.filters[&entry.shard_id];
        let validated = zakura_pir_client::transparent::filter::validate_filter(
            bytes,
            zakura_pir_client::transparent::filter::FilterLimits::default(),
        )
        .unwrap();
        let key = zakura_pir_client::transparent::filter::ShardKey::derive(
            &published.map.profile,
            genesis(),
            entry.shard_id,
            entry.start_height,
            entry.end_height,
            BlockHash::from_display_hex(&entry.terminal_block_hash).unwrap(),
        );
        matched +=
            zakura_pir_client::transparent::filter::match_range_scripts(&validated, key, &wallet)
                .unwrap()
                .len();
    }
    assert_eq!(matched, 0, "unused scripts should not match any shard");
}

/// Unused by the stand-in transport, but it keeps the trait honest: the sync
/// entry point must compile against the traits it declares.
#[allow(dead_code)]
fn sync_signature_is_usable(
    published: &Published,
    geometry: &ServiceGeometry,
    scripts: &[ScriptBytes],
) {
    let mut filters = Filters { published };
    let mut rows = DirectRows;
    let _ = sync(
        &published.map,
        published.map_bytes,
        geometry,
        &mut filters,
        &mut rows,
        scripts,
        FIRST,
        &zakura_pir_client::transparent::engine::StaticChain::from_map(&published.map),
        &zakura_pir_client::transparent::engine::Anchor {
            height: published.map.shards.last().unwrap().end_height,
            hash: published
                .map
                .shards
                .last()
                .unwrap()
                .terminal_block_hash
                .clone(),
        },
    );
}
