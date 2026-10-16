//! The RocksDB reader against a real node database: a primary instance commits the
//! public mainnet genesis block and synthetic transparent blocks after it, and the
//! reader opens the same directory as a secondary while the primary is still open.
//! Its reads must agree with the RPC path over the same blocks.
use std::sync::{Arc, Mutex};

use zakura_chain::block::{Block, Header};
use zakura_chain::parameters::Network as NodeNetwork;
use zakura_chain::serialization::{ZcashDeserialize, ZcashSerialize};
use zakura_server_chain::{
    Network, NodeClient,
    testing::*,
    transparent::{
        ExtractError, Fee, OutputCache,
        state::{StateError, StateReader},
    },
};
use zakura_state::{Config, FinalizedState};

const P2PKH: &[u8] = &[
    0x76, 0xa9, 0x14, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0x88, 0xac,
];
const ODD: &[u8] = &[0x51, 0x6a, 0x00, 0xff];

/// `transactions` as the block after `parent`, with a correct Merkle root.
fn child(parent: &Block, transactions: &[Tx]) -> Block {
    let transactions: Vec<_> = transactions
        .iter()
        .map(|tx| {
            Arc::new(
                zakura_chain::transaction::Transaction::zcash_deserialize(&tx.bytes()[..]).unwrap(),
            )
        })
        .collect();
    let header = Header {
        previous_block_hash: parent.hash(),
        merkle_root: transactions.iter().collect(),
        time: parent.header.time + chrono::Duration::seconds(150),
        ..*parent.header
    };
    Block {
        header: Arc::new(header),
        transactions,
    }
}

fn commit(state: &mut FinalizedState, block: &Block) {
    state
        .commit_finalized_direct(Arc::new(block.clone()).into(), None, None, "state test")
        .expect("synthetic block commits");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_database_reader_agrees_with_rpc_and_refuses_missing_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        cache_dir: dir.path().to_path_buf(),
        ephemeral: false,
        ..Config::default()
    };
    let mut primary = FinalizedState::new(&config, &NodeNetwork::Mainnet).unwrap();
    let genesis =
        Block::zcash_deserialize(&zakura_test::vectors::BLOCK_MAINNET_GENESIS_BYTES[..]).unwrap();
    commit(&mut primary, &genesis);
    // Block 1 pays a standard and a nonstandard script; block 2 spends both, and
    // spends its own first transaction's output in the same block.
    let mined = coinbase(1, &[(50_000, P2PKH), (20_000, ODD)]);
    let first = child(&genesis, std::slice::from_ref(&mined));
    let parent = transfer(
        vec![spend(&mined, 0), spend(&mined, 1)],
        &[(60_000, &[]), (9_000, P2PKH)],
    );
    let spender = transfer(vec![spend(&parent, 0)], &[(59_000, ODD)]);
    let second_coinbase = coinbase(2, &[(1, P2PKH)]);
    let second = child(
        &first,
        &[second_coinbase.clone(), parent.clone(), spender.clone()],
    );
    commit(&mut primary, &first);
    commit(&mut primary, &second);

    // A secondary instance beside the running primary.
    let reader = StateReader::open(dir.path(), Network::Mainnet).unwrap();
    assert_eq!(reader.tip_height().unwrap(), 2);
    assert_eq!(
        reader.block_hash(0).unwrap(),
        Network::Mainnet.genesis_hash()
    );
    assert_eq!(reader.block_hash(2).unwrap(), second.hash().0);
    assert_eq!(
        reader.block_time(2).unwrap(),
        second.header.time.timestamp()
    );
    let read = reader.transparent_block(2).unwrap();
    assert_eq!(
        (read.height, read.hash, read.parent),
        (2, second.hash().0, first.hash().0)
    );
    let [_, made, spent] = &read.transactions[..] else {
        panic!("three transactions");
    };
    assert_eq!(made.fee, Fee::Exact(50_000 + 20_000 - 69_000));
    assert_eq!(made.inputs[1].spent.script, ODD);
    assert_eq!(spent.inputs[0].spent.script, Vec::<u8>::new());
    assert_eq!(spent.fee, Fee::Exact(1_000));
    // Both of block 1's outputs come from the database; the same-block spend does not.
    assert_eq!(read.lookups + read.cache_hits, 2);

    // The RPC path over the same blocks reads the same transactions.
    let chain: SharedChain = Arc::new(Mutex::new(Chain::default()));
    {
        let mut c = chain.lock().unwrap();
        for (height, block) in [(1u64, &first), (2, &second)] {
            let raw = block.zcash_serialize_to_vec().unwrap();
            c.blocks
                .insert(height, (hex::encode(raw), block.hash().to_string(), 0));
            for tx in &block.transactions {
                c.add_transaction(&Tx::from_bytes(&tx.zcash_serialize_to_vec().unwrap()));
            }
        }
        c.tip = 2;
    }
    let (url, _) = serve_chain(chain).await;
    let cookie_dir = tempfile::tempdir().unwrap();
    let rpc = NodeClient::from_cookie_file(url, cookie(cookie_dir.path())).unwrap();
    let fetched = rpc.fetch_block(2).await.unwrap();
    let over_rpc = rpc
        .transparent_block(2, fetched, &mut OutputCache::new(100))
        .await
        .unwrap();
    assert_eq!(over_rpc.transactions, read.transactions);
    assert_eq!((over_rpc.hash, over_rpc.parent), (read.hash, read.parent));
    assert_eq!(
        reader.fetch_block(2).unwrap().txids(),
        rpc.fetch_block(2).await.unwrap().txids()
    );

    // Heights the database does not hold, or no block height can name, are refused
    // rather than read as empty.
    assert!(matches!(
        reader.fetch_block(3),
        Err(StateError::MissingBlock(3))
    ));
    assert!(matches!(
        reader.block_hash(3),
        Err(StateError::MissingBlock(3))
    ));
    assert!(matches!(
        reader.transparent_block(3),
        Err(ExtractError::MissingBlock(3))
    ));
    assert!(matches!(
        reader.block_hash(u64::MAX),
        Err(StateError::HeightRange(_))
    ));

    // The reader is a snapshot: a block the node commits after it opened stays
    // missing to it, while a reader opened afterwards sees it.
    let third = child(&second, &[coinbase(3, &[(1, P2PKH)])]);
    commit(&mut primary, &third);
    assert_eq!(reader.tip_height().unwrap(), 2);
    assert!(matches!(
        reader.fetch_block(3),
        Err(StateError::MissingBlock(3))
    ));
    let later = StateReader::open(dir.path(), Network::Mainnet).unwrap();
    assert_eq!(later.tip_height().unwrap(), 3);
    assert_eq!(later.block_hash(3).unwrap(), third.hash().0);
    drop(later);

    // The reader keeps its database open on its own handles after the primary closes.
    drop(primary);
    assert_eq!(
        reader.transparent_block(2).unwrap().transactions,
        read.transactions
    );
    drop(reader);
    // A directory without a database is an error, never an empty chain.
    let empty = tempfile::tempdir().unwrap();
    assert!(StateReader::open(empty.path(), Network::Mainnet).is_err());
}

/// Every file under `dir` with its contents, so a refused open can be shown to
/// have left the node's database exactly as it was.
fn files(dir: &std::path::Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut found = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(files(&path));
        } else {
            found.insert(path.clone(), std::fs::read(&path).unwrap());
        }
    }
    found
}

#[tokio::test(flavor = "multi_thread")]
async fn a_database_carrying_either_pruning_marker_is_refused_at_open() {
    type Mark = fn(&mut zakura_state::DiskWriteBatch, &zakura_state::ZakuraDb);
    let markers: [(&str, Mark); 2] = [
        ("raw transactions pruned", |batch, db| {
            batch.prepare_pruning_marker_batch(db, zakura_chain::block::Height(1))
        }),
        ("transparent indexes skipped", |batch, db| {
            batch.prepare_transparent_indexes_skipped_marker_batch(
                db,
                zakura_chain::block::Height(1),
            )
        }),
    ];
    for (name, mark) in markers {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            cache_dir: dir.path().to_path_buf(),
            ephemeral: false,
            ..Config::default()
        };
        let mut primary = FinalizedState::new(&config, &NodeNetwork::Mainnet).unwrap();
        let genesis =
            Block::zcash_deserialize(&zakura_test::vectors::BLOCK_MAINNET_GENESIS_BYTES[..])
                .unwrap();
        commit(&mut primary, &genesis);
        let mut batch = zakura_state::DiskWriteBatch::new();
        mark(&mut batch, &primary.db);
        primary.db.write_batch(batch).unwrap();
        // The node's own view of the marker, before the reader sees it.
        let pruned = primary.db.lowest_retained_height().is_some();
        let skipped = primary.db.transparent_indexes_skipped_from().is_some();
        assert!(pruned != skipped, "{name}: exactly one marker is written");
        let database = primary.db.path().to_path_buf();
        drop(primary);
        let before = files(&database);

        // Refused with this crate's error rather than a panic, and without
        // touching the primary's files.
        let opened = StateReader::open(dir.path(), Network::Mainnet);
        assert!(
            matches!(opened, Err(StateError::NotArchive { .. })),
            "{name}: {:?}",
            opened.as_ref().err()
        );
        drop(opened);
        assert!(
            before == files(&database),
            "{name}: the primary is unchanged"
        );
    }
}
