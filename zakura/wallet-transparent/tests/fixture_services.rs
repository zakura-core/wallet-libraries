//! Fixture services for a rehearsal through the real bridge.
//!
//! Set `ZAKURA_FIXTURE_SERVE=1` and this test becomes a program: it makes a
//! wallet from a fresh phrase, builds the catalogue chain for it, publishes
//! the chain as shards, serves them from the real shard service with one
//! query held, serves the same blocks from a fixture light server, and
//! prints where everything is. It then waits on standard input: `release`
//! lets the held query go, `exit` ends it. Whenever the held query arrives it
//! prints `HELD`.
//!
//! ```sh
//! ZAKURA_FIXTURE_SERVE=1 cargo test --release -p zakura-wallet-transparent \
//!   --test fixture_services -- --nocapture --test-threads=1
//! ```
//!
//! The phrase is printed for the driving test to hand to the wallet under
//! test and nowhere else; it exists only for this run.

mod common;

use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use common::blocks::*;
use common::catalogue::*;
use common::*;
use zakura_wallet_lwd::fixture::{FixtureChain, FixtureLightServer};
use zakura_wallet_lwd::proto;

fn wire_block(block: &Block) -> proto::CompactBlock {
    proto::CompactBlock {
        height: block.height,
        hash: block.hash.internal_bytes().to_vec(),
        prev_hash: block.prev_hash.internal_bytes().to_vec(),
        // Ten minutes and change per block, from a fixed origin.
        time: (1_700_000_000 + (block.height - FIRST + 1) * 75) as u32,
        header: Vec::new(),
        vtx: block
            .txs
            .iter()
            .enumerate()
            .map(|(index, tx)| proto::CompactTx {
                index: index as u64,
                txid: tx.txid.0.to_vec(),
                fee: 0,
                spends: Vec::new(),
                outputs: Vec::new(),
                actions: Vec::new(),
                ironwood_actions: Vec::new(),
                vin: tx
                    .vin
                    .iter()
                    .map(|i| proto::CompactTxIn {
                        prevout_txid: i.prevout.txid.0.to_vec(),
                        prevout_index: i.prevout.n,
                    })
                    .collect(),
                vout: tx
                    .vout
                    .iter()
                    .map(|o| proto::TxOut {
                        value: o.value,
                        script_pub_key: o.script.as_slice().to_vec(),
                    })
                    .collect(),
            })
            .collect(),
        chain_metadata: Some(proto::ChainMetadata {
            sapling_commitment_tree_size: 0,
            orchard_commitment_tree_size: 0,
            ironwood_commitment_tree_size: 0,
        }),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn fixture_services() {
    if std::env::var("ZAKURA_FIXTURE_SERVE").as_deref() != Ok("1") {
        return;
    }
    let held_shard: u64 = std::env::var("ZAKURA_FIXTURE_HOLD_SHARD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let held_table: &'static str = match std::env::var("ZAKURA_FIXTURE_HOLD_TABLE").as_deref() {
        Ok("directory") => "directory",
        _ => "pages",
    };
    let held_nth: u32 = std::env::var("ZAKURA_FIXTURE_HOLD_NTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);

    // A wallet from a fresh phrase, so the catalogue pays scripts the wallet
    // under test will derive from the same phrase.
    let mnemonic = bip0039::Mnemonic::<bip0039::English>::generate(bip0039::Count::Words24);
    let phrase = mnemonic.phrase().to_owned();
    let seed = mnemonic.to_seed("");
    let mut db = zakura_wallet_store::testing::test_db().unwrap();
    let account = db
        .create_account(
            &params(),
            &seed[..],
            zip32::AccountId::try_from(0).unwrap(),
            h(FIRST),
        )
        .unwrap();
    let (chain, cast) = catalogue(&mut db, account);
    // The wallet under test restores from the phrase alone: it holds the
    // derived scripts and not the imported one, whose events are decoys to it.
    let derived: Vec<_> = cast
        .all
        .iter()
        .filter(|s| **s != cast.imported)
        .cloned()
        .collect();
    let expected = reduce(&chain, &derived, FIRST, chain.last());

    let set = tempfile::tempdir().unwrap();
    let map = publish_layout(
        set.path(),
        &extract(&chain),
        DEFAULT_LAYOUT,
        tiers,
        0,
        "",
        chain.hash_fn(),
    );
    let hold = HoldOn::new(held_shard, Some(held_table), held_nth);
    let faults = Faults::hold(hold.clone());
    let (shards, _handle) = serve_with(set.path(), faults).await;
    let port = shards.rsplit(':').next().unwrap();

    let blocks: BTreeMap<u64, proto::CompactBlock> = chain
        .blocks
        .values()
        .map(|b| (b.height, wire_block(b)))
        .collect();
    let (lwd, _task) = FixtureLightServer::new(FixtureChain {
        chain_name: "main".into(),
        blocks,
    })
    .spawn()
    .await
    .unwrap();

    let mut out = std::io::stdout().lock();
    let mut say = |line: String| {
        writeln!(out, "{line}").unwrap();
        out.flush().unwrap();
    };
    // The test runner prints the test's name without a newline; the first
    // fact must not share its line.
    say(String::new());
    say(format!("LWD=http://127.0.0.1:{}", lwd.port()));
    say(format!("FILTERS=http://localhost:{port}"));
    say(format!("SHARDS={shards}"));
    say(format!("BIRTHDAY={FIRST}"));
    say(format!("TIP={}", chain.last()));
    say(format!("MAP_SHARDS={}", map.shards.len()));
    say(format!("EXPECTED_BALANCE={}", expected.balance));
    // The bridge shows the spendable transparent value, which leaves out a
    // coinbase output until the wallet's maturity rule says otherwise.
    let spendable: u64 = expected
        .utxos
        .values()
        .filter(|(_, _, _, coinbase)| !coinbase)
        .map(|(_, value, _, _)| value)
        .sum();
    say(format!("EXPECTED_SPENDABLE={spendable}"));
    say(format!("EXPECTED_HISTORY={}", expected.history.len()));
    say(format!("EXPECTED_UTXOS={}", expected.utxos.len()));
    say(format!("HOLD={held_shard}:{held_table}:{held_nth}"));
    say(format!("PHRASE={phrase}"));
    say("READY".into());

    // Announce the held query when it arrives; obey stdin.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            if tx.send(line.trim().to_owned()).is_err() {
                break;
            }
        }
    });
    let mut announced = false;
    loop {
        if !announced && hold.is_in_flight() {
            announced = true;
            say("HELD".into());
        }
        match tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await {
            Ok(Some(line)) => match line.as_str() {
                "release" => {
                    hold.release();
                    say("RELEASED".into());
                }
                "exit" => {
                    say("BYE".into());
                    return;
                }
                other => say(format!("UNKNOWN {other}")),
            },
            Ok(None) => return,
            Err(_) => {}
        }
    }
}
