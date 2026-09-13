//! Real mainnet blocks through the same path: a sample of the chain, read by
//! the block model, is published as shards, and scripts chosen from it are
//! imported into a synthetic wallet and recovered privately. The reducer
//! over the same blocks says what must come back.
//!
//! Set `ZAKURA_TRANSPARENT_BLOCKS_JSONL` to the sample's path, or to several
//! paths joined by `:` when a capture was resumed into a second file. The test
//! prints counts only; no script, address or txid from the sample reaches
//! its output.

mod common;

use common::blocks::*;
use common::*;
use transparent_shard::layout::{RECENT_4K, RECENT_8K};
use transparent_wallet::WorkLimits;
use zakura_wallet_sync::TransparentCompletion;

const LAYOUT: Layout = Layout {
    first: 3_470_268,
    span: 192,
    shards: 6,
};

#[tokio::test(flavor = "multi_thread")]
async fn a_mainnet_sample_recovered_through_imported_scripts_matches_the_block_reducer() {
    let Ok(path) = std::env::var("ZAKURA_TRANSPARENT_BLOCKS_JSONL") else {
        eprintln!("ZAKURA_TRANSPARENT_BLOCKS_JSONL unset; skipping");
        return;
    };
    let paths: Vec<std::path::PathBuf> = path.split(':').map(std::path::PathBuf::from).collect();
    let refs: Vec<&std::path::Path> = paths.iter().map(|p| p.as_path()).collect();
    let chain = Chain::load_jsonl(&refs, LAYOUT);
    let candidates = chain.candidate_scripts();

    // Deterministic choices from the sample: three P2PKH scripts with a
    // receive and a spend inside it, one P2SH with activity, one that a
    // coinbase paid, and one receive-only P2PKH.
    let mut chosen = Vec::new();
    chosen.extend(
        candidates
            .iter()
            .filter(|c| c.is_p2pkh() && c.spends > 0 && c.receives > 0 && !c.coinbase)
            .take(3)
            .cloned(),
    );
    chosen.extend(
        candidates
            .iter()
            .filter(|c| c.is_p2sh() && c.receives > 0)
            .take(1)
            .cloned(),
    );
    chosen.extend(
        candidates
            .iter()
            .filter(|c| c.coinbase && c.is_p2pkh())
            .take(1)
            .cloned(),
    );
    chosen.extend(
        candidates
            .iter()
            .filter(|c| c.is_p2pkh() && c.spends == 0 && c.receives == 1 && !c.coinbase)
            .take(1)
            .cloned(),
    );
    assert_eq!(
        chosen.len(),
        6,
        "the sample holds every kind of script the case needs"
    );
    eprintln!(
        "sample: {} blocks, {} scripts with activity; chosen 6 with {} receives and {} spends",
        chain.blocks.len() - 1,
        candidates.len(),
        chosen.iter().map(|c| c.receives).sum::<u32>(),
        chosen.iter().map(|c| c.spends).sum::<u32>()
    );

    let (mut db, account) = wallet_born_at(LAYOUT.first);
    for (i, candidate) in chosen.iter().enumerate() {
        db.import_transparent_script(
            account,
            &format!("t1ImportedFromSample{i}"),
            candidate.script.as_slice(),
        )
        .unwrap();
    }
    accept_layout(&db, LAYOUT, LAYOUT.shards, chain.hash_fn());
    let dir = tempfile::tempdir().unwrap();
    let events = extract(&chain);
    let map = publish_layout(
        dir.path(),
        &events,
        LAYOUT,
        |shard| if shard < 3 { &RECENT_4K } else { &RECENT_8K },
        0,
        "",
        chain.hash_fn(),
    );
    assert_eq!(map.genesis_hash, GENESIS);
    let (base, faults) = serve_traced(dir.path()).await;

    let (mut db, transport, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.expect("recovery completes");
    let scripts: Vec<_> = chosen.iter().map(|c| c.script.clone()).collect();
    let expected = reduce(&chain, &scripts, LAYOUT.first, chain.last());
    // A spend of an output created before the sample is unresolved by
    // construction; the reducer counts it and the wallet must agree.
    let want = if expected.unresolved > 0 {
        TransparentCompletion::Incomplete("unresolved-spends".into())
    } else {
        TransparentCompletion::Complete
    };
    assert_eq!(progress.completion, want, "{progress:?}");
    assert!(transport.queries > 0);
    compare_blocks(&mut db, account, &expected);
    assert_projection_matches_ledger(&mut db, account);
    eprintln!(
        "recovered: {} events, {} utxos, {} spends, {} unresolved, balance {} zat, {} private queries over {} shards",
        expected.events.len(),
        expected.utxos.len(),
        expected.spends.len(),
        expected.unresolved,
        expected.balance,
        transport.queries,
        transport.queried.len()
    );
    let requests = faults.lock().unwrap().requests.clone();
    let needles = Needles::of(&db, account, &events);
    assert_no_plaintext(&requests, &needles);
}
