//! Tests against a real lightwalletd server.
//!
//! These are ignored by default, because they need the network and a server
//! that speaks the Zakura compact format. Run them with:
//!
//! ```text
//! ZAKURA_LWD=https://us.zec.stardust.rest:443 cargo test -p zakura-wallet-lwd -- --ignored --nocapture
//! ```

use zakura_wallet_core::pool::PoolId;
use zakura_wallet_lwd::LightwalletdSource;
use zakura_wallet_sync::{ByteBudget, ChainSource, Direction};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

/// The server to test against, or the default public one.
fn endpoint() -> String {
    std::env::var("ZAKURA_LWD").unwrap_or_else(|_| "https://us.zec.stardust.rest:443".to_owned())
}

fn ironwood_activation() -> BlockHeight {
    zcash_protocol::consensus::Network::MainNetwork
        .activation_height(NetworkUpgrade::Nu6_3)
        .expect("Ironwood has a mainnet activation height")
}

#[tokio::test]
#[ignore = "requires network access"]
async fn the_server_is_past_ironwood_activation() {
    let source = LightwalletdSource::connect(&endpoint()).await.unwrap();
    let tip = source.tip().await.unwrap();

    println!("tip: {} (Ironwood activates at {})", tip.height, ironwood_activation());
    assert!(
        tip.height > ironwood_activation(),
        "the server is below Ironwood activation, so nothing here would exercise it"
    );
}

#[tokio::test]
#[ignore = "requires network access"]
async fn tree_state_reports_both_pools() {
    let source = LightwalletdSource::connect(&endpoint()).await.unwrap();
    let tip = source.tip().await.unwrap();

    let anchor = source.anchor(tip.height - 1).await.unwrap();
    println!(
        "anchor at {}: orchard={} ironwood={}",
        anchor.height, anchor.tree_sizes.orchard, anchor.tree_sizes.ironwood
    );

    assert!(anchor.tree_sizes.orchard > 0, "Orchard has been live for years");
    assert!(
        anchor.tree_sizes.ironwood > 0,
        "the Ironwood tree should be non-empty above activation; \
         a zero here means the server is not serving Ironwood tree state"
    );
}

#[tokio::test]
#[ignore = "requires network access"]
async fn fetched_blocks_carry_ironwood_actions() {
    // The failure this guards against is silent: a server that omits Ironwood
    // actions *and* reports a zero Ironwood tree size is self-consistent, so
    // the scanner's tree-size check passes and the wallet simply never sees any
    // Ironwood funds.
    let source = LightwalletdSource::connect(&endpoint()).await.unwrap();
    let tip = source.tip().await.unwrap();

    let start = tip.height - 200;
    let blocks = source
        .fetch(start..tip.height, ByteBudget::DESKTOP, Direction::Ascending)
        .await
        .unwrap();

    assert!(!blocks.is_empty());

    let ironwood_actions: usize = blocks
        .iter()
        .flat_map(|b| b.txs.iter())
        .map(|tx| tx.ironwood_actions.len())
        .sum();
    let orchard_actions: usize = blocks
        .iter()
        .flat_map(|b| b.txs.iter())
        .map(|tx| tx.orchard_actions.len())
        .sum();

    println!(
        "{} blocks: {orchard_actions} Orchard actions, {ironwood_actions} Ironwood actions",
        blocks.len()
    );

    assert!(
        ironwood_actions > 0,
        "200 blocks above activation contained no Ironwood actions; \
         either the chain is idle or the server is not serving them"
    );

    // The tree sizes must advance by exactly the number of actions, which is
    // the check that catches a server dropping one.
    let first = &blocks[0];
    let last = blocks.last().unwrap();
    let anchor = source.anchor(start - 1).await.unwrap();

    assert_eq!(
        u64::from(last.tree_sizes.ironwood - anchor.tree_sizes.ironwood),
        ironwood_actions as u64,
        "the Ironwood tree grew by a different amount than the actions served"
    );
    assert_eq!(
        u64::from(last.tree_sizes.orchard - anchor.tree_sizes.orchard),
        orchard_actions as u64,
    );
    assert_eq!(first.prev_hash, anchor.hash, "the anchor must join the range");

    for pool in PoolId::ALL {
        println!("{pool:?} tree at tip: {}", last.tree_sizes.get(pool));
    }
}

#[tokio::test]
#[ignore = "requires network access"]
async fn the_byte_budget_is_honoured_over_the_wire() {
    let source = LightwalletdSource::connect(&endpoint()).await.unwrap();
    let tip = source.tip().await.unwrap();

    let small = ByteBudget::new(4 * 1024);
    let blocks = source
        .fetch((tip.height - 500)..tip.height, small, Direction::Ascending)
        .await
        .unwrap();

    let total: usize = blocks.iter().map(zakura_wallet_sync::estimated_size).sum();
    println!("{} blocks, {total} bytes for a {} byte budget", blocks.len(), small.bytes());

    assert!(!blocks.is_empty(), "at least one block must always come back");
    assert!(
        blocks.len() < 500,
        "the budget should have stopped the stream well short of the range"
    );
}
