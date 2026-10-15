//! Receiver blocks around the public zero-OVK refund, read through a node double.
use axum::{Json, Router, extract::State, routing::post};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use zakura_server_chain::{
    Network, NodeClient, NodeError,
    receiver::{Checkpoint, extract_block},
    testing::{receiver::RefundBlock, serve},
};

/// The refund's receiver, decoded independently of recovery; see the receiver
/// validation crate's fixture.
const RECEIVER_HEX: &str =
    "42cd776949bba6f2164b347ebdbf9c225028ed0f5b6eaa3a402f3322c6aadfbde6288d167dbcaed0fdf01e";

#[test]
fn coinbase_exclusion_preserves_position_and_compact_context() {
    let b = RefundBlock::new(3496114);
    let indexed = extract_block(&b.bytes(), 3496114, 610504).unwrap();
    assert_eq!(indexed.coinbase_actions, 1);
    assert_eq!(indexed.start_position, 610502);
    assert_eq!(indexed.commitments, b.commitments());
    assert_eq!(indexed.payments.len(), 1);
    let (receiver, p) = &indexed.payments[0];
    assert_eq!(hex::encode(receiver), RECEIVER_HEX);
    assert_eq!((p.tx_index, p.action_index, p.position), (1, 0, 610503));
    assert_eq!(p.txid, b.txids()[1]);
    assert_eq!((p.height, p.block_hash), (3496114, b.hash()));
    assert_eq!(p.ciphertext_prefix, b.refund_ciphertext()[..52]);
    assert!(extract_block(&b.bytes(), 3496115, 610504).is_err());
    assert!(extract_block(&b.bytes(), 3496114, 1).is_err());
    let mut trailing = b.bytes();
    trailing.push(0);
    assert!(extract_block(&trailing, 3496114, 610504).is_err());
}

/// A served block's height, raw hex, display hash and the Ironwood tree size its
/// verbose form reports.
type Served = (u64, String, String, u64);

/// Blocks by height.
#[derive(Clone, Default)]
struct Node {
    blocks: Arc<Mutex<Vec<Served>>>,
}

async fn answer(State(node): State<Node>, Json(r): Json<Value>) -> Json<Value> {
    let blocks = node.blocks.lock().unwrap();
    let by_height = |height: u64| blocks.iter().find(|b| b.0 == height);
    let height = r["params"][0]
        .as_u64()
        .or_else(|| r["params"][0].as_str().and_then(|s| s.parse().ok()));
    let result = match r["method"].as_str().unwrap() {
        "getblockhash" => json!(by_height(height.unwrap()).unwrap().2),
        "getblock" if r["params"][1] == 1 => {
            let block = blocks
                .iter()
                .find(|b| json!(b.2) == r["params"][0])
                .unwrap();
            json!({"trees": {"ironwood": {"size": block.3}}})
        }
        "getblock" => json!(by_height(height.unwrap()).unwrap().1),
        method => panic!("unexpected {method}"),
    };
    Json(json!({"result": result, "error": null}))
}

/// Two refund blocks at activation after `[2; 32]`, the second with only its
/// coinbase, and the client of a node serving them with the given tree sizes.
async fn chain(sizes: [u64; 2]) -> (NodeClient, Vec<RefundBlock>, Node) {
    let height = Network::Mainnet.ironwood_activation();
    let first = RefundBlock::new(height).after([2; 32]);
    let second = RefundBlock::new(height + 1)
        .coinbase_only()
        .after(first.hash());
    let node = Node::default();
    *node.blocks.lock().unwrap() = vec![
        (
            u64::from(height) - 1,
            String::new(),
            zakura_server_chain::hash::display(&[2; 32]),
            0,
        ),
        (
            u64::from(height),
            first.raw_hex(),
            first.display_hash(),
            sizes[0],
        ),
        (
            u64::from(height) + 1,
            second.raw_hex(),
            second.display_hash(),
            sizes[1],
        ),
    ];
    let (url, _) = serve(
        Router::new()
            .route("/", post(answer))
            .with_state(node.clone()),
    )
    .await;
    (
        NodeClient::new(url, None).unwrap(),
        vec![first, second],
        node,
    )
}

#[tokio::test]
async fn batches_extend_the_saved_chain_and_match_the_tree_size() {
    let height = Network::Mainnet.ironwood_activation();
    let previous = Checkpoint {
        height: height - 1,
        hash: [2; 32],
        position: 0,
    };
    let (rpc, blocks, _) = chain([2, 3]).await;
    assert_eq!(rpc.receiver_boundary(height).await.unwrap().position, 2);
    let read = rpc.receiver_batch(&previous, 2, 2).await.unwrap();
    assert_eq!(read.len(), 2);
    assert_eq!((read[0].start_position, read[0].end_position), (0, 2));
    assert_eq!((read[1].start_position, read[1].end_position), (2, 3));
    assert_eq!(read[0].payments.len(), 1);
    assert!(read[1].payments.is_empty());
    assert_eq!(read[1].parent, blocks[0].hash());
    // A tree size that disagrees with the Actions, a chain from another parent and
    // out-of-range limits are refused before anything is returned.
    let (rpc, _, _) = chain([2, 4]).await;
    assert!(matches!(
        rpc.receiver_batch(&previous, 2, 2).await,
        Err(NodeError::Block(_))
    ));
    let (rpc, _, _) = chain([2, 3]).await;
    let other = Checkpoint {
        hash: [9; 32],
        ..previous.clone()
    };
    assert!(rpc.receiver_batch(&other, 2, 2).await.is_err());
    for (count, concurrency) in [(0, 1), (65, 1), (1, 0), (1, 17)] {
        assert!(
            rpc.receiver_batch(&previous, count, concurrency)
                .await
                .is_err()
        );
    }
}

/// A served block whose transactions do not match its header is refused.
#[tokio::test]
async fn transactions_must_match_the_header() {
    let height = Network::Mainnet.ironwood_activation();
    let (rpc, blocks, node) = chain([2, 3]).await;
    // The second block's header, which commits to its coinbase alone, over the same
    // coinbase and the refund: the height and parent still match.
    let full = RefundBlock::new(height + 1);
    let mut raw = hex::decode(blocks[1].raw_hex()).unwrap()[..1487].to_vec();
    raw.extend_from_slice(&full.bytes()[1487..]);
    node.blocks.lock().unwrap()[2].1 = hex::encode(raw);
    let previous = Checkpoint {
        height: height - 1,
        hash: [2; 32],
        position: 0,
    };
    assert!(matches!(
        rpc.receiver_batch(&previous, 2, 1).await,
        Err(NodeError::Block(message)) if message.contains("do not match its header")
    ));
}
