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
    // The refund alone, as a node's tree over its one Action would root it.
    let refund = zakura_server_chain::testing::Tx::from_bytes(
        &hex::decode(zakura_server_chain::testing::RECEIVER_REFUND_HEX.trim()).unwrap(),
    );
    assert_eq!(refund.txid(), b.txids()[1]);
    assert_ne!(
        zakura_server_chain::testing::ironwood_root_of(&[refund]),
        zakura_server_chain::testing::receiver::ironwood_root(&[&b])
    );
    assert_eq!(indexed.payments.len(), 1);
    let (receiver, p) = &indexed.payments[0];
    // Services can pass the canonical record directly to the receiver codec.
    let p: &zakura_receiver_crypto::wire::Payment = p;
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

/// Four consecutive refund blocks from 3,496,114, each after the last, read at most
/// two at a time; each fault breaks one rule and must fail the whole batch before
/// anything is returned.
#[tokio::test]
async fn concurrent_batches_reject_gaps_forks_and_wrong_positions() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Clone)]
    struct BatchRpc {
        blocks: Arc<Vec<RefundBlock>>,
        fault: u8,
        calls: Arc<AtomicUsize>,
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }
    async fn handler(State(s): State<BatchRpc>, Json(r): Json<Value>) -> Json<Value> {
        let call = s.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let terminal = s.blocks.last().unwrap().display_hash();
        let result = match r["method"].as_str().unwrap() {
            "getblockhash" => {
                if s.fault == 4 || (s.fault == 7 && call == 7) {
                    json!("00".repeat(32))
                } else {
                    json!(terminal)
                }
            }
            "getblock" if r["params"][1] == 1 => {
                assert_eq!(
                    r["params"][0],
                    if s.fault == 4 {
                        "00".repeat(32)
                    } else {
                        terminal
                    }
                );
                json!({"trees":{"ironwood":{"size":if s.fault == 3 {209} else {208}}}})
            }
            "getblock" => {
                assert_eq!(r["params"][1], 0);
                let height: usize = r["params"][0].as_str().unwrap().parse().unwrap();
                let i = height - 3496114;
                let active = s.active.fetch_add(1, Ordering::SeqCst) + 1;
                s.peak.fetch_max(active, Ordering::SeqCst);
                // Force responses out of order while also observing the concurrency bound.
                tokio::time::sleep(std::time::Duration::from_millis(if i.is_multiple_of(2) {
                    30
                } else {
                    5
                }))
                .await;
                s.active.fetch_sub(1, Ordering::SeqCst);
                if s.fault == 6 && i == 1 {
                    return Json(
                        json!({"result":null,"error":{"code":-8,"message":"missing block"}}),
                    );
                }
                let mut raw = s.blocks[i].bytes();
                if s.fault == 5 && i == 1 {
                    raw.push(1);
                }
                json!(hex::encode(raw))
            }
            _ => panic!("unexpected method"),
        };
        Json(json!({"result":result,"error":null}))
    }
    for fault in 0..=8 {
        let mut blocks = Vec::new();
        let mut parent = [0; 32];
        for i in 0..4u32 {
            let mut b = RefundBlock::new(3496114 + i + u32::from(fault == 2 && i == 1));
            // A transaction changed under its header no longer matches its merkle root.
            if fault == 8 && i == 1 {
                b = b.tampered();
            }
            b = b.after(if fault == 1 && i == 1 {
                [99; 32]
            } else {
                parent
            });
            parent = b.hash();
            blocks.push(b);
        }
        let state = BatchRpc {
            blocks: Arc::new(blocks),
            fault,
            calls: Arc::new(AtomicUsize::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
        };
        let (url, task) = serve(
            Router::new()
                .route("/", post(handler))
                .with_state(state.clone()),
        )
        .await;
        let client = NodeClient::new(url, None).unwrap();
        let previous = Checkpoint {
            height: 3496113,
            hash: [0; 32],
            position: 200,
        };
        for (count, concurrency) in [(0, 2), (65, 2), (4, 0), (4, 17)] {
            assert!(
                client
                    .receiver_batch(&previous, count, concurrency)
                    .await
                    .is_err()
            );
        }
        assert_eq!(state.calls.load(Ordering::SeqCst), 0);
        let result = client.receiver_batch(&previous, 4, 2).await;
        assert_eq!(result.is_err(), fault != 0, "fault={fault}");
        assert_eq!(state.peak.load(Ordering::SeqCst), 2);
        if let Ok(indexed) = result {
            assert_eq!(indexed.len(), 4);
            // Four raw-block requests plus three terminal checks, rather than 20 requests.
            assert_eq!(state.calls.load(Ordering::SeqCst), 7);
            for (i, b) in indexed.iter().enumerate() {
                let expected = extract_block(
                    &state.blocks[i].bytes(),
                    3496114 + i as u32,
                    202 + i as u64 * 2,
                )
                .unwrap();
                assert_eq!(b.payments, expected.payments);
                assert_eq!(b.start_position, 200 + i as u64 * 2);
                assert_eq!(b.coinbase_actions, 1);
            }
        }
        task.abort();
    }
}
