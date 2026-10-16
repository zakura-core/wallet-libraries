//! Exact fees of mixed transactions through the real read path: serialized blocks and
//! transactions served by a JSON-RPC node double.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zakura_server_chain::{
    FeeError, Network, NodeClient, NodeError,
    enhance::{EnhanceAction, Prevouts, raw_transaction_actions},
    testing::*,
};

struct Node {
    chain: SharedChain,
    client: NodeClient,
    _dir: std::path::PathBuf,
    _task: tokio::task::JoinHandle<()>,
}

async fn node() -> Node {
    let chain: SharedChain = Arc::new(Mutex::new(Chain::default()));
    let (url, task) = serve_chain(chain.clone()).await;
    let dir = std::env::temp_dir().join(format!(
        "enhance-node-{}-{}",
        std::process::id(),
        url.rsplit(':').next().unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let client = NodeClient::from_cookie_file(url, cookie(&dir)).unwrap();
    Node {
        chain,
        client,
        _dir: dir,
        _task: task,
    }
}

impl Node {
    /// Publishes `previous` as fetchable chain history outside any served block.
    fn history(&self, previous: &[&Tx]) {
        let mut chain = self.chain.lock().unwrap();
        for tx in previous {
            chain.add_transaction(tx);
        }
    }

    async fn actions(
        &self,
        height: u64,
        transactions: &[Tx],
        prevouts: &Prevouts,
    ) -> Result<Vec<EnhanceAction>, NodeError> {
        self.chain
            .lock()
            .unwrap()
            .push_block(height, transactions, height as u8);
        self.client
            .enhance_block(height, prevouts)
            .await
            .map(|b| b.actions)
    }
}

fn fee_and_flags(action: &EnhanceAction) -> (Option<u64>, bool, bool) {
    (
        action.fee_zatoshis,
        action.has_transparent_inputs,
        action.has_transparent_outputs,
    )
}

/// Asserts `action` carries the fixture's Action `index`, sliced from the raw
/// transaction at the offsets the independent oracle records.
fn assert_fixture_action(action: &EnhanceAction, index: usize) {
    let raw = hex::decode(IRONWOOD_FIXTURE_HEX.trim()).unwrap();
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/ironwood-record-oracle.json")).unwrap();
    let at = |field: &str, length: usize| {
        let start = oracle["records"][index]["raw_offsets"][field]
            .as_u64()
            .unwrap() as usize;
        raw[start..start + length].to_vec()
    };
    assert_eq!(
        action.enc_ciphertext_suffix.to_vec(),
        at("enc_ciphertext", 580)[52..]
    );
    assert_eq!(action.cv_net.to_vec(), at("cv_net", 32));
    assert_eq!(action.out_ciphertext.to_vec(), at("out_ciphertext", 80));
    assert_eq!(action.expiry_height, 3483371);
}

fn h() -> u64 {
    u64::from(Network::Mainnet.ironwood_activation())
}

#[test]
fn the_fixture_matches_its_independent_oracle() {
    let raw = hex::decode(IRONWOOD_FIXTURE_HEX.trim()).unwrap();
    let actions = raw_transaction_actions(&raw, &HashMap::new()).unwrap();
    assert_eq!(actions.len(), 2);
    for (i, action) in actions.iter().enumerate() {
        assert_fixture_action(action, i);
        assert_eq!(fee_and_flags(action), (Some(10_000), false, false));
    }
    // A transparent spend needs its spent output's value.
    let a = funding(1, &[420_000]);
    let tx = Mixed::new(vec![spend(&a, 0)], &[], -400_000).build();
    assert!(matches!(
        raw_transaction_actions(&tx.bytes(), &HashMap::new()),
        Err(NodeError::Fee(_, FeeError::MissingPrevout(_)))
    ));
    let spent = HashMap::from([((a.txid(), 0), 420_000)]);
    let actions = raw_transaction_actions(&tx.bytes(), &spent).unwrap();
    assert!(
        actions
            .iter()
            .all(|a| fee_and_flags(a) == (Some(20_000), true, false))
    );
}

#[tokio::test]
async fn transparent_spends_into_ironwood_publish_the_whole_fee() {
    let node = node().await;
    let prevouts = Prevouts::new(1000);
    let a = funding(1, &[420_000]);
    let b = funding(2, &[200_000]);
    node.history(&[&a, &b]);
    let first = Mixed::new(vec![spend(&a, 0)], &[], -400_000).build();
    let second = Mixed::new(vec![spend(&b, 0)], &[], -180_000).build();
    let actions = node
        .actions(h(), &[first, second], &prevouts)
        .await
        .unwrap();
    assert_eq!(actions.len(), 4);
    for (i, action) in actions.iter().enumerate() {
        assert_eq!(fee_and_flags(action), (Some(20_000), true, false));
        assert_fixture_action(action, i % 2);
    }
    let chain = node.chain.lock().unwrap();
    // Both previous transactions came from one batch.
    assert_eq!(chain.batches, 1);
    assert_eq!(chain.count("getrawtransaction"), 2);
    assert_eq!(prevouts.counts().fetched_transactions, 2);
}

#[tokio::test]
async fn multiple_inputs_with_transparent_change() {
    let node = node().await;
    let prevouts = Prevouts::new(1000);
    let a = funding(1, &[300_000, 7]);
    let b = funding(2, &[150_000]);
    node.history(&[&a, &b]);
    // 450,000 in; 100,000 transparent change; 330,000 into Ironwood.
    let tx = Mixed::new(vec![spend(&a, 0), spend(&b, 0)], &[100_000], -330_000).build();
    let actions = node.actions(h(), &[tx], &prevouts).await.unwrap();
    for action in &actions {
        assert_eq!(fee_and_flags(action), (Some(20_000), true, true));
    }
}

#[tokio::test]
async fn same_block_and_cached_outputs_need_no_lookup() {
    let node = node().await;
    let prevouts = Prevouts::new(1000);
    let a = funding(1, &[420_000, 50_000]);
    let spends_a = Mixed::new(vec![spend(&a, 0)], &[], -400_000).build();
    let actions = node
        .actions(h(), &[a.clone(), spends_a], &prevouts)
        .await
        .unwrap();
    assert!(
        actions
            .iter()
            .all(|r| fee_and_flags(r) == (Some(20_000), true, false))
    );
    // A later block spends the earlier block's other output from the cache.
    let later = Mixed::new(vec![spend(&a, 1)], &[], -45_000).build();
    let actions = node.actions(h() + 1, &[later], &prevouts).await.unwrap();
    assert!(
        actions
            .iter()
            .all(|r| fee_and_flags(r) == (Some(5_000), true, false))
    );
    assert_eq!(node.chain.lock().unwrap().count("getrawtransaction"), 0);
    let counts = prevouts.counts();
    assert_eq!((counts.same_block_hits, counts.cache_hits), (1, 1));
}

#[tokio::test]
async fn pure_ironwood_fixture_keeps_its_fee_without_extra_rpc() {
    let node = node().await;
    let prevouts = Prevouts::new(1000);
    let block = {
        node.chain
            .lock()
            .unwrap()
            .push_block(h(), &[ironwood_fixture()], 0);
        node.client.enhance_block(h(), &prevouts).await.unwrap()
    };
    assert_eq!(block.actions.len(), 2);
    assert_eq!(block.tree_size, 2);
    for (i, action) in block.actions.iter().enumerate() {
        assert_fixture_action(action, i);
    }
    assert_eq!(
        fee_and_flags(&block.actions[0]),
        (Some(10_000), false, false)
    );
    let chain = node.chain.lock().unwrap();
    assert_eq!(chain.batches, 0);
    assert_eq!(chain.calls, ["getblock", "getblock"]);
    assert_eq!(
        zakura_server_chain::hash::display(&block.hash),
        chain.blocks[&h()].1
    );
}

#[tokio::test]
async fn orchard_and_ironwood_together() {
    let node = node().await;
    let prevouts = Prevouts::new(1000);
    let a = funding(1, &[100_000]);
    node.history(&[&a]);
    // 100,000 transparent and 50,000 from Orchard; 130,000 into Ironwood.
    let mut mixed = Mixed::new(vec![spend(&a, 0)], &[], -130_000);
    mixed.orchard = Some(50_000);
    let actions = node
        .actions(h(), &[mixed.build()], &prevouts)
        .await
        .unwrap();
    assert_eq!(actions.len(), 2, "only Ironwood actions become actions");
    for (i, action) in actions.iter().enumerate() {
        assert_eq!(fee_and_flags(action), (Some(20_000), true, false));
        assert_fixture_action(action, i);
    }
    // Without transparent inputs, a shielded-only mixed transaction needs no lookup.
    let mut shielded = Mixed::new(vec![], &[], -40_000);
    shielded.orchard = Some(60_000);
    let actions = node
        .actions(h() + 1, &[shielded.build()], &prevouts)
        .await
        .unwrap();
    assert_eq!(fee_and_flags(&actions[0]), (Some(20_000), false, false));
    assert_eq!(node.chain.lock().unwrap().count("getrawtransaction"), 1);
}

#[tokio::test]
async fn sapling_and_ironwood_together() {
    let node = node().await;
    let prevouts = Prevouts::new(1000);
    let a = funding(1, &[70_000]);
    node.history(&[&a]);
    // 70,000 transparent and 30,000 from Sapling; 80,000 into Ironwood.
    let mut mixed = Mixed::new(vec![spend(&a, 0)], &[], -80_000);
    mixed.sapling = Some(30_000);
    let tx = mixed.build();
    assert!(tx.has_sapling_outputs());
    let actions = node.actions(h(), &[tx], &prevouts).await.unwrap();
    for action in &actions {
        assert_eq!(fee_and_flags(action), (Some(20_000), true, false));
    }
}

#[tokio::test]
async fn coinbase_has_no_fee_and_needs_no_lookup() {
    let node = node().await;
    let prevouts = Prevouts::new(1000);
    let actions = node
        .actions(h(), &[ironwood_coinbase(h() as u32)], &prevouts)
        .await
        .unwrap();
    assert_eq!(actions.len(), 2);
    for (i, action) in actions.iter().enumerate() {
        // The coinbase input counts as a transparent input, as before.
        assert_eq!(fee_and_flags(action), (None, true, true));
        assert_fixture_action(action, i);
    }
    assert_eq!(node.chain.lock().unwrap().batches, 0);
}

async fn failure(previous: &[&Tx], tx: Tx, fault: Option<BatchFault>) -> NodeError {
    let node = node().await;
    node.history(previous);
    node.chain.lock().unwrap().fault = fault;
    node.actions(h(), &[tx], &Prevouts::new(1000))
        .await
        .expect_err("block must fail rather than publish a partial fee")
}

#[tokio::test]
async fn unresolvable_or_invalid_inputs_fail_the_block() {
    let a = funding(1, &[420_000]);
    let spends_a = || Mixed::new(vec![spend(&a, 0)], &[], -400_000).build();
    assert!(matches!(
        failure(&[], spends_a(), None).await,
        NodeError::MissingTransaction(txid) if txid == a.txid_display()
    ));
    assert!(matches!(
        failure(
            &[&a],
            Mixed::new(vec![spend(&a, 1)], &[], -400_000).build(),
            None
        )
        .await,
        NodeError::PrevoutIndex { outputs: 1, .. }
    ));
    assert!(matches!(
        failure(&[&a], spends_a(), Some(BatchFault::EntryError(-5))).await,
        NodeError::MissingTransaction(_)
    ));
    assert!(matches!(
        failure(&[&a], spends_a(), Some(BatchFault::EntryError(-32603))).await,
        NodeError::Rpc(-32603, _)
    ));
    assert!(matches!(
        failure(&[&a], spends_a(), Some(BatchFault::WholeBatchError)).await,
        NodeError::Rpc(-32600, _)
    ));
    for fault in [
        BatchFault::Short,
        BatchFault::DuplicateId,
        BatchFault::OutOfRangeId,
    ] {
        let b = funding(2, &[1]);
        let two = Mixed::new(vec![spend(&a, 0), spend(&b, 0)], &[], -400_000).build();
        assert!(
            matches!(
                failure(&[&a, &b], two, Some(fault)).await,
                NodeError::Batch(_)
            ),
            "{fault:?}"
        );
    }
    let other = funding(3, &[5]);
    assert!(matches!(
        failure(&[&other], spends_a(), Some(BatchFault::WrongTransaction)).await,
        NodeError::Transaction(..)
    ));
    assert!(matches!(
        failure(
            &[&a],
            Mixed::new(vec![spend(&a, 0), spend(&a, 0)], &[], -400_000).build(),
            None
        )
        .await,
        NodeError::Fee(_, FeeError::DuplicateInput(_))
    ));
    assert!(matches!(
        failure(
            &[&a],
            Mixed::new(vec![spend(&a, 0)], &[30_000], -400_000).build(),
            None
        )
        .await,
        NodeError::Fee(_, FeeError::Negative(_))
    ));
}

/// Block hashes are read in JSON-RPC 2.0 batches and returned in protocol order.
#[tokio::test]
async fn block_hashes_are_batched_in_protocol_order() {
    let node = node().await;
    let displayed: Vec<_> = (0..3u64)
        .map(|i| {
            node.chain
                .lock()
                .unwrap()
                .push_block(h() + i, &[funding(i as u8 + 1, &[1])], i as u8)
        })
        .collect();
    let hashes = node
        .client
        .block_hashes(&[h(), h() + 1, h() + 2])
        .await
        .unwrap();
    let shown: Vec<_> = hashes
        .iter()
        .map(zakura_server_chain::hash::display)
        .collect();
    assert_eq!(shown, displayed);
    assert_eq!(node.chain.lock().unwrap().batches, 1);
    assert!(matches!(
        node.client.block_hashes(&[h() + 3]).await,
        Err(NodeError::Rpc(-8, _))
    ));
}

/// A height can name a different block between the raw and verbose reads. The
/// returned actions and tree position must still describe the same block.
#[tokio::test]
async fn reorg_between_actions_and_tree_size_keeps_one_block_identity() {
    use axum::{Json, Router, routing::post};
    use serde_json::{Value, json};
    let (raw, displayed) = block(&[ironwood_fixture()], 41);
    let expected_hash = zakura_server_chain::hash::parse_display(&displayed).unwrap();
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let (raw, displayed) = (raw.clone(), displayed.clone());
            async move {
                let result = match request["method"].as_str().unwrap() {
                    "getblock" if request["params"][1] == 0 => json!(raw),
                    "getblock" => {
                        // The old block still has two actions. At this height the new
                        // canonical block now has an unrelated tree size.
                        let size = if request["params"][0] == displayed {
                            2
                        } else {
                            99
                        };
                        json!({"trees": {"ironwood": {"size": size}}})
                    }
                    method => panic!("unexpected RPC {method}"),
                };
                Json(json!({"result": result, "error": null}))
            }
        }),
    );
    let (url, task) = serve(app).await;
    let rpc = NodeClient::new(url, None).unwrap();
    let result = rpc.enhance_block(h(), &Prevouts::new(0)).await.unwrap();
    assert_eq!(result.hash, expected_hash);
    assert_eq!(result.actions.len(), 2);
    assert_eq!(
        result.tree_size, 2,
        "tree size must belong to the returned block"
    );
    task.abort();
}
