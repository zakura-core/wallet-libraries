//! Status blocks and mempools read through a node double.
use axum::{Json, Router, extract::State, routing::post};
use serde_json::{Value, json};
use zakura_server_chain::{
    NodeClient, NodeError,
    testing::{serve, status::regtest_genesis},
};

#[derive(Clone)]
struct Mock {
    raw: String,
    hash: String,
    txid: String,
}

async fn answer(State(mock): State<Mock>, Json(r): Json<Value>) -> Json<Value> {
    let result = match r["method"].as_str().unwrap() {
        "getblockhash" => json!(mock.hash),
        "getblock" => json!(mock.raw),
        "getrawmempool" => json!([mock.txid]),
        method => panic!("unexpected {method}"),
    };
    Json(json!({"result": result, "error": null}))
}

async fn client(mock: Mock) -> NodeClient {
    let (url, _) = serve(Router::new().route("/", post(answer)).with_state(mock)).await;
    let dir = std::env::temp_dir().join(format!(
        "status-{}-{}",
        std::process::id(),
        url.rsplit(':').next().unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cookie"), "user:password").unwrap();
    NodeClient::from_cookie_file(url, dir.join("cookie")).unwrap()
}

#[tokio::test]
async fn canonical_blocks_list_every_transaction_in_protocol_order() {
    let (raw, hash, txid) = regtest_genesis();
    let rpc = client(Mock {
        raw: raw.clone(),
        hash: hash.clone(),
        txid: txid.clone(),
    })
    .await;
    let block = rpc.status_block(1).await.unwrap();
    assert_eq!(zakura_server_chain::hash::display(&block.hash), hash);
    assert_eq!(block.height, 1);
    assert_eq!(block.parent, [0; 32]);
    let txid = zakura_server_chain::hash::parse_display(&txid).unwrap();
    assert_eq!(block.txids, [txid]);
    assert_eq!(rpc.status_mempool().await.unwrap(), [txid]);
    // A block other than the node's canonical one at its height is refused.
    let rpc = client(Mock {
        raw,
        hash: "00".repeat(32),
        txid: "zz".into(),
    })
    .await;
    assert!(matches!(
        rpc.status_block(1).await,
        Err(NodeError::Block(_))
    ));
    assert!(matches!(
        rpc.status_mempool().await,
        Err(NodeError::Block(_))
    ));
}
