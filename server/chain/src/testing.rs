//! Synthetic chain fixtures for tests of this crate and of the services that use it,
//! built with the node's own encoders so the services need no node dependency.
//!
//! Transactions keep a public mainnet Ironwood transaction's two Actions and replace
//! its value balance and transparent parts. Values are hand-set, so expected fees are
//! independent of the code under test. Block envelopes have zero roots and invalid
//! proof-of-work: the reads under test trust consensus to the node, so they neither
//! check nor need them. Proofs and signatures are not valid either.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::HeaderMap, http::StatusCode, routing::post};
use serde_json::{Value, json};
use zakura_chain::amount::Amount;
use zakura_chain::block::{Block, Height};
use zakura_chain::serialization::{ZcashDeserialize, ZcashSerialize};
use zakura_chain::transaction::{self, LockTime, Transaction};
use zakura_chain::transparent::{Input, OutPoint, Output, Script};

/// The public Ironwood transaction with a fee of 10,000 and expiry height 3,483,371;
/// see `tests/fixtures/ironwood-fee-expiry.md`.
pub const IRONWOOD_FIXTURE_HEX: &str = include_str!("../tests/fixtures/ironwood-fee-expiry.hex");
/// A public mainnet refund paying a receiver recoverable with the zero outgoing
/// viewing key.
pub const RECEIVER_REFUND_HEX: &str = include_str!("../tests/fixtures/receiver-refund.hex");
/// A public mainnet V5 Sapling transaction; see `tests/fixtures/sapling-v5-1687106.md`.
const SAPLING_FIXTURE_HEX: &str = include_str!("../tests/fixtures/sapling-v5-1687106.hex");

/// A synthetic transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx(Transaction);

impl Tx {
    /// The transaction serialized in `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Transaction::zcash_deserialize(bytes).expect("a serialized transaction"))
    }

    /// The serialized transaction.
    pub fn bytes(&self) -> Vec<u8> {
        self.0.zcash_serialize_to_vec().expect("serializable")
    }

    /// The serialized transaction, as hex, as `getrawtransaction` answers.
    pub fn raw_hex(&self) -> String {
        hex::encode(self.bytes())
    }

    /// The transaction ID in protocol byte order.
    pub fn txid(&self) -> [u8; 32] {
        self.0.hash().0
    }

    /// The transaction ID in RPC display order.
    pub fn txid_display(&self) -> String {
        self.0.hash().to_string()
    }

    /// The number of Ironwood Actions.
    pub fn ironwood_actions(&self) -> u64 {
        self.0.ironwood_actions().count() as u64
    }

    /// The Ironwood Actions' note commitments, in order.
    pub fn ironwood_commitments(&self) -> Vec<[u8; 32]> {
        self.0.ironwood_actions().map(|a| a.cm_x.into()).collect()
    }

    /// Whether the transaction has a Sapling output.
    pub fn has_sapling_outputs(&self) -> bool {
        self.0.sapling_outputs().next().is_some()
    }
}

/// A transparent input of a synthetic transaction.
#[derive(Clone, Debug)]
pub struct Spend(Input);

/// Serializes and parses back, as the node and the code under test see it.
fn reparse(transaction: Transaction) -> Tx {
    Tx::from_bytes(&transaction.zcash_serialize_to_vec().unwrap())
}

fn output(value: i64) -> Output {
    Output {
        value: Amount::try_from(value).unwrap(),
        // A non-standard test script; no real address is encoded.
        lock_script: Script::new(&[0x51]),
    }
}

/// The public Ironwood fixture transaction.
pub fn ironwood_fixture() -> Tx {
    Tx::from_bytes(&hex::decode(IRONWOOD_FIXTURE_HEX.trim()).unwrap())
}

/// Spends output `index` of `previous`.
pub fn spend(previous: &Tx, index: u32) -> Spend {
    spend_outpoint(previous.txid(), index)
}

/// Spends output `index` of the transaction `txid` (protocol byte order).
pub fn spend_outpoint(txid: [u8; 32], index: u32) -> Spend {
    Spend(Input::PrevOut {
        outpoint: OutPoint {
            hash: transaction::Hash(txid),
            index,
        },
        unlock_script: Script::new(&[0x51]),
        sequence: u32::MAX,
    })
}

/// A transparent V4 transaction paying `values`. Its own input refers to an
/// arbitrary `seed` outpoint that is never resolved.
pub fn funding(seed: u8, values: &[i64]) -> Tx {
    reparse(Transaction::V4 {
        inputs: vec![spend_outpoint([seed; 32], 0).0],
        outputs: values.iter().copied().map(output).collect(),
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        joinsplit_data: None,
        sapling_shielded_data: None,
    })
}

/// A V6 transaction with the fixture's Ironwood Actions and the given transparent
/// parts and value balances.
pub struct Mixed {
    pub inputs: Vec<Spend>,
    pub outputs: Vec<i64>,
    pub ironwood: i64,
    /// Orchard value balance; the fixture's Ironwood bundle is reused as the
    /// Orchard bundle since both pools share one encoding.
    pub orchard: Option<i64>,
    /// Sapling value balance of the public Sapling fixture's bundle.
    pub sapling: Option<i64>,
}

impl Mixed {
    pub fn new(inputs: Vec<Spend>, outputs: &[i64], ironwood: i64) -> Self {
        Self {
            inputs,
            outputs: outputs.to_vec(),
            ironwood,
            orchard: None,
            sapling: None,
        }
    }

    pub fn build(self) -> Tx {
        let Transaction::V6 {
            network_upgrade,
            lock_time,
            expiry_height,
            mut ironwood_shielded_data,
            ..
        } = ironwood_fixture().0
        else {
            panic!("fixture is V6");
        };
        let ironwood = ironwood_shielded_data.as_mut().unwrap();
        ironwood.value_balance = Amount::try_from(self.ironwood).unwrap();
        let orchard_shielded_data = self.orchard.map(|value| {
            let mut orchard = ironwood.clone();
            // Ironwood's cross-address flag is reserved in the Orchard pool.
            orchard.flags = zakura_chain::orchard::Flags::ENABLE_SPENDS
                | zakura_chain::orchard::Flags::ENABLE_OUTPUTS;
            orchard.value_balance = Amount::try_from(value).unwrap();
            orchard
        });
        let sapling_shielded_data = self.sapling.map(|value| {
            let raw = hex::decode(SAPLING_FIXTURE_HEX.trim()).unwrap();
            let Transaction::V5 {
                sapling_shielded_data: Some(mut sapling),
                ..
            } = Transaction::zcash_deserialize(raw.as_slice()).unwrap()
            else {
                panic!("fixture is a V5 Sapling transaction");
            };
            sapling.value_balance = Amount::try_from(value).unwrap();
            sapling
        });
        reparse(Transaction::V6 {
            network_upgrade,
            lock_time,
            expiry_height,
            inputs: self.inputs.into_iter().map(|spend| spend.0).collect(),
            outputs: self.outputs.into_iter().map(output).collect(),
            sapling_shielded_data,
            orchard_shielded_data,
            ironwood_shielded_data,
        })
    }
}

/// A coinbase transaction at `height` carrying the fixture's Ironwood Actions.
pub fn ironwood_coinbase(height: u32) -> Tx {
    let Transaction::V6 {
        network_upgrade,
        lock_time,
        expiry_height,
        mut ironwood_shielded_data,
        ..
    } = ironwood_fixture().0
    else {
        panic!("fixture is V6");
    };
    ironwood_shielded_data.as_mut().unwrap().value_balance = Amount::try_from(-50_000).unwrap();
    reparse(Transaction::V6 {
        network_upgrade,
        lock_time,
        expiry_height,
        inputs: vec![Input::Coinbase {
            height: Height(height),
            data: vec![0x51; 4],
            sequence: u32::MAX,
        }],
        outputs: vec![output(100_000)],
        sapling_shielded_data: None,
        orchard_shielded_data: None,
        ironwood_shielded_data,
    })
}

/// A synthetic block envelope around the serialized transactions `transactions`:
/// zero roots, and `nonce` distinguishes hashes. Returns the raw block hex, as
/// `getblock` answers at verbosity zero, and its hash in display order.
pub fn block_from_raw(transactions: &[Vec<u8>], nonce: u8) -> (String, String) {
    let mut raw = vec![0u8; 140];
    raw[..4].copy_from_slice(&4u32.to_le_bytes());
    raw[108] = nonce;
    raw.extend_from_slice(&[0xfd, 0x40, 0x05]);
    raw.extend_from_slice(&[0; 1344]);
    assert!(transactions.len() < 0xfd);
    raw.push(transactions.len() as u8);
    for transaction in transactions {
        raw.extend_from_slice(transaction);
    }
    let parsed = Block::zcash_deserialize(raw.as_slice()).unwrap();
    (hex::encode(raw), parsed.hash().to_string())
}

/// [`block_from_raw`] for synthetic transactions.
pub fn block(transactions: &[Tx], nonce: u8) -> (String, String) {
    block_from_raw(
        &transactions.iter().map(Tx::bytes).collect::<Vec<_>>(),
        nonce,
    )
}

/// Fault injected into JSON-RPC 2.0 batch responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchFault {
    None,
    /// Answer the batch with one error object.
    WholeBatchError,
    /// Drop the last entry.
    Short,
    /// Repeat the first id.
    DuplicateId,
    /// Echo an id past the batch.
    OutOfRangeId,
    /// Answer every transaction with this RPC error code.
    EntryError(i64),
    /// Return a different transaction than requested.
    WrongTransaction,
}

/// A JSON-RPC node double's chain.
#[derive(Default)]
pub struct Chain {
    /// Height to (raw block hex, display hash, Ironwood tree size after it).
    pub blocks: HashMap<u64, (String, String, u64)>,
    pub tip: u64,
    /// Display txid to raw transaction hex.
    pub transactions: HashMap<String, String>,
    pub fault: Option<BatchFault>,
    /// Heights whose `getblock` is held until released.
    pub hold: Option<u64>,
    /// Method names in request order; a batch records each entry.
    pub calls: Vec<String>,
    /// Count of HTTP requests that were batches.
    pub batches: usize,
    /// `getblock` requests as (height, verbosity).
    pub getblocks: Vec<(u64, u64)>,
}

impl Chain {
    pub fn add_transaction(&mut self, transaction: &Tx) {
        self.transactions
            .insert(transaction.txid_display(), transaction.raw_hex());
    }

    /// Appends a block at `height` holding `transactions`. Returns its display hash.
    pub fn push_block(&mut self, height: u64, transactions: &[Tx], nonce: u8) -> String {
        let previous = self.blocks.get(&(height - 1)).map_or(0, |block| block.2);
        let actions: u64 = transactions.iter().map(Tx::ironwood_actions).sum();
        let (raw, hash) = block(transactions, nonce);
        for transaction in transactions {
            self.add_transaction(transaction);
        }
        self.blocks
            .insert(height, (raw, hash.clone(), previous + actions));
        self.tip = self.tip.max(height);
        hash
    }

    pub fn count(&self, method: &str) -> usize {
        self.calls.iter().filter(|call| *call == method).count()
    }
}

pub type SharedChain = Arc<Mutex<Chain>>;

fn answer(chain: &mut Chain, request: &Value) -> Value {
    let method = request["method"].as_str().unwrap().to_string();
    chain.calls.push(method.clone());
    let id = request["id"].clone();
    let error = |code: i64, message: &str| json!({"result": null, "error": {"code": code, "message": message}, "id": id});
    let height = |value: &Value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
            .unwrap()
    };
    let result = match method.as_str() {
        "getblockcount" => json!(chain.tip),
        "getblockhash" => match chain.blocks.get(&height(&request["params"][0])) {
            Some(block) => json!(block.1),
            None => return error(-8, "Block height out of range"),
        },
        "getblock" => {
            let requested = height(&request["params"][0]);
            let verbosity = request["params"][1].as_u64().unwrap();
            chain.getblocks.push((requested, verbosity));
            let Some(block) = chain.blocks.get(&requested) else {
                return error(-8, "Block height out of range");
            };
            match verbosity {
                0 => json!(block.0),
                2 => json!({"trees": {"ironwood": {"size": block.2}}}),
                _ => panic!("unexpected verbosity"),
            }
        }
        "getrawtransaction" => {
            assert_eq!(request["params"][1], 0);
            if let Some(BatchFault::EntryError(code)) = chain.fault {
                return error(code, "injected");
            }
            if chain.fault == Some(BatchFault::WrongTransaction) {
                json!(chain.transactions.values().next().unwrap())
            } else {
                match chain
                    .transactions
                    .get(request["params"][0].as_str().unwrap())
                {
                    Some(raw) => json!(raw),
                    None => return error(-5, "No such mempool or main chain transaction"),
                }
            }
        }
        other => panic!("unexpected RPC method {other}"),
    };
    json!({"result": result, "error": null, "id": id})
}

/// The public, test-only credential the node double accepts; see [`cookie`].
const TEST_AUTHORIZATION: &str = "Basic dGVzdDp0ZXN0";

async fn handle(
    State(chain): State<SharedChain>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(TEST_AUTHORIZATION) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let hold = chain.lock().unwrap().hold;
    if let (Some(hold), Some("getblock")) = (hold, request["method"].as_str())
        && request["params"][0].as_str() == Some(hold.to_string().as_str())
    {
        while chain.lock().unwrap().hold == Some(hold) {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
    let mut chain = chain.lock().unwrap();
    let Value::Array(requests) = request else {
        assert_eq!(
            request["jsonrpc"], "1.0",
            "single calls stay on JSON-RPC 1.0"
        );
        return Ok(Json(answer(&mut chain, &request)));
    };
    chain.batches += 1;
    let mut answers = Vec::new();
    for request in &requests {
        // The node rejects JSON-RPC 1.0 batches.
        assert_eq!(request["jsonrpc"], "2.0");
        answers.push(answer(&mut chain, request));
    }
    // Responses may arrive in any order; the client places them by id.
    answers.reverse();
    match chain.fault.unwrap_or(BatchFault::None) {
        BatchFault::WholeBatchError => {
            return Ok(Json(
                json!({"result": null, "error": {"code": -32600, "message": "batch refused"}, "id": null}),
            ));
        }
        BatchFault::Short => {
            answers.pop();
        }
        BatchFault::DuplicateId => {
            let id = answers[0]["id"].clone();
            answers.last_mut().unwrap()["id"] = id;
        }
        BatchFault::OutOfRangeId => answers[0]["id"] = json!(requests.len()),
        _ => {}
    }
    Ok(Json(Value::Array(answers)))
}

/// Serves `chain` as a JSON-RPC node at the returned URL.
pub async fn serve_chain(chain: SharedChain) -> (String, tokio::task::JoinHandle<()>) {
    serve(Router::new().route("/", post(handle)).with_state(chain)).await
}

/// Serves `router` on a local port at the returned URL.
pub async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", socket.local_addr().unwrap());
    (
        origin,
        tokio::spawn(async move {
            axum::serve(socket, router).await.unwrap();
        }),
    )
}

/// Writes a cookie file holding the public test credential into `dir`.
pub fn cookie(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("cookie");
    std::fs::write(&path, "test:test").unwrap();
    path
}

/// Receiver directory blocks around the public zero-OVK refund.
pub mod receiver {
    use super::*;

    /// A block holding a coinbase transaction with the refund's Ironwood Action,
    /// whose recipient the directory excludes, then the refund itself. Its header
    /// commits to its transactions.
    #[derive(Clone, Debug)]
    pub struct RefundBlock(Block);

    impl RefundBlock {
        /// The block at `height`, after the zero hash.
        pub fn new(height: u32) -> Self {
            let tx = Transaction::zcash_deserialize(
                hex::decode(RECEIVER_REFUND_HEX.trim()).unwrap().as_slice(),
            )
            .unwrap();
            let mut coinbase = tx.clone();
            match &mut coinbase {
                Transaction::V6 { inputs, .. } => {
                    *inputs = vec![Input::Coinbase {
                        height: Height(height),
                        data: vec![0],
                        sequence: u32::MAX,
                    }]
                }
                _ => panic!("expected V6"),
            }
            // Give the coinbase the same recoverable ciphertext to exercise its exclusion.
            let mut raw = vec![0u8; 140];
            raw[..4].copy_from_slice(&4u32.to_le_bytes());
            raw.extend_from_slice(&[0xfd, 0x40, 0x05]);
            raw.extend_from_slice(&[0; 1344]);
            raw.push(2);
            coinbase.zcash_serialize(&mut raw).unwrap();
            tx.zcash_serialize(&mut raw).unwrap();
            let mut block = Self(Block::zcash_deserialize(raw.as_slice()).unwrap());
            block.seal();
            block
        }

        /// Sets the header's merkle root to its transactions' root.
        fn seal(&mut self) {
            let root = self.0.transactions.iter().collect();
            Arc::make_mut(&mut self.0.header).merkle_root = root;
        }

        /// This block at `height`, its coinbase's height changed.
        pub fn at_height(mut self, height: u32) -> Self {
            match Arc::make_mut(&mut self.0.transactions[0]) {
                Transaction::V6 { inputs, .. } => match &mut inputs[0] {
                    Input::Coinbase { height: h, .. } => *h = Height(height),
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            }
            self.seal();
            self
        }

        /// This block after the block `parent` (protocol byte order).
        pub fn after(mut self, parent: [u8; 32]) -> Self {
            Arc::make_mut(&mut self.0.header).previous_block_hash =
                zakura_chain::block::Hash(parent);
            self
        }

        /// This block with only its coinbase transaction.
        pub fn coinbase_only(mut self) -> Self {
            self.0.transactions.truncate(1);
            self.seal();
            self
        }

        /// This block with another header nonce, so another hash, and the same
        /// transactions.
        pub fn renonced(mut self) -> Self {
            Arc::make_mut(&mut self.0.header).nonce[0] ^= 1;
            self
        }

        /// The serialized block.
        pub fn bytes(&self) -> Vec<u8> {
            self.0.zcash_serialize_to_vec().unwrap()
        }

        /// The serialized block, as hex, as `getblock` answers at verbosity zero.
        pub fn raw_hex(&self) -> String {
            hex::encode(self.bytes())
        }

        /// The block hash in protocol byte order.
        pub fn hash(&self) -> [u8; 32] {
            self.0.hash().0
        }

        /// The block hash in RPC display order.
        pub fn display_hash(&self) -> String {
            self.0.hash().to_string()
        }

        /// The transaction IDs, in protocol byte order.
        pub fn txids(&self) -> Vec<[u8; 32]> {
            self.0.transactions.iter().map(|tx| tx.hash().0).collect()
        }

        /// The Ironwood Actions' note commitments, in position order.
        pub fn commitments(&self) -> Vec<[u8; 32]> {
            self.0
                .transactions
                .iter()
                .flat_map(|tx| tx.ironwood_actions().map(|a| a.cm_x.into()))
                .collect()
        }

        /// The refund's encrypted note ciphertext.
        pub fn refund_ciphertext(&self) -> [u8; 580] {
            self.0.transactions[1]
                .ironwood_actions()
                .next()
                .unwrap()
                .enc_ciphertext
                .into()
        }
    }

    /// The Ironwood tree root, as the node's `z_gettreestate` encodes it, after
    /// `blocks`, from the empty tree.
    pub fn ironwood_root(blocks: &[&RefundBlock]) -> [u8; 32] {
        let mut tree = zakura_chain::orchard::tree::NoteCommitmentTree::default();
        for tx in blocks.iter().flat_map(|block| &block.0.transactions) {
            for action in tx.ironwood_actions() {
                tree.append(action.cm_x).unwrap();
            }
        }
        tree.root().bytes_in_display_order()
    }
}

/// Status blocks.
pub mod status {
    use super::*;

    /// The regtest genesis block: its raw hex, display hash and its coinbase
    /// transaction's display ID.
    pub fn regtest_genesis() -> (String, String, String) {
        let block = zakura_chain::block::genesis::regtest_genesis_block();
        let mut raw = Vec::new();
        block.zcash_serialize(&mut raw).unwrap();
        (
            hex::encode(raw),
            block.hash().to_string(),
            block.transactions[0].hash().to_string(),
        )
    }
}
