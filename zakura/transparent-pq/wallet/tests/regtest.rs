//! End to end against a regtest node that validates dedicated PQ transparent outputs.
//!
//! Needs a `zakurad` from zakura #2186 (`roman/mac/claude/pq-dedicated-output`) built with
//! `cargo build -p zakura --bin zakurad --features pq`; set `ZAKURAD_PQ` to its path and
//! run `python3 scripts/dev.py test --config transparent-pq-wallet --ignored regtest`.
//! The test starts the node itself and talks to it over JSON-RPC only, so the node stays
//! out of this workspace's dependency graph.
//!
//! Two consequences of the dedicated output shape the harness. The node cannot mine to a
//! PQ output, because its block template builder has no PQ destination, so the chain is
//! mined to the `OP_TRUE` pay-to-script-hash address every PQ test on the node side uses,
//! and the first PQ coins come from a funding transaction that spends such a coinbase with
//! no signature at all. And a PQ output has no address, so no address index can find one:
//! outputs are located in the transactions this test builds, and a restore walks the
//! chain's blocks looking for the output script a key would be paid at.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::TempDir;
use transparent::address::{Script, TransparentAddress};
use transparent::bundle::{Authorized as TransparentAuthorized, Bundle, OutPoint, TxIn, TxOut};
use transparent_pq_keys::{Branch, KeyOrigin, Network, ParameterSet, PublicKey, WalletSeed};
use transparent_pq_pool::{AccountPool, Issued};
use transparent_pq_wallet::{
    Payment, PqDestination, PqUtxo, Recipient, SeedSigner, SignedSpend, build_spend, verify_inputs,
};
use zcash_primitives::transaction::{Transaction, TransactionData, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType};
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::Zatoshis;
use zcash_script::script::Code;

const SEED: [u8; 32] = [0x7e; 32];

/// Blocks before a coinbase output can be spent.
const COINBASE_MATURITY: u32 = 100;

/// PQ spends become valid here, just after the first coinbase matures.
const PQ_ACTIVATION: u32 = COINBASE_MATURITY + 3;

fn seed() -> WalletSeed {
    WalletSeed::from_bytes(&SEED).unwrap()
}

/// The node's regtest: every upgrade through NU5 active from height 1, nothing later.
fn network() -> LocalNetwork {
    let one = Some(BlockHeight::from_u32(1));
    LocalNetwork {
        overwinter: one,
        sapling: one,
        blossom: one,
        heartwood: one,
        canopy: one,
        nu5: one,
        nu6: None,
        nu6_1: None,
        nu6_2: None,
        nu6_3: None,
        nu7: None,
    }
}

fn window() -> NonZeroU32 {
    NonZeroU32::new(3).unwrap()
}

fn pool(parameters: ParameterSet, account: u32) -> AccountPool {
    let mut pool = AccountPool::new(parameters, Network::Regtest, account, window());
    pool.replenish(Branch::Receive, &mut seed()).unwrap();
    pool.replenish(Branch::Change, &mut seed()).unwrap();
    pool
}

/// The output script a key is paid at. A PQ output has no address of its own yet, so
/// this is what stands in for one everywhere in this test.
fn script(public_key: &PublicKey) -> Script {
    PqDestination::single_signer(public_key).script_pubkey()
}

/// HASH160 of the one-byte redeem script `OP_TRUE`, the address this chain is mined to.
///
/// A coinbase paid there is spendable by revealing that script and nothing else, so the
/// funding transaction below needs no key, which is how the node's own PQ tests fund
/// theirs.
const OP_TRUE_SCRIPT_HASH: [u8; 20] = [
    0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56, 0x99, 0x71, 0xc7, 0x7e, 0xba,
    0x30, 0xcd, 0x5a, 0x4b,
];

/// The scriptSig that satisfies that coinbase: a direct push of `OP_TRUE`.
const OP_TRUE_SCRIPT_SIG: [u8; 2] = [0x01, 0x51];

fn miner_address() -> String {
    TransparentAddress::ScriptHash(OP_TRUE_SCRIPT_HASH)
        .to_zcash_address(NetworkType::Regtest)
        .encode()
}

/// Spends one `OP_TRUE` coinbase output into PQ outputs, so the wallet has PQ coins to
/// spend. Nothing here is signed: the revealed script is satisfied by itself.
fn fund(
    (outpoint, value): (OutPoint, Zatoshis),
    payments: &[(Script, Zatoshis)],
    target_height: u32,
) -> Transaction {
    let paid: u64 = payments.iter().map(|(_, value)| u64::from(*value)).sum();
    assert!(
        paid <= u64::from(value),
        "the coinbase cannot pay that much"
    );
    TransactionData::from_parts(
        TxVersion::V5,
        BranchId::for_height(&network(), BlockHeight::from_u32(target_height)),
        0,
        BlockHeight::from_u32(target_height + 40),
        Some(Bundle {
            vin: vec![TxIn::from_parts(
                outpoint,
                Script(Code(OP_TRUE_SCRIPT_SIG.to_vec())),
                u32::MAX,
            )],
            vout: payments
                .iter()
                .map(|(script, value)| TxOut::new(*value, script.clone()))
                .collect(),
            authorization: TransparentAuthorized,
        }),
        None,
        None,
        None,
    )
    .freeze()
    .expect("a transparent-only transaction serializes")
}

/// A zakurad regtest node in a temporary directory, stopped on drop.
struct Node {
    child: Child,
    rpc: SocketAddr,
    log: PathBuf,
    _dir: TempDir,
}

impl Node {
    fn start(binary: &Path, miner_address: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let rpc = SocketAddr::from(([127, 0, 0, 1], free_port()));
        let config = dir.path().join("zakurad.toml");
        std::fs::write(
            &config,
            format!(
                r#"[network]
network = "Regtest"
listen_addr = "127.0.0.1:0"
initial_testnet_peers = []
cache_dir = false

[network.testnet_parameters]
pq_activation_height = {PQ_ACTIVATION}

[network.testnet_parameters.activation_heights]
NU5 = 1

[consensus]
checkpoint_sync = false

[mempool]
debug_enable_at_height = 0

[mining]
miner_address = "{miner_address}"

[rpc]
listen_addr = "{rpc}"
enable_cookie_auth = false

[state]
ephemeral = true
cache_dir = "{state}"
"#,
                state = dir.path().join("state").display(),
            ),
        )
        .unwrap();
        let log = dir.path().join("zakurad.log");
        let output = std::fs::File::create(&log).unwrap();
        let child = Command::new(binary)
            .arg("-c")
            .arg(&config)
            .arg("start")
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .stdin(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("cannot start {}: {error}", binary.display()));
        let mut node = Self {
            child,
            rpc,
            log,
            _dir: dir,
        };
        node.wait_for_log("activating mempool");
        node
    }

    fn wait_for_log(&mut self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if std::fs::read_to_string(&self.log).is_ok_and(|log| log.contains(needle)) {
                return;
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("zakurad exited with {status}:\n{}", self.log_tail());
            }
            assert!(
                Instant::now() < deadline,
                "no {needle:?} in the node log:\n{}",
                self.log_tail()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn log_tail(&self) -> String {
        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<_> = log.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }

    /// Calls `method`, returning the RPC error object when the node refuses.
    fn call(&self, method: &str, params: Value) -> Result<Value, Value> {
        let body =
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        let mut stream = TcpStream::connect(self.rpc).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(300)))
            .unwrap();
        write!(
            stream,
            "POST / HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            self.rpc,
            body.len()
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (_, reply) = response
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("{method}: malformed HTTP response {response:?}"));
        let reply: Value = serde_json::from_str(reply)
            .unwrap_or_else(|error| panic!("{method}: {error} in {reply:?}"));
        match reply.get("error") {
            Some(error) if !error.is_null() => Err(error.clone()),
            _ => Ok(reply["result"].clone()),
        }
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        self.call(method, params)
            .unwrap_or_else(|error| panic!("{method}: {error}\n{}", self.log_tail()))
    }

    fn generate(&self, blocks: u32) {
        self.rpc("generate", json!([blocks]));
    }

    fn tip(&self) -> u32 {
        self.rpc("getblockcount", json!([])).as_u64().unwrap() as u32
    }

    fn send(&self, transaction: &Transaction) -> Result<Value, Value> {
        let mut bytes = Vec::new();
        transaction.write(&mut bytes).unwrap();
        self.send_bytes(&bytes)
    }

    fn send_bytes(&self, bytes: &[u8]) -> Result<Value, Value> {
        self.call("sendrawtransaction", json!([hex::encode(bytes)]))
    }

    /// Unspent outputs at `address`, as (outpoint, value, height).
    fn utxos(&self, address: &str) -> Vec<(OutPoint, Zatoshis, u32)> {
        let utxos = self.rpc("getaddressutxos", json!([{"addresses": [address]}]));
        utxos
            .as_array()
            .unwrap()
            .iter()
            .map(|utxo| {
                let mut txid: [u8; 32] = hex::decode(utxo["txid"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                // RPC txids are displayed byte-reversed.
                txid.reverse();
                let index = utxo["outputIndex"].as_u64().unwrap() as u32;
                (
                    OutPoint::new(txid, index),
                    Zatoshis::from_u64(utxo["satoshis"].as_u64().unwrap()).unwrap(),
                    utxo["height"].as_u64().unwrap() as u32,
                )
            })
            .collect()
    }

    /// Every transaction on the chain, oldest block first.
    ///
    /// PQ outputs are in no address index, so finding one means reading the blocks. The
    /// chains in this test are a few hundred blocks long, which this walks in well under
    /// the node's own startup time.
    fn transactions(&self) -> Vec<Transaction> {
        let branch_id = BranchId::for_height(&network(), BlockHeight::from_u32(self.tip()));
        (1..=self.tip())
            .flat_map(|height| {
                let block = self.rpc("getblock", json!([height.to_string(), 1]));
                let txids: Vec<String> = block["tx"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|txid| txid.as_str().unwrap().to_owned())
                    .collect();
                txids.into_iter().map(move |txid| {
                    let raw = self.rpc("getrawtransaction", json!([txid, 0]));
                    let bytes = hex::decode(raw.as_str().unwrap()).unwrap();
                    Transaction::read(&bytes[..], branch_id)
                        .expect("the node serves transactions it accepted")
                })
            })
            .collect()
    }

    /// Whether any transaction on the chain pays `script`, which is what "this key has
    /// received funds" means for a key with no address.
    fn pays_script(&self, script: &Script) -> bool {
        self.transactions().iter().any(|transaction| {
            transaction
                .transparent_bundle()
                .is_some_and(|bundle| bundle.vout.iter().any(|out| out.script_pubkey() == script))
        })
    }

    /// The output `transaction` pays to `script`, after checking the node has it on chain.
    fn output(&self, transaction: &Transaction, script: &Script) -> (OutPoint, Zatoshis) {
        let txid = transaction.txid().to_string();
        let confirmed = self.rpc("getrawtransaction", json!([txid, 1]));
        assert!(
            confirmed["height"]
                .as_i64()
                .is_some_and(|height| height > 0),
            "{txid} is not mined: {confirmed}"
        );
        let bundle = transaction.transparent_bundle().expect("transparent spend");
        let (index, out) = bundle
            .vout
            .iter()
            .enumerate()
            .find(|(_, out)| out.script_pubkey() == script)
            .unwrap_or_else(|| panic!("{txid} pays nothing to that script"));
        (
            OutPoint::new(*transaction.txid().as_ref(), index as u32),
            out.value(),
        )
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn utxo(issued: &Issued, (outpoint, value): (OutPoint, Zatoshis)) -> PqUtxo {
    PqUtxo {
        outpoint,
        value,
        origin: issued.origin,
        public_key: issued.public_key,
    }
}

fn spend(
    node: &Node,
    inputs: &[PqUtxo],
    payment: Payment,
    change_pool: &mut AccountPool,
) -> SignedSpend {
    build_spend(
        &network(),
        BlockHeight::from_u32(node.tip() + 1),
        BlockHeight::from_u32(PQ_ACTIVATION),
        inputs,
        &[payment],
        change_pool,
        &mut SeedSigner::new(seed()),
    )
    .unwrap()
}

fn received(pool: &mut AccountPool, origin: KeyOrigin) {
    pool.record_received(origin).unwrap();
}

#[test]
#[ignore = "needs ZAKURAD_PQ, a zakurad built with the pq feature"]
fn regtest_pq_spends_rotate_change_and_restore() {
    let binary = PathBuf::from(
        std::env::var_os("ZAKURAD_PQ")
            .expect("set ZAKURAD_PQ to a zakurad built with --features pq"),
    );
    // Account 0 holds 128f keys and account 1 holds 192s keys. Neither can be mined to:
    // the chain is mined to the OP_TRUE address and the PQ coins come from a funding
    // transaction that spends one of its coinbases.
    let mut first_account = pool(ParameterSet::Sha2_128f, 0);
    let mut second_account = pool(ParameterSet::Sha2_192s, 1);
    let miner = first_account.issue(Branch::Receive).unwrap();

    let node = Node::start(&binary, &miner_address());
    node.generate(PQ_ACTIVATION - 1);
    assert_eq!(node.tip(), PQ_ACTIVATION - 1);

    let mut coinbases: Vec<_> = node
        .utxos(&miner_address())
        .into_iter()
        .filter(|(_, _, height)| height + COINBASE_MATURITY <= node.tip() + 1)
        .map(|(outpoint, value, _)| (outpoint, value))
        .collect();
    assert!(coinbases.len() >= 2, "expected two mature coinbase outputs");

    // Fund two of the wallet's keys. Creating PQ outputs is only allowed from the
    // activation height, which the next block is.
    let funded = fund(
        coinbases.remove(0),
        &[(
            script(&miner.public_key),
            Zatoshis::const_from_u64(500_000_000),
        )],
        node.tip() + 1,
    );
    node.send(&funded).unwrap();
    node.generate(1);
    let mined = node.output(&funded, &script(&miner.public_key));
    received(&mut first_account, miner.origin);

    // Spend that PQ output to the second account, with change to a fresh 128f key.
    let second = second_account.issue(Branch::Receive).unwrap();
    let second_script = script(&second.public_key);
    let first = spend(
        &node,
        &[utxo(&miner, mined)],
        Payment {
            recipient: Recipient::Pq {
                parameters: ParameterSet::Sha2_192s,
                commitment: *PqDestination::single_signer(&second.public_key).commitment(),
            },
            value: Zatoshis::const_from_u64(100_000_000),
        },
        &mut first_account,
    );
    verify_inputs(NetworkType::Regtest, &first.transaction, &first.spent).unwrap();
    let change = first.change.expect("change");
    assert_eq!(change.origin.branch(), Branch::Change);
    node.send(&first.transaction).unwrap();
    node.generate(1);
    let paid = node.output(&first.transaction, &second_script);
    assert_eq!(paid.1, Zatoshis::const_from_u64(100_000_000));
    let kept = node.output(&first.transaction, &script(&change.public_key));
    received(&mut second_account, second.origin);
    received(&mut first_account, change.origin);

    // Spend the 128f change and the 192s output together, paying the first account's
    // next receiving address, with change to the next change key.
    let next = first_account.issue(Branch::Receive).unwrap();
    assert_eq!(next.origin.index(), 1);
    let both = spend(
        &node,
        &[utxo(&change, kept), utxo(&second, paid)],
        Payment {
            recipient: Recipient::Pq {
                parameters: ParameterSet::Sha2_128f,
                commitment: *PqDestination::single_signer(&next.public_key).commitment(),
            },
            value: Zatoshis::const_from_u64(50_000_000),
        },
        &mut first_account,
    );
    let second_change = both.change.expect("change");
    assert_eq!(second_change.origin.index(), change.origin.index() + 1);
    node.send(&both.transaction).unwrap();
    node.generate(1);
    node.output(&both.transaction, &script(&next.public_key));
    node.output(&both.transaction, &script(&second_change.public_key));
    received(&mut first_account, next.origin);
    received(&mut first_account, second_change.origin);

    // A flipped signature byte is rejected; the untouched spend is accepted.
    let spare = fund(
        coinbases.remove(0),
        &[(
            script(&next.public_key),
            Zatoshis::const_from_u64(200_000_000),
        )],
        node.tip() + 1,
    );
    node.send(&spare).unwrap();
    node.generate(1);
    let spare = node.output(&spare, &script(&next.public_key));
    let last = spend(
        &node,
        &[utxo(&next, spare)],
        Payment {
            recipient: Recipient::Pq {
                parameters: ParameterSet::Sha2_192s,
                commitment: *PqDestination::single_signer(&second.public_key).commitment(),
            },
            value: Zatoshis::const_from_u64(1_000_000),
        },
        &mut first_account,
    );
    let mut bytes = Vec::new();
    last.transaction.write(&mut bytes).unwrap();
    let signature = bytes
        .windows(3)
        .position(|w| w == [0x4d, 0xc1, 0x42]) // PUSHDATA2 of a 128f signature and sighash type
        .expect("signature push");
    let mut tampered = bytes.clone();
    tampered[signature + 100] ^= 1;
    assert!(node.send_bytes(&tampered).is_err());
    node.send_bytes(&bytes).unwrap();
    node.generate(1);
    let last_change = last.change.expect("change");
    node.output(&last.transaction, &script(&last_change.public_key));
    received(&mut first_account, last_change.origin);

    // Restoring from the seed finds the same used keys, by looking for each key's output
    // script on the chain: a PQ output is in no address index.
    let restored = AccountPool::discover(
        ParameterSet::Sha2_128f,
        Network::Regtest,
        0,
        window(),
        &mut seed(),
        |_, public_key| node.pays_script(&script(public_key)),
    )
    .unwrap();
    for (restored, used) in [
        (&restored.state().receive, &first_account.state().receive),
        (&restored.state().change, &first_account.state().change),
    ] {
        assert_eq!(restored.highest_used, used.highest_used);
        assert_eq!(restored.issued_end, used.issued_end);
    }
    assert_eq!(restored.state().change.highest_used, Some(2));
}
