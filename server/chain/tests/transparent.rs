//! Transparent blocks read over RPC from a node double, and compact blocks from a
//! public mainnet block.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zakura_server_chain::{
    NodeClient,
    testing::*,
    transparent::{
        BoxError, ExtractError, Fee, FetchedBlock, Output, OutputCache, PreviousOutputs,
        read_transaction,
    },
};

async fn node() -> (SharedChain, NodeClient) {
    let chain: SharedChain = Arc::new(Mutex::new(Chain::default()));
    let (url, _) = serve_chain(chain.clone()).await;
    let dir = std::env::temp_dir().join(format!(
        "transparent-node-{}-{}",
        std::process::id(),
        url.rsplit(':').next().unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let client = NodeClient::from_cookie_file(url, cookie(&dir))
        .unwrap()
        .with_request_id("transparent-filter");
    (chain, client)
}

/// A P2PKH script, a nonstandard one, an empty one and one whose first opcode is
/// `OP_RETURN`.
const P2PKH: &[u8] = &[
    0x76, 0xa9, 0x14, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0x88, 0xac,
];
const ODD: &[u8] = &[0x51, 0x6a, 0x00, 0xff];
const RETURN: &[u8] = &[0x6a, 0x04, 1, 2, 3, 4];

/// Resolves from outputs given in advance, as the database reader resolves from its
/// own transaction index.
struct Known(HashMap<([u8; 32], u32), Output>);

impl PreviousOutputs for Known {
    fn previous_output(&mut self, txid: [u8; 32], index: u32) -> Result<Option<Output>, BoxError> {
        Ok(self.0.get(&(txid, index)).cloned())
    }
}

#[tokio::test]
async fn rpc_blocks_resolve_every_spent_script_raw_with_exact_fees() {
    let (chain, rpc) = node().await;
    let earlier = transfer(vec![spend_outpoint([9; 32], 0)], &[(50_000, ODD), (7, &[])]);
    let parent = transfer(vec![spend_outpoint([7; 32], 0)], &[(41_000, ODD)]);
    let created = transfer(vec![spend(&parent, 0)], &[(40_000, P2PKH)]);
    let spender = transfer(
        vec![spend(&created, 0), spend(&earlier, 0), spend(&earlier, 1)],
        &[(80_000, RETURN), (9_000, P2PKH)],
    );
    let miner = coinbase(1_000_000, &[(625_000, P2PKH), (0, RETURN)]);
    let hash = {
        let mut c = chain.lock().unwrap();
        // Earlier history the node holds outside the block.
        c.add_transaction(&earlier);
        c.add_transaction(&parent);
        c.push_block(10, &[miner, created.clone(), spender], 1)
    };
    let mut cache = OutputCache::new(1000);
    let fetched = rpc.fetch_block(10).await.unwrap();
    assert_eq!(zakura_server_chain::hash::display(&fetched.hash()), hash);
    let read = rpc
        .transparent_block(10, fetched.clone(), &mut cache)
        .await
        .unwrap();
    assert_eq!(read.height, 10);
    let [mined, made, spent] = &read.transactions[..] else {
        panic!("three transactions");
    };
    assert!(mined.coinbase && mined.inputs.is_empty());
    assert_eq!(mined.fee, Fee::NotApplicable);
    assert_eq!(
        mined.outputs[1].script, RETURN,
        "scripts are raw, OP_RETURN included"
    );
    assert_eq!(made.fee, Fee::Exact(1_000));
    assert_eq!(
        made.inputs[0].spent,
        Output {
            value: 41_000,
            script: ODD.to_vec()
        }
    );
    // Same-block, fetched and empty spent scripts, in input order.
    assert_eq!(spent.transparent_input_count, 3);
    assert_eq!(spent.inputs[0].spent.script, P2PKH);
    assert_eq!(
        spent.inputs[1].spent,
        Output {
            value: 50_000,
            script: ODD.to_vec()
        }
    );
    assert_eq!(
        spent.inputs[2].spent,
        Output {
            value: 7,
            script: vec![]
        }
    );
    assert_eq!(spent.inputs[2].input_index, 2);
    assert_eq!(spent.fee, Fee::Exact(40_000 + 50_000 + 7 - 89_000));
    assert_eq!(spent.transaction_index, 2);
    // Two outside parents fetched in one batch; the block's own spend needs none.
    assert_eq!(read.lookups, 2);
    assert_eq!(chain.lock().unwrap().batches, 1);
    // The same block through a resolver over the same transactions, as the database
    // reader resolves, reads identically.
    let mut known = Known(
        [
            (
                (parent.txid(), 0),
                Output {
                    value: 41_000,
                    script: ODD.to_vec(),
                },
            ),
            (
                (earlier.txid(), 0),
                Output {
                    value: 50_000,
                    script: ODD.to_vec(),
                },
            ),
            (
                (earlier.txid(), 1),
                Output {
                    value: 7,
                    script: vec![],
                },
            ),
        ]
        .into_iter()
        .collect(),
    );
    assert_eq!(
        fetched.transparent(10, &mut known).unwrap(),
        read.transactions
    );
    // A transaction outside any block reads with the same identity and outputs,
    // and its outputs keep their consensus encoding.
    let alone = read_transaction(&earlier.bytes()).unwrap();
    assert_eq!(alone.txid, earlier.txid());
    assert_eq!(
        (alone.coinbase, alone.has_shielded_components),
        (false, false)
    );
    assert_eq!(alone.spends, vec![([9; 32], 0)]);
    assert_eq!(
        alone.outputs,
        vec![
            Output {
                value: 50_000,
                script: ODD.to_vec()
            },
            Output {
                value: 7,
                script: vec![]
            }
        ]
    );
    assert!(read_transaction(&earlier.bytes()[1..]).is_err());
    assert!(read_transaction(&[earlier.bytes(), vec![0]].concat()).is_err());
    let encoded = alone.outputs[0].consensus_bytes().unwrap();
    assert_eq!(
        encoded,
        [&50_000u64.to_le_bytes()[..], &[ODD.len() as u8], ODD].concat()
    );
    assert_eq!(
        Output::from_consensus_bytes(&encoded).unwrap(),
        alone.outputs[0]
    );
    // The block's transactions read as they appear, and each can be read alone,
    // resolving even a same-block spend through the resolver.
    let views = fetched.transactions();
    assert_eq!(views.len(), 3);
    assert!(views[0].coinbase && views[0].spends.is_empty());
    assert_eq!(views[2].spends.len(), 3);
    assert_eq!(fetched.coinbase_height(), Some(1_000_000));
    let mut alone_resolver = Known(
        [(
            (created.txid(), 0),
            Output {
                value: 40_000,
                script: P2PKH.to_vec(),
            },
        )]
        .into_iter()
        .chain(known.0.clone())
        .collect(),
    );
    let single = fetched
        .transparent_transaction(2, 10, &mut alone_resolver)
        .unwrap();
    assert_eq!(single.transaction_index, 0);
    assert_eq!(
        (single.inputs.clone(), single.outputs.clone(), single.fee),
        (spent.inputs.clone(), spent.outputs.clone(), spent.fee)
    );
    assert!(matches!(
        fetched.transparent_transaction(2, 10, &mut Known(Default::default())),
        Err(ExtractError::MissingPreviousOutput(_))
    ));
    assert!(fetched.transparent_transaction(3, 10, &mut known).is_err());
    // A later block spending those outputs again reads them from the cache.
    let again = transfer(vec![spend(&earlier, 0)], &[(1, P2PKH)]);
    chain.lock().unwrap().push_block(11, &[again], 2);
    let next = rpc.fetch_block(11).await.unwrap();
    let read = rpc.transparent_block(11, next, &mut cache).await.unwrap();
    assert_eq!((read.lookups, read.cache_hits), (0, 1));
}

#[tokio::test]
async fn an_unknown_spent_output_fails_the_block() {
    let (chain, rpc) = node().await;
    let orphan = transfer(vec![spend_outpoint([5; 32], 0)], &[(1, P2PKH)]);
    chain.lock().unwrap().push_block(3, &[orphan], 0);
    let fetched = rpc.fetch_block(3).await.unwrap();
    assert!(matches!(
        rpc.transparent_block(3, fetched, &mut OutputCache::new(10))
            .await,
        Err(ExtractError::MissingPreviousOutput(_))
    ));
    // A batch refusing the lookup fails rather than resolving nothing.
    chain.lock().unwrap().fault = Some(BatchFault::EntryError(-32603));
    let fetched = rpc.fetch_block(3).await.unwrap();
    assert!(
        rpc.transparent_block(3, fetched, &mut OutputCache::new(10))
            .await
            .is_err()
    );
}

/// The public block's compact form keeps every transparent input and output and
/// 52-byte compact ciphertexts, and advances the tree sizes.
#[test]
fn compact_blocks_keep_transparent_and_shielded_fields() {
    let raw = hex::decode(include_str!("fixtures/compact-mainnet-1687106.hex").trim()).unwrap();
    let block = FetchedBlock::from_exact_bytes(&raw).unwrap();
    assert!(FetchedBlock::from_exact_bytes(&[raw.clone(), vec![0]].concat()).is_err());
    assert_eq!(
        FetchedBlock::from_bytes(&[raw.clone(), vec![0]].concat())
            .unwrap()
            .hash(),
        block.hash()
    );
    let mut counts = [0; 3];
    let compact = block.compact(1687106, &mut counts).unwrap();
    assert_eq!(compact.hash, block.hash());
    assert_eq!(compact.prev_hash, block.parent());
    assert_eq!(compact.transactions.len(), block.txids().len());
    let transparent = block.transparent(1687106, &mut AnyOutput).unwrap();
    assert_eq!(
        compact
            .transactions
            .iter()
            .map(|t| t.inputs.len())
            .sum::<usize>(),
        transparent.iter().map(|t| t.inputs.len()).sum::<usize>()
    );
    for (compact, tx) in compact.transactions.iter().zip(&transparent) {
        assert_eq!(compact.outputs, tx.outputs);
        assert_eq!(compact.txid, tx.txid);
    }
    assert!(
        compact
            .transactions
            .iter()
            .any(|t| !t.sapling_outputs.is_empty() || !t.orchard_actions.is_empty())
    );
    for tx in &compact.transactions {
        assert!(tx.sapling_outputs.iter().all(|o| o.ciphertext.len() == 52));
        assert!(tx.orchard_actions.iter().all(|a| a.ciphertext.len() == 52));
    }
    assert_eq!(
        counts[0] as usize,
        compact
            .transactions
            .iter()
            .map(|t| t.sapling_outputs.len())
            .sum::<usize>()
    );
    assert_eq!(compact.sapling_tree_size, counts[0]);
}

/// Resolves every spent output to a large value, for reading a block's shape.
struct AnyOutput;

impl PreviousOutputs for AnyOutput {
    fn previous_output(&mut self, _: [u8; 32], _: u32) -> Result<Option<Output>, BoxError> {
        Ok(Some(Output {
            value: 2_100_000_000_000_000,
            script: vec![0x51],
        }))
    }
}
