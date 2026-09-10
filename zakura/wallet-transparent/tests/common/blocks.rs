//! A chain of blocks, and two independent readings of it.
//!
//! The recovery suite's fixtures are events already sorted into shards, and
//! its independent check replays those same events through the library's own
//! ledger. That proves retrieval and persistence, not extraction, and not the
//! ledger. Here the fixture is blocks — transactions with inputs and outputs —
//! and two things are derived from them by code that shares nothing:
//!
//! - [`extract`] turns blocks into the events a publisher would index, by the
//!   publisher's rules: an output is a receive under its own script; an input
//!   is a spend under the script of the output it consumes; the first
//!   transaction of a block with no inputs is coinbase. What it produces is
//!   published and served, and the wallet recovers it privately.
//! - [`reduce`] walks the same blocks with its own outpoint bookkeeping and
//!   says what a wallet holding some scripts must end up with: every event,
//!   every unspent output, every spend, every transaction's effect, and the
//!   balance. It never consults an event, a ledger or the store.
//!
//! [`compare_blocks`] holds the store to the second reading, event by event and
//! through the projection the wallet shows.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use transparent_events::{ReceiveEvent, SpendEvent, TransparentEvent, Txid};
use transparent_filter::{BlockHash, ScriptBytes};
use zakura_wallet_core::AccountId;
use zakura_wallet_store::WalletDb;

use super::{Events, Layout, h, hash_at, my_scripts, state, store_ledger};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: Txid,
    pub n: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub script: ScriptBytes,
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub prevout: OutPoint,
    /// The consumed output's script and value when the output is not in the
    /// modelled chain, as a real-chain sample carries them. `None` means the
    /// input spends something the model never saw, which no event indexes.
    pub prev: Option<TxOut>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    pub txid: Txid,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub height: u64,
    pub hash: BlockHash,
    pub prev_hash: BlockHash,
    /// In block order; the transaction index is the position.
    pub txs: Vec<Tx>,
}

/// Blocks from one before the layout's first height through its last.
#[derive(Debug, Clone)]
pub struct Chain {
    pub layout: Layout,
    pub blocks: BTreeMap<u64, Block>,
    next_tag: u64,
}

impl Chain {
    /// Empty blocks with the suite's height-derived hashes.
    pub fn synthetic(layout: Layout) -> Self {
        let mut blocks = BTreeMap::new();
        for height in (layout.first - 1)..=layout.last() {
            blocks.insert(
                height,
                Block {
                    height,
                    hash: hash_at(height),
                    prev_hash: hash_at(height - 1),
                    txs: Vec::new(),
                },
            );
        }
        Self {
            layout,
            blocks,
            next_tag: 5_000_000,
        }
    }

    pub fn first(&self) -> u64 {
        self.layout.first
    }

    pub fn last(&self) -> u64 {
        self.layout.last()
    }

    pub fn hash(&self, height: u64) -> BlockHash {
        self.blocks[&height].hash
    }

    /// The chain's hashes, for publishing and accepting.
    pub fn hash_fn(&self) -> impl Fn(u64) -> BlockHash + '_ {
        move |height| self.hash(height)
    }

    fn fresh_txid(&mut self) -> Txid {
        self.next_tag += 1;
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&self.next_tag.to_le_bytes());
        bytes[8] = 0xb1;
        Txid(bytes)
    }

    /// Unrelated activity in every block of every shard: three hundred decoy
    /// scripts per shard receive, and a third of each shard's receives are
    /// spent in the shard after it, so extraction resolves inputs against
    /// outputs nobody in the wallet owns.
    pub fn with_decoys(mut self) -> Self {
        let mut spendable: Vec<OutPoint> = Vec::new();
        for shard in 0..self.layout.shards {
            let (start, _) = self.layout.bounds(shard);
            let mut next: Vec<OutPoint> = Vec::new();
            for tag in 100..400u32 {
                let height = start + u64::from(tag % 50);
                let out = self.pay(height, super::script(tag), 1);
                if tag % 3 == 0 {
                    next.push(out);
                }
            }
            for (i, out) in spendable.drain(..).enumerate() {
                let height = start + (i as u64 % 50);
                self.spend(height, &[out], &[(super::script(900 + i as u32), 1)]);
            }
            spendable = next;
        }
        self
    }

    /// Pays `script` at `height` from money outside the chain.
    pub fn pay(&mut self, height: u64, script: ScriptBytes, value: u64) -> OutPoint {
        let txid = self.fresh_txid();
        let funding = self.fresh_txid();
        let block = self.blocks.get_mut(&height).expect("a height in the chain");
        block.txs.push(Tx {
            txid,
            vin: vec![TxIn {
                prevout: OutPoint {
                    txid: funding,
                    n: 0,
                },
                prev: None,
            }],
            vout: vec![TxOut { script, value }],
        });
        OutPoint { txid, n: 0 }
    }

    /// Pays `script` from the block's coinbase, creating one if the block has
    /// none. The coinbase is the block's first transaction and has no inputs.
    pub fn coinbase(&mut self, height: u64, script: ScriptBytes, value: u64) -> OutPoint {
        let block = self.blocks.get_mut(&height).expect("a height in the chain");
        let has_coinbase = block.txs.first().is_some_and(|tx| tx.vin.is_empty());
        if !has_coinbase {
            let txid = self.fresh_txid();
            let block = self.blocks.get_mut(&height).unwrap();
            block.txs.insert(
                0,
                Tx {
                    txid,
                    vin: Vec::new(),
                    vout: Vec::new(),
                },
            );
        }
        let block = self.blocks.get_mut(&height).unwrap();
        let coinbase = &mut block.txs[0];
        coinbase.vout.push(TxOut { script, value });
        OutPoint {
            txid: coinbase.txid,
            n: (coinbase.vout.len() - 1) as u32,
        }
    }

    /// Spends `inputs`, which must be outputs of this chain, paying `outputs`.
    pub fn spend(
        &mut self,
        height: u64,
        inputs: &[OutPoint],
        outputs: &[(ScriptBytes, u64)],
    ) -> Txid {
        for input in inputs {
            assert!(
                self.find_output(input).is_some(),
                "a fixture spends an output the chain does not hold"
            );
        }
        let txid = self.fresh_txid();
        let block = self.blocks.get_mut(&height).expect("a height in the chain");
        block.txs.push(Tx {
            txid,
            vin: inputs
                .iter()
                .map(|prevout| TxIn {
                    prevout: *prevout,
                    prev: None,
                })
                .collect(),
            vout: outputs
                .iter()
                .map(|(script, value)| TxOut {
                    script: script.clone(),
                    value: *value,
                })
                .collect(),
        });
        txid
    }

    /// The output an outpoint names, with the height it was created at.
    pub fn find_output(&self, outpoint: &OutPoint) -> Option<(u64, &TxOut)> {
        for block in self.blocks.values() {
            for tx in &block.txs {
                if tx.txid == outpoint.txid {
                    return tx.vout.get(outpoint.n as usize).map(|o| (block.height, o));
                }
            }
        }
        None
    }

    /// Another chain from `fork` on: the blocks at and above it are rehashed as
    /// a reorg leaves them, after `edit` has changed their contents.
    pub fn fork_at(&self, fork: u64, edit: impl FnOnce(&mut BTreeMap<u64, Block>)) -> Chain {
        let mut blocks = self.blocks.clone();
        edit(&mut blocks);
        let forked = super::hash_forked(fork);
        for (height, block) in blocks.iter_mut() {
            block.hash = forked(*height);
            block.prev_hash = forked(*height - 1);
        }
        Chain {
            layout: self.layout,
            blocks,
            next_tag: self.next_tag,
        }
    }

    /// Every transaction, in chain order, with its height and index.
    pub fn transactions(&self) -> impl Iterator<Item = (u64, u16, &Tx)> {
        self.blocks.values().flat_map(|block| {
            block
                .txs
                .iter()
                .enumerate()
                .map(move |(index, tx)| (block.height, index as u16, tx))
        })
    }

    /// Every script that receives in the chain, with what happens to it.
    pub fn candidate_scripts(&self) -> Vec<Candidate> {
        let mut by_script: BTreeMap<Vec<u8>, Candidate> = BTreeMap::new();
        let mut outputs: BTreeMap<OutPoint, ScriptBytes> = BTreeMap::new();
        for (_, index, tx) in self.transactions() {
            let coinbase = index == 0 && tx.vin.is_empty();
            for input in &tx.vin {
                if let Some(script) = outputs.get(&input.prevout) {
                    let entry = by_script.entry(script.as_slice().to_vec()).or_default();
                    entry.spends += 1;
                }
            }
            for (n, out) in tx.vout.iter().enumerate() {
                let entry = by_script.entry(out.script.as_slice().to_vec()).or_default();
                entry.script = out.script.clone();
                entry.receives += 1;
                entry.coinbase |= coinbase;
                outputs.insert(
                    OutPoint {
                        txid: tx.txid,
                        n: n as u32,
                    },
                    out.script.clone(),
                );
            }
        }
        by_script.into_values().collect()
    }

    /// A chain from a JSON-lines block sample: one `manifest` line and one
    /// `block` line per height, with raw scripts and previous-output scripts
    /// on inputs. Heights outside the layout are refused.
    pub fn load_jsonl(path: &Path, layout: Layout) -> Chain {
        let text = std::fs::read_to_string(path).expect("the block sample is readable");
        let mut blocks = BTreeMap::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value = serde_json::from_str(line).expect("json line");
            match value["type"].as_str() {
                Some("manifest") => {
                    assert_eq!(
                        value["genesis_hash"].as_str().unwrap_or_default(),
                        super::GENESIS,
                        "the sample is not mainnet"
                    );
                }
                Some("block") => {
                    let height = value["height"].as_u64().unwrap();
                    assert!(
                        height + 1 >= layout.first && height <= layout.last(),
                        "block {height} is outside the layout"
                    );
                    let hash =
                        BlockHash::from_display_hex(value["hash"].as_str().unwrap()).unwrap();
                    let prev_hash =
                        BlockHash::from_display_hex(value["prev_hash"].as_str().unwrap()).unwrap();
                    let mut txs = Vec::new();
                    for tx in value["transactions"].as_array().unwrap() {
                        let txid = txid_from_display(tx["txid"].as_str().unwrap());
                        let vin = tx["vin"]
                            .as_array()
                            .map(|v| v.as_slice())
                            .unwrap_or_default()
                            .iter()
                            .map(|input| TxIn {
                                prevout: OutPoint {
                                    txid: txid_from_display(input["txid"].as_str().unwrap()),
                                    n: input["n"].as_u64().unwrap() as u32,
                                },
                                prev: match (input["script"].as_str(), input["value_zat"].as_u64())
                                {
                                    (Some(script), Some(value)) => Some(TxOut {
                                        script: ScriptBytes::new(hex::decode(script).unwrap()),
                                        value,
                                    }),
                                    _ => None,
                                },
                            })
                            .collect();
                        let vout = tx["vout"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|out| TxOut {
                                script: ScriptBytes::new(
                                    hex::decode(out["script"].as_str().unwrap()).unwrap(),
                                ),
                                value: out["value_zat"].as_u64().unwrap(),
                            })
                            .collect();
                        txs.push(Tx { txid, vin, vout });
                    }
                    blocks.insert(
                        height,
                        Block {
                            height,
                            hash,
                            prev_hash,
                            txs,
                        },
                    );
                }
                other => panic!("unknown line type {other:?}"),
            }
        }
        for height in layout.first..=layout.last() {
            let block = blocks
                .get(&height)
                .unwrap_or_else(|| panic!("no block at {height}"));
            if let Some(prev) = blocks.get(&(height - 1)) {
                assert_eq!(block.prev_hash, prev.hash, "block {height} does not chain");
            }
        }
        // The parent of the first block is known only by hash.
        let first = &blocks[&layout.first];
        let parent_hash = first.prev_hash;
        blocks.entry(layout.first - 1).or_insert(Block {
            height: layout.first - 1,
            hash: parent_hash,
            prev_hash: BlockHash::from_internal_bytes([0; 32]),
            txs: Vec::new(),
        });
        Chain {
            layout,
            blocks,
            next_tag: 0,
        }
    }
}

/// One script's activity in a chain, for choosing real-chain cases.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub script: ScriptBytes,
    pub receives: u32,
    pub spends: u32,
    pub coinbase: bool,
}

impl Default for Candidate {
    fn default() -> Self {
        Self {
            script: ScriptBytes::new(Vec::new()),
            receives: 0,
            spends: 0,
            coinbase: false,
        }
    }
}

impl Candidate {
    pub fn is_p2pkh(&self) -> bool {
        let s = self.script.as_slice();
        s.len() == 25
            && s[0] == 0x76
            && s[1] == 0xa9
            && s[2] == 0x14
            && s[23] == 0x88
            && s[24] == 0xac
    }

    pub fn is_p2sh(&self) -> bool {
        let s = self.script.as_slice();
        s.len() == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87
    }
}

fn txid_from_display(text: &str) -> Txid {
    let mut bytes: [u8; 32] = hex::decode(text).unwrap().try_into().unwrap();
    bytes.reverse();
    Txid(bytes)
}

// -------------------------------------------------------- path (a): events

/// The events a publisher indexes from these blocks, per shard.
pub fn extract(chain: &Chain) -> Events {
    let mut per_shard: Events = (0..chain.layout.shards).map(|_| Vec::new()).collect();
    let mut outputs: BTreeMap<OutPoint, TxOut> = BTreeMap::new();
    for (height, index, tx) in chain.transactions() {
        if height < chain.layout.first {
            // The parent block is not published; its outputs can still be
            // spent in the set.
            for (n, out) in tx.vout.iter().enumerate() {
                outputs.insert(
                    OutPoint {
                        txid: tx.txid,
                        n: n as u32,
                    },
                    out.clone(),
                );
            }
            continue;
        }
        let shard = chain.layout.shard_of(height);
        let coinbase = index == 0 && tx.vin.is_empty();
        for (input_index, input) in tx.vin.iter().enumerate() {
            let consumed = outputs
                .get(&input.prevout)
                .cloned()
                .or_else(|| input.prev.clone());
            let Some(consumed) = consumed else {
                continue;
            };
            per_shard[shard].push((
                consumed.script.clone(),
                TransparentEvent::Spend(SpendEvent {
                    height: height as u32,
                    spending_txid: tx.txid,
                    transaction_index: index,
                    input_index: input_index as u32,
                    spent_txid: input.prevout.txid,
                    spent_output_index: input.prevout.n,
                }),
            ));
        }
        for (n, out) in tx.vout.iter().enumerate() {
            per_shard[shard].push((
                out.script.clone(),
                TransparentEvent::Receive(ReceiveEvent {
                    height: height as u32,
                    txid: tx.txid,
                    transaction_index: index,
                    output_index: n as u32,
                    value: out.value,
                    coinbase,
                }),
            ));
            outputs.insert(
                OutPoint {
                    txid: tx.txid,
                    n: n as u32,
                },
                out.clone(),
            );
        }
    }
    per_shard
}

/// A chain that carries each of the suite's legacy events as its own
/// transaction, so the two fixture forms can be checked against each other.
pub fn chain_from_events(layout: Layout, events: &Events) -> Chain {
    let mut chain = Chain::synthetic(layout);
    let mut receives: Vec<(ScriptBytes, ReceiveEvent)> = Vec::new();
    let mut spends: Vec<(ScriptBytes, SpendEvent)> = Vec::new();
    for shard in events {
        for (script, event) in shard {
            match event {
                TransparentEvent::Receive(r) => receives.push((script.clone(), *r)),
                TransparentEvent::Spend(s) => spends.push((script.clone(), *s)),
            }
        }
    }
    receives.sort_by_key(|(_, r)| (r.height, r.txid, r.output_index));
    for (script, r) in &receives {
        let block = chain.blocks.get_mut(&u64::from(r.height)).unwrap();
        let tx = match block.txs.iter_mut().find(|t| t.txid == r.txid) {
            Some(tx) => tx,
            None => {
                block.txs.push(Tx {
                    txid: r.txid,
                    vin: if r.coinbase {
                        Vec::new()
                    } else {
                        vec![TxIn {
                            prevout: OutPoint {
                                txid: Txid([0xee; 32]),
                                n: 0,
                            },
                            prev: None,
                        }]
                    },
                    vout: Vec::new(),
                });
                block.txs.last_mut().unwrap()
            }
        };
        while tx.vout.len() <= r.output_index as usize {
            tx.vout.push(TxOut {
                script: ScriptBytes::new(vec![0x6a]),
                value: 0,
            });
        }
        tx.vout[r.output_index as usize] = TxOut {
            script: script.clone(),
            value: r.value,
        };
    }
    for (_, s) in &spends {
        let block = chain.blocks.get_mut(&u64::from(s.height)).unwrap();
        let prevout = OutPoint {
            txid: s.spent_txid,
            n: s.spent_output_index,
        };
        match block.txs.iter_mut().find(|t| t.txid == s.spending_txid) {
            Some(tx) => {
                while tx.vin.len() <= s.input_index as usize {
                    tx.vin.push(TxIn {
                        prevout: OutPoint {
                            txid: Txid([0xee; 32]),
                            n: 0,
                        },
                        prev: None,
                    });
                }
                tx.vin[s.input_index as usize].prevout = prevout;
            }
            None => block.txs.push(Tx {
                txid: s.spending_txid,
                vin: vec![TxIn {
                    prevout,
                    prev: None,
                }],
                vout: Vec::new(),
            }),
        }
    }
    chain
}

// ------------------------------------------------------ path (b): expected

/// One event, as a fact about the chain rather than an encoding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fact {
    Receive {
        script: Vec<u8>,
        height: u32,
        txid: [u8; 32],
        tx_index: u16,
        output_index: u32,
        value: u64,
        coinbase: bool,
    },
    Spend {
        script: Vec<u8>,
        height: u32,
        spending_txid: [u8; 32],
        tx_index: u16,
        input_index: u32,
        spent_txid: [u8; 32],
        spent_output_index: u32,
    },
}

impl Fact {
    pub fn of(script: &[u8], event: &TransparentEvent) -> Fact {
        match event {
            TransparentEvent::Receive(r) => Fact::Receive {
                script: script.to_vec(),
                height: r.height,
                txid: r.txid.0,
                tx_index: r.transaction_index,
                output_index: r.output_index,
                value: r.value,
                coinbase: r.coinbase,
            },
            TransparentEvent::Spend(s) => Fact::Spend {
                script: script.to_vec(),
                height: s.height,
                spending_txid: s.spending_txid.0,
                tx_index: s.transaction_index,
                input_index: s.input_index,
                spent_txid: s.spent_txid.0,
                spent_output_index: s.spent_output_index,
            },
        }
    }

    /// The same fact with the transaction index forgotten.
    pub fn without_index(&self) -> Fact {
        let mut fact = self.clone();
        match &mut fact {
            Fact::Receive { tx_index, .. } | Fact::Spend { tx_index, .. } => *tx_index = 0,
        }
        fact
    }
}

/// What a wallet holding `scripts` must hold after reading `from..=through`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Expected {
    pub events: BTreeSet<Fact>,
    /// Unspent outputs: script, value, creation height, coinbase.
    pub utxos: BTreeMap<(Txid, u32), (Vec<u8>, u64, u64, bool)>,
    /// Spent outputs: script, value, spend height, spending txid.
    pub spends: BTreeMap<(Txid, u32), (Vec<u8>, u64, u64, Txid)>,
    /// Per transaction: height, received, spent.
    pub history: BTreeMap<Txid, (u64, u64, u64)>,
    pub balance: u64,
    /// Spends of wallet outputs created below `from`, which the wallet cannot
    /// resolve and must count rather than absorb.
    pub unresolved: usize,
}

pub fn reduce(chain: &Chain, scripts: &[ScriptBytes], from: u64, through: u64) -> Expected {
    let mine: BTreeSet<&[u8]> = scripts.iter().map(|s| s.as_slice()).collect();
    let mut expected = Expected::default();
    // Every wallet output ever created, with its creation height, so a spend
    // of one from below `from` is recognised as unresolved rather than
    // mistaken for a fixture bug.
    let mut created: BTreeMap<(Txid, u32), (Vec<u8>, u64, u64, bool)> = BTreeMap::new();
    let mut unspent: BTreeMap<(Txid, u32), (Vec<u8>, u64, u64, bool)> = BTreeMap::new();
    let mut spent: BTreeSet<(Txid, u32)> = BTreeSet::new();
    for (height, index, tx) in chain.transactions() {
        let coinbase = index == 0 && tx.vin.is_empty();
        let in_range = height >= from && height <= through;
        let mut received = 0u64;
        let mut spent_value = 0u64;
        // Inputs before outputs: a transaction cannot spend its own output.
        for (input_index, input) in tx.vin.iter().enumerate() {
            let key = (input.prevout.txid, input.prevout.n);
            let Some((script, value, created_at, _)) = created.get(&key).cloned() else {
                // Not a wallet output, or one the chain never saw.
                continue;
            };
            if !in_range {
                // Spent outside the range the wallet read: the output stays
                // whatever it was, and the spend is not an event it holds.
                if height > through {
                    continue;
                }
                // Below `from`: the wallet never sees this spend either, and
                // the output it consumed is not in its ledger.
                unspent.remove(&key);
                continue;
            }
            assert!(spent.insert(key), "a fixture double-spends {:?}", key);
            expected.events.insert(Fact::Spend {
                script: script.clone(),
                height: height as u32,
                spending_txid: tx.txid.0,
                tx_index: index,
                input_index: input_index as u32,
                spent_txid: input.prevout.txid.0,
                spent_output_index: input.prevout.n,
            });
            if created_at < from {
                expected.unresolved += 1;
                continue;
            }
            assert!(
                unspent.remove(&key).is_some(),
                "a fixture spends an output the wallet does not hold: {key:?}"
            );
            expected
                .spends
                .insert(key, (script, value, height, tx.txid));
            spent_value += value;
        }
        for (n, out) in tx.vout.iter().enumerate() {
            if !mine.contains(out.script.as_slice()) {
                continue;
            }
            let key = (tx.txid, n as u32);
            let fact = (out.script.as_slice().to_vec(), out.value, height, coinbase);
            created.insert(key, fact.clone());
            if !in_range {
                continue;
            }
            expected.events.insert(Fact::Receive {
                script: out.script.as_slice().to_vec(),
                height: height as u32,
                txid: tx.txid.0,
                tx_index: index,
                output_index: n as u32,
                value: out.value,
                coinbase,
            });
            unspent.insert(key, fact);
            received += out.value;
        }
        if in_range && (received > 0 || spent_value > 0) {
            let entry = expected.history.entry(tx.txid).or_insert((height, 0, 0));
            entry.1 += received;
            entry.2 += spent_value;
        }
    }
    expected.balance = unspent.values().map(|(_, value, _, _)| value).sum();
    expected.utxos = unspent;
    expected
}

/// Holds the store to `expected`: the events it keeps, the ledger the library
/// replays from them, and the balance, outputs and history the wallet shows.
pub fn compare_blocks(db: &mut WalletDb, account: AccountId, expected: &Expected) {
    let mine: BTreeSet<Vec<u8>> = my_scripts(db, account)
        .into_iter()
        .map(|s| s.as_slice().to_vec())
        .collect();

    // 1. The events themselves.
    let stored: BTreeSet<Fact> = super::stored_events(db)
        .iter()
        .filter(|(script, _)| mine.contains(script))
        .map(|(script, event)| Fact::of(script, event))
        .collect();
    let missing: Vec<_> = expected.events.difference(&stored).collect();
    let extra: Vec<_> = stored.difference(&expected.events).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "events differ: missing {missing:#?}, extra {extra:#?}"
    );

    // 2. The ledger the library replays from them.
    let ledger = store_ledger(db);
    let utxos: BTreeMap<(Txid, u32), (Vec<u8>, u64, u64, bool)> = ledger
        .utxos()
        .filter(|u| mine.contains(&u.script))
        .map(|u| {
            (
                (u.txid, u.output_index),
                (
                    u.script.clone(),
                    u.value,
                    u64::from(u.creation_height),
                    u.coinbase,
                ),
            )
        })
        .collect();
    assert_eq!(utxos, expected.utxos, "UTXO sets differ");
    let spends: BTreeMap<(Txid, u32), (Vec<u8>, u64, u64, Txid)> = ledger
        .spends()
        .iter()
        .filter(|s| mine.contains(&s.script))
        .map(|s| {
            (
                (s.spent_txid, s.spent_output_index),
                (
                    s.script.clone(),
                    s.value,
                    u64::from(s.height),
                    s.spending_txid,
                ),
            )
        })
        .collect();
    assert_eq!(spends, expected.spends, "spend sets differ");
    let history: BTreeMap<Txid, (u64, u64, u64)> = ledger
        .history()
        .iter()
        .map(|t| (t.txid, (u64::from(t.height), t.received, t.spent)))
        .collect();
    assert_eq!(history, expected.history, "ledger histories differ");
    assert_eq!(
        ledger.unresolved().len(),
        expected.unresolved,
        "unresolved spends differ"
    );

    // 3. What the wallet shows.
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        expected.balance,
        "the balance shown differs"
    );
    let address_of: BTreeMap<Vec<u8>, String> = db
        .connection()
        .prepare(
            "SELECT transparent_script, transparent_address FROM cache.addresses
             WHERE account_id = ?1 AND transparent_script IS NOT NULL",
        )
        .unwrap()
        .query_map([account.0], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut shown: Vec<(String, u64, Option<u64>)> = db
        .transparent_utxos(account)
        .unwrap()
        .into_iter()
        .map(|(address, value, height)| (address, value, height.map(u64::from)))
        .collect();
    shown.sort();
    let mut wanted: Vec<(String, u64, Option<u64>)> = expected
        .utxos
        .values()
        .map(|(script, value, height, _)| (address_of[script].clone(), *value, Some(*height)))
        .collect();
    wanted.sort();
    assert_eq!(shown, wanted, "the outputs shown differ");
    let mut shown_history: BTreeMap<Txid, (u64, u64, u64)> = BTreeMap::new();
    for entry in db.history(account, usize::MAX).unwrap() {
        let txid = Txid(*entry.txid.as_ref());
        let height = entry.mined_height.map(u64::from).unwrap_or(0);
        shown_history.insert(
            txid,
            (height, entry.received.into_u64(), entry.spent.into_u64()),
        );
    }
    assert_eq!(shown_history, expected.history, "the history shown differs");
    assert_eq!(
        state(db, account).unresolved_spends as usize,
        expected.unresolved,
        "unresolved spends shown differ"
    );
    let _ = h;
}
