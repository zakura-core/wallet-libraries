//! The simulated chain: real heights, a block every 75 seconds, real Ironwood note
//! encryption, and a record of every payment the receiver directory could index.

use std::{collections::BTreeMap, time::Duration};

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use receiver_directory::{Payment, Receiver, Record};
use zcash_client_backend::{
    data_api::{
        chain::{BlockSource as _, ChainState},
        testing::{AddressType, FakeCompactOutput, IronwoodFvk, TestBuilder, TestCache, TestState},
    },
    proto::compact_formats::CompactBlock,
};
use zcash_client_sqlite::{
    testing::{
        BlockCache, BlockCacheInsertionResult,
        db::{TestDb, TestDbFactory},
    },
    util::testing::FixedClock,
};
use zcash_primitives::{
    block::BlockHash,
    transaction::{Transaction, TxId},
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    local_consensus::LocalNetwork,
    value::Zatoshis,
};

/// Ironwood, and every upgrade before it, activates at this height.
pub const ACTIVATION: u32 = 100_000;
/// Seconds between blocks.
pub const BLOCK_SECS: i64 = 75;
/// Unix time of the block at [`ACTIVATION`] (2026-09-21).
pub const T0: i64 = 1_790_000_000;
/// The genesis hash every publication commits to.
pub const GENESIS: [u8; 32] = [9; 32];
pub const MINUTE: i64 = 60;
pub const HOUR: i64 = 3_600;
pub const DAY: i64 = 86_400;
pub const ZEC: u64 = 100_000_000;

/// The simulated network: mainnet's upgrade order with everything active at
/// [`ACTIVATION`].
pub fn network() -> LocalNetwork {
    let at = Some(BlockHeight::from_u32(ACTIVATION));
    LocalNetwork {
        nu6: at,
        nu6_1: at,
        nu6_2: at,
        nu6_3: at,
        ..TestBuilder::<(), ()>::DEFAULT_NETWORK
    }
}

/// The time stamped on block `height`.
pub fn block_time(height: BlockHeight) -> i64 {
    T0 + (i64::from(u32::from(height)) - i64::from(ACTIVATION)) * BLOCK_SECS
}

/// Days since [`T0`] at Unix time `unix`.
pub fn day_of(unix: i64) -> f64 {
    (unix - T0) as f64 / DAY as f64
}

/// A block cache that stamps each block with its scheduled time, which the wallet's
/// closing rules read.
pub struct TimedCache(BlockCache);

impl TestCache for TimedCache {
    type BsError = <BlockCache as TestCache>::BsError;
    type BlockSource = <BlockCache as TestCache>::BlockSource;
    type InsertResult = BlockCacheInsertionResult;

    fn block_source(&self) -> &Self::BlockSource {
        self.0.block_source()
    }

    fn insert(&mut self, cb: &CompactBlock) -> Self::InsertResult {
        let mut cb = cb.clone();
        cb.time = u32::try_from(block_time(cb.height())).expect("block times fit u32");
        self.0.insert(&cb)
    }

    fn truncate_to_height(&mut self, height: BlockHeight) {
        self.0.truncate_to_height(height)
    }
}

/// Who paid an output, which decides whether the receiver directory can index it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Payer {
    /// NEAR pays with the all-zero outgoing viewing key, so the directory recovers the
    /// receiver and lists the payment.
    Near,
    /// An ordinary wallet pays with its own outgoing viewing key, which the directory
    /// cannot use.
    Wallet,
}

impl Payer {
    /// How the timeline and report name the payer.
    pub fn label(self) -> &'static str {
        match self {
            Self::Near => "NEAR (zero OVK)",
            Self::Wallet => "a wallet (own OVK)",
        }
    }
}

/// An Ironwood output the chain mined to a known receiver.
#[derive(Clone, Debug)]
pub struct Mined {
    pub txid: TxId,
    pub action_index: u32,
    pub height: BlockHeight,
    /// The output's leaf position in the Ironwood note commitment tree.
    pub position: u64,
    pub value: u64,
    pub receiver: [u8; 43],
    pub payer: Payer,
    /// The record a zero-OVK payment gives the directory.
    pub indexed: Option<Record>,
}

impl Mined {
    /// The output's identity in a wallet: transaction and action index.
    pub fn id(&self) -> ([u8; 32], u32) {
        (*self.txid.as_ref(), self.action_index)
    }
}

/// The receiver bytes of `fvk`'s default external address.
pub fn receiver_of(fvk: &FullViewingKey) -> [u8; 43] {
    fvk.address_at(0u32, Scope::External).to_raw_address_bytes()
}

/// Other people's Ironwood activity: `outputs` outputs to a foreign key in every
/// `every`-th block. Mainnet blocks almost always carry shielded outputs, and wallets
/// checkpoint their note commitment trees only at blocks that do.
#[derive(Clone, Copy, Debug)]
pub struct Traffic {
    pub every: u32,
    pub outputs: usize,
}

impl Default for Traffic {
    fn default() -> Self {
        Self {
            every: 10,
            outputs: 1,
        }
    }
}

/// The simulated chain and the shared clock wallets read.
pub struct Chain {
    st: TestState<TimedCache, TestDb, LocalNetwork>,
    states: BTreeMap<u32, ChainState>,
    commitments: Vec<[u8; 32]>,
    mined: Vec<Mined>,
    /// The base clock; wallets read clones of it, offset by their skew.
    clocks: Vec<(FixedClock, i64)>,
    clock_now: i64,
    /// Background activity added while mining; scenarios may change it.
    pub traffic: Traffic,
    foreign: FullViewingKey,
    /// Wallet-built transactions the chain mined, as raw bytes with their heights, for
    /// wallets that ask for them by txid.
    txs: BTreeMap<[u8; 32], (Vec<u8>, BlockHeight)>,
}

impl Chain {
    /// A chain holding only its activation block.
    pub fn new() -> Self {
        let st = TestBuilder::new()
            .with_network(network())
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(TimedCache(BlockCache::new()))
            .build();
        let mut chain = Self {
            st,
            states: BTreeMap::new(),
            commitments: Vec::new(),
            mined: Vec::new(),
            clocks: Vec::new(),
            clock_now: T0,
            traffic: Traffic::default(),
            foreign: FullViewingKey::from(
                &SpendingKey::from_bytes([7; 32]).expect("a valid spending key"),
            ),
            txs: BTreeMap::new(),
        };
        chain.mine(1);
        chain
    }

    /// The latest block.
    pub fn tip(&self) -> BlockHeight {
        self.st.latest_cached_block().expect("the chain has blocks").height()
    }

    /// Unix time now, which is the tip's block time.
    pub fn now(&self) -> i64 {
        block_time(self.tip())
    }

    /// A clock for a wallet whose device runs `skew` seconds ahead (or behind, if
    /// negative). It follows the chain.
    pub fn clock(&mut self, skew: i64) -> FixedClock {
        let clock = FixedClock::new(
            std::time::UNIX_EPOCH + Duration::from_secs((self.clock_now + skew) as u64),
        );
        self.clocks.push((clock.clone(), skew));
        clock
    }

    /// Records the state at the new tip and moves every clock to its time.
    fn advance(&mut self) {
        let block = self.st.latest_cached_block().expect("a block was just added");
        self.states
            .insert(u32::from(block.height()), block.chain_state().clone());
        let now = self.now();
        if now > self.clock_now {
            let delta = Duration::from_secs((now - self.clock_now) as u64);
            for (clock, _) in &self.clocks {
                clock.tick(delta);
            }
            self.clock_now = now;
        }
    }

    /// Mines `n` blocks of background traffic only (see [`Traffic`]).
    pub fn mine(&mut self, n: u32) {
        for _ in 0..n {
            // The chain's first block carries no traffic.
            let next = self
                .st
                .latest_cached_block()
                .map(|block| u32::from(block.height()) + 1);
            let traffic = self.traffic;
            let busy = next.is_some_and(|h| traffic.every > 0 && h % traffic.every == 0);
            if traffic.outputs > 0 && busy {
                let outputs: Vec<_> = (0..traffic.outputs)
                    .map(|_| {
                        FakeCompactOutput::new(
                            IronwoodFvk(self.foreign.clone()),
                            AddressType::DefaultExternal,
                            Zatoshis::const_from_u64(10_000),
                        )
                    })
                    .collect();
                let (height, _, _) = self.st.generate_next_block_multi(&outputs);
                self.advance();
                let block = self.block(height);
                for tx in &block.vtx {
                    for action in &tx.ironwood_actions {
                        self.commitments
                            .push(action.cmx.as_slice().try_into().expect("32-byte cmx"));
                    }
                }
            } else {
                self.st.generate_empty_block();
                self.advance();
            }
        }
    }

    /// Mines empty blocks until at least `secs` have passed, at least one block.
    pub fn wait(&mut self, secs: i64) {
        let blocks = (secs + BLOCK_SECS - 1) / BLOCK_SECS;
        self.mine(u32::try_from(blocks.max(1)).expect("waits fit u32"));
    }

    /// Mines empty blocks until the tip's time is at least `at`.
    pub fn mine_until(&mut self, at: i64) {
        let behind = at - self.now();
        if behind > 0 {
            let blocks = (behind + BLOCK_SECS - 1) / BLOCK_SECS;
            self.mine(u32::try_from(blocks).expect("waits fit u32"));
        }
    }

    /// Mines empty blocks until the next block's time is at least `at`, so a payment
    /// mined next lands at `at` or just after.
    pub fn mine_until_next_at(&mut self, at: i64) {
        self.mine_until(at - BLOCK_SECS);
    }

    /// The chain state at the end of the block below `height`, which scanning from
    /// `height` and an account birthday at `height` start from.
    pub fn state_below(&self, height: BlockHeight) -> ChainState {
        self.states[&(u32::from(height) - 1)].clone()
    }

    /// The hash of block `height`.
    pub fn hash_at(&self, height: BlockHeight) -> BlockHash {
        self.states[&u32::from(height)].block_hash()
    }

    /// The Ironwood note commitment tree size at the end of block `height`.
    pub fn tree_size_at(&self, height: BlockHeight) -> u64 {
        self.states[&u32::from(height)]
            .final_ironwood_tree()
            .tree_size()
    }

    /// Every Ironwood note commitment, in tree order.
    pub fn commitments(&self) -> &[[u8; 32]] {
        &self.commitments
    }

    /// Every output mined to a known receiver, in chain order.
    pub fn mined(&self) -> &[Mined] {
        &self.mined
    }

    /// The compact blocks wallets scan.
    pub fn block_source(&self) -> &<TimedCache as TestCache>::BlockSource {
        self.st.cache()
    }

    /// Mines one block with one transaction paying each of `outputs` from `payer`.
    pub fn pay(&mut self, outputs: &[(FullViewingKey, u64)], payer: Payer) -> Vec<Mined> {
        let first_position = self.commitments.len() as u64;
        let fake: Vec<_> = outputs
            .iter()
            .map(|(fvk, value)| {
                FakeCompactOutput::new(
                    IronwoodFvk(fvk.clone()),
                    AddressType::DefaultExternal,
                    Zatoshis::const_from_u64(*value),
                )
            })
            .collect();
        let (height, _, _) = self.st.generate_next_block_multi(&fake);
        self.advance();
        let block = self.block(height);
        let tx = &block.vtx[0];
        let txid = tx.txid();
        let mut mined = Vec::new();
        for (index, ((fvk, value), compact)) in
            outputs.iter().zip(&tx.ironwood_actions).enumerate()
        {
            let cmx: [u8; 32] = compact.cmx.as_slice().try_into().expect("32-byte cmx");
            self.commitments.push(cmx);
            let position = first_position + index as u64;
            let action_index = u32::try_from(index).expect("few actions");
            let receiver = receiver_of(fvk);
            let indexed = (payer == Payer::Near).then(|| Record {
                    receiver: Receiver::from_bytes(receiver).expect("a valid receiver"),
                    page: 0,
                    total: 1,
                    payment: Payment {
                        height: u32::from(height),
                        block_hash: block.hash().0,
                        txid: *txid.as_ref(),
                        // The fake block has no coinbase; the directory reads index 0 as one.
                        tx_index: u32::try_from(tx.index).expect("small index") + 1,
                        action_index,
                        position,
                        action_nullifier: compact
                            .nullifier
                            .as_slice()
                            .try_into()
                            .expect("32-byte nullifier"),
                        cmx,
                        ephemeral_key: compact
                            .ephemeral_key
                            .as_slice()
                            .try_into()
                            .expect("32-byte key"),
                        ciphertext_prefix: compact
                            .ciphertext
                            .as_slice()
                            .try_into()
                            .expect("52 bytes"),
                    },
            });
            let entry = Mined {
                txid,
                action_index,
                height,
                position,
                value: *value,
                receiver,
                payer,
                indexed,
            };
            self.mined.push(entry.clone());
            mined.push(entry);
        }
        mined
    }

    /// Mines a block holding only `tx`, a transaction a wallet built and signed.
    pub fn mine_tx(&mut self, tx: &Transaction) -> BlockHeight {
        let (height, _) = self.st.generate_next_block_from_tx(1, tx);
        self.advance();
        let block = self.block(height);
        for compact in &block.vtx {
            for action in &compact.ironwood_actions {
                self.commitments
                    .push(action.cmx.as_slice().try_into().expect("32-byte cmx"));
            }
        }
        let mut raw = Vec::new();
        tx.write(&mut raw).expect("the transaction serializes");
        self.txs.insert(*tx.txid().as_ref(), (raw, height));
        height
    }

    /// A transaction the chain mined, and its height, as lightwalletd's GetTransaction
    /// would return it.
    pub fn transaction(&self, txid: &TxId) -> Option<(Transaction, BlockHeight)> {
        let (raw, height) = self.txs.get(txid.as_ref())?;
        let branch = BranchId::for_height(&network(), *height);
        let tx = Transaction::read(&raw[..], branch).expect("the stored transaction parses");
        Some((tx, *height))
    }

    /// The cached compact block at `height`.
    fn block(&self, height: BlockHeight) -> CompactBlock {
        let mut block = None;
        self.st
            .cache()
            .with_blocks::<_, ()>(Some(height), Some(1), |cb| {
                block = Some(cb);
                Ok(())
            })
            .expect("the block is cached");
        block.expect("the block is cached")
    }
}
