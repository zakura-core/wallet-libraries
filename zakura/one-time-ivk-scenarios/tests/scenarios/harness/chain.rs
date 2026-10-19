//! The simulated chain: real heights, a block every 75 seconds, real Ironwood note
//! encryption, and a record of every payment the receiver directory could index.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, PoisonError, RwLock},
    time::Duration,
};

use incrementalmerkletree::frontier::Frontier;
use orchard::{
    Anchor,
    bundle::BatchValidator,
    circuit::{OrchardCircuitVersion, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendingKey},
    tree::MerkleHashOrchard,
};
use transparent::{address::Script, sighash::TransparentAuthorizingContext};
use zakura_receiver_crypto::{Payment, Receiver, Record};
use zcash_client_backend::{
    data_api::{
        TransactionStatus,
        chain::{BlockSource, ChainState, error::Error as ChainError},
        testing::{
            AddressType, CacheInsertionResult, FakeCompactOutput, IronwoodFvk, TestBuilder,
            TestCache, TestRng, TestState,
        },
    },
    proto::compact_formats::CompactBlock,
};
use zcash_client_sqlite::{
    testing::db::{TestDb, TestDbFactory},
    util::testing::FixedClock,
};
use zcash_primitives::{
    block::BlockHash,
    transaction::{
        Authorization, Transaction, TransactionData, TxId,
        sighash::{SignableInput, signature_hash},
        txid::TxIdDigester,
    },
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

/// The chain's compact blocks, in memory and shared, so a reorg can replace them.
#[derive(Clone, Default)]
pub struct Blocks(Arc<RwLock<BTreeMap<u32, CompactBlock>>>);

impl BlockSource for Blocks {
    type Error = std::convert::Infallible;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ChainError<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ChainError<WalletErrT, Self::Error>>,
    {
        let from = from_height.map_or(0, u32::from);
        let blocks: Vec<CompactBlock> = self
            .0
            .read()
            .unwrap()
            .range(from..)
            .take(limit.unwrap_or(usize::MAX))
            .map(|(_, block)| block.clone())
            .collect();
        for block in blocks {
            with_block(block)?;
        }
        Ok(())
    }
}

/// What inserting a block reports to the test chain.
pub struct Inserted(Vec<TxId>);

impl CacheInsertionResult for Inserted {
    fn txids(&self) -> &[TxId] {
        &self.0
    }
}

/// A block cache that stamps each block with its scheduled time, which the wallet's
/// closing rules read, and lets a reorg replace blocks.
pub struct TimedCache(Blocks);

impl TestCache for TimedCache {
    type BsError = std::convert::Infallible;
    type BlockSource = Blocks;
    type InsertResult = Inserted;

    fn block_source(&self) -> &Self::BlockSource {
        &self.0
    }

    fn insert(&mut self, cb: &CompactBlock) -> Self::InsertResult {
        let mut cb = cb.clone();
        cb.time = u32::try_from(block_time(cb.height())).expect("block times fit u32");
        // A fake block has no coinbase. Number its transactions as if it had one, as the
        // directory's records do, so a wallet that stores a transaction from scanning
        // agrees with the directory on its index.
        if cb.vtx.first().is_some_and(|tx| tx.index == 0) {
            for tx in &mut cb.vtx {
                tx.index += 1;
            }
        }
        let txids = cb.vtx.iter().map(|tx| tx.txid()).collect();
        self.0.0.write().unwrap().insert(u32::from(cb.height()), cb);
        Inserted(txids)
    }

    fn truncate_to_height(&mut self, height: BlockHeight) {
        self.0
            .0
            .write()
            .unwrap()
            .split_off(&(u32::from(height) + 1));
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
    pub payer: Payer,
    /// The receiver it pays, as raw address bytes.
    pub receiver: [u8; 43],
    /// The record a zero-OVK payment gives the directory.
    pub indexed: Option<Record>,
    /// The nullifier that spends the received note, derived with the receiving key.
    pub nullifier: [u8; 32],
}

impl Mined {
    /// The output's identity in a wallet: transaction and action index.
    pub fn id(&self) -> ([u8; 32], u32) {
        (*self.txid.as_ref(), self.action_index)
    }
}

/// The nullifier of the note `compact` pays `fvk`'s default external address, which
/// spends it. Panics if the action does not decrypt with `fvk`.
fn received_nullifier(
    fvk: &FullViewingKey,
    compact: &zcash_client_backend::proto::compact_formats::CompactOrchardAction,
) -> [u8; 32] {
    use orchard::note_encryption::{CompactAction, IronwoodDomain};
    use zcash_note_encryption::try_compact_note_decryption;
    let action = CompactAction::try_from(compact).expect("a valid compact action");
    let domain = IronwoodDomain::for_compact_action(&action);
    let (note, _) =
        try_compact_note_decryption(&domain, &fvk.to_ivk(Scope::External).prepare(), &action)
            .expect("the output pays the key");
    note.nullifier(fvk).to_bytes()
}

/// `bytes` in lowercase hex, for diagnostics.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
    roots: Roots,
}

/// Blocks [`Chain::root_height`] searches first: wallets anchor at one of their last
/// 100 tree checkpoints, which are blocks with shielded outputs.
const RECENT_ROOTS: u32 = 2_000;

/// Ironwood tree roots at block boundaries, computed from [`Chain::commitments`] on
/// demand, since hashing every boundary of a long chain takes seconds.
struct Roots {
    /// The tree of the first `len` commitments.
    frontier: Frontier<MerkleHashOrchard, 32>,
    len: u64,
    /// Roots computed so far, by tree size.
    by_size: BTreeMap<u64, MerkleHashOrchard>,
}

impl Roots {
    /// No roots computed yet.
    fn new() -> Self {
        Self {
            frontier: Frontier::empty(),
            len: 0,
            by_size: BTreeMap::new(),
        }
    }

    /// The root of the tree of the first `size` of `commitments`. Rebuilds the frontier
    /// when `size` is below it, so callers ask in ascending order.
    fn root(&mut self, commitments: &[[u8; 32]], size: u64) -> MerkleHashOrchard {
        if let Some(root) = self.by_size.get(&size) {
            return *root;
        }
        if size < self.len {
            self.frontier = Frontier::empty();
            self.len = 0;
        }
        for cmx in &commitments[usize::try_from(self.len).expect("fits")..] {
            if self.len == size {
                break;
            }
            let leaf = MerkleHashOrchard::from_bytes(cmx).expect("a canonical commitment");
            assert!(self.frontier.append(leaf), "the tree has room");
            self.len += 1;
        }
        assert_eq!(self.len, size, "the chain holds {size} commitments");
        let root = self.frontier.root();
        self.by_size.insert(size, root);
        root
    }

    /// Forgets every root past `size`, as a rewind to that tree size does.
    fn truncate(&mut self, size: u64) {
        self.by_size.split_off(&(size + 1));
        if self.len > size {
            self.frontier = Frontier::empty();
            self.len = 0;
        }
    }
}

/// What [`Chain::accepts`] found.
pub struct Accepted {
    /// The latest block whose final Ironwood tree root is the transaction's anchor.
    pub anchor_height: BlockHeight,
    /// Ironwood actions whose proofs and signatures verified.
    pub actions: usize,
}

/// A transaction's authorization with its transparent inputs left out, which lets its
/// shielded sighash be computed when it has none.
struct ShieldedOnly;

impl Authorization for ShieldedOnly {
    type TransparentAuth = NoInputs;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

/// A transparent bundle without inputs, so there is nothing for a sighash to commit to.
#[derive(Debug)]
struct NoInputs;

impl transparent::bundle::Authorization for NoInputs {
    type ScriptSig = ();
}

impl TransparentAuthorizingContext for NoInputs {
    /// No inputs, so no amounts.
    fn input_amounts(&self) -> Vec<Zatoshis> {
        Vec::new()
    }

    /// No inputs, so no scripts.
    fn input_scriptpubkeys(&self) -> Vec<Script> {
        Vec::new()
    }
}

/// The sighash `tx`'s spend authorizations and binding signatures sign, computed as the
/// PCZT transaction extractor does, for a transaction without transparent inputs.
fn shielded_sighash(tx: &Transaction) -> [u8; 32] {
    let mut raw = Vec::new();
    tx.write(&mut raw).expect("the transaction serializes");
    let data = Transaction::read(&raw[..], tx.consensus_branch_id())
        .expect("the transaction parses")
        .into_data();
    let data: TransactionData<ShieldedOnly> = data.map_bundles(
        |t| {
            t.map(|b| {
                assert!(b.vin.is_empty(), "no transparent inputs");
                transparent::bundle::Bundle {
                    vin: Vec::new(),
                    vout: b.vout,
                    authorization: NoInputs,
                }
            })
        },
        |s| s,
        |o| o,
    );
    let parts = data.digest(TxIdDigester);
    *signature_hash(&data, &SignableInput::Shielded, &parts).as_ref()
}

/// The verifying key for `version`, built once per run, since building one takes
/// seconds.
fn verifying_key(version: OrchardCircuitVersion) -> &'static VerifyingKey {
    static KEYS: Mutex<Vec<&'static VerifyingKey>> = Mutex::new(Vec::new());
    let mut keys = KEYS.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(key) = keys.iter().find(|k| k.circuit_version() == version) {
        return key;
    }
    let key: &'static VerifyingKey = Box::leak(Box::new(VerifyingKey::build(version)));
    keys.push(key);
    key
}

impl Chain {
    /// A chain holding only its activation block.
    pub fn new() -> Self {
        let st = TestBuilder::new()
            .with_network(network())
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(TimedCache(Blocks::default()))
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
            roots: Roots::new(),
        };
        chain.mine(1);
        chain
    }

    /// The latest block.
    pub fn tip(&self) -> BlockHeight {
        self.st
            .latest_cached_block()
            .expect("the chain has blocks")
            .height()
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
        let block = self
            .st
            .latest_cached_block()
            .expect("a block was just added");
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

    /// The hash of block `height`, if the chain has it.
    pub fn known_hash(&self, height: BlockHeight) -> Option<BlockHash> {
        self.states
            .get(&u32::from(height))
            .map(|state| state.block_hash())
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
        for (index, ((fvk, value), compact)) in outputs.iter().zip(&tx.ironwood_actions).enumerate()
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
                    // The cache numbers transactions after a coinbase (see `TimedCache`).
                    tx_index: u32::try_from(tx.index).expect("small index"),
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
                    ciphertext_prefix: compact.ciphertext.as_slice().try_into().expect("52 bytes"),
                },
            });
            let entry = Mined {
                txid,
                action_index,
                height,
                position,
                value: *value,
                payer,
                receiver,
                indexed,
                nullifier: received_nullifier(fvk, compact),
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

    /// Replaces every block above `to`, as a reorg does: the new branch starts with one
    /// empty block at `to + 1`. Outputs mined above `to` are forgotten (the directory no
    /// longer lists them); wallet-built transactions stay available to mine again.
    pub fn rewind(&mut self, to: BlockHeight) {
        let at = u32::from(to);
        self.st.cache().0.write().unwrap().split_off(&(at + 1));
        self.states.retain(|h, _| *h <= at);
        let size = usize::try_from(self.tree_size_at(to)).expect("fits");
        self.commitments.truncate(size);
        self.roots.truncate(size as u64);
        self.mined.retain(|m| u32::from(m.height) <= at);
        self.txs.retain(|_, (_, height)| u32::from(*height) <= at);
        let state = self.states[&at].clone();
        let sizes = |tree: u64| u32::try_from(tree).expect("fits");
        self.st.generate_block_at::<IronwoodFvk>(
            to + 1,
            state.block_hash(),
            &[],
            sizes(state.final_sapling_tree().tree_size()),
            sizes(state.final_orchard_tree().tree_size()),
            sizes(state.final_ironwood_tree().tree_size()),
            false,
        );
        self.advance();
    }

    /// Records the output of the transaction mined at `height` that `fvk`'s default
    /// address received, found by trial decryption, as a payment from `payer`.
    pub fn record_payment(
        &mut self,
        height: BlockHeight,
        fvk: &FullViewingKey,
        value: u64,
        payer: Payer,
    ) -> Mined {
        use orchard::note_encryption::{CompactAction, IronwoodDomain};
        use zcash_note_encryption::try_compact_note_decryption;
        let block = self.block(height);
        let ivk = fvk.to_ivk(Scope::External).prepare();
        let first = self.tree_size_at(height - 1);
        let mut index = 0u64;
        for tx in &block.vtx {
            for (action_index, compact) in tx.ironwood_actions.iter().enumerate() {
                let position = first + index;
                index += 1;
                let action = CompactAction::try_from(compact).expect("a valid compact action");
                let domain = IronwoodDomain::for_compact_action(&action);
                if try_compact_note_decryption(&domain, &ivk, &action).is_none() {
                    continue;
                }
                let txid = tx.txid();
                let receiver = receiver_of(fvk);
                let cmx: [u8; 32] = compact.cmx.as_slice().try_into().expect("32-byte cmx");
                let action_index = u32::try_from(action_index).expect("few actions");
                let indexed = (payer == Payer::Near).then(|| Record {
                    receiver: Receiver::from_bytes(receiver).expect("a valid receiver"),
                    page: 0,
                    total: 1,
                    payment: Payment {
                        height: u32::from(height),
                        block_hash: block.hash().0,
                        txid: *txid.as_ref(),
                        tx_index: u32::try_from(tx.index).expect("small index").max(1),
                        action_index,
                        position,
                        action_nullifier: compact
                            .nullifier
                            .as_slice()
                            .try_into()
                            .expect("32 bytes"),
                        cmx,
                        ephemeral_key: compact
                            .ephemeral_key
                            .as_slice()
                            .try_into()
                            .expect("32 bytes"),
                        ciphertext_prefix: compact
                            .ciphertext
                            .as_slice()
                            .try_into()
                            .expect("52 bytes"),
                    },
                });
                let mined = Mined {
                    txid,
                    action_index,
                    height,
                    position,
                    value,
                    payer,
                    receiver,
                    indexed,
                    nullifier: received_nullifier(fvk, compact),
                };
                self.mined.push(mined.clone());
                return mined;
            }
        }
        panic!("no output in block {} pays the key", u32::from(height));
    }

    /// What lightwalletd would say about `txid`: mined at a height on this branch, or
    /// unknown (a payment the reorg removed and nobody rebroadcast).
    pub fn status(&self, txid: &TxId) -> TransactionStatus {
        if let Some((_, height)) = self.txs.get(txid.as_ref()) {
            if u32::from(*height) <= u32::from(self.tip())
                && self.states.contains_key(&u32::from(*height))
            {
                return TransactionStatus::Mined(*height);
            }
        }
        match self.mined.iter().find(|m| m.txid == *txid) {
            Some(m) => TransactionStatus::Mined(m.height),
            None => TransactionStatus::TxidNotRecognized,
        }
    }

    /// A transaction the chain mined, and its height, as lightwalletd's GetTransaction
    /// would return it.
    pub fn transaction(&self, txid: &TxId) -> Option<(Transaction, BlockHeight)> {
        let (raw, height) = self.txs.get(txid.as_ref())?;
        let branch = BranchId::for_height(&network(), *height);
        let tx = Transaction::read(&raw[..], branch).expect("the stored transaction parses");
        Some((tx, *height))
    }

    /// Checks that consensus would accept `tx`, a wallet-built transaction that spends
    /// only Ironwood notes: its Ironwood anchor is the tree root at the end of some block
    /// on this branch, it reveals no nullifier twice or one the chain already holds, and
    /// its proof, spend authorizations and binding signature verify against its shielded
    /// sighash. Returns why not otherwise.
    pub fn accepts(&mut self, tx: &Transaction) -> Result<Accepted, String> {
        if tx.sapling_bundle().is_some() || tx.orchard_bundle().is_some() {
            return Err("it has Sapling or Orchard parts, which this check does not cover".into());
        }
        if tx.transparent_bundle().is_some_and(|b| !b.vin.is_empty()) {
            return Err("it spends transparent inputs, which this check does not cover".into());
        }
        let bundle = tx.ironwood_bundle().ok_or("it has no Ironwood bundle")?;
        let tip_size = self.tree_size_at(self.tip());
        if tip_size != self.commitments.len() as u64 {
            return Err(format!(
                "the chain recorded {} commitments for a tree of {tip_size}",
                self.commitments.len()
            ));
        }
        let anchor_height = self.root_height(bundle.anchor()).ok_or_else(|| {
            format!(
                "its anchor {} is no block's Ironwood tree root",
                hex(&bundle.anchor().to_bytes())
            )
        })?;
        // The batch validator checks proofs and signatures, not nullifier uniqueness.
        let spent = self.nullifiers();
        let mut revealed = BTreeSet::new();
        for action in bundle.actions() {
            let nf = action.nullifier().to_bytes();
            if spent.contains(&nf) {
                return Err(format!(
                    "it reveals nullifier {}, already on chain",
                    hex(&nf)
                ));
            }
            if !revealed.insert(nf) {
                return Err(format!("it reveals nullifier {} twice", hex(&nf)));
            }
        }
        let sighash = shielded_sighash(tx);
        let mut validator =
            BatchValidator::new(verifying_key(bundle.bundle_version().circuit_version()));
        validator
            .add_bundle(bundle, sighash)
            .map_err(|e| format!("the verifier refused its bundle: {e:?}"))?;
        let seed = u64::from_le_bytes(tx.txid().as_ref()[..8].try_into().expect("8 bytes"));
        if !validator.validate(TestRng::seed_from_u64(seed)) {
            return Err("its proof or signatures do not verify".into());
        }
        Ok(Accepted {
            anchor_height,
            actions: bundle.actions().len(),
        })
    }

    /// The latest block on this branch whose final Ironwood tree root is `tx`'s Ironwood
    /// anchor, or `None` when no block's is or `tx` has no Ironwood bundle. Unlike
    /// [`Self::accepts`], it checks nothing else, so it covers transactions with
    /// transparent inputs too.
    pub fn anchor_height(&mut self, tx: &Transaction) -> Option<BlockHeight> {
        let bundle = tx.ironwood_bundle()?;
        self.root_height(bundle.anchor())
    }

    /// The latest block whose final Ironwood tree root is `anchor`, searching the last
    /// [`RECENT_ROOTS`] blocks before the rest of the chain.
    fn root_height(&mut self, anchor: &Anchor) -> Option<BlockHeight> {
        let tip = u32::from(self.tip());
        let first = *self.states.keys().next()?;
        let recent = tip.saturating_sub(RECENT_ROOTS).max(first);
        // Oldest first within each span, so the frontier mostly grows.
        for span in [recent..=tip, first..=recent - 1] {
            let mut found = None;
            for height in span {
                let size = self.tree_size_at(BlockHeight::from_u32(height));
                if Anchor::from(self.roots.root(&self.commitments, size)) == *anchor {
                    found = Some(BlockHeight::from_u32(height));
                }
            }
            if found.is_some() {
                return found;
            }
        }
        None
    }

    /// Every Ironwood nullifier the chain's blocks reveal.
    pub fn nullifiers(&self) -> BTreeSet<[u8; 32]> {
        let blocks = self.st.cache().0.read().unwrap();
        blocks
            .values()
            .flat_map(|block| &block.vtx)
            .flat_map(|tx| &tx.ironwood_actions)
            .map(|action| action.nullifier.as_slice().try_into().expect("32 bytes"))
            .collect()
    }

    /// Every Ironwood nullifier the chain's blocks reveal, with the height revealing it.
    pub fn nullifier_heights(&self) -> BTreeMap<[u8; 32], u32> {
        let blocks = self.st.cache().0.read().unwrap();
        blocks
            .iter()
            .flat_map(|(height, block)| {
                block
                    .vtx
                    .iter()
                    .flat_map(|tx| &tx.ironwood_actions)
                    .map(move |action| {
                        let nf: [u8; 32] =
                            action.nullifier.as_slice().try_into().expect("32 bytes");
                        (nf, *height)
                    })
            })
            .collect()
    }

    /// Every wallet-built transaction mined on this branch, with its height.
    pub fn mined_txs(&self) -> Vec<(Transaction, BlockHeight)> {
        self.txs
            .keys()
            .filter_map(|txid| self.transaction(&TxId::from_bytes(*txid)))
            .collect()
    }

    /// The cached compact block at `height`.
    fn block(&self, height: BlockHeight) -> CompactBlock {
        self.st.cache().0.read().unwrap()[&u32::from(height)].clone()
    }
}
