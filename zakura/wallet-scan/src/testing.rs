//! A synthetic chain, for driving detection in tests.
//!
//! Blocks built here contain *real* notes: actual Orchard and Ironwood note
//! plaintexts, encrypted with the real note-encryption domains under real
//! viewing keys. Detection is exercised against the same cryptography it will
//! meet on mainnet, so a test that passes here is evidence about the real
//! scanner rather than about a mock of it.
//!
//! Everything is driven by a seeded [`ChaChaRng`], so a given sequence of
//! builder calls always produces byte-identical blocks. That is what makes
//! golden comparisons and shrinking property-test failures possible.

use orchard::{
    Address,
    keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, Note, NoteVersion, Nullifier, RandomSeed, Rho},
    note_encryption::{
        CompactAction, IronwoodDomain, IronwoodNoteEncryption, OrchardDomain, OrchardNoteEncryption,
    },
    value::NoteValue,
};
use rand_chacha::{
    ChaChaRng,
    rand_core::{RngCore, SeedableRng},
};
use transparent::{
    address::{Script, TransparentAddress},
    bundle::{OutPoint, TxOut},
};
use zakura_wallet_core::{
    BlockHash, CompactBlock, CompactTx,
    pool::{PoolId, TreeSizes},
};
use zcash_note_encryption::Domain;
use zcash_protocol::{
    TxId, consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis,
};

use zakura_wallet_core::{BlockAnchor, KeyScope};

/// The height at which Orchard activates on [`test_params`].
pub const ORCHARD_ACTIVATION: u32 = 100;
/// The height at which Ironwood activates on [`test_params`].
pub const IRONWOOD_ACTIVATION: u32 = 200;

/// Consensus parameters with both pools activating at known, low heights.
///
/// Real network parameters put NU6.3 far above any height a test wants to
/// build blocks at, and on some networks it has no activation height at all —
/// which would silently skip the pre-activation checks rather than exercising
/// them.
pub fn test_params() -> LocalNetwork {
    LocalNetwork {
        overwinter: Some(BlockHeight::from_u32(1)),
        sapling: Some(BlockHeight::from_u32(1)),
        blossom: Some(BlockHeight::from_u32(1)),
        heartwood: Some(BlockHeight::from_u32(1)),
        canopy: Some(BlockHeight::from_u32(1)),
        nu5: Some(BlockHeight::from_u32(ORCHARD_ACTIVATION)),
        nu6: Some(BlockHeight::from_u32(ORCHARD_ACTIVATION)),
        nu6_1: Some(BlockHeight::from_u32(ORCHARD_ACTIVATION)),
        nu6_2: Some(BlockHeight::from_u32(ORCHARD_ACTIVATION)),
        nu6_3: Some(BlockHeight::from_u32(IRONWOOD_ACTIVATION)),
    }
}

/// Returns a full viewing key derived deterministically from `seed`.
///
/// Distinct seeds give unrelated accounts, which is what tests need in order to
/// assert that one account cannot see another's notes.
pub fn fvk_from_seed(seed: u8) -> FullViewingKey {
    let mut bytes = [0u8; 32];
    let mut rng = ChaChaRng::from_seed([seed; 32]);
    loop {
        rng.fill_bytes(&mut bytes);
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes)) {
            return FullViewingKey::from(&sk);
        }
    }
}

/// Builds a chain of compact blocks containing real encrypted notes.
pub struct ChainBuilder {
    rng: ChaChaRng,
    next_height: BlockHeight,
    prev_hash: BlockHash,
    anchor: BlockAnchor,
    sizes: TreeSizes,
    blocks: Vec<CompactBlock>,
}

impl ChainBuilder {
    /// Starts a chain whose first block is at `start_height`, anchored on a
    /// synthetic predecessor with empty commitment trees.
    pub fn new(start_height: u32) -> Self {
        Self::with_anchor(start_height, TreeSizes::default())
    }

    /// Starts a chain whose predecessor already has the given tree sizes.
    ///
    /// Used to test scanning a range that begins above the wallet's birthday,
    /// where the trees are already populated.
    pub fn with_anchor(start_height: u32, tree_sizes: TreeSizes) -> Self {
        // Seeded from the starting height, so two chains built independently
        // at different heights produce different transaction identifiers. A
        // fixed seed would make them collide, which silently invalidates any
        // test that applies both to one wallet.
        let mut seed = [0x5a; 32];
        seed[..4].copy_from_slice(&start_height.to_le_bytes());
        let mut rng = ChaChaRng::from_seed(seed);
        let anchor_hash = random_hash(&mut rng);
        Self {
            rng,
            next_height: BlockHeight::from_u32(start_height),
            prev_hash: anchor_hash,
            anchor: BlockAnchor {
                height: BlockHeight::from_u32(start_height.saturating_sub(1)),
                hash: anchor_hash,
                tree_sizes,
            },
            sizes: tree_sizes,
            blocks: Vec::new(),
        }
    }

    /// Returns the anchor the first block of this chain must be scanned against.
    pub fn anchor(&self) -> BlockAnchor {
        self.anchor.clone()
    }

    /// Appends a block, letting `f` populate its transactions.
    pub fn block(&mut self, f: impl FnOnce(&mut BlockBuilder<'_>)) -> &mut Self {
        let height = self.next_height;
        let mut builder = BlockBuilder {
            rng: &mut self.rng,
            txs: Vec::new(),
        };
        f(&mut builder);
        let txs = builder.txs;

        for tx in &txs {
            self.sizes.orchard += tx.orchard_actions.len() as u32;
            self.sizes.ironwood += tx.ironwood_actions.len() as u32;
        }

        let hash = random_hash(&mut self.rng);
        self.blocks.push(CompactBlock {
            height,
            hash,
            prev_hash: self.prev_hash,
            time: 1_000_000 + u32::from(height),
            tree_sizes: self.sizes,
            txs,
        });

        self.prev_hash = hash;
        self.next_height = height + 1;
        self
    }

    /// Appends `count` blocks with no transactions.
    pub fn empty_blocks(&mut self, count: usize) -> &mut Self {
        for _ in 0..count {
            self.block(|_| {});
        }
        self
    }

    /// Returns the blocks built so far.
    pub fn blocks(&self) -> &[CompactBlock] {
        &self.blocks
    }

    /// Consumes the builder, returning its blocks.
    pub fn into_blocks(self) -> Vec<CompactBlock> {
        self.blocks
    }
}

/// Populates one block's transactions.
pub struct BlockBuilder<'a> {
    rng: &'a mut ChaChaRng,
    txs: Vec<CompactTx>,
}

impl BlockBuilder<'_> {
    /// Appends a transaction, letting `f` populate its actions.
    ///
    /// Returns the transaction's identifier, so a test can assert against it or
    /// spend its outputs later.
    pub fn tx(&mut self, f: impl FnOnce(&mut TxBuilder<'_>)) -> TxId {
        let index = self.txs.len() as u64;
        let txid = TxId::from_bytes(random_bytes(self.rng));
        let mut builder = TxBuilder {
            rng: self.rng,
            tx: CompactTx {
                index,
                txid,
                orchard_actions: Vec::new(),
                ironwood_actions: Vec::new(),
                vin: Vec::new(),
                vout: Vec::new(),
            },
        };
        f(&mut builder);
        self.txs.push(builder.tx);
        txid
    }
}

/// Populates one transaction's actions.
pub struct TxBuilder<'a> {
    rng: &'a mut ChaChaRng,
    tx: CompactTx,
}

impl TxBuilder<'_> {
    /// Adds an action paying `value` to `fvk`'s address on `scope`.
    ///
    /// Returns the note that was created, so a test can predict its nullifier
    /// and later spend it.
    pub fn receive(
        &mut self,
        pool: PoolId,
        fvk: &FullViewingKey,
        scope: KeyScope,
        value: u64,
    ) -> Note {
        let recipient = fvk.address_at(
            0u32,
            match scope {
                KeyScope::External => Scope::External,
                KeyScope::Internal => Scope::Internal,
            },
        );
        let ovk = fvk.to_ovk(Scope::External);
        let (action, note) = make_action(self.rng, pool, recipient, Some(ovk), value);
        self.push(pool, action);
        note
    }

    /// Adds an action paying an unrelated recipient.
    ///
    /// This stands in for both other people's notes and the padding dummies
    /// that real bundles carry, neither of which this wallet can decrypt.
    pub fn decoy(&mut self, pool: PoolId, value: u64) -> Note {
        let stranger = fvk_from_seed(self.rng.next_u32() as u8 | 0x80);
        let recipient = stranger.address_at(0u32, Scope::External);
        let (action, note) = make_action(self.rng, pool, recipient, None, value);
        self.push(pool, action);
        note
    }

    /// Adds an action that reveals `nullifier`, spending the note it belongs to.
    ///
    /// The action still creates an output, because every Orchard-family action
    /// does; that output pays a stranger.
    pub fn spend(&mut self, pool: PoolId, nullifier: Nullifier) {
        let stranger = fvk_from_seed(self.rng.next_u32() as u8 | 0x40);
        let recipient = stranger.address_at(0u32, Scope::External);
        let (action, _) = make_action_with_nullifier(self.rng, pool, recipient, None, 0, nullifier);
        self.push(pool, action);
    }

    /// Adds a transparent output paying `script`.
    pub fn transparent_out(&mut self, script: Script, value: u64) {
        self.tx
            .vout
            .push(TxOut::new(Zatoshis::const_from_u64(value), script));
    }

    /// Adds a transparent input spending `outpoint`.
    pub fn transparent_in(&mut self, outpoint: OutPoint) {
        self.tx.vin.push(outpoint);
    }

    fn push(&mut self, pool: PoolId, action: CompactAction) {
        match pool {
            PoolId::Orchard => self.tx.orchard_actions.push(action),
            PoolId::Ironwood => self.tx.ironwood_actions.push(action),
        }
    }
}

/// Builds a compact action carrying a real encrypted note for `pool`.
fn make_action(
    rng: &mut ChaChaRng,
    pool: PoolId,
    recipient: Address,
    ovk: Option<OutgoingViewingKey>,
    value: u64,
) -> (CompactAction, Note) {
    let nullifier = random_nullifier(rng);
    make_action_with_nullifier(rng, pool, recipient, ovk, value, nullifier)
}

/// As [`make_action`], but with a caller-chosen revealed nullifier.
///
/// The nullifier an action reveals is the one being *spent*; `rho` for the new
/// note is derived from it, exactly as the protocol requires, so the domain the
/// scanner reconstructs from the action matches the one used to encrypt.
fn make_action_with_nullifier(
    rng: &mut ChaChaRng,
    pool: PoolId,
    recipient: Address,
    ovk: Option<OutgoingViewingKey>,
    value: u64,
    nullifier: Nullifier,
) -> (CompactAction, Note) {
    let rho = Rho::from_bytes(&nullifier.to_bytes()).expect("a nullifier is a valid rho");

    let rseed = loop {
        let bytes = random_bytes(rng);
        if let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes, &rho)) {
            break rseed;
        }
    };

    let version = match pool {
        PoolId::Orchard => NoteVersion::V2,
        PoolId::Ironwood => NoteVersion::V3,
    };

    let note = Option::<Note>::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        rho,
        rseed,
        version,
    ))
    .expect("note components are valid");

    let cmx = ExtractedNoteCommitment::from(note.commitment());
    let (ephemeral_key, enc_ciphertext) = match pool {
        PoolId::Orchard => {
            let e = OrchardNoteEncryption::new(ovk, note, [0u8; 512]);
            (OrchardDomain::epk_bytes(e.epk()), e.encrypt_note_plaintext())
        }
        PoolId::Ironwood => {
            let e = IronwoodNoteEncryption::new(ovk, note, [0u8; 512]);
            (
                IronwoodDomain::epk_bytes(e.epk()),
                e.encrypt_note_plaintext(),
            )
        }
    };

    let action = CompactAction::from_parts(
        nullifier,
        cmx,
        ephemeral_key,
        enc_ciphertext[..52].try_into().expect("52-byte prefix"),
    );

    (action, note)
}

fn random_bytes(rng: &mut ChaChaRng) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn random_hash(rng: &mut ChaChaRng) -> BlockHash {
    BlockHash(random_bytes(rng))
}

/// Returns a valid, otherwise arbitrary nullifier.
pub fn random_nullifier(rng: &mut ChaChaRng) -> Nullifier {
    loop {
        let bytes = random_bytes(rng);
        if let Some(nf) = Option::<Nullifier>::from(Nullifier::from_bytes(&bytes)) {
            return nf;
        }
    }
}

/// Returns a deterministic RNG for tests that need to mint their own values.
pub fn test_rng(seed: u8) -> ChaChaRng {
    ChaChaRng::from_seed([seed; 32])
}

/// Returns the `scriptPubKey` paying a distinct, arbitrary P2PKH address.
///
/// Different `tag`s give different addresses, which is what a test needs in
/// order to check that the wallet matches only the scripts it was given.
pub fn script(tag: u8) -> Script {
    Script::from(&TransparentAddress::PublicKeyHash([tag; 20]).script())
}
