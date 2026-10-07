//! Qualification of private mixed transparent/Ironwood recovery against serialized
//! transactions and both private services.
//!
//! Each transaction is authored with the transaction builder, signed, proved, serialized and
//! parsed back. Everything the wallet learns about it is derived from those bytes:
//!
//! - its compact block, as a compact source projects it (Ironwood actions, no transparent data);
//! - its transparent events and their transaction metadata, by the transparent publisher's
//!   extraction rules (wallet-pir `transparent-filter-server` `extract.rs` at 648264bb), published
//!   as real shards and recovered over loopback HTTP and real PIR;
//! - its Enhance PIR records, by the Enhance publisher's rules (wallet-pir
//!   `enhance-pir-server` `zakura.rs` at 648264bb and current main), served at their commitment
//!   tree positions over the native two-mask protocol and queried by the client crate.
//!
//! No step fetches a transaction by its ID: under `PrivateRequired` no public payload work
//! exists, and every request each service received is checked. Only the explicit public
//! comparison at the end hands the serialized transaction to the wallet, after public authority
//! is restored, as ordinary enhancement would.
//!
//! The Enhance publisher reports a fee only for pure-Ironwood transactions. For a mixed
//! transaction its records carry none; private reconstruction relies on the qualified exact fee
//! from the transparent metadata, never copied into the wallet's canonical fee.

mod enhance_service;
mod fixture;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Mutex, PoisonError},
    time::Duration,
};

use enhance_service::EnhanceService;
use fixture::{SEAL, Server, ShardSpec, synthetic};
use incrementalmerkletree::{Hashable, Level};
use orchard::{
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use rand::{SeedableRng as _, rngs::StdRng};
use transparent::{
    address::TransparentAddress,
    builder::TransparentSigningSet,
    bundle::{OutPoint, TxOut},
    keys::{NonHardenedChildIndex, TransparentKeyScope},
};
use transparent_events::{
    FeeState, ReceiveEvent, SpendEvent, TransactionMetadata, TransparentEvent, Txid,
};
use transparent_filter::ScriptBytes;
use transparent_wallet::http::{HttpFilterSource, HttpOptions, HttpShardTransport};
use zakura_pir_enhance::{
    EnhanceRecord, EnhanceRecordParts, EnhanceTransactionMetadata, transport::PendingClient,
    wallet::PreparedWork,
};
use zakura_pir_transparent::{BatchState, Outcome, RecoveryConfig, ReferenceRecovery, WalletChain};
use zcash_client_backend::data_api::{
    Account as _, WalletRead as _, WalletWrite as _,
    chain::ChainState,
    enhance_pir::{
        EnhancePirBatchResult, EnhancePirRead as _, EnhancePirRequest, EnhancePirStoreResult,
        EnhancePirWork, EnhancePirWrite as _, EnhancementMode, TransactionEnhancementWork,
    },
    testing::{InitialChainState, TestBuilder, TestState},
    transparent_ledger::{
        AggregatePayment, DetailCompleteness, EffectCompleteness, FeeState as HistoryFee,
        HistoryClassification, PoolEffect, TransactionHistoryDetails,
        TransparentLedgerMode::{self, PrivateRequired, PrivateShadow, Public},
        TransparentLedgerRead as _, TransparentLedgerWrite as _, TransparentWatchSet, WatchOrigin,
        WholeTransactionFee,
    },
    wallet::decrypt_and_store_transaction,
};
use zcash_client_sqlite::{
    AccountUuid,
    testing::{
        BlockCache,
        db::{TestDb, TestDbFactory},
    },
};
use zcash_primitives::{
    block::BlockHash,
    transaction::{
        Transaction, TxId,
        builder::{BuildConfig, Builder, BundlePadding},
        fees::zip317,
    },
};
use zcash_protocol::{
    PoolType, ShieldedPool,
    consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters as _},
    local_consensus::LocalNetwork,
    memo::MemoBytes,
    value::Zatoshis,
};

type State = TestState<BlockCache, TestDb, LocalNetwork>;

/// The first height the transparent publisher covers, a mainnet height.
const H0: u64 = 3_428_143;
/// Where the wallet is born, and where Ironwood activates for the fixture network.
const BIRTHDAY: u64 = H0 + 10;
const ORIGIN: &str = "https://fixture.test";

/// One PIR service pair and wallet at a time keeps memory and CPU bounded.
static HEAVY: Mutex<()> = Mutex::new(());

fn height(at: u64) -> BlockHeight {
    BlockHeight::from(u32::try_from(at).unwrap())
}

fn zat(value: u64) -> Zatoshis {
    Zatoshis::const_from_u64(value)
}

fn network() -> LocalNetwork {
    let activation = Some(height(BIRTHDAY));
    LocalNetwork {
        nu6: activation,
        nu6_1: activation,
        nu6_2: activation,
        nu6_3: activation,
        ..TestBuilder::<(), ()>::DEFAULT_NETWORK
    }
}

fn pubkey_hash(address: TransparentAddress) -> [u8; 20] {
    match address {
        TransparentAddress::PublicKeyHash(hash) => hash,
        TransparentAddress::ScriptHash(_) => panic!("fixture addresses pay to public key hashes"),
    }
}

/// The locking script of a P2PKH address, as the publisher indexes it.
fn script(address: TransparentAddress) -> ScriptBytes {
    ScriptBytes::new([&[0x76, 0xa9, 20][..], &pubkey_hash(address), &[0x88, 0xac]].concat())
}

/// A spending key no wallet account holds.
fn foreign_orchard() -> (SpendingKey, FullViewingKey) {
    let sk = SpendingKey::from_bytes([0x77; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    (sk, fvk)
}

/// A secp256k1 key no wallet account holds, and its address.
fn foreign_transparent(tag: u8) -> (secp256k1::SecretKey, TransparentAddress) {
    let sk = secp256k1::SecretKey::from_slice(&[tag; 32]).unwrap();
    let pk = sk.public_key(&secp256k1::Secp256k1::signing_only());
    let address = TransparentAddress::from_pubkey(&pk);
    (sk, address)
}

// ---------------------------------------------------------------------------------------------
// Publisher derivations, from serialized transactions only.
// ---------------------------------------------------------------------------------------------

/// The transparent publisher's whole-transaction metadata: the exact fee from the value balance
/// with every previous output, the transparent input count, and whether any shielded bundle
/// exists.
fn transparent_metadata(
    tx: &Transaction,
    prevouts: &HashMap<OutPoint, TxOut>,
) -> TransactionMetadata {
    let fee = tx
        .fee_paid(|outpoint| {
            Ok::<_, zcash_protocol::value::BalanceError>(Some(
                prevouts
                    .get(outpoint)
                    .expect("a known previous output")
                    .value(),
            ))
        })
        .unwrap()
        .expect("a balanced transaction");
    TransactionMetadata {
        fee: FeeState::Exact(fee.into_u64()),
        transparent_input_count: tx
            .transparent_bundle()
            .map_or(0, |bundle| bundle.vin.len() as u32),
        has_shielded_components: tx.sapling_bundle().is_some()
            || tx.orchard_bundle().is_some()
            || tx.ironwood_bundle().is_some(),
    }
}

/// The transparent publisher's indexed events for `tx` mined at `at`, transaction index 1:
/// one receive per output and one spend per input, each under the script it concerns.
fn transparent_events(
    tx: &Transaction,
    at: u64,
    prevouts: &HashMap<OutPoint, TxOut>,
) -> Vec<(ScriptBytes, TransparentEvent)> {
    let metadata = transparent_metadata(tx, prevouts);
    let txid = Txid(*tx.txid().as_ref());
    let Some(bundle) = tx.transparent_bundle() else {
        return vec![];
    };
    let mut events = vec![];
    for (index, output) in bundle.vout.iter().enumerate() {
        events.push((
            ScriptBytes::new(output.script_pubkey().0.0.clone()),
            TransparentEvent::Receive(ReceiveEvent {
                metadata: Some(metadata),
                height: at as u32,
                txid,
                transaction_index: 1,
                output_index: index as u32,
                value: output.value().into_u64(),
                coinbase: false,
            }),
        ));
    }
    for (index, input) in bundle.vin.iter().enumerate() {
        let prevout = &prevouts[input.prevout()];
        events.push((
            ScriptBytes::new(prevout.script_pubkey().0.0.clone()),
            TransparentEvent::Spend(SpendEvent {
                metadata: Some(metadata),
                height: at as u32,
                spending_txid: txid,
                transaction_index: 1,
                input_index: index as u32,
                spent_txid: Txid(*input.prevout().hash()),
                spent_output_index: input.prevout().n(),
            }),
        ));
    }
    events
}

/// The Enhance publisher's records for `tx`'s Ironwood actions, in action order. A fee is
/// reported only for a pure-Ironwood transaction, as the publisher does.
fn enhance_records(tx: &Transaction) -> Vec<EnhanceRecord> {
    let bundle = tx.ironwood_bundle().expect("an Ironwood bundle");
    let transparent = tx.transparent_bundle();
    let has_transparent_inputs = transparent.is_some_and(|b| !b.vin.is_empty());
    let has_transparent_outputs = transparent.is_some_and(|b| !b.vout.is_empty());
    let pure_ironwood = !has_transparent_inputs
        && !has_transparent_outputs
        && tx.sapling_bundle().is_none()
        && tx.orchard_bundle().is_none();
    let fee = pure_ironwood.then(|| u64::try_from(i64::from(*bundle.value_balance())).unwrap());
    let metadata = EnhanceTransactionMetadata::new(u32::from(tx.expiry_height()), fee).unwrap();
    bundle
        .actions()
        .iter()
        .map(|action| {
            EnhanceRecord::from_parts(EnhanceRecordParts {
                enc_ciphertext_suffix: action.encrypted_note().enc_ciphertext[52..]
                    .try_into()
                    .unwrap(),
                cv_net: action.cv_net().to_bytes(),
                out_ciphertext: action.encrypted_note().out_ciphertext,
                has_transparent_inputs,
                has_transparent_outputs,
                metadata,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Transaction authoring.
// ---------------------------------------------------------------------------------------------

/// A version-3 Ironwood note for `recipient` with a deterministic, valid `rho` and `rseed`.
fn note(recipient: orchard::Address, value: u64, tag: u8) -> orchard::Note {
    let rho = Rho::from_bytes(&[
        tag, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ])
    .unwrap();
    let rseed = (0u8..=255)
        .find_map(|n| Option::from(RandomSeed::from_bytes([n; 32], &rho)))
        .unwrap();
    orchard::Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap()
}

/// A Merkle path for a tree holding `note` alone at `position`, and its anchor. The builder
/// proves the spend against this anchor; the wallet does not validate anchors.
fn lone_path(note: &orchard::Note, position: u32) -> (MerklePath, orchard::Anchor) {
    let path = MerklePath::from_parts(
        position,
        std::array::from_fn(|level| MerkleHashOrchard::empty_root(Level::from(level as u8))),
    );
    let anchor = path.root(ExtractedNoteCommitment::from(note.commitment()));
    (path, anchor)
}

/// What a transaction under test spends and pays.
#[derive(Default)]
struct Spec {
    /// Transparent inputs: previous output, its value, and the signing key.
    inputs: Vec<(OutPoint, TxOut, secp256k1::SecretKey)>,
    /// Ironwood spends: the spending key and the note.
    ironwood_spends: Vec<(SpendingKey, orchard::Note)>,
    /// Ironwood outputs: recipient, value, and the OVK the output is recoverable with.
    ironwood_outputs: Vec<(
        orchard::Address,
        u64,
        Option<orchard::keys::OutgoingViewingKey>,
    )>,
    /// Transparent outputs.
    transparent_outputs: Vec<(TransparentAddress, u64)>,
}

/// Builds, signs, proves and serializes the transaction `spec` describes at `at`, under the ZIP
/// 317 fee rule, and parses it back.
fn author(spec: &Spec, at: u64, seed: u8) -> Transaction {
    let params = network();
    let anchor = spec
        .ironwood_spends
        .first()
        .map(|(_, note)| lone_path(note, 0).1)
        .unwrap_or_else(orchard::Anchor::empty_tree);
    let ironwood = !spec.ironwood_spends.is_empty() || !spec.ironwood_outputs.is_empty();
    let mut builder = Builder::new(
        params,
        height(at),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: ironwood.then_some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    let mut signing = TransparentSigningSet::new();
    for (outpoint, coin, sk) in &spec.inputs {
        let pubkey = signing.add_key(*sk);
        builder
            .add_transparent_p2pkh_input(pubkey, outpoint.clone(), coin.clone())
            .unwrap();
    }
    let mut saks = vec![];
    for (sk, spent) in &spec.ironwood_spends {
        let (path, _) = lone_path(spent, 0);
        builder
            .add_ironwood_spend::<std::convert::Infallible>(FullViewingKey::from(sk), *spent, path)
            .unwrap();
        saks.push(SpendAuthorizingKey::from(sk));
    }
    for (recipient, value, ovk) in &spec.ironwood_outputs {
        builder
            .add_ironwood_output::<std::convert::Infallible>(
                ovk.clone(),
                *recipient,
                zat(*value),
                MemoBytes::empty(),
            )
            .unwrap();
    }
    for (address, value) in &spec.transparent_outputs {
        builder
            .add_transparent_output(address, zat(*value))
            .unwrap();
    }
    let built = builder
        .build(
            &signing,
            &[],
            &saks,
            StdRng::from_seed([seed; 32]),
            &sapling::prover::mock::MockSpendProver,
            &sapling::prover::mock::MockOutputProver,
            &zip317::FeeRule::standard(),
        )
        .expect("a buildable transaction");
    let mut bytes = vec![];
    built.transaction().write(&mut bytes).unwrap();
    let parsed =
        Transaction::read(&bytes[..], BranchId::for_height(&network(), height(at))).unwrap();
    assert_eq!(parsed.txid(), built.transaction().txid());
    parsed
}

// ---------------------------------------------------------------------------------------------
// The wallet and its services.
// ---------------------------------------------------------------------------------------------

/// A mined transaction and what the services publish about it.
struct Mined {
    tx: Transaction,
    at: u64,
    /// The Ironwood commitment tree position of its first action.
    first_position: u64,
    prevouts: HashMap<OutPoint, TxOut>,
}

/// (route, fee, the account's memo, transparent-output flag, flag height) stored for a
/// transaction.
type Stored = (
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<bool>,
    Option<u32>,
);

struct Wallet {
    st: State,
    account: AccountUuid,
    /// The seed-derived keys of the account, for authoring its spends.
    usk: zcash_keys::keys::UnifiedSpendingKey,
    other: Option<(AccountUuid, zcash_keys::keys::UnifiedSpendingKey)>,
    server: Server,
    dir: tempfile::TempDir,
    publications: usize,
    url: Option<String>,
    companion: Option<ReferenceRecovery>,
    /// Every transaction mined, in order.
    mined: Vec<Mined>,
    /// The Ironwood tree size after the last mined block.
    tree_size: u64,
    /// Every watched public key hash, for the transparent service's privacy check.
    watched: BTreeSet<[u8; 20]>,
    /// The Enhance generations served, for their privacy check.
    enhance_requests: Vec<enhance_service::Recorded>,
}

fn config(account: AccountUuid) -> RecoveryConfig {
    RecoveryConfig {
        source: b"fixture/transparent-pir/v1".to_vec(),
        account_binding: account.expose_uuid().as_bytes().to_vec(),
        origin: ORIGIN.into(),
        scripts: 10_000,
        shards: 1_024,
        events: 500_000,
        queries: 256,
        private_bytes: 96 << 20,
    }
}

impl Wallet {
    fn new(other_account: bool) -> Self {
        let mut st = TestBuilder::new()
            .with_network(network())
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_initial_chain_state(|_, _| InitialChainState {
                chain_state: ChainState::empty(
                    height(BIRTHDAY - 1),
                    BlockHash(synthetic(BIRTHDAY - 1).0),
                ),
                prior_sapling_roots: vec![],
                prior_orchard_roots: vec![],
            })
            .with_account_having_current_birthday()
            .build();
        let account = st.test_account().unwrap().id();
        let usk = st.test_account().unwrap().usk().clone();
        let other = other_account.then(|| {
            let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
                st.network(),
                &[0x42; 32],
                zip32::AccountId::ZERO,
            )
            .unwrap();
            let birthday = st.test_account().unwrap().birthday().clone();
            let id = st
                .wallet_mut()
                .import_account_ufvk(
                    "other",
                    &usk.to_unified_full_viewing_key(),
                    &birthday,
                    zcash_client_backend::data_api::AccountPurpose::Spending { derivation: None },
                    None,
                )
                .unwrap()
                .id();
            (id, usk)
        });
        let mut wallet = Self {
            st,
            account,
            usk,
            other,
            server: Server::start(),
            dir: tempfile::tempdir().unwrap(),
            publications: 0,
            url: None,
            companion: None,
            mined: vec![],
            tree_size: 0,
            watched: BTreeSet::new(),
            enhance_requests: vec![],
        };
        wallet.scan_to(H0 + 20);
        wallet.set_policy(PrivateShadow);
        wallet.companion = Some(
            ReferenceRecovery::open(wallet.dir.path().join("companion.sqlite"), config(account))
                .unwrap(),
        );
        wallet
    }

    fn tip(&self) -> u64 {
        self.st
            .wallet()
            .chain_height()
            .unwrap()
            .map_or(BIRTHDAY - 1, |tip| u64::from(u32::from(tip)))
    }

    fn scan_to(&mut self, through: u64) {
        let from = self.tip() + 1;
        for _ in from..=through {
            self.st.generate_empty_block();
        }
        if through >= from {
            self.st
                .scan_cached_blocks(height(from), (through + 1 - from) as usize);
        }
    }

    /// Mines `tx` alone (after the coinbase position) in the next block and scans it.
    fn mine(&mut self, tx: Transaction, prevouts: HashMap<OutPoint, TxOut>) -> usize {
        let (at, _) = self.st.generate_next_block_from_tx(1, &tx);
        self.st.scan_cached_blocks(at, 1);
        let at = u64::from(u32::from(at));
        let actions = tx.ironwood_bundle().map_or(0, |b| b.actions().len()) as u64;
        self.mined.push(Mined {
            tx,
            at,
            first_position: self.tree_size,
            prevouts,
        });
        self.tree_size += actions;
        self.mined.len() - 1
    }

    fn set_policy(&mut self, mode: TransparentLedgerMode) {
        let db = self.st.wallet_mut().db_mut();
        db.apply_transparent_policy(mode).unwrap();
        db.set_transparent_ledger_mode(mode);
    }

    fn watch(&self) -> TransparentWatchSet<AccountUuid> {
        self.st
            .wallet()
            .db()
            .transparent_watch_set(self.account)
            .unwrap()
    }

    /// The account's external address at `index`, and its signing key.
    fn external(&self, index: u32) -> (TransparentAddress, secp256k1::SecretKey) {
        let address = self
            .watch()
            .addresses
            .iter()
            .find(|watched| {
                matches!(watched.origin, WatchOrigin::Derived { scope, index: i }
                    if scope == TransparentKeyScope::EXTERNAL && i.index() == index)
            })
            .expect("a derived address")
            .address;
        let sk = self
            .usk
            .transparent()
            .derive_external_secret_key(NonHardenedChildIndex::from_index(index).unwrap())
            .unwrap();
        let pk = sk.public_key(&secp256k1::Secp256k1::signing_only());
        assert_eq!(TransparentAddress::from_pubkey(&pk), address);
        (address, sk)
    }

    /// The wallet's hash at `at`, or a synthetic one below the birthday.
    fn block(&self, at: u64) -> transparent_filter::BlockHash {
        if at < BIRTHDAY {
            return synthetic(at);
        }
        let hash = self
            .st
            .wallet()
            .get_block_hash(height(at))
            .unwrap()
            .expect("a scanned block");
        transparent_filter::BlockHash::from_internal_bytes(hash.0)
    }

    /// Publishes every mined transaction's transparent events in one shard through the tip,
    /// at `revision`, and serves it.
    fn publish_transparent(&mut self, revision: u32) {
        let tip = self.tip();
        let mut events: Vec<(ScriptBytes, TransparentEvent)> = self
            .mined
            .iter()
            .flat_map(|m| transparent_events(&m.tx, m.at, &m.prevouts))
            .collect();
        // Receives to scripts no account derives, so the account's are not alone.
        for n in 0..40u32 {
            let (_, address) = foreign_transparent(0x80 + (n % 64) as u8);
            let mut txid = [0u8; 32];
            txid[..4].copy_from_slice(&n.to_le_bytes());
            txid[31] = 0x99;
            events.push((
                script(address),
                TransparentEvent::Receive(ReceiveEvent {
                    metadata: None,
                    height: (H0 + u64::from(n) % (tip - H0 + 1)) as u32,
                    txid: Txid(txid),
                    transaction_index: 1,
                    output_index: 0,
                    value: 1,
                    coinbase: false,
                }),
            ));
        }
        self.publications += 1;
        let dir = self
            .dir
            .path()
            .join(format!("publication-{}", self.publications));
        let shards = [ShardSpec {
            start: H0,
            end: tip,
            sealed: false,
            revision,
            events,
        }];
        fixture::publish(&dir, &shards, SEAL, |at| self.block(at));
        self.url = Some(self.server.serve(&dir));
    }

    /// Recovery passes until the batch settles, applying every commit; trusted under
    /// `PrivateRequired`.
    fn recover_transparent(&mut self) {
        for _ in 0..8 {
            let watch = self.watch();
            self.watched
                .extend(watch.addresses.iter().map(|w| pubkey_hash(w.address)));
            let url = self.url.clone().expect("a served publication");
            let options = HttpOptions {
                timeout: Duration::from_secs(60),
                ..HttpOptions::default()
            };
            let mut filters = HttpFilterSource::new(&url, &options).unwrap();
            let mut transport = HttpShardTransport::new(&url, &options).unwrap();
            let companion = self.companion.as_mut().unwrap();
            let batch = {
                let chain = WalletChain::new(self.st.wallet().db(), watch.target.unwrap());
                companion
                    .recover(&watch, &chain, &mut filters, &mut transport)
                    .unwrap()
            };
            assert_eq!(batch.state, BatchState::Ready);
            let db = self.st.wallet_mut().db_mut();
            let trusted = db.applied_transparent_policy().unwrap().mode == PrivateRequired;
            let mut grew = false;
            for commit in &batch.commits {
                let applied = if trusted {
                    db.qualify_and_apply_transparent_ledger_commit(commit.clone())
                } else {
                    db.apply_transparent_ledger_commit(commit.clone())
                };
                grew |= applied
                    .expect("the wallet applies every commit")
                    .window_grew;
            }
            if batch.retired_revisions().is_empty() {
                companion.acknowledge_applied(&batch).unwrap();
            } else {
                companion.acknowledge_reconciled(&batch).unwrap();
            }
            if !grew && batch.progress.outcome != Outcome::More {
                assert_eq!(batch.progress.outcome, Outcome::Complete);
                return;
            }
        }
        panic!("transparent recovery did not settle");
    }

    /// Every pending private query. `PrivateRequired` must never expose a public payload
    /// (`GetTransaction`) request.
    fn private_queries(&self) -> Vec<EnhancePirRequest> {
        self.st
            .wallet()
            .transaction_enhancement_work()
            .unwrap()
            .into_iter()
            .filter_map(|work| match work {
                TransactionEnhancementWork::Private(EnhancePirWork::Query(request)) => {
                    Some(request)
                }
                TransactionEnhancementWork::Public(request) => {
                    panic!("public payload work for {}", request.txid())
                }
                _ => None,
            })
            .collect()
    }

    /// One Enhance generation over every mined transaction's records, anchored at the wallet's
    /// tip; then one round of private queries, each row's records applied as the client returns
    /// them. Returns the store results by txid.
    fn recover_enhance(&mut self) -> BTreeMap<TxId, Vec<EnhancePirStoreResult>> {
        let records: Vec<(u64, EnhanceRecord)> = self
            .mined
            .iter()
            .filter(|m| m.tx.ironwood_bundle().is_some())
            .flat_map(|m| {
                enhance_records(&m.tx)
                    .into_iter()
                    .enumerate()
                    .map(move |(i, record)| (m.first_position + i as u64, record))
            })
            .collect();
        let tip = self.tip();
        let mut anchor_hash = self
            .st
            .wallet()
            .get_block_hash(height(tip))
            .unwrap()
            .unwrap()
            .0;
        anchor_hash.reverse();
        let service = EnhanceService::new(&records, tip, anchor_hash, self.tree_size);
        let activation = u64::from(u32::from(
            network().activation_height(NetworkUpgrade::Nu6_3).unwrap(),
        ));
        let status = self
            .st
            .wallet()
            .enhance_pir_snapshot_status(
                zakura_pir_enhance::wallet::snapshot_anchor(service.manifest()).unwrap(),
            )
            .unwrap();
        let acceptance = enhance_service::accept(service.manifest(), activation, status);

        let work = PreparedWork::new(
            self.st
                .wallet()
                .transaction_enhancement_work()
                .unwrap()
                .into_iter()
                .map(|work| match work {
                    TransactionEnhancementWork::Private(work) => work,
                    TransactionEnhancementWork::Public(request) => {
                        panic!("public payload work for {}", request.txid())
                    }
                }),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut results: BTreeMap<TxId, Vec<EnhancePirStoreResult>> = BTreeMap::new();
        runtime.block_on(async {
            let mut client = PendingClient::fetch(&&service, enhance_service::BASE)
                .await
                .unwrap()
                .accept(&acceptance)
                .unwrap();
            for ((txid, _row), requests) in work.batches_by_tx_and_row() {
                let rows = client
                    .query_row_requests(&&service, &requests)
                    .await
                    .unwrap();
                match self
                    .st
                    .wallet_mut()
                    .db_mut()
                    .apply_ironwood_enhance_records(&rows.slots)
                    .unwrap()
                {
                    EnhancePirBatchResult::Committed(applied) => {
                        results.entry(txid).or_default().extend(applied)
                    }
                    rejected => panic!("rejected batch {rejected:?}"),
                }
            }
        });
        self.enhance_requests.extend(service.requests());
        results
    }

    fn history(&self, txid: TxId) -> TransactionHistoryDetails {
        let mut entries = self
            .st
            .wallet()
            .db()
            .transaction_history_details(self.account, &[txid])
            .unwrap();
        assert_eq!(entries.len(), 1);
        entries.remove(0)
    }

    /// (route, fee, memo, transparent-output flag, flag height) stored for `txid`.
    fn stored(&self, txid: TxId) -> Stored {
        self.st
            .wallet()
            .conn()
            .query_row(
                "SELECT r.route, t.fee,
                        (SELECT memo FROM ironwood_received_notes n
                         JOIN accounts a ON a.id = n.account_id
                         WHERE n.transaction_id = t.id_tx AND a.uuid = ?2),
                        r.has_transparent_outputs, r.has_transparent_outputs_height
                 FROM transactions t
                 LEFT JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
                 WHERE t.txid = ?1",
                rusqlite::params![txid.as_ref(), self.account.expose_uuid()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap()
    }

    /// Privacy over every request either service received: only their routes, no watched
    /// script, and no mined transaction's ID, in any byte order, anywhere.
    fn assert_private(&self) {
        let txids: Vec<[u8; 32]> = self
            .mined
            .iter()
            .flat_map(|m| {
                let id = *m.tx.txid().as_ref();
                let mut display = id;
                display.reverse();
                [id, display]
            })
            .collect();
        let hexes: Vec<Vec<u8>> = txids
            .iter()
            .flat_map(|id| [hex::encode(id), hex::encode_upper(id)])
            .map(String::into_bytes)
            .collect();
        let carries_txid = |bytes: &[u8]| {
            txids.iter().any(|id| bytes.windows(32).any(|w| w == id))
                || hexes.iter().any(|h| bytes.windows(64).any(|w| w == &h[..]))
        };
        let hashes: Vec<[u8; 20]> = self.watched.iter().copied().collect();
        let carries_script = |bytes: &[u8]| {
            hashes.iter().any(|h| bytes.windows(20).any(|w| w == h))
                || hashes.iter().any(|h| {
                    let text = hex::encode(h);
                    bytes.windows(40).any(|w| w == text.as_bytes())
                })
        };
        // Positive controls.
        assert!(carries_txid(self.mined[0].tx.txid().as_ref()));
        assert!(!self.enhance_requests.is_empty());
        assert!(self.enhance_requests.iter().any(|r| r.post));
        let enhance_routes = regex::Regex::new(
            r"^https://enhance\.fixture\.test/v1/enhance/(init|session/[0-9a-f]{64}|query)$",
        )
        .unwrap();
        for request in &self.enhance_requests {
            assert!(
                enhance_routes.is_match(&request.url),
                "route {}",
                request.url
            );
            assert_eq!(request.post, request.url.ends_with("/query"));
            assert!(!carries_txid(request.url.as_bytes()) && !carries_txid(&request.body));
            assert!(!carries_script(request.url.as_bytes()) && !carries_script(&request.body));
        }
        let transparent = self.server.requests();
        assert!(transparent.iter().any(|r| r.method == "POST"));
        for request in &transparent {
            assert!(
                !carries_txid(request.path.as_bytes()) && !carries_txid(&request.body),
                "a transaction ID in {}",
                request.path
            );
            assert!(
                !carries_script(request.path.as_bytes()) && !carries_script(&request.body),
                "a script in {}",
                request.path
            );
            assert_eq!(request.query, None, "a query string on {}", request.path);
            assert!(
                request
                    .headers
                    .iter()
                    .all(|(_, value)| !carries_txid(value))
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Scenarios.
// ---------------------------------------------------------------------------------------------

const FEE: u64 = 20_000;

/// A funded account under `PrivateRequired` with private authority, `PrivateIronwood`
/// enhancement, and two recovered transparent outputs of `inputs` paid by serialized funding
/// transactions from a foreign key.
fn funded(
    inputs: [u64; 2],
    other_account: bool,
) -> (Wallet, [(OutPoint, TxOut, secp256k1::SecretKey); 2]) {
    let mut w = Wallet::new(other_account);
    let mut owned = vec![];
    for (i, value) in inputs.into_iter().enumerate() {
        let (address, sk) = w.external(i as u32);
        let (foreign_sk, foreign_address) = foreign_transparent(0x10 + i as u8);
        // The funder's own previous output lies before the publisher's coverage.
        let prevout = OutPoint::new([0xf0 + i as u8; 32], 0);
        let coin = TxOut::new(zat(value + 10_000), foreign_address.script().into());
        let spec = Spec {
            inputs: vec![(prevout.clone(), coin.clone(), foreign_sk)],
            transparent_outputs: vec![(address, value)],
            ..Spec::default()
        };
        let tx = author(&spec, w.tip() + 1, 0x30 + i as u8);
        let funding = OutPoint::new(*tx.txid().as_ref(), 0);
        let out = tx.transparent_bundle().unwrap().vout[0].clone();
        w.mine(tx, HashMap::from([(prevout, coin)]));
        owned.push((funding, out, sk));
    }
    w.scan_to(w.tip() + 2);
    w.publish_transparent(0);
    w.recover_transparent();
    w.set_policy(PrivateRequired);
    w.recover_transparent();
    w.st.wallet_mut()
        .db_mut()
        .promote_transparent_account(w.account)
        .unwrap();
    w.st.wallet_mut()
        .db_mut()
        .set_enhancement_mode(EnhancementMode::PrivateIronwood);
    (w, owned.try_into().unwrap())
}

/// Mines `spec`'s transaction next and republishes the transparent events through the new tip,
/// recovered under `PrivateRequired`.
fn mine_and_recover(w: &mut Wallet, spec: Spec, seed: u8, revision: u32) -> usize {
    let prevouts = spec
        .inputs
        .iter()
        .map(|(outpoint, coin, _)| (outpoint.clone(), coin.clone()))
        .collect();
    let tx = author(&spec, w.tip() + 1, seed);
    let index = w.mine(tx, prevouts);
    w.scan_to(w.tip() + 2);
    w.publish_transparent(revision);
    w.recover_transparent();
    index
}

/// A transparent-to-Ironwood shielding of both owned inputs to the account's internal address.
fn shielding_spec(
    w: &Wallet,
    owned: &[(OutPoint, TxOut, secp256k1::SecretKey); 2],
    shielded: u64,
) -> Spec {
    let fvk = FullViewingKey::from(w.usk.orchard());
    Spec {
        inputs: owned.to_vec(),
        ironwood_outputs: vec![(fvk.address_at(0u32, Scope::Internal), shielded, None)],
        ..Spec::default()
    }
}

fn effect(entry: &TransactionHistoryDetails, pool: PoolType) -> PoolEffect {
    *entry.effects.iter().find(|e| e.pool == pool).unwrap()
}

/// The independently expected owned effects: the account spent exactly its two transparent
/// outputs and received exactly its Ironwood output, completely.
fn assert_owned_effects(entry: &TransactionHistoryDetails, spent: u64, received: u64) {
    assert_eq!(
        effect(entry, PoolType::Transparent),
        PoolEffect {
            pool: PoolType::Transparent,
            received: Zatoshis::ZERO,
            spent: zat(spent),
            completeness: EffectCompleteness::Complete,
        }
    );
    assert_eq!(
        effect(entry, PoolType::Shielded(ShieldedPool::Ironwood)),
        PoolEffect {
            pool: PoolType::Shielded(ShieldedPool::Ironwood),
            received: zat(received),
            spent: Zatoshis::ZERO,
            completeness: EffectCompleteness::Complete,
        }
    );
    assert!(entry.account_movement.complete);
    assert_eq!(
        entry.account_movement.net(),
        i128::from(received) - i128::from(spent)
    );
}

fn assert_provisional(entry: &TransactionHistoryDetails) {
    assert_eq!(entry.classification, HistoryClassification::Provisional);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
    assert_eq!(entry.fee, HistoryFee::Unknown);
    assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
}

fn assert_net_shielding(entry: &TransactionHistoryDetails) {
    assert_eq!(
        entry.classification,
        HistoryClassification::NetReconstructed
    );
    assert_eq!(entry.payment_details, DetailCompleteness::Complete);
    assert_eq!(entry.fee, HistoryFee::Unknown);
    assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
}

/// The whole-transaction fee the transparent publisher derived, as the wallet reports it.
fn whole_fee(entry: &TransactionHistoryDetails) -> WholeTransactionFee {
    entry.transaction_metadata.as_ref().unwrap().metadata.fee
}

/// The reported shapes, end to end: the publishers' current records recover the memo and the
/// shape but no Enhance fee, and the qualified transparent fee completes the history as a net
/// shielding with the exact public amounts; the public path over the same serialized
/// transaction shows the same movement, receipt and fee.
#[test]
fn reported_shielding_shapes_qualify_against_serialized_transactions_and_both_services() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    for (inputs, shielded) in [([120_000, 80_000], 180_000), ([300_000, 120_000], 400_000)] {
        let (mut w, owned) = funded(inputs, false);
        let spec = shielding_spec(&w, &owned, shielded);
        let index = mine_and_recover(&mut w, spec, 0x50, 1);
        let txid = w.mined[index].tx.txid();
        let at = w.mined[index].at;

        // The serialized transaction is the reported shape.
        let tx = &w.mined[index].tx;
        let metadata = transparent_metadata(tx, &w.mined[index].prevouts);
        assert_eq!(metadata.fee, FeeState::Exact(FEE));
        assert_eq!(metadata.transparent_input_count, 2);
        assert!(metadata.has_shielded_components);
        assert_eq!(tx.ironwood_bundle().unwrap().actions().len(), 2);
        assert!(tx.transparent_bundle().unwrap().vout.is_empty());
        let records = enhance_records(tx);
        assert!(records.iter().all(|r| r.has_transparent_inputs()
            && !r.has_transparent_outputs()
            && r.metadata().fee_zatoshis().is_none()));

        // Before enhancement: the owned effects are already complete, nothing else is.
        let before = w.history(txid);
        assert_owned_effects(&before, inputs[0] + inputs[1], shielded);
        assert_eq!(whole_fee(&before), WholeTransactionFee::Exact(zat(FEE)));
        assert_provisional(&before);

        // The publishers' current records: the memo and the shape, no fee.
        let results = w.recover_enhance();
        assert_eq!(
            results[&txid],
            vec![EnhancePirStoreResult::PrivateDetailsUnsupported]
        );
        assert_eq!(
            w.stored(txid),
            (
                Some(2),
                None,
                Some(MemoBytes::empty().as_slice().to_vec()),
                Some(false),
                Some(at as u32)
            )
        );
        // The qualified transparent fee completes it as a net shielding, with no work left.
        assert!(w.private_queries().is_empty());
        let private = w.history(txid);
        assert_owned_effects(&private, inputs[0] + inputs[1], shielded);
        assert_net_shielding(&private);
        assert_eq!(whole_fee(&private), WholeTransactionFee::Exact(zat(FEE)));
        w.assert_private();

        // The public path over the same bytes, once public authority is restored.
        w.set_policy(Public);
        assert!(
            w.st.wallet()
                .transaction_enhancement_work()
                .unwrap()
                .iter()
                .any(
                    |work| matches!(work, TransactionEnhancementWork::Public(r) if r.txid() == txid)
                )
        );
        // Ordinary enhancement retrieves the shielding and then the parents of its
        // transparent inputs.
        let network = network();
        for m in [index, 0, 1] {
            let (tx, mined_at) = (w.mined[m].tx.clone(), w.mined[m].at);
            decrypt_and_store_transaction(&network, w.st.wallet_mut(), &tx, Some(height(mined_at)))
                .unwrap();
        }
        let public = w.history(txid);
        assert_eq!(
            public.account_movement.net(),
            private.account_movement.net()
        );
        assert_eq!(
            effect(&public, PoolType::Shielded(ShieldedPool::Ironwood)).received,
            zat(shielded)
        );
        assert_eq!(public.fee, HistoryFee::Known(zat(FEE)));
        assert_eq!(public.classification, HistoryClassification::Reconstructed);
    }
}

/// The counterexample, serialized: another party spends a 50,000-zatoshi Ironwood note and the
/// transaction pays 50,000 zatoshis to an external transparent output. The account's side is the
/// reported shape exactly: its two inputs (200,000) became its 180,000 Ironwood receipt and the
/// 20,000 fee, it owns every transparent input, and the qualified fee is exact. The Enhance
/// record's transparent-output flag, derived from the transaction, keeps it provisional.
#[test]
fn foreign_ironwood_funding_an_external_transparent_output_qualifies_as_provisional() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut w, owned) = funded([120_000, 80_000], false);
    let (foreign_sk, foreign_fvk) = foreign_orchard();
    let (_, external) = foreign_transparent(0x66);
    let mut spec = shielding_spec(&w, &owned, 180_000);
    spec.ironwood_spends = vec![(
        foreign_sk,
        note(foreign_fvk.address_at(0u32, Scope::External), 50_000, 7),
    )];
    spec.transparent_outputs = vec![(external, 50_000)];
    let index = mine_and_recover(&mut w, spec, 0x51, 1);
    let txid = w.mined[index].tx.txid();
    let metadata = transparent_metadata(&w.mined[index].tx, &w.mined[index].prevouts);
    assert_eq!(metadata.fee, FeeState::Exact(FEE));
    assert_eq!(metadata.transparent_input_count, 2);

    w.recover_enhance();
    assert_eq!(w.stored(txid).3, Some(true));
    let entry = w.history(txid);
    assert_owned_effects(&entry, 200_000, 180_000);
    assert_eq!(whole_fee(&entry), WholeTransactionFee::Exact(zat(FEE)));
    assert_provisional(&entry);
    w.assert_private();
}

/// Another account of the wallet funds the transaction from its own Ironwood note, which pays an
/// external Ironwood output. Scanning links that spend; the account's own side is the reported
/// shape, and it stays provisional.
#[test]
fn another_accounts_ironwood_funding_qualifies_as_provisional() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut w, owned) = funded([120_000, 80_000], true);
    let (other, other_usk) = w.other.clone().unwrap();
    let other_sk = *other_usk.orchard();
    let other_fvk = FullViewingKey::from(&other_sk);

    // The other account receives a 50,000-zatoshi Ironwood note from a foreign transparent
    // output.
    let (funder_sk, funder) = foreign_transparent(0x21);
    let prevout = OutPoint::new([0xe1; 32], 0);
    let coin = TxOut::new(zat(65_000), funder.script().into());
    let funding = Spec {
        inputs: vec![(prevout.clone(), coin.clone(), funder_sk)],
        ironwood_outputs: vec![(other_fvk.address_at(0u32, Scope::External), 50_000, None)],
        ..Spec::default()
    };
    mine_and_recover(&mut w, funding, 0x52, 1);
    let (diversifier, value, rho, rseed): (Vec<u8>, u64, Vec<u8>, Vec<u8>) =
        w.st.wallet()
            .conn()
            .query_row(
                "SELECT n.diversifier, n.value, n.rho, n.rseed FROM ironwood_received_notes n
             JOIN accounts a ON a.id = n.account_id WHERE a.uuid = ?1",
                [other.expose_uuid()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
    let rho = Rho::from_bytes(&rho.try_into().unwrap()).unwrap();
    let held = orchard::Note::from_parts(
        other_fvk.address(
            orchard::keys::Diversifier::from_bytes(diversifier.try_into().unwrap()),
            Scope::External,
        ),
        NoteValue::from_raw(value),
        rho,
        RandomSeed::from_bytes(rseed.try_into().unwrap(), &rho).unwrap(),
        NoteVersion::V3,
    )
    .unwrap();

    let (_, foreign_fvk) = foreign_orchard();
    let mut spec = shielding_spec(&w, &owned, 180_000);
    spec.ironwood_spends = vec![(other_sk, held)];
    spec.ironwood_outputs
        .push((foreign_fvk.address_at(0u32, Scope::External), 50_000, None));
    let index = mine_and_recover(&mut w, spec, 0x53, 2);
    let txid = w.mined[index].tx.txid();
    // Scanning linked the other account's spend.
    let linked: i64 =
        w.st.wallet()
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM ironwood_received_note_spends s
             JOIN transactions t ON t.id_tx = s.transaction_id WHERE t.txid = ?1",
                [txid.as_ref()],
                |row| row.get(0),
            )
            .unwrap();
    assert_eq!(linked, 1);

    w.recover_enhance();
    assert_eq!(w.stored(txid).3, Some(false));
    let entry = w.history(txid);
    assert_owned_effects(&entry, 200_000, 180_000);
    assert_provisional(&entry);
    w.assert_private();
}

/// A hidden self-balanced pair: another party spends 100,000 of its Ironwood funds into an equal
/// output of its own. The evidence matches a pure shielding exactly, so it is reported as a net
/// reconstruction with unknown payment and account fee, as documented.
#[test]
fn a_hidden_self_balanced_ironwood_pair_remains_a_net_reconstruction() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut w, owned) = funded([120_000, 80_000], false);
    let (foreign_sk, foreign_fvk) = foreign_orchard();
    let mut spec = shielding_spec(&w, &owned, 180_000);
    spec.ironwood_spends = vec![(
        foreign_sk,
        note(foreign_fvk.address_at(0u32, Scope::External), 100_000, 9),
    )];
    spec.ironwood_outputs
        .push((foreign_fvk.address_at(1u32, Scope::External), 100_000, None));
    let index = mine_and_recover(&mut w, spec, 0x54, 1);
    let txid = w.mined[index].tx.txid();
    let metadata = transparent_metadata(&w.mined[index].tx, &w.mined[index].prevouts);
    assert_eq!(metadata.fee, FeeState::Exact(FEE));

    w.recover_enhance();
    let entry = w.history(txid);
    assert_owned_effects(&entry, 200_000, 180_000);
    assert_net_shielding(&entry);
    w.assert_private();
}

/// Re-mining the shielding elsewhere: the shape recorded at the first placement is stale, so the
/// history waits until the record is retrieved again at the new position and height.
#[test]
fn re_mining_a_recovered_shielding_elsewhere_requires_fresh_evidence() {
    let _heavy = HEAVY.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut w, owned) = funded([120_000, 80_000], false);
    let spec = shielding_spec(&w, &owned, 180_000);
    let index = mine_and_recover(&mut w, spec, 0x55, 1);
    let txid = w.mined[index].tx.txid();
    let first = w.mined[index].at;
    w.recover_enhance();
    assert_net_shielding(&w.history(txid));

    // A reorg replaces the block; the same transaction is mined one block later.
    let mined = w.mined.remove(index);
    w.st.truncate_to_height(height(first - 1));
    w.tree_size = mined.first_position;
    w.scan_to(first);
    let index = w.mine(mined.tx, mined.prevouts);
    assert_eq!(w.mined[index].at, first + 1);
    w.scan_to(w.tip() + 2);
    w.publish_transparent(2);
    w.recover_transparent();
    assert_eq!(w.stored(txid).4, Some(first as u32));
    assert_eq!(
        w.history(txid).classification,
        HistoryClassification::Provisional
    );
    // The wallet asks again, privately, at the new position.
    let retry = w.private_queries();
    assert_eq!(retry.len(), 1);
    let placed = w.mined[index].first_position;
    assert!((placed..placed + 2).contains(&u64::from(retry[0].position())));
    w.recover_enhance();
    assert_eq!(w.stored(txid).4, Some(first as u32 + 1));
    assert_net_shielding(&w.history(txid));
    w.assert_private();
}
