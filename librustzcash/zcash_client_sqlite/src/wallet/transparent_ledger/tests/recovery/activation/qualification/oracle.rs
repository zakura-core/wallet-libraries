//! The block-derived oracle.
//!
//! A fixture chain holds real transactions with transparent bundles at local heights. The
//! oracle walks it block by block with only the account's keys and derives the exact receives,
//! spends, unspent outputs, and balances. A fixture source indexes the same chain by address,
//! as a server would. A driver delivers the source's results through the ledger the way a
//! coordinator might: split into several commits, reordered, with spends before their receives,
//! through pages, and replayed. The candidate diagnostics, the projection, the snapshot, and the
//! selectors must then agree with the oracle exactly.

use std::collections::{BTreeMap, BTreeSet};

use transparent::{
    address::Script,
    bundle::{Bundle, TxIn, TxOut},
};
use zcash_client_backend::data_api::{
    CoinbaseFilter, InputSource as _,
    wallet::{
        TargetHeight,
        input_selection::{LockFilter, LockedInputPolicy},
    },
};
use zcash_primitives::transaction::{Transaction, TransactionData, TxVersion};
use zcash_protocol::consensus::BranchId;

use transparent::keys::{IncomingViewingKey as _, NonHardenedChildIndex};

use super::*;

/// Blocks of real transactions, by height.
#[derive(Default)]
pub(super) struct Chain {
    blocks: BTreeMap<BlockHeight, Vec<Transaction>>,
    nonce: u32,
}

impl Chain {
    fn transaction(&mut self, vin: Vec<OutPoint>, vout: Vec<TxOut>) -> Transaction {
        self.nonce += 1;
        let bundle = Bundle {
            vin: vin
                .into_iter()
                .map(|prevout| TxIn::from_parts(prevout, Script::default(), u32::MAX))
                .collect(),
            vout,
            authorization: transparent::bundle::Authorized,
        };
        // The nonce in the lock time keeps otherwise identical transactions distinct.
        TransactionData::<zcash_primitives::transaction::Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            self.nonce,
            BlockHeight::from_u32(0),
            Some(bundle),
            None,
            None,
            None,
        )
        .freeze()
        .unwrap()
    }

    fn outputs(vout: &[(TransparentAddress, u64)]) -> Vec<TxOut> {
        vout.iter()
            .map(|(address, value)| {
                TxOut::new(Zatoshis::const_from_u64(*value), address.script().into())
            })
            .collect()
    }

    /// Mines a transaction spending `vin` to `vout` at `height`, returning its txid.
    pub(super) fn pay(
        &mut self,
        height: BlockHeight,
        vin: Vec<OutPoint>,
        vout: &[(TransparentAddress, u64)],
    ) -> TxId {
        let tx = self.transaction(vin, Self::outputs(vout));
        let txid = tx.txid();
        self.blocks.entry(height).or_default().push(tx);
        txid
    }

    /// Mines a payment into `vout` from outside the wallet at `height`.
    pub(super) fn fund(&mut self, height: BlockHeight, vout: &[(TransparentAddress, u64)]) -> TxId {
        let foreign = OutPoint::new([0xf0; 32], self.nonce);
        self.pay(height, vec![foreign], vout)
    }

    /// Mines a coinbase transaction paying `vout` at `height`.
    pub(super) fn coinbase(
        &mut self,
        height: BlockHeight,
        vout: &[(TransparentAddress, u64)],
    ) -> TxId {
        let tx = self.transaction(vec![OutPoint::NULL], Self::outputs(vout));
        assert!(tx.transparent_bundle().unwrap().is_coinbase());
        let txid = tx.txid();
        // A coinbase transaction is the first in its block.
        self.blocks.entry(height).or_default().insert(0, tx);
        txid
    }

    /// Removes every block above `floor`, returning their transactions in chain order.
    pub(super) fn truncate(&mut self, floor: BlockHeight) -> Vec<(BlockHeight, Transaction)> {
        let above = self.blocks.split_off(&(floor + 1));
        above
            .into_iter()
            .flat_map(|(height, txs)| txs.into_iter().map(move |tx| (height, tx)))
            .collect()
    }

    /// Mines `tx` again at `height`.
    pub(super) fn remine(&mut self, height: BlockHeight, tx: Transaction) {
        let block = self.blocks.entry(height).or_default();
        if tx.transparent_bundle().unwrap().is_coinbase() {
            block.insert(0, tx);
        } else {
            block.push(tx);
        }
    }

    fn mined(&self, through: BlockHeight) -> impl Iterator<Item = (BlockHeight, &Transaction)> {
        self.blocks
            .range(..=through)
            .flat_map(|(height, txs)| txs.iter().map(move |tx| (*height, tx)))
    }
}

fn outpoint_key(outpoint: &OutPoint) -> ([u8; 32], u32) {
    (*outpoint.hash(), outpoint.n())
}

/// What the chain holds for an account, derived without the ledger.
#[derive(Debug)]
pub(super) struct Expected {
    pub(super) receives: Vec<ReceiveEvent>,
    pub(super) spends: Vec<SpendEvent>,
    pub(super) unspent: Vec<ReceiveEvent>,
}

impl Expected {
    pub(super) fn total(&self, coinbase: bool) -> Zatoshis {
        self.unspent
            .iter()
            .filter(|r| r.coinbase == coinbase)
            .map(|r| r.value)
            .sum::<Option<Zatoshis>>()
            .unwrap()
    }

    fn unspent_outpoints(&self, coinbase: Option<bool>) -> Vec<OutPoint> {
        self.unspent
            .iter()
            .filter(|r| coinbase.is_none_or(|c| r.coinbase == c))
            .map(|r| r.outpoint.clone())
            .collect()
    }
}

/// Walks `chain` through `through` and derives, for the `owned` addresses, every receive and
/// spend and the outputs left unspent.
pub(super) fn oracle(
    chain: &Chain,
    owned: &BTreeSet<TransparentAddress>,
    through: BlockHeight,
) -> Expected {
    let mut receives = vec![];
    let mut spends = vec![];
    let mut utxos: BTreeMap<_, ReceiveEvent> = BTreeMap::new();
    for (height, tx) in chain.mined(through) {
        let bundle = tx.transparent_bundle().unwrap();
        let coinbase = bundle.is_coinbase();
        if !coinbase {
            for (index, input) in bundle.vin.iter().enumerate() {
                if let Some(spent) = utxos.remove(&outpoint_key(input.prevout())) {
                    spends.push(SpendEvent {
                        metadata: None,
                        spending_txid: tx.txid(),
                        input_index: index as u32,
                        prevout: input.prevout().clone(),
                        prevout_address: spent.address,
                        mined_height: height,
                    });
                }
            }
        }
        for (n, output) in bundle.vout.iter().enumerate() {
            let Some(address) = output.recipient_address().filter(|a| owned.contains(a)) else {
                continue;
            };
            let received = ReceiveEvent {
                metadata: None,
                outpoint: OutPoint::new(*tx.txid().as_ref(), n as u32),
                address,
                value: output.value(),
                coinbase,
                mined_height: height,
            };
            utxos.insert(outpoint_key(&received.outpoint), received.clone());
            receives.push(received);
        }
    }
    receives.sort_by_key(|r| outpoint_key(&r.outpoint));
    spends.sort_by_key(|s| (*s.spending_txid.as_ref(), s.input_index));
    Expected {
        receives,
        spends,
        unspent: utxos.into_values().collect(),
    }
}

/// What a server indexing `chain` by address returns for `addresses` through `through`: the
/// outputs paying them, and the inputs spending those outputs.
pub(super) fn source(
    chain: &Chain,
    addresses: &BTreeSet<TransparentAddress>,
    through: BlockHeight,
) -> (Vec<ReceiveEvent>, Vec<SpendEvent>) {
    let mut paid = BTreeMap::new();
    let mut receives = vec![];
    let mut spends = vec![];
    for (height, tx) in chain.mined(through) {
        let bundle = tx.transparent_bundle().unwrap();
        for (n, output) in bundle.vout.iter().enumerate() {
            let outpoint = OutPoint::new(*tx.txid().as_ref(), n as u32);
            if let Some(address) = output.recipient_address() {
                paid.insert(outpoint_key(&outpoint), address);
                if addresses.contains(&address) {
                    receives.push(ReceiveEvent {
                        metadata: None,
                        outpoint,
                        address,
                        value: output.value(),
                        coinbase: bundle.is_coinbase(),
                        mined_height: height,
                    });
                }
            }
        }
        if bundle.is_coinbase() {
            continue;
        }
        for (index, input) in bundle.vin.iter().enumerate() {
            if let Some(address) = paid
                .get(&outpoint_key(input.prevout()))
                .filter(|a| addresses.contains(a))
            {
                spends.push(SpendEvent {
                    metadata: None,
                    spending_txid: tx.txid(),
                    input_index: index as u32,
                    prevout: input.prevout().clone(),
                    prevout_address: *address,
                    mined_height: height,
                });
            }
        }
    }
    // Delivered newest first, as a paginated server might.
    receives.reverse();
    spends.reverse();
    (receives, spends)
}

fn script_of(address: &TransparentAddress) -> Vec<u8> {
    Script::from(address.script()).0.0
}

/// Recovers `account` through its target from `chain` as the production adapter does, from
/// public reads alone, and returns the number of passes.
///
/// Each pass reads the watch set, resumes the pages it lists, and covers every watched address
/// from its required start through the target. Recovery ends at the first pass that finds no
/// open page and the same addresses as the pass before. Only that address set is carried
/// between passes; coverage is never read.
///
/// Delivery varies by address position: one commit, then a replay; spends first, then receives
/// with coverage; or one commit. In the third position, an address the window added since the
/// previous pass is instead delivered through a page opened with its receives and left for the
/// next pass to resume. Only such an address gets a page, because a revision cannot reopen
/// retrieval over a range it already covered.
pub(super) fn recover(
    st: &mut State,
    account: AccountUuid,
    chain: &Chain,
    revision: &RecoveryRevision,
) -> usize {
    let mut previous: Option<BTreeMap<TransparentAddress, BlockHeight>> = None;
    for pass in 1..=64 {
        let ws = watch(st, account);
        let watched: BTreeMap<_, _> = ws
            .addresses
            .iter()
            .map(|w| (w.address, w.required_from))
            .collect();
        if previous.as_ref() == Some(&watched) && ws.pending_pages.is_empty() {
            return pass;
        }
        let target = ws.target.unwrap();
        let base = || {
            let mut c = commit(&ws);
            c.revision = revision.clone();
            c
        };

        for page in &ws.pending_pages {
            assert_eq!(page.revision, *revision);
            let addresses: BTreeSet<_> = page.request.addresses.iter().copied().collect();
            let (receives, spends) = source(chain, &addresses, page.request.through);
            let mut c = base();
            c.anchor = page.target;
            c.receives = receives;
            c.spends = spends;
            c.coverage = addresses
                .iter()
                .map(|address| AddressRange {
                    address: *address,
                    from: page.request.from,
                    through: page.request.through,
                })
                .collect();
            c.completed_pages.push(page.request.page.clone());
            apply(st, c).unwrap();
        }

        for (index, (address, required_from)) in watched.iter().enumerate() {
            let range = AddressRange {
                address: *address,
                from: *required_from,
                through: target.height,
            };
            let (receives, spends) = source(chain, &BTreeSet::from([*address]), target.height);
            let fresh = previous
                .as_ref()
                .is_some_and(|previous| !previous.contains_key(address));
            match index % 3 {
                0 => {
                    let mut c = base();
                    c.receives = receives;
                    c.spends = spends;
                    c.coverage = vec![range];
                    apply(st, c.clone()).unwrap();
                    // A replay changes nothing.
                    let before = recovery(st, account);
                    apply(st, c).unwrap();
                    assert_eq!(recovery(st, account), before);
                }
                1 => {
                    let mut c = base();
                    c.spends = spends;
                    apply(st, c).unwrap();
                    let mut c = base();
                    c.receives = receives;
                    c.coverage = vec![range];
                    apply(st, c).unwrap();
                }
                _ if fresh => {
                    let mut c = base();
                    c.receives = receives;
                    c.opened_pages.push(PageRequest {
                        page: format!("pass {pass} address {index}").into_bytes(),
                        addresses: vec![*address],
                        from: range.from,
                        through: range.through,
                    });
                    apply(st, c).unwrap();
                }
                _ => {
                    let mut c = base();
                    c.receives = receives;
                    c.spends = spends;
                    c.coverage = vec![range];
                    apply(st, c).unwrap();
                }
            }
        }
        previous = Some(watched);
    }
    panic!("fixture recovery did not converge within 64 passes")
}

/// Every derived external and internal address of the test account within reach of the
/// fixture chains below.
pub(super) fn owned_addresses(st: &State) -> BTreeSet<TransparentAddress> {
    let key = st
        .test_account()
        .unwrap()
        .usk()
        .transparent()
        .to_account_pubkey();
    let external = key.derive_external_ivk().unwrap();
    let internal = key.derive_internal_ivk().unwrap();
    (0..48)
        .map(|i| {
            external
                .derive_address(NonHardenedChildIndex::from_index(i).unwrap())
                .unwrap()
        })
        .chain((0..24).map(|i| {
            internal
                .derive_address(NonHardenedChildIndex::from_index(i).unwrap())
                .unwrap()
        }))
        .collect()
}

pub(super) fn external_at(st: &State, index: u32) -> TransparentAddress {
    st.test_account()
        .unwrap()
        .usk()
        .transparent()
        .to_account_pubkey()
        .derive_external_ivk()
        .unwrap()
        .derive_address(NonHardenedChildIndex::from_index(index).unwrap())
        .unwrap()
}

pub(super) fn internal_at(st: &State, index: u32) -> TransparentAddress {
    st.test_account()
        .unwrap()
        .usk()
        .transparent()
        .to_account_pubkey()
        .derive_internal_ivk()
        .unwrap()
        .derive_address(NonHardenedChildIndex::from_index(index).unwrap())
        .unwrap()
}

fn foreign(tag: u8) -> TransparentAddress {
    TransparentAddress::PublicKeyHash([tag; 20])
}

/// Asserts that `account`'s candidate diagnostics equal the oracle's view of `chain` at the
/// account's target, returning that view.
pub(super) fn assert_diagnostics_agree(
    st: &State,
    account: AccountUuid,
    chain: &Chain,
    owned: &BTreeSet<TransparentAddress>,
) -> Expected {
    let r = recovery(st, account);
    let target = r.target.unwrap().height;
    let expected = oracle(chain, owned, target);
    assert_eq!(r.blockers, vec![]);
    assert_eq!(r.covered_through, Some(target));
    assert_eq!(r.unresolved_spends, 0);
    let mut receives = r.receives.clone();
    receives.sort_by_key(|r| outpoint_key(&r.outpoint));
    assert_eq!(receives, expected.receives);
    let mut spends = r.spends.clone();
    spends.sort_by_key(|s| (*s.spending_txid.as_ref(), s.input_index));
    assert_eq!(spends, expected.spends);
    let mut unspent = r.unspent.clone();
    unspent.sort_by_key(outpoint_key);
    assert_eq!(unspent, expected.unspent_outpoints(None));
    assert_eq!(
        r.recovered_unverified,
        Some((expected.total(false) + expected.total(true)).unwrap())
    );
    expected
}

/// The ledger-origin outputs and spends of `account` whose transactions are mined, as
/// `(outpoint, script, value, height)` and `(spending txid, prevout)`.
#[allow(clippy::type_complexity)]
fn projection(
    st: &State,
    account: AccountUuid,
) -> (
    BTreeSet<(([u8; 32], u32), Vec<u8>, u64, u32)>,
    BTreeSet<([u8; 32], ([u8; 32], u32))>,
) {
    let outputs = conn(st)
        .prepare(
            "SELECT t.txid, o.output_index, o.script, o.value_zat, t.mined_height
             FROM transparent_received_outputs o
             JOIN transactions t ON t.id_tx = o.transaction_id
             JOIN accounts a ON a.id = o.account_id
             WHERE a.uuid = ?1 AND t.mined_height IS NOT NULL
             AND EXISTS (SELECT 1 FROM tpir_output_origins oo
                         WHERE oo.output_id = o.id AND oo.origin = 2)",
        )
        .unwrap()
        .query_map([account.0], |row| {
            Ok((
                (row.get::<_, [u8; 32]>(0)?, row.get(1)?),
                row.get(2)?,
                row.get::<_, i64>(3)? as u64,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let spends = conn(st)
        .prepare(
            "SELECT st.txid, pt.txid, o.output_index
             FROM transparent_received_output_spends s
             JOIN transparent_received_outputs o ON o.id = s.transparent_received_output_id
             JOIN transactions pt ON pt.id_tx = o.transaction_id
             JOIN transactions st ON st.id_tx = s.transaction_id
             JOIN accounts a ON a.id = o.account_id
             WHERE a.uuid = ?1 AND st.mined_height IS NOT NULL
             AND EXISTS (SELECT 1 FROM tpir_spend_origins so
                         WHERE so.spending_transaction_id = s.transaction_id
                         AND so.prevout_txid = pt.txid
                         AND so.prevout_output_index = o.output_index
                         AND so.origin = 2)",
        )
        .unwrap()
        .query_map([account.0], |row| {
            Ok((row.get(0)?, (row.get(1)?, row.get(2)?)))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    (outputs, spends)
}

/// Asserts that `account`'s projection, snapshot, and selectors equal `expected`.
pub(super) fn assert_authority_agrees(st: &State, account: AccountUuid, expected: &Expected) {
    let (outputs, spends) = projection(st, account);
    assert_eq!(
        outputs,
        expected
            .receives
            .iter()
            .map(|r| (
                outpoint_key(&r.outpoint),
                script_of(&r.address),
                u64::from(r.value),
                u32::from(r.mined_height)
            ))
            .collect()
    );
    assert_eq!(
        spends,
        expected
            .spends
            .iter()
            .map(|s| (*s.spending_txid.as_ref(), outpoint_key(&s.prevout)))
            .collect()
    );

    let s = snapshot(st, account);
    assert_eq!(s.authority, TransparentAuthority::Private);
    assert_eq!(s.blockers, vec![]);
    let authorized = s.authorized.unwrap();
    assert_eq!(authorized.regular.total(), expected.total(false));
    assert_eq!(authorized.regular.spendable_value(), expected.total(false));
    assert_eq!(authorized.coinbase.total(), expected.total(true));
    // The fixture chain is far shorter than coinbase maturity.
    assert_eq!(authorized.coinbase.spendable_value(), Zatoshis::ZERO);

    let target = TargetHeight::from(st.wallet().chain_height().unwrap().unwrap() + 1);
    let addresses: Vec<_> = watch(st, account)
        .addresses
        .iter()
        .map(|w| w.address)
        .collect();
    let mut selected: Vec<_> = st
        .wallet()
        .db()
        .get_spendable_transparent_outputs_for_addresses(
            &addresses,
            target,
            ConfirmationsPolicy::MIN,
            CoinbaseFilter::AllTransparentOutputs,
            LockFilter::Policy(&LockedInputPolicy::Exclude),
        )
        .unwrap()
        .iter()
        .map(|o| o.outpoint().clone())
        .collect();
    selected.sort_by_key(outpoint_key);
    assert_eq!(selected, expected.unspent_outpoints(Some(false)));
}

/// A wallet scanned twenty blocks past the birthday, under `PrivateRequired`, with a fixture
/// chain that exercises window growth in both scopes, a coinbase output, spends in the block of
/// their receive, a multi-input spend mixing foreign and owned inputs, and outputs to foreign
/// scripts. One of its outputs was also found by public discovery.
pub(super) fn recovery_oracle_wallet() -> (
    State,
    AccountUuid,
    Chain,
    BTreeSet<TransparentAddress>,
    ReceiveEvent,
) {
    let (mut st, accounts) = recovery_wallet_with(0);
    let account = accounts[0];
    scan_new_blocks(&mut st, 10);
    let b = st.test_account().unwrap().birthday().height();
    let owned = owned_addresses(&st);
    let (e, i) = (|n| external_at(&st, n), |n| internal_at(&st, n));

    let mut chain = Chain::default();
    let r1 = chain.fund(b + 1, &[(e(0), 50_000), (foreign(1), 9_000)]);
    let r2 = chain.fund(b + 2, &[(e(0), 20_000)]);
    chain.coinbase(b + 3, &[(e(1), 625_000)]);
    // Activity near each window's end extends it, twice for the external scope.
    let r3 = chain.fund(b + 4, &[(e(9), 31_000), (i(3), 7_000)]);
    let r4 = chain.fund(b + 5, &[(e(17), 12_000), (e(17), 13_000)]);
    // An owned output spent in the block that received it.
    chain.pay(
        b + 5,
        vec![OutPoint::new(*r4.as_ref(), 0)],
        &[(foreign(2), 11_000)],
    );
    // A spend mixing owned and foreign inputs, with change to the internal window.
    chain.pay(
        b + 7,
        vec![
            OutPoint::new([0xee; 32], 3),
            OutPoint::new(*r1.as_ref(), 0),
            OutPoint::new(*r3.as_ref(), 1),
        ],
        &[(foreign(3), 40_000), (i(7), 16_000)],
    );
    chain.fund(b + 8, &[(e(25), 8_000)]);
    // Foreign activity only.
    chain.fund(b + 9, &[(foreign(4), 1_000)]);
    chain.pay(
        b + 10,
        vec![OutPoint::new(*r3.as_ref(), 0)],
        &[(e(26), 30_000)],
    );

    // Public discovery already saw the second payment.
    let legacy = ReceiveEvent {
        metadata: None,
        outpoint: OutPoint::new(*r2.as_ref(), 0),
        address: e(0),
        value: Zatoshis::const_from_u64(20_000),
        coinbase: false,
        mined_height: b + 2,
    };
    let output = zcash_client_backend::wallet::WalletTransparentOutput::from_parts(
        legacy.outpoint.clone(),
        TxOut::new(legacy.value, legacy.address.script().into()),
        Some(legacy.mined_height),
        Some(account),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    publicly(&mut st, |st| {
        st.wallet_mut()
            .db_mut()
            .put_received_transparent_utxo(&output)
            .unwrap()
    });
    (st, account, chain, owned, legacy)
}

/// A [`recovery_oracle_wallet`] recovered, qualified, and promoted.
pub(super) fn promoted_oracle_wallet() -> (
    State,
    AccountUuid,
    Chain,
    BTreeSet<TransparentAddress>,
    RecoveryRevision,
) {
    let (mut st, account, chain, owned, _) = recovery_oracle_wallet();
    let fixture = revision(1, true);
    recover(&mut st, account, &chain, &fixture);
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();
    (st, account, chain, owned, fixture)
}

#[test]
fn candidate_recovery_promotion_and_active_commits_match_the_oracle() {
    let (mut st, account, mut chain, owned, legacy) = recovery_oracle_wallet();
    let b = st.test_account().unwrap().birthday().height();
    let fixture = revision(1, true);

    // Candidate recovery reaches the oracle's exact view and leaves the wallet untouched.
    let before = production_dump(conn(&st));
    // Window growth takes several passes.
    assert!(recover(&mut st, account, &chain, &fixture) >= 3);
    let expected = assert_diagnostics_agree(&st, account, &chain, &owned);
    assert_eq!(production_dump(conn(&st)), before);
    // The chain reached external index 26 and internal index 7, far past the initial windows.
    assert!(
        expected
            .receives
            .iter()
            .any(|r| r.address == external_at(&st, 26))
    );
    assert!(
        expected
            .receives
            .iter()
            .any(|r| r.address == internal_at(&st, 7))
    );
    assert!(expected.receives.iter().any(|r| r.coinbase));

    // Promotion projects exactly the oracle's view. The legacy output agrees with it, but the
    // oracle, not that agreement, is what the balance is checked against.
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();
    assert_authority_agrees(&st, account, &expected);
    assert_eq!(
        super::super::super::super::output_origins(conn(&st), &legacy.outpoint),
        vec![0, 2]
    );
    assert!(expected.total(false) > legacy.value);

    // The chain advances: new receives, a spend of a promoted output, and more growth.
    scan_new_blocks(&mut st, 3);
    let tip = st.wallet().chain_height().unwrap().unwrap();
    assert!(tip > b + 20);
    let e30 = external_at(&st, 30);
    let r5 = chain.fund(tip - 2, &[(e30, 70_000)]);
    let change = internal_at(&st, 12);
    chain.pay(
        tip,
        vec![
            OutPoint::new(*r5.as_ref(), 0),
            expected
                .unspent
                .iter()
                .find(|r| r.address == external_at(&st, 26))
                .unwrap()
                .outpoint
                .clone(),
        ],
        &[(foreign(5), 60_000), (change, 39_000)],
    );
    recover(&mut st, account, &chain, &fixture);
    let expected = assert_diagnostics_agree(&st, account, &chain, &owned);
    assert_authority_agrees(&st, account, &expected);
    assert!(expected.receives.iter().any(|r| r.address == change));
}

#[test]
fn rewind_and_remining_match_the_oracle() {
    let (mut st, account, mut chain, owned, fixture) = promoted_oracle_wallet();
    let b = st.test_account().unwrap().birthday().height();

    // Blocks above the floor are replaced. Their transactions are mined again on the new chain:
    // the first block's at the same height, the rest three blocks later, except one payment
    // that is never mined again.
    let floor = b + 6;
    st.truncate_to_height(floor);
    let mut orphaned = None;
    for (height, tx) in chain.truncate(floor) {
        let pays_e25 = tx
            .transparent_bundle()
            .unwrap()
            .vout
            .iter()
            .any(|o| o.recipient_address() == Some(external_at(&st, 25)));
        if pays_e25 {
            orphaned = Some(tx.txid());
        } else if height == floor + 1 {
            chain.remine(height, tx);
        } else {
            chain.remine(height + 3, tx);
        }
    }
    let orphaned = orphaned.unwrap();
    scan_new_blocks(&mut st, 8);

    recover(&mut st, account, &chain, &fixture);
    let expected = assert_diagnostics_agree(&st, account, &chain, &owned);
    assert_authority_agrees(&st, account, &expected);
    // The orphaned payment keeps its projection row, unmined, and authorizes nothing.
    assert!(
        !expected
            .receives
            .iter()
            .any(|r| r.outpoint.txid() == &orphaned)
    );
    assert_eq!(st.wallet().get_tx_height(orphaned).unwrap(), None);
    assert_eq!(
        super::super::super::super::output_origins(
            conn(&st),
            &OutPoint::new(*orphaned.as_ref(), 0)
        ),
        vec![2]
    );
}
