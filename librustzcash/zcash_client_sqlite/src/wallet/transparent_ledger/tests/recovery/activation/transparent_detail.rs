//! Transparent txid enhancement: work creation, listing, backoff, validation and the view.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zcash_client_backend::data_api::transparent_ledger::{
    TransactionMetadata, TransparentDetailOutcome, TransparentDetailRead as _,
    TransparentDetailWrite as _, TransparentDisplayContradiction, TransparentDisplayFacts,
    TransparentDisplayOutput, TransparentDisplayProvenance, TransparentDisplaySource,
    TransparentDisplayStore, TransparentDisplayView, WholeTransactionFee,
};

use super::*;
use crate::{
    TxRef,
    wallet::{TxQueryType, transparent_ledger::details::backoff},
};

const RECEIVE: u8 = 1;
const SPEND: u8 = 2;
const MIXED: u8 = 4;
const MAP_A: [u8; 32] = [0xa; 32];
const MAP_B: [u8; 32] = [0xb; 32];

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_000_000_000)
}

fn later(secs: u64) -> SystemTime {
    now() + Duration::from_secs(secs)
}

fn txid_of(receive: &ReceiveEvent) -> TxId {
    *receive.outpoint.txid()
}

fn tx_ref(st: &State, txid: TxId) -> TxRef {
    TxRef(
        conn(st)
            .query_row(
                "SELECT id_tx FROM transactions WHERE txid = ?1",
                [txid.as_ref()],
                |row| row.get(0),
            )
            .unwrap(),
    )
}

/// Every work row, by txid, with its reasons.
fn work_rows(st: &State) -> Vec<(TxId, u8)> {
    conn(st)
        .prepare(
            "SELECT t.txid, w.reasons FROM transparent_detail_work w
             JOIN transactions t ON t.id_tx = w.transaction_id ORDER BY t.txid",
        )
        .unwrap()
        .query_map([], |row| Ok((TxId::from_bytes(row.get(0)?), row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn reasons(st: &State, txid: TxId) -> Option<u8> {
    work_rows(st)
        .into_iter()
        .find(|(t, _)| *t == txid)
        .map(|(_, r)| r)
}

fn attempts(st: &State, txid: TxId) -> u32 {
    conn(st)
        .query_row(
            "SELECT w.attempts FROM transparent_detail_work w
             JOIN transactions t ON t.id_tx = w.transaction_id WHERE t.txid = ?1",
            [txid.as_ref()],
            |row| row.get(0),
        )
        .unwrap()
}

fn listing_at(st: &State, at: SystemTime, map: Option<[u8; 32]>) -> Vec<TxId> {
    st.wallet()
        .db()
        .transparent_detail_work(at, 100, map)
        .unwrap()
        .into_iter()
        .map(|r| r.txid)
        .collect()
}

fn listing(st: &State) -> Vec<TxId> {
    listing_at(st, now(), None)
}

fn defer(st: &mut State, txid: TxId, outcome: TransparentDetailOutcome, at: SystemTime) {
    st.wallet_mut()
        .db_mut()
        .defer_transparent_detail(txid, outcome, Some(MAP_A), at)
        .unwrap()
}

fn unavailable() -> TransparentDetailOutcome {
    TransparentDetailOutcome::Unavailable { retry_after: None }
}

fn generation(st: &State) -> u64 {
    st.wallet()
        .db()
        .applied_transparent_policy()
        .unwrap()
        .generation
}

fn script_of(address: TransparentAddress) -> Vec<u8> {
    transparent::address::Script::from(address.script()).0.0
}

/// Facts agreeing with everything the wallet holds about `receive`'s transaction: the receive
/// at its index, after an unowned output.
fn facts_for(receive: &ReceiveEvent) -> TransparentDisplayFacts {
    let mut outputs = vec![
        TransparentDisplayOutput {
            value: Zatoshis::const_from_u64(1),
            script: vec![0x6a],
        };
        receive.outpoint.n() as usize + 2
    ];
    outputs[receive.outpoint.n() as usize] = TransparentDisplayOutput {
        value: receive.value,
        script: script_of(receive.address),
    };
    TransparentDisplayFacts {
        txid: txid_of(receive),
        coinbase: false,
        metadata: TransactionMetadata {
            fee: WholeTransactionFee::Exact(Zatoshis::const_from_u64(1_000)),
            transparent_input_count: 1,
            has_shielded_components: false,
        },
        outputs,
        provenance: TransparentDisplayProvenance {
            shard_id: 3,
            revision: 1,
            map_sha256: MAP_A,
            looked_up_height: receive.mined_height,
        },
    }
}

fn store(st: &mut State, facts: TransparentDisplayFacts) -> TransparentDisplayStore {
    let generation = generation(st);
    st.wallet_mut()
        .db_mut()
        .store_transparent_display(facts, generation, now())
        .unwrap()
}

fn view(st: &State, account: AccountUuid, txid: TxId) -> Option<TransparentDisplayView> {
    st.wallet()
        .db()
        .transparent_display_view(account, txid)
        .unwrap()
}

fn display_rows(st: &State) -> (i64, i64) {
    (
        count(st, "transparent_tx_display"),
        count(st, "transparent_tx_display_outputs"),
    )
}

#[test]
fn migration_additive_and_backfills_route2_and_ledger_origin() {
    let (mut st, _, unspent) = active_wallet();
    // A mixed transaction marked route 2, and an unrelated one, both without raw bytes.
    let mixed = TxId::from_bytes([0x55; 32]);
    let height = u32::from(unspent.mined_height);
    for txid in [mixed, TxId::from_bytes([0x66; 32])] {
        conn(&st)
            .execute(
                "INSERT INTO transactions (txid, mined_height, min_observed_height)
                 VALUES (?1, ?2, ?2)",
                rusqlite::params![txid.as_ref(), height],
            )
            .unwrap();
    }
    conn(&st)
        .execute(
            "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (?1, 2)",
            [tx_ref(&st, mixed).0],
        )
        .unwrap();
    // The wallet as it was before the migration.
    conn(&st)
        .execute_batch(
            "DROP TABLE transparent_tx_display_outputs;
             DROP TABLE transparent_tx_display;
             DROP TABLE transparent_detail_work;",
        )
        .unwrap();
    conn(&st)
        .execute(
            "DELETE FROM schemer_migrations WHERE id = ?1",
            [uuid::Uuid::from_u128(0x73d751a3_dbdc_461a_9154_e061903aae4f).as_bytes()],
        )
        .unwrap();
    let dump = |st: &State| -> Vec<_> {
        production_dump(conn(st))
            .into_iter()
            .filter(|(table, _)| {
                ![
                    "schemer_migrations",
                    "transparent_detail_work",
                    "transparent_tx_display",
                    "transparent_tx_display_outputs",
                ]
                .contains(&table.as_str())
            })
            .collect()
    };
    let before = dump(&st);

    crate::wallet::init::WalletMigrator::new()
        .init_or_migrate(st.wallet_mut().db_mut())
        .unwrap();

    // Additive: every earlier table keeps its rows; the new display tables are empty.
    assert_eq!(dump(&st), before);
    assert_eq!(display_rows(&st), (0, 0));
    // Ledger-origin receives and the spend, and the route-2 transaction, have work.
    let mut expected = vec![
        (TxId::from_bytes([1; 32]), RECEIVE),
        (TxId::from_bytes([2; 32]), RECEIVE),
        (TxId::from_bytes([3; 32]), SPEND),
        (mixed, MIXED),
    ];
    expected.sort();
    assert_eq!(work_rows(&st), expected);
}

#[test]
fn projection_receive_enqueues() {
    let (mut st, account, _) = active_wallet();
    let ws = watch(&st, account);
    let fresh = receive(5, external(&ws), 60_000, below_target(&ws, 0));
    let mut c = commit(&ws);
    c.receives = vec![fresh.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    assert_eq!(reasons(&st, txid_of(&fresh)), Some(RECEIVE));
    assert!(listing(&st).contains(&txid_of(&fresh)));
}

#[test]
fn projection_spend_enqueues() {
    let (mut st, account, unspent) = active_wallet();
    let ws = watch(&st, account);
    let payment = spend(6, &unspent, below_target(&ws, 1));
    let mut c = commit(&ws);
    c.spends = vec![payment.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    assert_eq!(reasons(&st, payment.spending_txid), Some(SPEND));
}

#[test]
fn projection_promotion_enqueues() {
    let (mut st, account, unspent, spent) = ready_wallet();
    // Candidate recovery queued nothing.
    assert_eq!(work_rows(&st), vec![]);
    promote(&mut st, account).unwrap();
    assert_eq!(
        work_rows(&st),
        vec![
            (txid_of(&unspent), RECEIVE),
            (txid_of(&spent), RECEIVE),
            (TxId::from_bytes([3; 32]), SPEND),
        ]
    );
}

#[test]
fn candidate_commit_no_enqueue() {
    let (mut st, accounts) = shadow_wallet_with(0);
    recover_one(&mut st, accounts[0], revision(1, true), 1);
    assert_eq!(count(&st, "tpir_receive_events"), 1);
    assert_eq!(work_rows(&st), vec![]);
}

#[test]
fn raw_present_no_enqueue() {
    let (mut st, account, taddr, txid, output_index) = local_payment_to_self();
    let fixture = revision(1, true);
    let ws = watch(&st, account);
    let recovered = ReceiveEvent {
        metadata: None,
        outpoint: OutPoint::new(*txid.as_ref(), output_index),
        address: taddr,
        value: Zatoshis::const_from_u64(50_000),
        coinbase: false,
        mined_height: below_target(&ws, 0),
    };
    cover(&mut st, account, &fixture, vec![recovered.clone()]);
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();
    assert_eq!(
        super::super::super::output_origins(conn(&st), &recovered.outpoint),
        vec![1, 2]
    );
    assert_eq!(reasons(&st, txid), None);
}

#[cfg(feature = "orchard")]
#[test]
fn route2_and_transition_enqueue() {
    let (mut st, _, unspent) = active_wallet();
    // Enhance PIR marks a projected receive's transaction as mixed: reasons accumulate.
    let tx = tx_ref(&st, txid_of(&unspent));
    crate::wallet::enhance_pir::route_transparent_details(conn(&st), None, tx).unwrap();
    assert_eq!(reasons(&st, txid_of(&unspent)), Some(RECEIVE | MIXED));

    // A route-1 transaction becomes route 2 when PrivateRequired is applied.
    set_policy(&mut st, PrivateShadow);
    let mixed = TxId::from_bytes([0x55; 32]);
    let height = u32::from(unspent.mined_height);
    conn(&st)
        .execute(
            "INSERT INTO transactions (txid, mined_height, min_observed_height)
             VALUES (?1, ?2, ?2)",
            rusqlite::params![mixed.as_ref(), height],
        )
        .unwrap();
    crate::wallet::enhance_pir::require_lwd_for_test(conn(&st), tx_ref(&st, mixed)).unwrap();
    assert_eq!(reasons(&st, mixed), None);
    set_policy(&mut st, PrivateRequired);
    assert_eq!(reasons(&st, mixed), Some(MIXED));
    assert!(listing(&st).contains(&mixed));
}

#[test]
fn public_lanes_no_enqueue() {
    let (st, _, outpoint) = super::super::super::funded_wallet();
    assert!(!super::super::super::output_origins(conn(&st), &outpoint).is_empty());
    assert_eq!(work_rows(&st), vec![]);
}

#[test]
fn parent_transactions_not_enqueued() {
    let (mut st, account, _) = active_wallet();
    // A parent of a projected spend, queued for retrieval, height unknown.
    let parent = TxId::from_bytes([0x11; 32]);
    conn(&st)
        .execute(
            "INSERT INTO transactions (txid, min_observed_height) VALUES (?1, 1)",
            [parent.as_ref()],
        )
        .unwrap();
    let dependent = tx_ref(&st, TxId::from_bytes([3; 32]));
    let tx = conn(&st).unchecked_transaction().unwrap();
    crate::wallet::queue_tx_retrieval(&tx, std::iter::once(parent), Some(dependent)).unwrap();
    tx.commit().unwrap();
    // Further projection still queues only the transactions it records.
    let ws = watch(&st, account);
    let mut c = commit(&ws);
    c.receives = vec![receive(5, external(&ws), 60_000, below_target(&ws, 0))];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    assert_eq!(reasons(&st, parent), None);
    assert!(!listing(&st).contains(&parent));
}

#[test]
fn listing_requires_mined_height() {
    let (st, _, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    assert!(listing(&st).contains(&txid));
    conn(&st)
        .execute(
            "UPDATE transactions SET mined_height = NULL, block = NULL WHERE txid = ?1",
            [txid.as_ref()],
        )
        .unwrap();
    assert!(!listing(&st).contains(&txid));
    // The work remains for when it is mined again.
    assert_eq!(reasons(&st, txid), Some(RECEIVE));
}

#[test]
fn rewind_remine_resets_backoff() {
    let (mut st, account, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    for _ in 0..3 {
        defer(&mut st, txid, unavailable(), now());
    }
    assert_eq!(attempts(&st, txid), 3);
    assert!(!listing(&st).contains(&txid));

    // Rewound: unmined, so not listed.
    let floor = unspent.mined_height - 2;
    st.truncate_to_height(floor);
    assert!(!listing_at(&st, later(7 * 24 * 3600), None).contains(&txid));

    // Mined again at another height: due at once, with a fresh backoff.
    scan_new_blocks(&mut st, 4);
    let remined = ReceiveEvent {
        mined_height: floor + 3,
        ..unspent.clone()
    };
    cover(&mut st, account, &revision(1, true), vec![remined]);
    assert!(listing(&st).contains(&txid));
    defer(&mut st, txid, unavailable(), now());
    assert_eq!(attempts(&st, txid), 1);
    assert!(!listing(&st).contains(&txid));
}

#[test]
fn priority_and_backoff_order() {
    let (mut st, _, unspent) = active_wallet();
    let unspent = txid_of(&unspent);
    let spent = TxId::from_bytes([2; 32]);
    let spending = TxId::from_bytes([3; 32]);
    // Never-attempted work, most recently mined first.
    assert_eq!(listing(&st), vec![spending, unspent, spent]);
    assert_eq!(
        st.wallet()
            .db()
            .transparent_detail_work(now(), 2, None)
            .unwrap()
            .len(),
        2
    );

    // A failed lookup waits out its backoff, then follows never-attempted work.
    defer(&mut st, spending, unavailable(), now());
    assert_eq!(listing(&st), vec![unspent, spent]);
    assert_eq!(
        listing_at(&st, later(3600), None),
        vec![unspent, spent, spending]
    );

    // Backoff schedule.
    let secs = |outcome, attempts| backoff(outcome, attempts, &spending).as_secs();
    assert!((30..=38).contains(&secs(unavailable(), 1)));
    assert!((60..=75).contains(&secs(unavailable(), 2)));
    assert_eq!(secs(unavailable(), 20), 3600);
    assert_eq!(
        secs(
            TransparentDetailOutcome::Unavailable {
                retry_after: Some(Duration::from_secs(600)),
            },
            1
        ),
        600
    );
    assert_eq!(
        secs(
            TransparentDetailOutcome::Unavailable {
                retry_after: Some(Duration::from_secs(7200)),
            },
            1
        ),
        3600
    );
    assert_eq!(
        secs(TransparentDetailOutcome::Protocol, 20),
        secs(unavailable(), 20)
    );
    assert!((3600..=4500).contains(&secs(TransparentDetailOutcome::Absent, 1)));
    assert_eq!(secs(TransparentDetailOutcome::Absent, 10), 24 * 3600);
    for held in [
        TransparentDetailOutcome::NotCovered,
        TransparentDetailOutcome::Unsupported,
        TransparentDetailOutcome::Contradiction,
    ] {
        assert!((24 * 3600..=30 * 3600).contains(&secs(held, 1)));
    }
    // Jitter spreads rows apart.
    assert_ne!(
        backoff(TransparentDetailOutcome::Absent, 1, &spending),
        backoff(TransparentDetailOutcome::Absent, 1, &unspent)
    );
}

#[test]
fn public_listing_excludes_payload_owned() {
    let (mut st, _, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    conn(&st)
        .execute(
            "INSERT INTO tx_retrieval_queue (txid, query_type, policy_generation)
             VALUES (?1, ?2, 0)",
            rusqlite::params![txid.as_ref(), TxQueryType::Enhancement.code()],
        )
        .unwrap();
    // Without public authority, payload work cannot be dispatched: display work proceeds.
    assert!(listing(&st).contains(&txid));
    set_policy(&mut st, Public);
    let listed = listing(&st);
    assert!(!listed.contains(&txid));
    assert!(listed.contains(&TxId::from_bytes([2; 32])));
}

#[test]
fn not_covered_rearmed_on_map_change() {
    let (mut st, _, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    defer(&mut st, txid, TransparentDetailOutcome::NotCovered, now());
    let day = 24 * 3600;
    // Held under the same map, or without one, however long it waits.
    assert!(!listing_at(&st, later(30 * day), Some(MAP_A)).contains(&txid));
    assert!(!listing_at(&st, later(30 * day), None).contains(&txid));
    // A new map re-arms it, but not within a day.
    assert!(!listing_at(&st, later(3600), Some(MAP_B)).contains(&txid));
    assert!(listing_at(&st, later(2 * day), Some(MAP_B)).contains(&txid));
    assert_eq!(
        view(&st, unspent_account(&st), txid),
        Some(TransparentDisplayView::NotCovered)
    );
}

fn unspent_account(st: &State) -> AccountUuid {
    st.test_account().unwrap().id()
}

#[test]
fn store_valid_resolves_work() {
    let (mut st, account, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    let facts = facts_for(&unspent);
    assert_eq!(
        store(&mut st, facts.clone()),
        TransparentDisplayStore::Stored
    );
    assert_eq!(reasons(&st, txid), None);
    assert!(!listing(&st).contains(&txid));
    assert_eq!(display_rows(&st), (1, 2));
    let Some(TransparentDisplayView::Available(details)) = view(&st, account, txid) else {
        panic!("expected available details");
    };
    assert_eq!(
        details.source,
        TransparentDisplaySource::Display(facts.provenance.clone())
    );
    assert_eq!(details.fee, facts.metadata.fee);
    assert_eq!(details.input_count, 1);
    assert!(!details.coinbase && !details.shielded);
    let owned: Vec<_> = details.outputs.iter().map(|o| o.owned).collect();
    assert_eq!(owned, vec![true, false]);
    assert_eq!(details.outputs[0].address, Some(unspent.address));
    assert_eq!(details.outputs[1].address, None);
    assert_eq!(details.outputs[0].value, unspent.value);
}

/// Stores facts that contradict the wallet, checking that nothing is saved and the work is held.
fn contradicted(
    st: &mut State,
    facts: TransparentDisplayFacts,
    expected: TransparentDisplayContradiction,
) {
    let txid = facts.txid;
    assert!(reasons(st, txid).is_some());
    assert_eq!(
        store(st, facts),
        TransparentDisplayStore::Contradiction(expected)
    );
    assert_eq!(display_rows(st), (0, 0));
    assert!(reasons(st, txid).is_some());
    assert!(!listing_at(st, later(30 * 24 * 3600), Some(MAP_A)).contains(&txid));
    assert!(listing_at(st, later(30 * 24 * 3600), Some(MAP_B)).contains(&txid));
}

#[test]
fn contradiction_coinbase() {
    let (mut st, _, unspent) = active_wallet();
    let mut facts = facts_for(&unspent);
    facts.coinbase = true;
    facts.metadata = TransactionMetadata {
        fee: WholeTransactionFee::NotApplicable,
        transparent_input_count: 0,
        has_shielded_components: false,
    };
    contradicted(&mut st, facts, TransparentDisplayContradiction::Coinbase);
    // Metadata invalid for the flag is also a coinbase contradiction.
    let mut facts = facts_for(&unspent);
    facts.metadata.fee = WholeTransactionFee::NotApplicable;
    contradicted(&mut st, facts, TransparentDisplayContradiction::Coinbase);
}

#[test]
fn contradiction_owned_output() {
    let (mut st, _, unspent) = active_wallet();
    let mut facts = facts_for(&unspent);
    facts.outputs[0].value = Zatoshis::const_from_u64(40_001);
    contradicted(
        &mut st,
        facts,
        TransparentDisplayContradiction::OwnedOutput { index: 0 },
    );
    let mut facts = facts_for(&unspent);
    facts.outputs[0].script = vec![0x51];
    contradicted(
        &mut st,
        facts,
        TransparentDisplayContradiction::OwnedOutput { index: 0 },
    );
}

#[test]
fn contradiction_index_oob() {
    let (mut st, _, unspent) = active_wallet();
    let mut facts = facts_for(&unspent);
    facts.outputs.clear();
    contradicted(
        &mut st,
        facts,
        TransparentDisplayContradiction::OutputIndexOutOfRange { index: 0 },
    );
}

#[test]
fn contradiction_metadata() {
    let (mut st, account, _) = active_wallet();
    let ws = watch(&st, account);
    let recovered = TransactionMetadata {
        fee: WholeTransactionFee::Exact(Zatoshis::const_from_u64(1_000)),
        transparent_input_count: 2,
        has_shielded_components: false,
    };
    let fresh = ReceiveEvent {
        metadata: Some(recovered),
        ..receive(5, external(&ws), 60_000, below_target(&ws, 0))
    };
    let mut c = commit(&ws);
    c.receives = vec![fresh.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    let mut facts = facts_for(&fresh);
    facts.metadata = recovered;
    facts.metadata.transparent_input_count = 1;
    contradicted(&mut st, facts, TransparentDisplayContradiction::Metadata);
    let mut facts = facts_for(&fresh);
    facts.metadata = recovered;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
}

#[test]
fn contradiction_fee() {
    let (mut st, _, unspent) = active_wallet();
    conn(&st)
        .execute(
            "UPDATE transactions SET fee = 500 WHERE txid = ?1",
            [txid_of(&unspent).as_ref()],
        )
        .unwrap();
    contradicted(
        &mut st,
        facts_for(&unspent),
        TransparentDisplayContradiction::Fee,
    );
    // An unknown published fee asserts nothing.
    let mut facts = facts_for(&unspent);
    facts.metadata.fee = WholeTransactionFee::Unknown;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
}

#[test]
fn contradiction_shielded() {
    let (mut st, _, unspent) = active_wallet();
    conn(&st)
        .execute(
            "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (?1, 2)",
            [tx_ref(&st, txid_of(&unspent)).0],
        )
        .unwrap();
    contradicted(
        &mut st,
        facts_for(&unspent),
        TransparentDisplayContradiction::Shielded,
    );
    let mut facts = facts_for(&unspent);
    facts.metadata.has_shielded_components = true;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
}

#[test]
fn contradiction_input_index() {
    let (mut st, _, unspent) = active_wallet();
    // The projected spend consumes its output at input 0.
    let mut facts = facts_for(&unspent);
    facts.txid = TxId::from_bytes([3; 32]);
    facts.outputs = vec![];
    facts.metadata.transparent_input_count = 0;
    contradicted(
        &mut st,
        facts.clone(),
        TransparentDisplayContradiction::InputIndex { index: 0 },
    );
    facts.metadata.transparent_input_count = 1;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
}

#[test]
fn raw_present_superseded() {
    let (mut st, _, taddr, txid, output_index) = local_payment_to_self();
    let facts = facts_for(&ReceiveEvent {
        metadata: None,
        outpoint: OutPoint::new(*txid.as_ref(), output_index),
        address: taddr,
        value: Zatoshis::const_from_u64(50_000),
        coinbase: false,
        mined_height: BlockHeight::from_u32(1),
    });
    assert_eq!(
        store(&mut st, facts.clone()),
        TransparentDisplayStore::Superseded
    );
    assert_eq!(display_rows(&st), (0, 0));
    // A transaction the wallet does not hold is also superseded.
    let mut unknown = facts;
    unknown.txid = TxId::from_bytes([0x77; 32]);
    assert_eq!(store(&mut st, unknown), TransparentDisplayStore::Superseded);
}

#[test]
fn stale_generation_rejected() {
    let (mut st, _, unspent) = active_wallet();
    let stale = generation(&st) + 1;
    let result =
        st.wallet_mut()
            .db_mut()
            .store_transparent_display(facts_for(&unspent), stale, now());
    assert!(matches!(
        result,
        Err(SqliteClientError::StaleTransparentPolicy { .. })
    ));
    assert_eq!(display_rows(&st), (0, 0));
    assert_eq!(reasons(&st, txid_of(&unspent)), Some(RECEIVE));
}

#[test]
fn contradiction_and_store_leave_balances_history_unchanged() {
    let (mut st, account, unspent) = active_wallet();
    let txids: Vec<TxId> = work_rows(&st).into_iter().map(|(t, _)| t).collect();
    let state = |st: &State| {
        let db = st.wallet().db();
        (
            db.transparent_ledger_snapshot(account, ConfirmationsPolicy::MIN)
                .unwrap(),
            db.transaction_history_details(account, &txids).unwrap(),
            db.transaction_history_summaries(account).unwrap(),
            format!(
                "{:?}",
                db.get_wallet_summary(ConfirmationsPolicy::MIN).unwrap()
            ),
        )
    };
    let before = state(&st);
    let mut facts = facts_for(&unspent);
    facts.outputs[0].value = Zatoshis::const_from_u64(1);
    assert!(matches!(
        store(&mut st, facts),
        TransparentDisplayStore::Contradiction(_)
    ));
    assert_eq!(state(&st), before);
    assert_eq!(
        store(&mut st, facts_for(&unspent)),
        TransparentDisplayStore::Stored
    );
    assert_eq!(state(&st), before);
}

#[test]
fn put_tx_data_clears_work() {
    let (mut st, account, taddr, txid, output_index) = local_payment_to_self();
    let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
    // Recovered as if the wallet had only the ledger's evidence of it.
    conn(&st)
        .execute(
            "UPDATE transactions SET raw = NULL WHERE txid = ?1",
            [txid.as_ref()],
        )
        .unwrap();
    let fixture = revision(1, true);
    let ws = watch(&st, account);
    let recovered = ReceiveEvent {
        metadata: None,
        outpoint: OutPoint::new(*txid.as_ref(), output_index),
        address: taddr,
        value: Zatoshis::const_from_u64(50_000),
        coinbase: false,
        mined_height: below_target(&ws, 0),
    };
    cover(&mut st, account, &fixture, vec![recovered.clone()]);
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();
    assert_eq!(reasons(&st, txid), Some(RECEIVE));
    let mut facts = facts_for(&recovered);
    facts.metadata.has_shielded_components = true;
    facts.metadata.fee = WholeTransactionFee::Unknown;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    // A pending row too, so both are seen to clear.
    conn(&st)
        .execute(
            "INSERT INTO transparent_detail_work (transaction_id, reasons) VALUES (?1, 1)",
            [tx_ref(&st, txid).0],
        )
        .unwrap();

    crate::wallet::put_tx_data(conn(&st), &tx, None, None, None, recovered.mined_height).unwrap();
    assert_eq!(reasons(&st, txid), None);
    assert_eq!(display_rows(&st), (0, 0));
    let Some(TransparentDisplayView::Available(details)) = view(&st, account, txid) else {
        panic!("expected available details");
    };
    assert_eq!(details.source, TransparentDisplaySource::RawTransaction);
    assert!(details.shielded);
    assert!(details.outputs[output_index as usize].owned);
    assert_eq!(details.outputs[output_index as usize].address, Some(taddr));
}

#[test]
fn account_delete_cascades() {
    let (mut st, account, unspent) = active_wallet();
    assert_eq!(
        store(&mut st, facts_for(&unspent)),
        TransparentDisplayStore::Stored
    );
    assert!(!work_rows(&st).is_empty());
    st.wallet_mut().delete_account(account).unwrap();
    assert_eq!(work_rows(&st), vec![]);
    assert_eq!(display_rows(&st), (0, 0));
}

#[test]
fn view_state_matrix() {
    let (mut st, account, unspent) = active_wallet();
    let other = import_account(&mut st, 9);
    let txid = txid_of(&unspent);
    assert_eq!(view(&st, account, TxId::from_bytes([0x77; 32])), None);
    assert_eq!(
        view(&st, account, txid),
        Some(TransparentDisplayView::Pending)
    );
    defer(&mut st, txid, unavailable(), now());
    assert_eq!(
        view(&st, account, txid),
        Some(TransparentDisplayView::Unavailable)
    );
    defer(&mut st, txid, TransparentDetailOutcome::Absent, now());
    assert_eq!(
        view(&st, account, txid),
        Some(TransparentDisplayView::Unavailable)
    );
    defer(&mut st, txid, TransparentDetailOutcome::NotCovered, now());
    assert_eq!(
        view(&st, account, txid),
        Some(TransparentDisplayView::NotCovered)
    );
    // Reconciles once the service answers.
    assert_eq!(
        store(&mut st, facts_for(&unspent)),
        TransparentDisplayStore::Stored
    );
    let owned = |account| match view(&st, account, txid) {
        Some(TransparentDisplayView::Available(d)) => d.outputs[0].owned,
        other => panic!("expected available details, got {other:?}"),
    };
    assert!(owned(account));
    assert!(!owned(other));

    // Without work: pending while payload retrieval owns it, otherwise unavailable.
    let spent = TxId::from_bytes([2; 32]);
    conn(&st)
        .execute(
            "DELETE FROM transparent_detail_work WHERE transaction_id = ?1",
            [tx_ref(&st, spent).0],
        )
        .unwrap();
    conn(&st)
        .execute(
            "DELETE FROM tx_retrieval_queue WHERE txid = ?1",
            [spent.as_ref()],
        )
        .unwrap();
    assert_eq!(
        view(&st, account, spent),
        Some(TransparentDisplayView::Unavailable)
    );
    conn(&st)
        .execute(
            "INSERT INTO tx_retrieval_queue (txid, query_type) VALUES (?1, ?2)",
            rusqlite::params![spent.as_ref(), TxQueryType::Enhancement.code()],
        )
        .unwrap();
    assert_eq!(
        view(&st, account, spent),
        Some(TransparentDisplayView::Pending)
    );
}
