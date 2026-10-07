//! Transparent txid enhancement: work creation, listing, backoff, validation and the view.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zcash_client_backend::data_api::transparent_ledger::{
    TransactionMetadata, TransparentDetailOutcome, TransparentDetailParked,
    TransparentDetailRead as _, TransparentDetailReasons, TransparentDetailWrite as _,
    TransparentDisplayContradiction, TransparentDisplayFacts, TransparentDisplayOutput,
    TransparentDisplayProvenance, TransparentDisplaySource, TransparentDisplayStore,
    TransparentDisplayView, WholeTransactionFee,
};

use super::*;
use crate::{
    TxRef,
    wallet::{
        TxQueryType,
        transparent_ledger::details::{self, PARKED_BACKSTOP, backoff},
    },
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
        .requests
        .into_iter()
        .map(|r| r.txid)
        .collect()
}

fn listing(st: &State) -> Vec<TxId> {
    listing_at(st, now(), None)
}

fn mined_height(st: &State, txid: TxId) -> BlockHeight {
    let height = conn(st)
        .query_row(
            "SELECT mined_height FROM transactions WHERE txid = ?1",
            [txid.as_ref()],
            |row| row.get::<_, u32>(0),
        )
        .unwrap();
    BlockHeight::from(height)
}

fn defer(st: &mut State, txid: TxId, outcome: TransparentDetailOutcome, at: SystemTime) {
    let height = mined_height(st, txid);
    st.wallet_mut()
        .db_mut()
        .defer_transparent_detail(txid, height, outcome, Some(MAP_A), at)
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
    // Route-2 transactions that are skipped: one with raw bytes, and a parent (height unknown).
    let with_raw = TxId::from_bytes([0x67; 32]);
    let parent = TxId::from_bytes([0x68; 32]);
    conn(&st)
        .execute(
            "INSERT INTO transactions (txid, mined_height, min_observed_height, raw)
             VALUES (?1, ?2, ?2, x'00')",
            rusqlite::params![with_raw.as_ref(), height],
        )
        .unwrap();
    conn(&st)
        .execute(
            "INSERT INTO transactions (txid, min_observed_height) VALUES (?1, ?2)",
            rusqlite::params![parent.as_ref(), height],
        )
        .unwrap();
    for txid in [mixed, with_raw, parent] {
        conn(&st)
            .execute(
                "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (?1, 2)",
                [tx_ref(&st, txid).0],
            )
            .unwrap();
    }
    // The wallet as it was before the migration.
    crate::wallet::init::migrations::forget_txid_enhancement(conn(&st));
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
    let (mut st, _, unspent) = active_wallet();
    // A parent of a projected spend, queued for retrieval, height unknown; and a mined control
    // transaction driven through the same sites.
    let parent = TxId::from_bytes([0x11; 32]);
    let control = TxId::from_bytes([0x12; 32]);
    let height = u32::from(unspent.mined_height);
    conn(&st)
        .execute(
            "INSERT INTO transactions (txid, min_observed_height) VALUES (?1, 1)",
            [parent.as_ref()],
        )
        .unwrap();
    conn(&st)
        .execute(
            "INSERT INTO transactions (txid, mined_height, min_observed_height)
             VALUES (?1, ?2, ?2)",
            rusqlite::params![control.as_ref(), height],
        )
        .unwrap();
    let dependent = tx_ref(&st, TxId::from_bytes([3; 32]));
    let tx = conn(&st).unchecked_transaction().unwrap();
    crate::wallet::queue_tx_retrieval(&tx, std::iter::once(parent), Some(dependent)).unwrap();
    tx.commit().unwrap();

    // Every enqueue site: projection by txid (receive) and by row (spend), and route 2.
    let sites = |st: &State, txid: TxId| {
        let tx = tx_ref(st, txid);
        details::enqueue_txid(conn(st), &txid, TransparentDetailReasons::RECEIVE).unwrap();
        details::enqueue_tx(conn(st), tx, TransparentDetailReasons::SPEND).unwrap();
        conn(st)
            .execute(
                "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (?1, 2)",
                [tx.0],
            )
            .unwrap();
        details::enqueue_route_two(conn(st)).unwrap();
    };
    sites(&st, parent);
    sites(&st, control);
    assert_eq!(reasons(&st, parent), None);
    assert_eq!(reasons(&st, control), Some(RECEIVE | SPEND | MIXED));
    assert!(!listing(&st).contains(&parent));
    assert!(listing(&st).contains(&control));

    // And the migration backfill.
    conn(&st)
        .execute_batch("DELETE FROM transparent_detail_work")
        .unwrap();
    crate::wallet::init::migrations::forget_txid_enhancement(conn(&st));
    crate::wallet::init::WalletMigrator::new()
        .init_or_migrate(st.wallet_mut().db_mut())
        .unwrap();
    assert_eq!(reasons(&st, parent), None);
    assert_eq!(reasons(&st, control), Some(MIXED));
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
fn stale_detail_failure_after_remine_preserves_immediate_retry() {
    let (mut st, account, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    defer(&mut st, txid, unavailable(), now());
    let before = production_dump(conn(&st));
    let work_before = before
        .iter()
        .find(|(table, _)| table == "transparent_detail_work")
        .unwrap()
        .clone();

    let floor = unspent.mined_height - 2;
    st.truncate_to_height(floor);
    scan_new_blocks(&mut st, 4);
    let remined = ReceiveEvent {
        mined_height: floor + 3,
        ..unspent.clone()
    };
    cover(&mut st, account, &revision(1, true), vec![remined]);
    assert!(listing(&st).contains(&txid));

    // The lookup started at the original height and finished after re-mining.
    st.wallet_mut()
        .db_mut()
        .defer_transparent_detail(
            txid,
            unspent.mined_height,
            TransparentDetailOutcome::NotCovered,
            Some(MAP_A),
            now(),
        )
        .unwrap();
    let after = production_dump(conn(&st));
    assert_eq!(
        after
            .iter()
            .find(|(table, _)| table == "transparent_detail_work")
            .unwrap(),
        &work_before
    );
    assert!(listing(&st).contains(&txid));

    // Validation may also discover a contradiction after the placement changes.
    let mut stale_facts = facts_for(&unspent);
    stale_facts.coinbase = true;
    assert!(matches!(
        store(&mut st, stale_facts),
        TransparentDisplayStore::Contradiction(_)
    ));
    assert_eq!(production_dump(conn(&st)), after);
    assert!(listing(&st).contains(&txid));

    // A failure for the current placement still starts a fresh backoff.
    defer(&mut st, txid, unavailable(), now());
    assert_eq!(attempts(&st, txid), 1);
    assert!(!listing(&st).contains(&txid));
}

#[test]
fn stale_detail_failure_while_unmined_changes_nothing() {
    let (mut st, _, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    defer(&mut st, txid, unavailable(), now());
    st.truncate_to_height(unspent.mined_height - 2);
    let before = production_dump(conn(&st));
    st.wallet_mut()
        .db_mut()
        .defer_transparent_detail(
            txid,
            unspent.mined_height,
            TransparentDetailOutcome::NotCovered,
            Some(MAP_A),
            now(),
        )
        .unwrap();
    assert_eq!(production_dump(conn(&st)), before);
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
            .requests
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
        7200
    );
    // A transaction newer than the publication is retried within minutes.
    let not_yet = TransparentDetailOutcome::NotYetPublished;
    assert!((60..=75).contains(&secs(not_yet, 1)));
    assert_eq!(secs(not_yet, 20), 300);
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
    // A privately protected Ironwood transaction is never fetched publicly.
    let protected = TxId::from_bytes([2; 32]);
    conn(&st)
        .execute(
            "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (?1, 0)",
            [tx_ref(&st, protected).0],
        )
        .unwrap();
    // Without public authority, payload work cannot be dispatched: display work proceeds.
    assert!(listing(&st).contains(&txid));
    assert!(listing(&st).contains(&protected));
    set_policy(&mut st, Public);
    let listed = listing(&st);
    assert!(!listed.contains(&txid));
    assert!(!listed.contains(&protected));
    assert!(listed.contains(&TxId::from_bytes([3; 32])));
}

#[test]
fn not_covered_rearmed_on_map_change() {
    let (mut st, _, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    defer(&mut st, txid, TransparentDetailOutcome::NotCovered, now());
    let day = 24 * 3600;
    // Held under the same map, or without one, until the backstop.
    assert!(!listing_at(&st, later(6 * day), Some(MAP_A)).contains(&txid));
    assert!(!listing_at(&st, later(6 * day), None).contains(&txid));
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
    assert!(!listing_at(st, later(6 * 24 * 3600), Some(MAP_A)).contains(&txid));
    assert!(listing_at(st, later(6 * 24 * 3600), Some(MAP_B)).contains(&txid));
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
    facts.provenance.looked_up_height = mined_height(&st, facts.txid);
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
    // A lookup dispatched under the listing's snapshot, completing after a policy switch.
    let listed = st
        .wallet()
        .db()
        .transparent_detail_work(now(), 10, None)
        .unwrap();
    assert_eq!(listed.policy_generation, generation(&st));
    set_policy(&mut st, PrivateShadow);
    assert_ne!(generation(&st), listed.policy_generation);
    let result = st.wallet_mut().db_mut().store_transparent_display(
        facts_for(&unspent),
        listed.policy_generation,
        now(),
    );
    assert!(matches!(
        result,
        Err(SqliteClientError::StaleTransparentPolicy { .. })
    ));
    assert_eq!(display_rows(&st), (0, 0));
    assert_eq!(reasons(&st, txid_of(&unspent)), Some(RECEIVE));
}

#[test]
fn listing_reports_policy_snapshot() {
    let (mut st, _, _) = active_wallet();
    let work = |st: &State| {
        st.wallet()
            .db()
            .transparent_detail_work(now(), 10, None)
            .unwrap()
    };
    let private = work(&st);
    assert_eq!(private.mode, PrivateRequired);
    assert_eq!(private.policy_generation, generation(&st));
    assert!(!private.public_transport());
    assert!(!private.requests.is_empty());
    set_policy(&mut st, Public);
    let public = work(&st);
    assert_eq!(public.mode, Public);
    assert_eq!(public.policy_generation, generation(&st));
    assert!(public.policy_generation > private.policy_generation);
    assert!(public.public_transport());
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
    let owned = |st: &State, account| match view(st, account, txid) {
        Some(TransparentDisplayView::Available(d)) => d.outputs[0].owned,
        other => panic!("expected available details, got {other:?}"),
    };
    assert!(owned(&st, account));
    // Another account does not own it. (Importing one unplaces the ledger's receives until
    // they are recovered again; balances exclude the output meanwhile, and so does the view.)
    let other = import_account(&mut st, 9);
    assert!(!owned(&st, other));

    // Without work: pending while public payload retrieval owns it, otherwise unavailable.
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
    // Under PrivateRequired payload retrieval cannot run publicly: unavailable, not pending.
    assert_eq!(
        view(&st, account, spent),
        Some(TransparentDisplayView::Unavailable)
    );
    set_policy(&mut st, Public);
    assert_eq!(
        view(&st, account, spent),
        Some(TransparentDisplayView::Pending)
    );
}

const DAY: u64 = 24 * 3600;

fn parked(st: &State, at: SystemTime) -> TransparentDetailParked {
    st.wallet().db().transparent_detail_parked(at).unwrap()
}

#[test]
fn unsupported_parked_until_any_map() {
    let (mut st, _, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    // The service had no display map to offer.
    st.wallet_mut()
        .db_mut()
        .defer_transparent_detail(
            txid,
            unspent.mined_height,
            TransparentDetailOutcome::Unsupported,
            None,
            now(),
        )
        .unwrap();
    assert!(!listing_at(&st, later(2 * DAY), None).contains(&txid));
    assert_eq!(
        parked(&st, later(2 * DAY)),
        TransparentDetailParked {
            count: 1,
            oldest_map_sha256: None
        }
    );
    // The first map ever seen re-arms it, but not within the minimum wait.
    assert!(!listing_at(&st, later(3600), Some(MAP_A)).contains(&txid));
    assert!(listing_at(&st, later(2 * DAY), Some(MAP_A)).contains(&txid));
    // Any map re-arms it, including the one it was deferred under.
    defer(&mut st, txid, TransparentDetailOutcome::Unsupported, now());
    assert!(listing_at(&st, later(2 * DAY), Some(MAP_A)).contains(&txid));
    assert!(!listing_at(&st, later(2 * DAY), None).contains(&txid));
}

#[test]
fn parked_without_map_reported_and_backstop_rearms() {
    let (mut st, _, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    defer(&mut st, txid, TransparentDetailOutcome::NotCovered, now());
    let contradicted = TxId::from_bytes([2; 32]);
    defer(
        &mut st,
        contradicted,
        TransparentDetailOutcome::Contradiction,
        later(60),
    );
    // Within the minimum wait nothing is parked: a map refresh could not help yet.
    assert_eq!(parked(&st, later(3600)).count, 0);
    // Then both wait only for a map change, and the caller is told so.
    let at = later(2 * DAY);
    assert!(!listing_at(&st, at, None).contains(&txid));
    assert_eq!(
        parked(&st, at),
        TransparentDetailParked {
            count: 2,
            oldest_map_sha256: Some(MAP_A)
        }
    );
    // Without any map change, the backstop makes them due again.
    let backstop = later(PARKED_BACKSTOP.as_secs() + 60);
    let listed = listing_at(&st, backstop, None);
    assert!(listed.contains(&txid) && listed.contains(&contradicted));
    assert_eq!(parked(&st, backstop).count, 0);
}

#[test]
fn not_yet_published_short_backoff_pending() {
    let (mut st, account, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    defer(
        &mut st,
        txid,
        TransparentDetailOutcome::NotYetPublished,
        now(),
    );
    assert_eq!(
        view(&st, account, txid),
        Some(TransparentDisplayView::Pending)
    );
    assert!(!listing_at(&st, later(30), None).contains(&txid));
    assert!(listing_at(&st, later(80), None).contains(&txid));
    assert_eq!(parked(&st, later(80)).count, 0);
    // Repeated, it stays within five minutes.
    for _ in 0..10 {
        defer(
            &mut st,
            txid,
            TransparentDetailOutcome::NotYetPublished,
            now(),
        );
    }
    assert!(listing_at(&st, later(300), None).contains(&txid));
}

#[test]
fn no_requeue_after_stored() {
    let (mut st, account, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    assert_eq!(
        store(&mut st, facts_for(&unspent)),
        TransparentDisplayStore::Stored
    );
    assert_eq!(reasons(&st, txid), None);
    // The receive is reported again by the active ledger.
    cover(&mut st, account, &revision(1, true), vec![unspent.clone()]);
    assert_eq!(reasons(&st, txid), None);
    // Leaving and re-entering PrivateRequired promotes, and so projects, the ledger again.
    set_policy(&mut st, PrivateShadow);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();
    assert_eq!(reasons(&st, txid), None);
    assert!(!listing(&st).contains(&txid));
    // Transactions without facts are still wanted.
    assert_eq!(reasons(&st, TxId::from_bytes([2; 32])), Some(RECEIVE));
    assert!(matches!(
        view(&st, account, txid),
        Some(TransparentDisplayView::Available(_))
    ));
}

#[test]
fn withdrawn_receive_not_owned_and_not_related() {
    let (mut st, account, _) = active_wallet();
    let provisional = revision(2, false);
    qualify(&mut st, &provisional);
    let ws = watch(&st, account);
    let fresh = receive(5, external(&ws), 60_000, below_target(&ws, 0));
    let mut c = commit(&ws);
    c.revision = provisional;
    c.receives = vec![fresh.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    let txid = txid_of(&fresh);
    assert!(listing(&st).contains(&txid));

    // A higher provisional lineage replaces it and does not report the receive.
    let replacement = revision(3, false);
    qualify(&mut st, &replacement);
    let ws = watch(&st, account);
    let mut c = commit(&ws);
    c.revision = replacement;
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    // The output row stays for its history, but the wallet no longer relates to the
    // transaction: not listed, not parked.
    assert_eq!(count_outputs(&st, txid), 1);
    assert!(!listing(&st).contains(&txid));
    assert!(!listing_at(&st, later(2 * DAY), Some(MAP_B)).contains(&txid));
    assert!(!listing_at(&st, later(30 * DAY), None).contains(&txid));

    // The withdrawn output neither constrains in-flight facts nor shows as owned.
    let mut facts = facts_for(&fresh);
    facts.outputs[fresh.outpoint.n() as usize].value = Zatoshis::const_from_u64(1);
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    let Some(TransparentDisplayView::Available(details)) = view(&st, account, txid) else {
        panic!("expected available details");
    };
    assert!(details.outputs.iter().all(|o| !o.owned));
}

fn count_outputs(st: &State, txid: TxId) -> i64 {
    conn(st)
        .query_row(
            "SELECT COUNT(*) FROM transparent_received_outputs o
             JOIN transactions t ON t.id_tx = o.transaction_id WHERE t.txid = ?1",
            [txid.as_ref()],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn contradiction_public_spend_links() {
    let (mut st, _, unspent) = active_wallet();
    // A mined transaction without raw bytes that public discovery linked to two spent
    // outpoints: the unspent output, and one known only through the spend map.
    let spender = TxId::from_bytes([0x44; 32]);
    let height = u32::from(unspent.mined_height) + 1;
    conn(&st)
        .execute(
            "INSERT INTO transactions (txid, mined_height, min_observed_height)
             VALUES (?1, ?2, ?2)",
            rusqlite::params![spender.as_ref(), height],
        )
        .unwrap();
    let tx = tx_ref(&st, spender);
    conn(&st)
        .execute(
            "INSERT INTO transparent_received_output_spends (transparent_received_output_id,
                                                             transaction_id)
             SELECT o.id, ?1 FROM transparent_received_outputs o
             JOIN transactions t ON t.id_tx = o.transaction_id
             WHERE t.txid = ?2 AND o.output_index = ?3",
            rusqlite::params![tx.0, txid_of(&unspent).as_ref(), unspent.outpoint.n()],
        )
        .unwrap();
    conn(&st)
        .execute(
            "INSERT INTO transparent_spend_map
             (spending_transaction_id, prevout_txid, prevout_output_index)
             VALUES (?1, ?2, 0)",
            rusqlite::params![tx.0, [0x45u8; 32].as_slice()],
        )
        .unwrap();
    details::enqueue_tx(conn(&st), tx, TransparentDetailReasons::SPEND).unwrap();

    let mut facts = facts_for(&unspent);
    facts.txid = spender;
    facts.provenance.looked_up_height = BlockHeight::from(height);
    facts.outputs = vec![];
    facts.metadata.transparent_input_count = 1;
    contradicted(
        &mut st,
        facts.clone(),
        TransparentDisplayContradiction::InputCount { known: 2 },
    );
    let mut coinbase = facts.clone();
    coinbase.coinbase = true;
    coinbase.metadata = TransactionMetadata {
        fee: WholeTransactionFee::NotApplicable,
        transparent_input_count: 0,
        has_shielded_components: false,
    };
    contradicted(&mut st, coinbase, TransparentDisplayContradiction::Coinbase);
    facts.metadata.transparent_input_count = 2;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
}

#[test]
fn store_requires_work_or_relation() {
    let (mut st, _, unspent) = active_wallet();
    // Mined, without raw bytes, but neither wanted nor related.
    let stranger = TxId::from_bytes([0x46; 32]);
    conn(&st)
        .execute(
            "INSERT INTO transactions (txid, mined_height, min_observed_height)
             VALUES (?1, ?2, ?2)",
            rusqlite::params![stranger.as_ref(), u32::from(unspent.mined_height)],
        )
        .unwrap();
    let mut facts = facts_for(&unspent);
    facts.txid = stranger;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Superseded);
    assert_eq!(display_rows(&st), (0, 0));
    // A related transaction whose work row is gone still takes facts.
    conn(&st)
        .execute(
            "DELETE FROM transparent_detail_work WHERE transaction_id = ?1",
            [tx_ref(&st, txid_of(&unspent)).0],
        )
        .unwrap();
    assert_eq!(
        store(&mut st, facts_for(&unspent)),
        TransparentDisplayStore::Stored
    );
}
