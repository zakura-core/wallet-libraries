//! Transparent txid enhancement: work creation, listing, backoff, validation and the view.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zcash_client_backend::data_api::transparent_ledger::{
    TRANSPARENT_DISPLAY_MAP_RECHECK, TransactionMetadata, TransparentDetailOutcome,
    TransparentDetailParked, TransparentDetailRead as _, TransparentDetailReasons,
    TransparentDetailWrite as _, TransparentDisplayContradiction, TransparentDisplayDetails,
    TransparentDisplayFacts, TransparentDisplayOmission, TransparentDisplayOutput,
    TransparentDisplayProvenance, TransparentDisplaySender, TransparentDisplaySource,
    TransparentDisplayStore, TransparentDisplayView, TransparentDisplayViewSender,
    WholeTransactionFee, transparent_display_address,
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

/// An address of nobody in the wallet.
const FOREIGN: TransparentAddress = TransparentAddress::PublicKeyHash([0x99; 20]);

fn zat(value: u64) -> Zatoshis {
    Zatoshis::const_from_u64(value)
}

fn provenance(height: BlockHeight) -> TransparentDisplayProvenance {
    TransparentDisplayProvenance {
        shard_id: 3,
        revision: 1,
        map_sha256: MAP_A,
        looked_up_height: height,
    }
}

/// Facts agreeing with everything the wallet holds about `receive`'s transaction: one input
/// from [`FOREIGN`], and the receive at its index next to an `OP_RETURN` output.
fn facts_for(receive: &ReceiveEvent) -> TransparentDisplayFacts {
    let index = receive.outpoint.n();
    let output_count = index + 2;
    let outputs = (0..output_count.min(2))
        .map(|i| {
            if i == index {
                TransparentDisplayOutput {
                    value: receive.value,
                    address: Some(receive.address),
                }
            } else {
                TransparentDisplayOutput {
                    value: zat(1),
                    address: None,
                }
            }
        })
        .collect();
    TransparentDisplayFacts {
        txid: txid_of(receive),
        coinbase: false,
        fee: zat(1_000),
        input_count: 1,
        output_count,
        shielded_components: false,
        sender: TransparentDisplaySender::Address(FOREIGN),
        outputs,
        multiple_source_scripts: false,
        shielded_and_transparent_funding: false,
        provenance: provenance(receive.mined_height),
    }
}

/// The address transaction `spending` spends at `input`, by the wallet's recovered spend.
fn spent_address(st: &State, spending: TxId, input: u32) -> TransparentAddress {
    let script: Vec<u8> = conn(st)
        .query_row(
            "SELECT prevout_script FROM tpir_spend_events
             WHERE spending_txid = ?1 AND input_index = ?2",
            rusqlite::params![spending.as_ref(), input],
            |row| row.get(0),
        )
        .unwrap();
    transparent_display_address(&script).unwrap()
}

/// Facts for the fixture's spending transaction (`[3; 32]`, whose one input spends 25 000
/// zatoshis of the wallet's): a shielding transaction without transparent outputs.
fn spend_facts(st: &State) -> TransparentDisplayFacts {
    let txid = TxId::from_bytes([3; 32]);
    TransparentDisplayFacts {
        txid,
        coinbase: false,
        fee: zat(1_000),
        input_count: 1,
        output_count: 0,
        shielded_components: true,
        sender: TransparentDisplaySender::Address(spent_address(st, txid, 0)),
        outputs: vec![],
        multiple_source_scripts: false,
        shielded_and_transparent_funding: false,
        provenance: provenance(mined_height(st, txid)),
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
    let (mut st, accounts) = recovery_wallet_with(0);
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
    set_policy(&mut st, Public);
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
    // The work remains for when it is mined again, and the view still expects it.
    assert_eq!(reasons(&st, txid), Some(RECEIVE));
    assert_eq!(
        view(&st, unspent_account(&st), txid),
        Some(TransparentDisplayView::Pending)
    );
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
    // Advice beyond a day is clamped to a day.
    assert_eq!(
        secs(
            TransparentDetailOutcome::Unavailable {
                retry_after: Some(Duration::from_secs(3 * 24 * 3600)),
            },
            1
        ),
        24 * 3600
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

/// Work held for the private source's map is due at its ordinary retry once public authority
/// returns: a public lookup answers with the raw transaction whatever the map covers, and the
/// public source has no map to change.
#[test]
fn held_work_due_at_ordinary_retry_under_public_authority() {
    let (mut st, _, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    let contradicted = TxId::from_bytes([2; 32]);
    let unsupported = TxId::from_bytes([3; 32]);
    defer(&mut st, txid, TransparentDetailOutcome::NotCovered, now());
    defer(
        &mut st,
        contradicted,
        TransparentDetailOutcome::Contradiction,
        now(),
    );
    let unsupported_height = mined_height(&st, unsupported);
    st.wallet_mut()
        .db_mut()
        .defer_transparent_detail(
            unsupported,
            unsupported_height,
            TransparentDetailOutcome::Unsupported,
            None,
            now(),
        )
        .unwrap();
    let held = [txid, contradicted, unsupported];
    // Without public authority they wait for a map change.
    let at = later(2 * DAY);
    assert!(held.iter().all(|t| !listing_at(&st, at, None).contains(t)));
    assert_eq!(parked(&st, at).count, 3);

    set_policy(&mut st, Public);
    // Not before their ordinary retry...
    assert!(
        held.iter()
            .all(|t| !listing_at(&st, later(3600), None).contains(t))
    );
    // ...and then without any map, nor a wait for the backstop.
    let listed = listing_at(&st, at, None);
    assert!(held.iter().all(|t| listed.contains(t)), "{listed:?}");
    assert_eq!(parked(&st, at).count, 0);
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
    let details = available(&st, account, txid);
    assert_eq!(
        details.source,
        TransparentDisplaySource::Display(facts.provenance.clone())
    );
    assert_eq!(details.fee, WholeTransactionFee::Exact(zat(1_000)));
    assert_eq!((details.input_count, details.output_count), (1, 2));
    assert!(!details.coinbase && !details.shielded);
    assert_eq!(sender_of(&details), Some((FOREIGN, false)));
    let owned: Vec<_> = details.outputs.iter().map(|o| o.owned).collect();
    assert_eq!(owned, vec![true, false]);
    assert_eq!(addresses_of(&details), vec![Some(unspent.address), None]);
    assert_eq!(details.outputs[0].value, unspent.value);
    // The `OP_RETURN` output has no address to show.
    assert_eq!(
        details.omissions,
        vec![TransparentDisplayOmission::NonStandardOutput { index: 1 }]
    );
    assert!(!details.is_complete());
}

/// Stores facts that contradict the wallet, checking that nothing is saved and the work is held.
fn contradicted(
    st: &mut State,
    facts: TransparentDisplayFacts,
    expected: TransparentDisplayContradiction,
) {
    let txid = facts.txid;
    assert!(reasons(st, txid).is_some());
    let before = display_rows(st);
    assert_eq!(
        store(st, facts),
        TransparentDisplayStore::Contradiction(expected)
    );
    assert_eq!(display_rows(st), before);
    assert!(reasons(st, txid).is_some());
    assert!(!listing_at(st, later(6 * 24 * 3600), Some(MAP_A)).contains(&txid));
    assert!(listing_at(st, later(6 * 24 * 3600), Some(MAP_B)).contains(&txid));
}

/// Coinbase facts for `facts`' transaction: no input, no fee.
fn as_coinbase(mut facts: TransparentDisplayFacts) -> TransparentDisplayFacts {
    facts.coinbase = true;
    facts.fee = Zatoshis::ZERO;
    facts.input_count = 0;
    facts.sender = TransparentDisplaySender::Absent;
    facts
}

#[test]
fn contradiction_coinbase() {
    let (mut st, _, unspent) = active_wallet();
    // The recovered receive is not a coinbase output.
    contradicted(
        &mut st,
        as_coinbase(facts_for(&unspent)),
        TransparentDisplayContradiction::Coinbase,
    );
    // A coinbase transaction with an input or a fee is also a coinbase contradiction.
    let mut facts = facts_for(&unspent);
    facts.coinbase = true;
    contradicted(&mut st, facts, TransparentDisplayContradiction::Coinbase);
}

#[test]
fn contradiction_malformed() {
    let (mut st, _, unspent) = active_wallet();
    // An input without a sender.
    let mut facts = facts_for(&unspent);
    facts.sender = TransparentDisplaySender::Absent;
    contradicted(&mut st, facts, TransparentDisplayContradiction::Malformed);
    // Two outputs counted, one given.
    let mut facts = facts_for(&unspent);
    facts.outputs.pop();
    contradicted(&mut st, facts, TransparentDisplayContradiction::Malformed);
    // Several source scripts with one input.
    let mut facts = facts_for(&unspent);
    facts.multiple_source_scripts = true;
    contradicted(&mut st, facts, TransparentDisplayContradiction::Malformed);
    // Mixed funding without shielded components.
    let mut facts = facts_for(&unspent);
    facts.shielded_and_transparent_funding = true;
    contradicted(&mut st, facts, TransparentDisplayContradiction::Malformed);
    // Neither transparent inputs nor shielded components.
    let mut facts = facts_for(&unspent);
    facts.input_count = 0;
    facts.sender = TransparentDisplaySender::Absent;
    contradicted(&mut st, facts, TransparentDisplayContradiction::Malformed);
}

#[test]
fn contradiction_owned_output() {
    let (mut st, _, unspent) = active_wallet();
    let mut facts = facts_for(&unspent);
    facts.outputs[0].value = zat(40_001);
    contradicted(
        &mut st,
        facts,
        TransparentDisplayContradiction::OwnedOutput { index: 0 },
    );
    // Another address, or none, is another script.
    for address in [Some(FOREIGN), None] {
        let mut facts = facts_for(&unspent);
        facts.outputs[0].address = address;
        contradicted(
            &mut st,
            facts,
            TransparentDisplayContradiction::OwnedOutput { index: 0 },
        );
    }
}

#[test]
fn contradiction_index_oob() {
    let (mut st, _, unspent) = active_wallet();
    let mut facts = facts_for(&unspent);
    facts.outputs.clear();
    facts.output_count = 0;
    contradicted(
        &mut st,
        facts,
        TransparentDisplayContradiction::OutputIndexOutOfRange { index: 0 },
    );
}

#[test]
fn owned_output_beyond_the_given_two() {
    let (mut st, account, _) = active_wallet();
    let ws = watch(&st, account);
    // A receive at output 2.
    let third = ReceiveEvent {
        outpoint: OutPoint::new([0x40; 32], 2),
        ..receive(0x40, external(&ws), 5_000, below_target(&ws, 0))
    };
    let mut c = commit(&ws);
    c.receives = vec![third.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    let mut facts = facts_for(&third);
    assert_eq!(facts.outputs.len(), 2);
    facts.outputs = vec![
        TransparentDisplayOutput {
            value: zat(7),
            address: Some(FOREIGN),
        };
        2
    ];
    // Two outputs leave no room for it.
    facts.output_count = 2;
    contradicted(
        &mut st,
        facts.clone(),
        TransparentDisplayContradiction::OutputIndexOutOfRange { index: 2 },
    );
    // With three it is one of the omitted outputs.
    facts.output_count = 3;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    let details = available(&st, account, txid_of(&third));
    assert_eq!(details.output_count, 3);
    assert_eq!(details.outputs.len(), 2);
    assert!(details.outputs.iter().all(|o| !o.owned));
    assert_eq!(
        details.omissions,
        vec![TransparentDisplayOmission::MoreThanTwoOutputs]
    );
}

#[test]
fn contradiction_metadata() {
    let (mut st, account, _) = active_wallet();
    let ws = watch(&st, account);
    let recovered = TransactionMetadata {
        fee: WholeTransactionFee::Exact(zat(1_000)),
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
    let agreeing = || {
        let mut facts = facts_for(&fresh);
        facts.input_count = 2;
        facts
    };
    let mut facts = agreeing();
    facts.input_count = 1;
    contradicted(&mut st, facts, TransparentDisplayContradiction::Metadata);
    let mut facts = agreeing();
    facts.fee = zat(999);
    contradicted(&mut st, facts, TransparentDisplayContradiction::Metadata);
    let mut facts = agreeing();
    facts.shielded_components = true;
    contradicted(&mut st, facts, TransparentDisplayContradiction::Metadata);
    assert_eq!(store(&mut st, agreeing()), TransparentDisplayStore::Stored);
}

#[test]
fn unknown_recovered_fee_asserts_nothing() {
    let (mut st, account, _) = active_wallet();
    let ws = watch(&st, account);
    let fresh = ReceiveEvent {
        metadata: Some(TransactionMetadata {
            fee: WholeTransactionFee::Unknown,
            transparent_input_count: 1,
            has_shielded_components: false,
        }),
        ..receive(5, external(&ws), 60_000, below_target(&ws, 0))
    };
    let mut c = commit(&ws);
    c.receives = vec![fresh.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    assert_eq!(
        store(&mut st, facts_for(&fresh)),
        TransparentDisplayStore::Stored
    );
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
    let mut facts = facts_for(&unspent);
    facts.fee = zat(500);
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
    facts.shielded_components = true;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
}

#[test]
fn contradiction_input_index() {
    let (mut st, _, _) = active_wallet();
    // The projected spend consumes its output at input 0: an unshielding transaction cannot
    // be it.
    let mut facts = spend_facts(&st);
    facts.input_count = 0;
    facts.sender = TransparentDisplaySender::Absent;
    contradicted(
        &mut st,
        facts,
        TransparentDisplayContradiction::InputIndex { index: 0 },
    );
    let facts = spend_facts(&st);
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
    set_policy(&mut st, Public);
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
    // The payment is funded from the shielded pool, with the fee the wallet stored.
    let fee: u64 = conn(&st)
        .query_row(
            "SELECT fee FROM transactions WHERE txid = ?1",
            [txid.as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    let mut facts = facts_for(&recovered);
    facts.fee = zat(fee);
    facts.input_count = 0;
    facts.sender = TransparentDisplaySender::Absent;
    facts.shielded_components = true;
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
    assert_eq!(addresses_of(&details)[output_index as usize], Some(taddr));
    // Funded from the shielded pool only.
    assert_eq!(details.sender, TransparentDisplayViewSender::Shielded);
    assert_eq!(details.input_count, 0);
    assert!(details.is_complete());
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
    // Another account does not own it. Importing one unplaces the ledger's receives until they
    // are recovered again, so public discovery also records the output: it stays counted, and
    // only the account filter separates the two accounts.
    conn(&st)
        .execute(
            "INSERT INTO tpir_output_origins (output_id, origin)
             SELECT o.id, 0 FROM transparent_received_outputs o
             JOIN transactions t ON t.id_tx = o.transaction_id
             WHERE t.txid = ?1",
            [txid.as_ref()],
        )
        .unwrap();
    let other = import_account(&mut st, 9);
    assert!(owned(&st, account));
    // The other account takes no part in the transaction, so it has no view of it.
    assert_eq!(view(&st, other, txid), None);

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
    parked_under(st, at, None, None)
}

fn parked_under(
    st: &State,
    at: SystemTime,
    map: Option<[u8; 32]>,
    checked_at: Option<SystemTime>,
) -> TransparentDetailParked {
    st.wallet()
        .db()
        .transparent_detail_parked(at, map, checked_at)
        .unwrap()
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
            oldest_map_sha256: None,
            refresh_at: Some(now() + TRANSPARENT_DISPLAY_MAP_RECHECK),
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
            oldest_map_sha256: Some(MAP_A),
            refresh_at: Some(later(60) + TRANSPARENT_DISPLAY_MAP_RECHECK),
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
    set_policy(&mut st, Public);
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

/// Commits `receives` from a qualified provisional revision of `lineage`.
fn provisional_commit(
    st: &mut State,
    account: AccountUuid,
    lineage: u64,
    receives: Vec<ReceiveEvent>,
) {
    let provisional = revision(lineage, false);
    qualify(st, &provisional);
    let ws = watch(st, account);
    let mut c = commit(&ws);
    c.revision = provisional;
    c.receives = receives;
    c.coverage = full_coverage(&ws);
    apply(st, c).unwrap();
}

/// A receive projected from provisional lineage 2, then withdrawn by lineage 3, which does not
/// report it.
fn withdrawn_receive(st: &mut State, account: AccountUuid) -> ReceiveEvent {
    let ws = watch(st, account);
    let fresh = receive(5, external(&ws), 60_000, below_target(&ws, 0));
    provisional_commit(st, account, 2, vec![fresh.clone()]);
    assert!(listing(st).contains(&txid_of(&fresh)));
    provisional_commit(st, account, 3, vec![]);
    fresh
}

#[test]
fn withdrawn_receive_not_owned_and_not_related() {
    let (mut st, account, _) = active_wallet();
    let fresh = withdrawn_receive(&mut st, account);
    let txid = txid_of(&fresh);
    // The output row stays for its history, but the wallet no longer relates to the
    // transaction: not listed, not parked.
    assert_eq!(count_outputs(&st, txid), 1);
    assert!(!listing(&st).contains(&txid));
    assert!(!listing_at(&st, later(2 * DAY), Some(MAP_B)).contains(&txid));
    assert!(!listing_at(&st, later(30 * DAY), None).contains(&txid));
    // Its never-attempted work will not be listed, so the view does not wait for it.
    assert_eq!(
        view(&st, account, txid),
        Some(TransparentDisplayView::Unavailable)
    );

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

    // A shielding transaction whose one known script is the unspent output's.
    let mut facts = facts_for(&unspent);
    facts.txid = spender;
    facts.provenance.looked_up_height = BlockHeight::from(height);
    facts.outputs = vec![];
    facts.output_count = 0;
    facts.shielded_components = true;
    facts.sender = TransparentDisplaySender::Address(unspent.address);
    contradicted(
        &mut st,
        facts.clone(),
        TransparentDisplayContradiction::InputCount { known: 2 },
    );
    contradicted(
        &mut st,
        as_coinbase(facts.clone()),
        TransparentDisplayContradiction::Coinbase,
    );
    facts.input_count = 2;
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

#[test]
fn migration_skips_withdrawn_receive() {
    let (mut st, account, unspent) = active_wallet();
    let fresh = withdrawn_receive(&mut st, account);
    conn(&st)
        .execute_batch("DELETE FROM transparent_detail_work")
        .unwrap();
    crate::wallet::init::migrations::forget_txid_enhancement(conn(&st));
    crate::wallet::init::WalletMigrator::new()
        .init_or_migrate(st.wallet_mut().db_mut())
        .unwrap();
    // The withdrawn output's row remains, but it is not the wallet's: no work.
    assert_eq!(count_outputs(&st, txid_of(&fresh)), 1);
    assert_eq!(reasons(&st, txid_of(&fresh)), None);
    assert_eq!(reasons(&st, txid_of(&unspent)), Some(RECEIVE));
}

#[test]
fn facts_stored_while_withdrawn_revalidated_when_reported_again() {
    let (mut st, account, _) = active_wallet();
    let fresh = withdrawn_receive(&mut st, account);
    let txid = txid_of(&fresh);
    // Facts contradicting the withdrawn output are accepted: it does not constrain them.
    let mut facts = facts_for(&fresh);
    facts.outputs[fresh.outpoint.n() as usize].value = Zatoshis::const_from_u64(1);
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    assert_eq!(reasons(&st, txid), None);

    // A later lineage reports the receive again: the stored facts now contradict an owned
    // output, so they are deleted and the transaction is looked up again.
    provisional_commit(&mut st, account, 4, vec![fresh.clone()]);
    assert_eq!(display_rows(&st), (0, 0));
    assert_eq!(reasons(&st, txid), Some(RECEIVE));
    assert!(listing(&st).contains(&txid));
    assert_eq!(
        view(&st, account, txid),
        Some(TransparentDisplayView::Pending)
    );
    // Facts agreeing with it are stored, and survive the next report.
    assert_eq!(
        store(&mut st, facts_for(&fresh)),
        TransparentDisplayStore::Stored
    );
    provisional_commit(&mut st, account, 5, vec![fresh.clone()]);
    assert_eq!(display_rows(&st), (1, 2));
    assert_eq!(reasons(&st, txid), None);
}

#[test]
fn spend_projected_over_facts_revalidated() {
    let (mut st, account, unspent) = active_wallet();
    // The spending transaction's facts name one input: the spend already projected.
    let spending = TxId::from_bytes([3; 32]);
    let height = mined_height(&st, spending);
    let facts = spend_facts(&st);
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    assert_eq!(reasons(&st, spending), None);

    // The ledger then reports the same transaction spending another output at input 1.
    let ws = watch(&st, account);
    let second = SpendEvent {
        input_index: 1,
        ..spend(3, &unspent, height)
    };
    let mut c = commit(&ws);
    c.spends = vec![second];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    assert_eq!(display_rows(&st), (0, 0));
    assert_eq!(reasons(&st, spending), Some(SPEND));
    assert!(listing(&st).contains(&spending));
}

#[test]
fn parked_refresh_bounded_by_map_check() {
    let (mut st, _, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    defer(&mut st, txid, TransparentDetailOutcome::NotCovered, now());
    let at = later(2 * DAY);
    // Parked under the caller's map, and a refresh is due: the lookup used the map two days ago.
    let report = parked_under(&st, at, Some(MAP_A), None);
    assert_eq!(report.count, 1);
    assert_eq!(
        report.refresh_at,
        Some(now() + TRANSPARENT_DISPLAY_MAP_RECHECK)
    );
    assert!(report.refresh_at.unwrap() <= at);
    // The caller refreshed and got the same map: the next refresh waits six hours.
    let report = parked_under(&st, at + Duration::from_secs(60), Some(MAP_A), Some(at));
    assert_eq!(report.count, 1);
    assert_eq!(
        report.refresh_at,
        Some(at + TRANSPARENT_DISPLAY_MAP_RECHECK)
    );
    assert!(!listing_at(&st, at + Duration::from_secs(60), Some(MAP_A)).contains(&txid));
    // Under another map the row is due, not parked.
    assert_eq!(
        parked_under(&st, at, Some(MAP_B), Some(at)),
        TransparentDetailParked::default()
    );
    assert!(listing_at(&st, at, Some(MAP_B)).contains(&txid));
}

#[test]
fn not_yet_published_does_not_inflate_backoff() {
    let (mut st, _, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    for _ in 0..10 {
        defer(
            &mut st,
            txid,
            TransparentDetailOutcome::NotYetPublished,
            now(),
        );
    }
    assert_eq!(attempts(&st, txid), 10);
    // Another class of outcome starts its own backoff from the first step.
    defer(&mut st, txid, unavailable(), now());
    assert_eq!(attempts(&st, txid), 1);
    assert!(!listing_at(&st, later(29), None).contains(&txid));
    assert!(listing_at(&st, later(40), None).contains(&txid));
    // Outcomes of one class keep counting.
    defer(&mut st, txid, TransparentDetailOutcome::Protocol, now());
    assert_eq!(attempts(&st, txid), 2);
    defer(&mut st, txid, TransparentDetailOutcome::Absent, now());
    assert_eq!(attempts(&st, txid), 1);
    defer(
        &mut st,
        txid,
        TransparentDetailOutcome::NotYetPublished,
        now(),
    );
    assert_eq!(attempts(&st, txid), 1);
}

#[test]
fn view_matches_listability() {
    let (mut st, account, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    let protected = TxId::from_bytes([2; 32]);
    conn(&st)
        .execute(
            "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (?1, 0)",
            [tx_ref(&st, protected).0],
        )
        .unwrap();
    conn(&st)
        .execute(
            "INSERT INTO tx_retrieval_queue (txid, query_type, policy_generation)
             VALUES (?1, ?2, 0)",
            rusqlite::params![txid.as_ref(), TxQueryType::Enhancement.code()],
        )
        .unwrap();
    // Without public authority both are listed, and so pending.
    for t in [txid, protected] {
        assert!(listing(&st).contains(&t));
        assert_eq!(view(&st, account, t), Some(TransparentDisplayView::Pending));
    }
    set_policy(&mut st, Public);
    // Under public authority neither is listed. Payload retrieval owns one; nothing will fetch
    // the privately protected one.
    let listed = listing(&st);
    assert!(!listed.contains(&txid) && !listed.contains(&protected));
    assert_eq!(reasons(&st, protected), Some(RECEIVE));
    assert_eq!(
        view(&st, account, txid),
        Some(TransparentDisplayView::Pending)
    );
    assert_eq!(
        view(&st, account, protected),
        Some(TransparentDisplayView::Unavailable)
    );
}

#[cfg(feature = "orchard")]
#[test]
fn route2_unmined_at_transition_queued_when_mined() {
    use zcash_client_backend::data_api::{TransactionStatus, WalletWrite as _};

    let (mut st, _, unspent) = active_wallet();
    set_policy(&mut st, Public);
    // A route-1 transaction, mined, then rewound before PrivateRequired is applied.
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
    st.truncate_to_height(unspent.mined_height - 1);
    set_policy(&mut st, PrivateRequired);
    let route: i64 = conn(&st)
        .query_row(
            "SELECT route FROM ironwood_enhance_routing WHERE transaction_id = ?1",
            [tx_ref(&st, mixed).0],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(route, 2);
    // Unmined, it cannot be queued.
    assert_eq!(reasons(&st, mixed), None);

    // Mined again: queued, and due.
    scan_new_blocks(&mut st, 2);
    st.wallet_mut()
        .set_transaction_status(mixed, TransactionStatus::Mined(unspent.mined_height + 1))
        .unwrap();
    assert_eq!(reasons(&st, mixed), Some(MIXED));
    assert!(listing(&st).contains(&mixed));
}

fn available(st: &State, account: AccountUuid, txid: TxId) -> TransparentDisplayDetails {
    match view(st, account, txid) {
        Some(TransparentDisplayView::Available(details)) => details,
        other => panic!("expected available details, got {other:?}"),
    }
}

/// The view's sender address and whether the account owns it, when it shows one.
fn sender_of(details: &TransparentDisplayDetails) -> Option<(TransparentAddress, bool)> {
    match &details.sender {
        TransparentDisplayViewSender::Address { address, owned } => Some((address.address, *owned)),
        _ => None,
    }
}

fn addresses_of(details: &TransparentDisplayDetails) -> Vec<Option<TransparentAddress>> {
    details
        .outputs
        .iter()
        .map(|o| o.address.as_ref().map(|a| a.address))
        .collect()
}

fn output(value: u64, address: Option<TransparentAddress>) -> TransparentDisplayOutput {
    TransparentDisplayOutput {
        value: zat(value),
        address,
    }
}

/// Projects transaction `[tag; 32]` spending fresh 10 000-zatoshi receives at `addresses`, one
/// input each, in order.
fn project_spends(
    st: &mut State,
    account: AccountUuid,
    tag: u8,
    addresses: &[TransparentAddress],
) -> TxId {
    project_spends_from(st, account, tag, addresses, 0)
}

/// [`project_spends`] with the projected inputs at indices from `first_index` on.
fn project_spends_from(
    st: &mut State,
    account: AccountUuid,
    tag: u8,
    addresses: &[TransparentAddress],
    first_index: u32,
) -> TxId {
    let ws = watch(st, account);
    let receives: Vec<ReceiveEvent> = addresses
        .iter()
        .zip(1u8..)
        .map(|(address, i)| receive(tag + i, *address, 10_000, below_target(&ws, 1)))
        .collect();
    let spends = receives
        .iter()
        .zip(first_index..)
        .map(|(r, input_index)| SpendEvent {
            input_index,
            ..spend(tag, r, below_target(&ws, 0))
        })
        .collect();
    let mut c = commit(&ws);
    c.receives = receives;
    c.spends = spends;
    c.coverage = full_coverage(&ws);
    apply(st, c).unwrap();
    TxId::from_bytes([tag; 32])
}

/// Facts for a projected spending transaction `txid` of `input_count` inputs, sent by `sender`:
/// a shielding transaction without transparent outputs.
fn spending_facts(
    st: &State,
    txid: TxId,
    input_count: u32,
    sender: TransparentAddress,
) -> TransparentDisplayFacts {
    TransparentDisplayFacts {
        txid,
        input_count,
        sender: TransparentDisplaySender::Address(sender),
        provenance: provenance(mined_height(st, txid)),
        ..spend_facts(st)
    }
}

/// Two distinct external addresses of `account`.
fn two_addresses(st: &State, account: AccountUuid) -> (TransparentAddress, TransparentAddress) {
    let ws = watch(st, account);
    let (a, b) = (external(&ws), last_external(&ws).0);
    assert_ne!(a, b);
    (a, b)
}

#[test]
fn contradiction_source_scripts() {
    let (mut st, account, _) = active_wallet();
    let (a, b) = two_addresses(&st, account);
    // The wallet knows two of three inputs, spending two scripts: the flag must be set.
    let partial = project_spends(&mut st, account, 0x70, &[a, b]);
    let mut facts = spending_facts(&st, partial, 3, a);
    contradicted(
        &mut st,
        facts.clone(),
        TransparentDisplayContradiction::SourceScripts,
    );
    facts.multiple_source_scripts = true;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    // The wallet knows both inputs, spending one script: the flag must be clear.
    let same = project_spends(&mut st, account, 0x80, &[a, a]);
    let mut facts = spending_facts(&st, same, 2, a);
    facts.multiple_source_scripts = true;
    contradicted(
        &mut st,
        facts.clone(),
        TransparentDisplayContradiction::SourceScripts,
    );
    facts.multiple_source_scripts = false;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
}

#[test]
fn contradiction_sender() {
    let (mut st, account, _) = active_wallet();
    let (a, b) = two_addresses(&st, account);
    // Every input known, in order: the sender is the first one's address.
    let both = project_spends(&mut st, account, 0x70, &[a, b]);
    let mut facts = spending_facts(&st, both, 2, a);
    facts.multiple_source_scripts = true;
    for wrong in [
        TransparentDisplaySender::Address(b),
        TransparentDisplaySender::Address(FOREIGN),
        TransparentDisplaySender::NonStandard,
    ] {
        contradicted(
            &mut st,
            TransparentDisplayFacts {
                sender: wrong,
                ..facts.clone()
            },
            TransparentDisplayContradiction::Sender,
        );
    }
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);

    // The first two of three inputs known, in order: the first is still the sender.
    let prefix = project_spends(&mut st, account, 0x78, &[a, b]);
    let mut facts = spending_facts(&st, prefix, 3, FOREIGN);
    facts.multiple_source_scripts = true;
    contradicted(
        &mut st,
        facts.clone(),
        TransparentDisplayContradiction::Sender,
    );
    facts.sender = TransparentDisplaySender::Address(a);
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);

    // One of two inputs known, the first. With one source script every input spends it.
    let spending = TxId::from_bytes([3; 32]);
    let spent = spent_address(&st, spending, 0);
    assert_ne!(spent, FOREIGN);
    let mut facts = spending_facts(&st, spending, 2, FOREIGN);
    contradicted(
        &mut st,
        facts.clone(),
        TransparentDisplayContradiction::Sender,
    );
    // With several, a known address-shaped script rules out a non-standard sender, and a
    // known first input still fixes the sender.
    facts.multiple_source_scripts = true;
    for wrong in [
        TransparentDisplaySender::NonStandard,
        TransparentDisplaySender::Address(FOREIGN),
    ] {
        contradicted(
            &mut st,
            TransparentDisplayFacts {
                sender: wrong,
                ..facts.clone()
            },
            TransparentDisplayContradiction::Sender,
        );
    }
    facts.sender = TransparentDisplaySender::Address(spent);
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);

    // Only the second of two inputs known: the unknown first one may be the sender.
    let second = project_spends_from(&mut st, account, 0x7c, &[b], 1);
    let mut facts = spending_facts(&st, second, 2, FOREIGN);
    facts.multiple_source_scripts = true;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
}

#[test]
fn contradiction_funding() {
    let (mut st, _, _) = active_wallet();
    // The one input spends 25 000 zatoshis.
    let base = spend_facts(&st);
    let paying = |value: u64| TransparentDisplayFacts {
        output_count: 1,
        outputs: vec![output(value, Some(FOREIGN))],
        ..base.clone()
    };
    // Without shielded components it must balance: 10 000 + 1 000 is not 25 000.
    let mut facts = paying(10_000);
    facts.shielded_components = false;
    contradicted(&mut st, facts, TransparentDisplayContradiction::Funding);
    // The shielded pools contributed nothing (14 000 went to them).
    let mut facts = paying(10_000);
    facts.shielded_and_transparent_funding = true;
    contradicted(&mut st, facts, TransparentDisplayContradiction::Funding);
    // 30 000 + 1 000 exceeds the input: the shielded pools paid 6 000.
    contradicted(
        &mut st,
        paying(30_000),
        TransparentDisplayContradiction::Funding,
    );
    // With omitted outputs only a contribution the given ones prove is checked.
    let mut facts = paying(10_000);
    facts.output_count = 3;
    facts.outputs = vec![output(10_000, Some(FOREIGN)), output(10_000, None)];
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    // Balanced without shielded components.
    let mut facts = paying(24_000);
    facts.shielded_components = false;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
}

#[test]
fn view_regular_send_with_shielded_change() {
    let (mut st, account, _) = active_wallet();
    let spending = TxId::from_bytes([3; 32]);
    let mut facts = spend_facts(&st);
    facts.output_count = 1;
    facts.outputs = vec![output(15_000, Some(FOREIGN))];
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    let details = available(&st, account, spending);
    let spent = spent_address(&st, spending, 0);
    assert_eq!(sender_of(&details), Some((spent, true)));
    let TransparentDisplayViewSender::Address { address, .. } = &details.sender else {
        unreachable!()
    };
    assert_eq!(
        address.encoded,
        zcash_keys::encoding::encode_transparent_address_p(st.network(), &spent)
    );
    assert_eq!(addresses_of(&details), vec![Some(FOREIGN)]);
    assert!(!details.outputs[0].owned);
    assert!(details.shielded);
    assert_eq!(details.fee, WholeTransactionFee::Exact(zat(1_000)));
    assert!(details.is_complete());
}

#[test]
fn view_shielding() {
    let (mut st, account, _) = active_wallet();
    let spending = TxId::from_bytes([3; 32]);
    let facts = spend_facts(&st);
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    let details = available(&st, account, spending);
    assert_eq!(
        sender_of(&details),
        Some((spent_address(&st, spending, 0), true))
    );
    assert_eq!((details.input_count, details.output_count), (1, 0));
    assert!(details.outputs.is_empty() && details.shielded && details.is_complete());
}

#[test]
fn view_several_inputs_one_script() {
    let (mut st, account, _) = active_wallet();
    let (a, _) = two_addresses(&st, account);
    let txid = project_spends(&mut st, account, 0x70, &[a, a, a]);
    // A transparent-only send: 30 000 in, 29 000 out and 1 000 fee.
    let mut facts = spending_facts(&st, txid, 3, a);
    facts.shielded_components = false;
    facts.output_count = 1;
    facts.outputs = vec![output(29_000, Some(FOREIGN))];
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    let details = available(&st, account, txid);
    assert_eq!(sender_of(&details), Some((a, true)));
    assert_eq!(details.input_count, 3);
    assert!(details.is_complete());
}

#[test]
fn view_same_wallet_multi_source() {
    let (mut st, account, _) = active_wallet();
    let (a, b) = two_addresses(&st, account);
    let txid = project_spends(&mut st, account, 0x70, &[a, b]);
    let mut facts = spending_facts(&st, txid, 2, a);
    facts.multiple_source_scripts = true;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    // The account funded every input: its own send, not an omission.
    let details = available(&st, account, txid);
    assert_eq!(sender_of(&details), Some((a, true)));
    assert!(details.is_complete());
}

#[test]
fn view_ownership_requires_current_qualified_evidence() {
    let (mut st, account, _) = active_wallet();
    let (a, b) = two_addresses(&st, account);
    let txid = project_spends(&mut st, account, 0x70, &[a, b]);
    let mut facts = spending_facts(&st, txid, 2, a);
    facts.multiple_source_scripts = true;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    assert!(available(&st, account, txid).is_complete());

    for (case, withdraw) in [
        ("candidate account", "DELETE FROM tpir_active_accounts"),
        (
            "unqualified revision",
            "DELETE FROM tpir_qualified_revisions",
        ),
        ("missing observation", "DELETE FROM tpir_spend_observations"),
        (
            "quarantined account",
            "INSERT INTO tpir_quarantined_accounts SELECT account_id FROM tpir_active_accounts",
        ),
        (
            "quarantined source",
            "INSERT INTO tpir_quarantined_sources SELECT DISTINCT source FROM tpir_revisions",
        ),
        (
            "unplaced spend",
            "UPDATE tpir_spend_events SET mined_height = NULL",
        ),
        (
            "stale placement",
            "UPDATE tpir_spend_events SET mined_height = mined_height - 1",
        ),
    ] {
        conn(&st)
            .execute_batch("SAVEPOINT withdraw_ownership")
            .unwrap();
        conn(&st).execute_batch(withdraw).unwrap();
        let details = available(&st, account, txid);
        assert_eq!(
            details.omissions,
            vec![TransparentDisplayOmission::MultipleSourceScripts],
            "{case} must not prove that the account funded every input"
        );
        assert!(!details.is_complete(), "{case}");
        conn(&st)
            .execute_batch("ROLLBACK TO withdraw_ownership; RELEASE withdraw_ownership")
            .unwrap();
        assert!(
            available(&st, account, txid).is_complete(),
            "restored {case}"
        );
    }
}

#[test]
fn view_ownership_keeps_independent_spend_evidence() {
    let (mut st, account, _) = active_wallet();
    let (a, b) = two_addresses(&st, account);
    let txid = project_spends(&mut st, account, 0x70, &[a, b]);
    let mut facts = spending_facts(&st, txid, 2, a);
    facts.multiple_source_scripts = true;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    for origin in [0, 1] {
        conn(&st)
            .execute_batch("SAVEPOINT independent_ownership")
            .unwrap();
        conn(&st)
            .execute(
                "INSERT INTO tpir_spend_origins
                 SELECT ?1, prevout_txid, prevout_output_index, ?2
                 FROM tpir_spend_events WHERE spending_txid = ?3",
                rusqlite::params![tx_ref(&st, txid).0, origin, txid.as_ref()],
            )
            .unwrap();
        conn(&st)
            .execute_batch(
                "DELETE FROM tpir_qualified_revisions;
                 INSERT INTO tpir_quarantined_accounts SELECT account_id FROM tpir_active_accounts;",
            )
            .unwrap();
        assert!(
            available(&st, account, txid).is_complete(),
            "origin {origin}"
        );
        conn(&st)
            .execute_batch("ROLLBACK TO independent_ownership; RELEASE independent_ownership")
            .unwrap();
    }
}

#[test]
fn view_shared_funding() {
    let (mut st, account, _) = active_wallet();
    let spending = TxId::from_bytes([3; 32]);
    let spent = spent_address(&st, spending, 0);
    // The account funded one of two inputs; the other spends another script.
    let mut facts = spending_facts(&st, spending, 2, spent);
    facts.multiple_source_scripts = true;
    assert_eq!(
        store(&mut st, facts.clone()),
        TransparentDisplayStore::Stored
    );
    let details = available(&st, account, spending);
    assert_eq!(sender_of(&details), Some((spent, true)));
    assert_eq!(
        details.omissions,
        vec![TransparentDisplayOmission::SharedFunding]
    );
    // With one source script the other input spends the account's script too.
    facts.multiple_source_scripts = false;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    assert!(available(&st, account, spending).is_complete());
}

/// Facts for `unspent` paying it at output 0 and `change` at output 1.
fn receive_facts(
    unspent: &ReceiveEvent,
    change: TransparentDisplayOutput,
) -> TransparentDisplayFacts {
    let mut facts = facts_for(unspent);
    facts.outputs[1] = change;
    facts
}

#[test]
fn view_zcashd_two_outputs_and_more() {
    let (mut st, account, unspent) = active_wallet();
    let txid = txid_of(&unspent);
    let facts = receive_facts(&unspent, output(9_000, Some(FOREIGN)));
    assert_eq!(
        store(&mut st, facts.clone()),
        TransparentDisplayStore::Stored
    );
    let details = available(&st, account, txid);
    assert_eq!(sender_of(&details), Some((FOREIGN, false)));
    assert_eq!(
        addresses_of(&details),
        vec![Some(unspent.address), Some(FOREIGN)]
    );
    let owned: Vec<_> = details.outputs.iter().map(|o| o.owned).collect();
    assert_eq!(owned, vec![true, false]);
    assert!(details.is_complete());

    // Two more outputs exist and are not shown.
    let mut more = facts;
    more.output_count = 4;
    assert_eq!(store(&mut st, more), TransparentDisplayStore::Stored);
    let details = available(&st, account, txid);
    assert_eq!((details.output_count, details.outputs.len()), (4, 2));
    assert_eq!(
        details.omissions,
        vec![TransparentDisplayOmission::MoreThanTwoOutputs]
    );
}

#[test]
fn view_foreign_multi_source() {
    let (mut st, account, unspent) = active_wallet();
    let mut facts = receive_facts(&unspent, output(9_000, Some(FOREIGN)));
    facts.input_count = 3;
    facts.multiple_source_scripts = true;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    let details = available(&st, account, txid_of(&unspent));
    assert_eq!(sender_of(&details), Some((FOREIGN, false)));
    assert_eq!(
        details.omissions,
        vec![TransparentDisplayOmission::MultipleSourceScripts]
    );
}

#[test]
fn view_unshielding() {
    let (mut st, account, unspent) = active_wallet();
    let mut facts = facts_for(&unspent);
    facts.input_count = 0;
    facts.sender = TransparentDisplaySender::Absent;
    facts.shielded_components = true;
    facts.output_count = 1;
    facts.outputs.truncate(1);
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    let details = available(&st, account, txid_of(&unspent));
    assert_eq!(details.sender, TransparentDisplayViewSender::Shielded);
    assert_eq!(details.input_count, 0);
    assert!(details.is_complete());
}

#[test]
fn view_mixed_funding() {
    let (mut st, account, _) = active_wallet();
    let spending = TxId::from_bytes([3; 32]);
    // 30 000 + 1 000 paid, 25 000 from the transparent input: 6 000 from the shielded pools.
    let mut facts = spend_facts(&st);
    facts.output_count = 1;
    facts.outputs = vec![output(30_000, Some(FOREIGN))];
    facts.shielded_and_transparent_funding = true;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    let details = available(&st, account, spending);
    assert_eq!(
        details.omissions,
        vec![TransparentDisplayOmission::ShieldedAndTransparentFunding]
    );
}

#[test]
fn view_coinbase() {
    let (mut st, account, _) = active_wallet();
    let ws = watch(&st, account);
    let reward = ReceiveEvent {
        coinbase: true,
        ..receive(0x50, external(&ws), 90_000, below_target(&ws, 0))
    };
    let mut c = commit(&ws);
    c.receives = vec![reward.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    let mut facts = as_coinbase(facts_for(&reward));
    facts.output_count = 1;
    facts.outputs.truncate(1);
    // Another transaction cannot be a coinbase transaction.
    contradicted(
        &mut st,
        TransparentDisplayFacts {
            coinbase: false,
            shielded_components: true,
            ..facts.clone()
        },
        TransparentDisplayContradiction::Coinbase,
    );
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    let details = available(&st, account, txid_of(&reward));
    assert_eq!(details.sender, TransparentDisplayViewSender::Coinbase);
    assert_eq!(details.fee, WholeTransactionFee::NotApplicable);
    assert!(details.coinbase && details.outputs[0].owned && details.is_complete());
}

#[test]
fn view_non_standard_sender_and_output() {
    let (mut st, account, unspent) = active_wallet();
    let mut facts = facts_for(&unspent);
    facts.sender = TransparentDisplaySender::NonStandard;
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    let details = available(&st, account, txid_of(&unspent));
    assert_eq!(details.sender, TransparentDisplayViewSender::NonStandard);
    assert_eq!(
        details.omissions,
        vec![
            TransparentDisplayOmission::NonStandardSender,
            TransparentDisplayOmission::NonStandardOutput { index: 1 },
        ]
    );
}

#[test]
fn view_sender_owned_by_address() {
    let (mut st, account, unspent) = active_wallet();
    // The account paid itself from an address whose spend the wallet has not recorded.
    let (a, _) = two_addresses(&st, account);
    let mut facts = receive_facts(&unspent, output(9_000, Some(a)));
    facts.sender = TransparentDisplaySender::Address(a);
    assert_eq!(store(&mut st, facts), TransparentDisplayStore::Stored);
    let details = available(&st, account, txid_of(&unspent));
    assert_eq!(sender_of(&details), Some((a, true)));
    // Another account takes no part in the transaction, so it has no view of it.
    let other = import_account(&mut st, 9);
    assert_eq!(view(&st, other, txid_of(&unspent)), None);
}

/// A DER-shaped signature with its sighash byte.
fn signature() -> Vec<u8> {
    let mut sig = vec![0x30; 71];
    sig[70] = 0x01;
    sig
}

fn push(data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= 75);
    [&[data.len() as u8][..], data].concat()
}

/// Stores a copy of local transaction `txid` with transparent inputs unlocked by `script_sigs`,
/// returning the copy's txid.
fn with_inputs(st: &mut State, txid: TxId, script_sigs: Vec<Vec<u8>>) -> TxId {
    with_outpoints(
        st,
        txid,
        script_sigs
            .into_iter()
            .zip(0x90u8..)
            .map(|(script_sig, tag)| (OutPoint::new([tag; 32], 0), script_sig))
            .collect(),
    )
}

fn with_outpoints(st: &mut State, txid: TxId, inputs: Vec<(OutPoint, Vec<u8>)>) -> TxId {
    use transparent::bundle::{Authorized, Bundle, TxIn};
    let data = st
        .wallet()
        .get_transaction(txid)
        .unwrap()
        .unwrap()
        .into_data();
    let vin = inputs
        .into_iter()
        .map(|(outpoint, script_sig)| {
            TxIn::from_parts(
                outpoint,
                transparent::address::Script(zcash_script::script::Code(script_sig)),
                u32::MAX,
            )
        })
        .collect();
    let vout = data
        .transparent_bundle()
        .map(|b| b.vout.clone())
        .unwrap_or_default();
    let tx = zcash_primitives::transaction::TransactionData::from_parts(
        data.version(),
        data.consensus_branch_id(),
        data.lock_time(),
        data.expiry_height(),
        Some(Bundle {
            vin,
            vout,
            authorization: Authorized,
        }),
        data.sprout_bundle().cloned(),
        data.sapling_bundle().cloned(),
        data.orchard_bundle().cloned(),
    )
    .freeze()
    .unwrap();
    let height = st.wallet().chain_height().unwrap().unwrap();
    crate::wallet::put_tx_data(conn(st), &tx, None, None, None, height).unwrap();
    tx.txid()
}

#[test]
fn raw_view_ownership_requires_an_actual_input() {
    let (mut st, account, taddr, txid, output_index) = local_payment_to_self();
    let ws = watch(&st, account);
    let WatchOrigin::Derived { scope, index } = ws
        .addresses
        .iter()
        .find(|w| w.address == taddr)
        .unwrap()
        .origin
    else {
        panic!("expected a derived address");
    };
    let key = st
        .test_account()
        .unwrap()
        .usk()
        .to_unified_full_viewing_key()
        .transparent()
        .unwrap()
        .derive_address_pubkey(scope, index)
        .unwrap();
    assert_eq!(TransparentAddress::from_pubkey(&key), taddr);
    let script_sig = [push(&signature()), push(&key.serialize())].concat();
    let unrelated = with_inputs(&mut st, txid, vec![script_sig.clone()]);
    let actual = with_outpoints(
        &mut st,
        txid,
        vec![(OutPoint::new(*txid.as_ref(), output_index), script_sig)],
    );
    for (copy, expected_owned) in [(unrelated, false), (actual, true)] {
        // The independently constructed link is retained even if the raw transaction spends
        // a different outpoint. It must only attribute ownership when the input is present.
        conn(&st)
            .execute(
                "INSERT INTO transparent_received_output_spends
                 SELECT id, ?1 FROM transparent_received_outputs
                 WHERE transaction_id = ?2 AND output_index = ?3",
                rusqlite::params![tx_ref(&st, copy).0, tx_ref(&st, txid).0, output_index],
            )
            .unwrap();
        crate::wallet::transparent_ledger::record_spend_origin(
            conn(&st),
            tx_ref(&st, copy),
            &OutPoint::new(*txid.as_ref(), output_index),
            crate::wallet::transparent_ledger::ProjectionOrigin::LocalConstruction,
        )
        .unwrap();
        assert_eq!(
            sender_of(&available(&st, account, copy)),
            Some((taddr, expected_owned))
        );
    }
}

#[test]
fn raw_view_sender_from_unlocking_scripts() {
    use TransparentDisplayOmission as O;
    use transparent::util::hash160::hash;
    let (mut st, account, taddr, txid, output_index) = local_payment_to_self();
    // The account takes part in each copy: it spends the account's output, by a link no
    // spend origin backs, so the account owns no input. A txid does not commit to unlocking
    // scripts, so a copy that differs from an earlier one only in them replaces it, already
    // linked.
    let with_inputs = |st: &mut State, txid, script_sigs| {
        let copy = with_inputs(st, txid, script_sigs);
        conn(st)
            .execute(
                "INSERT OR IGNORE INTO transparent_received_output_spends
                 SELECT id, ?1 FROM transparent_received_outputs
                 WHERE transaction_id = ?2 AND output_index = ?3",
                rusqlite::params![tx_ref(st, copy).0, tx_ref(st, txid).0, output_index],
            )
            .unwrap();
        copy
    };
    // The copies keep the original's Sapling spend, so the shielded pool also funds them.
    let key = [&[0x02][..], &[7; 32]].concat();
    let p2pk = push(&signature());
    let p2pkh = [push(&signature()), push(&key)].concat();
    let redeem = [
        &[0x52][..],
        &push(&key),
        &push(&[&[0x03][..], &[8; 32]].concat()),
        &[0x52, 0xae],
    ]
    .concat();
    let p2sh = [
        vec![0x00],
        push(&signature()),
        push(&signature()),
        push(&redeem),
    ]
    .concat();

    // The first input whose unlocking script shows an address is the sender.
    let copy = with_inputs(&mut st, txid, vec![p2pk.clone(), p2pkh]);
    let details = available(&st, account, copy);
    assert_eq!(details.source, TransparentDisplaySource::RawTransaction);
    assert_eq!(
        sender_of(&details),
        Some((TransparentAddress::PublicKeyHash(hash(&key)), false))
    );
    assert_eq!(details.input_count, 2);
    assert_eq!(addresses_of(&details), vec![Some(taddr)]);
    assert_eq!(
        details.omissions,
        vec![O::MultipleSourceScripts, O::ShieldedAndTransparentFunding]
    );

    let copy = with_inputs(&mut st, txid, vec![p2sh]);
    let details = available(&st, account, copy);
    assert_eq!(
        sender_of(&details),
        Some((TransparentAddress::ScriptHash(hash(&redeem)), false))
    );
    assert_eq!(details.omissions, vec![O::ShieldedAndTransparentFunding]);

    let copy = with_inputs(&mut st, txid, vec![p2pk]);
    let details = available(&st, account, copy);
    assert_eq!(details.sender, TransparentDisplayViewSender::NonStandard);
    assert_eq!(
        details.omissions,
        vec![O::NonStandardSender, O::ShieldedAndTransparentFunding]
    );
}
