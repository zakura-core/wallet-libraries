//! Private status polls follow the window fixed when the work was queued, not the replies
//! (`docs/pir-remaining-leaks-plan.md`, change A). Each test drives the wallet as an
//! application must: send every due query, record every reply that came back, and apply only
//! answers to work that is not yet settled.
use rusqlite::params;
use zcash_client_backend::data_api::{
    TransactionStatus, WalletRead, WalletWrite,
    status::{
        TransactionStatusMode, TransactionStatusRead, TransactionStatusWork, TransactionStatusWrite,
    },
    testing::{TestBuilder, TestState},
};
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork};

use crate::testing::{
    BlockCache,
    db::{TestDb, TestDbFactory},
};

type State = TestState<BlockCache, TestDb, LocalNetwork>;

/// Polls at each of the ten tips of the window, and the expiry poll.
const WINDOW: u32 = 10;
const EXPIRY_DELTA: u32 = 40;

fn fixture() -> (State, BlockHeight) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::file_backed())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    let (height, _) = st.generate_empty_block();
    st.scan_cached_blocks(height, 1);
    st.wallet_mut()
        .db_mut()
        .set_status_mode(TransactionStatusMode::Private);
    (st, height)
}

/// Queues private status work for `txid` at the current tip, as storing a sent transaction that
/// compact scanning cannot observe does.
fn queue(st: &State, txid: TxId, expiry: u32) {
    st.wallet()
        .conn()
        .execute(
            "INSERT INTO transactions (txid, expiry_height, min_observed_height)
             VALUES (?1, ?2, 0)",
            params![txid.as_ref(), expiry],
        )
        .unwrap();
    let tx = st.wallet().conn().unchecked_transaction().unwrap();
    super::queue_tx_status(&tx, txid).unwrap();
    tx.commit().unwrap();
}

fn queued(st: &State, txid: TxId) -> bool {
    st.wallet()
        .conn()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM tx_retrieval_queue WHERE txid = ?1 AND query_type = 0)",
            [txid.as_ref()],
            |row| row.get(0),
        )
        .unwrap()
}

fn private_work(st: &State, txid: TxId) -> Vec<TransactionStatusWork> {
    st.wallet()
        .transaction_status_work()
        .unwrap()
        .into_iter()
        .filter(|work| work.txid() == txid)
        .inspect(|work| assert!(matches!(work, TransactionStatusWork::Private(_))))
        .collect()
}

fn settled(work: TransactionStatusWork) -> bool {
    match work {
        TransactionStatusWork::Private(request) => request.settled(),
        TransactionStatusWork::Public(_) => panic!("expected private work"),
    }
}

/// What a status service answers when asked at a tip. Heights are offsets from the tip at
/// which the work was queued.
#[derive(Clone, Copy, Debug)]
enum Service {
    /// The transaction waits in the mempool, then mines at `mined`.
    Honest { mined: u32 },
    /// Forges "mined at `at`" from the first query on.
    Forging { at: u32 },
    /// Every row fails to decode (`StatusError::Unreadable`).
    Unreadable,
    /// The snapshot does not cover the transaction (`StatusError::CoverageIncomplete`).
    CoverageIncomplete,
    /// The transaction is not in the table.
    NotFound,
}

impl Service {
    /// The answer to apply at `tip` for work queued at `queued`, or `None` for a reply that
    /// carries no status.
    fn answer(self, queued: BlockHeight, tip: BlockHeight) -> Option<TransactionStatus> {
        match self {
            Service::Honest { mined } => {
                (tip >= queued + mined).then_some(TransactionStatus::Mined(queued + mined))
            }
            Service::Forging { at } => Some(TransactionStatus::Mined(queued + at)),
            Service::Unreadable | Service::CoverageIncomplete => None,
            Service::NotFound => Some(TransactionStatus::TxidNotRecognized),
        }
    }
}

/// Serves the due work at the current tip `tip` and returns the txids queried.
fn serve(st: &mut State, queued: BlockHeight, tip: BlockHeight, service: Service) -> Vec<TxId> {
    let work = st.wallet().transaction_status_work().unwrap();
    let mut asked = vec![];
    for item in work {
        let TransactionStatusWork::Private(request) = item else {
            panic!("expected private work");
        };
        asked.push(request.txid());
        st.wallet_mut()
            .db_mut()
            .record_private_status_poll(request.txid(), tip)
            .unwrap();
        if let (false, Some(status)) = (request.settled(), service.answer(queued, tip)) {
            st.wallet_mut()
                .set_transaction_status(request.txid(), status)
                .unwrap();
        }
    }
    asked
}

/// Walks the tip from the queue tip `h` to `h + 45` and records each (tip, txid) queried.
fn transcript(service: Service) -> (Vec<(u32, TxId)>, State, TxId) {
    let (mut st, h) = fixture();
    let txid = TxId::from_bytes([7; 32]);
    queue(&st, txid, u32::from(h) + EXPIRY_DELTA);
    let mut seen = vec![];
    for tip in u32::from(h)..=u32::from(h) + 45 {
        let tip = BlockHeight::from(tip);
        st.wallet_mut().update_chain_tip(tip).unwrap();
        for asked in serve(&mut st, h, tip, service) {
            seen.push((u32::from(tip) - u32::from(h), asked));
        }
    }
    (seen, st, txid)
}

fn expected(txid: TxId) -> Vec<(u32, TxId)> {
    (0..WINDOW)
        .chain([EXPIRY_DELTA])
        .map(|offset| (offset, txid))
        .collect()
}

#[test]
fn replies_do_not_change_which_tips_are_polled() {
    let (honest, honest_st, txid) = transcript(Service::Honest { mined: 2 });
    let (forging, forging_st, _) = transcript(Service::Forging { at: 0 });
    let (unreadable, _, _) = transcript(Service::Unreadable);
    let (coverage, _, _) = transcript(Service::CoverageIncomplete);

    assert_eq!(honest, expected(txid), "honest service, mined at h + 2");
    assert_eq!(forging, expected(txid), "service forging mined at h");
    assert_eq!(unreadable, expected(txid), "unreadable rows");
    assert_eq!(coverage, expected(txid), "coverage incomplete throughout");

    // The first conclusive answer stands; the later polls are sent and discarded.
    let h = fixture().1;
    assert_eq!(honest_st.wallet().get_tx_height(txid).unwrap(), Some(h + 2));
    assert_eq!(forging_st.wallet().get_tx_height(txid).unwrap(), Some(h));
}

#[test]
fn a_poll_is_due_at_most_once_per_tip() {
    let (mut st, h) = fixture();
    let txid = TxId::from_bytes([8; 32]);
    queue(&st, txid, 0);
    assert_eq!(private_work(&st, txid).len(), 1);
    // A request outcome records nothing: the poll stays due at this tip.
    assert_eq!(private_work(&st, txid).len(), 1);
    st.wallet_mut()
        .db_mut()
        .record_private_status_poll(txid, h)
        .unwrap();
    assert!(private_work(&st, txid).is_empty(), "polled at this tip");
    assert!(private_work(&st, txid).is_empty(), "polled at this tip");
    st.wallet_mut().update_chain_tip(h + 1).unwrap();
    assert_eq!(
        private_work(&st, txid).len(),
        1,
        "due again at the next tip"
    );
}

#[test]
fn work_stays_due_after_mining_and_is_marked_settled() {
    let (mut st, h) = fixture();
    let txid = TxId::from_bytes([9; 32]);
    queue(&st, txid, 0);
    let work = private_work(&st, txid);
    assert_eq!(work.len(), 1);
    assert!(!settled(work[0]));
    serve(&mut st, h, h, Service::Forging { at: 0 });
    st.wallet_mut().update_chain_tip(h + 1).unwrap();
    let work = private_work(&st, txid);
    assert_eq!(
        work.len(),
        1,
        "a mined transaction is still polled in its window"
    );
    assert!(settled(work[0]));
}

#[test]
fn a_second_mined_answer_does_not_overwrite_the_first() {
    let (mut st, h) = fixture();
    let txid = TxId::from_bytes([10; 32]);
    queue(&st, txid, 0);
    // Heights above the scanned blocks, so neither answer links a block.
    st.wallet_mut().update_chain_tip(h + 10).unwrap();
    st.wallet_mut()
        .set_transaction_status(txid, TransactionStatus::Mined(h + 3))
        .unwrap();
    st.wallet_mut()
        .set_transaction_status(txid, TransactionStatus::Mined(h + 5))
        .unwrap();
    assert_eq!(st.wallet().get_tx_height(txid).unwrap(), Some(h + 3));
}

#[test]
fn the_expiry_poll_is_sent_mined_or_not_and_settles_an_expired_transaction() {
    // Mined at h + 1: still asked at the expiry height.
    let (mut st, h) = fixture();
    let mined = TxId::from_bytes([11; 32]);
    queue(&st, mined, u32::from(h) + EXPIRY_DELTA);
    let mut seen = vec![];
    for tip in u32::from(h)..=u32::from(h) + 45 {
        let tip = BlockHeight::from(tip);
        st.wallet_mut().update_chain_tip(tip).unwrap();
        if !serve(&mut st, h, tip, Service::Honest { mined: 1 }).is_empty() {
            seen.push(u32::from(tip) - u32::from(h));
        }
    }
    assert_eq!(seen.last(), Some(&EXPIRY_DELTA));
    assert_eq!(st.wallet().get_tx_height(mined).unwrap(), Some(h + 1));

    // Never mined: the window's answers are not conclusive, the expiry poll's is.
    let (mut st, h) = fixture();
    let never = TxId::from_bytes([12; 32]);
    queue(&st, never, u32::from(h) + EXPIRY_DELTA);
    let mut seen = vec![];
    for tip in u32::from(h)..=u32::from(h) + 45 {
        let tip = BlockHeight::from(tip);
        st.wallet_mut().update_chain_tip(tip).unwrap();
        if !serve(&mut st, h, tip, Service::NotFound).is_empty() {
            seen.push(u32::from(tip) - u32::from(h));
        }
        if tip < h + EXPIRY_DELTA {
            assert!(queued(&st, never), "pending at offset {}", tip - h);
        }
    }
    assert_eq!(seen, (0..WINDOW).chain([EXPIRY_DELTA]).collect::<Vec<_>>());
    assert!(!queued(&st, never), "settled as expired by the expiry poll");
    let expired_at: Option<u32> = st
        .wallet()
        .conn()
        .query_row(
            "SELECT confirmed_unmined_at_height FROM transactions WHERE txid = ?1",
            [never.as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(expired_at, Some(u32::from(h) + EXPIRY_DELTA));
}

#[test]
fn an_unresolved_transaction_leaves_automatic_work_but_stays_pending() {
    let (mut st, h) = fixture();
    let txid = TxId::from_bytes([13; 32]);
    queue(&st, txid, 0);
    let mut seen = vec![];
    for tip in u32::from(h)..=u32::from(h) + 30 {
        let tip = BlockHeight::from(tip);
        st.wallet_mut().update_chain_tip(tip).unwrap();
        if !serve(&mut st, h, tip, Service::CoverageIncomplete).is_empty() {
            seen.push(u32::from(tip) - u32::from(h));
        }
    }
    assert_eq!(seen, (0..WINDOW).collect::<Vec<_>>());
    assert!(queued(&st, txid));
    assert!(matches!(
        st.wallet().transaction_status_work_for(txid).unwrap(),
        TransactionStatusWork::Private(_)
    ));
}

#[test]
fn the_window_survives_a_reopen() {
    let (mut st, h) = fixture();
    let txid = TxId::from_bytes([14; 32]);
    queue(&st, txid, 0);
    for tip in u32::from(h)..u32::from(h) + 3 {
        let tip = BlockHeight::from(tip);
        st.wallet_mut().update_chain_tip(tip).unwrap();
        serve(&mut st, h, tip, Service::Unreadable);
    }
    let reopen = |st: &State| {
        let conn = rusqlite::Connection::open(st.wallet().conn().path().unwrap()).unwrap();
        crate::WalletDb::from_connection(conn, *st.network(), (), ())
            .with_status_mode(TransactionStatusMode::Private)
            .with_transparent_ledger_mode(
                zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode::Public,
            )
    };
    let has = |db: &crate::WalletDb<rusqlite::Connection, LocalNetwork, (), ()>| {
        db.transaction_status_work()
            .unwrap()
            .iter()
            .any(|work| work.txid() == txid)
    };
    assert!(!has(&reopen(&st)), "polled at h + 2 before the reopen");
    st.wallet_mut().update_chain_tip(h + WINDOW - 1).unwrap();
    assert!(has(&reopen(&st)), "the last tip of the window");
    st.wallet_mut().update_chain_tip(h + WINDOW).unwrap();
    assert!(!has(&reopen(&st)), "past the window");
}

#[test]
fn a_rewind_that_requeues_reconfirmation_opens_a_new_window() {
    let (mut st, prior) = fixture();
    let (mined_at, _) = st.generate_empty_block();
    st.scan_cached_blocks(mined_at, 1);
    let txid = TxId::from_bytes([15; 32]);
    queue(&st, txid, 0);
    serve(&mut st, mined_at, mined_at, Service::Forging { at: 0 });
    assert_eq!(st.wallet().get_tx_height(txid).unwrap(), Some(mined_at));
    let later = mined_at + 2 * WINDOW;
    st.wallet_mut().update_chain_tip(later).unwrap();
    assert!(private_work(&st, txid).is_empty(), "past the first window");

    st.wallet_mut().db_mut().truncate_to_height(prior).unwrap();
    assert_eq!(st.wallet().get_tx_height(txid).unwrap(), None);
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let mut seen = vec![];
    for offset in 0..2 * WINDOW {
        let at = tip + offset;
        st.wallet_mut().update_chain_tip(at).unwrap();
        if !serve(&mut st, tip, at, Service::CoverageIncomplete).is_empty() {
            seen.push(offset);
        }
    }
    assert_eq!(seen, (0..WINDOW).collect::<Vec<_>>());
}
