//! The filter trigger and the account marker: which ranges commit, how far the marker
//! moves, what a hit queues, refund aging against the marker, receive hand-out's freshness
//! gate, and the status fields that say when a round is due.
use super::discovery::*;
use super::*;
use zcash_client_backend::data_api::one_time_ivk::restore::{
    FilterOutcome, FilterSpan, RecoveryStatus,
};

/// Ironwood activation on the test network, where filter coverage starts.
fn activation(st: &State) -> BlockHeight {
    BlockHeight::from(crate::wallet::one_time_ivk::restore::queue::activation(
        st.network(),
    ))
}

/// Receive index `index`.
fn receive(index: u64) -> KeyId {
    KeyId::new(Purpose::Receive, index)
}

/// Commits `span` with `hits` under the account's current token.
fn record(
    st: &mut State,
    account: AccountUuid,
    span: &FilterSpan,
    hits: &[(BlockHeight, KeyId)],
) -> FilterOutcome {
    let token = status(st.wallet().db(), account).token;
    st.wallet_mut()
        .db_mut()
        .record_one_time_filter_span(account, token, span, hits)
        .unwrap()
}

/// The span over the cached chain from just past the account's frontier, or activation,
/// through the last cached block, under the account's revision.
fn next_span(st: &State, account: AccountUuid) -> FilterSpan {
    let state = status(st.wallet().db(), account);
    let from = state
        .filter_frontier
        .map_or(activation(st), |frontier| frontier.height + 1);
    span_over(
        st.wallet().db(),
        state.token.history_revision,
        &blocks_above(st, from - 1),
    )
}

/// Commits [`next_span`] with `hits`.
fn advance(st: &mut State, account: AccountUuid, hits: &[(BlockHeight, KeyId)]) -> FilterOutcome {
    let span = next_span(st, account);
    record(st, account, &span, hits)
}

/// Begins a round at a publication ending at the tip, without a complete check, and answers
/// every due lookup, returning how many ran.
fn run_pir(st: &mut State, account: AccountUuid) -> usize {
    let publication = RecoveryPublication {
        history_revision: status(st.wallet().db(), account).token.history_revision,
        ..publication_at(st, tip(st).height)
    };
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    for lookups in 0..256 {
        if !answer_lookup(st, account, publication) {
            return lookups;
        }
    }
    panic!("recovery did not converge");
}

/// Starts a complete check at the tip and answers it, returning how many lookups ran.
fn complete(st: &mut State, account: AccountUuid) -> usize {
    let publication = publication_at(st, tip(st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    run_pir(st, account)
}

/// Reserves the lowest eligible receive address, running its issuance lookup first when it
/// is due, and returns the key with how many lookups ran.
fn reserve_receive(st: &mut State, account: AccountUuid) -> (KeyId, usize) {
    let mut lookups = 0;
    for _ in 0..4 {
        match st
            .wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, clock_now())
            .unwrap()
        {
            Ok(key) => return (key.key_id(), lookups),
            Err(ReservationPolicy::ReceiveHistory) => lookups += run_pir(st, account),
            Err(other) => panic!("{other:?}"),
        }
    }
    panic!("issuance did not settle");
}

/// The keys whose lookups are due.
fn due(st: &State, account: AccountUuid) -> Vec<KeyId> {
    status(st.wallet().db(), account)
        .lookups
        .iter()
        .map(|w| w.work.key)
        .collect()
}

/// The status read against an inventory ending at `end`.
fn status_at(st: &State, account: AccountUuid, end: BlockHeight) -> RecoveryStatus {
    assert_no_stall(st.wallet().db(), account);
    st.wallet()
        .db()
        .one_time_recovery(account, clock_now(), Some(end))
        .unwrap()
}

/// A span must continue the marker exactly. A replay from inside it or a span leaving a gap
/// after it is an error, even with the wallet's own block as its parent, and a wrong parent
/// is a mismatch. Nothing changes.
#[test]
fn only_an_exact_continuation_of_the_marker_commits() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(4);
    let account = st.test_account().unwrap().id();
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    let frontier = tip(&st).height;
    st.generate_and_scan_empty_blocks(3);
    let token = status(st.wallet().db(), account).token;
    let replay = span_over(st.wallet().db(), 0, &blocks_above(&st, frontier - 3));
    let gap = span_over(st.wallet().db(), 0, &blocks_above(&st, frontier + 1));
    for span in [replay, gap] {
        assert!(
            st.wallet_mut()
                .db_mut()
                .record_one_time_filter_span(account, token, &span, &[])
                .is_err()
        );
    }
    let mut wrong = next_span(&st, account);
    wrong.parent = BlockHash([9; 32]);
    assert_eq!(
        record(&mut st, account, &wrong, &[]),
        FilterOutcome::Mismatch
    );
    let state = status(st.wallet().db(), account);
    assert_eq!(state.filter_frontier.map(|f| f.height), Some(frontier));
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
}

/// A span whose end block hash disagrees with the wallet's own block is a mismatch and
/// changes nothing.
#[test]
fn a_span_whose_end_disagrees_with_the_wallet_is_a_mismatch() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(2);
    let account = st.test_account().unwrap().id();
    let mut wrong = next_span(&st, account);
    wrong.end.hash = BlockHash([9; 32]);
    assert_eq!(
        record(&mut st, account, &wrong, &[]),
        FilterOutcome::Mismatch
    );
    assert_eq!(status(st.wallet().db(), account).filter_frontier, None);
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
}

/// A span ending above the wallet's fully scanned block waits, even when the wallet holds
/// its end block, however deep it is, and commits once the gap below it is scanned.
#[test]
fn a_span_above_the_fully_scanned_block_waits_until_the_gap_is_scanned() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    let frontier = tip(&st).height;
    let (gap, _) = st.generate_empty_block();
    st.generate_empty_block();
    let (third, _) = st.generate_empty_block();
    st.scan_cached_blocks(third, 1);
    for _ in 0..1_000 {
        st.generate_empty_block();
    }
    st.scan_cached_blocks(third + 1, 1_000);
    assert_eq!(
        tip(&st).height,
        frontier,
        "the gap holds the fully scanned block"
    );
    let span = span_over(st.wallet().db(), 0, &blocks_above(&st, frontier));
    assert_eq!(record(&mut st, account, &span, &[]), FilterOutcome::Wait);
    st.scan_cached_blocks(gap, 2);
    assert_eq!(
        record(&mut st, account, &span, &[]),
        FilterOutcome::Committed
    );
    assert_eq!(
        status(st.wallet().db(), account).filter_frontier,
        Some(tip(&st))
    );
}

/// A complete check moves the marker to the highest block at or below both its
/// publication's end and the wallet's fully scanned block. Behind the tip it stops at the
/// end, since only its lookups read that far, and the next span continues from there.
/// Above a scan gap it stops at the fully scanned block, since a block stored above the gap
/// may not be on the wallet's chain.
#[test]
fn a_complete_check_caps_the_marker_at_its_end_and_the_fully_scanned_block() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks(4);
    let end = tip(&st).height - 2;
    let publication = publication_at(&st, end);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    let marker = status(st.wallet().db(), account).filter_frontier;
    assert_eq!(marker.map(|f| f.height), Some(end));
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);

    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let scanned = tip(&st);
    st.generate_empty_block();
    let (above, _) = st.generate_empty_block();
    st.scan_cached_blocks(above, 1);
    assert_eq!(tip(&st), scanned, "the gap holds the fully scanned block");
    let publication = publication_at(&st, above);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    assert_eq!(
        status(st.wallet().db(), account).filter_frontier,
        Some(scanned)
    );
}

/// A reorg moves the marker back to the fork and reopens the histories above it, so a
/// round is due, and the next span continues from the fork. A rewind that rolls back
/// nothing leaves no round due.
#[test]
fn a_reorg_moves_the_marker_back_to_the_fork() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(4);
    let account = st.test_account().unwrap().id();
    assert_eq!(complete(&mut st, account), 4);
    let height = tip(&st).height;
    tx(st.wallet_mut().db_mut(), |c, _| {
        crate::wallet::one_time_rewind::truncate(c, height)
    })
    .unwrap();
    assert!(
        !status(st.wallet().db(), account).round_due,
        "nothing above the tip"
    );
    let floor = height - 2;
    st.truncate_to_height(floor);
    let state = status(st.wallet().db(), account);
    assert_eq!(state.filter_frontier.map(|f| f.height), Some(floor));
    assert!(state.round_due && !state.lookups.is_empty());
    st.generate_and_scan_empty_blocks(3);
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
}

/// A newer revision clears the marker, and with no marker a round is due and runs a
/// complete check, which sets the marker again.
#[test]
fn no_marker_means_a_complete_check() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(complete(&mut st, account), 4);
    assert!(!status(st.wallet().db(), account).round_due);
    st.generate_and_scan_empty_blocks(1);
    let mut corrected = next_span(&st, account);
    corrected.revision = 1;
    assert_eq!(
        record(&mut st, account, &corrected, &[]),
        FilterOutcome::Restart
    );
    let state = status(st.wallet().db(), account);
    assert_eq!(state.filter_frontier, None);
    assert_eq!(state.token.history_revision, 1);
    assert!(state.round_due);
    let publication = RecoveryPublication {
        history_revision: 1,
        ..publication_at(&st, tip(&st).height)
    };
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    run_pir(&mut st, account);
    let state = status(st.wallet().db(), account);
    assert_eq!(state.filter_frontier, Some(tip(&st)));
    assert!(!state.round_due);
}

/// A hit past the key's checked history queues a lookup from its history start, which
/// joins the completed history, through the hit, marked `INVALIDATED`, and makes a round
/// due. A hit inside checked history settles with no query.
#[test]
fn a_hit_queues_from_the_history_start_and_settles_inside_checked_history() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(1);
    let account = st.test_account().unwrap().id();
    assert_eq!(complete(&mut st, account), 4);
    let checked = tip(&st).height;
    let paid = pay_candidate(&mut st, receive(2));
    assert!(!status(st.wallet().db(), account).round_due);
    assert_eq!(
        advance(&mut st, account, &[(paid.height, receive(2))]),
        FilterOutcome::Committed
    );
    let work = work_of(&st, receive(2));
    assert_eq!((work.from, work.through), (checked + 1, paid.height));
    let reasons: u8 = value(
        st.wallet().conn(),
        "SELECT l.reasons FROM ironwood_one_time_lookups l JOIN ironwood_one_time_keys k
             ON k.id = l.one_time_key_id WHERE k.purpose = 1 AND k.key_index = ?1",
        [2u64.to_be_bytes()],
    );
    assert_ne!(reasons & 4, 0);
    assert!(status(st.wallet().db(), account).round_due);
    run_pir(&mut st, account);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);

    // Filters lagging PIR history: a hit on I1 inside the history its bootstrap checked.
    let lagging: (u32, [u8; 32]) = row(
        st.wallet().conn(),
        "SELECT height, hash FROM blocks WHERE height = ?1",
        [u32::from(checked) - 1],
    );
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_recovery SET filter_height = ?1, filter_hash = ?2",
        rusqlite::params![lagging.0, lagging.1],
    );
    assert_eq!(
        advance(&mut st, account, &[(checked, receive(1))]),
        FilterOutcome::Committed
    );
    assert!(due(&st, account).is_empty());
    assert!(!status(st.wallet().db(), account).round_due);
}

/// A complete check reads a paid key again from its last PIR check, so it finds a repeat
/// payment after it without a manual history check.
#[test]
fn a_complete_check_finds_a_repeat_payment_to_a_paid_key() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    pay_candidate(&mut st, receive(0));
    complete(&mut st, account);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    let frontier = status(st.wallet().db(), account)
        .filter_frontier
        .unwrap()
        .height;
    pay_candidate(&mut st, receive(0));
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    assert_eq!(work_of(&st, receive(0)).from, frontier + 1);
    run_pir(&mut st, account);
    assert_eq!(one_time_notes(&st), [(100_000, false), (100_000, false)]);
}

/// Receive hand-out waits while the marker is more than 10 blocks behind the chain tip,
/// even with every lookup complete, and the status asks for the round that catches the
/// marker up. Once filters catch up, it hands out the address and no round is due.
#[test]
fn receive_hand_out_waits_for_a_current_marker() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(complete(&mut st, account), 4);
    st.generate_and_scan_empty_blocks(10);
    assert!(!status(st.wallet().db(), account).round_due);
    st.generate_and_scan_empty_blocks(1);
    let held = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, clock_now())
        .unwrap();
    assert!(matches!(held, Err(ReservationPolicy::ReceiveHistory)));
    let state = status(st.wallet().db(), account);
    assert!(state.round_due && state.lookups.is_empty());
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    assert!(!status(st.wallet().db(), account).round_due);
    assert_eq!(reserve_receive(&mut st, account), (receive(0), 0));
}

/// Blocks between Ironwood activation and [`late_wallet`]'s birthday, more than the memo
/// refund window.
const LATE: u32 = 200_000;

/// A wallet born [`LATE`] blocks after Ironwood activation and scanned through one block,
/// so the memo refund window can lie below its birthday. Its receive window's bootstrap
/// lookups are already answered.
fn late_wallet() -> State {
    use zcash_client_backend::data_api::{chain::ChainState, testing::InitialChainState};
    let mut st = TestBuilder::new()
        .with_network(ironwood_network())
        .with_data_store_factory(TestDbFactory::file_backed())
        .with_block_cache(crate::testing::BlockCache::new())
        .with_initial_chain_state(|_, network| InitialChainState {
            chain_state: ChainState::empty(
                network
                    .activation_height(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
                    .unwrap()
                    + LATE
                    - 1,
                BlockHash([0; 32]),
            ),
            prior_sapling_roots: vec![],
            prior_orchard_roots: vec![],
        })
        .with_account_having_current_birthday()
        .build();
    st.generate_and_scan_empty_blocks(1);
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .enable_one_time_recovery(account)
        .unwrap();
    assert_eq!(run_pir(&mut st, account), 4);
    st
}

/// Starts a complete check at the tip without answering it, which moves the marker there,
/// and returns the tip.
fn mark_tip(st: &mut State, account: AccountUuid) -> BlockHeight {
    let end = tip(st).height;
    let publication = publication_at(st, end);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    end
}

/// The window's blocks, as the memo refund window spans them at 75-second spacing.
fn days(days: u32) -> u32 {
    days * 24 * 60 * 60 / 75
}

/// Refund key `index`.
fn refund(index: u64) -> KeyId {
    KeyId::new(Purpose::Refund, index)
}

/// The window is 90 days of chain time, counting each height at its own target spacing.
#[test]
fn the_memo_refund_window_spans_90_days_of_chain_time() {
    use crate::wallet::one_time_ivk::restore::queue::{MEMO_REFUND_WINDOW, watch_end_sql};
    use zcash_protocol::zip318::BlockSpacing;
    assert_eq!(MEMO_REFUND_WINDOW, days(90));
    let conn = Connection::open_in_memory().unwrap();
    let end = |spacing: BlockSpacing, funding: u32| -> u32 {
        value(
            &conn,
            &format!(
                "SELECT {} FROM (SELECT ?1 AS funding_height) k",
                watch_end_sql(spacing)
            ),
            [funding],
        )
    };
    let nu7 = 1_000_000;
    let spacings = [
        BlockSpacing::UNIFORM,
        BlockSpacing::with_nu7_activation(BlockHeight::from(nu7)),
    ];
    for spacing in spacings {
        for funding in [0, nu7 - days(90) - 1, nu7 - days(45), nu7, nu7 + 7] {
            let advanced = spacing.advance(funding.into(), MEMO_REFUND_WINDOW);
            assert_eq!(end(spacing, funding), u32::from(advanced), "{funding}");
        }
    }
    // After NU7, 90 days spans three times as many 25-second blocks.
    assert_eq!(end(spacings[1], nu7) - nu7, 3 * days(90));
}

/// A memo-only refund key ages out of monitoring once the account's marker passes 90 days
/// after its funding, and not before. With no marker it is not aged.
#[test]
fn memo_only_refund_keys_age_against_the_marker() {
    let mut st = late_wallet();
    let account = st.test_account().unwrap().id();
    let tip = tip(&st).height;
    recover(
        st.wallet_mut().db_mut(),
        account,
        refund(0),
        tip - days(100),
    );
    recover(st.wallet_mut().db_mut(), account, refund(1), tip - days(45));
    assert_eq!(
        refunds_watched(&st, account),
        [0, 1],
        "no marker ages nothing"
    );
    mark_tip(&mut st, account);
    assert_eq!(refunds_watched(&st, account), [1]);
}

/// A funding memo learned after its 90-day window has passed still gets its bootstrap
/// lookup over that window. The key retires from monitoring at once, but the pending lookup
/// still runs, so a refund already paid is found.
#[test]
fn a_late_memo_older_than_90_days_still_gets_its_lookup() {
    let mut st = late_wallet();
    let account = st.test_account().unwrap().id();
    mark_tip(&mut st, account);
    pay_candidate(&mut st, refund(0));
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    let funded = tip(&st).height - days(100);
    recover(st.wallet_mut().db_mut(), account, refund(0), funded);
    assert_eq!(refunds_watched(&st, account), Vec::<u64>::new());
    assert_eq!(due(&st, account), [refund(0)]);
    assert_eq!(run_pir(&mut st, account), 1);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert_eq!(refunds_watched(&st, account), Vec::<u64>::new());
}

/// A round is due while the seed walk waits for its first publication, even with every
/// lookup backing off, and never for an account that isn't enabled.
#[test]
fn a_round_is_due_while_the_seed_walk_waits_for_a_publication() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    assert!(!status(st.wallet().db(), account).round_due);
    st.wallet_mut()
        .db_mut()
        .enable_one_time_recovery(account)
        .unwrap();
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_lookups SET next_attempt_at = ?1",
        [i64::MAX],
    );
    let state = status(st.wallet().db(), account);
    assert!(
        state.lookups.is_empty() && state.round_due,
        "the walk needs a publication"
    );
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_lookups SET next_attempt_at = 0",
        [],
    );
    assert_eq!(complete(&mut st, account), 4);
    assert!(!status(st.wallet().db(), account).round_due);
}

/// I0 to I3 with hits past the tip `end` they were bootstrapped to, so their lookups wait
/// for a later publication, and I8, after them in queue order, with a lookup through
/// `end`. Returns the wallet, account and `end`.
fn four_waiting_and_a_fifth() -> (State, AccountUuid, BlockHeight) {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let end = tip(&st).height;
    recover(st.wallet_mut().db_mut(), account, key8(), end);
    st.generate_and_scan_empty_blocks(2);
    let hit = tip(&st).height;
    let hits: Vec<_> = (0..4).map(|i| (hit, receive(i))).collect();
    assert_eq!(advance(&mut st, account, &hits), FilterOutcome::Committed);
    let unbounded = status(st.wallet().db(), account);
    let keys: Vec<_> = unbounded.lookups.iter().map(|w| w.work.key).collect();
    assert_eq!(
        keys,
        (0..4).map(receive).collect::<Vec<_>>(),
        "I8 is hidden"
    );
    (st, account, end)
}

/// Four lookups waiting for a later publication don't hide a fifth the inventory can
/// answer, and the read says the others wait for a publication.
#[test]
fn four_lookups_waiting_on_a_publication_do_not_hide_a_runnable_fifth() {
    let (st, account, end) = four_waiting_and_a_fifth();
    let state = status_at(&st, account, end);
    let keys: Vec<_> = state.lookups.iter().map(|w| w.work.key).collect();
    assert_eq!(keys, [key8()]);
    assert!(state.waits_for_publication && !state.waits_for_retry);
}

/// With the runnable lookup backing off, the read reports the retry delay as well as the
/// lookups waiting for a publication, so a caller can wait out the backoff first.
#[test]
fn a_backoff_plus_waiting_lookups_reports_a_backoff() {
    let (mut st, account, end) = four_waiting_and_a_fifth();
    let work = status_at(&st, account, end).lookups[0].clone();
    st.wallet_mut()
        .db_mut()
        .defer_one_time_lookup(account, &work, clock_now())
        .unwrap();
    let state = status_at(&st, account, end);
    assert!(state.lookups.is_empty());
    assert!(state.waits_for_retry && state.waits_for_publication);
}

/// Starting a history check makes a backed-off lookup due again, so a check the user runs
/// after an outage doesn't wait out the outage's backoff.
#[test]
fn a_history_check_retries_a_backed_off_lookup_now() {
    let (mut st, account, end) = four_waiting_and_a_fifth();
    let work = status_at(&st, account, end).lookups[0].clone();
    let publication = publication_at(&st, end);
    let db = st.wallet_mut().db_mut();
    db.defer_one_time_lookup(account, &work, clock_now())
        .unwrap();
    let backing_off = |db: &mut _| {
        tx(db, |conn, _| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM ironwood_one_time_lookups WHERE next_attempt_at > 0",
                [],
                |r| r.get::<_, u32>(0),
            )?)
        })
        .unwrap()
    };
    assert_eq!(backing_off(db), 1);
    assert!(
        db.check_one_time_history(account, publication, None)
            .unwrap()
    );
    assert_eq!(backing_off(db), 0);
}

/// A payment to I8 whose history was read through the tip, returned, with its payload built
/// two blocks later and waiting for admission because the scan left the tip uncovered, in
/// the scanned wallet `st`.
fn waiting_witness_in(mut st: State) -> (State, BlockHeight) {
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    let read = tip(&st).height;
    recover(st.wallet_mut().db_mut(), account, key8(), candidate.height);
    let publication = publication_at(&st, read);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    let work = work_of(&st, key8());
    st.generate_and_scan_empty_blocks(2);
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_journal_coverage SET end_height = ?1 WHERE end_height > ?1",
        [u32::from(tip(&st).height)],
    );
    let later = publication_at(&st, tip(&st).height).end;
    let records = history(work.work.receiver, &[&candidate]);
    let page = whole_at(&st, publication, records, later);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.record_one_time_lookup(account, &work, &page, clock_now())
            .unwrap()
    );
    assert!(one_time_notes(&st).is_empty(), "admission waits");
    (st, read)
}

/// `awaiting_admission` counts a witnessed payment while admission waits for the rescan,
/// only for its own account, and returns to zero once the payment is admitted.
#[test]
fn awaiting_admission_counts_a_witnessed_payment_until_it_is_admitted() {
    let waiting = |st: &State, account| {
        st.wallet()
            .db()
            .one_time_recovery(account, clock_now(), None)
            .unwrap()
            .awaiting_admission
    };
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    // Another account born at the tip, so it adds no history to scan.
    let born = st.latest_cached_block().unwrap().chain_state().clone();
    let birthday = zcash_client_backend::data_api::AccountBirthday::from_parts(born, None);
    let (other, _) = st
        .wallet_mut()
        .db_mut()
        .create_account("other", &SecretVec::new(vec![9; 32]), &birthday, None)
        .unwrap();
    st.wallet_mut()
        .db_mut()
        .enable_one_time_recovery(other)
        .unwrap();
    assert_eq!(waiting(&st, account), 0);
    let (mut st, _) = waiting_witness_in(st);
    // The rescan admission queued for the uncovered tip.
    let (uncovered, end): (u32, u32) = row(
        st.wallet().conn(),
        "SELECT block_range_start, block_range_end FROM scan_queue WHERE priority != 10",
        [],
    );
    assert_eq!((waiting(&st, account), waiting(&st, other)), (1, 0));
    st.scan_cached_blocks(uncovered.into(), (end - uncovered) as usize);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert_eq!(waiting(&st, account), 0);
}

/// A rewind above a waiting payment's block but below its payload's anchor voids the
/// payload. The payment's key is read again, so a round is due, the next round fetches a
/// fresh payload, and the payment is admitted.
#[test]
fn a_rewind_that_voids_a_waiting_witness_rereads_the_payment() {
    let (mut st, read) = waiting_witness_in(scanned_wallet());
    let account = st.test_account().unwrap().id();
    st.truncate_to_height(read + 1);
    assert_eq!(candidates(&st), 1);
    let state = status(st.wallet().db(), account);
    assert!(state.round_due && state.awaiting_admission == 0);
    let reopened: bool = value(
        st.wallet().conn(),
        "SELECT l.read_complete = 0 AND l.reasons & 3 != 0 AND l.next_attempt_at = 0
         FROM ironwood_one_time_lookups l JOIN ironwood_one_time_keys k
             ON k.id = l.one_time_key_id WHERE k.purpose = 1 AND k.key_index = ?1",
        [key8().index().to_be_bytes()],
    );
    assert!(reopened, "the payment's key is read again");
    st.generate_and_scan_empty_blocks(2);
    run_pir(&mut st, account);
    // Admission may queue a rescan of a block the scan left uncovered.
    let rescans: Vec<(u32, u32)> = rows(
        st.wallet().conn(),
        "SELECT block_range_start, block_range_end FROM scan_queue WHERE priority != 10",
        [],
    );
    for (start, end) in rescans {
        st.scan_cached_blocks(start.into(), (end - start) as usize);
    }
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert_eq!(candidates(&st), 0);
}
