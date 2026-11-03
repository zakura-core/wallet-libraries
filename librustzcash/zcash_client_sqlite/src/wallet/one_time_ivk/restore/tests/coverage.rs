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
            .prepare_receive_reservation(account, clock_now(), NO_LIVE_TIP)
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
        .prepare_receive_reservation(account, clock_now(), NO_LIVE_TIP)
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

/// A restored wallet synced two blocks past the end of the publication it returns, whose
/// account turns recovery on at the tip and accepts that publication first, as a round
/// does, without a complete check.
fn first_recovery() -> (State, AccountUuid, RecoveryPublication) {
    let mut st = restored_wallet();
    st.generate_and_scan_empty_blocks(4);
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height - 2);
    let db = st.wallet_mut().db_mut();
    db.enable_one_time_recovery(account).unwrap();
    assert!(
        db.begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    (st, account, publication)
}

/// `account`'s receive lookups as (index, target, completed through).
fn receive_lookups(st: &State, account: AccountUuid) -> Vec<(u64, Option<u32>, Option<u32>)> {
    let sql = "SELECT k.key_index, l.target_height, l.done_height
        FROM ironwood_one_time_lookups l JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
        JOIN accounts a ON a.id = k.account_id WHERE a.uuid = ?1 AND k.purpose = 1
        ORDER BY k.key_index";
    rows::<(Vec<u8>, Option<u32>, Option<u32>)>(st.wallet().conn(), sql, [account.0])
        .into_iter()
        .map(|(i, t, d)| (u64::from_be_bytes(i.try_into().unwrap()), t, d))
        .collect()
}

/// Turning recovery on for two accounts synced past the publication reads each one's
/// first receive window only through the publication and places its marker there, so its
/// first address is issued without the publication reaching the tip. The PIR history
/// records only what was read, the seed walk finishes, and filters cover the blocks after.
#[test]
fn a_first_recovery_reads_its_bootstraps_through_the_publication() {
    let mut st = restored_wallet();
    let born = st.latest_cached_block().unwrap().chain_state().clone();
    let birthday = zcash_client_backend::data_api::AccountBirthday::from_parts(born, None);
    let (other, _) = st
        .wallet_mut()
        .db_mut()
        .create_account("other", &SecretVec::new(vec![9; 32]), &birthday, None)
        .unwrap();
    st.generate_and_scan_empty_blocks(4);
    let tip_height = u32::from(tip(&st).height);
    let end = tip(&st).height - 2;
    let publication = publication_at(&st, end);
    for account in [st.test_account().unwrap().id(), other] {
        let db = st.wallet_mut().db_mut();
        db.enable_one_time_recovery(account).unwrap();
        let queued: Vec<_> = (0..4).map(|i| (i, Some(tip_height), None)).collect();
        assert_eq!(receive_lookups(&st, account), queued);
        let db = st.wallet_mut().db_mut();
        assert!(
            db.begin_one_time_recovery(account, publication, false)
                .unwrap()
        );
        let state = status_at(&st, account, end);
        assert_eq!(state.filter_frontier.map(|f| f.height), Some(end));
        let runnable: Vec<_> = state
            .lookups
            .iter()
            .map(|w| (w.work.key, w.through))
            .collect();
        assert_eq!(
            runnable,
            (0..4).map(|i| (receive(i), end)).collect::<Vec<_>>()
        );
        drain(&mut st, account, publication);
        let done: Vec<_> = (0..4).map(|i| (i, None, Some(u32::from(end)))).collect();
        assert_eq!(receive_lookups(&st, account), done);
        let state = status(st.wallet().db(), account);
        assert!(state.restore_complete && state.lookups.is_empty());
        let issued = st
            .wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, clock_now(), NO_LIVE_TIP)
            .unwrap();
        assert_eq!(issued.map(|k| k.key_id()), Ok(receive(0)));
        assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
        assert_eq!(
            status(st.wallet().db(), account).filter_frontier,
            Some(tip(&st))
        );
    }
}

/// Another device paid I0 just past the publication before this one turned recovery on.
/// The first lookup reads only through the publication, so it doesn't see the payment, but
/// filters from the marker watch I0: their hit holds I0 until a publication reaches the
/// payment, which is then recovered once.
#[test]
fn a_first_recovery_finds_a_payment_past_its_publication_through_filters() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks(1);
    let end = tip(&st).height;
    let paid = pay_candidate(&mut st, receive(0));
    st.generate_and_scan_empty_blocks(1);
    let publication = publication_at(&st, end);
    let db = st.wallet_mut().db_mut();
    db.enable_one_time_recovery(account).unwrap();
    assert!(
        db.begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    assert_eq!(status_at(&st, account, end).lookups.len(), 4);
    // The publication ends before the payment, so each history it holds is empty.
    for _ in 0..4 {
        let work = status_at(&st, account, end).lookups[0].clone();
        let page = whole(publication, vec![]);
        let db = st.wallet_mut().db_mut();
        assert!(
            db.record_one_time_lookup(account, &work, &page, clock_now())
                .unwrap()
        );
    }
    assert!(status_at(&st, account, end).lookups.is_empty());
    assert!(one_time_notes(&st).is_empty());
    assert_eq!(
        advance(&mut st, account, &[(paid.height, receive(0))]),
        FilterOutcome::Committed
    );
    let held = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, clock_now(), NO_LIVE_TIP)
        .unwrap();
    assert!(matches!(held, Err(ReservationPolicy::ReceiveHistory)));
    let state = status_at(&st, account, end);
    assert!(state.lookups.is_empty() && state.waits_for_publication);
    run_pir(&mut st, account);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    complete(&mut st, account);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert_eq!(reserve_receive(&mut st, account).0, receive(1));
}

/// Only receive bootstraps read through a first publication. A funded refund key keeps
/// reading through the tip it was queued at.
#[test]
fn a_first_recovery_keeps_refund_targets() {
    let mut st = restored_wallet();
    st.generate_and_scan_empty_blocks(4);
    let account = st.test_account().unwrap().id();
    let tip_height = tip(&st).height;
    let publication = publication_at(&st, tip_height - 2);
    let db = st.wallet_mut().db_mut();
    db.enable_one_time_recovery(account).unwrap();
    recover(db, account, refund(0), tip_height - 3);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    assert_eq!(work_of(&st, receive(0)).through, publication.end.height);
    assert_eq!(work_of(&st, refund(0)).through, tip_height);
}

/// A first recovery whose seed already paid I0 reads I0 to I3 through the publication and
/// recovers the payment. That exposes I4 after the marker was placed, so I4 keeps the
/// frontier as its target and waits for a publication reaching it.
#[test]
fn an_index_a_first_recovery_exposes_keeps_the_frontier() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let paid = pay_candidate(&mut st, receive(0));
    st.generate_and_scan_empty_blocks(2);
    let tip_height = tip(&st).height;
    let publication = publication_at(&st, paid.height);
    let db = st.wallet_mut().db_mut();
    db.enable_one_time_recovery(account).unwrap();
    assert!(
        db.begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    drain_at(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert_eq!(work_of(&st, receive(4)).through, tip_height);
    let state = status_at(&st, account, paid.height);
    assert!(state.lookups.is_empty() && state.waits_for_publication);
    assert!(!state.restore_complete);
}

/// Answers `account`'s lookups in queue order while the next one is within `publication`.
fn drain_at(st: &mut State, account: AccountUuid, publication: RecoveryPublication) {
    for _ in 0..256 {
        let next = status(st.wallet().db(), account).lookups.first().cloned();
        if !next.is_some_and(|w| w.through <= publication.end.height) {
            return;
        }
        assert!(answer_lookup(st, account, publication));
    }
    panic!("fixture recovery did not converge");
}

/// A history reset and a lowered birthday both clear the marker, but neither is a first
/// recovery: a held reservation, a filter hit and the reopened histories keep their targets
/// past an older publication, and accepting it places no marker.
#[test]
fn a_cleared_marker_keeps_targets_past_the_publication() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(complete(&mut st, account), 4);
    assert_eq!(reserve_receive(&mut st, account).0, receive(0));
    st.generate_and_scan_empty_blocks(2);
    let hit = tip(&st).height;
    assert_eq!(
        advance(&mut st, account, &[(hit, receive(1))]),
        FilterOutcome::Committed
    );
    let publication = publication_at(&st, hit - 1);
    let accept = |st: &mut State| {
        assert!(
            st.wallet_mut()
                .db_mut()
                .begin_one_time_recovery(account, publication, false)
                .unwrap()
        );
        let state = status_at(st, account, publication.end.height);
        assert_eq!(state.filter_frontier, None);
        assert!(state.lookups.is_empty() && state.waits_for_publication);
    };
    st.wallet_mut()
        .db_mut()
        .reset_one_time_history(account)
        .unwrap();
    accept(&mut st);
    for key in [receive(0), receive(1)] {
        assert_eq!(work_of(&st, key).through, hit);
    }
    tx(st.wallet_mut().db_mut(), |conn, _| {
        crate::wallet::one_time_rewind::reopen_discovery(conn, account)
    })
    .unwrap();
    accept(&mut st);
    for index in 0..4 {
        assert_eq!(work_of(&st, receive(index)).through, hit);
    }
}

/// A history check started at the tip, then paused, keeps its frontier: a round at an older
/// publication places no marker, and the resumed check still needs history through the tip.
#[test]
fn a_paused_history_check_keeps_its_frontier_past_the_publication() {
    let mut st = restored_wallet();
    st.generate_and_scan_empty_blocks(4);
    let account = st.test_account().unwrap().id();
    let tip_height = tip(&st).height;
    let (older, latest) = (
        publication_at(&st, tip_height - 2),
        publication_at(&st, tip_height),
    );
    let db = st.wallet_mut().db_mut();
    db.enable_one_time_recovery(account).unwrap();
    assert!(db.check_one_time_history(account, latest, None).unwrap());
    let db = st.wallet_mut().db_mut();
    db.cancel_one_time_history(account).unwrap();
    assert!(db.begin_one_time_recovery(account, older, false).unwrap());
    assert!(db.check_one_time_history(account, older, None).unwrap());
    let state = status_at(&st, account, older.end.height);
    assert_eq!(state.filter_frontier, None);
    assert!(state.manual.is_some_and(|m| m.active));
    assert!(state.lookups.is_empty() && state.waits_for_publication);
    assert_eq!(work_of(&st, receive(0)).through, tip_height);
}

/// After a first recovery, its address is issued while the newest tip the wallet saved,
/// which can be past its scanned blocks, is within 10 blocks of the marker, and not at 11.
/// A span that fails, by a mismatch or by waiting for a block the wallet hasn't scanned,
/// leaves the marker where it was, and a span that commits lets the address be issued.
#[test]
fn a_first_recovery_issues_within_ten_blocks_of_the_newest_tip() {
    for (lag, issued) in [(10, true), (11, false)] {
        let (mut st, account, publication) = first_recovery();
        drain(&mut st, account, publication);
        let end = publication.end.height;
        let db = st.wallet_mut().db_mut();
        db.update_chain_tip(end + lag).unwrap();
        let reserved = db
            .prepare_receive_reservation(account, clock_now(), NO_LIVE_TIP)
            .unwrap();
        assert_eq!(reserved.is_ok(), issued, "{lag} blocks behind");
        if issued {
            continue;
        }
        assert!(matches!(reserved, Err(ReservationPolicy::ReceiveHistory)));
        let mut wrong = next_span(&st, account);
        wrong.end.hash = BlockHash([9; 32]);
        assert_eq!(
            record(&mut st, account, &wrong, &[]),
            FilterOutcome::Mismatch
        );
        st.generate_empty_block();
        let unscanned = next_span(&st, account);
        assert_eq!(
            record(&mut st, account, &unscanned, &[]),
            FilterOutcome::Wait
        );
        let state = status(st.wallet().db(), account);
        assert_eq!(state.filter_frontier.map(|f| f.height), Some(end));
        let held = st
            .wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, clock_now(), NO_LIVE_TIP)
            .unwrap();
        assert!(matches!(held, Err(ReservationPolicy::ReceiveHistory)));
        let scanned = tip(&st).height + 1;
        st.scan_cached_blocks(scanned, 1);
        assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
        assert_eq!(reserve_receive(&mut st, account), (receive(0), 0));
    }
}

/// A correction or a server reset before an account's first accepted publication leaves
/// nothing checked, so its untouched bootstraps still read only through that publication.
/// The hit the voided filters found keeps its target, so the obligations those events
/// carry are kept.
#[test]
fn a_reset_before_the_first_publication_keeps_its_obligations() {
    let mut st = restored_wallet();
    st.generate_and_scan_empty_blocks(4);
    let account = st.test_account().unwrap().id();
    let tip_height = tip(&st).height;
    st.wallet_mut()
        .db_mut()
        .enable_one_time_recovery(account)
        .unwrap();
    assert_eq!(
        advance(&mut st, account, &[(tip_height, receive(1))]),
        FilterOutcome::Committed
    );
    let corrected = span_over(st.wallet().db(), 1, &blocks_above(&st, activation(&st) - 1));
    assert_eq!(
        record(&mut st, account, &corrected, &[]),
        FilterOutcome::Restart
    );
    st.wallet_mut()
        .db_mut()
        .reset_one_time_history(account)
        .unwrap();
    let publication = RecoveryPublication {
        history_revision: 1,
        ..publication_at(&st, tip_height - 2)
    };
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    let end = publication.end.height;
    assert_eq!(work_of(&st, receive(1)).through, tip_height);
    let state = status_at(&st, account, end);
    assert_eq!(state.filter_frontier.map(|f| f.height), Some(end));
    let runnable: Vec<_> = state
        .lookups
        .iter()
        .map(|w| (w.work.key, w.through))
        .collect();
    assert_eq!(runnable, [0, 2, 3].map(|i| (receive(i), end)));
}

/// Issuance checks the marker against the newer of the caller's live tip and the saved
/// tip. With the saved tip and the marker at the same block and the live tip 100 blocks
/// past both, as at saved 1,900, marker 1,900 and live 2,000, a new address waits, since
/// those 100 blocks were never read through filters. A live draft waits too, since another
/// device may have paid it in those blocks, and is quoted again once filters reach them.
#[test]
fn receive_hand_out_checks_the_marker_against_the_live_tip() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(complete(&mut st, account), 4);
    let marker = status(st.wallet().db(), account).filter_frontier.unwrap();
    let saved = st.wallet().chain_height().unwrap().unwrap();
    assert_eq!(saved, marker.height);
    let live = saved + 100;
    let prepare = |st: &mut State, tip| {
        st.wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, clock_now(), tip)
            .unwrap()
            .map(|key| key.key_id())
    };
    assert_eq!(
        prepare(&mut st, live),
        Err(ReservationPolicy::ReceiveHistory)
    );
    assert_eq!(prepare(&mut st, saved), Ok(receive(0)));
    assert_eq!(
        prepare(&mut st, live),
        Err(ReservationPolicy::ReceiveHistory)
    );
    st.generate_and_scan_empty_blocks(100);
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    assert_eq!(prepare(&mut st, live), Ok(receive(0)));
}

/// A live draft is quoted again only while the marker is within 10 blocks of the tip. With
/// the draft reserved at marker M and the wallet then scanned 100 blocks on, as marker 1,900
/// and tip 2,000, the draft waits while filters reach 1,989, 11 blocks behind, and is
/// handed out again once they reach 1,990.
#[test]
fn a_live_draft_waits_for_the_marker_to_catch_up() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(complete(&mut st, account), 4);
    let marker = status(st.wallet().db(), account)
        .filter_frontier
        .unwrap()
        .height;
    let prepare = |st: &mut State| {
        st.wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, clock_now(), NO_LIVE_TIP)
            .unwrap()
            .map(|key| key.key_id())
    };
    assert_eq!(prepare(&mut st), Ok(receive(0)));
    st.generate_and_scan_empty_blocks(100);
    assert_eq!(tip(&st).height, marker + 100);
    assert_eq!(prepare(&mut st), Err(ReservationPolicy::ReceiveHistory));
    let blocks = blocks_above(&st, marker);
    let revision = status(st.wallet().db(), account).token.history_revision;
    let behind = span_over(st.wallet().db(), revision, &blocks[..89]);
    assert_eq!(
        record(&mut st, account, &behind, &[]),
        FilterOutcome::Committed
    );
    assert_eq!(prepare(&mut st), Err(ReservationPolicy::ReceiveHistory));
    let within = span_over(st.wallet().db(), revision, &blocks[89..90]);
    assert_eq!(
        record(&mut st, account, &within, &[]),
        FilterOutcome::Committed
    );
    assert_eq!(prepare(&mut st), Ok(receive(0)));
}

/// A wallet-wide history check forgets each account's history in the transaction that
/// starts it. Account A holds a found payment waiting for admission, and account B saved a
/// newer history revision than the publication, so B refuses it: nothing starts, and A's
/// payment and history are as they were. Once B accepts, both start, and A's new check
/// reads its history again from the start.
#[test]
fn a_refused_history_check_leaves_every_account_unchanged() {
    let (mut st, _) = waiting_witness_in(scanned_wallet());
    let account = st.test_account().unwrap().id();
    let born = st.latest_cached_block().unwrap().chain_state().clone();
    let birthday = zcash_client_backend::data_api::AccountBirthday::from_parts(born, None);
    let db = st.wallet_mut().db_mut();
    let (other, _) = db
        .create_account("other", &SecretVec::new(vec![9; 32]), &birthday, None)
        .unwrap();
    db.enable_one_time_recovery(other).unwrap();
    let revise = |st: &State, revision: u64| {
        exec(
            st.wallet().conn(),
            "UPDATE ironwood_one_time_recovery SET history_revision = ?1
             WHERE account_id = (SELECT id FROM accounts WHERE uuid = ?2)",
            rusqlite::params![revision.to_be_bytes(), other.0],
        );
    };
    revise(&st, 1);
    let snapshot = |st: &State| {
        let lookups: Vec<(i64, Option<u32>, u8, Option<u32>, Option<u32>, bool)> = rows(
            st.wallet().conn(),
            "SELECT one_time_key_id, target_height, reasons, done_height, done_from,
                read_complete FROM ironwood_one_time_lookups ORDER BY one_time_key_id",
            [],
        );
        (status(st.wallet().db(), account), candidates(st), lookups)
    };
    let before = snapshot(&st);
    assert_eq!((before.0.awaiting_admission, before.1), (1, 1));
    let publication = publication_at(&st, tip(&st).height);
    let refused = st
        .wallet_mut()
        .db_mut()
        .recheck_one_time_history_for(&[account, other], publication)
        .unwrap();
    assert_eq!(refused, Some(other));
    assert_eq!(snapshot(&st), before);
    revise(&st, 0);
    let started = st
        .wallet_mut()
        .db_mut()
        .recheck_one_time_history_for(&[account, other], publication)
        .unwrap();
    assert_eq!(started, None);
    let after = status(st.wallet().db(), account);
    assert!(after.manual.is_some_and(|m| m.active));
    assert_eq!((after.awaiting_admission, candidates(&st)), (0, 0));
}

/// An unfinished history check resumes with the history it kept: rechecking doesn't forget
/// the payment it found.
#[test]
fn rechecking_resumes_an_unfinished_history_check() {
    let (mut st, _) = waiting_witness_in(scanned_wallet());
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.check_one_time_history(account, publication, None)
            .unwrap()
    );
    db.cancel_one_time_history(account).unwrap();
    assert_eq!(
        db.recheck_one_time_history_for(&[account], publication)
            .unwrap(),
        None
    );
    assert_eq!(candidates(&st), 1);
    let state = status(st.wallet().db(), account);
    assert!(state.manual.is_some_and(|m| m.active));
    assert_eq!(state.awaiting_admission, 1);
}

/// Account A's history check paused at receive index 0 of 4, whose four addresses automatic
/// lookups then read in full, with I8's found payment waiting for admission outside the
/// check's range.
fn paused_check_with_a_waiting_payment() -> (State, AccountUuid, RecoveryPublication) {
    let (mut st, read) = waiting_witness_in(scanned_wallet());
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, read);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.check_one_time_history(account, publication, None)
            .unwrap()
    );
    db.cancel_one_time_history(account).unwrap();
    drain(&mut st, account, publication);
    let state = status(st.wallet().db(), account);
    let manual = state.manual.unwrap();
    assert!(!manual.active && manual.next < manual.receive_end);
    assert_eq!((state.awaiting_admission, candidates(&st)), (1, 1));
    (st, account, publication)
}

/// Naming an account twice in one history check batch checks it once. Rechecking A's paused
/// check resumes it, and it finishes at once since its remaining addresses are read. The
/// repeat must not then start a new check, which would forget I8's waiting payment.
#[test]
fn a_repeated_account_in_a_history_check_batch_is_checked_once() {
    let snapshot = |st: &State, account| {
        let payments: Vec<String> = column(
            st.wallet().conn(),
            "SELECT quote(one_time_key_id) || quote(txid) || quote(action_index)
                || quote(height) || quote(block_hash) || quote(tx_index) || quote(position)
                || quote(encrypted_note) || quote(directory) || quote(companion)
                || quote(ordinal) || quote(witness) || quote(witness_height)
                || quote(witness_hash) || quote(witness_size)
             FROM ironwood_one_time_payment_recovery ORDER BY txid, action_index",
            [],
        );
        (status(st.wallet().db(), account), payments)
    };
    let recheck = |accounts: &[AccountUuid], publication, st: &mut State| {
        let refused = st
            .wallet_mut()
            .db_mut()
            .recheck_one_time_history_for(accounts, publication)
            .unwrap();
        assert_eq!(refused, None);
    };
    let (mut once, a, publication) = paused_check_with_a_waiting_payment();
    let (mut twice, a2, publication2) = paused_check_with_a_waiting_payment();
    assert_eq!(snapshot(&once, a), snapshot(&twice, a2));
    recheck(&[a], publication, &mut once);
    recheck(&[a2, a2], publication2, &mut twice);
    let after = snapshot(&once, a);
    assert!(
        after
            .0
            .manual
            .is_some_and(|m| !m.active && m.next == m.receive_end)
    );
    assert_eq!((after.0.awaiting_admission, after.1.len()), (1, 1));
    assert_eq!(snapshot(&twice, a2), after);
}
