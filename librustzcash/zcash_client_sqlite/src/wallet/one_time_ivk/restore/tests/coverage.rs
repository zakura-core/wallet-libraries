//! Filter coverage: spans, re-checks, complete checks and their rollback.
use super::discovery::*;
use super::*;
use zcash_client_backend::data_api::one_time_ivk::restore::{FilterOutcome, FilterSpan};

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

/// Answers every due lookup and witness at a publication ending at the tip, returning how
/// many lookups ran.
fn run_pir(st: &mut State, account: AccountUuid) -> usize {
    let publication = RecoveryPublication {
        history_revision: status(st.wallet().db(), account).token.history_revision,
        ..publication_at(st, tip(st).height)
    };
    let mut lookups = 0;
    for _ in 0..256 {
        if answer_lookup(st, account, publication) {
            lookups += 1;
            continue;
        }
        let state = status(st.wallet().db(), account);
        let Some(request) = state.witnesses.first() else {
            return lookups;
        };
        let answer = witness_answer(st, request, tip(st).height);
        assert!(
            st.wallet_mut()
                .db_mut()
                .record_one_time_witness(account, state.token, *request, &answer, clock_now())
                .unwrap()
        );
    }
    panic!("recovery did not converge");
}

/// The monitored keys whose coverage is behind the account's frontier.
fn behind(st: &State, account: AccountUuid) -> Vec<KeyId> {
    let frontier = status(st.wallet().db(), account)
        .filter_frontier
        .map(|f| f.height);
    let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    receivers
        .iter()
        .filter(|r| frontier.is_some_and(|f| r.covered < f))
        .map(|r| r.work.key)
        .collect()
}

/// Re-checks every key behind the frontier over all committed history, with `hits`.
fn recheck(st: &mut State, account: AccountUuid, hits: &[(BlockHeight, KeyId)]) {
    let keys = behind(st, account);
    let state = status(st.wallet().db(), account);
    let frontier = state.filter_frontier.unwrap().height;
    let from = activation(st);
    assert!(
        st.wallet_mut()
            .db_mut()
            .recheck_one_time_filters(account, state.token, 0, from..=frontier, &keys, hits)
            .unwrap()
    );
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

/// An account that never swapped finishes its seed walk from one span with no PIR query,
/// stays fresh, and can hand out its first address.
#[test]
fn an_account_that_never_swapped_walks_with_no_pir() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(3);
    let account = st.test_account().unwrap().id();
    assert!(status(st.wallet().db(), account).fresh);
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    let state = status(st.wallet().db(), account);
    assert!(state.lookups.is_empty() && state.witnesses.is_empty());
    assert_eq!(
        (
            state.restore_next,
            state.restore_gap,
            state.restore_complete
        ),
        (4, 4, true)
    );
    assert_eq!(state.filter_frontier, Some(tip(&st)));
    assert!(state.fresh);
    let next = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, clock_now())
        .unwrap()
        .unwrap();
    assert_eq!(next.key_id().index(), 0);
}

/// I0 and I4 are both paid in history. Filters match only I0, whose lookup slides the
/// window, and re-checking the newly watched I4 over the history already covered finds
/// its payment with one more lookup. The walk then finishes on re-checks alone.
#[test]
fn paid_i0_and_i4_are_found_through_rechecking() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let paid0 = pay_candidate(&mut st, receive(0));
    let paid4 = pay_candidate(&mut st, receive(4));
    assert_eq!(
        advance(&mut st, account, &[(paid0.height, receive(0))]),
        FilterOutcome::Committed
    );
    assert_eq!(run_pir(&mut st, account), 1);
    assert!(!status(st.wallet().db(), account).fresh);
    assert_eq!(behind(&st, account), [receive(4)]);
    recheck(&mut st, account, &[(paid4.height, receive(4))]);
    assert_eq!(run_pir(&mut st, account), 1);
    assert_eq!(
        behind(&st, account),
        [receive(5), receive(6), receive(7), receive(8)]
    );
    recheck(&mut st, account, &[]);
    assert_eq!(run_pir(&mut st, account), 0);
    assert_eq!(one_time_notes(&st), [(100_000, false), (100_000, false)]);
    let state = status(st.wallet().db(), account);
    assert!(state.restore_complete && state.lookups.is_empty());
    assert_eq!(state.restore_next, 9);
}

/// A re-check must continue each key's coverage and stay inside committed history.
#[test]
fn a_recheck_cannot_skip_history() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(3);
    let account = st.test_account().unwrap().id();
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    let frontier = tip(&st).height;
    // Pretend I0 is behind, so a re-check must start at activation.
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_keys SET covered_height = NULL WHERE key_index = ?1",
        [0u64.to_be_bytes()],
    );
    let token = status(st.wallet().db(), account).token;
    let start = activation(&st);
    let db = st.wallet_mut().db_mut();
    for heights in [start + 1..=frontier, start..=frontier + 1] {
        assert!(
            db.recheck_one_time_filters(account, token, 0, heights, &[receive(0)], &[])
                .is_err()
        );
    }
    assert!(
        db.recheck_one_time_filters(account, token, 0, start..=frontier, &[receive(0)], &[])
            .unwrap()
    );
}

/// I0 was paid before a late restore birthday, and I4 after it.
fn late_birthday() -> (State, AccountUuid, PendingPayment, PendingPayment) {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let paid0 = pay_candidate(&mut st, receive(0));
    st.generate_and_scan_empty_blocks(1);
    exec(
        st.wallet().conn(),
        "UPDATE accounts SET birthday_height = ?1",
        [u32::from(paid0.height) + 1],
    );
    let paid4 = pay_candidate(&mut st, receive(4));
    (st, account, paid0, paid4)
}

/// A hit below the birthday is checked like any other, and the payment it finds there
/// slides the receive window, so I4 becomes watched.
#[test]
fn a_hit_before_the_birthday_advances_the_window() {
    let (mut st, account, paid0, _) = late_birthday();
    assert_eq!(
        advance(&mut st, account, &[(paid0.height, receive(0))]),
        FilterOutcome::Committed
    );
    assert_eq!(run_pir(&mut st, account), 1);
    assert!(
        one_time_notes(&st).is_empty(),
        "notes before the birthday are not tracked"
    );
    let marked: Option<u32> = value(
        st.wallet().conn(),
        "SELECT prebirthday_height FROM ironwood_one_time_keys WHERE purpose = 1 AND key_index = ?1",
        [0u64.to_be_bytes()],
    );
    assert!(marked.is_some());
    assert_eq!(behind(&st, account), [receive(4)]);
}

/// Filters cover history from activation, so a late birthday cannot hide I0's earlier
/// payment, and the window it opens still finds the later payment to I4.
#[test]
fn a_late_birthday_still_finds_a_later_payment_to_i4() {
    let (mut st, account, paid0, paid4) = late_birthday();
    assert_eq!(
        advance(&mut st, account, &[(paid0.height, receive(0))]),
        FilterOutcome::Committed
    );
    run_pir(&mut st, account);
    recheck(&mut st, account, &[(paid4.height, receive(4))]);
    assert_eq!(run_pir(&mut st, account), 1);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A match with no payment behind it costs one empty lookup and settles.
#[test]
fn a_false_match_costs_one_lookup() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    st.generate_and_scan_empty_blocks(1);
    let block = tip(&st).height;
    assert_eq!(
        advance(&mut st, account, &[(block, receive(1))]),
        FilterOutcome::Committed
    );
    assert_eq!(run_pir(&mut st, account), 1);
    let state = status(st.wallet().db(), account);
    assert!(state.lookups.is_empty() && state.witnesses.is_empty());
    assert!(state.restore_complete && one_time_notes(&st).is_empty());
    assert!(behind(&st, account).is_empty());
}

/// A span whose end or parent disagrees with the wallet's chain or committed coverage is
/// refused and changes nothing.
#[test]
fn a_span_that_disagrees_with_the_wallet_is_refused() {
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
    let frontier = status(st.wallet().db(), account).filter_frontier;
    st.generate_and_scan_empty_blocks(1);
    let mut wrong = next_span(&st, account);
    wrong.parent = BlockHash([9; 32]);
    assert_eq!(
        record(&mut st, account, &wrong, &[]),
        FilterOutcome::Mismatch
    );
    assert_eq!(status(st.wallet().db(), account).filter_frontier, frontier);
}

/// A span ending above the wallet's fully scanned block waits, even when the wallet holds
/// its end block, until it ends more than the reorg limit below the scanned tip.
#[test]
fn a_span_above_the_fully_scanned_block_waits_until_it_is_stable() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    let frontier = tip(&st).height;
    st.generate_empty_block();
    st.generate_empty_block();
    let (third, _) = st.generate_empty_block();
    st.scan_cached_blocks(third, 1);
    assert_eq!(
        tip(&st).height,
        frontier,
        "the gap holds the fully scanned block"
    );
    let span = next_span(&st, account);
    assert_eq!(span.end.height, third);
    assert_eq!(record(&mut st, account, &span, &[]), FilterOutcome::Wait);
    let (first, _) = st.generate_empty_block();
    for _ in 1..1_000 {
        st.generate_empty_block();
    }
    st.scan_cached_blocks(first, 1_000);
    assert_eq!(tip(&st).height, frontier);
    assert_eq!(
        record(&mut st, account, &span, &[]),
        FilterOutcome::Committed
    );
    assert_eq!(
        status(st.wallet().db(), account)
            .filter_frontier
            .map(|f| f.height),
        Some(third)
    );
}

/// A newer revision restarts coverage from activation, for the frontier and every key, and
/// the account is no longer fresh. Coverage then starts again under the new revision.
#[test]
fn a_correction_restarts_coverage_from_activation() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
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
    assert!(!state.fresh);
    let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(receivers.iter().all(|r| r.covered == activation(&st) - 1));
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    assert_eq!(
        status(st.wallet().db(), account).filter_frontier,
        Some(tip(&st))
    );
}

/// The keys whose lookups are due.
fn due(st: &State, account: AccountUuid) -> Vec<KeyId> {
    status(st.wallet().db(), account)
        .lookups
        .iter()
        .map(|w| w.work.key)
        .collect()
}

/// Commits a span over the cached chain from activation under revision 1 after filters
/// covered the chain under revision 0, so the store applies the correction.
fn correct_by_filters(st: &mut State, account: AccountUuid) {
    st.generate_and_scan_empty_blocks(1);
    let mut corrected = next_span(st, account);
    corrected.revision = 1;
    assert_eq!(record(st, account, &corrected, &[]), FilterOutcome::Restart);
}

/// A correction after a complete check reads no settled history by PIR: negative
/// replacement filters leave no lookup, except the one holding an open reservation.
#[test]
fn a_correction_with_negative_filters_queues_no_sweep() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(complete(&mut st, account), 4);
    st.generate_and_scan_empty_blocks(1);
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    let reserved = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, clock_now())
        .unwrap()
        .unwrap();
    assert_eq!(reserved.key_id(), receive(0));
    correct_by_filters(&mut st, account);
    assert_eq!(
        due(&st, account),
        [receive(0)],
        "only the reservation is held"
    );
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    assert_eq!(run_pir(&mut st, account), 1);
    let state = status(st.wallet().db(), account);
    assert!(state.lookups.is_empty() && state.restore_complete);
    assert!(behind(&st, account).is_empty());
}

/// After a correction, a replacement filter hit still queues a lookup for its key alone.
#[test]
fn a_correction_with_a_replacement_hit_queues_that_key() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let paid = pay_candidate(&mut st, receive(0));
    complete(&mut st, account);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    st.generate_and_scan_empty_blocks(1);
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    correct_by_filters(&mut st, account);
    assert!(due(&st, account).is_empty());
    assert_eq!(
        advance(&mut st, account, &[(paid.height, receive(0))]),
        FilterOutcome::Committed
    );
    assert_eq!(due(&st, account), [receive(0)]);
    assert_eq!(run_pir(&mut st, account), 1);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert!(status(st.wallet().db(), account).lookups.is_empty());
}

/// A reorg rolls the frontier and every key's coverage back to the fork, and the next span
/// continues from there.
#[test]
fn a_reorg_rolls_back_span_and_key_coverage() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(4);
    let account = st.test_account().unwrap().id();
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    let floor = tip(&st).height - 2;
    st.truncate_to_height(floor);
    let state = status(st.wallet().db(), account);
    assert_eq!(state.filter_frontier.map(|f| f.height), Some(floor));
    let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(receivers.iter().all(|r| r.covered <= floor));
    st.generate_and_scan_empty_blocks(3);
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    assert!(behind(&st, account).is_empty());
}

/// A sealed chunk replayed from inside committed coverage is accepted when its parent is
/// the wallet's own block, and refused otherwise.
#[test]
fn a_replay_overlapping_committed_coverage_is_accepted() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(4);
    let account = st.test_account().unwrap().id();
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    let frontier = tip(&st).height;
    st.generate_and_scan_empty_blocks(3);
    let replay = span_over(st.wallet().db(), 0, &blocks_above(&st, frontier - 3));
    let mut wrong = replay;
    wrong.parent = BlockHash([9; 32]);
    assert_eq!(
        record(&mut st, account, &wrong, &[]),
        FilterOutcome::Mismatch
    );
    assert_eq!(
        record(&mut st, account, &replay, &[]),
        FilterOutcome::Committed
    );
    assert_eq!(
        status(st.wallet().db(), account).filter_frontier,
        Some(tip(&st))
    );
    assert!(behind(&st, account).is_empty());
}

/// A complete check reads a paid key again over the gap from its coverage, so it finds a
/// repeat payment there without a manual history check.
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

/// The birthday just past the last cached block.
fn birthday_after_cache(st: &State) -> zcash_client_backend::data_api::AccountBirthday {
    let born = st.latest_cached_block().unwrap().chain_state().clone();
    zcash_client_backend::data_api::AccountBirthday::from_parts(born, None)
}

/// Restores `st`'s seed into a fresh wallet born at `birthday`, scanned from there through
/// the cached tip, so it holds no block below its birthday, and enables recovery.
fn restore_at(
    st: &mut State,
    birthday: &zcash_client_backend::data_api::AccountBirthday,
) -> AccountUuid {
    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let tip = st.latest_cached_block().unwrap().height();
    let _old = st.reset();
    let (account, _) = st
        .wallet_mut()
        .create_account("restored", &seed, birthday, None)
        .unwrap();
    st.wallet_mut().update_chain_tip(tip).unwrap();
    let from = birthday.height();
    st.scan_cached_blocks(from, (u32::from(tip) - u32::from(from) + 1) as usize);
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(account, true)
        .unwrap();
    account
}

/// A restore that never scanned below its birthday covers that history with a span the
/// reorg limit makes final, so I0's payment there opens the window, and the next span finds
/// the later payment to I4.
#[test]
fn a_restore_without_blocks_below_its_birthday_covers_them_with_stable_spans() {
    let mut st = scanned_wallet();
    let paid0 = pay_candidate(&mut st, receive(0));
    let birthday = birthday_after_cache(&st);
    let paid4 = pay_candidate(&mut st, receive(4));
    for _ in 0..1_000 {
        st.generate_empty_block();
    }
    let account = restore_at(&mut st, &birthday);
    assert!(st.wallet().get_block_hash(paid0.height).unwrap().is_none());
    let below: Vec<_> = blocks_above(&st, activation(&st) - 1)
        .into_iter()
        .filter(|b| b.height < birthday.height())
        .collect();
    let end = *below.last().unwrap();
    let span = FilterSpan {
        revision: 0,
        from: activation(&st),
        parent: BlockHash([0; 32]),
        end,
    };
    assert_eq!(
        record(&mut st, account, &span, &[(paid0.height, receive(0))]),
        FilterOutcome::Committed
    );
    assert_eq!(run_pir(&mut st, account), 1);
    assert_eq!(behind(&st, account), [receive(4)]);
    let rest = blocks_above(&st, end.height);
    let span = FilterSpan {
        revision: 0,
        from: birthday.height(),
        parent: end.hash,
        end: *rest.last().unwrap(),
    };
    assert_eq!(
        record(&mut st, account, &span, &[(paid4.height, receive(4))]),
        FilterOutcome::Committed
    );
    assert_eq!(run_pir(&mut st, account), 1);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A replay starting below the birthday has a parent the wallet does not hold, so it cannot
/// be checked, and coverage restarts from activation.
#[test]
fn a_replay_whose_parent_the_wallet_lacks_restarts_coverage() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(4);
    let birthday = birthday_after_cache(&st);
    for _ in 0..4 {
        st.generate_empty_block();
    }
    let account = restore_at(&mut st, &birthday);
    let mut blocks = blocks_above(&st, activation(&st) - 1);
    blocks.pop();
    let first = span_over(st.wallet().db(), 0, &blocks);
    assert_eq!(
        record(&mut st, account, &first, &[]),
        FilterOutcome::Committed
    );
    let replay = span_over(
        st.wallet().db(),
        0,
        &blocks_above(&st, birthday.height() - 3),
    );
    assert_eq!(
        record(&mut st, account, &replay, &[]),
        FilterOutcome::Restart
    );
    assert_eq!(status(st.wallet().db(), account).filter_frontier, None);
    let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(receivers.iter().all(|r| r.covered == activation(&st) - 1));
}

/// A complete check's lookup is held while a filter span commits past it, then answered.
/// The span counts the check's coverage, the held answer still settles it, each payment is
/// admitted once, and only the keys the payments exposed need a re-check.
#[test]
fn a_span_over_a_held_complete_check_keeps_both() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let paid0 = pay_candidate(&mut st, receive(0));
    let first = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, first, true)
            .unwrap()
    );
    let held = work_of(&st, receive(0));
    let paid1 = pay_candidate(&mut st, receive(1));
    assert_eq!(
        advance(&mut st, account, &[(paid1.height, receive(1))]),
        FilterOutcome::Committed
    );
    let page = whole(
        first,
        vec![DirectoryRecord {
            receiver: held.work.receiver,
            page: 0,
            total: 1,
            payment: directory_answer(&paid0),
            ordinal: 0,
        }],
    );
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &held, &page, clock_now())
            .unwrap()
    );
    run_pir(&mut st, account);
    assert_eq!(one_time_notes(&st), [(100_000, false), (100_000, false)]);
    // Only the keys the payments exposed wait for a re-check; I0 and I1 keep coverage.
    assert_eq!(behind(&st, account), [receive(4), receive(5)]);
    recheck(&mut st, account, &[]);
    assert_eq!(run_pir(&mut st, account), 0);
    assert!(behind(&st, account).is_empty());
    assert!(status(st.wallet().db(), account).lookups.is_empty());
}

/// A filter hit's lookup is held while a complete check extends it, then answered with the
/// shorter history. The rest is read from where that answer stopped, so the repeat payment
/// is found and nothing is admitted twice.
#[test]
fn a_complete_check_over_a_held_hit_lookup_keeps_both() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    let paid0 = pay_candidate(&mut st, receive(0));
    assert_eq!(
        advance(&mut st, account, &[(paid0.height, receive(0))]),
        FilterOutcome::Committed
    );
    let held = work_of(&st, receive(0));
    let first = publication_at(&st, held.through);
    pay_candidate(&mut st, receive(0));
    let second = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, second, true)
            .unwrap()
    );
    let page = whole(
        first,
        vec![DirectoryRecord {
            receiver: held.work.receiver,
            page: 0,
            total: 1,
            payment: directory_answer(&paid0),
            ordinal: 0,
        }],
    );
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &held, &page, clock_now())
            .unwrap()
    );
    run_pir(&mut st, account);
    assert_eq!(one_time_notes(&st), [(100_000, false), (100_000, false)]);
    assert!(behind(&st, account).is_empty());
    assert!(status(st.wallet().db(), account).lookups.is_empty());
}
