//! Filter coverage: spans, bootstrap lookups, complete checks and their rollback.
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

/// An account that never swapped finishes its seed walk with the four bootstrap lookups
/// its receive window queued, stays fresh, and hands out its first address.
#[test]
fn an_account_that_never_swapped_walks_with_four_lookups() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(3);
    let account = st.test_account().unwrap().id();
    assert!(status(st.wallet().db(), account).fresh);
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    assert!(!status(st.wallet().db(), account).restore_complete);
    assert_eq!(run_pir(&mut st, account), 4);
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
    assert_eq!(reserve_receive(&mut st, account).0, receive(0));
}

/// I0 and I4 are both paid in history. Filters match only I0, whose payment slides the
/// window, and I4's bootstrap lookup over the history filters already passed finds its
/// payment. The walk then finishes on the bootstrap lookups of I5 to I8.
#[test]
fn paid_i0_and_i4_are_found_through_bootstrap() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let paid0 = pay_candidate(&mut st, receive(0));
    pay_candidate(&mut st, receive(4));
    assert_eq!(
        advance(&mut st, account, &[(paid0.height, receive(0))]),
        FilterOutcome::Committed
    );
    assert_eq!(run_pir(&mut st, account), 9);
    assert!(!status(st.wallet().db(), account).fresh);
    assert_eq!(one_time_notes(&st), [(100_000, false), (100_000, false)]);
    let state = status(st.wallet().db(), account);
    assert!(state.restore_complete && state.lookups.is_empty());
    assert_eq!(state.restore_next, 9);
}

/// The coverage of receive index `index`.
fn covered_height(st: &State, index: u64) -> Option<u32> {
    value(
        st.wallet().conn(),
        "SELECT covered_height FROM ironwood_one_time_keys WHERE purpose = 1 AND key_index = ?1",
        [index.to_be_bytes()],
    )
}

/// A key that enters monitoring after filters passed its history gets one lookup from
/// activation through the frontier, and its coverage reaches the frontier, so the next
/// span carries it forward without reading that history again.
#[test]
fn an_enrolled_key_gets_one_obligation_and_no_recheck() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    assert_eq!(run_pir(&mut st, account), 4);
    let paid = pay_candidate(&mut st, receive(0));
    assert_eq!(
        advance(&mut st, account, &[(paid.height, receive(0))]),
        FilterOutcome::Committed
    );
    let publication = publication_at(&st, tip(&st).height);
    assert!(answer_lookup(&mut st, account, publication));
    send_witness(&mut st, receive(0), &paid);
    let frontier = tip(&st).height;
    assert_eq!(due(&st, account), [receive(4)]);
    let bootstrap = work_of(&st, receive(4));
    assert_eq!(
        (bootstrap.from, bootstrap.through),
        (activation(&st), frontier)
    );
    assert_eq!(covered_height(&st, 4), Some(u32::from(frontier)));
    st.generate_and_scan_empty_blocks(1);
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    assert_eq!(work_of(&st, receive(4)).through, frontier);
    assert_eq!(covered_height(&st, 4), Some(u32::from(tip(&st).height)));
    assert_eq!(run_pir(&mut st, account), 1);
    assert!(status(st.wallet().db(), account).lookups.is_empty());
}

/// A hit past a pending bootstrap's target extends that same lookup through the span's end,
/// keeping its start, so the payment costs no second obligation.
#[test]
fn a_hit_while_a_bootstrap_is_pending_extends_it() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let bootstrap = work_of(&st, receive(1));
    let paid = pay_candidate(&mut st, receive(1));
    assert!(paid.height > bootstrap.through);
    assert_eq!(
        advance(&mut st, account, &[(paid.height, receive(1))]),
        FilterOutcome::Committed
    );
    let extended = work_of(&st, receive(1));
    assert_eq!(
        (extended.from, extended.through),
        (bootstrap.from, tip(&st).height)
    );
    run_pir(&mut st, account);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A rewind below a pending bootstrap's target keeps the target, so the lookup waits for
/// the replacement chain to reach it and then completes.
#[test]
fn a_rewind_below_a_pending_target_keeps_it() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(run_pir(&mut st, account), 4);
    st.generate_and_scan_empty_blocks(4);
    let target = tip(&st).height;
    recover(st.wallet_mut().db_mut(), account, refund(0), target - 3);
    st.truncate_to_height(target - 2);
    let work = work_of(&st, refund(0));
    assert_eq!(work.through, target);
    let short = publication_at(&st, target - 2);
    let page = whole(short, vec![]);
    assert!(
        !st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &work, &page, clock_now())
            .unwrap()
    );
    st.generate_and_scan_empty_blocks(2);
    assert_eq!(run_pir(&mut st, account), 1);
    assert!(status(st.wallet().db(), account).lookups.is_empty());
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
    run_pir(&mut st, account);
    assert_eq!(
        one_time_notes(&st),
        [(100_000, false)],
        "only I4's note, after the birthday, is tracked"
    );
    let marked: Option<u32> = value(
        st.wallet().conn(),
        "SELECT prebirthday_height FROM ironwood_one_time_keys WHERE purpose = 1 AND key_index = ?1",
        [0u64.to_be_bytes()],
    );
    assert!(marked.is_some());
    let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(receivers.iter().any(|r| r.work.key == receive(4)));
}

/// Filters cover history from activation, so a late birthday cannot hide I0's earlier
/// payment, and the window it opens still finds the later payment to I4.
#[test]
fn a_late_birthday_still_finds_a_later_payment_to_i4() {
    let (mut st, account, paid0, _) = late_birthday();
    assert_eq!(
        advance(&mut st, account, &[(paid0.height, receive(0))]),
        FilterOutcome::Committed
    );
    run_pir(&mut st, account);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A match with no payment behind it costs one empty lookup and settles.
#[test]
fn a_false_match_costs_one_lookup() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(advance(&mut st, account, &[]), FilterOutcome::Committed);
    assert_eq!(run_pir(&mut st, account), 4);
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
    assert_eq!(reserve_receive(&mut st, account).0, receive(0));
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
/// reorg limit makes final, and the bootstrap lookups find I0's payment there, which opens
/// the window, and the later payment to I4. The next span then continues the frontier.
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
    run_pir(&mut st, account);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
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
    assert_eq!(run_pir(&mut st, account), 0);
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
/// admitted once, and the keys the payments exposed get their bootstrap lookups.
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
    assert!(status(st.wallet().db(), account).lookups.is_empty());
}

/// I0's payment, matched by filters, is found while an extended manual check runs, and the
/// window it opens brings I4 into monitoring with its bootstrap lookup, which the check
/// then also needs. Cancelling the check keeps that automatic obligation, so the seed walk
/// finishes once it runs.
#[test]
fn a_cancelled_manual_check_keeps_an_enrolled_keys_bootstrap() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let paid0 = pay_candidate(&mut st, receive(0));
    assert_eq!(
        advance(&mut st, account, &[(paid0.height, receive(0))]),
        FilterOutcome::Committed
    );
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, Some(5))
            .unwrap()
    );
    while due(&st, account) != [receive(4)] {
        if answer_lookup(&mut st, account, publication) {
            continue;
        }
        let state = status(st.wallet().db(), account);
        let request = state.witnesses[0];
        let answer = witness_answer(&st, &request, tip(&st).height);
        assert!(
            st.wallet_mut()
                .db_mut()
                .record_one_time_witness(account, state.token, request, &answer, clock_now())
                .unwrap()
        );
    }
    st.wallet_mut()
        .db_mut()
        .cancel_one_time_history(account)
        .unwrap();
    assert_eq!(due(&st, account), [receive(4)]);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert_eq!(run_pir(&mut st, account), 1);
    let state = status(st.wallet().db(), account);
    assert!(state.lookups.is_empty());
    assert_eq!((state.restore_next, state.restore_complete), (5, true));
}

/// Blocks between Ironwood activation and [`late_wallet`]'s birthday, more than the memo
/// refund window.
const LATE: u32 = 200_000;

/// A wallet born [`LATE`] blocks after Ironwood activation and scanned through one block,
/// so stable spans can cover more than the memo refund window below its birthday. Its
/// receive window's bootstrap lookups are already answered.
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
        .set_one_time_recovery_enabled(account, true)
        .unwrap();
    assert_eq!(run_pir(&mut st, account), 4);
    st
}

/// A stand-in hash for a block below the late wallet's birthday, which it never stored.
fn unheld(height: BlockHeight) -> BlockHash {
    let mut hash = [0xee; 32];
    hash[..4].copy_from_slice(&u32::from(height).to_le_bytes());
    BlockHash(hash)
}

/// Commits a span from just past the account's frontier, or activation, through `end`.
fn commit_to(
    st: &mut State,
    account: AccountUuid,
    end: ChainPoint,
    hits: &[(BlockHeight, KeyId)],
) -> FilterOutcome {
    let state = status(st.wallet().db(), account);
    let span = FilterSpan {
        revision: 0,
        from: state
            .filter_frontier
            .map_or(activation(st), |f| f.height + 1),
        parent: state.filter_frontier.map_or(BlockHash([0; 32]), |f| f.hash),
        end,
    };
    record(st, account, &span, hits)
}

/// Commits the late wallet's history below its birthday as far as the reorg limit makes
/// final, with no hit.
fn cover_below_birthday(st: &mut State, account: AccountUuid) -> BlockHeight {
    let end = tip(st).height - 1_000;
    let point = ChainPoint {
        height: end,
        hash: unheld(end),
    };
    assert_eq!(commit_to(st, account, point, &[]), FilterOutcome::Committed);
    end
}

/// Commits a span through the cached tip with `hits`.
fn commit_to_tip(
    st: &mut State,
    account: AccountUuid,
    hits: &[(BlockHeight, KeyId)],
) -> FilterOutcome {
    let end = *blocks_above(st, tip(st).height - 1).last().unwrap();
    commit_to(st, account, end, hits)
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

/// A memo-only refund key funded 45 days before the frontier is still watched, so its
/// refund is found automatically.
#[test]
fn a_refund_on_day_45_is_found_automatically() {
    let mut st = late_wallet();
    let account = st.test_account().unwrap().id();
    let funded = tip(&st).height - days(45);
    recover(st.wallet_mut().db_mut(), account, refund(0), funded);
    cover_below_birthday(&mut st, account);
    assert_eq!(refunds_watched(&st, account), [0]);
    let paid = pay_candidate(&mut st, refund(0));
    assert_eq!(
        commit_to_tip(&mut st, account, &[(paid.height, refund(0))]),
        FilterOutcome::Committed
    );
    assert_eq!(run_pir(&mut st, account), 1);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// Once a memo-only refund key's own coverage passes 90 days after its funding, filters
/// stop watching it, and after its bootstrap lookup has read that window, a later refund is
/// found only by the manual history check.
#[test]
fn a_refund_after_90_days_is_found_only_by_the_manual_check() {
    let mut st = late_wallet();
    let account = st.test_account().unwrap().id();
    let funded = tip(&st).height - days(100);
    recover(st.wallet_mut().db_mut(), account, refund(0), funded);
    cover_below_birthday(&mut st, account);
    assert_eq!(refunds_watched(&st, account), Vec::<u64>::new());
    assert_eq!(run_pir(&mut st, account), 1);
    pay_candidate(&mut st, refund(0));
    assert_eq!(
        commit_to_tip(&mut st, account, &[]),
        FilterOutcome::Committed
    );
    complete(&mut st, account);
    assert!(one_time_notes(&st).is_empty());
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, None)
            .unwrap()
    );
    run_pir(&mut st, account);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A funding memo learned after its 90-day window has passed still gets its bootstrap
/// lookup over that window. The key retires from monitoring at once, but the pending lookup
/// still runs, so a refund already paid is found.
#[test]
fn a_late_memo_older_than_90_days_still_gets_its_lookup() {
    let mut st = late_wallet();
    let account = st.test_account().unwrap().id();
    cover_below_birthday(&mut st, account);
    pay_candidate(&mut st, refund(0));
    assert_eq!(
        commit_to_tip(&mut st, account, &[]),
        FilterOutcome::Committed
    );
    let funded = tip(&st).height - days(100);
    recover(st.wallet_mut().db_mut(), account, refund(0), funded);
    assert_eq!(refunds_watched(&st, account), Vec::<u64>::new());
    assert_eq!(due(&st, account), [refund(0)]);
    assert_eq!(run_pir(&mut st, account), 1);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert_eq!(refunds_watched(&st, account), Vec::<u64>::new());
}

/// A reorg above a refund key's funding height clears it, so the funding the replacement
/// chain mines later moves the window with it rather than keeping the earlier height.
#[test]
fn a_reorg_moving_funding_shifts_the_bound() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(4);
    let account = st.test_account().unwrap().id();
    let funded = tip(&st).height;
    recover(st.wallet_mut().db_mut(), account, refund(0), funded);
    let funding = |st: &State| -> Option<u32> {
        value(
            st.wallet().conn(),
            "SELECT funding_height FROM ironwood_one_time_keys WHERE purpose = 0",
            [],
        )
    };
    assert_eq!(funding(&st), Some(u32::from(funded)));
    st.truncate_to_height(funded - 1);
    assert_eq!(funding(&st), None);
    assert_eq!(refunds_watched(&st, account), Vec::<u64>::new());
    st.generate_and_scan_empty_blocks(6);
    recover(st.wallet_mut().db_mut(), account, refund(0), funded + 5);
    assert_eq!(funding(&st), Some(u32::from(funded) + 5));
    assert_eq!(refunds_watched(&st, account), [0]);
}

/// Recording a first local operation on a retired memo-only key replaces the memo-only
/// rule with the operation rule, which returns it to monitoring and fences held filters.
#[test]
fn a_first_operation_on_a_retired_memo_only_key_fences_held_filters() {
    let mut st = late_wallet();
    let account = st.test_account().unwrap().id();
    let funded = tip(&st).height - days(100);
    recover(st.wallet_mut().db_mut(), account, refund(0), funded);
    cover_below_birthday(&mut st, account);
    assert_eq!(refunds_watched(&st, account), Vec::<u64>::new());
    let (held, _) = st.wallet().db().one_time_receivers(account).unwrap();
    let deposit = p2pkh(7).encode(st.network());
    let now = clock_now();
    st.wallet_mut()
        .db_mut()
        .record_refund_operation(account, 0, &deposit, now + 3_600, now)
        .unwrap();
    assert_eq!(refunds_watched(&st, account), [0]);
    let (current, _) = st.wallet().db().one_time_receivers(account).unwrap();
    assert_ne!(current, held);
}

/// A manual check finds a payment to a retired memo-only key, and its candidate waits for
/// a witness, which returns the key to monitoring. That advances the generation, so a
/// filter request captured without the key cannot commit. The key keeps the coverage it
/// had when it retired.
#[test]
fn a_candidate_that_returns_a_retired_key_to_monitoring_fences_held_filters() {
    let mut st = late_wallet();
    let account = st.test_account().unwrap().id();
    let funded = tip(&st).height - days(100);
    recover(st.wallet_mut().db_mut(), account, refund(0), funded);
    let frontier = cover_below_birthday(&mut st, account);
    assert_eq!(refunds_watched(&st, account), Vec::<u64>::new());
    pay_candidate(&mut st, refund(0));
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, None)
            .unwrap()
    );
    let (held, _) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(answer_lookup(&mut st, account, publication));
    assert_eq!(candidates(&st), 1, "the payment waits for its witness");
    assert_eq!(refunds_watched(&st, account), [0]);
    let end = *blocks_above(&st, tip(&st).height - 1).last().unwrap();
    let span = FilterSpan {
        revision: 0,
        from: frontier + 1,
        parent: unheld(frontier),
        end,
    };
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_filter_span(account, held, &span, &[])
            .unwrap(),
        FilterOutcome::Stale,
        "a request captured without R0 cannot commit"
    );
}

/// A rewind that reopens an empty completed history is new work, and one that rolls back
/// nothing is not.
#[test]
fn a_rewind_counts_as_new_work_only_when_it_rolls_something_back() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(3);
    let account = st.test_account().unwrap().id();
    assert_eq!(complete(&mut st, account), 4);
    let work = |st: &State| st.wallet().db().one_time_new_work().unwrap();
    let before = work(&st);
    let height = tip(&st).height;
    tx(st.wallet_mut().db_mut(), |c, _| {
        crate::wallet::one_time_rewind::truncate(c, height)
    })
    .unwrap();
    assert_eq!(work(&st), before, "nothing above the tip");
    st.truncate_to_height(height - 1);
    assert!(work(&st) > before, "the empty histories are read again");
    assert!(!status(st.wallet().db(), account).lookups.is_empty());
}

/// The work sequence never goes back, so deleting an account with work cannot make it
/// repeat a value an app already saw.
#[test]
fn the_work_sequence_survives_account_deletion() {
    let mut st = scanned_wallet();
    let work = |st: &State| st.wallet().db().one_time_new_work().unwrap();
    let birthday = st.test_account().unwrap().birthday().clone();
    let (other, _) = st
        .wallet_mut()
        .db_mut()
        .create_account("other", &SecretVec::new(vec![9; 32]), &birthday, None)
        .unwrap();
    let seen = work(&st);
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(other, true)
        .unwrap();
    let grown = work(&st);
    assert!(grown > seen);
    st.wallet_mut().db_mut().delete_account(other).unwrap();
    assert_eq!(work(&st), grown);
    let account = st.test_account().unwrap().id();
    let start = activation(&st);
    recover(st.wallet_mut().db_mut(), account, receive(9), start);
    assert!(work(&st) > grown);
}

/// Storing the same disputing transaction again before the repair settles keeps the
/// repair's progress and adds no work.
#[test]
fn a_repeated_dispute_keeps_its_repair() {
    use zcash_client_backend::data_api::wallet::decrypt_and_store_transaction;
    let Mislabeled { mut st, wrong, .. } = mislabeled(Mislabel::OtherTransaction);
    let account = st.test_account().unwrap().id();
    let network = *st.network();
    decrypt_and_store_transaction(&network, st.wallet_mut(), &wrong, None).unwrap();
    let work = status(st.wallet().db(), account).lookups[0].clone();
    st.wallet_mut()
        .db_mut()
        .defer_one_time_lookup(account, &work, clock_now())
        .unwrap();
    let attempts = |st: &State| -> u32 {
        value(
            st.wallet().conn(),
            "SELECT MAX(attempts) FROM ironwood_one_time_lookups",
            [],
        )
    };
    let counted = st.wallet().db().one_time_new_work().unwrap();
    assert_eq!(attempts(&st), 1);
    decrypt_and_store_transaction(&network, st.wallet_mut(), &wrong, None).unwrap();
    assert_eq!(
        attempts(&st),
        1,
        "the repair keeps its backoff and progress"
    );
    assert_eq!(st.wallet().db().one_time_new_work().unwrap(), counted);
}

/// Rewinds `floor` directly, as the wallet's own rewind does first.
fn rewind(st: &mut State, floor: BlockHeight) {
    tx(st.wallet_mut().db_mut(), |c, _| {
        crate::wallet::one_time_rewind::truncate(c, floor)
    })
    .unwrap();
}

/// A payment to I8 whose history was read through `read`, with its witness built two blocks
/// later and waiting for admission because the scan left the tip uncovered.
fn waiting_witness() -> (State, BlockHeight) {
    waiting_witness_in(scanned_wallet())
}

/// [`waiting_witness`] in the scanned wallet `st`.
fn waiting_witness_in(mut st: State) -> (State, BlockHeight) {
    let candidate = pay_candidate(&mut st, key8());
    queue_late(&mut st, key8(), &candidate);
    let read = tip(&st).height;
    st.generate_and_scan_empty_blocks(2);
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_journal_coverage SET end_height = ?1 WHERE end_height > ?1",
        [u32::from(tip(&st).height)],
    );
    send_witness(&mut st, key8(), &candidate);
    assert!(one_time_notes(&st).is_empty(), "admission waits");
    (st, read)
}

/// A rewind that only voids a waiting payment's witness counts as new work once; repeating
/// it rolls nothing back and counts nothing.
#[test]
fn a_witness_only_rewind_counts_once() {
    let (mut st, read) = waiting_witness();
    let work = |st: &State| st.wallet().db().one_time_new_work().unwrap();
    let before = work(&st);
    rewind(&mut st, read + 1);
    assert_eq!(work(&st), before + 1);
    rewind(&mut st, read + 1);
    assert_eq!(work(&st), before + 1);
}

/// A rewind that resets an unfinished seed walk counts once; repeating it before the walk
/// moves again counts nothing.
#[test]
fn a_repeated_rewind_does_not_recount_a_reset_walk() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(3);
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    while status(st.wallet().db(), account).restore_next == 0 {
        assert!(answer_lookup(&mut st, account, publication));
    }
    assert!(!status(st.wallet().db(), account).restore_complete);
    let work = |st: &State| st.wallet().db().one_time_new_work().unwrap();
    let floor = publication.end.height - 1;
    let before = work(&st);
    rewind(&mut st, floor);
    assert_eq!(work(&st), before + 1);
    assert_eq!(status(st.wallet().db(), account).restore_next, 0);
    rewind(&mut st, floor);
    assert_eq!(work(&st), before + 1);
}

/// `awaiting_admission` counts a witnessed payment while admission waits for the rescan,
/// only for its own account, and returns to zero once the payment is admitted.
#[test]
fn awaiting_admission_counts_a_witnessed_payment_until_it_is_admitted() {
    let waiting = |st: &State, account| {
        st.wallet()
            .db()
            .one_time_recovery(account, clock_now())
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
        .set_one_time_recovery_enabled(other, true)
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
