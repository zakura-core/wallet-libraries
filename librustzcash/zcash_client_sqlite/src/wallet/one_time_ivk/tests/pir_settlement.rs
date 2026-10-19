//! Real encrypted notes exercise durable cursors, callback fences and admission separately.
use super::*;
use crate::wallet::one_time_ivk::restore::tests::discovery::{
    one_time_notes, publication_at, siblings, witness_at,
};
use zcash_client_backend::data_api::one_time_ivk::recovery::{
    FilterJudgment, History, OneTimeRecoveryRead, OneTimeRecoveryWrite,
    settlement::{OneTimePirRecovery, PirSnapshot, PirWork},
};

/// Returns the history identity accepted by this test wallet.
fn history() -> History {
    History {
        genesis: [1; 32],
        archive: [2; 32],
        epoch: 0,
    }
}

/// Scans a real payment before discovering its key and records its public filter match.
fn fixture() -> (State, KeyId, PendingPayment, PirSnapshot) {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    check_seen(st.wallet_mut().db_mut(), account);
    st.wallet_mut()
        .accept_one_time_history(account, history())
        .unwrap();
    let key = KeyId::new(Purpose::Receive, 0);
    let fvk = derive(&st, key);
    let (height, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk.clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(50_000),
    );
    let candidate = candidate_at(&st, height, &fvk);
    st.scan_cached_blocks_with_recovery(height, 1, &[]);
    matches(&mut st, key, height);
    let snapshot = PirSnapshot {
        history: history(),
        session: [9; 32],
        publication: publication_at(&st, height),
    };
    (st, key, candidate, snapshot)
}

/// Records contiguous actual block identities from the receiver cursor through a chosen match.
fn matches(st: &mut State, key: KeyId, height: BlockHeight) {
    let account = st.test_account().unwrap().id();
    let work = st
        .wallet()
        .one_time_filter_work(account, 1024)
        .unwrap()
        .unwrap();
    let judgments = (u32::from(work.next_height)..=u32::from(height))
        .map(|h| {
            let p = publication_at(st, h.into());
            FilterJudgment {
                block: ChainPoint {
                    height: h.into(),
                    hash: BlockHash(p.hash),
                },
                hits: if h == u32::from(height) {
                    vec![key]
                } else {
                    vec![]
                },
            }
        })
        .collect::<Vec<_>>();
    assert!(
        st.wallet_mut()
            .record_one_time_filters(account, &work, &judgments)
            .unwrap()
    );
}

/// Begins eligible work using the fixture's real local publication.
fn begin(st: &mut State, key: KeyId, snapshot: PirSnapshot) -> PirWork<AccountUuid> {
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .begin_one_time_pir(account, key, snapshot, clock_now())
        .unwrap()
        .unwrap()
}

/// Counts unsettled positive blocks independently of whether a payment has been queued.
fn pending(st: &State) -> u64 {
    st.wallet()
        .one_time_recovery_state(st.test_account().unwrap().id())
        .unwrap()
        .unwrap()
        .pending_matches
}

/// Provides the real path at the current cached tip and performs local admission.
fn finish(st: &mut State) {
    let account = st.test_account().unwrap().id();
    let work = st.wallet().one_time_pir_witnesses(account, 64).unwrap();
    let anchor = tip(st);
    for witness in work {
        let path = witness_at(st, witness.payment.position as u32);
        assert!(
            st.wallet_mut()
                .record_one_time_pir_witness(&witness, anchor, siblings(&path))
                .unwrap()
        );
    }
    st.wallet_mut().admit_one_time_pir(account, 64).unwrap();
}

/// Enumeration survives a handle restart and cannot settle before verified receipt admission.
#[test]
fn durable_page_waits_for_inclusion_and_admission() {
    let (mut st, key, candidate, snapshot) = fixture();
    let account = st.test_account().unwrap().id();
    let work = begin(&mut st, key, snapshot);
    assert!(
        st.wallet_mut()
            .record_one_time_pir_page(&work, 0, &[directory_answer(&candidate)], true)
            .unwrap()
    );
    assert_eq!(pending(&st), 1);
    assert!(one_time_notes(&st).is_empty());
    let mut reopened = WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    let resumed = reopened
        .begin_one_time_pir(account, key, snapshot, clock_now())
        .unwrap()
        .unwrap();
    assert!(resumed.enumerated);
    assert_eq!(resumed.lookup.applied, 1);
    assert_eq!(
        reopened.one_time_pir_witnesses(account, 64).unwrap().len(),
        1
    );
    finish(&mut st);
    assert_eq!(one_time_notes(&st), vec![(50_000, false)]);
    assert_eq!(pending(&st), 0);
    assert!(
        st.wallet_mut()
            .begin_one_time_pir(account, key, snapshot, clock_now())
            .unwrap()
            .is_none()
    );
    assert!(
        !st.wallet_mut()
            .record_one_time_pir_page(&work, 0, &[directory_answer(&candidate)], true)
            .unwrap()
    );
}

/// Pausing, re-enabling and correcting the archive revoke old page and witness callbacks.
#[test]
fn stale_callbacks_never_clear_pending_matches() {
    let (mut st, key, candidate, snapshot) = fixture();
    let account = st.test_account().unwrap().id();
    let work = begin(&mut st, key, snapshot);
    st.wallet_mut()
        .set_one_time_recovery_enabled(account, false)
        .unwrap();
    assert!(
        !st.wallet_mut()
            .record_one_time_pir_page(&work, 0, &[], true)
            .unwrap()
    );
    assert!(
        st.wallet_mut()
            .begin_one_time_pir(account, key, snapshot, clock_now())
            .unwrap()
            .is_none()
    );
    st.wallet_mut()
        .set_one_time_recovery_enabled(account, true)
        .unwrap();
    assert!(
        !st.wallet_mut()
            .record_one_time_pir_page(&work, 0, &[], true)
            .unwrap()
    );
    let work = begin(&mut st, key, snapshot);
    st.wallet_mut()
        .record_one_time_pir_page(&work, 0, &[directory_answer(&candidate)], true)
        .unwrap();
    let witness = st
        .wallet()
        .one_time_pir_witnesses(account, 64)
        .unwrap()
        .remove(0);
    let mut corrected = snapshot;
    corrected.history.epoch += 1;
    st.wallet_mut()
        .accept_one_time_history(account, corrected.history)
        .unwrap();
    assert_eq!(
        value::<u32>(
            st.wallet().conn(),
            "SELECT COUNT(*) FROM ironwood_block_payments",
            []
        ),
        0
    );
    assert_eq!(pending(&st), 1);
    let anchor = tip(&st);
    let path = witness_at(&st, candidate.position);
    assert!(
        !st.wallet_mut()
            .record_one_time_pir_witness(&witness, anchor, siblings(&path))
            .unwrap()
    );
    st.wallet_mut().admit_one_time_pir(account, 64).unwrap();
    assert!(one_time_notes(&st).is_empty());
    assert_eq!(pending(&st), 1);
    assert_eq!(begin(&mut st, key, corrected).lookup.applied, 0);
}

/// A newer compatible session preserves the cursor but rejects answers from the prior session.
#[test]
fn paging_resumes_across_sessions_and_keeps_later_matches() {
    let (mut st, key, first, snapshot) = fixture();
    let work = begin(&mut st, key, snapshot);
    st.wallet_mut()
        .record_one_time_pir_page(&work, 0, &[directory_answer(&first)], false)
        .unwrap();
    let old = begin(&mut st, key, snapshot);
    let fvk = derive(&st, key);
    let (height, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk.clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(20_000),
    );
    let second = candidate_at(&st, height, &fvk);
    st.scan_cached_blocks_with_recovery(height, 1, &[]);
    matches(&mut st, key, height);
    let newer = PirSnapshot {
        session: [10; 32],
        publication: publication_at(&st, height),
        ..snapshot
    };
    let resumed = begin(&mut st, key, newer);
    assert_eq!(resumed.lookup.applied, 1);
    assert_eq!(resumed.lookup.cutoff, first.height);
    assert!(
        !st.wallet_mut()
            .record_one_time_pir_page(&old, 1, &[], true)
            .unwrap()
    );
    st.wallet_mut()
        .record_one_time_pir_page(&resumed, 1, &[], true)
        .unwrap();
    finish(&mut st);
    assert_eq!(pending(&st), 1);
    let next = begin(&mut st, key, newer);
    assert_eq!(next.lookup.applied, 1);
    assert_eq!(next.lookup.cutoff, height);
    assert!(!next.enumerated);
    st.wallet_mut()
        .record_one_time_pir_page(&next, 1, &[directory_answer(&second)], true)
        .unwrap();
    finish(&mut st);
    assert_eq!(pending(&st), 0);
    assert_eq!(one_time_notes(&st), vec![(50_000, false), (20_000, false)]);
}

/// A malformed page rolls back all candidates and a deferred request remains deferred after restart.
#[test]
fn invalid_pages_and_retries_preserve_the_obligation() {
    let (mut st, key, candidate, snapshot) = fixture();
    let account = st.test_account().unwrap().id();
    let work = begin(&mut st, key, snapshot);
    let mut bad = directory_answer(&candidate);
    bad.ciphertext_prefix[0] ^= 1;
    assert!(
        st.wallet_mut()
            .record_one_time_pir_page(&work, 0, &[bad], true)
            .is_err()
    );
    assert_eq!(begin(&mut st, key, snapshot).lookup.applied, 0);
    assert_eq!(pending(&st), 1);
    st.wallet_mut()
        .defer_one_time_pir(&work.scope, clock_now())
        .unwrap();
    let mut reopened = WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    assert!(
        reopened
            .begin_one_time_pir(account, key, snapshot, clock_now() + 59)
            .unwrap()
            .is_none()
    );
    assert!(
        reopened
            .begin_one_time_pir(account, key, snapshot, clock_now() + 60)
            .unwrap()
            .is_some()
    );
}

/// A false positive settles only its covered blocks and creates no permanent exemption for the key.
#[test]
fn an_empty_history_does_not_hide_a_later_payment() {
    let (mut st, key, candidate, snapshot) = fixture();
    let work = begin(&mut st, key, snapshot);
    // The empty answer models a false-positive filter, not proof against a malicious directory.
    st.wallet_mut()
        .record_one_time_pir_page(&work, 0, &[], true)
        .unwrap();
    assert_eq!(pending(&st), 0);
    let fvk = derive(&st, key);
    let (height, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk.clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(20_000),
    );
    let second = candidate_at(&st, height, &fvk);
    st.scan_cached_blocks_with_recovery(height, 1, &[]);
    matches(&mut st, key, height);
    let newer = PirSnapshot {
        publication: publication_at(&st, height),
        session: [10; 32],
        ..snapshot
    };
    let work = begin(&mut st, key, newer);
    assert!(!work.enumerated);
    assert_eq!(work.lookup.applied, 0);
    st.wallet_mut()
        .record_one_time_pir_page(
            &work,
            0,
            &[directory_answer(&candidate), directory_answer(&second)],
            true,
        )
        .unwrap();
    finish(&mut st);
    assert_eq!(one_time_notes(&st).len(), 2);
    assert_eq!(pending(&st), 0);
}

/// A fresh publication on a quiet chain can use its unchanged older commitment-tree checkpoint.
#[test]
fn quiet_chain_admits_with_an_older_unchanged_tree_checkpoint() {
    let (mut st, key, candidate, mut snapshot) = fixture();
    let count = crate::PRUNING_DEPTH as usize + 10;
    for _ in 0..count {
        st.generate_empty_block();
    }
    st.scan_cached_blocks_with_recovery(candidate.height + 1, count, &[]);
    snapshot.publication = publication_at(&st, candidate.height + count as u32);
    let work = begin(&mut st, key, snapshot);
    st.wallet_mut()
        .record_one_time_pir_page(&work, 0, &[directory_answer(&candidate)], true)
        .unwrap();
    finish(&mut st);
    assert_eq!(one_time_notes(&st), vec![(50_000, false)]);
    assert_eq!(pending(&st), 0);
}

/// Historical admission uses the durable journal even after temporary spend evidence is pruned.
#[test]
fn a_late_pir_receipt_is_admitted_spent() {
    let (mut st, key, candidate, mut snapshot) = fixture();
    let recovered = candidate.encrypted_note.decrypt(&parent(&st), key).unwrap();
    let ordinary = IronwoodFvk(parent(&st));
    st.generate_next_block_spending(
        &ordinary,
        (*recovered.nullifier(), Zatoshis::const_from_u64(50_000)),
        unified(foreign_receiver()),
        Zatoshis::const_from_u64(40_000),
    );
    let count = crate::PRUNING_DEPTH as usize + 10;
    for _ in 0..count {
        st.generate_empty_block();
    }
    st.scan_cached_blocks_with_recovery(candidate.height + 1, count + 1, &[]);
    snapshot.publication = publication_at(&st, candidate.height + count as u32 + 1);
    let work = begin(&mut st, key, snapshot);
    st.wallet_mut()
        .record_one_time_pir_page(&work, 0, &[directory_answer(&candidate)], true)
        .unwrap();
    finish(&mut st);
    assert_eq!(one_time_notes(&st), vec![(50_000, true)]);
    assert_eq!(pending(&st), 0);
}

/// A path for a different candidate or session cannot authorize the queued payment.
#[test]
fn witness_response_is_bound_to_the_exact_candidate() {
    let (mut st, key, candidate, snapshot) = fixture();
    let account = st.test_account().unwrap().id();
    let work = begin(&mut st, key, snapshot);
    st.wallet_mut()
        .record_one_time_pir_page(&work, 0, &[directory_answer(&candidate)], true)
        .unwrap();
    let mut witness = st
        .wallet()
        .one_time_pir_witnesses(account, 64)
        .unwrap()
        .remove(0);
    let anchor = tip(&st);
    let path = siblings(&witness_at(&st, candidate.position));
    witness.payment.txid[0] ^= 1;
    assert!(
        !st.wallet_mut()
            .record_one_time_pir_witness(&witness, anchor, path)
            .unwrap()
    );
    witness.payment.txid[0] ^= 1;
    witness.scope.snapshot.session[0] ^= 1;
    assert!(
        !st.wallet_mut()
            .record_one_time_pir_witness(&witness, anchor, path)
            .unwrap()
    );
    st.wallet_mut().admit_one_time_pir(account, 64).unwrap();
    assert!(one_time_notes(&st).is_empty());
    assert_eq!(pending(&st), 1);
    finish(&mut st);
    assert_eq!(pending(&st), 0);
}

/// A locally disproven claim restarts enumeration instead of silently settling its match.
#[test]
fn rejected_inclusion_restarts_without_losing_the_match() {
    let (mut st, key, candidate, snapshot) = fixture();
    let account = st.test_account().unwrap().id();
    let work = begin(&mut st, key, snapshot);
    st.wallet_mut()
        .record_one_time_pir_page(&work, 0, &[directory_answer(&candidate)], true)
        .unwrap();
    let witness = st
        .wallet()
        .one_time_pir_witnesses(account, 64)
        .unwrap()
        .remove(0);
    let mut path = siblings(&witness_at(&st, candidate.position));
    path[0] = path[1];
    let anchor = tip(&st);
    st.wallet_mut()
        .record_one_time_pir_witness(&witness, anchor, path)
        .unwrap();
    st.wallet_mut().admit_one_time_pir(account, 64).unwrap();
    assert!(one_time_notes(&st).is_empty());
    assert_eq!(pending(&st), 1);
    assert!(
        st.wallet_mut()
            .begin_one_time_pir(account, key, snapshot, clock_now())
            .unwrap()
            .is_none()
    );
    let restarted = st
        .wallet_mut()
        .begin_one_time_pir(account, key, snapshot, clock_now() + 60)
        .unwrap()
        .unwrap();
    assert_eq!(restarted.lookup.applied, 0);
    assert!(!restarted.enumerated);
    st.wallet_mut()
        .record_one_time_pir_page(&restarted, 0, &[directory_answer(&candidate)], true)
        .unwrap();
    finish(&mut st);
    assert_eq!(pending(&st), 0);
}

/// An authenticated payment awaiting its path cannot be offered as a new receive address.
#[test]
fn a_pending_pir_payment_is_not_reissued() {
    let (mut st, key, candidate, snapshot) = fixture();
    let account = st.test_account().unwrap().id();
    let work = begin(&mut st, key, snapshot);
    st.wallet_mut()
        .record_one_time_pir_page(&work, 0, &[directory_answer(&candidate)], true)
        .unwrap();
    let now = clock_now();
    let seen = empty_seen(now);
    let height = tip(&st).height;
    let reserved = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, now, height, Some(&seen))
        .unwrap()
        .unwrap();
    assert_ne!(reserved.key_id(), key);
    assert_eq!(pending(&st), 1);
}
