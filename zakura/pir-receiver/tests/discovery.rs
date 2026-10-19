//! Discovery end to end: a restored wallet checks its one-time keys against a receiver
//! directory served in process, over the service's routes and real PIR, and imports what
//! it finds only after checking it against its own chain. The service's own HTTP router
//! is tested against these clients in wallet-pir.

mod common;

use common::*;
use orchard::keys::{FullViewingKey, Scope};
use zakura_one_time_ivk::swap::RESTORE_WATCH_SECS;
use zakura_pir_receiver::{
    DirectoryError, Discovered, Error, FIRST_WINDOW, Transport, discover, fetch_seen,
};
use zakura_receiver_crypto::Receiver;
use zcash_client_backend::data_api::{
    Account as _, WalletWrite as _,
    one_time_ivk::restore::{
        EnumerationCursor, FilterCheck, OneTimeIvkRestoreRead as _, OneTimeIvkRestoreWrite as _,
    },
    transparent_ledger::ChainPoint,
};
use zcash_client_sqlite::{
    AccountUuid,
    error::SqliteClientError,
    testing::db::TestDbFactory,
    wallet::one_time_ivk::{KeyId, Purpose, swap::ProviderSeen},
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

/// Runs discovery for `account` at [`NOW`].
async fn run(
    st: &mut State,
    account: AccountUuid,
    directory: impl Transport,
) -> Result<Discovered<SqliteClientError>, Error<SqliteClientError>> {
    let network = *st.network();
    discover(
        st.wallet_mut().db_mut(),
        &network,
        account,
        GENESIS,
        ORIGIN,
        directory,
        &NoLock,
        NOW,
    )
    .await
}

/// [`run`]s for the test account, expecting no failed key.
async fn run_clean(st: &mut State, directory: impl Transport) -> Discovered<SqliteClientError> {
    let account = st.test_account().unwrap().id();
    let found = run(st, account, directory).await.unwrap();
    assert!(found.failed.is_empty(), "{:?}", found.failed);
    found
}

/// A late restore pages through each paid key's history and imports every payment once the
/// scan covers it, with no further request once discovery is complete. Keys the filters
/// do not mark are never registered.
#[tokio::test]
async fn discovery_imports_every_late_payment() {
    let mut r = restored(&[0, 3, 3, 40]);
    let directory = serve(&r.records, r.through);
    let found = run_clean(&mut r.st, &directory).await;
    assert!(found.complete);
    assert_eq!((found.lookups, found.witnesses), (0, 0));
    assert_eq!(balance(&r.st), 4 * VALUE);
    // One query per page, and one more for each key's empty first page is never needed.
    assert_eq!(lookups(&directory), 4);
    assert_eq!(registered(&r.st, Purpose::Receive), [0, 3, 40]);
    assert!(registered(&r.st, Purpose::Refund).is_empty());

    let requests = directory.requests().len();
    let found = run_clean(&mut r.st, &directory).await;
    assert!(found.complete);
    assert_eq!(
        directory.requests().len(),
        requests,
        "a run with nothing due makes no request"
    );
}

/// A recheck checks a closed key far past the first window of unused keys again, without
/// walking the keys between, so a payment after it closed is found.
#[tokio::test]
async fn a_closed_key_past_a_filter_gap_is_rechecked() {
    closed_key_paid_later(false).await;
}

/// A fresh account asked to recheck finds the payment and completes once its discovery has
/// nothing left to run.
#[tokio::test]
async fn a_fresh_account_completes_once_its_recheck_finishes() {
    closed_key_paid_later(true).await;
}

/// Closes an incoming key far past the first window unpaid, pays it, rechecks and runs
/// discovery, expecting it to find the payment and complete. A `fresh` account is declared
/// fresh first.
async fn closed_key_paid_later(fresh: bool) {
    let mut st = ironwood_wallet_in(TestDbFactory::default());
    let account = st.test_account().unwrap().id();
    if fresh {
        st.wallet_mut()
            .db_mut()
            .mark_one_time_account_fresh(account)
            .unwrap();
    }
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let index = 1_000_000_000;
    // An earlier pass saw the key unpaid, so it closed.
    let earlier = stored_publication(&st, tip(&st).height);
    let seen = FilterCheck {
        key: KeyId::new(Purpose::Receive, index),
        seen: true,
        paid: false,
        recent: false,
    };
    let done = EnumerationCursor {
        next: index + 1,
        reach: index + 1,
    };
    let db = st.wallet_mut().db_mut();
    for (purpose, checks) in [(Purpose::Receive, vec![seen]), (Purpose::Refund, vec![])] {
        assert!(
            db.record_one_time_filter_checks(account, earlier, purpose, &checks, done, true, NOW)
                .unwrap()
        );
    }

    let record = pay_restored_key(&mut st, index, 0);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    // Only Check swap history looks for a payment to a closed key.
    let db = st.wallet_mut().db_mut();
    db.recheck_one_time_key_history(account).unwrap();
    let directory = serve(&[record], tip(&st));
    let found = run_clean(&mut st, &directory).await;
    assert!(found.complete);
    assert_eq!(balance(&st), VALUE);
}

/// A wallet with no payments downloads only the manifest and the filters, and is complete
/// once its publication matches its chain.
#[tokio::test]
async fn a_wallet_without_payments_downloads_only_the_filters() {
    let mut r = restored(&[]);
    let directory = serve(&[], r.through);
    let found = run_clean(&mut r.st, &directory).await;
    assert!(found.complete);
    let requests = directory.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(requests[0].ends_with("/init"));
    assert!(requests[1].contains("/filters/"));
}

/// A restore that runs before the scan reaches its payments records them as hints, and the
/// scan finds the notes itself, judging the publication as it stores its last block.
#[tokio::test]
async fn payments_ahead_of_the_scan_are_found_by_it() {
    let mut st = ironwood_wallet_in(TestDbFactory::default());
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let first = pay_unscanned(&mut st, 2, 0);
    let second = pay_unscanned(&mut st, 7, 1);
    let end_height = BlockHeight::from(second.payment.height);
    st.wallet_mut().update_chain_tip(end_height).unwrap();
    let end = ChainPoint {
        height: end_height,
        hash: BlockHash(second.payment.block_hash),
    };
    let start = BlockHeight::from(first.payment.height);
    let directory = serve(&[first, second], end);
    let found = run_clean(&mut st, &directory).await;
    assert!(!found.complete, "the publication waits for the scan");
    assert_eq!(found.witnesses, 0);
    assert_eq!(one_time_value(&st), 0);
    st.scan_cached_blocks_with_one_time_ivks(start, 2);
    assert_eq!(one_time_value(&st), 2 * VALUE);
    let account = st.test_account().unwrap().id();
    let status = st.wallet().db().one_time_discovery(account, NOW).unwrap();
    assert!(status.unwrap().complete);
}

/// A payment the key cannot decrypt is the directory's error: the wallet refuses the
/// answer, imports nothing, and backs the lookup off.
#[tokio::test]
async fn a_forged_payment_is_refused() {
    let mut r = restored(&[4]);
    let mut forged = r.records[0].clone();
    forged.payment.ciphertext_prefix[0] ^= 1;
    let directory = serve(&[forged], r.through);
    let found = run(&mut r.st, r.account, &directory).await.unwrap();
    assert!(!found.complete);
    assert_eq!(found.failed.len(), 1);
    assert_eq!(balance(&r.st), 0);
    // Backed off, so an immediate rerun makes no lookup.
    let before = lookups(&directory);
    run(&mut r.st, r.account, &directory).await.unwrap();
    assert_eq!(lookups(&directory), before);
}

/// A publication above the wallet's chain tip waits for the wallet to learn that tip.
#[tokio::test]
async fn a_publication_ahead_of_the_wallet_waits() {
    let mut r = restored(&[]);
    let ahead = ChainPoint {
        height: r.through.height + 5,
        hash: BlockHash([7; 32]),
    };
    let directory = serve(&[], ahead);
    let refused = run(&mut r.st, r.account, &directory).await;
    assert_matches!(refused, Err(Error::Unavailable(_)));
}

/// Unless every provider's recent set is current, discovery watches every key it checks
/// from the publication's end; with them, only the keys they list, up to the filters'
/// false positives.
#[tokio::test]
async fn without_every_recent_set_every_checked_key_scans_after_the_end() {
    for complete in [true, false] {
        let mut r = restored(&[]);
        let refund = key_receiver(&parent(&r.st), KeyId::new(Purpose::Refund, 0));
        let sets = provider(&[refund]);
        let sets = if complete { &sets[..] } else { &sets[1..] };
        let directory = Directory::new(publish(&[], &[], r.through, sets));
        run_clean(&mut r.st, &directory).await;
        let incoming = registered(&r.st, Purpose::Receive).len() as u64;
        if complete {
            // The filters' false positives register a few keys at most.
            assert!(incoming < 5, "{incoming}");
            assert!(scanning(&r.st).len() < 5);
        } else {
            assert_eq!(incoming, FIRST_WINDOW);
            assert_eq!(scanning(&r.st).len() as u64, FIRST_WINDOW + 1);
        }
    }
}

/// Two accounts discover their histories independently.
#[tokio::test]
async fn two_accounts_discover_independently() {
    let mut r = restored(&[]);
    let seed = secrecy::SecretVec::new(vec![3; 32]);
    let birthday = r.st.test_account().unwrap().birthday().clone();
    let (other, usk) =
        r.st.wallet_mut()
            .db_mut()
            .create_account("other", &seed, &birthday, None)
            .unwrap();
    let other_parent = FullViewingKey::from(usk.orchard());
    let paid = pay_unscanned_to(&mut r.st, &other_parent, 1, 0);
    // The new account sends the scan back to its birthday, at Ironwood activation.
    let blocks = paid.payment.height - ACTIVATION + 1;
    r.st.scan_cached_blocks_with_one_time_ivks(BlockHeight::from(ACTIVATION), blocks as usize);
    r.st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let directory = serve(&[paid], tip(&r.st));
    run_clean(&mut r.st, &directory).await;
    let found = run(&mut r.st, other, &directory).await.unwrap();
    assert!(found.failed.is_empty(), "{:?}", found.failed);
    assert!(found.complete);
    let other_balance = r.st.get_total_balance(other).into_u64();
    assert_eq!(other_balance, VALUE);
    assert_eq!(balance(&r.st), 0);
}

/// Seen sets must commit to the wallet's genesis, as discovery's publication must: another
/// network's sets say nothing about this network's quotes. A publication without seen
/// sets, or with a provider that has a recent set but no seen set, may omit any receiver,
/// so issuance refuses it as discovery does. Once every provider has a dated seen set, the
/// sets cover the quote times they all cover, and hold what any of them holds.
#[tokio::test]
async fn seen_sets_need_this_network_and_every_provider() {
    let r = restored(&[]);
    // Provider `a` has its seen set only if `a_seen`. `b` has only a seen set, from a
    // later feed start and a later read.
    let sets = |a_seen: bool| {
        let mut sets = provider_named("a", &[receiver(&r.st, 0)]);
        sets.truncate(1 + usize::from(a_seen));
        let mut b = provider_named("b", &[receiver(&r.st, 1)]).pop().unwrap();
        b.since_unix = NOW - RESTORE_WATCH_SECS;
        b.until_unix = NOW - 30;
        sets.push(b);
        sets
    };
    for sets in [sets(false), Vec::new()] {
        let directory = Directory::new(publish(&[], &[], r.through, &sets));
        let refused = fetch_seen(ORIGIN, &directory, GENESIS).await;
        assert!(matches!(refused, Err(DirectoryError::Malformed)));
    }

    let directory = Directory::new(publish(&[], &[], r.through, &sets(true)));
    let refused = fetch_seen(ORIGIN, &directory, [8; 32]).await;
    let coverage = |e: &_| matches!(e, receiver_directory::Error::Coverage);
    assert_matches!(refused.err(), Some(DirectoryError::Directory(e)) if coverage(e));
    let seen = fetch_seen(ORIGIN, &directory, GENESIS).await.unwrap();
    assert_eq!(
        (seen.since(), seen.until()),
        (NOW - RESTORE_WATCH_SECS, NOW - 60)
    );
    let held = [0, 1, 2].map(|index| *receiver(&r.st, index).as_bytes());
    assert_eq!(seen.contains(&held), [true, true, false]);
}

/// Issuance takes [`fetch_seen`]'s sets as its [`ProviderSeen`]: a refund address they
/// hold is never issued.
#[tokio::test]
async fn issuance_skips_a_refund_address_in_the_fetched_seen_sets() {
    let mut r = restored(&[]);
    let parent = FullViewingKey::from(r.st.test_account().unwrap().usk().orchard());
    let refund = KeyId::new(Purpose::Refund, 0).derive(&parent).unwrap();
    let address = refund.address_at(0u32, Scope::External);
    let held = Receiver::from_bytes(address.to_raw_address_bytes()).unwrap();
    let sets = provider(&[held]);
    let directory = Directory::new(publish(&[], &[], r.through, &sets));
    // Issuance waits for the restored account's discovery.
    run_clean(&mut r.st, &directory).await;
    let seen = fetch_seen(ORIGIN, &directory, GENESIS).await.unwrap();
    let contains = |receivers: &[[u8; 43]]| seen.contains(receivers);
    let seen = ProviderSeen {
        until: seen.until(),
        contains: &contains,
    };
    let db = r.st.wallet_mut().db_mut();
    let key = db.reserve_refund_key(r.account, NOW, r.through.height, Some(&seen));
    // Discovery registered the seen refund index, so issuance takes the next one.
    assert_eq!(
        key.unwrap().unwrap().key_id(),
        KeyId::new(Purpose::Refund, 1)
    );
}

/// A run that left only an inclusion path to fetch, here because the witness file failed
/// to download, fetches it in the next run and completes.
#[tokio::test]
async fn a_run_with_only_a_path_due_fetches_it() {
    let mut r = restored(&[3]);
    let directory = serve(&r.records, r.through);
    assert!(
        run(&mut r.st, r.account, WithoutWitnesses(&directory))
            .await
            .is_err()
    );
    let status = r.st.wallet().db().one_time_discovery(r.account, NOW);
    let status = status.unwrap().unwrap();
    assert!(status.enumeration.is_none() && status.lookups.is_empty());
    assert_eq!(status.witnesses.len(), 1);
    let found = run_clean(&mut r.st, &directory).await;
    assert!(found.complete);
    assert_eq!(balance(&r.st), VALUE);
}

/// A search left unfinished against an older publication starts over from index zero
/// against a newer one, so a key it had already passed is checked against the newer
/// filters.
#[tokio::test]
async fn an_unfinished_search_starts_over_on_a_newer_publication() {
    let mut r = restored(&[5]);
    let older = stored_publication(&r.st, BlockHeight::from(ACTIVATION));
    let partway = EnumerationCursor {
        next: FIRST_WINDOW,
        reach: FIRST_WINDOW + 10,
    };
    let db = r.st.wallet_mut().db_mut();
    let receive = Purpose::Receive;
    assert!(
        db.record_one_time_filter_checks(r.account, older, receive, &[], partway, false, NOW)
            .unwrap()
    );
    let directory = serve(&r.records, r.through);
    let found = run_clean(&mut r.st, &directory).await;
    assert!(found.complete);
    assert_eq!(balance(&r.st), VALUE);
}

/// A key issuance registers for a lookup after the pass finished, from a provider's seen
/// set, waits without a lookup request for a publication that reaches the blocks the
/// wallet scanned without it. That publication's lookup finds its payment without starting
/// a new pass.
#[tokio::test]
async fn a_key_registered_after_the_pass_waits_for_a_newer_publication() {
    let mut r = restored(&[]);
    let first = serve(&[], r.through);
    assert!(run_clean(&mut r.st, &first).await.complete);
    let record = pay_restored_key(&mut r.st, 0, 0);
    r.st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let through = tip(&r.st);
    let sets = provider(&[receiver(&r.st, 0)]);
    let seen = Directory::new(publish(&[], &[], through, &sets));
    let seen = fetch_seen(ORIGIN, &seen, GENESIS).await.unwrap();
    let contains = |receivers: &[[u8; 43]]| seen.contains(receivers);
    let seen = ProviderSeen {
        until: seen.until(),
        contains: &contains,
    };
    let db = r.st.wallet_mut().db_mut();
    let issued = db.prepare_receive_reservation(r.account, NOW, through.height, Some(&seen));
    assert_eq!(issued.unwrap().unwrap().key_id().index(), 1);

    let requests = first.requests().len();
    let found = run_clean(&mut r.st, &first).await;
    assert!(!found.complete);
    assert_eq!(found.lookups, 0);
    assert_eq!(first.requests().len(), requests + 1, "only the manifest");

    let newer = serve(&[record], through);
    let found = run_clean(&mut r.st, &newer).await;
    assert!(found.complete);
    assert_eq!(balance(&r.st), VALUE);
    let requests = newer.requests();
    assert!(
        !requests.iter().any(|r| r.contains("/filters/")),
        "{requests:?}"
    );
}

/// A lookup resumed from its cursor starts over from page zero when the record before the
/// cursor changed, here because an earlier revision omitted a payment, so it finds that
/// payment.
#[tokio::test]
async fn a_lookup_whose_cursor_record_changed_starts_over() {
    let mut r = restored(&[3, 3]);
    let commitments: Vec<_> = r.records.iter().map(|x| x.payment.cmx).collect();
    let mut second = r.records[1].clone();
    (second.page, second.total) = (0, 1);
    let omitting = Directory::new(publish(&[second], &commitments, r.through, &provider(&[])));
    run_clean(&mut r.st, &omitting).await;
    assert_eq!(balance(&r.st), VALUE);
    // Check swap history reads the paid key's history again from its cursor.
    let db = r.st.wallet_mut().db_mut();
    db.recheck_one_time_key_history(r.account).unwrap();
    let directory = serve(&r.records, r.through);
    let found = run_clean(&mut r.st, &directory).await;
    assert!(found.complete);
    assert_eq!(balance(&r.st), 2 * VALUE);
}
