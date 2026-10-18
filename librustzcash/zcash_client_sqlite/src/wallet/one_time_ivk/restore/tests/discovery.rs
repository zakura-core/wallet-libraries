use super::*;
use zakura_one_time_ivk::Purpose;
use zcash_client_backend::data_api::one_time_ivk::restore::{DiscoveryStatus, LookupWork};

/// Receive key 8, which the fixtures pay before registering it.
pub(in crate::wallet::one_time_ivk) fn key8() -> KeyId {
    KeyId::new(Purpose::Receive, 8)
}

/// A filter check that marks `key` seen and paid.
pub(in crate::wallet::one_time_ivk) fn paid(key: KeyId) -> FilterCheck {
    FilterCheck {
        key,
        seen: true,
        paid: true,
        recent: false,
    }
}

/// The publication ending at cached block `height`, as the directory declares it, whether
/// or not the wallet stored that block.
pub(in crate::wallet::one_time_ivk) fn publication_at(
    st: &State,
    height: BlockHeight,
) -> PublicationEnd {
    let data: Vec<u8> = value(
        &st.cache().0,
        "SELECT data FROM compactblocks WHERE height = ?1",
        [u32::from(height)],
    );
    let block = CompactBlock::decode(data.as_slice()).unwrap();
    PublicationEnd {
        height,
        hash: block.hash().0,
        tree_size: block
            .chain_metadata
            .unwrap()
            .ironwood_commitment_tree_size
            .into(),
    }
}

/// Runs a whole discovery pass of `account` against `publication`: incoming `checks`, and
/// no refund key used. Returns whether the store took the publication.
pub(in crate::wallet::one_time_ivk) fn run_pass(
    db: &mut Db,
    account: AccountUuid,
    publication: PublicationEnd,
    checks: &[FilterCheck],
) -> bool {
    let done = EnumerationCursor {
        next: 100,
        reach: 100,
    };
    let now = clock_now();
    let took = db
        .record_one_time_filter_checks(
            account,
            publication,
            Purpose::Receive,
            checks,
            done,
            true,
            now,
        )
        .unwrap();
    took && db
        .record_one_time_filter_checks(account, publication, Purpose::Refund, &[], done, true, now)
        .unwrap()
}

/// `account`'s discovery status.
pub(in crate::wallet::one_time_ivk) fn status(db: &Db, account: AccountUuid) -> DiscoveryStatus {
    db.one_time_discovery(account, clock_now())
        .unwrap()
        .unwrap()
}

/// Records `payments` as `key`'s whole history read from `revision`, from page zero.
pub(in crate::wallet::one_time_ivk) fn look_up(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    revision: PublicationEnd,
    payments: &[PendingPayment],
) -> bool {
    let records: Vec<_> = payments.iter().map(directory_answer).collect();
    db.record_one_time_lookup(account, key, revision, 0, &records, true, clock_now())
        .unwrap()
}

/// The path of the chain's Ironwood leaf at `position` at the cached tip.
pub(in crate::wallet::one_time_ivk) fn witness_at(st: &State, position: u32) -> MerklePath {
    use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    let mut witness: Option<IncrementalWitness<_, 32>> = None;
    let blocks: Vec<Vec<u8>> = column(
        &st.cache().0,
        "SELECT data FROM compactblocks ORDER BY height",
        [],
    );
    let actions = blocks
        .iter()
        .flat_map(|data| CompactBlock::decode(data.as_slice()).unwrap().vtx)
        .flat_map(|tx| tx.ironwood_actions);
    for (leaf, action) in actions.enumerate() {
        let cmx = MerkleHashOrchard::from_cmx(&action.cmx().unwrap());
        match &mut witness {
            Some(witness) => witness.append(cmx).unwrap(),
            None => {
                tree.append(cmx).unwrap();
                if leaf == position as usize {
                    witness = IncrementalWitness::from_tree(tree.clone());
                }
            }
        }
    }
    witness.unwrap().path().unwrap().into()
}

/// `path`'s sibling hashes, as the directory serves them.
pub(in crate::wallet::one_time_ivk) fn siblings(path: &MerklePath) -> [[u8; 32]; 32] {
    std::array::from_fn(|level| path.auth_path()[level].to_bytes())
}

/// Records the path of `key`'s late payment `candidate` at the scanned tip.
pub(in crate::wallet::one_time_ivk) fn send_witness(
    st: &mut State,
    key: KeyId,
    candidate: &PendingPayment,
) {
    let account = st.test_account().unwrap().id();
    let (anchor, path) = (tip(st), witness_at(st, candidate.position));
    let db = st.wallet_mut().db_mut();
    db.record_one_time_witness(
        account,
        key,
        candidate.position,
        anchor,
        siblings(&path),
        clock_now(),
    )
    .unwrap();
}

/// Pays [`key8`] in a [`restored_wallet`] before the wallet knows the key and scans past
/// the payment, then runs a pass that finds the key paid and records its lookup: the
/// payment is a late candidate. Returns the payment and the publication, which ends at the
/// scanned tip.
pub(in crate::wallet::one_time_ivk) fn late_fixture() -> (State, PendingPayment, PublicationEnd) {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    st.generate_and_scan_empty_blocks_with_one_time_ivks(2);
    let publication = discover(&mut st, account, &[paid(key8())]);
    let db = st.wallet_mut().db_mut();
    assert!(look_up(
        db,
        account,
        key8(),
        publication,
        &[candidate.clone()]
    ));
    (st, candidate, publication)
}

/// The note values the wallet holds for one-time keys, with whether each is spent.
pub(in crate::wallet::one_time_ivk) fn one_time_notes(st: &State) -> Vec<(i64, bool)> {
    rows(
        st.wallet().conn(),
        "SELECT n.value, EXISTS(SELECT 1 FROM ironwood_received_note_spends s
             WHERE s.ironwood_received_note_id = n.id)
         FROM ironwood_received_notes n WHERE n.one_time_key_id IS NOT NULL ORDER BY n.id",
        [],
    )
}

/// A payment found after the scan passed its block waits for its inclusion path, then is
/// admitted unspent, once, and discovery completes.
#[test]
fn a_late_payment_is_admitted_once_its_path_arrives() {
    let (mut st, candidate, publication) = late_fixture();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let found = status(db, account);
    assert_eq!(found.publication, Some(publication));
    // The waiting payment keeps discovery incomplete, so the app keeps running it.
    assert!(!found.complete);
    assert!(found.lookups.is_empty());
    assert_eq!(found.witnesses.len(), 1);
    assert_eq!(found.witnesses[0].position, candidate.position);
    assert!(one_time_notes(&st).is_empty());

    send_witness(&mut st, key8(), &candidate);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    let db = st.wallet_mut().db_mut();
    assert!(pending(db, account, key8()).is_empty());
    let found = status(db, account);
    assert!(found.witnesses.is_empty());
    assert!(found.complete);
    // The same answer again changes nothing.
    assert!(!look_up(db, account, key8(), publication, &[candidate]));
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A late payment whose note was spent before discovery found it is admitted spent: the
/// spending transaction carries an output the scan recognized, so the journal holds the
/// note's nullifier.
#[test]
fn a_spent_late_payment_is_admitted_spent_through_the_journal() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    let note = candidate
        .encrypted_note
        .decrypt(&parent(&st), key8())
        .unwrap();
    let spender = IronwoodFvk(parent(&st));
    let (height, _) = st.generate_next_block_spending(
        &spender,
        (*note.nullifier(), Zatoshis::const_from_u64(100_000)),
        unified(foreign_receiver()),
        Zatoshis::const_from_u64(20_000),
    );
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(2);
    let publication = discover(&mut st, account, &[paid(key8())]);
    let db = st.wallet_mut().db_mut();
    assert!(look_up(
        db,
        account,
        key8(),
        publication,
        &[candidate.clone()]
    ));
    send_witness(&mut st, key8(), &candidate);
    assert_eq!(one_time_notes(&st), [(100_000, true)]);
}

/// A late payment whose sibling leaf the wallet already holds unpruned is admitted with
/// that sibling intact. Here the sibling is the funder's change after it, its block's last
/// leaf, which the wallet keeps as a reference once a later scan starts after that block.
/// Inserting the sibling's hash before the marked payment let the pair prune, and
/// inserting the payment under the pruned node then lost the sibling.
#[test]
fn a_late_payment_keeps_a_sibling_the_wallet_already_holds() {
    let foreign = orchard::keys::FullViewingKey::from(
        &orchard::keys::SpendingKey::from_bytes([3; 32]).unwrap(),
    );
    let receiver = derive(&ironwood_wallet(), key8()).address_at(0u32, Scope::External);
    // The payment is the first of its bundle's two actions in some attempts.
    for _ in 0..40 {
        let tx = external_payment(receiver, &zcash_protocol::memo::MemoBytes::empty());
        let mut st = ironwood_wallet();
        let account = st.test_account().unwrap().id();
        let (height, _) = st.generate_next_block_from_tx(1, &tx);
        st.scan_cached_blocks_with_one_time_ivks(height, 1);
        let candidate = candidate_at(&st, height, &derive(&st, key8()));
        if candidate.position != 0 {
            continue;
        }
        // A later scan starts after the payment's block.
        pay(&mut st, &foreign, 10_000);
        let publication = discover(&mut st, account, &[paid(key8())]);
        let db = st.wallet_mut().db_mut();
        assert!(look_up(
            db,
            account,
            key8(),
            publication,
            &[candidate.clone()]
        ));
        send_witness(&mut st, key8(), &candidate);
        assert_eq!(one_time_notes(&st), [(50_000, false)]);
        assert_eq!(notes(&st, tip(&st).height).len(), 1);
        return;
    }
    panic!("the payment was never its bundle's first action");
}

/// A publication above the wallet's chain tip, or older than the current pass's, is
/// refused.
#[test]
fn stale_and_future_publications_are_refused() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let current = publication_at(&st, tip(&st).height);
    let mut future = current;
    future.height = current.height + 10;
    let db = st.wallet_mut().db_mut();
    assert!(!run_pass(db, account, future, &[]));
    assert!(run_pass(db, account, current, &[]));
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    discover(&mut st, account, &[]);
    let db = st.wallet_mut().db_mut();
    assert!(!run_pass(db, account, current, &[]));
}

/// A rewind below a late payment returns it to a hint, which the rescan settles.
#[test]
fn a_rewind_returns_late_payments_to_hints() {
    let (mut st, candidate, _) = late_fixture();
    st.truncate_to_height_retaining_cache(candidate.height - 1);
    assert!(scan_hint(&st));
    let tip = st.latest_cached_block().unwrap().height();
    st.scan_cached_blocks_with_one_time_ivks(
        candidate.height,
        u32::from(tip - candidate.height) as usize + 1,
    );
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A publication ending before the birthday completes discovery without lookups, still
/// protecting its paid keys from issuance. Its keys close, so a recheck checks them for a
/// payment after the birthday.
#[test]
fn a_publication_before_the_birthday_needs_no_lookups() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let birthday = st.test_account().unwrap().birthday().height();
    let publication = PublicationEnd {
        height: birthday - 1,
        hash: [3; 32],
        tree_size: 0,
    };
    let db = st.wallet_mut().db_mut();
    assert!(run_pass(db, account, publication, &[paid(key8())]));
    let found = status(db, account);
    assert!(found.complete);
    assert!(found.lookups.is_empty());
    assert!(key_state(db, key8()).1);
}

/// Whether the wallet's one queued candidate is a scan hint rather than a late candidate.
fn scan_hint(st: &State) -> bool {
    value(
        st.wallet().conn(),
        "SELECT scan_hint FROM ironwood_one_time_payment_recovery",
        [],
    )
}

/// Mines, without scanning, a block paying [`key8`] above a scanned tip, and runs a pass
/// whose publication ends there, recording the payment: a scan hint. Returns the payment.
fn hint_fixture() -> (State, PendingPayment) {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let fvk = derive(&st, key8());
    let amount = Zatoshis::const_from_u64(100_000);
    let paid_to = IronwoodFvk(fvk.clone());
    let (height, _, _) = st.generate_next_block(&paid_to, AddressType::DefaultExternal, amount);
    let candidate = candidate_at(&st, height, &fvk);
    st.wallet_mut().update_chain_tip(height).unwrap();
    let publication = publication_at(&st, height);
    let db = st.wallet_mut().db_mut();
    assert!(run_pass(db, account, publication, &[paid(key8())]));
    assert!(look_up(
        db,
        account,
        key8(),
        publication,
        &[candidate.clone()]
    ));
    assert!(scan_hint(&st));
    (st, candidate)
}

/// A payment whose block the scan has not stored is a hint: the batch holding it tries the
/// key, finds the note itself, judges the publication, and leaves nothing pending.
#[test]
fn a_hint_is_found_by_the_scan() {
    let (mut st, candidate) = hint_fixture();
    let account = st.test_account().unwrap().id();
    assert!(!status(st.wallet_mut().db_mut(), account).complete);
    st.scan_cached_blocks_with_one_time_ivks(candidate.height, 1);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    let db = st.wallet_mut().db_mut();
    assert!(pending(db, account, key8()).is_empty());
    assert!(status(db, account).complete);
}

/// A scan that did not try a hint's key, here a plain scan, leaves its payment late; the
/// late path then admits it.
#[test]
fn a_hint_a_scan_skips_becomes_late() {
    let (mut st, candidate) = hint_fixture();
    st.scan_cached_blocks(candidate.height, 1);
    assert!(one_time_notes(&st).is_empty());
    assert!(!scan_hint(&st));
    send_witness(&mut st, key8(), &candidate);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A hint the scan tried and missed is the directory's error: its lookup restarts from page
/// zero, backed off so a directory that keeps giving it does not loop.
#[test]
fn a_missed_hint_restarts_its_lookup_backed_off() {
    let (mut st, candidate) = hint_fixture();
    let account = st.test_account().unwrap().id();
    // The record claims the next position, which holds no note for the key.
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_payment_recovery SET position = position + 1",
        [],
    );
    st.scan_cached_blocks_with_one_time_ivks(candidate.height, 1);
    let db = st.wallet_mut().db_mut();
    assert!(pending(db, account, key8()).is_empty());
    let (cutoff, next_attempt): (Option<u32>, i64) = row(
        &db.conn,
        "SELECT cutoff_height, next_attempt_at FROM ironwood_one_time_lookups",
        [],
    );
    assert!(cutoff.is_some());
    assert!(next_attempt > clock_now());
    assert!(status(db, account).lookups.is_empty());
}

/// A fresh account's key registered for a lookup after discovery finished, as a recovered
/// refund key is, keeps discovery incomplete until a pass looks it up.
#[test]
fn a_fresh_accounts_waiting_lookup_keeps_discovery_incomplete() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let from = tip(&st).height + 1;
    let db = st.wallet_mut().db_mut();
    let key = reserve_key(db, account, Purpose::Receive, from).key_id();
    exec(
        &db.conn,
        "INSERT INTO ironwood_one_time_lookups (one_time_key_id)
         SELECT id FROM ironwood_one_time_keys WHERE key_index = ?1",
        [key.index().to_be_bytes()],
    );
    let found = status(db, account);
    assert!(!found.complete);
    assert!(found.publication.is_none());
    discover(&mut st, account, &[]);
    let due = status(st.wallet().db(), account).lookups;
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].work.key, key);
}

/// A publication whose last block differs from the wallet's is rejected: nothing is due
/// against it, and the account waits for a newer one. Its paid key's lookup stays due in
/// the next pass.
#[test]
fn a_publication_off_the_wallets_chain_is_rejected() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let mut publication = publication_at(&st, tip(&st).height);
    publication.hash = [9; 32];
    let db = st.wallet_mut().db_mut();
    assert!(run_pass(db, account, publication, &[paid(key8())]));
    let found = status(db, account);
    assert!(!found.complete);
    assert!(found.lookups.is_empty());
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let publication = discover(&mut st, account, &[]);
    let db = st.wallet_mut().db_mut();
    let found = status(db, account);
    assert!(!found.complete);
    assert_eq!(found.lookups.len(), 1);
    assert!(look_up(db, account, key8(), publication, &[]));
    assert!(status(db, account).complete);
}

/// A publication rejected for its tree size can be corrected at the same block, and a claim
/// that contradicts an accepted one is refused. Another account's pass over the rejected
/// claim starts over.
#[test]
fn a_rejected_tree_size_can_be_corrected() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let seed = SecretVec::new(vec![3; 32]);
    let birthday = st.test_account().unwrap().birthday().clone();
    let (other, _) = st
        .wallet_mut()
        .db_mut()
        .create_account("other", &seed, &birthday, None)
        .unwrap();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let publication = publication_at(&st, tip(&st).height);
    let wrong = PublicationEnd {
        tree_size: publication.tree_size + 1,
        ..publication
    };
    let db = st.wallet_mut().db_mut();
    assert!(run_pass(db, other, wrong, &[]));
    assert!(run_pass(db, account, wrong, &[paid(key8())]));
    let found = status(db, account);
    assert!(found.publication.is_none());
    assert!(found.lookups.is_empty());
    assert!(run_pass(db, account, publication, &[paid(key8())]));
    let found = status(db, account);
    assert_eq!(found.publication, Some(publication));
    assert_eq!(found.lookups.len(), 1);
    assert!(!run_pass(db, account, wrong, &[]));
    assert!(!look_up(db, account, key8(), wrong, &[]));
    assert!(look_up(db, account, key8(), publication, &[]));
    assert!(status(db, account).complete);
    let found = status(db, other);
    assert!(found.publication.is_none());
    assert!(!found.complete);
}

/// A recheck reads again the history of a key with a known payment, including one before
/// the birthday, but not of a key the filters only marked seen, which waits for newer
/// filters to mark it paid.
#[test]
fn a_recheck_looks_up_only_keys_with_payments() {
    let (mut st, candidate, _) = late_fixture();
    let account = st.test_account().unwrap().id();
    send_witness(&mut st, key8(), &candidate);
    let seen = |index| FilterCheck {
        key: KeyId::new(Purpose::Receive, index),
        paid: false,
        ..paid(key8())
    };
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    discover(&mut st, account, &[seen(9), seen(10)]);
    let db = st.wallet_mut().db_mut();
    exec(
        &db.conn,
        "UPDATE ironwood_one_time_keys SET paid_before_birthday = 1 WHERE key_index = ?1",
        [10u64.to_be_bytes()],
    );
    db.recheck_one_time_key_history(account).unwrap();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    discover(&mut st, account, &[]);
    let db = st.wallet_mut().db_mut();
    let due: Vec<KeyId> = status(db, account)
        .lookups
        .iter()
        .map(|l| l.work.key)
        .collect();
    assert_eq!(due, [key8(), KeyId::new(Purpose::Receive, 10)]);
}

/// A filter hit on a closed key past the searched range, maybe a false positive at a sparse
/// index, does not move refund issuance past it.
#[test]
fn a_hit_past_the_search_does_not_advance_allocation() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    let sparse = FilterCheck {
        key: KeyId::new(Purpose::Refund, 1_000_000),
        paid: false,
        ..paid(key8())
    };
    let searched = EnumerationCursor {
        next: 100,
        reach: 100,
    };
    let db = st.wallet_mut().db_mut();
    for (purpose, checks) in [(Purpose::Receive, vec![]), (Purpose::Refund, vec![sparse])] {
        assert!(
            db.record_one_time_filter_checks(
                account,
                publication,
                purpose,
                &checks,
                searched,
                true,
                clock_now()
            )
            .unwrap()
        );
    }
    let next = reserve_key(db, account, Purpose::Refund, start());
    assert_eq!(next.key_id().index(), 0);
}

/// An unknown account is an error, not an account with no discovery to run.
#[test]
fn an_unknown_accounts_discovery_is_an_error() {
    let st = restored_wallet();
    let unknown = AccountUuid::from_uuid(uuid::Uuid::nil());
    assert!(matches!(
        st.wallet().db().one_time_discovery(unknown, clock_now()),
        Err(SqliteClientError::AccountUnknown)
    ));
}

/// A key the filters mark seen but not paid closes even when the publication was accepted
/// before the pass registered it, so a newer publication rechecks it.
#[test]
fn a_seen_key_closes_against_an_accepted_publication() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let seen = FilterCheck {
        paid: false,
        ..paid(key8())
    };
    discover(&mut st, account, &[seen]);
    let db = st.wallet_mut().db_mut();
    let (closed,): (bool,) = row(
        &db.conn,
        "SELECT closed_at IS NOT NULL FROM ironwood_one_time_keys WHERE key_index = ?1",
        [key8().index().to_be_bytes()],
    );
    assert!(closed);
    assert!(status(db, account).complete);
}

/// A page refused for a bad record keeps nothing it queued before that record, so the
/// corrected page is taken.
#[test]
fn a_refused_page_queues_nothing() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let publication = discover(&mut st, account, &[paid(key8())]);
    let db = st.wallet_mut().db_mut();
    let beyond = DirectoryPayment {
        height: u32::from(publication.height) + 1,
        ..directory_answer(&candidate)
    };
    let page = [directory_answer(&candidate), beyond];
    assert!(
        !db.record_one_time_lookup(account, key8(), publication, 0, &page, true, clock_now())
            .unwrap()
    );
    assert!(pending(db, account, key8()).is_empty());
    exec(
        &db.conn,
        "UPDATE ironwood_one_time_lookups SET next_attempt_at = 0",
        [],
    );
    assert!(look_up(db, account, key8(), publication, &[candidate]));
    assert_eq!(pending(db, account, key8()).len(), 1);
}

/// Paging resumes from the cursor and refuses a page that does not continue it.
#[test]
fn paging_resumes_from_its_cursor() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let first = pay_candidate(&mut st, key8());
    let fvk = derive(&st, key8());
    let height = pay(&mut st, &fvk, 50_000);
    let second = candidate_at(&st, height, &fvk);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    // The scan did not know the key, so both payments are late.
    assert!(unspent_keys(&st, tip(&st).height).is_empty());
    let publication = discover(&mut st, account, &[paid(key8())]);
    let db = st.wallet_mut().db_mut();
    let now = clock_now();
    let page = |p: &PendingPayment| [directory_answer(p)];
    let record = |db: &mut Db, from: u32, p: &PendingPayment, done: bool| {
        db.record_one_time_lookup(account, key8(), publication, from, &page(p), done, now)
            .unwrap()
    };
    assert!(record(db, 0, &first, false));
    let LookupWork { applied, last, .. } = status(db, account).lookups[0].clone();
    assert_eq!(applied, 1);
    assert_eq!(
        last.map(|(position, _)| position),
        Some(u64::from(first.position))
    );
    assert!(!record(db, 2, &second, true));
    assert!(record(db, 1, &second, true));
    let found = status(db, account);
    assert!(found.lookups.is_empty());
    assert_eq!(found.witnesses.len(), 2);
}

/// A fresh account needs no discovery, even once a key it issued closes without a payment,
/// until a recheck asks for it. The recheck's pass looks up the closed key the filters mark
/// paid, and its discovery stays visible while that lookup is unfinished, even once a
/// payment it found leaves no key closed unpaid. Issuance waits only for the pass's
/// registration.
#[test]
fn a_fresh_account_rechecks_on_request() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    // The key starts after its payment, so the scan misses it and discovery finds it late.
    let after = tip(&st).height + 10;
    let db = st.wallet_mut().db_mut();
    assert!(
        db.one_time_discovery(account, clock_now())
            .unwrap()
            .is_none()
    );
    let key = reserve_key(db, account, Purpose::Receive, after).key_id();
    exec(
        &db.conn,
        "UPDATE ironwood_one_time_keys SET closed_at = 1 WHERE key_index = ?1",
        [key.index().to_be_bytes()],
    );
    assert!(
        db.one_time_discovery(account, clock_now())
            .unwrap()
            .is_none()
    );
    db.recheck_one_time_key_history(account).unwrap();
    assert!(status(db, account).publication.is_none());
    let candidate = pay_candidate(&mut st, key);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let publication = discover(&mut st, account, &[paid(key)]);
    let db = st.wallet_mut().db_mut();
    let page = [directory_answer(&candidate)];
    assert!(
        db.record_one_time_lookup(account, key, publication, 0, &page, false, clock_now())
            .unwrap()
    );
    send_witness(&mut st, key, &candidate);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    let db = st.wallet_mut().db_mut();
    let found = status(db, account);
    assert!(!found.complete);
    assert_eq!(found.lookups.len(), 1);
    assert!(
        prepare_from(
            db,
            account,
            clock_now(),
            after,
            Some(&empty_seen(clock_now()))
        )
        .unwrap()
        .is_ok()
    );
    assert!(
        db.record_one_time_lookup(account, key, publication, 1, &[], true, clock_now())
            .unwrap()
    );
    assert!(status(db, account).complete);
}

/// A late payment whose blocks the scan finished without journal coverage, as before the
/// journal existed, has those blocks scanned again, then is admitted.
#[test]
fn a_late_payment_over_uncovered_blocks_is_rescanned() {
    let (mut st, candidate, _) = late_fixture();
    exec(
        st.wallet().conn(),
        "DELETE FROM ironwood_journal_coverage",
        [],
    );
    send_witness(&mut st, key8(), &candidate);
    assert!(one_time_notes(&st).is_empty());
    let queued: Vec<(u32, u32)> = rows(
        st.wallet().conn(),
        "SELECT block_range_start, block_range_end FROM scan_queue WHERE priority != ?1",
        [crate::wallet::scanning::priority_code(
            &ScanPriority::Scanned,
        )],
    );
    assert_eq!(
        queued.first().map(|r| r.0),
        Some(u32::from(candidate.height))
    );
    let tip = st.latest_cached_block().unwrap().height();
    let blocks = u32::from(tip) - u32::from(candidate.height) + 1;
    st.scan_cached_blocks_with_one_time_ivks(candidate.height, blocks as usize);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A lookup still due when a newer pass starts reads on to the newer publication's end,
/// keeping its cursor, so it finds a payment between the two. It refuses a revision ending
/// below that cutoff, which cannot show the history through it.
#[test]
fn a_new_pass_raises_a_due_lookups_cutoff() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let first = discover(&mut st, account, &[paid(key8())]);
    let candidate = pay_candidate(&mut st, key8());
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let second = discover(&mut st, account, &[paid(key8())]);
    let db = st.wallet_mut().db_mut();
    let due = status(db, account).lookups;
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].cutoff, second.height);
    assert!(!look_up(db, account, key8(), first, &[]));
    assert!(look_up(db, account, key8(), second, &[candidate]));
    assert_eq!(status(db, account).witnesses.len(), 1);
}

/// A key registered for a lookup after its account's pass, as a refund key recovered from
/// a funding memo is, is looked up through every block the scan stored without it, not
/// only through the pass's publication.
#[test]
fn a_key_registered_after_the_pass_is_looked_up_through_the_scanned_blocks() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let pass = discover(&mut st, account, &[]);
    let candidate = pay_candidate(&mut st, key8());
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let scanned = publication_at(&st, tip(&st).height);
    let db = st.wallet_mut().db_mut();
    recover(db, account, key8(), candidate.height);
    let due = status(db, account).lookups;
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].cutoff, scanned.height);
    assert!(!look_up(db, account, key8(), pass, &[]));
    assert!(look_up(db, account, key8(), scanned, &[candidate]));
    assert_eq!(status(db, account).witnesses.len(), 1);
}

/// Mines an empty block above the scanned tip without scanning it, learns the new chain
/// tip, and returns the publication ending at that block.
fn unscanned_publication(st: &mut State) -> PublicationEnd {
    let (height, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(height).unwrap();
    publication_at(st, height)
}

/// A lookup read from a revision the scan has not judged yet keeps discovery incomplete,
/// even with nothing found, until the scan finds that revision on the wallet's chain.
#[test]
fn a_lookup_from_an_unjudged_revision_keeps_discovery_incomplete() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    discover(&mut st, account, &[paid(key8())]);
    let revision = unscanned_publication(&mut st);
    let db = st.wallet_mut().db_mut();
    assert!(look_up(db, account, key8(), revision, &[]));
    assert!(!status(db, account).complete);
    st.scan_cached_blocks_with_one_time_ivks(revision.height, 1);
    assert!(status(st.wallet().db(), account).complete);
}

/// A lookup read from a revision the scan then finds off the wallet's chain starts over
/// from page zero, dropping that read and the payment it supplied, and the payment comes
/// back from a revision that matches.
#[test]
fn a_lookup_from_a_rejected_revision_starts_over() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    discover(&mut st, account, &[paid(key8())]);
    let revision = unscanned_publication(&mut st);
    let wrong = PublicationEnd {
        hash: [9; 32],
        ..revision
    };
    let db = st.wallet_mut().db_mut();
    assert!(look_up(
        db,
        account,
        key8(),
        wrong,
        std::slice::from_ref(&candidate)
    ));
    st.scan_cached_blocks_with_one_time_ivks(revision.height, 1);
    let db = st.wallet_mut().db_mut();
    assert!(pending(db, account, key8()).is_empty());
    let due = status(db, account).lookups;
    assert_eq!(due.len(), 1);
    assert_eq!((due[0].applied, due[0].last), (0, None));
    assert!(look_up(
        db,
        account,
        key8(),
        revision,
        std::slice::from_ref(&candidate)
    ));
    send_witness(&mut st, key8(), &candidate);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert!(status(st.wallet().db(), account).complete);
}

/// A late payment whose path does not lead to the wallet's root is the directory's error:
/// the payment is dropped and its lookup starts over, backed off.
#[test]
fn a_late_payment_with_a_wrong_path_is_looked_up_again() {
    let (mut st, candidate, _) = late_fixture();
    let account = st.test_account().unwrap().id();
    let (anchor, path) = (tip(&st), witness_at(&st, candidate.position));
    let mut siblings = siblings(&path);
    siblings[0] = siblings[1];
    let db = st.wallet_mut().db_mut();
    db.record_one_time_witness(
        account,
        key8(),
        candidate.position,
        anchor,
        siblings,
        clock_now(),
    )
    .unwrap();
    assert!(pending(db, account, key8()).is_empty());
    let (cutoff, applied, next_attempt): (Option<u32>, u32, i64) = row(
        &db.conn,
        "SELECT cutoff_height, applied, next_attempt_at FROM ironwood_one_time_lookups",
        [],
    );
    assert!(cutoff.is_some());
    assert_eq!(applied, 0);
    assert!(next_attempt > clock_now());
    assert!(one_time_notes(&st).is_empty());
}

/// A late payment waits while the scan's coverage ends one block short of its scanned tip,
/// since a spend of the note there may be missing from the journal. Scanning that block
/// again covers it, and the payment is admitted spent.
#[test]
fn a_late_payment_waits_for_coverage_of_the_scanned_tip() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    let note = candidate
        .encrypted_note
        .decrypt(&parent(&st), key8())
        .unwrap();
    let spender = IronwoodFvk(parent(&st));
    let (height, _) = st.generate_next_block_spending(
        &spender,
        (*note.nullifier(), Zatoshis::const_from_u64(100_000)),
        unified(foreign_receiver()),
        Zatoshis::const_from_u64(20_000),
    );
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
    let publication = discover(&mut st, account, &[paid(key8())]);
    let db = st.wallet_mut().db_mut();
    assert!(look_up(
        db,
        account,
        key8(),
        publication,
        std::slice::from_ref(&candidate)
    ));
    // The spending block was stored without coverage, so without its journal entry.
    let tip = u32::from(height);
    for sql in [
        "UPDATE ironwood_journal_coverage SET end_height = ?1 WHERE end_height > ?1",
        "DELETE FROM ironwood_spend_journal_nullifiers WHERE block_height = ?1",
        "DELETE FROM ironwood_spend_journal WHERE block_height = ?1",
    ] {
        exec(&db.conn, sql, [tip]);
    }
    send_witness(&mut st, key8(), &candidate);
    assert!(one_time_notes(&st).is_empty());
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
    assert_eq!(one_time_notes(&st), [(100_000, true)]);
}

/// A late payment over a one-block hole in the scan's coverage has that block scanned
/// again, then is admitted.
#[test]
fn a_late_payment_over_a_one_block_coverage_hole_is_rescanned() {
    let (mut st, candidate, _) = late_fixture();
    let hole = u32::from(candidate.height) + 1;
    let conn = st.wallet().conn();
    exec(
        conn,
        "INSERT INTO ironwood_journal_coverage (account_id, start_height, end_height)
         SELECT account_id, ?1 + 1, end_height FROM ironwood_journal_coverage
         WHERE start_height <= ?1 AND end_height > ?1 + 1",
        [hole],
    );
    exec(
        conn,
        "UPDATE ironwood_journal_coverage SET end_height = ?1
         WHERE start_height <= ?1 AND end_height > ?1 + 1",
        [hole],
    );
    send_witness(&mut st, key8(), &candidate);
    assert!(one_time_notes(&st).is_empty());
    let queued: Vec<(u32, u32)> = rows(
        st.wallet().conn(),
        "SELECT block_range_start, block_range_end FROM scan_queue WHERE priority != ?1",
        [crate::wallet::scanning::priority_code(
            &ScanPriority::Scanned,
        )],
    );
    assert!(queued.contains(&(hole, hole + 1)), "{queued:?}");
    st.scan_cached_blocks_with_one_time_ivks(BlockHeight::from(hole), 1);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A late payment the scan has since stored under another action is redundant: its path
/// dequeues it, and discovery completes.
#[test]
fn a_late_payment_the_scan_stored_elsewhere_is_dequeued() {
    let (mut st, candidate, _) = late_fixture();
    let account = st.test_account().unwrap().id();
    activate_key(st.wallet_mut().db_mut(), account, key8(), candidate.height);
    let tip = st.latest_cached_block().unwrap().height();
    let blocks = (tip - candidate.height) as usize + 1;
    st.scan_cached_blocks_with_one_time_ivks(candidate.height, blocks);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    // The directory's claim names another action of the transaction.
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_payment_recovery SET action_index = action_index + 1",
        [],
    );
    let claimed = PendingPayment {
        action_index: candidate.action_index + 1,
        ..candidate.clone()
    };
    send_witness(&mut st, key8(), &claimed);
    let db = st.wallet_mut().db_mut();
    assert!(pending(db, account, key8()).is_empty());
    assert!(status(db, account).complete);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// Issuance waits until the pass checked both purposes against a publication that matched
/// the wallet's chain: not while the scan has yet to judge it, nor before the refund keys
/// are checked.
#[test]
fn issuance_waits_for_both_purposes_against_a_judged_publication() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let unjudged = unscanned_publication(&mut st);
    let gap = |db: &mut Db, tip| {
        matches!(
            db.reserve_refund_key(account, tip, None),
            Ok(Err(ReservationPolicy::Gap))
        )
    };
    let db = st.wallet_mut().db_mut();
    assert!(run_pass(db, account, unjudged, &[]));
    assert!(gap(db, unjudged.height));
    st.scan_cached_blocks_with_one_time_ivks(unjudged.height, 1);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let newer = publication_at(&st, tip(&st).height);
    let done = EnumerationCursor {
        next: 100,
        reach: 100,
    };
    let db = st.wallet_mut().db_mut();
    let check = |db: &mut Db, purpose| {
        db.record_one_time_filter_checks(account, newer, purpose, &[], done, true, clock_now())
            .unwrap()
    };
    assert!(check(db, Purpose::Receive));
    assert!(gap(db, newer.height));
    assert!(check(db, Purpose::Refund));
    let key = db.reserve_refund_key(account, newer.height, None).unwrap();
    assert_eq!(key.unwrap().key_id(), KeyId::new(Purpose::Refund, 0));
}

/// A payment from before the account's birthday is never a scan hint, since the scan never
/// stores its block: it waits for its path, then marks its key paid before the birthday.
#[test]
fn a_payment_before_the_birthday_is_late_not_a_hint() {
    let mut st = ironwood_wallet();
    let seed = SecretVec::new(vec![3; 32]);
    let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
        st.network(),
        seed.expose_secret(),
        zip32::AccountId::ZERO,
    )
    .unwrap();
    let fvk = key8().derive(&FullViewingKey::from(usk.orchard())).unwrap();
    let paid_to = IronwoodFvk(fvk.clone());
    let amount = Zatoshis::const_from_u64(100_000);
    let (height, _, _) = st.generate_next_block(&paid_to, AddressType::DefaultExternal, amount);
    let candidate = candidate_at(&st, height, &fvk);
    // Born after the payment, whose block the wallet never stores.
    let prior = st.latest_cached_block().unwrap().chain_state().clone();
    let birthday = zcash_client_backend::data_api::AccountBirthday::from_parts(prior, None);
    let db = st.wallet_mut().db_mut();
    let (other, created) = db.create_account("other", &seed, &birthday, None).unwrap();
    assert_eq!(created.orchard().to_bytes(), usk.orchard().to_bytes());
    let (born, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(born).unwrap();
    st.scan_cached_blocks_with_one_time_ivks(born, 1);
    let publication = publication_at(&st, born);
    let path = witness_at(&st, candidate.position);
    let db = st.wallet_mut().db_mut();
    assert!(run_pass(db, other, publication, &[paid(key8())]));
    assert!(look_up(
        db,
        other,
        key8(),
        publication,
        std::slice::from_ref(&candidate)
    ));
    assert_eq!(status(db, other).witnesses.len(), 1);
    let anchor = ChainPoint {
        height: born,
        hash: BlockHash(publication.hash),
    };
    db.record_one_time_witness(
        other,
        key8(),
        candidate.position,
        anchor,
        siblings(&path),
        clock_now(),
    )
    .unwrap();
    assert!(status(db, other).complete);
    let paid_before: bool = value(
        &db.conn,
        "SELECT k.paid_before_birthday FROM ironwood_one_time_keys k
         JOIN accounts a ON a.id = k.account_id WHERE a.uuid = ?1",
        [other.expose_uuid()],
    );
    assert!(paid_before);
}

/// A rewind below a note a lookup found reopens its key, which closed without scanning,
/// from the note's block, so the rescan finds the note again.
#[test]
fn a_rewind_below_a_looked_up_note_scans_its_key_again() {
    let (mut st, candidate, _) = late_fixture();
    send_witness(&mut st, key8(), &candidate);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    st.truncate_to_height_retaining_cache(candidate.height - 1);
    let tip = st.latest_cached_block().unwrap().height();
    let blocks = (tip - candidate.height) as usize + 1;
    st.scan_cached_blocks_with_one_time_ivks(candidate.height, blocks);
    let mined: Vec<Option<u32>> = column(
        st.wallet().conn(),
        "SELECT t.mined_height FROM ironwood_received_notes n
         JOIN transactions t ON t.id_tx = n.transaction_id
         WHERE n.one_time_key_id IS NOT NULL",
        [],
    );
    assert_eq!(mined, [Some(u32::from(candidate.height))]);
}

/// A pass that lists a key as recent watches it from the publication's end, even though
/// issuance registered the key for a lookup from the provider's seen set before the pass.
/// Once the watch ends, a later pass that lists it as recent again, as every key is without
/// a current recent set, does not reopen it.
#[test]
fn a_pass_watches_a_recent_key_once_even_if_issuance_registered_it() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = KeyId::new(Purpose::Receive, 0);
    let receiver = derive(&st, key)
        .address_at(0u32, Scope::External)
        .to_raw_address_bytes();
    let contains = |receivers: &[[u8; 43]]| receivers.iter().map(|r| *r == receiver).collect();
    let seen = ProviderSeen {
        since: 0,
        until: clock_now(),
        contains: &contains,
    };
    let from = tip(&st).height + 1;
    let db = st.wallet_mut().db_mut();
    let issued = prepare_from(db, account, clock_now(), from, Some(&seen)).unwrap();
    assert!(issued.is_ok_and(|k| k.key_id() != key));
    let watch = |st: &State| -> (Option<u32>, bool) {
        row(
            st.wallet().conn(),
            "SELECT active_from, closed_at IS NOT NULL FROM ironwood_one_time_keys
             WHERE purpose = 1 AND key_index = ?1",
            [key.index().to_be_bytes()],
        )
    };
    assert_eq!(watch(&st), (None, false));
    let recent = FilterCheck {
        key,
        seen: true,
        paid: false,
        recent: true,
    };
    let pass = discover(&mut st, account, &[recent]);
    let start = u32::from(pass.height) + 1;
    assert_eq!(watch(&st), (Some(start), false));
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_keys SET closed_at = 1 WHERE purpose = 1 AND key_index = ?1",
        [key.index().to_be_bytes()],
    );
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    discover(&mut st, account, &[recent]);
    assert_eq!(watch(&st), (Some(start), true));
}

/// Pays `key` in a new scanned block, before the wallet scans with it, and returns the
/// output as a directory candidate.
fn pay_candidate(st: &mut State, key: KeyId) -> PendingPayment {
    let fvk = derive(st, key);
    let height = pay(st, &fvk, 100_000);
    candidate_at(st, height, &fvk)
}
