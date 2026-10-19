use super::*;
use zakura_one_time_ivk::Purpose;
use zcash_client_backend::data_api::one_time_ivk::coverage::{
    CoverageOutcome, CoverageStep, CoverageTarget, DirectoryHistory, LookupTicket,
    OneTimeIvkCoverageRead as _, OneTimeIvkCoverageWrite as _, RecoveryStatus, Snapshot,
};
use zcash_client_backend::data_api::one_time_ivk::restore::LookupWork;

/// Receive key 8, which the fixtures pay before registering it.
pub(in crate::wallet::one_time_ivk) fn key8() -> KeyId {
    KeyId::new(Purpose::Receive, 8)
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

/// Covers `account`'s whole receiver set through the block `publication` ends at with a
/// cumulative snapshot that holds only `hits`, as recovery does: it bootstraps the
/// frontier there, or moves an established one up to it. Returns whether the store
/// recorded it; a step it refuses leaves nothing pinned.
pub(in crate::wallet::one_time_ivk) fn cover_at(
    db: &mut Db,
    account: AccountUuid,
    publication: PublicationEnd,
    hits: &[KeyId],
) -> bool {
    let now = clock_now();
    let history = DirectoryHistory {
        catalog: [1; 32],
        epoch: 1,
    };
    assert!(db.prepare_one_time_coverage(account, 1_000, now).unwrap());
    db.reset_one_time_history(account, history).unwrap();
    let generation = db.one_time_receiver_set(account).unwrap().generation;
    let target = CoverageTarget::Frontier { generation };
    let snapshot = Snapshot {
        cutoff: ChainPoint {
            height: publication.height,
            hash: BlockHash(publication.hash),
        },
        digest: [3; 32],
    };
    if db.pin_one_time_snapshot(account, target, snapshot).unwrap() != Some(snapshot) {
        return false;
    }
    let step = CoverageStep {
        start: None,
        end: snapshot.cutoff,
        digest: snapshot.digest,
        history,
    };
    let recorded = db.record_one_time_coverage(account, target, step, hits, now);
    if recorded.unwrap() == CoverageOutcome::Recorded {
        return true;
    }
    db.unpin_one_time_snapshot(account, target, snapshot)
        .unwrap();
    false
}

/// `account`'s recovery status.
pub(in crate::wallet::one_time_ivk) fn status(db: &Db, account: AccountUuid) -> RecoveryStatus {
    db.one_time_recovery_status(account).unwrap().unwrap()
}

/// `account`'s lookups due now, handed out as tickets.
pub(in crate::wallet::one_time_ivk) fn due(db: &mut Db, account: AccountUuid) -> Vec<LookupTicket> {
    db.dispatch_one_time_lookups(account, clock_now()).unwrap()
}

/// Records `records`, a page of `key`'s history read from `revision` from `page`, against
/// a fresh ticket for its lookup, or returns false if none is due.
#[allow(clippy::too_many_arguments)]
pub(in crate::wallet::one_time_ivk) fn record_page(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    revision: PublicationEnd,
    page: u32,
    records: &[DirectoryPayment],
    complete: bool,
) -> bool {
    let Some(ticket) = due(db, account)
        .into_iter()
        .find(|t| t.work.work.key == key)
    else {
        return false;
    };
    db.record_one_time_lookup_page(
        account,
        &ticket,
        revision,
        page,
        records,
        complete,
        clock_now(),
    )
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
    record_page(db, account, key, revision, 0, &records, true)
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
/// the payment, then covers it with a snapshot that holds the key, and records its lookup:
/// the payment is a late candidate. Returns the payment and the publication, which ends at the
/// scanned tip.
pub(in crate::wallet::one_time_ivk) fn late_fixture() -> (State, PendingPayment, PublicationEnd) {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    st.generate_and_scan_empty_blocks_with_one_time_ivks(2);
    let publication = cover(&mut st, account, &[key8()]);
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
/// admitted unspent, once, and recovery completes.
#[test]
fn a_late_payment_is_admitted_once_its_path_arrives() {
    let (mut st, candidate, publication) = late_fixture();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let found = status(db, account);
    // The waiting payment keeps recovery incomplete, so the app keeps running it.
    assert!(!found.complete);
    assert_eq!(found.lookups, 0);
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

/// A late payment whose note was spent before recovery found it is admitted spent: the
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
    let publication = cover(&mut st, account, &[key8()]);
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

/// A funding memo on the change of a transaction that spent a late payment has no own-send
/// evidence until the payment is admitted, so its key starts sparse. Admitting the payment
/// spent supplies the evidence, and the key is promoted with no later block.
#[test]
fn admitting_a_spent_late_payment_promotes_its_funding_memo() {
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
    let memo = zcash_protocol::memo::MemoBytes::from_bytes(
        &zakura_one_time_ivk::swap::RefundMemo::new(3).encode(),
    )
    .unwrap();
    let sql = "UPDATE ironwood_received_notes SET memo = ?1 WHERE recipient_key_scope = 1";
    exec(st.wallet().conn(), sql, [memo.as_slice()]);
    let publication = cover(&mut st, account, &[key8()]);
    let refund = KeyId::new(Purpose::Refund, 3);
    let facts = |st: &State| -> (bool, bool) {
        let sql = "SELECT authenticated, advances_allocation FROM ironwood_one_time_keys
                   WHERE purpose = 0 AND key_index = ?1";
        row(st.wallet().conn(), sql, [refund.index().to_be_bytes()])
    };
    assert_eq!(facts(&st), (false, false));

    let db = st.wallet_mut().db_mut();
    assert!(look_up(
        db,
        account,
        key8(),
        publication,
        std::slice::from_ref(&candidate)
    ));
    send_witness(&mut st, key8(), &candidate);
    assert_eq!(one_time_notes(&st), [(100_000, true)]);
    assert_eq!(facts(&st), (true, true));
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
        let publication = cover(&mut st, account, &[key8()]);
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

/// A snapshot ending at a block the wallet has not stored waits, and one ending at or
/// below the frontier no longer continues it.
#[test]
fn snapshots_ahead_of_the_scan_or_behind_the_frontier_are_refused() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let current = publication_at(&st, tip(&st).height);
    let mut future = current;
    future.height = current.height + 10;
    let db = st.wallet_mut().db_mut();
    assert!(!cover_at(db, account, future, &[]));
    assert!(cover_at(db, account, current, &[]));
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    cover(&mut st, account, &[]);
    let db = st.wallet_mut().db_mut();
    assert!(!cover_at(db, account, current, &[]));
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

/// Whether the wallet's one queued candidate is a scan hint rather than a late candidate.
fn scan_hint(st: &State) -> bool {
    value(
        st.wallet().conn(),
        "SELECT scan_hint FROM ironwood_one_time_payment_recovery",
        [],
    )
}

/// Covers a [`restored_wallet`], mines without scanning a block paying [`key8`] above its
/// scanned tip, and looks the key up through a publication ending there, as "Check swap
/// history" does, recording the payment: a scan hint. Returns the payment.
fn hint_fixture() -> (State, PendingPayment) {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    cover(&mut st, account, &[]);
    let fvk = derive(&st, key8());
    let amount = Zatoshis::const_from_u64(100_000);
    let paid_to = IronwoodFvk(fvk.clone());
    let (height, _, _) = st.generate_next_block(&paid_to, AddressType::DefaultExternal, amount);
    let candidate = candidate_at(&st, height, &fvk);
    st.wallet_mut().update_chain_tip(height).unwrap();
    let publication = publication_at(&st, height);
    let db = st.wallet_mut().db_mut();
    db.restart_one_time_lookups(account, &[key8()], height, clock_now())
        .unwrap();
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
    assert!(due(db, account).is_empty());
}

/// A lookup read from a revision whose last block differs from the wallet's is refused at
/// once and stays due, so a revision that matches completes it.
#[test]
fn a_revision_off_the_wallets_chain_is_refused() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let publication = cover(&mut st, account, &[key8()]);
    let wrong = PublicationEnd {
        hash: [9; 32],
        ..publication
    };
    let db = st.wallet_mut().db_mut();
    assert!(!look_up(db, account, key8(), wrong, &[]));
    let found = status(db, account);
    assert!(!found.complete);
    assert_eq!(found.lookups, 1);
    assert!(look_up(db, account, key8(), publication, &[]));
    assert!(status(db, account).complete);
}

/// A revision rejected for its tree size can be corrected at the same block, and a claim
/// that contradicts an accepted one is refused.
#[test]
fn a_rejected_tree_size_can_be_corrected() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let publication = cover(&mut st, account, &[key8()]);
    let wrong = PublicationEnd {
        tree_size: publication.tree_size + 1,
        ..publication
    };
    let db = st.wallet_mut().db_mut();
    assert!(!look_up(db, account, key8(), wrong, &[]));
    assert_eq!(status(db, account).lookups, 1);
    assert!(look_up(db, account, key8(), publication, &[]));
    assert!(status(db, account).complete);
    db.restart_one_time_lookups(account, &[], publication.height, clock_now())
        .unwrap();
    assert!(!look_up(db, account, key8(), wrong, &[]));
}

/// An unknown account is an error, not an account with nothing to recover.
#[test]
fn an_unknown_accounts_recovery_is_an_error() {
    let st = restored_wallet();
    let unknown = AccountUuid::from_uuid(uuid::Uuid::nil());
    assert!(matches!(
        st.wallet().db().one_time_recovery_status(unknown),
        Err(SqliteClientError::AccountUnknown)
    ));
}

/// A page refused for a bad record keeps nothing it queued before that record, so the
/// corrected page is taken.
#[test]
fn a_refused_page_queues_nothing() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let publication = cover(&mut st, account, &[key8()]);
    let db = st.wallet_mut().db_mut();
    let beyond = DirectoryPayment {
        height: u32::from(publication.height) + 1,
        ..directory_answer(&candidate)
    };
    let page = [directory_answer(&candidate), beyond];
    assert!(!record_page(
        db,
        account,
        key8(),
        publication,
        0,
        &page,
        true
    ));
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
    let publication = cover(&mut st, account, &[key8()]);
    let db = st.wallet_mut().db_mut();
    let page = |p: &PendingPayment| [directory_answer(p)];
    let record = |db: &mut Db, from: u32, p: &PendingPayment, done: bool| {
        record_page(db, account, key8(), publication, from, &page(p), done)
    };
    assert!(record(db, 0, &first, false));
    let LookupWork { applied, last, .. } = due(db, account)[0].work.clone();
    assert_eq!(applied, 1);
    assert_eq!(
        last.map(|(position, _)| position),
        Some(u64::from(first.position))
    );
    assert!(!record(db, 2, &second, true));
    assert!(record(db, 1, &second, true));
    let found = status(db, account);
    assert_eq!(found.lookups, 0);
    assert_eq!(found.witnesses.len(), 2);
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

/// A lookup still due when a newer step hits its key again reads on to the newer step's
/// end, keeping its cursor, so it finds a payment between the two. It refuses a revision
/// ending below that cutoff, which cannot show the history through it.
#[test]
fn a_newer_hit_raises_a_due_lookups_cutoff() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let first = cover(&mut st, account, &[key8()]);
    let candidate = pay_candidate(&mut st, key8());
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let second = cover(&mut st, account, &[key8()]);
    let db = st.wallet_mut().db_mut();
    let tickets = due(db, account);
    assert_eq!(tickets.len(), 1);
    assert_eq!(tickets[0].work.cutoff, second.height);
    assert!(!look_up(db, account, key8(), first, &[]));
    assert!(look_up(db, account, key8(), second, &[candidate]));
    assert_eq!(status(db, account).witnesses.len(), 1);
}

/// A key registered for a lookup after the frontier passed it, as a refund key recovered
/// from a funding memo is, is looked up through every block the scan stored without it.
#[test]
fn a_key_registered_for_a_lookup_is_looked_up_through_the_scanned_blocks() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let covered = cover(&mut st, account, &[]);
    let candidate = pay_candidate(&mut st, key8());
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let scanned = publication_at(&st, tip(&st).height);
    let db = st.wallet_mut().db_mut();
    recover(db, account, key8(), candidate.height);
    let tickets = due(db, account);
    assert_eq!(tickets.len(), 1);
    assert_eq!(tickets[0].work.cutoff, scanned.height);
    assert!(!look_up(db, account, key8(), covered, &[]));
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

/// A lookup read from a revision the scan has not judged yet keeps recovery incomplete,
/// even with nothing found, until the scan finds that revision on the wallet's chain.
#[test]
fn a_lookup_from_an_unjudged_revision_keeps_recovery_incomplete() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    cover(&mut st, account, &[key8()]);
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
    cover(&mut st, account, &[key8()]);
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
    let tickets = due(db, account);
    assert_eq!(tickets.len(), 1);
    assert_eq!((tickets[0].work.applied, tickets[0].work.last), (0, None));
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
    let publication = cover(&mut st, account, &[key8()]);
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
/// dequeues it, and recovery completes.
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

/// Issuance waits until the account's windows were checked against a seen set, so it
/// never issues an index another device gave out.
#[test]
fn issuance_waits_for_a_seen_check() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let tip = tip(&st).height;
    let db = st.wallet_mut().db_mut();
    assert!(matches!(
        reserve_refund(db, account, tip),
        Ok(Err(ReservationPolicy::Gap))
    ));
    check_seen(db, account);
    let key = reserve_refund(db, account, tip).unwrap();
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
    assert!(cover_at(db, other, publication, &[key8()]));
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

/// A rewind below a note a lookup found makes the lookup due again, so the note is found
/// again on the replacing chain without reopening its key.
#[test]
fn a_rewind_below_a_looked_up_note_looks_it_up_again() {
    let (mut st, candidate, _) = late_fixture();
    let account = st.test_account().unwrap().id();
    send_witness(&mut st, key8(), &candidate);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    let tip = st.latest_cached_block().unwrap().height();
    st.truncate_to_height_retaining_cache(candidate.height - 1);
    let blocks = (tip - candidate.height) as usize + 1;
    st.scan_cached_blocks_with_one_time_ivks(candidate.height, blocks);
    let publication = publication_at(&st, tip);
    let db = st.wallet_mut().db_mut();
    assert!(look_up(
        db,
        account,
        key8(),
        publication,
        std::slice::from_ref(&candidate)
    ));
    send_witness(&mut st, key8(), &candidate);
    let mined: Vec<Option<u32>> = column(
        st.wallet().conn(),
        "SELECT t.mined_height FROM ironwood_received_notes n
         JOIN transactions t ON t.id_tx = n.transaction_id
         WHERE n.one_time_key_id IS NOT NULL",
        [],
    );
    assert_eq!(mined, [Some(u32::from(candidate.height))]);
}

/// Pays `key` in a new scanned block, before the wallet scans with it, and returns the
/// output as a directory candidate.
fn pay_candidate(st: &mut State, key: KeyId) -> PendingPayment {
    let fvk = derive(st, key);
    let height = pay(st, &fvk, 100_000);
    candidate_at(st, height, &fvk)
}
