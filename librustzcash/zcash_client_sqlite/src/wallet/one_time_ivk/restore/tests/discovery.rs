//! Queue behavior using an independent compact-block oracle and Merkle witness builder.
use super::*;
use zcash_client_backend::data_api::one_time_ivk::restore::{
    LookupCursor, RecoveryStatus, SegmentRef, WitnessAnswer, WitnessRequest,
};

/// A fixture publication's whole history for one receiver: one shard of one segment,
/// read through its final page in this step.
pub(in crate::wallet::one_time_ivk) fn whole(
    publication: RecoveryPublication,
    records: Vec<DirectoryRecord>,
) -> LookupPage {
    LookupPage {
        publication,
        segment: Some(segment_ref(publication)),
        records,
        checked_through: Some(publication.end.height),
        next: None,
    }
}

/// The fixture publication's only segment: its payment session is the publication's
/// identity and its witness session is fixed.
pub(in crate::wallet::one_time_ivk) fn segment_ref(publication: RecoveryPublication) -> SegmentRef {
    SegmentRef {
        shard: 0,
        segment: 0,
        payments: publication.id,
        witnesses: [7; 32],
    }
}

/// A receive identity beyond the initial window, used by explicit-history fixtures.
pub(in crate::wallet::one_time_ivk) fn key8() -> KeyId {
    KeyId::new(Purpose::Receive, 8)
}

/// A full-history publication ending at a real cached block.
pub(in crate::wallet::one_time_ivk) fn publication_at(
    st: &State,
    height: BlockHeight,
) -> RecoveryPublication {
    let data: Vec<u8> = value(
        &st.cache().0,
        "SELECT data FROM compactblocks WHERE height = ?1",
        [u32::from(height)],
    );
    let block = CompactBlock::decode(data.as_slice()).unwrap();
    RecoveryPublication {
        id: [1; 32],
        history_revision: 0,
        start_height: st.sapling_activation_height(),
        end: PublicationEnd {
            height,
            hash: block.hash().0,
            tree_size: block
                .chain_metadata
                .unwrap()
                .ironwood_commitment_tree_size
                .into(),
        },
    }
}

/// Reads due work from the database after each committed step, checking it cannot stall
/// (see [`assert_no_stall`]).
pub(in crate::wallet::one_time_ivk) fn status(db: &Db, account: AccountUuid) -> RecoveryStatus {
    assert_no_stall(db, account);
    db.one_time_recovery(account, clock_now()).unwrap()
}

/// The path of the chain's Ironwood leaf at `position` at the cached tip.
pub(in crate::wallet::one_time_ivk) fn witness_at(st: &State, position: u32) -> MerklePath {
    path_after(st, &[], position)
}

/// The path of the leaf at `position` in a tree of `prefix`, the leaves before the first
/// cached block, followed by every cached block's Ironwood actions.
fn path_after(st: &State, prefix: &[MerkleHashOrchard], position: u32) -> MerklePath {
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
        .flat_map(|tx| tx.ironwood_actions)
        .map(|action| MerkleHashOrchard::from_cmx(&action.cmx().unwrap()));
    for (leaf, cmx) in prefix.iter().copied().chain(actions).enumerate() {
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

/// `path`'s sibling hashes.
fn siblings(path: &MerklePath) -> [[u8; 32]; 32] {
    std::array::from_fn(|level| path.auth_path()[level].to_bytes())
}

/// The companion witness `request` names, as a publication ending at `end` serves it: the
/// independent path's lower siblings that are complete at that block's tree size, every
/// other slot zero.
pub(in crate::wallet::one_time_ivk) fn witness_answer(
    st: &State,
    request: &WitnessRequest,
    end: BlockHeight,
) -> WitnessAnswer {
    answer(
        request,
        &witness_at(st, request.position),
        publication_at(st, end).end,
    )
}

/// `path`'s lower siblings complete at `context`, answering `request`.
fn answer(request: &WitnessRequest, path: &MerklePath, context: PublicationEnd) -> WitnessAnswer {
    let mut payload = [0; 512];
    for level in 0..16 {
        let start = ((u64::from(request.position) >> level) ^ 1) << level;
        if start + (1 << level) <= context.tree_size {
            payload[level * 32..(level + 1) * 32]
                .copy_from_slice(&path.auth_path()[level].to_bytes());
        }
    }
    WitnessAnswer {
        payments: request.payments,
        revision: request.witnesses,
        context,
        payload,
    }
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

/// Builds complete payment history independently from the wallet's stored candidates.
fn oracle(st: &State, receiver: [u8; 43], fvk: &FullViewingKey) -> Vec<DirectoryRecord> {
    let blocks: Vec<Vec<u8>> = column(
        &st.cache().0,
        "SELECT data FROM compactblocks ORDER BY height",
        [],
    );
    let ivk = fvk.to_ivk(Scope::External).prepare();
    let mut records = vec![];
    for bytes in blocks {
        let block = CompactBlock::decode(bytes.as_slice()).unwrap();
        let mut position = block
            .chain_metadata
            .as_ref()
            .unwrap()
            .ironwood_commitment_tree_size
            - block
                .vtx
                .iter()
                .map(|tx| tx.ironwood_actions.len() as u32)
                .sum::<u32>();
        for tx in &block.vtx {
            for (index, compact) in tx.ironwood_actions.iter().enumerate() {
                let action = CompactAction::try_from(compact).unwrap();
                let domain = IronwoodDomain::for_compact_action(&action);
                if let Some((note, _)) = try_compact_note_decryption(&domain, &ivk, &action) {
                    let payment = PendingPayment {
                        txid: tx.txid(),
                        action_index: index as u32,
                        height: BlockHeight::from(block.height as u32),
                        block_hash: block.hash(),
                        tx_index: tx.index as u16,
                        position,
                        encrypted_note: encrypt_note(note),
                    };
                    records.push(DirectoryRecord {
                        receiver,
                        page: records.len() as u32,
                        total: 0,
                        payment: directory_answer(&payment),
                        ordinal: records.len() as u32,
                    });
                }
                position += 1;
            }
        }
    }
    let total = records.len() as u32;
    for record in &mut records {
        record.total = total;
    }
    records
}

/// The no-stall invariant, checked after every recovery step and mutation. Recovery must be
/// complete, expose a lookup or witness, or wait only on time (a backoff, made due here by
/// a far-future clock), a publication or ordinary sync, or the user (feature or manual
/// search paused, which leaves a cancelled search's lookups without a reason). Anything
/// else waits on a mutation nothing will make.
///
/// Shard-local state must also stay consistent: no settled request keeps a target nothing
/// would clear, a completed read keeps no segment cursor, and a candidate whose witness
/// binding was dropped has an unread lookup to rebind it after rewound coverage, unless the
/// user paused that lookup.
pub(in crate::wallet::one_time_ivk) fn assert_no_stall(db: &Db, account: AccountUuid) {
    let owner: i64 = value(
        &db.conn,
        "SELECT id FROM accounts WHERE uuid = ?1",
        [account.0],
    );
    let (settled, cursor, unbound): (bool, bool, bool) = row(
        &db.conn,
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
         JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
         WHERE k.account_id = ?1 AND l.reasons != 0 AND l.target_height IS NOT NULL
           AND l.read_complete = 1 AND l.done_height >= l.target_height
           AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
               WHERE p.one_time_key_id = k.id)),
         EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
         JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
         WHERE k.account_id = ?1 AND l.read_complete = 1 AND l.inventory IS NOT NULL),
         EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
         JOIN ironwood_one_time_keys k ON k.id = p.one_time_key_id
         JOIN ironwood_one_time_lookups l ON l.one_time_key_id = k.id
         WHERE k.account_id = ?1 AND p.payments IS NULL
           AND l.reasons != 0 AND (l.read_complete = 1 OR l.target_height IS NULL))",
        [owner],
    );
    assert!(!settled, "a settled request keeps a target nothing clears");
    assert!(!cursor, "a completed read keeps a segment cursor");
    assert!(!unbound, "an unbound candidate has no read to rebind it");
    let state = db.one_time_recovery(account, i64::MAX).unwrap();
    if !state.enabled || !state.lookups.is_empty() || !state.witnesses.is_empty() {
        return;
    }
    // Restore before any publication, or a proven payment waiting for ordinary sync.
    let (unstarted, syncing): (bool, bool) = row(
        &db.conn,
        "SELECT r.restore_height IS NULL, EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
             JOIN ironwood_one_time_keys k ON k.id = p.one_time_key_id
             WHERE k.account_id = r.account_id AND p.witness IS NOT NULL)
         FROM ironwood_one_time_recovery r JOIN accounts a ON a.id = r.account_id
         WHERE a.uuid = ?1",
        [account.0],
    );
    let hidden: bool = value(
        &db.conn,
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
             JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
             JOIN accounts a ON a.id = k.account_id
             WHERE a.uuid = ?1 AND l.target_height IS NOT NULL AND l.read_complete = 0 AND l.reasons != 0)",
        [account.0],
    );
    let manual = state.manual.is_some_and(|m| m.active);
    let complete = state.restore_complete && !manual && !hidden;
    assert!(
        complete || syncing || (unstarted && !manual && !hidden),
        "recovery stalled with no runnable work: restore_next {}, restore_gap {}, \
         restore_complete {}, manual {:?}, hidden lookups {hidden}",
        state.restore_next,
        state.restore_gap,
        state.restore_complete,
        state.manual,
    );
}

/// Supplies pages and independent proofs until the bounded fixture has no outstanding work.
pub(in crate::wallet::one_time_ivk) fn drain(
    st: &mut State,
    account: AccountUuid,
    publication: RecoveryPublication,
) {
    for _ in 0..256 {
        if answer_lookup(st, account, publication) {
            continue;
        }
        let state = status(st.wallet().db(), account);
        if let Some(request) = state.witnesses.first() {
            let answer = witness_answer(st, request, tip(st).height);
            assert!(
                st.wallet_mut()
                    .db_mut()
                    .record_one_time_witness(account, state.token, *request, &answer, clock_now())
                    .unwrap()
            );
            continue;
        }
        return;
    }
    panic!("fixture recovery did not converge");
}

/// Answers the first due lookup from the independent oracle, if any is due.
fn answer_lookup(st: &mut State, account: AccountUuid, publication: RecoveryPublication) -> bool {
    let state = status(st.wallet().db(), account);
    let Some(work) = state.lookups.first() else {
        return false;
    };
    let fvk = get_key(st.wallet().db(), account, work.work.key)
        .unwrap()
        .unwrap();
    let records = oracle(st, work.work.receiver, fvk.full_viewing_key());
    let start = work
        .cursor
        .as_ref()
        .filter(|c| c.inventory == publication.id)
        .and_then(|c| c.last.as_ref())
        .map_or(0, |r| r.page as usize + 1);
    let end = (start + 32).min(records.len());
    let page = LookupPage {
        publication,
        segment: Some(segment_ref(publication)),
        records: records[start..end].to_vec(),
        checked_through: (end == records.len()).then_some(publication.end.height),
        next: (end < records.len()).then(|| LookupCursor {
            inventory: publication.id,
            shard: 0,
            segment: 0,
            last: records[..end].last().cloned(),
        }),
    };
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, work, &page, clock_now())
            .unwrap()
    );
    true
}

/// Pays an unknown key while ordinary sync deliberately does not discover it.
pub(in crate::wallet::one_time_ivk) fn pay_candidate(st: &mut State, key: KeyId) -> PendingPayment {
    let fvk = derive(st, key);
    let (height, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk.clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );
    payment_indexes(st, height, 1);
    st.scan_cached_blocks(height, 1);
    candidate_at(st, height, &fvk)
}

/// Reads `candidate`'s history at a publication ending at the tip, so it waits for its
/// witness.
pub(in crate::wallet::one_time_ivk) fn queue_late(
    st: &mut State,
    key: KeyId,
    candidate: &PendingPayment,
) -> RecoveryPublication {
    let account = st.test_account().unwrap().id();
    recover(st.wallet_mut().db_mut(), account, key, candidate.height);
    let publication = publication_at(st, tip(st).height);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    let work = work_of(st, key);
    let db = st.wallet_mut().db_mut();
    let page = whole(
        publication,
        vec![DirectoryRecord {
            receiver: work.work.receiver,
            page: 0,
            total: 1,
            payment: directory_answer(candidate),
            ordinal: 0,
        }],
    );
    assert!(
        db.record_one_time_lookup(account, &work, &page, clock_now())
            .unwrap()
    );
    publication
}

/// `key`'s pending lookup as status hands it out, without a saved cursor.
pub(in crate::wallet::one_time_ivk) fn work_of(st: &State, key: KeyId) -> LookupWork {
    let account = st.test_account().unwrap().id();
    let db = st.wallet().db();
    let id = key_ref(&db.conn, account, key).unwrap();
    let (through, start, checked, inventory): (u32, u32, Option<u32>, Option<Vec<u8>>) = row(
        &db.conn,
        "SELECT target_height, start_height, checked_height, inventory
         FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
        [id],
    );
    assert!(inventory.is_none(), "no saved cursor");
    let stored = get_key(db, account, key).unwrap().unwrap();
    LookupWork {
        token: status(db, account).token,
        work: zcash_client_backend::data_api::one_time_ivk::restore::DiscoveryWork {
            key,
            receiver: stored.receiver().to_raw_address_bytes(),
        },
        from: BlockHeight::from(checked.map_or(start, |c| start.max(c + 1))),
        through: BlockHeight::from(through),
        cursor: None,
    }
}

/// A matched address has authenticated its candidate but is still waiting for inclusion.
pub(in crate::wallet::one_time_ivk) fn late_fixture() -> (State, PendingPayment, RecoveryPublication)
{
    let mut st = scanned_wallet();
    let candidate = pay_candidate(&mut st, key8());
    let publication = queue_late(&mut st, key8(), &candidate);
    (st, candidate, publication)
}

/// The pending witness request for `candidate`.
pub(in crate::wallet::one_time_ivk) fn request_for(
    st: &State,
    key: KeyId,
    candidate: &PendingPayment,
) -> WitnessRequest {
    let account = st.test_account().unwrap().id();
    *status(st.wallet().db(), account)
        .witnesses
        .iter()
        .find(|r| r.key == key && r.position == candidate.position)
        .expect("a pending witness request")
}

/// Delivers a candidate's witness, built at the current tip, under the current
/// cancellation fence. A candidate already admitted reuses its last binding.
pub(in crate::wallet::one_time_ivk) fn send_witness(
    st: &mut State,
    key: KeyId,
    candidate: &PendingPayment,
) {
    let account = st.test_account().unwrap().id();
    let state = status(st.wallet().db(), account);
    let request = state
        .witnesses
        .iter()
        .find(|r| r.key == key && r.position == candidate.position)
        .copied()
        .unwrap_or(WitnessRequest {
            key,
            position: candidate.position,
            cmx: candidate.encrypted_note.to_bytes()[32..64]
                .try_into()
                .unwrap(),
            payments: [1; 32],
            witnesses: [7; 32],
            ordinal: 0,
        });
    let answer = witness_answer(st, &request, tip(st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_witness(account, state.token, request, &answer, clock_now())
            .unwrap()
    );
    assert_no_stall(st.wallet().db(), account);
}

/// Ordinary scanning never credits a private receiver. Inclusion proof admission does, once.
#[test]
fn a_late_payment_is_admitted_once_its_path_arrives() {
    let (mut st, candidate, publication) = late_fixture();
    assert!(one_time_notes(&st).is_empty());
    send_witness(&mut st, key8(), &candidate);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    send_witness(&mut st, key8(), &candidate);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    let account = st.test_account().unwrap().id();
    drain(&mut st, account, publication);
}

/// Four genuine empty histories stop seed recovery and survive reopening the wallet.
#[test]
fn seed_recovery_stops_at_four_completed_empty_histories() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    reopen(&mut st);
    let state = status(st.wallet().db(), account);
    assert_eq!(
        (
            state.restore_next,
            state.restore_gap,
            state.restore_complete
        ),
        (4, 4, true)
    );
    assert!(state.lookups.is_empty());
}

/// Manual extended ranges continue past four empty receivers and preserve cancellation progress.
#[test]
fn manual_bound_and_cancellation_do_not_use_the_seed_gap() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, Some(10))
            .unwrap()
    );
    let old = status(st.wallet().db(), account);
    st.wallet_mut()
        .db_mut()
        .cancel_one_time_history(account)
        .unwrap();
    let paused = status(st.wallet().db(), account);
    assert!(!paused.manual.unwrap().active);
    assert_ne!(old.token, paused.token);
    reopen(&mut st);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, None)
            .unwrap()
    );
    drain(&mut st, account, publication);
    let done = status(st.wallet().db(), account).manual.unwrap();
    assert_eq!((done.active, done.next, done.receive_end), (false, 10, 10));
}

/// A callback captured before disabling cannot admit a payment or advance negative coverage.
#[test]
fn feature_toggle_rejects_stale_lookup_and_proof_callbacks() {
    let (mut st, candidate, publication) = late_fixture();
    let account = st.test_account().unwrap().id();
    let old = status(st.wallet().db(), account);
    let request = old.witnesses[0];
    let answer = witness_answer(&st, &request, tip(&st).height);
    assert_eq!(request.position, candidate.position);
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(account, false)
        .unwrap();
    let state = status(st.wallet().db(), account);
    assert!(state.lookups.is_empty() && state.witnesses.is_empty());
    assert!(
        !st.wallet_mut()
            .db_mut()
            .record_one_time_witness(account, old.token, request, &answer, clock_now())
            .unwrap()
    );
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(account, true)
        .unwrap();
    assert!(one_time_notes(&st).is_empty());
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// Quiet blocks need no new commitment, so an old same-size checkpoint remains a valid proof root.
#[test]
fn quiet_chain_still_admits_a_late_payment() {
    let (mut st, candidate, _) = late_fixture();
    st.generate_and_scan_empty_blocks(crate::PRUNING_DEPTH as usize + 5);
    send_witness(&mut st, key8(), &candidate);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// Delayed recovery of I0 must queue I4 through filters already consumed without knowing I4.
#[test]
fn delayed_window_expansion_checks_history_after_the_filter_frontier() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let initial = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, initial, true)
            .unwrap()
    );
    let held = status(st.wallet().db(), account).lookups[0].clone();
    let key0 = KeyId::new(Purpose::Receive, 0);
    let payment0 = pay_candidate(&mut st, key0);
    let key4 = KeyId::new(Purpose::Receive, 4);
    pay_candidate(&mut st, key4);
    let publication = publication_at(&st, tip(&st).height);
    let blocks: Vec<Vec<u8>> = column(
        &st.cache().0,
        "SELECT data FROM compactblocks WHERE height > ?1 ORDER BY height",
        [u32::from(initial.end.height)],
    );
    let blocks: Vec<ChainPoint> = blocks
        .into_iter()
        .map(|bytes| {
            let b = CompactBlock::decode(bytes.as_slice()).unwrap();
            ChainPoint {
                height: BlockHeight::from(b.height as u32),
                hash: b.hash(),
            }
        })
        .collect();
    let captured = status(st.wallet().db(), account).token;
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_filters(account, captured, 0, &blocks, &[key0])
            .unwrap()
    );
    let page = whole(
        publication,
        vec![DirectoryRecord {
            receiver: held.work.receiver,
            page: 0,
            total: 1,
            payment: directory_answer(&payment0),
            ordinal: 0,
        }],
    );
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &held, &page, clock_now())
            .unwrap()
    );
    send_witness(&mut st, key0, &payment0);
    reopen(&mut st);
    let db = st.wallet().db();
    let id = key_ref(&db.conn, account, key4).unwrap();
    let target: u32 = value(
        &db.conn,
        "SELECT target_height FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
        [id],
    );
    assert_eq!(target, u32::from(publication.end.height));
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false), (100_000, false)]);
    let next = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, clock_now())
        .unwrap()
        .unwrap();
    assert_eq!(next.key_id().index(), 1);
}

/// An indexing correction invalidates a held empty answer and restarts an unfinished seed gap.
#[test]
fn corrected_history_cannot_be_completed_by_an_old_empty_response() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    let held = status(db, account).lookups[0].clone();
    let old = whole(publication, vec![]);
    assert!(
        db.record_one_time_lookup(account, &held, &old, clock_now())
            .unwrap()
    );
    assert_eq!(status(db, account).restore_next, 1);
    let corrected = RecoveryPublication {
        history_revision: 1,
        id: [2; 32],
        ..publication
    };
    assert!(
        db.begin_one_time_recovery(account, corrected, true)
            .unwrap()
    );
    assert_eq!(status(db, account).restore_next, 0);
    assert!(
        !db.record_one_time_lookup(account, &held, &old, clock_now())
            .unwrap()
    );
    drain(&mut st, account, corrected);
    assert!(status(st.wallet().db(), account).restore_complete);
}

/// A target raised while a request is in flight remains queryable after the older answer arrives.
#[test]
fn a_new_filter_target_survives_a_held_older_complete_answer() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    let held = status(st.wallet().db(), account).lookups[0].clone();
    st.generate_and_scan_empty_blocks(1);
    let block = tip(&st);
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_filters(account, held.token, 0, &[block], &[held.work.key])
            .unwrap()
    );
    let page = whole(publication, vec![]);
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &held, &page, clock_now())
            .unwrap()
    );
    let work = status(st.wallet().db(), account).lookups;
    assert!(
        work.iter()
            .any(|w| w.work.key == held.work.key && w.through == block.height)
    );
}

/// Lowering the birthday retains explicit recheck intent across disable and restart.
#[test]
fn birthday_recheck_survives_feature_off_and_restart() {
    let (mut st, candidate, publication) = late_fixture();
    let account = st.test_account().unwrap().id();
    send_witness(&mut st, key8(), &candidate);
    drain(&mut st, account, publication);
    let db = st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(account, false).unwrap();
    tx(db, |conn, _| {
        crate::wallet::one_time_rewind::reopen_discovery(conn, account)
    })
    .unwrap();
    assert!(status(db, account).lookups.is_empty());
    reopen(&mut st);
    let db = st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(account, true).unwrap();
    let id = key_ref(&db.conn, account, key8()).unwrap();
    let pending: bool = value(
        &db.conn,
        "SELECT target_height IS NOT NULL AND last_record IS NULL
        AND done_height IS NULL FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
        [id],
    );
    assert!(pending);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// An explicit extended check must not turn unused indexes into permanent automatic lookahead.
#[test]
fn manual_history_does_not_expand_automatic_catch_up() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, Some(10))
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert!(!status(st.wallet().db(), account).manual.unwrap().active);
    st.generate_and_scan_empty_blocks(1);
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    let queued: Vec<Vec<u8>> = column(st.wallet().conn(),
        "SELECT k.key_index FROM ironwood_one_time_keys k JOIN ironwood_one_time_lookups l
         ON l.one_time_key_id = k.id WHERE l.target_height IS NOT NULL AND l.reasons != 0 ORDER BY k.key_index", []);
    let queued: Vec<_> = queued
        .into_iter()
        .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
        .collect();
    assert_eq!(queued, [0, 1, 2, 3]);
}

/// Direct catch-up covers a later payment even when an older empty answer is still in flight.
#[test]
fn direct_catch_up_raises_pending_targets_before_skipping_filters() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let initial = publication_at(&st, tip(&st).height);
    st.wallet_mut()
        .db_mut()
        .begin_one_time_recovery(account, initial, true)
        .unwrap();
    drain(&mut st, account, initial);
    st.generate_and_scan_empty_blocks(1);
    let older = publication_at(&st, tip(&st).height);
    st.wallet_mut()
        .db_mut()
        .begin_one_time_recovery(account, older, true)
        .unwrap();
    let held = status(st.wallet().db(), account).lookups[0].clone();
    pay_candidate(&mut st, held.work.key);
    let current = publication_at(&st, tip(&st).height);
    st.wallet_mut()
        .db_mut()
        .begin_one_time_recovery(account, current, true)
        .unwrap();
    let page = whole(older, vec![]);
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &held, &page, clock_now())
            .unwrap()
    );
    assert!(
        status(st.wallet().db(), account)
            .lookups
            .iter()
            .any(|w| w.work.key == held.work.key && w.through == current.end.height)
    );
    drain(&mut st, account, current);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A correction or reorg invalidates the already-checked prefix of a paused manual job.
#[test]
fn paused_manual_history_rechecks_its_prefix_after_invalidation() {
    for correction in [false, true] {
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        let publication = publication_at(&st, tip(&st).height);
        let db = st.wallet_mut().db_mut();
        db.check_one_time_history(account, publication, Some(10))
            .unwrap();
        let work = status(db, account).lookups[0].clone();
        let page = whole(publication, vec![]);
        assert!(
            db.record_one_time_lookup(account, &work, &page, clock_now())
                .unwrap()
        );
        assert_eq!(status(db, account).manual.unwrap().next, 1);
        db.cancel_one_time_history(account).unwrap();
        if correction {
            let publication = RecoveryPublication {
                history_revision: 1,
                ..publication
            };
            db.begin_one_time_recovery(account, publication, false)
                .unwrap();
        } else {
            tx(db, |conn, _| {
                crate::wallet::one_time_rewind::truncate(conn, publication.end.height - 1)
            })
            .unwrap();
        }
        let paused = status(db, account).manual.unwrap();
        assert!(!paused.active);
        assert_eq!(paused.next, 0);
        assert!(!paused.refunds_done);
    }
}

/// Once a replacement chain proves the paid slots empty, the initial window can be reused.
#[test]
fn orphaned_receipts_do_not_permanently_exhaust_the_receive_window() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let floor = tip(&st).height;
    for index in 0..4 {
        pay_candidate(&mut st, KeyId::new(Purpose::Receive, index));
    }
    let publication = publication_at(&st, tip(&st).height);
    st.wallet_mut()
        .db_mut()
        .begin_one_time_recovery(account, publication, true)
        .unwrap();
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st).len(), 4);
    st.truncate_to_height(floor);
    st.generate_and_scan_empty_blocks(20);
    // The publication covers the captured repair obligation while trailing the live scan.
    let publication = publication_at(&st, tip(&st).height - 5);
    st.wallet_mut()
        .db_mut()
        .begin_one_time_recovery(account, publication, true)
        .unwrap();
    drain(&mut st, account, publication);
    let next = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, clock_now())
        .unwrap()
        .unwrap();
    assert_eq!(next.key_id().index(), 0);
}

/// Rewound owned funds can be repaired while off, without discovering another payment to the key.
#[test]
fn disabled_discovery_repairs_known_receipts_without_adding_payments() {
    let (mut st, candidate, publication) = late_fixture();
    let account = st.test_account().unwrap().id();
    send_witness(&mut st, key8(), &candidate);
    drain(&mut st, account, publication);
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(account, false)
        .unwrap();
    pay_candidate(&mut st, key8());
    let end = tip(&st).height;
    st.truncate_to_height_retaining_cache(candidate.height - 1);
    reopen(&mut st);
    st.scan_cached_blocks(candidate.height, (end - candidate.height + 1) as usize);
    let publication = publication_at(&st, end);
    let before = status(st.wallet().db(), account);
    assert!(!before.enabled);
    assert_eq!(before.lookups.len(), 1);
    assert_eq!(before.lookups[0].work.key, key8());
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    assert!(
        !st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, Some(20))
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    let mined: Option<u32> = value(
        st.wallet().conn(),
        "SELECT mined_height FROM transactions WHERE txid = ?1",
        [candidate.txid.as_ref()],
    );
    assert_eq!(mined, Some(u32::from(candidate.height)));
    let after = status(st.wallet().db(), account);
    assert!(!after.enabled);
    assert_eq!(after.restore_next, before.restore_next);
    assert_eq!(after.filter_frontier, before.filter_frontier);
    assert!(after.lookups.is_empty() && after.witnesses.is_empty());
}

/// A disabled repair can skip a second receipt, but re-enabling must recover it from page zero.
#[test]
fn disabled_repair_does_not_consume_future_discovery_pages() {
    let (mut st, candidate, publication) = late_fixture();
    let account = st.test_account().unwrap().id();
    send_witness(&mut st, key8(), &candidate);
    drain(&mut st, account, publication);
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(account, false)
        .unwrap();
    pay_candidate(&mut st, key8());
    let end = tip(&st).height;
    st.truncate_to_height_retaining_cache(candidate.height - 1);
    reopen(&mut st);
    st.scan_cached_blocks(candidate.height, (end - candidate.height + 1) as usize);
    let publication = publication_at(&st, end);
    st.wallet_mut()
        .db_mut()
        .begin_one_time_recovery(account, publication, true)
        .unwrap();
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    reopen(&mut st);
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(account, true)
        .unwrap();
    st.wallet_mut()
        .db_mut()
        .check_one_time_history(account, publication, Some(9))
        .unwrap();
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false), (100_000, false)]);
}

/// Birthday changes cannot enroll incoming-only or Sapling-only accounts in receiver recovery.
#[test]
fn birthday_rewind_keeps_ineligible_accounts_out_of_receiver_recovery() {
    use std::collections::HashSet;
    use zcash_client_backend::data_api::{
        Account as _, AccountBirthday, AccountPurpose, AccountSource, chain::ChainState,
    };
    use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
    let mut st = restored_wallet();
    let network = *st.network();
    let anchor = tip(&st);
    let birthday = AccountBirthday::from_parts(
        ChainState::empty(anchor.height + 4, BlockHash([0; 32])),
        None,
    );
    let mut imported = HashSet::new();
    for incoming_only in [false, true] {
        let ufvk = UnifiedSpendingKey::from_seed(
            &network,
            &[if incoming_only { 8 } else { 7 }; 32],
            zip32::AccountId::ZERO,
        )
        .unwrap()
        .to_unified_full_viewing_key();
        let key = if incoming_only {
            crate::wallet::ViewingKey::Incoming(Box::new(ufvk.to_unified_incoming_viewing_key()))
        } else {
            crate::wallet::ViewingKey::Full(Box::new(
                UnifiedFullViewingKey::new(
                    #[cfg(feature = "transparent-inputs")]
                    None,
                    ufvk.sapling().cloned(),
                    None,
                )
                .unwrap(),
            ))
        };
        let account = st
            .wallet_mut()
            .db_mut()
            .transactionally(|db| {
                crate::wallet::add_account(
                    db.conn.0,
                    db.params,
                    "viewing",
                    &AccountSource::Imported {
                        purpose: AccountPurpose::ViewOnly,
                        key_source: None,
                    },
                    key,
                    &birthday,
                    #[cfg(feature = "transparent-inputs")]
                    &crate::GapLimits::default(),
                )
            })
            .unwrap();
        imported.insert(account.id());
    }
    st.wallet_mut()
        .rewind_to_chain_state(ChainState::empty(anchor.height, anchor.hash), imported)
        .unwrap();
    let count: u32 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_recovery",
        [],
    );
    assert_eq!(count, 0);
    st.generate_and_scan_empty_blocks(1);
}

/// Mines `count` blocks each paying one output to a key outside the wallet, then scans them.
fn foreign_blocks(st: &mut State, count: usize) {
    let other = IronwoodFvk(FullViewingKey::from(
        &orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap(),
    ));
    let mut first = None;
    for _ in 0..count {
        let (height, _, _) = st.generate_next_block(
            &other,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(1_000),
        );
        first.get_or_insert(height);
    }
    if let Some(first) = first {
        st.scan_cached_blocks(first, count);
    }
}

/// A provisional witness built at three leaves supplies no partial sibling. Once the
/// wallet has six leaves and has pruned its tree at three, that witness cannot be checked:
/// the payment stays pending, is read again, and the witness built at the new tree size
/// is admitted.
#[test]
fn a_pruned_provisional_witness_is_refreshed_rather_than_completed() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    foreign_blocks(&mut st, 2);
    let three = tip(&st).height;
    queue_late(&mut st, key8(), &candidate);
    let request = request_for(&st, key8(), &candidate);
    let stale = witness_answer(&st, &request, three);
    assert_eq!(stale.context.tree_size, candidate.position as u64 + 3);
    assert!(
        stale.payload[32..64].iter().all(|b| *b == 0),
        "the [2, 4) sibling is partial at three leaves"
    );
    foreign_blocks(&mut st, crate::PRUNING_DEPTH as usize + 3);
    let token = status(st.wallet().db(), account).token;
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_witness(account, token, request, &stale, clock_now())
            .unwrap()
    );
    assert!(one_time_notes(&st).is_empty());
    let pending = status(st.wallet().db(), account);
    assert!(pending.witnesses.is_empty(), "the old binding is dropped");
    let candidates: u32 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_payment_recovery WHERE payments IS NULL",
        [],
    );
    assert_eq!(candidates, 1, "the payment stays pending");
    let id = key_ref(&st.wallet().db().conn, account, key8()).unwrap();
    let (done, read): (bool, bool) = row(
        st.wallet().conn(),
        "SELECT done_height IS NOT NULL, read_complete FROM ironwood_one_time_lookups
         WHERE one_time_key_id = ?1",
        [id],
    );
    assert!(done && !read, "its history must be read again");
    // The next attempt waits out the backoff, then a current publication rebinds it.
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_lookups SET next_attempt_at = 0",
        [],
    );
    let publication = publication_at(&st, tip(&st).height);
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// `count` distinct Ironwood leaves for a chain's prefix.
fn distinct_leaves(count: u64) -> Vec<MerkleHashOrchard> {
    (0..count)
        .map(|i| {
            let mut cmx = [0; 32];
            cmx[..8].copy_from_slice(&(i + 1).to_le_bytes());
            MerkleHashOrchard::from_cmx(
                &orchard::note::ExtractedNoteCommitment::from_bytes(&cmx).unwrap(),
            )
        })
        .collect()
}

/// A wallet whose chain starts with `prefix` known Ironwood leaves before its birthday.
fn wallet_after_leaves(prefix: &[MerkleHashOrchard]) -> State {
    use incrementalmerkletree::frontier::Frontier;
    use zcash_client_backend::data_api::{chain::ChainState, testing::InitialChainState};
    let mut ironwood = Frontier::<MerkleHashOrchard, 32>::empty();
    for leaf in prefix {
        ironwood.append(*leaf);
    }
    let mut st = TestBuilder::new()
        .with_network(ironwood_network())
        .with_data_store_factory(TestDbFactory::file_backed())
        .with_block_cache(crate::testing::BlockCache::new())
        .with_initial_chain_state(|_, _| InitialChainState {
            chain_state: ChainState::new(
                BlockHeight::from_u32(100_010),
                BlockHash([5; 32]),
                Frontier::empty(),
                Frontier::empty(),
                ironwood,
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
    st
}

/// Once a payment's Ironwood shard is full its lower path is final, so the block it was
/// built at is provenance only: past the pruning depth on a quiet chain, a provisional
/// witness from before the shard filled is refreshed, while a final witness from just
/// after it is admitted at a fresh anchor.
#[test]
fn a_final_witness_is_admitted_at_a_fresh_quiet_anchor() {
    let prefix = distinct_leaves(65_534);
    let mut st = wallet_after_leaves(&prefix);
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    assert_eq!(candidate.position, 65_534);
    let filling = tip(&st).height;
    // Leaf 65,535 completes shard zero and 65,536 starts shard one.
    foreign_blocks(&mut st, 2);
    let full = tip(&st).height;
    queue_late(&mut st, key8(), &candidate);
    let request = request_for(&st, key8(), &candidate);
    let path = path_after(&st, &prefix, candidate.position);
    let provisional = answer(&request, &path, publication_at(&st, filling).end);
    let complete = answer(&request, &path, publication_at(&st, full).end);
    assert!(provisional.payload[..32].iter().all(|b| *b == 0));
    assert!(
        complete
            .payload
            .chunks(32)
            .all(|s| s.iter().any(|b| *b != 0))
    );
    st.generate_and_scan_empty_blocks(crate::PRUNING_DEPTH as usize + 5);

    let token = status(st.wallet().db(), account).token;
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_witness(account, token, request, &provisional, clock_now())
            .unwrap()
    );
    assert!(
        one_time_notes(&st).is_empty(),
        "too old to rebuild at 65,535"
    );
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_lookups SET next_attempt_at = 0",
        [],
    );
    let work = &work_of(&st, key8());
    let publication = publication_at(&st, tip(&st).height);
    let page = whole(
        publication,
        vec![DirectoryRecord {
            receiver: work.work.receiver,
            page: 0,
            total: 1,
            payment: directory_answer(&candidate),
            ordinal: 0,
        }],
    );
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, work, &page, clock_now())
            .unwrap()
    );
    let request = request_for(&st, key8(), &candidate);
    let token = status(st.wallet().db(), account).token;
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_witness(account, token, request, &complete, clock_now())
            .unwrap()
    );
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A history scan leaves a late payment's note-free shard stored as its root alone, and
/// the payment's final path is inserted there. If that insertion conflicts with the stored
/// tree, nothing is kept and the payment waits for a newer anchor rather than failing every
/// step. Once the tree agrees, the next scanned block admits it.
#[test]
fn a_witness_insertion_conflict_waits_for_a_newer_anchor() {
    use incrementalmerkletree::{Address, Hashable, Position, Retention};
    use shardtree::{LocatedTree, RetentionFlags, Tree, error::ShardTreeError, store::ShardStore};
    use zcash_client_backend::data_api::WalletCommitmentTrees;
    let prefix = distinct_leaves(65_534);
    let mut st = wallet_after_leaves(&prefix);
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    foreign_blocks(&mut st, 2);
    let full = tip(&st).height;
    queue_late(&mut st, key8(), &candidate);
    let request = request_for(&st, key8(), &candidate);
    let path = path_after(&st, &prefix, candidate.position);
    let complete = answer(&request, &path, publication_at(&st, full).end);
    // Shard zero becomes its root alone, optionally with a wrong leaf where the note goes.
    let shard = Address::from_parts(16.into(), 0);
    let store_shard = |st: &mut State, planted: bool| {
        st.wallet_mut()
            .db_mut()
            .with_ironwood_tree_mut(|tree| {
                let root = tree.root(shard, Position::from(1 << 16))?;
                let leaf = Tree::leaf((root, RetentionFlags::EPHEMERAL));
                tree.store_mut()
                    .put_shard(LocatedTree::from_parts(shard, leaf).unwrap())
                    .map_err(ShardTreeError::Storage)?;
                if planted {
                    tree.batch_insert(
                        Position::from(u64::from(candidate.position)),
                        std::iter::once((MerkleHashOrchard::empty_leaf(), Retention::Ephemeral)),
                    )?;
                }
                Ok::<_, ShardTreeError<_>>(())
            })
            .unwrap();
    };
    store_shard(&mut st, true);
    let token = status(st.wallet().db(), account).token;
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_witness(account, token, request, &complete, clock_now())
            .unwrap()
    );
    assert!(one_time_notes(&st).is_empty());
    let bound: u32 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_payment_recovery WHERE witness IS NOT NULL",
        [],
    );
    assert_eq!(bound, 1, "the final witness waits with the payment");

    store_shard(&mut st, false);
    st.generate_and_scan_empty_blocks(1);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A witness built on a block the wallet's chain does not hold is unusable: the payment
/// stays pending and is read again rather than crediting or completing the address.
#[test]
fn a_witness_from_another_fork_is_refreshed() {
    let (mut st, candidate, _) = late_fixture();
    let account = st.test_account().unwrap().id();
    let request = request_for(&st, key8(), &candidate);
    let mut answer = witness_answer(&st, &request, tip(&st).height);
    answer.context.hash[0] ^= 1;
    let token = status(st.wallet().db(), account).token;
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_witness(account, token, request, &answer, clock_now())
            .unwrap()
    );
    assert!(one_time_notes(&st).is_empty());
    let state = status(st.wallet().db(), account);
    assert!(state.witnesses.is_empty());
    let pending: u32 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_payment_recovery",
        [],
    );
    assert_eq!(pending, 1);
    // A request naming a binding the wallet no longer holds is not accepted.
    assert!(
        !st.wallet_mut()
            .db_mut()
            .refresh_one_time_witness(account, state.token, request)
            .unwrap()
    );
}

/// Progress through whole shards survives a replacement inventory, but a cursor inside a
/// shard is never resumed under another inventory, and a reorg clamps checked progress to
/// the fork and drops the cursor.
#[test]
fn shard_progress_survives_recapture_but_cursors_do_not() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks(6);
    let end = tip(&st).height;
    let first = RecoveryPublication {
        id: [0xa1; 32],
        ..publication_at(&st, end)
    };
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, first, false)
            .unwrap()
    );
    let work = work_of(&st, KeyId::new(Purpose::Receive, 0));
    let sealed_end = end - 3;
    // A sealed shard was excluded by its filter; the step stopped at the recent tier.
    let step = LookupPage {
        publication: first,
        segment: None,
        records: vec![],
        checked_through: Some(sealed_end),
        next: Some(LookupCursor {
            inventory: first.id,
            shard: 1,
            segment: 0,
            last: None,
        }),
    };
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &work, &step, clock_now())
            .unwrap()
    );
    let resumed = status(st.wallet().db(), account)
        .lookups
        .into_iter()
        .find(|w| w.work.key == work.work.key)
        .unwrap();
    assert_eq!(resumed.from, sealed_end + 1);
    assert_eq!(resumed.cursor.as_ref().unwrap().inventory, first.id);
    // A cursor the step did not continue must name the same inventory.
    let foreign = LookupPage {
        next: Some(LookupCursor {
            inventory: [0xb2; 32],
            shard: 1,
            segment: 0,
            last: None,
        }),
        ..step.clone()
    };
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &resumed, &foreign, clock_now())
            .is_err()
    );
    // Under a replacement inventory the step starts at the first unchecked height.
    let second = RecoveryPublication {
        id: [0xb2; 32],
        ..first
    };
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &resumed, &whole(second, vec![]), clock_now())
            .unwrap()
    );
    let id = key_ref(&st.wallet().db().conn, account, work.work.key).unwrap();
    let (done, done_from): (Option<u32>, Option<u32>) = row(
        st.wallet().conn(),
        "SELECT done_height, done_from FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
        [id],
    );
    assert_eq!(done, Some(u32::from(end)));
    assert_eq!(done_from, Some(u32::from(work.from)));
    // A reorg below the completed end keeps coverage only to the fork.
    st.wallet_mut().truncate_to_height(end - 2).unwrap();
    let (done, cursor): (Option<u32>, Option<Vec<u8>>) = row(
        st.wallet().conn(),
        "SELECT done_height, inventory FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
        [id],
    );
    assert_eq!(done, Some(u32::from(end - 2)));
    assert!(cursor.is_none());
}

/// The mined one-time receipts the wallet holds, by receive or refund key index.
fn mined_receipt_indexes(st: &State) -> Vec<u64> {
    let indexes: Vec<Vec<u8>> = column(
        st.wallet().conn(),
        "SELECT k.key_index FROM ironwood_received_notes n
         JOIN ironwood_one_time_keys k ON k.id = n.one_time_key_id
         JOIN transactions t ON t.id_tx = n.transaction_id
         WHERE t.mined_height IS NOT NULL ORDER BY k.key_index",
        [],
    );
    indexes
        .into_iter()
        .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
        .collect()
}

/// I0's payment enrolled I4. A reorg drops that payment after another device issued I4,
/// so direct catch-up must still check I4 and find its payment on the replacement chain.
#[test]
fn a_reorg_that_orphans_the_window_payment_keeps_its_lookahead() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let floor = tip(&st).height;
    pay_candidate(&mut st, KeyId::new(Purpose::Receive, 0));
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert_eq!(mined_receipt_indexes(&st), [0]);
    let key4 = KeyId::new(Purpose::Receive, 4);
    assert!(get_key(st.wallet().db(), account, key4).unwrap().is_some());

    st.truncate_to_height(floor);
    pay_candidate(&mut st, key4);
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert_eq!(mined_receipt_indexes(&st), [4]);
}

/// A manual check completed I4 as empty. Direct catch-up then skipped live filters while
/// I0 and I4 were paid, so recovering I0 must queue I4's history through that frontier.
#[test]
fn window_expansion_rechecks_an_index_a_manual_check_completed() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, Some(5))
            .unwrap()
    );
    drain(&mut st, account, publication);
    let key4 = KeyId::new(Purpose::Receive, 4);
    assert!(get_key(st.wallet().db(), account, key4).unwrap().is_some());

    pay_candidate(&mut st, KeyId::new(Purpose::Receive, 0));
    pay_candidate(&mut st, key4);
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    let frontier = status(st.wallet().db(), account).filter_frontier.unwrap();
    assert_eq!(frontier.height, publication.end.height);
    drain(&mut st, account, publication);
    assert_eq!(mined_receipt_indexes(&st), [0, 4]);
}

/// A late payment whose sibling leaf the wallet already holds unpruned is admitted with
/// that sibling intact. Here the sibling is the funder's change after it, its block's last
/// leaf, which the wallet keeps as a reference once a later scan starts after that block.
/// Inserting the sibling's hash before the marked payment let the pair prune, and
/// inserting the payment under the pruned node then lost the sibling.
#[test]
fn a_late_payment_keeps_a_sibling_the_wallet_already_holds() {
    use zcash_client_backend::data_api::WalletCommitmentTrees as _;
    let foreign = FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes([3; 32]).unwrap());
    let receiver = derive(&ironwood_wallet(), key8()).address_at(0u32, Scope::External);
    // The payment is the first of its bundle's two actions in some attempts.
    for _ in 0..40 {
        let tx = external_payment(receiver, &zcash_protocol::memo::MemoBytes::empty());
        let mut st = ironwood_wallet();
        let account = st.test_account().unwrap().id();
        let (height, _) = st.generate_next_block_from_tx(1, &tx);
        st.scan_cached_blocks(height, 1);
        let candidate = candidate_at(&st, height, &derive(&st, key8()));
        if candidate.position != 0 {
            continue;
        }
        // A later scan starts after the payment's block.
        pay(&mut st, &foreign, 10_000);
        recover(st.wallet_mut().db_mut(), account, key8(), candidate.height);
        let publication = publication_at(&st, tip(&st).height);
        assert!(
            st.wallet_mut()
                .db_mut()
                .begin_one_time_recovery(account, publication, false)
                .unwrap()
        );
        drain(&mut st, account, publication);
        assert_eq!(one_time_notes(&st), [(50_000, false)]);
        assert_eq!(notes(&st, tip(&st).height).len(), 1);
        // The wallet's own witness matches one built independently from every block.
        let position = incrementalmerkletree::Position::from(u64::from(candidate.position));
        let stored = st
            .wallet_mut()
            .db_mut()
            .with_ironwood_tree_mut(|tree| tree.witness_at_checkpoint_depth(position, 0))
            .unwrap()
            .unwrap()
            .unwrap();
        let independent = witness_at(&st, candidate.position);
        assert_eq!(siblings(&stored.into()), siblings(&independent));
        return;
    }
    panic!("the payment was never its bundle's first action");
}

/// Clears every lookup's retry backoff.
fn retry_now(st: &State) {
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_lookups SET next_attempt_at = 0",
        [],
    );
}

/// A payload that decodes but misses the accepted root condemns the witness, not the
/// authenticated payment. The candidate stays pending through a later empty reread, which
/// cannot settle the key, and a correct reread then recovers the payment.
#[test]
fn a_witness_missing_the_root_keeps_the_payment_pending() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    foreign_blocks(&mut st, 2);
    queue_late(&mut st, key8(), &candidate);
    let request = request_for(&st, key8(), &candidate);
    let mut wrong = witness_answer(&st, &request, tip(&st).height);
    assert!(
        wrong.payload[..32].iter().any(|b| *b != 0),
        "leaf sibling supplied"
    );
    wrong.payload[..32].copy_from_slice(&{
        use incrementalmerkletree::Hashable;
        MerkleHashOrchard::empty_leaf().to_bytes()
    });
    let token = status(st.wallet().db(), account).token;
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_witness(account, token, request, &wrong, clock_now())
            .unwrap()
    );
    assert!(one_time_notes(&st).is_empty());
    let pending = || {
        value::<u32>(
            st.wallet().conn(),
            "SELECT COUNT(*) FROM ironwood_one_time_payment_recovery",
            [],
        )
    };
    assert_eq!(pending(), 1, "the payment is kept");
    // An empty replacement answer cannot settle the key while the payment is pending.
    retry_now(&st);
    let work = work_of(&st, key8());
    let publication = publication_at(&st, tip(&st).height);
    let empty = whole(publication, vec![]);
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &work, &empty, clock_now())
            .unwrap()
    );
    let pending = value::<u32>(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_payment_recovery",
        [],
    );
    assert_eq!(pending, 1);
    let id = key_ref(&st.wallet().db().conn, account, key8()).unwrap();
    let read: bool = value(
        st.wallet().conn(),
        "SELECT read_complete FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
        [id],
    );
    assert!(!read, "the key is read again");
    retry_now(&st);
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A witness-only replacement keeps the payment session, so the witness session pins the
/// companion: an answer from another companion is refused until the payment is reread.
#[test]
fn an_answer_from_another_companion_is_refused() {
    let (mut st, candidate, _) = late_fixture();
    let account = st.test_account().unwrap().id();
    let request = request_for(&st, key8(), &candidate);
    let mut other = witness_answer(&st, &request, tip(&st).height);
    other.revision[0] ^= 1;
    let token = status(st.wallet().db(), account).token;
    assert!(
        !st.wallet_mut()
            .db_mut()
            .record_one_time_witness(account, token, request, &other, clock_now())
            .unwrap()
    );
    assert!(one_time_notes(&st).is_empty());
    assert_eq!(status(st.wallet().db(), account).witnesses, [request]);
    let right = witness_answer(&st, &request, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_witness(account, token, request, &right, clock_now())
            .unwrap()
    );
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// Refreshing the witness of an extended manual index keeps its lookup manual-only, so
/// cancelling the search pauses it until the search resumes.
#[test]
fn a_refreshed_manual_witness_stays_manual() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key9 = KeyId::new(Purpose::Receive, 9);
    let candidate = pay_candidate(&mut st, key9);
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, Some(10))
            .unwrap()
    );
    while answer_lookup(&mut st, account, publication) {}
    let request = request_for(&st, key9, &candidate);
    let token = status(st.wallet().db(), account).token;
    assert!(
        st.wallet_mut()
            .db_mut()
            .refresh_one_time_witness(account, token, request)
            .unwrap()
    );
    let id = key_ref(&st.wallet().db().conn, account, key9).unwrap();
    let reasons: u8 = value(
        st.wallet().conn(),
        "SELECT reasons FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
        [id],
    );
    assert_eq!(reasons, 2, "still manual only");
    st.wallet_mut()
        .db_mut()
        .cancel_one_time_history(account)
        .unwrap();
    let paused = status(st.wallet().db(), account);
    assert!(paused.lookups.iter().all(|w| w.work.key != key9));
    assert!(paused.witnesses.is_empty());
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, Some(10))
            .unwrap()
    );
    let resumed = status(st.wallet().db(), account);
    assert!(resumed.lookups.iter().any(|w| w.work.key == key9));
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// Within the pruning depth, a provisional witness whose construction tree the wallet no
/// longer holds stays pending and is read again; it neither credits nor completes.
#[test]
fn missing_tree_material_within_the_pruning_depth_is_refreshed() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    foreign_blocks(&mut st, 2);
    let three = tip(&st).height;
    queue_late(&mut st, key8(), &candidate);
    let request = request_for(&st, key8(), &candidate);
    let stale = witness_answer(&st, &request, three);
    foreign_blocks(&mut st, 3);
    assert!(tip(&st).height - three <= crate::PRUNING_DEPTH);
    // The tree material at three leaves is gone, though the block is recent.
    exec(
        st.wallet().conn(),
        "DELETE FROM ironwood_tree_checkpoints WHERE checkpoint_id <= ?1",
        [u32::from(three)],
    );
    let token = status(st.wallet().db(), account).token;
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_witness(account, token, request, &stale, clock_now())
            .unwrap()
    );
    assert!(one_time_notes(&st).is_empty());
    let unbound: u32 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_payment_recovery WHERE payments IS NULL",
        [],
    );
    assert_eq!(unbound, 1, "pending and read again");
    retry_now(&st);
    let publication = publication_at(&st, tip(&st).height);
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A payment whose claim admission rejects after its segment was read through the final
/// page must not leave that coverage behind: the next lookup reads the payment's shard
/// again instead of completing past it.
#[test]
fn a_rejection_after_the_final_segment_rereads_the_payment() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    foreign_blocks(&mut st, 2);
    recover(st.wallet_mut().db_mut(), account, key8(), candidate.height);
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    let work = work_of(&st, key8());
    let mut misplaced = directory_answer(&candidate);
    misplaced.position += 1;
    let receiver = work.work.receiver;
    let page = whole(
        publication,
        vec![DirectoryRecord {
            receiver,
            page: 0,
            total: 1,
            payment: misplaced,
            ordinal: 0,
        }],
    );
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &work, &page, clock_now())
            .unwrap()
    );
    let request = *status(st.wallet().db(), account).witnesses.first().unwrap();
    let answer = witness_answer(&st, &request, tip(&st).height);
    let token = status(st.wallet().db(), account).token;
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_witness(account, token, request, &answer, clock_now())
            .unwrap()
    );
    assert!(one_time_notes(&st).is_empty());
    let pending: u32 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_payment_recovery",
        [],
    );
    assert_eq!(pending, 0, "the rejected claim is dropped");
    retry_now(&st);
    let again = work_of(&st, key8());
    assert!(
        again.from <= candidate.height,
        "the payment's shard is required again"
    );
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// After a finished seed walk completed I0 empty, a live hit queues I0 only from the next
/// block. A correction then voids the old negatives on the non-direct route, so I0's active
/// request must cover its whole history again and find the payment the old generation
/// omitted.
#[test]
fn a_correction_restores_the_historical_start_of_active_requests() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key0 = KeyId::new(Purpose::Receive, 0);
    let candidate = pay_candidate(&mut st, key0);
    st.generate_and_scan_empty_blocks(1);
    let omitted = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, omitted, true)
            .unwrap()
    );
    for _ in 0..16 {
        let Some(work) = status(st.wallet().db(), account).lookups.first().cloned() else {
            break;
        };
        assert!(
            st.wallet_mut()
                .db_mut()
                .record_one_time_lookup(account, &work, &whole(omitted, vec![]), clock_now())
                .unwrap()
        );
    }
    assert!(status(st.wallet().db(), account).restore_complete);
    st.generate_and_scan_empty_blocks(1);
    let block = tip(&st);
    let token = status(st.wallet().db(), account).token;
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_filters(account, token, 0, &[block], &[key0])
            .unwrap()
    );
    assert_eq!(work_of(&st, key0).from, block.height);
    let corrected = RecoveryPublication {
        history_revision: 1,
        id: [2; 32],
        ..publication_at(&st, block.height)
    };
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, corrected, false)
            .unwrap()
    );
    assert!(work_of(&st, key0).from <= candidate.height);
    drain(&mut st, account, corrected);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// While disabled, a repair read can pass shards and skip receipts that discovery would
/// keep, even when a completed prefix survived a reorg. Enabling discovery between shards
/// drops that partial progress and the cursor, keeping only the surviving prefix.
#[test]
fn enabling_between_shards_drops_partial_repair_progress() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    let key0 = KeyId::new(Purpose::Receive, 0);
    let id = key_ref(&st.wallet().db().conn, account, key0).unwrap();
    let done: u32 = value(
        st.wallet().conn(),
        "SELECT done_height FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
        [id],
    );
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(account, false)
        .unwrap();
    // A repair request after the surviving prefix, stopped between shards.
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_lookups SET target_height = ?2 + 5, reasons = 1,
         start_height = ?2 + 1, checked_height = ?2 + 3, inventory = zeroblob(32), shard = 2,
         segment = 0, read_complete = 0 WHERE one_time_key_id = ?1",
        rusqlite::params![id, done],
    );
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(account, true)
        .unwrap();
    let work = work_of(&st, key0);
    assert_eq!(work.from, BlockHeight::from(done + 1));
    assert!(work.cursor.is_none());
}

/// The seed walk checked I1 to I4 after authenticating I0's still unconfirmed payment.
/// A reorg then drops that payment, so direct catch-up must still check I4.
#[test]
fn a_reorg_keeps_lookahead_the_seed_walk_reached_before_confirmation() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let floor = tip(&st).height;
    pay_candidate(&mut st, KeyId::new(Purpose::Receive, 0));
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    let walked = status(st.wallet().db(), account);
    assert_eq!((walked.restore_next, walked.restore_complete), (5, true));
    assert_eq!(mined_receipt_indexes(&st), [0]);

    let key4 = KeyId::new(Purpose::Receive, 4);
    st.truncate_to_height(floor);
    pay_candidate(&mut st, key4);
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert_eq!(mined_receipt_indexes(&st), [4]);
}

/// Extending a finished manual search past one step's budget of completed indexes must
/// queue the first new index right away, without another unrelated mutation.
#[test]
fn an_extended_manual_search_queues_new_indexes_past_a_long_completed_prefix() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, Some(64))
            .unwrap()
    );
    drain(&mut st, account, publication);
    let done = status(st.wallet().db(), account).manual.unwrap();
    assert_eq!((done.active, done.next), (false, 64));

    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, Some(100))
            .unwrap()
    );
    let queued = status(st.wallet().db(), account).lookups;
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].work.key, KeyId::new(Purpose::Receive, 64));
    drain(&mut st, account, publication);
    let done = status(st.wallet().db(), account).manual.unwrap();
    assert_eq!(
        (done.active, done.next, done.receive_end),
        (false, 100, 100)
    );
}

/// Answers every queued lookup from the independent oracle without delivering proofs.
fn answer_lookups(st: &mut State, account: AccountUuid, publication: RecoveryPublication) {
    for _ in 0..512 {
        let Some(work) = status(st.wallet().db(), account).lookups.first().cloned() else {
            return;
        };
        let fvk = get_key(st.wallet().db(), account, work.work.key)
            .unwrap()
            .unwrap();
        let records = oracle(st, work.work.receiver, fvk.full_viewing_key());
        let page = whole(publication, records);
        assert!(
            st.wallet_mut()
                .db_mut()
                .record_one_time_lookup(account, &work, &page, clock_now())
                .unwrap()
        );
        assert_no_stall(st.wallet().db(), account);
    }
    panic!("lookups did not settle");
}

/// The seed walk reaches I4 only after I4's own lookup already completed, because I0's
/// proof arrived last. Enrolling I4 must not leave the walk waiting on an already
/// covered history, so its paid I4 opens the next lookahead index at once.
#[test]
fn the_seed_walk_continues_past_an_index_completed_before_enrollment() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key0 = KeyId::new(Purpose::Receive, 0);
    let key4 = KeyId::new(Purpose::Receive, 4);
    let payment0 = pay_candidate(&mut st, key0);
    let payment4 = pay_candidate(&mut st, key4);
    recover(st.wallet_mut().db_mut(), account, key4, payment4.height);
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    answer_lookups(&mut st, account, publication);
    send_witness(&mut st, key4, &payment4);
    send_witness(&mut st, key0, &payment0);
    let next = status(st.wallet().db(), account);
    assert!(
        next.lookups
            .iter()
            .any(|w| w.work.key == KeyId::new(Purpose::Receive, 5)),
        "the walk stalled at index {}",
        next.restore_next
    );
    drain(&mut st, account, publication);
    let done = status(st.wallet().db(), account);
    assert_eq!((done.restore_next, done.restore_complete), (9, true));
    assert_eq!(mined_receipt_indexes(&st), [0, 4]);
}

/// After a restart the walk meets 68 completed histories at once, when I0's delayed proof
/// lands last. Running out of its step budget there must leave the worker runnable work.
#[test]
fn a_restarted_seed_walk_resumes_after_exhausting_its_step_budget() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let payments: Vec<_> = (0..64)
        .map(|index| pay_candidate(&mut st, KeyId::new(Purpose::Receive, index)))
        .collect();
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    let walked = status(st.wallet().db(), account);
    assert_eq!((walked.restore_next, walked.restore_complete), (68, true));

    tx(st.wallet_mut().db_mut(), |conn, _| {
        crate::wallet::one_time_rewind::reopen_discovery(conn, account)
    })
    .unwrap();
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    answer_lookups(&mut st, account, publication);
    let key0 = KeyId::new(Purpose::Receive, 0);
    while let Some(request) = status(st.wallet().db(), account)
        .witnesses
        .into_iter()
        .find(|w| w.key != key0)
    {
        send_witness(
            &mut st,
            request.key,
            &payments[request.key.index() as usize],
        );
    }
    send_witness(&mut st, key0, &payments[0]);
    let resumed = status(st.wallet().db(), account);
    assert!(
        resumed.restore_complete || !resumed.lookups.is_empty() || !resumed.witnesses.is_empty(),
        "the walk stalled at index {}",
        resumed.restore_next
    );
    drain(&mut st, account, publication);
    let walked = status(st.wallet().db(), account);
    assert_eq!((walked.restore_next, walked.restore_complete), (68, true));
    assert_eq!(one_time_notes(&st).len(), 64);
}

/// A manual search first passes more completed funded refunds than one step's budget,
/// and must still queue its first new receive index without another mutation.
#[test]
fn a_manual_search_passes_more_completed_refunds_than_one_step_budget() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let height = tip(&st).height;
    for index in 0..70 {
        recover(
            st.wallet_mut().db_mut(),
            account,
            KeyId::new(Purpose::Refund, index),
            height,
        );
    }
    let publication = publication_at(&st, height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, Some(6))
            .unwrap()
    );
    let queued = status(st.wallet().db(), account).lookups;
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].work.key, KeyId::new(Purpose::Receive, 4));
    drain(&mut st, account, publication);
    let done = status(st.wallet().db(), account).manual.unwrap();
    assert_eq!(
        (done.active, done.refunds_done, done.next),
        (false, true, 6)
    );
}

/// A paid key completed through the publication end, then a live hit queued it from the
/// next block. A reorg below that end voids part of the completed span, so the active
/// request must cover the invalidated interval again and find a replacement payment there.
#[test]
fn a_reorg_below_completed_coverage_lowers_active_request_starts() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key0 = KeyId::new(Purpose::Receive, 0);
    pay_candidate(&mut st, key0);
    let floor = tip(&st).height + 2;
    st.generate_and_scan_empty_blocks(8);
    let completed = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, completed, true)
            .unwrap()
    );
    drain(&mut st, account, completed);
    assert_eq!(mined_receipt_indexes(&st), [0]);
    st.generate_and_scan_empty_blocks(1);
    let block = tip(&st);
    let token = status(st.wallet().db(), account).token;
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_filters(account, token, 0, &[block], &[key0])
            .unwrap()
    );
    assert_eq!(work_of(&st, key0).from, block.height);

    st.truncate_to_height(floor);
    assert!(work_of(&st, key0).from <= floor + 1);
    pay_candidate(&mut st, key0);
    st.generate_and_scan_empty_blocks(10);
    let replaced = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, replaced, false)
            .unwrap()
    );
    drain(&mut st, account, replaced);
    assert_eq!(mined_receipt_indexes(&st), [0, 0]);
}

/// After a completed restore and a reorg that keeps part of each key's completed span, a
/// manual search reaching only that span settles each key in the same step instead of
/// leaving the search with nothing runnable.
#[test]
fn a_manual_search_over_surviving_coverage_does_not_stall() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    pay_candidate(&mut st, KeyId::new(Purpose::Receive, 0));
    st.generate_and_scan_empty_blocks(8);
    let completed = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, completed, true)
            .unwrap()
    );
    drain(&mut st, account, completed);
    let floor = tip(&st).height - 3;
    st.truncate_to_height(floor);
    let surviving = publication_at(&st, floor);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, surviving, Some(4))
            .unwrap()
    );
    assert_no_stall(st.wallet().db(), account);
    drain(&mut st, account, surviving);
    let manual = status(st.wallet().db(), account).manual.unwrap();
    assert_eq!((manual.active, manual.next), (false, 4));
}

/// More covered refunds than one progress step's budget: after a rewind keeps their
/// completed spans, a manual search settles them in place across several steps, each
/// handing the rest to the worker, and reaches its end.
#[test]
fn a_manual_search_over_many_covered_refunds_hands_off_and_finishes() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks(8);
    let funded = tip(&st).height - 6;
    for index in 0..70 {
        recover(
            st.wallet_mut().db_mut(),
            account,
            KeyId::new(Purpose::Refund, index),
            funded,
        );
    }
    let completed = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, completed, true)
            .unwrap()
    );
    drain(&mut st, account, completed);
    let floor = tip(&st).height - 3;
    st.truncate_to_height(floor);
    let surviving = publication_at(&st, floor);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, surviving, Some(1))
            .unwrap()
    );
    drain(&mut st, account, surviving);
    let manual = status(st.wallet().db(), account).manual.unwrap();
    assert_eq!(
        (manual.active, manual.refunds_done, manual.next),
        (false, true, 1)
    );
}

/// A deterministic generator for the property test below.
struct Steps(u64);

impl Steps {
    /// The next value below `bound`.
    fn below(&mut self, bound: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % bound
    }
}

/// Seeded sequences of payments, direct catch-up, manual searches over more than one step's
/// budget of completed receive and refund entries, rewinds before manual searches, birthday
/// lowering and toggles. Every status read checks the no-stall invariant (see
/// [`assert_no_stall`]), and every search finishes.
#[test]
fn seeded_recovery_sequences_never_stall() {
    for seed in 0..3u64 {
        let mut steps = Steps(seed);
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        st.generate_and_scan_empty_blocks(4);
        let funded = tip(&st).height;
        for index in 0..70 {
            recover(
                st.wallet_mut().db_mut(),
                account,
                KeyId::new(Purpose::Refund, index),
                funded,
            );
        }
        let publication = publication_at(&st, tip(&st).height);
        assert!(
            st.wallet_mut()
                .db_mut()
                .begin_one_time_recovery(account, publication, true)
                .unwrap()
        );
        drain(&mut st, account, publication);
        for _ in 0..24 {
            let publication = publication_at(&st, tip(&st).height);
            // Rewinds before manual searches come up twice as often as other steps.
            match steps.below(7).min(6) {
                6 => {
                    let depth = 1 + steps.below(3) as u32;
                    rewind_and_search(&mut st, account, depth, 1 + steps.below(80), seed);
                }
                0 => {
                    let index = steps.below(6);
                    pay_candidate(&mut st, KeyId::new(Purpose::Receive, index));
                    st.generate_and_scan_empty_blocks(1);
                }
                1 => {
                    assert!(
                        st.wallet_mut()
                            .db_mut()
                            .begin_one_time_recovery(account, publication, true)
                            .unwrap()
                    );
                    drain(&mut st, account, publication);
                }
                2 => {
                    let end = 1 + steps.below(80);
                    assert!(
                        st.wallet_mut()
                            .db_mut()
                            .check_one_time_history(account, publication, Some(end))
                            .unwrap()
                    );
                    drain(&mut st, account, publication);
                    let manual = status(st.wallet().db(), account).manual.unwrap();
                    assert!(!manual.active, "seed {seed}: the search finishes");
                }
                3 => {
                    let depth = 1 + steps.below(3) as u32;
                    rewind_and_search(&mut st, account, depth, 1 + steps.below(80), seed);
                }
                4 => {
                    // Lowering the birthday reopens every known history.
                    tx(st.wallet_mut().db_mut(), |conn, _| {
                        crate::wallet::one_time_rewind::reopen_discovery(conn, account)
                    })
                    .unwrap();
                    status(st.wallet().db(), account);
                    assert!(
                        st.wallet_mut()
                            .db_mut()
                            .begin_one_time_recovery(account, publication, true)
                            .unwrap()
                    );
                    drain(&mut st, account, publication);
                }
                _ => {
                    let db = st.wallet_mut().db_mut();
                    db.set_one_time_recovery_enabled(account, false).unwrap();
                    status(db, account);
                    db.set_one_time_recovery_enabled(account, true).unwrap();
                    status(db, account);
                }
            }
            status(st.wallet().db(), account);
        }
    }
}

/// Rewinds `depth` blocks, keeping part of the completed coverage, and runs a manual search
/// bounded by `end` over the surviving chain, then finishes it after the chain grows back.
fn rewind_and_search(st: &mut State, account: AccountUuid, depth: u32, end: u64, seed: u64) {
    let floor = tip(st).height - depth;
    st.truncate_to_height(floor);
    let surviving = publication_at(st, floor);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, surviving, Some(end))
            .unwrap()
    );
    status(st.wallet().db(), account);
    // Older work may need a later publication; answer what this one covers.
    for _ in 0..512 {
        let Some(work) = status(st.wallet().db(), account)
            .lookups
            .into_iter()
            .find(|w| w.through <= floor)
        else {
            break;
        };
        let fvk = get_key(st.wallet().db(), account, work.work.key)
            .unwrap()
            .unwrap();
        let records = oracle(st, work.work.receiver, fvk.full_viewing_key());
        assert!(
            st.wallet_mut()
                .db_mut()
                .record_one_time_lookup(account, &work, &whole(surviving, records), clock_now())
                .unwrap()
        );
    }
    st.generate_and_scan_empty_blocks(depth as usize + 1);
    let current = publication_at(st, tip(st).height);
    drain(st, account, current);
    let manual = status(st.wallet().db(), account).manual.unwrap();
    assert!(
        !manual.active,
        "seed {seed}: the search after a rewind finishes"
    );
}

/// Cancelling a manual search while its manual-only lookup is pending leaves that lookup
/// queued but unexposed. The no-stall check, run by every status read here, counts it as
/// paused by the user, and resuming the search exposes it again.
#[test]
fn a_cancelled_manual_only_lookup_counts_as_paused() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert!(status(st.wallet().db(), account).restore_complete);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, Some(10))
            .unwrap()
    );
    let key4 = KeyId::new(Purpose::Receive, 4);
    assert_eq!(status(st.wallet().db(), account).lookups[0].work.key, key4);
    st.wallet_mut()
        .db_mut()
        .cancel_one_time_history(account)
        .unwrap();
    let paused = status(st.wallet().db(), account);
    assert!(paused.lookups.is_empty() && !paused.manual.unwrap().active);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, None)
            .unwrap()
    );
    assert_eq!(status(st.wallet().db(), account).lookups[0].work.key, key4);
    drain(&mut st, account, publication);
    assert!(!status(st.wallet().db(), account).manual.unwrap().active);
}

/// A manual check derives receive keys beyond the automatic end. They stay out of the
/// filter receiver set, and a filter hit for one is refused, so one manual search never
/// widens automatic monitoring.
#[test]
fn manual_only_receive_keys_stay_out_of_automatic_monitoring() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, publication, Some(10))
            .unwrap()
    );
    drain(&mut st, account, publication);
    let manual_only = KeyId::new(Purpose::Receive, 8);
    assert!(
        get_key(st.wallet().db(), account, manual_only)
            .unwrap()
            .is_some()
    );
    let (token, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    let receive: Vec<u64> = receivers
        .iter()
        .filter(|w| w.key.purpose() == Purpose::Receive)
        .map(|w| w.key.index())
        .collect();
    assert_eq!(receive, [0, 1, 2, 3]);

    st.generate_and_scan_empty_blocks(1);
    let block = tip(&st);
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_filters(account, token, 0, &[block], &[manual_only])
            .is_err()
    );
    let automatic: u32 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_lookups l
         JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
         WHERE k.purpose = 1 AND k.key_index = ?1 AND l.reasons & 1 != 0",
        [8u64.to_be_bytes()],
    );
    assert_eq!(automatic, 0);
}

/// A faulty directory returns the right note and path under another transaction's ID. The
/// payment is admitted under that label, but storing that transaction's raw bytes finds
/// no such action in it: the note is dropped rather than credited to it, its key's history
/// is read again, and the true record is then admitted under its own transaction.
#[test]
fn a_raw_transaction_without_the_claimed_action_drops_the_admitted_note() {
    use zcash_client_backend::data_api::wallet::decrypt_and_store_transaction;
    let mut st = scanned_wallet();
    let network = *st.network();
    let account = st.test_account().unwrap().id();
    let other = external_payment(
        foreign_receiver(),
        &zcash_protocol::memo::MemoBytes::empty(),
    );
    let (mined, _) = st.generate_next_block_from_tx(1, &other);
    st.scan_cached_blocks(mined, 1);
    let candidate = pay_candidate(&mut st, key8());
    let mut forged = candidate.clone();
    forged.txid = other.txid();
    let publication = queue_late(&mut st, key8(), &forged);
    send_witness(&mut st, key8(), &forged);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);

    decrypt_and_store_transaction(&network, st.wallet_mut(), &other, Some(mined)).unwrap();
    assert!(
        one_time_notes(&st).is_empty(),
        "nothing is credited to the other transaction"
    );
    let id = key_ref(&st.wallet().db().conn, account, key8()).unwrap();
    let reopened: bool = value(
        st.wallet().conn(),
        "SELECT target_height IS NOT NULL AND read_complete = 0 FROM ironwood_one_time_lookups
         WHERE one_time_key_id = ?1",
        [id],
    );
    assert!(reopened, "the key's history is read again");

    drain(&mut st, account, publication);
    let txids: Vec<Vec<u8>> = column(
        st.wallet().conn(),
        "SELECT t.txid FROM ironwood_received_notes n JOIN transactions t
         ON t.id_tx = n.transaction_id WHERE n.one_time_key_id IS NOT NULL",
        [],
    );
    assert_eq!(txids, [candidate.txid.as_ref().to_vec()]);
}

/// A final lookup step that does not prove coverage through the inventory's end, by an
/// absent or short checked height, is refused and leaves the history unchecked, so a
/// partial answer cannot mark the rest of history as read.
#[test]
fn a_final_step_short_of_the_inventory_end_is_refused() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks(3);
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    let work = status(st.wallet().db(), account).lookups[0].clone();
    let id = key_ref(&st.wallet().db().conn, account, work.work.key).unwrap();
    let progress = |st: &State| -> (Option<u32>, Option<u32>, bool) {
        row(
            st.wallet().conn(),
            "SELECT checked_height, done_height, read_complete FROM ironwood_one_time_lookups
             WHERE one_time_key_id = ?1",
            [id],
        )
    };
    let before = progress(&st);
    for checked in [None, Some(publication.end.height - 1)] {
        let partial = LookupPage {
            checked_through: checked,
            ..whole(publication, vec![])
        };
        assert!(
            st.wallet_mut()
                .db_mut()
                .record_one_time_lookup(account, &work, &partial, clock_now())
                .is_err()
        );
        assert_eq!(progress(&st), before);
    }
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &work, &whole(publication, vec![]), clock_now())
            .unwrap()
    );
    assert_eq!(progress(&st).1, Some(u32::from(publication.end.height)));
}
