//! Queue behavior using an independent compact-block oracle and Merkle witness builder.
use super::*;
use zcash_client_backend::data_api::one_time_ivk::restore::{
    LookupCursor, RecoveryStatus, SegmentRef, StepShard, WitnessAnswer, WitnessRequest,
};

/// A fixture publication's whole history for one receiver: one shard of one segment,
/// read through its final page in this step.
pub(in crate::wallet::one_time_ivk) fn whole(
    publication: RecoveryPublication,
    records: Vec<DirectoryRecord>,
) -> LookupPage {
    LookupPage {
        publication,
        inventory_shards: 1,
        shards: only_shard(publication),
        segment: Some(segment_ref(publication)),
        records,
        checked_through: Some(publication.end.height),
        next: None,
    }
}

/// [`whole`] for `work`, or the step that reads nothing when its first unchecked height is
/// past the publication's end.
pub(in crate::wallet::one_time_ivk) fn whole_for(
    work: &LookupWork,
    publication: RecoveryPublication,
    records: Vec<DirectoryRecord>,
) -> LookupPage {
    if work.from > publication.end.height {
        LookupPage {
            shards: vec![],
            segment: None,
            records: vec![],
            checked_through: None,
            ..whole(publication, vec![])
        }
    } else {
        whole(publication, records)
    }
}

/// The fixture publication's only shard, read rather than filtered.
pub(in crate::wallet::one_time_ivk) fn only_shard(
    publication: RecoveryPublication,
) -> Vec<StepShard> {
    vec![StepShard {
        index: 0,
        start_height: publication.start_height,
        end_height: publication.end.height,
        segments: 1,
        excluded: false,
    }]
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
/// search paused, which leaves a cancelled search's lookups without a reason, or an app
/// update the service requires). Anything else waits on a mutation nothing will make.
///
/// Shard-local state must also stay consistent: no settled request keeps a target nothing
/// would clear, a completed read keeps no segment cursor, and a candidate whose witness
/// binding was dropped has an unread lookup to rebind it after rewound coverage, unless the
/// user paused that lookup.
///
/// A reserved receiver held by invalidated history (see `queue::RECEIVE_PENDING`) must also
/// have a runnable lookup that can lift the hold, or a payment candidate in progress, unless
/// the user paused discovery, which refuses reservations anyway.
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
         WHERE k.account_id = ?1 AND l.reasons & 3 != 0 AND l.target_height IS NOT NULL
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
           AND l.reasons & 3 != 0 AND (l.read_complete = 1 OR l.target_height IS NULL))",
        [owner],
    );
    assert!(!settled, "a settled request keeps a target nothing clears");
    assert!(!cursor, "a completed read keeps a segment cursor");
    assert!(!unbound, "an unbound candidate has no read to rebind it");
    let state = db.one_time_recovery(account, i64::MAX).unwrap();
    if state.enabled {
        let held: bool = value(
            &db.conn,
            "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_keys k JOIN accounts a ON a.id = k.account_id
             WHERE a.uuid = ?1 AND k.purpose = 1 AND k.used = 0
               AND k.reserved_at IS NOT NULL AND k.released_at IS NULL
               AND EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
                   WHERE l.one_time_key_id = k.id AND l.reasons & 4 != 0)
               AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
                   WHERE l.one_time_key_id = k.id AND l.target_height IS NOT NULL
                     AND l.reasons & 3 != 0 AND l.read_complete = 0)
               AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
                   WHERE p.one_time_key_id = k.id))",
            [account.0],
        );
        assert!(
            !held,
            "a reserved receiver is held with no work to release it"
        );
    }
    if !state.enabled
        || state.upgrade_required
        || !state.lookups.is_empty()
        || !state.witnesses.is_empty()
    {
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
             WHERE a.uuid = ?1 AND l.target_height IS NOT NULL AND l.read_complete = 0 AND l.reasons & 3 != 0)",
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
    // Nothing is required past the inventory's end, so the step reads no shard.
    let page = if work.from > publication.end.height {
        LookupPage {
            shards: vec![],
            segment: None,
            records: vec![],
            checked_through: None,
            ..whole(publication, vec![])
        }
    } else {
        LookupPage {
            publication,
            inventory_shards: 1,
            shards: only_shard(publication),
            segment: Some(segment_ref(publication)),
            records: records[start..end].to_vec(),
            checked_through: (end == records.len()).then_some(publication.end.height),
            next: (end < records.len()).then(|| LookupCursor {
                inventory: publication.id,
                shard: 0,
                segment: 0,
                last: records[..end].last().cloned(),
            }),
        }
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
         ON l.one_time_key_id = k.id WHERE l.target_height IS NOT NULL AND l.reasons & 3 != 0 ORDER BY k.key_index", []);
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

/// A late payment waits while the scan's coverage ends one block short of its scanned tip,
/// since a spend of the note there may be missing from the journal. That block is queued
/// for a rescan, which covers it, and the payment is admitted spent, never unspent.
#[test]
fn a_late_payment_waits_for_coverage_of_the_scanned_tip() {
    let mut st = scanned_wallet();
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
    st.scan_cached_blocks(height, 1);
    queue_late(&mut st, key8(), &candidate);
    // The spending block was stored without coverage, so without its journal entry.
    let tip = u32::from(height);
    for sql in [
        "UPDATE ironwood_journal_coverage SET end_height = ?1 WHERE end_height > ?1",
        "DELETE FROM ironwood_spend_journal_nullifiers WHERE block_height = ?1",
        "DELETE FROM ironwood_spend_journal WHERE block_height = ?1",
    ] {
        exec(st.wallet().conn(), sql, [tip]);
    }
    send_witness(&mut st, key8(), &candidate);
    assert!(one_time_notes(&st).is_empty(), "admission waits");
    assert!(
        rescans(&st).contains(&(tip, tip + 1)),
        "the uncovered tip is queued"
    );
    st.scan_cached_blocks(height, 1);
    assert_eq!(one_time_notes(&st), [(100_000, true)]);
}

/// A late payment over a one-block hole in the scan's coverage waits, has that block queued
/// for a rescan, and is admitted once the rescan covers it.
#[test]
fn a_late_payment_over_a_one_block_coverage_hole_is_rescanned() {
    let (mut st, candidate, _) = late_fixture();
    st.generate_and_scan_empty_blocks(2);
    let hole = u32::from(candidate.height) + 1;
    let conn = st.wallet().conn();
    exec(
        conn,
        "INSERT INTO ironwood_journal_coverage (account_id, start_height, end_height)
         SELECT account_id, ?1 + 1, end_height FROM ironwood_journal_coverage
         WHERE start_height <= ?1 AND end_height > ?1 + 1",
        [hole],
    );
    let split = conn
        .execute(
            "UPDATE ironwood_journal_coverage SET end_height = ?1
             WHERE start_height <= ?1 AND end_height > ?1 + 1",
            [hole],
        )
        .unwrap();
    assert_eq!(split, 1, "the hole splits the coverage");
    send_witness(&mut st, key8(), &candidate);
    assert!(one_time_notes(&st).is_empty(), "admission waits");
    assert!(
        rescans(&st).contains(&(hole, hole + 1)),
        "{:?}",
        rescans(&st)
    );
    st.scan_cached_blocks(BlockHeight::from(hole), 1);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// The block ranges the scan queue still has to scan.
fn rescans(st: &State) -> Vec<(u32, u32)> {
    rows(
        st.wallet().conn(),
        "SELECT block_range_start, block_range_end FROM scan_queue WHERE priority != ?1",
        [crate::wallet::scanning::priority_code(
            &zcash_client_backend::data_api::scanning::ScanPriority::Scanned,
        )],
    )
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
        inventory_shards: 2,
        shards: vec![StepShard {
            index: 0,
            start_height: first.start_height,
            end_height: sealed_end,
            segments: 1,
            excluded: true,
        }],
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
                .record_one_time_lookup(
                    account,
                    &work,
                    &whole_for(&work, surviving, records),
                    clock_now()
                )
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

/// How a faulty directory mislabels a genuine payment.
#[derive(Clone, Copy, Debug)]
enum Mislabel {
    /// Under an unrelated transaction's ID.
    OtherTransaction,
    /// Under a transaction whose claimed action differs only in its note commitment.
    CommitmentOnly,
}

/// The payment's transaction with the note commitment of action `action` changed, so it
/// keeps the action's nullifier, ephemeral key and ciphertext but has another ID.
fn with_other_commitment(
    tx: &zcash_primitives::transaction::Transaction,
    action: u32,
) -> zcash_primitives::transaction::Transaction {
    let cmx = tx.ironwood_bundle().unwrap().actions()[action as usize]
        .cmx()
        .to_bytes();
    let mut bytes = vec![];
    tx.write(&mut bytes).unwrap();
    let at = bytes.windows(32).position(|w| w == cmx).unwrap();
    bytes[at] ^= 1;
    zcash_primitives::transaction::Transaction::read(&bytes[..], tx.consensus_branch_id()).unwrap()
}

/// A wallet holding a genuine payment to I8 that a faulty directory labeled with another
/// transaction's ID, admitted under that label, with that wrong transaction and the true
/// payment.
struct Mislabeled {
    st: State,
    candidate: PendingPayment,
    forged: PendingPayment,
    wrong: zcash_primitives::transaction::Transaction,
}

/// Admits a genuine payment to I8 under the wrong label `mislabel` describes.
fn mislabeled(mislabel: Mislabel) -> Mislabeled {
    let mut st = scanned_wallet();
    let receiver = derive(&st, key8()).address_at(0u32, Scope::External);
    let paying = external_payment(receiver, &zcash_protocol::memo::MemoBytes::empty());
    let (height, _) = st.generate_next_block_from_tx(1, &paying);
    st.scan_cached_blocks(height, 1);
    let candidate = candidate_at(&st, height, &derive(&st, key8()));
    let wrong = match mislabel {
        Mislabel::OtherTransaction => {
            let other = external_payment(
                foreign_receiver(),
                &zcash_protocol::memo::MemoBytes::empty(),
            );
            let (mined, _) = st.generate_next_block_from_tx(1, &other);
            st.scan_cached_blocks(mined, 1);
            other
        }
        Mislabel::CommitmentOnly => with_other_commitment(&paying, candidate.action_index),
    };
    let mut forged = candidate.clone();
    forged.txid = wrong.txid();
    queue_late(&mut st, key8(), &forged);
    send_witness(&mut st, key8(), &forged);
    Mislabeled {
        st,
        candidate,
        forged,
        wrong,
    }
}

/// The one-time receipts: note row, transaction ID, and whether its label is disputed.
fn receipts(st: &State) -> Vec<(i64, Vec<u8>, bool)> {
    rows(
        st.wallet().conn(),
        "SELECT n.id, t.txid, EXISTS(SELECT 1 FROM ironwood_one_time_disputed_receipts d
             WHERE d.note_id = n.id)
         FROM ironwood_received_notes n JOIN transactions t ON t.id_tx = n.transaction_id
         WHERE n.one_time_key_id IS NOT NULL ORDER BY n.id",
        [],
    )
}

/// A faulty directory returns a genuine payment's note and path under another
/// transaction's ID, either an unrelated one or one whose claimed action differs only in its
/// note commitment. The payment is admitted under that label, but the claimed action in the
/// fetched raw transaction does not hold it: the receipt keeps its note row and only its label
/// becomes disputed, and its key's history is read again. The raw transaction is kept, so the
/// same mislabeled record repeated later is refused at admission. The true record then moves
/// the same row to its own transaction. This holds with discovery enabled, and disabled before
/// the raw transaction arrived.
#[test]
fn a_raw_transaction_without_the_claimed_action_disputes_the_label() {
    use zcash_client_backend::data_api::wallet::decrypt_and_store_transaction;
    for (mislabel, enabled) in [
        (Mislabel::OtherTransaction, true),
        (Mislabel::OtherTransaction, false),
        (Mislabel::CommitmentOnly, true),
        (Mislabel::CommitmentOnly, false),
    ] {
        let Mislabeled {
            mut st,
            candidate,
            forged,
            wrong,
        } = mislabeled(mislabel);
        let network = *st.network();
        let account = st.test_account().unwrap().id();
        let [(note, ref label, false)] = receipts(&st)[..] else {
            panic!("one receipt under the wrong label");
        };
        assert_eq!(*label, forged.txid.as_ref().to_vec());
        if !enabled {
            st.wallet_mut()
                .db_mut()
                .set_one_time_recovery_enabled(account, false)
                .unwrap();
        }

        decrypt_and_store_transaction(&network, st.wallet_mut(), &wrong, None).unwrap();
        let disputed = vec![(note, forged.txid.as_ref().to_vec(), true)];
        assert_eq!(receipts(&st), disputed, "{mislabel:?} {enabled}");
        assert_eq!(one_time_notes(&st), [(50_000, false)]);
        let id = key_ref(&st.wallet().db().conn, account, key8()).unwrap();
        let reopened: bool = value(
            st.wallet().conn(),
            "SELECT target_height IS NOT NULL AND read_complete = 0 FROM ironwood_one_time_lookups
             WHERE one_time_key_id = ?1",
            [id],
        );
        assert!(reopened, "the key's history is read again");

        // The directory repeats the same mislabeled record: the kept raw bytes refuse it.
        let publication = queue_late(&mut st, key8(), &forged);
        send_witness(&mut st, key8(), &forged);
        assert_eq!(
            receipts(&st),
            disputed,
            "{mislabel:?} {enabled}: refused again"
        );

        // After the rejection's backoff, the true record is read.
        exec(
            st.wallet().conn(),
            "UPDATE ironwood_one_time_lookups SET next_attempt_at = 0",
            [],
        );
        drain(&mut st, account, publication);
        assert_eq!(status(st.wallet().db(), account).enabled, enabled);
        assert_eq!(
            receipts(&st),
            [(note, candidate.txid.as_ref().to_vec(), false)],
            "{mislabel:?} {enabled}"
        );
        assert_eq!(one_time_notes(&st), [(50_000, false)]);
    }
}

/// A build without Orchard stored the raw transaction a receipt's wrong label names, leaving
/// the check pending (see `ironwood_hooks::defer_receipt_check`). The next blocks an Orchard
/// build stores check those bytes, which disputes the label, and settle the pending check.
#[test]
fn an_orchard_build_checks_raw_bytes_a_build_without_it_stored() {
    let Mislabeled {
        mut st,
        forged,
        wrong,
        ..
    } = mislabeled(Mislabel::OtherTransaction);
    let [(note, _, false)] = receipts(&st)[..] else {
        panic!("one receipt under the wrong label");
    };
    let mut raw = vec![];
    wrong.write(&mut raw).unwrap();
    exec(
        st.wallet().conn(),
        "UPDATE transactions SET raw = ?2 WHERE txid = ?1",
        rusqlite::params![forged.txid.as_ref(), raw],
    );
    exec(
        st.wallet().conn(),
        "INSERT INTO ironwood_one_time_unchecked_raw (transaction_id)
         SELECT id_tx FROM transactions WHERE txid = ?1",
        [forged.txid.as_ref()],
    );
    st.generate_and_scan_empty_blocks(1);
    assert_eq!(receipts(&st), [(note, forged.txid.as_ref().to_vec(), true)]);
    let pending: u32 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_unchecked_raw",
        [],
    );
    assert_eq!(pending, 0);
}

/// A receipt admitted under a wrong label funds an unmined send before raw bytes disprove the
/// label. Disputing it keeps the note row and its spend, so the note stays unavailable and the
/// balance unchanged, while history, transaction outputs and transaction details stop
/// attributing it to the disproven transaction. The true record moves that same row to its
/// own transaction with the spend intact, and history shows it received there, with
/// discovery enabled and disabled.
#[test]
fn a_disputed_label_keeps_the_receipts_pending_spend() {
    use zcash_client_backend::data_api::{
        transparent_ledger::TransparentDetailRead as _, wallet::decrypt_and_store_transaction,
    };
    for enabled in [true, false] {
        let Mislabeled {
            mut st,
            candidate,
            forged,
            wrong,
        } = mislabeled(Mislabel::OtherTransaction);
        let network = *st.network();
        let account = st.test_account().cloned().unwrap();
        let [(note, _, false)] = receipts(&st)[..] else {
            panic!("one receipt under the wrong label");
        };
        let to = payment(&unified(foreign_receiver()), 30_000, None);
        let (_, send) = transfer(
            &mut st,
            (account.id(), account.usk()),
            vec![to],
            (None, zcash_protocol::ShieldedPool::Orchard),
        );
        let send = send.unwrap();
        let spends = |st: &State| -> Vec<Vec<u8>> {
            column(
                st.wallet().conn(),
                "SELECT t.txid FROM ironwood_received_note_spends s
                 JOIN transactions t ON t.id_tx = s.transaction_id
                 WHERE s.ironwood_received_note_id = ?1",
                [note],
            )
        };
        assert_eq!(spends(&st), [send.as_ref().to_vec()]);
        assert_eq!(one_time_notes(&st), [(50_000, true)]);
        if !enabled {
            st.wallet_mut()
                .db_mut()
                .set_one_time_recovery_enabled(account.id(), false)
                .unwrap();
        }

        decrypt_and_store_transaction(&network, st.wallet_mut(), &wrong, None).unwrap();
        assert_eq!(receipts(&st), [(note, forged.txid.as_ref().to_vec(), true)]);
        assert_eq!(
            spends(&st),
            [send.as_ref().to_vec()],
            "the pending spend survives"
        );
        assert_eq!(one_time_notes(&st), [(50_000, true)], "still unavailable");
        // The disproven transaction no longer shows the receipt, while the send that spends
        // it still counts the input.
        assert_eq!(
            received_in(&st, account.id()),
            [(send.as_ref().to_vec(), 0, 50_000)],
            "enabled {enabled}: history during the dispute"
        );
        assert!(outputs_of(&st, forged.txid).is_empty());
        assert!(
            st.wallet()
                .db()
                .transparent_display_view(account.id(), forged.txid)
                .unwrap()
                .is_none()
        );

        let publication = publication_at(&st, tip(&st).height);
        if enabled {
            assert!(
                st.wallet_mut()
                    .db_mut()
                    .begin_one_time_recovery(account.id(), publication, true)
                    .unwrap()
            );
        }
        drain(&mut st, account.id(), publication);
        assert_eq!(status(st.wallet().db(), account.id()).enabled, enabled);
        assert_eq!(
            receipts(&st),
            [(note, candidate.txid.as_ref().to_vec(), false)],
            "enabled {enabled}"
        );
        assert_eq!(spends(&st), [send.as_ref().to_vec()]);
        assert_eq!(one_time_notes(&st), [(50_000, true)]);
        let mut history = received_in(&st, account.id());
        history.sort();
        let mut expected = vec![
            (candidate.txid.as_ref().to_vec(), 50_000, 0),
            (send.as_ref().to_vec(), 0, 50_000),
        ];
        expected.sort();
        assert_eq!(
            history, expected,
            "enabled {enabled}: history after relabeling"
        );
        assert_eq!(outputs_of(&st, candidate.txid), [50_000]);
    }
}

/// A service format this client does not support makes recovery wait for an app update:
/// no work is exposed or backed off, every pending lookup and candidate is kept through a
/// restart, and a publication this client captured resumes it.
#[test]
fn an_unsupported_service_waits_for_an_upgrade_and_keeps_its_work() {
    let (mut st, _, publication) = late_fixture();
    let account = st.test_account().unwrap().id();
    let pending = status(st.wallet().db(), account);
    assert!(!pending.witnesses.is_empty());
    let snapshot = |st: &State| -> (Vec<(i64, Option<u32>, u8, u32, i64, bool)>, u32) {
        (
            rows(
                st.wallet().conn(),
                "SELECT one_time_key_id, target_height, reasons, attempts, next_attempt_at,
                     read_complete FROM ironwood_one_time_lookups ORDER BY one_time_key_id",
                [],
            ),
            value(
                st.wallet().conn(),
                "SELECT COUNT(*) FROM ironwood_one_time_payment_recovery
                 WHERE payments IS NOT NULL",
                [],
            ),
        )
    };
    let before = snapshot(&st);
    st.wallet_mut()
        .db_mut()
        .require_one_time_upgrade(account)
        .unwrap();
    reopen(&mut st);
    let waiting = status(st.wallet().db(), account);
    assert!(waiting.upgrade_required);
    assert!(waiting.lookups.is_empty() && waiting.witnesses.is_empty());
    assert_eq!(
        snapshot(&st),
        before,
        "nothing pending is dropped or backed off"
    );

    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    let resumed = status(st.wallet().db(), account);
    assert!(!resumed.upgrade_required);
    assert_eq!(resumed.witnesses, pending.witnesses);
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
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

/// Each transaction in `account`'s history summaries with its recorded received and spent
/// values, excluding change.
fn received_in(st: &State, account: AccountUuid) -> Vec<(Vec<u8>, u64, u64)> {
    st.wallet()
        .db()
        .transaction_history_summaries(account)
        .unwrap()
        .into_iter()
        .filter(|s| s.total_received != 0 || s.total_spent != 0)
        .map(|s| {
            let change: u64 = if s.has_change { s.total_received } else { 0 };
            (
                s.txid.as_ref().to_vec(),
                s.total_received - change,
                s.total_spent,
            )
        })
        .collect()
}

/// The values of `txid`'s received outputs in `v_tx_outputs`.
fn outputs_of(st: &State, txid: zcash_primitives::transaction::TxId) -> Vec<i64> {
    column(
        st.wallet().conn(),
        "SELECT value FROM v_tx_outputs WHERE txid = ?1 AND to_account_uuid IS NOT NULL",
        [txid.as_ref()],
    )
}

/// The blocks the cache holds above `height`, as filter progress names them.
pub(in crate::wallet::one_time_ivk) fn blocks_above(
    st: &State,
    height: BlockHeight,
) -> Vec<ChainPoint> {
    let blocks: Vec<Vec<u8>> = column(
        &st.cache().0,
        "SELECT data FROM compactblocks WHERE height > ?1 ORDER BY height",
        [u32::from(height)],
    );
    blocks
        .into_iter()
        .map(|bytes| {
            let b = CompactBlock::decode(bytes.as_slice()).unwrap();
            ChainPoint {
                height: BlockHeight::from(b.height as u32),
                hash: b.hash(),
            }
        })
        .collect()
}

/// A manual check already derived I4. A filter request captures the automatic receivers
/// I0 to I3, then I0's delayed payment proof enrolls I4, and ordinary sync stores a block
/// paying I4. The held callback never matched I4, so it cannot commit past that block; a
/// fresh capture does, and I4's payment is found.
#[test]
fn enrollment_invalidates_a_held_filter_request() {
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
            .check_one_time_history(account, publication, Some(5))
            .unwrap()
    );
    drain(&mut st, account, publication);
    let (key0, key4) = (
        KeyId::new(Purpose::Receive, 0),
        KeyId::new(Purpose::Receive, 4),
    );
    assert!(get_key(st.wallet().db(), account, key4).unwrap().is_some());

    // I0's payment is matched by filters, so its lookup is queued.
    let frontier = status(st.wallet().db(), account)
        .filter_frontier
        .unwrap()
        .height;
    pay_candidate(&mut st, key0);
    let (token, _) = st.wallet().db().one_time_receivers(account).unwrap();
    let first = blocks_above(&st, frontier);
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_filters(account, token, 0, &first, &[key0])
            .unwrap()
    );
    // A filter request for the next blocks captures I0 to I3.
    let (held, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(receivers.iter().all(|w| w.key != key4));
    // I0's proof arrives and enrolls I4.
    let current = publication_at(&st, tip(&st).height);
    drain(&mut st, account, current);
    let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(receivers.iter().any(|w| w.key == key4));
    // Ordinary sync stores I4's first payment, then the held callback returns.
    let synced = tip(&st).height;
    pay_candidate(&mut st, key4);
    let next = blocks_above(&st, synced);
    assert!(
        !st.wallet_mut()
            .db_mut()
            .record_one_time_filters(account, held, 0, &next, &[])
            .unwrap(),
        "a receiver set from before enrollment is stale"
    );
    let (token, _) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_filters(account, token, 0, &next, &[key4])
            .unwrap()
    );
    let current = publication_at(&st, tip(&st).height);
    drain(&mut st, account, current);
    assert_eq!(mined_receipt_indexes(&st), [0, 4]);
}

/// One transaction pays two private receipts. A reorg moves it to later positions. Each
/// receipt keeps its own repair eligibility until its own position and witness are
/// restored, so repairing the first, which marks the transaction mined, cannot leave the
/// second at its stale position, with recovery enabled or disabled.
#[test]
fn a_reorg_repairs_each_private_receipt_of_one_transaction() {
    for enabled in [true, false] {
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
        let floor = tip(&st).height;
        let keys = [0, 1].map(|i| KeyId::new(Purpose::Receive, i));
        let fvks = keys.map(|key| derive(&st, key));
        let second = payment(
            &unified(fvks[1].address_at(0u32, Scope::External)),
            30_000,
            None,
        );
        let tx = external_payment_with(
            fvks[0].address_at(0u32, Scope::External),
            &zcash_protocol::memo::MemoBytes::empty(),
            vec![second],
        );
        let mine = |st: &mut State| {
            let (height, _) = st.generate_next_block_from_tx(1, &tx);
            payment_indexes(st, height, 1);
            st.scan_cached_blocks(height, 1);
            let positions = fvks
                .clone()
                .map(|fvk| candidate_at(st, height, &fvk).position);
            let current = publication_at(st, height);
            assert!(
                st.wallet_mut()
                    .db_mut()
                    .begin_one_time_recovery(account, current, true)
                    .unwrap()
            );
            drain(st, account, current);
            (height, positions)
        };
        let placed = |st: &State| -> Vec<(Option<u32>, Option<u32>)> {
            rows(
                st.wallet().conn(),
                "SELECT t.mined_height, n.commitment_tree_position FROM ironwood_received_notes n
                 JOIN transactions t ON t.id_tx = n.transaction_id
                 WHERE n.one_time_key_id IS NOT NULL ORDER BY n.action_index",
                [],
            )
        };
        let (height, positions) = mine(&mut st);
        let mut expected: Vec<_> = positions
            .iter()
            .map(|p| (Some(u32::from(height)), Some(*p)))
            .collect();
        expected.sort_by_key(|(_, p)| *p);
        let mut got = placed(&st);
        got.sort_by_key(|(_, p)| *p);
        assert_eq!(got, expected);

        if !enabled {
            st.wallet_mut()
                .db_mut()
                .set_one_time_recovery_enabled(account, false)
                .unwrap();
        }
        st.truncate_to_height(floor);
        // Another payment first moves the transaction's outputs to later positions. It is
        // mined and scanned directly, since `pay` would enable recovery again.
        let other = IronwoodFvk(FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes([3; 32]).unwrap(),
        ));
        let (shifted, _, _) = st.generate_next_block(
            &other,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10_000),
        );
        payment_indexes(&st, shifted, 1);
        st.scan_cached_blocks(shifted, 1);
        assert_eq!(status(st.wallet().db(), account).enabled, enabled);
        let (height, moved) = mine(&mut st);
        assert_eq!(status(st.wallet().db(), account).enabled, enabled);
        assert_ne!(moved, positions);
        let mut expected: Vec<_> = moved
            .iter()
            .map(|p| (Some(u32::from(height)), Some(*p)))
            .collect();
        expected.sort_by_key(|(_, p)| *p);
        let mut got = placed(&st);
        got.sort_by_key(|(_, p)| *p);
        assert_eq!(got, expected, "enabled {enabled}");
        assert_eq!(one_time_notes(&st).len(), 2);
    }
}

/// Direct catch-up skips a used key whose history is complete, so a second payment the
/// directory left out of its history is not read. A correction that adds that payment
/// reads every monitored key once, used ones included, and recovers it automatically.
#[test]
fn a_correction_recovers_a_payment_it_adds_to_a_used_receiver() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key0 = KeyId::new(Purpose::Receive, 0);
    pay_candidate(&mut st, key0);
    let first = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, first, true)
            .unwrap()
    );
    drain(&mut st, account, first);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);

    // The directory omits the second payment, and catch-up does not read the used key.
    pay_candidate(&mut st, key0);
    let omitted = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, omitted, true)
            .unwrap()
    );
    assert!(
        status(st.wallet().db(), account)
            .lookups
            .iter()
            .all(|w| w.work.key != key0)
    );
    drain(&mut st, account, omitted);
    assert_eq!(one_time_notes(&st).len(), 1);

    let corrected = RecoveryPublication {
        history_revision: 1,
        ..omitted
    };
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, corrected, true)
            .unwrap()
    );
    drain(&mut st, account, corrected);
    assert_eq!(one_time_notes(&st), [(100_000, false), (100_000, false)]);
}

/// A correction invalidates a completed manual-only index 4, and a resumed manual search
/// queues it again. Cancelling that search must stop it: the invalidation only holds
/// reservations and never makes a lookup runnable on its own. The hold still applies to the
/// reserved automatic index 0 until its corrected history settles.
#[test]
fn a_cancelled_search_stops_an_invalidated_manual_only_lookup() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let now = clock_now();
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
    let reserved = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, now)
        .unwrap()
        .unwrap();
    assert_eq!(reserved.key_id().index(), 0);

    let corrected = RecoveryPublication {
        history_revision: 1,
        ..publication
    };
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, corrected, true)
            .unwrap()
    );
    assert!(
        matches!(
            st.wallet_mut()
                .db_mut()
                .prepare_receive_reservation(account, now)
                .unwrap(),
            Err(crate::wallet::one_time_ivk::swap::ReservationPolicy::ReceiveHistory)
        ),
        "the corrected reservation waits"
    );
    drain(&mut st, account, corrected);
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, now)
            .unwrap()
            .unwrap()
            .key_id()
            .index(),
        0
    );

    let key4 = KeyId::new(Purpose::Receive, 4);
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, corrected, Some(10))
            .unwrap()
    );
    assert!(
        status(st.wallet().db(), account)
            .lookups
            .iter()
            .any(|w| w.work.key == key4)
    );
    st.wallet_mut()
        .db_mut()
        .cancel_one_time_history(account)
        .unwrap();
    let paused = status(st.wallet().db(), account);
    assert!(paused.lookups.is_empty(), "no requests while paused");
    assert!(paused.witnesses.is_empty());
    assert!(
        st.wallet_mut()
            .db_mut()
            .check_one_time_history(account, corrected, None)
            .unwrap()
    );
    assert!(
        status(st.wallet().db(), account)
            .lookups
            .iter()
            .any(|w| w.work.key == key4)
    );
    drain(&mut st, account, corrected);
    assert!(!status(st.wallet().db(), account).manual.unwrap().active);
}

/// A funded refund key leaves automatic monitoring, both the filter receiver set and direct
/// catch-up, once every local operation on it is conclusive: R0's swap succeeded, so no
/// refund is coming, and R3's expected refund was received and settled. R1's swap ended
/// inconclusively and R2 has no local operation, as after recovering it from a funding memo,
/// so both stay watched. Retiring a key advances the generation, fencing held filter requests.
#[test]
fn conclusive_refund_keys_leave_automatic_monitoring() {
    use zakura_one_time_ivk::swap::{
        Observation,
        OperationStatus::{Active, Terminal},
        ReceiptExpectation,
    };
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let now = clock_now();
    let tip_height = tip(&st).height;
    let refund = |i| KeyId::new(Purpose::Refund, i);
    for i in 0..4 {
        recover(st.wallet_mut().db_mut(), account, refund(i), tip_height);
    }
    let active = Observation {
        status: Active,
        funded: true,
        receipts: vec![],
    };
    for i in [0, 1, 3] {
        observe_with(
            st.wallet_mut().db_mut(),
            account,
            refund(i),
            (&format!("deposit-{i}"), now + 3_600),
            active.clone(),
            now,
        )
        .unwrap();
    }
    let watched = |st: &State| -> (Vec<u64>, Vec<u64>) {
        let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
        let filters = receivers
            .iter()
            .filter(|w| w.key.purpose() == Purpose::Refund)
            .map(|w| w.key.index())
            .collect();
        let owner: i64 = value(
            st.wallet().conn(),
            "SELECT id FROM accounts WHERE uuid = ?1",
            [account.0],
        );
        let ids = crate::wallet::one_time_ivk::restore::queue::direct_keys(
            st.wallet().conn(),
            st.network(),
            owner,
        )
        .unwrap();
        let mut direct: Vec<u64> = ids
            .into_iter()
            .filter_map(|id: i64| {
                let (purpose, index): (u8, Vec<u8>) = row(
                    st.wallet().conn(),
                    "SELECT purpose, key_index FROM ironwood_one_time_keys WHERE id = ?1",
                    [id],
                );
                (purpose == 0).then(|| u64::from_be_bytes(index.try_into().unwrap()))
            })
            .collect();
        direct.sort();
        (filters, direct)
    };
    assert_eq!(watched(&st), (vec![0, 1, 2, 3], vec![0, 1, 2, 3]));

    let (held, _) = st.wallet().db().one_time_receivers(account).unwrap();
    let observe = |st: &mut State, i: u64, status, receipts| {
        st.wallet_mut()
            .db_mut()
            .record_operation_status(
                account,
                &format!("deposit-{i}"),
                None,
                Observation {
                    status,
                    funded: true,
                    receipts,
                },
                now + 60,
            )
            .unwrap();
    };
    observe(&mut st, 0, Terminal(ReceiptExpectation::None), vec![]);
    observe(&mut st, 1, Terminal(ReceiptExpectation::Unknown), vec![]);
    assert_eq!(watched(&st), (vec![1, 2, 3], vec![1, 2, 3]));
    let (current, _) = st.wallet().db().one_time_receivers(account).unwrap();
    assert_ne!(current, held, "retiring R0 fences held filter requests");

    // R3's refund arrives, the provider names it, and recovery settles it.
    let paid = pay_candidate(&mut st, refund(3));
    observe(
        &mut st,
        3,
        Terminal(ReceiptExpectation::Positive(Some(
            Zatoshis::const_from_u64(100_000),
        ))),
        vec![paid.txid],
    );
    assert_eq!(
        watched(&st),
        (vec![1, 2, 3], vec![1, 2, 3]),
        "not yet received"
    );
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert_eq!(watched(&st), (vec![1, 2], vec![1, 2]));
}

/// The refund indexes `account` monitors automatically: in its filter receiver set and in
/// direct catch-up.
fn refunds_watched(st: &State, account: AccountUuid) -> (Vec<u64>, Vec<u64>) {
    let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    let filters = receivers
        .iter()
        .filter(|w| w.key.purpose() == Purpose::Refund)
        .map(|w| w.key.index())
        .collect();
    let conn = st.wallet().conn();
    let owner: i64 = value(conn, "SELECT id FROM accounts WHERE uuid = ?1", [account.0]);
    let ids = crate::wallet::one_time_ivk::restore::queue::direct_keys(conn, st.network(), owner)
        .unwrap();
    let mut direct: Vec<u64> = ids
        .into_iter()
        .filter_map(|id: i64| {
            let (purpose, index): (u8, Vec<u8>) = row(
                conn,
                "SELECT purpose, key_index FROM ironwood_one_time_keys WHERE id = ?1",
                [id],
            );
            (purpose == 0).then(|| u64::from_be_bytes(index.try_into().unwrap()))
        })
        .collect();
    direct.sort();
    (filters, direct)
}

/// Starts recovery at the tip with direct catch-up and drains it, so filters have checked
/// through the tip. Returns that frontier.
fn catch_up(st: &mut State, account: AccountUuid) -> BlockHeight {
    let publication = publication_at(st, tip(st).height);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(st, account, publication);
    status(st.wallet().db(), account)
        .filter_frontier
        .unwrap()
        .height
}

/// Mines and scans one empty block and passes filters over it with no hit.
fn filter_one_block(st: &mut State, account: AccountUuid, frontier: BlockHeight) {
    st.generate_and_scan_empty_blocks(1);
    let (token, _) = st.wallet().db().one_time_receivers(account).unwrap();
    let passed = blocks_above(st, frontier);
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_filters(account, token, 0, &passed, &[])
            .unwrap()
    );
}

/// The memo-only window in blocks is the chain time it spans, so after NU7's 25-second
/// blocks it covers three times as many blocks, and a window across activation counts each
/// side at its own spacing.
#[test]
fn the_memo_refund_window_is_measured_in_chain_time() {
    use crate::wallet::one_time_ivk::restore::queue::{MEMO_REFUND_WINDOW, aged_cutoff};
    use zcash_protocol::zip318::BlockSpacing;
    let window = MEMO_REFUND_WINDOW;
    assert_eq!(window, 8_064, "7 days of 75-second blocks");
    let uniform = BlockSpacing::UNIFORM;
    assert_eq!(aged_cutoff(uniform, window), None);
    assert_eq!(aged_cutoff(uniform, window + 1), Some(0));
    assert_eq!(aged_cutoff(uniform, 100_000), Some(100_000 - window - 1));
    let nu7 = 1_000_000;
    let spacing = BlockSpacing::with_nu7_activation(BlockHeight::from(nu7));
    assert_eq!(aged_cutoff(spacing, nu7 - 1), Some(nu7 - 1 - window - 1));
    assert_eq!(aged_cutoff(spacing, nu7 + 3 * window), Some(nu7 - 1));
    assert_eq!(aged_cutoff(spacing, nu7 + 3 * window + 6), Some(nu7 + 5));
    // A third of the window after activation leaves two thirds before it.
    assert_eq!(
        aged_cutoff(spacing, nu7 + window),
        Some(nu7 - 2 * window / 3 - 1)
    );
}

/// A refund key known only from its funding memo has no local operation, so no provider
/// status can retire it. It leaves automatic monitoring once filters have checked more than
/// the memo-only window past its funding block, which fences held filter requests, and a key
/// already past the window when recovered still has its history read once. A key with a
/// local operation keeps the conclusive-operation rule, and retirement never makes an index
/// issuable again.
#[test]
fn a_memo_only_refund_key_retires_after_its_window() {
    use crate::wallet::one_time_ivk::restore::queue::MEMO_REFUND_WINDOW;
    use zakura_one_time_ivk::swap::{Observation, OperationStatus::Active};
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let frontier = catch_up(&mut st, account);
    let refund = |i| KeyId::new(Purpose::Refund, i);
    let edge = frontier - MEMO_REFUND_WINDOW;
    let db = st.wallet_mut().db_mut();
    recover(db, account, refund(0), edge);
    recover(db, account, refund(1), edge - 1);
    recover(db, account, refund(2), edge - 1);
    let active = Observation {
        status: Active,
        funded: true,
        receipts: vec![],
    };
    let now = clock_now();
    observe_with(
        db,
        account,
        refund(2),
        ("deposit-2", now + 3_600),
        active,
        now,
    )
    .unwrap();
    assert_eq!(refunds_watched(&st, account), (vec![0, 2], vec![0, 2]));
    // R1 was already past the window, so it was never watched, but its history is read.
    let r1 = key_ref(&st.wallet().db().conn, account, refund(1)).unwrap();
    let queued: bool = value(
        st.wallet().conn(),
        "SELECT target_height IS NOT NULL FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
        [r1],
    );
    assert!(queued);

    let (held, _) = st.wallet().db().one_time_receivers(account).unwrap();
    filter_one_block(&mut st, account, frontier);
    assert_eq!(refunds_watched(&st, account), (vec![2], vec![2]));
    let (current, _) = st.wallet().db().one_time_receivers(account).unwrap();
    assert_ne!(current, held, "retiring R0 fences held filter requests");

    let tip = tip(&st).height;
    let next = reserve_refund(st.wallet_mut().db_mut(), account, tip);
    assert_eq!(next.unwrap().unwrap().key_id().index(), 3);
}

/// A refund to a memo-only key after it retired is missed by automatic recovery, as the
/// filters no longer watch it, but an explicit history check still finds it.
#[test]
fn a_refund_to_a_retired_memo_only_key_is_found_by_a_history_check() {
    use crate::wallet::one_time_ivk::restore::queue::MEMO_REFUND_WINDOW;
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let frontier = catch_up(&mut st, account);
    let r0 = KeyId::new(Purpose::Refund, 0);
    recover(
        st.wallet_mut().db_mut(),
        account,
        r0,
        frontier - MEMO_REFUND_WINDOW,
    );
    let frontier = catch_up(&mut st, account);
    filter_one_block(&mut st, account, frontier);
    assert_eq!(refunds_watched(&st, account), (vec![], vec![]));

    let frontier = status(st.wallet().db(), account)
        .filter_frontier
        .unwrap()
        .height;
    pay_candidate(&mut st, r0);
    filter_one_block(&mut st, account, frontier);
    let publication = publication_at(&st, tip(&st).height);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert!(
        one_time_notes(&st).is_empty(),
        "automatic recovery skips R0"
    );

    let db = st.wallet_mut().db_mut();
    assert!(
        db.check_one_time_history(account, publication, None)
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// R0's refund is recovered, then a reorg replaces it with another transaction paying R0,
/// which is recovered and reported. The displaced receipt stays unmined, which kept R0 in
/// repair, and so monitored, forever. Expiry alone does not end that: the replacement chain
/// might hold the transaction, so R0 stays in repair until its history is read past the
/// expiry height. Then filters past the pruning depth beyond it retire R0.
#[test]
fn a_refund_replaced_by_a_reorg_still_retires() {
    use zakura_one_time_ivk::swap::{
        Observation,
        OperationStatus::{Active, Terminal},
        ReceiptExpectation,
    };
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let now = clock_now();
    let r0 = KeyId::new(Purpose::Refund, 0);
    let floor = tip(&st).height;
    recover(st.wallet_mut().db_mut(), account, r0, floor);
    let observe = |st: &mut State, status, receipts, at| {
        let observation = Observation {
            status,
            funded: true,
            receipts,
        };
        let db = st.wallet_mut().db_mut();
        observe_with(db, account, r0, ("deposit-0", now + 3_600), observation, at).unwrap();
    };
    observe(&mut st, Active, vec![], now);
    let displaced = pay_candidate(&mut st, r0);
    catch_up(&mut st, account);

    st.truncate_to_height(floor);
    let replacement = pay_candidate(&mut st, r0);
    assert_ne!(replacement.txid, displaced.txid);
    catch_up(&mut st, account);
    let refund = Terminal(ReceiptExpectation::Positive(Some(
        Zatoshis::const_from_u64(100_000),
    )));
    observe(&mut st, refund, vec![replacement.txid], now + 60);
    let receipts: Vec<(Option<u32>, Vec<u8>)> = rows(
        st.wallet().conn(),
        "SELECT t.mined_height, t.txid FROM ironwood_received_notes n
         JOIN transactions t ON t.id_tx = n.transaction_id
         WHERE n.one_time_key_id IS NOT NULL ORDER BY n.id",
        [],
    );
    assert_eq!(
        receipts,
        [
            (None, displaced.txid.as_ref().to_vec()),
            (
                Some(u32::from(replacement.height)),
                replacement.txid.as_ref().to_vec()
            ),
        ]
    );

    // Enhancement records the displaced transaction's expiry height.
    let expiry = u32::from(displaced.height) + 40;
    exec(
        st.wallet().conn(),
        "UPDATE transactions SET expiry_height = ?1 WHERE txid = ?2",
        rusqlite::params![expiry, displaced.txid.as_ref()],
    );
    let blocks = expiry + crate::PRUNING_DEPTH - u32::from(tip(&st).height);
    st.generate_and_scan_empty_blocks(blocks as usize);
    assert_eq!(
        refunds_watched(&st, account),
        (vec![0], vec![0]),
        "no history was read past the expiry"
    );
    let frontier = catch_up(&mut st, account);
    assert_eq!(u32::from(frontier), expiry + crate::PRUNING_DEPTH);
    assert_eq!(refunds_watched(&st, account), (vec![], vec![]));
}

/// A manual check finds a payment to a retired memo-only key, and its candidate waits for
/// a witness, which returns the key to monitoring. That advances the generation, so a
/// filter request captured without the key cannot commit past blocks that may pay it again,
/// and the key's history since its earlier completed read is queued automatically.
#[test]
fn a_candidate_that_returns_a_retired_key_to_monitoring_fences_held_filters() {
    use crate::wallet::one_time_ivk::restore::queue::MEMO_REFUND_WINDOW;
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let frontier = catch_up(&mut st, account);
    let r0 = KeyId::new(Purpose::Refund, 0);
    let db = st.wallet_mut().db_mut();
    recover(db, account, r0, frontier - MEMO_REFUND_WINDOW);
    let frontier = catch_up(&mut st, account);
    filter_one_block(&mut st, account, frontier);
    assert_eq!(refunds_watched(&st, account), (vec![], vec![]));

    let frontier = status(st.wallet().db(), account)
        .filter_frontier
        .unwrap()
        .height;
    pay_candidate(&mut st, r0);
    let publication = publication_at(&st, tip(&st).height);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.check_one_time_history(account, publication, None)
            .unwrap()
    );
    let (held, _) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(answer_lookup(&mut st, account, publication));
    assert_eq!(candidates(&st), 1, "the payment waits for its witness");
    assert_eq!(refunds_watched(&st, account), (vec![0], vec![0]));

    let passed = blocks_above(&st, frontier);
    let db = st.wallet_mut().db_mut();
    assert!(
        !db.record_one_time_filters(account, held, 0, &passed, &[])
            .unwrap(),
        "a request captured without R0 cannot commit"
    );
    let id = key_ref(&st.wallet().db().conn, account, r0).unwrap();
    let (target, reasons): (Option<u32>, u8) = row(
        st.wallet().conn(),
        "SELECT target_height, reasons FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
        [id],
    );
    assert!(target >= Some(u32::from(tip(&st).height)));
    assert_ne!(reasons & 1, 0, "R0's history is queued automatically");
}

/// Recording a first local operation on a retired memo-only key replaces the memo-only
/// rule with the operation rule, which returns it to monitoring and fences held filters.
#[test]
fn a_first_operation_on_a_retired_memo_only_key_fences_held_filters() {
    use crate::wallet::one_time_ivk::restore::queue::MEMO_REFUND_WINDOW;
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let frontier = catch_up(&mut st, account);
    let r0 = KeyId::new(Purpose::Refund, 0);
    let db = st.wallet_mut().db_mut();
    recover(db, account, r0, frontier - MEMO_REFUND_WINDOW);
    let frontier = catch_up(&mut st, account);
    filter_one_block(&mut st, account, frontier);
    assert_eq!(refunds_watched(&st, account), (vec![], vec![]));

    let (held, _) = st.wallet().db().one_time_receivers(account).unwrap();
    let deposit = p2pkh(7).encode(st.network());
    let now = clock_now();
    let db = st.wallet_mut().db_mut();
    db.record_refund_operation(account, 0, &deposit, now + 3_600, now)
        .unwrap();
    assert_eq!(refunds_watched(&st, account), (vec![0], vec![0]));
    let (current, _) = st.wallet().db().one_time_receivers(account).unwrap();
    assert_ne!(current, held);
}

/// As in [`a_refund_replaced_by_a_reorg_still_retires`], but the displaced receipt's expiry
/// height is unknown until its raw transaction is stored. Storing it retires R0, so it
/// advances the generation, fencing held filter requests.
#[test]
fn storing_a_displaced_receipts_raw_transaction_fences_its_retirement() {
    use zakura_one_time_ivk::swap::{
        Observation,
        OperationStatus::{Active, Terminal},
        ReceiptExpectation,
    };
    use zcash_client_backend::data_api::wallet::decrypt_and_store_transaction;
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let network = *st.network();
    let now = clock_now();
    let r0 = KeyId::new(Purpose::Refund, 0);
    let floor = tip(&st).height;
    let key = recover(st.wallet_mut().db_mut(), account, r0, floor);
    let observe = |st: &mut State, status, receipts, at| {
        let observation = Observation {
            status,
            funded: true,
            receipts,
        };
        let db = st.wallet_mut().db_mut();
        observe_with(db, account, r0, ("deposit-0", now + 3_600), observation, at).unwrap();
    };
    observe(&mut st, Active, vec![], now);
    let displaced = external_payment(key.receiver(), &zcash_protocol::memo::MemoBytes::empty());
    let (height, _) = st.generate_next_block_from_tx(1, &displaced);
    payment_indexes(&st, height, 1);
    st.scan_cached_blocks(height, 1);
    catch_up(&mut st, account);
    assert_eq!(one_time_notes(&st), [(50_000, false)]);

    st.truncate_to_height(floor);
    let replacement = pay_candidate(&mut st, r0);
    catch_up(&mut st, account);
    let refund = Terminal(ReceiptExpectation::Positive(Some(
        Zatoshis::const_from_u64(100_000),
    )));
    observe(&mut st, refund, vec![replacement.txid], now + 60);
    let expiry = u32::from(displaced.expiry_height());
    let blocks = expiry + crate::PRUNING_DEPTH - u32::from(tip(&st).height);
    st.generate_and_scan_empty_blocks(blocks as usize);
    catch_up(&mut st, account);
    assert_eq!(
        refunds_watched(&st, account),
        (vec![0], vec![0]),
        "the expiry height is unknown"
    );

    let (held, _) = st.wallet().db().one_time_receivers(account).unwrap();
    decrypt_and_store_transaction(&network, st.wallet_mut(), &displaced, None).unwrap();
    assert_eq!(refunds_watched(&st, account), (vec![], vec![]));
    let (current, _) = st.wallet().db().one_time_receivers(account).unwrap();
    assert_ne!(current, held, "retiring R0 fences held filter requests");
}

/// R0's empty history is checked through the tip and a "no refund" status retires it. A
/// refund then reaches R0 while rolling filters, no longer watching it, pass that block. A
/// newer status reports the refund, returning R0 to monitoring, and that alone queues its
/// skipped history: recovery finds the refund through rolling filters, with no direct
/// catch-up.
#[test]
fn a_refund_paid_while_its_key_was_retired_is_found_after_a_newer_status() {
    use zakura_one_time_ivk::swap::{
        Observation,
        OperationStatus::{Active, Terminal},
        ReceiptExpectation,
    };
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let now = clock_now();
    let r0 = KeyId::new(Purpose::Refund, 0);
    let funded_at = tip(&st).height;
    recover(st.wallet_mut().db_mut(), account, r0, funded_at);
    let observe = |st: &mut State, status, at| {
        observe_with(
            st.wallet_mut().db_mut(),
            account,
            r0,
            ("deposit-0", now + 3_600),
            Observation {
                status,
                funded: true,
                receipts: vec![],
            },
            at,
        )
        .unwrap();
    };
    observe(&mut st, Active, now);
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    observe(&mut st, Terminal(ReceiptExpectation::None), now + 60);
    let watched = |st: &State| {
        let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
        receivers.iter().any(|w| w.key == r0)
    };
    assert!(!watched(&st), "the no-refund status retires R0");

    // The refund lands, and filters without R0 pass its block and one more.
    let frontier = status(st.wallet().db(), account)
        .filter_frontier
        .unwrap()
        .height;
    pay_candidate(&mut st, r0);
    st.generate_and_scan_empty_blocks(1);
    let (token, _) = st.wallet().db().one_time_receivers(account).unwrap();
    let passed = blocks_above(&st, frontier);
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_filters(account, token, 0, &passed, &[])
            .unwrap()
    );

    observe(
        &mut st,
        Terminal(ReceiptExpectation::Positive(Some(
            Zatoshis::const_from_u64(100_000),
        ))),
        now + 120,
    );
    assert!(watched(&st), "the newer status returns R0 to monitoring");
    let current = publication_at(&st, tip(&st).height);
    drain(&mut st, account, current);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// Registers `key` from `from`, starts recovery at the tip without direct catch-up, and
/// answers `key`'s lookup with `payments` as one complete page.
fn answer_with(
    st: &mut State,
    key: KeyId,
    from: BlockHeight,
    payments: &[DirectoryPayment],
) -> Result<bool, SqliteClientError> {
    let account = st.test_account().unwrap().id();
    recover(st.wallet_mut().db_mut(), account, key, from);
    let publication = publication_at(st, tip(st).height);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    let work = work_of(st, key);
    let receiver = work.work.receiver;
    let total = payments.len() as u32;
    let page = whole(
        publication,
        (0..)
            .zip(payments)
            .map(|(page, payment)| DirectoryRecord {
                receiver,
                page,
                total,
                payment: payment.clone(),
                ordinal: page,
            })
            .collect(),
    );
    let db = st.wallet_mut().db_mut();
    db.record_one_time_lookup(account, &work, &page, clock_now())
}

/// The number of queued payment candidates.
fn candidates(st: &State) -> u32 {
    value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_payment_recovery",
        [],
    )
}

/// A late payment already admitted under one action of its transaction is redundant when
/// the directory later names another action for the same note: its path dequeues it, and
/// the stored receipt keeps its label.
#[test]
fn a_late_payment_already_admitted_under_another_action_is_dequeued() {
    let (mut st, candidate, _) = late_fixture();
    let account = st.test_account().unwrap().id();
    send_witness(&mut st, key8(), &candidate);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    let label = |st: &State| -> Vec<(Vec<u8>, u32)> {
        rows(
            st_conn(st),
            "SELECT t.txid, n.action_index FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id WHERE n.one_time_key_id IS NOT NULL",
            [],
        )
    };
    let before = label(&st);
    exec(
        st.wallet().conn(),
        "INSERT INTO ironwood_one_time_payment_recovery
             (one_time_key_id, txid, action_index, height, block_hash, tx_index, position,
              encrypted_note, payments, witnesses, ordinal)
         SELECT k.id, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?9, ?10, 0 FROM ironwood_one_time_keys k
         WHERE k.purpose = 1 AND k.key_index = ?8",
        rusqlite::params![
            candidate.txid.as_ref(),
            candidate.action_index + 1,
            u32::from(candidate.height),
            candidate.block_hash.0,
            candidate.tx_index,
            candidate.position,
            candidate.encrypted_note.to_bytes().to_vec(),
            key8().index().to_be_bytes(),
            [1u8; 32],
            [7u8; 32]
        ],
    );
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_lookups SET reasons = 1, target_height = ?1, read_complete = 0
         WHERE one_time_key_id = (SELECT id FROM ironwood_one_time_keys
             WHERE purpose = 1 AND key_index = ?2)",
        rusqlite::params![u32::from(tip(&st).height), key8().index().to_be_bytes()],
    );
    let claimed = PendingPayment {
        action_index: candidate.action_index + 1,
        ..candidate.clone()
    };
    send_witness(&mut st, key8(), &claimed);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert_eq!(candidates(&st), 0);
    assert_eq!(label(&st), before);
    let _ = account;
}

/// `st`'s wallet connection, for closures that cannot borrow `st` mutably.
fn st_conn(st: &State) -> &Connection {
    st.wallet().conn()
}

/// A publication whose last block or tree size differs from the wallet's is refused: it
/// changes no recovery state, so it sets no filter frontier, and cannot answer a lookup the
/// wallet holds, which stays due. A publication matching the chain is taken.
#[test]
fn a_publication_off_the_wallets_chain_is_rejected() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let good = publication_at(&st, tip(&st).height);
    let before = status(st.wallet().db(), account);
    let mut off_chain = good;
    off_chain.end.hash = [9; 32];
    let mut other_tree = good;
    other_tree.end.tree_size += 1;
    for bad in [off_chain, other_tree] {
        assert!(
            !st.wallet_mut()
                .db_mut()
                .begin_one_time_recovery(account, bad, true)
                .unwrap()
        );
        assert_eq!(status(st.wallet().db(), account), before);
        assert!(before.filter_frontier.is_none());
    }
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, good, true)
            .unwrap()
    );
    let held = status(st.wallet().db(), account).lookups[0].clone();
    let page = whole(off_chain, vec![]);
    assert!(
        !st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &held, &page, clock_now())
            .unwrap()
    );
    assert_eq!(status(st.wallet().db(), account).lookups[0], held);
}

/// A page refused for a bad record keeps nothing it would have queued before that record,
/// and its lookup stays due from the start, so the corrected page is taken.
#[test]
fn a_refused_page_queues_nothing() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    let good = directory_answer(&candidate);
    let beyond = DirectoryPayment {
        height: u32::from(tip(&st).height) + 1,
        position: good.position + 1,
        ..good.clone()
    };
    assert!(answer_with(&mut st, key8(), candidate.height, &[good.clone(), beyond]).is_err());
    assert_eq!(candidates(&st), 0);
    let (due, last): (bool, Option<Vec<u8>>) = row(
        st.wallet().conn(),
        "SELECT target_height IS NOT NULL AND read_complete = 0, last_record
         FROM ironwood_one_time_lookups WHERE one_time_key_id =
             (SELECT id FROM ironwood_one_time_keys WHERE purpose = 1 AND key_index = ?1)",
        [key8().index().to_be_bytes()],
    );
    assert!(due && last.is_none());
    assert!(answer_with(&mut st, key8(), candidate.height, &[good]).unwrap());
    assert_eq!(status(st.wallet().db(), account).witnesses.len(), 1);
}

/// A record outside the publication, or one the chain contradicts, refuses the whole page
/// and queues nothing: below the publication's start, at or past its tree size, at
/// transaction index 0, which only a coinbase holds, or in a block other than the wallet's
/// at its height. The true record is then taken.
#[test]
fn a_page_with_an_out_of_range_or_off_chain_record_is_refused() {
    let mut st = scanned_wallet();
    let candidate = pay_candidate(&mut st, key8());
    let good = directory_answer(&candidate);
    let publication = publication_at(&st, tip(&st).height);
    let refused = [
        DirectoryPayment {
            height: u32::from(publication.start_height) - 1,
            ..good.clone()
        },
        DirectoryPayment {
            position: publication.end.tree_size,
            ..good.clone()
        },
        DirectoryPayment {
            tx_index: 0,
            ..good.clone()
        },
        DirectoryPayment {
            block_hash: [7; 32],
            ..good.clone()
        },
    ];
    for (i, record) in refused.iter().enumerate() {
        assert!(
            matches!(
                answer_with(&mut st, key8(), candidate.height, &[record.clone()]),
                Err(SqliteClientError::InvalidOneTimeIvkInput(_))
            ),
            "record {i}"
        );
        assert_eq!(candidates(&st), 0, "record {i}");
    }
    assert!(answer_with(&mut st, key8(), candidate.height, &[good]).unwrap());
    assert_eq!(candidates(&st), 1);
}

/// A rewind below a payment still waiting for its path drops it, since its block may be
/// gone, and recovery over the replacement chain finds it again at its mined height.
#[test]
fn a_rewind_below_a_waiting_payment_drops_it_until_recovery_finds_it_again() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key0 = KeyId::new(Purpose::Receive, 0);
    let candidate = pay_candidate(&mut st, key0);
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    answer_lookups(&mut st, account, publication);
    assert_eq!(candidates(&st), 1);
    assert!(one_time_notes(&st).is_empty());
    let end = tip(&st).height;
    st.truncate_to_height_retaining_cache(candidate.height - 1);
    assert_eq!(candidates(&st), 0);
    reopen(&mut st);
    st.scan_cached_blocks(candidate.height, (end - candidate.height + 1) as usize);
    let publication = publication_at(&st, end);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
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
}

/// An unknown account is an error, not an account with nothing to recover.
#[test]
fn an_unknown_accounts_recovery_is_an_error() {
    let mut st = scanned_wallet();
    let unknown = crate::AccountUuid::from_uuid(uuid::Uuid::nil());
    let publication = publication_at(&st, tip(&st).height);
    let unknown_account =
        |r: Result<(), SqliteClientError>| matches!(r, Err(SqliteClientError::AccountUnknown));
    let token = status(st.wallet().db(), st.test_account().unwrap().id()).token;
    let db = st.wallet_mut().db_mut();
    assert!(unknown_account(
        db.one_time_recovery(unknown, clock_now()).map(drop)
    ));
    assert!(unknown_account(db.one_time_receivers(unknown).map(drop)));
    assert!(unknown_account(
        db.begin_one_time_recovery(unknown, publication, true)
            .map(drop)
    ));
    let work = LookupWork {
        token,
        work: zcash_client_backend::data_api::one_time_ivk::restore::DiscoveryWork {
            key: key8(),
            receiver: [0; 43],
        },
        from: publication.start_height,
        through: publication.end.height,
        cursor: None,
    };
    let db = st.wallet_mut().db_mut();
    assert!(unknown_account(db.defer_one_time_lookup(
        unknown,
        &work,
        clock_now()
    )));
}

/// A publication above the wallet's scanned chain, one older than the correction the
/// account already took, or one starting after Ironwood activation, is refused.
#[test]
fn stale_future_and_partial_publications_are_refused() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let begin = |st: &mut State, publication: RecoveryPublication| {
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    };

    let (future, _) = st.generate_empty_block();
    let ahead = publication_at(&st, future);
    assert!(!begin(&mut st, ahead));
    st.scan_cached_blocks(future, 1);
    assert!(begin(&mut st, ahead));

    let corrected = RecoveryPublication {
        history_revision: 1,
        ..ahead
    };
    assert!(begin(&mut st, corrected));
    assert!(!begin(&mut st, ahead), "an older correction is stale");

    let activation = st
        .network()
        .activation_height(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
        .unwrap();
    let late_start = RecoveryPublication {
        start_height: activation + 1,
        ..corrected
    };
    assert!(!begin(&mut st, late_start));
    let from_activation = RecoveryPublication {
        start_height: activation,
        ..corrected
    };
    assert!(begin(&mut st, from_activation));
}

/// A payment before the account's birthday must precede the birthday block's first
/// Ironwood output. A genuine one marks its key paid before the birthday, untracked like
/// any note there. A later note a directory claims at a height before the birthday is
/// refused and dropped, and marks nothing.
#[test]
fn a_payment_claimed_before_the_birthday_must_precede_the_birthday_block() {
    for genuine in [true, false] {
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        let mut candidate = pay_candidate(&mut st, key8());
        st.generate_and_scan_empty_blocks(1);
        let birthday = if genuine {
            u32::from(candidate.height) + 1
        } else {
            let hash: Vec<u8> = value(
                st.wallet().conn(),
                "SELECT hash FROM blocks WHERE height = ?1",
                [u32::from(candidate.height) - 1],
            );
            candidate.height = candidate.height - 1;
            candidate.block_hash = BlockHash(hash.try_into().unwrap());
            u32::from(candidate.height) + 1
        };
        exec(
            st.wallet().conn(),
            "UPDATE accounts SET birthday_height = ?1",
            [birthday],
        );
        let publication = queue_late(&mut st, key8(), &candidate);
        send_witness(&mut st, key8(), &candidate);
        drain(&mut st, account, publication);
        assert!(one_time_notes(&st).is_empty());
        assert_eq!(candidates(&st), 0);
        let marked: Option<u32> = value(
            st.wallet().conn(),
            "SELECT prebirthday_height FROM ironwood_one_time_keys
             WHERE purpose = 1 AND key_index = ?1",
            [key8().index().to_be_bytes()],
        );
        assert_eq!(marked, genuine.then_some(birthday), "genuine {genuine}");
    }
}

/// A refund key with several local operations retires only once every one is conclusive,
/// and an expected refund is settled by the sum of the receipts the provider reported for
/// it, not by any one of them.
#[test]
fn a_refund_key_retires_only_once_every_operation_settles() {
    use zakura_one_time_ivk::swap::{
        Observation,
        OperationStatus::{Active, Terminal},
        ReceiptExpectation,
    };
    let refund = |i| KeyId::new(Purpose::Refund, i);
    let watched = |st: &State, i: u64| -> bool {
        let account = st.test_account().unwrap().id();
        let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
        receivers.iter().any(|w| w.key == refund(i))
    };
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let now = clock_now();
    let height = tip(&st).height;
    for i in 0..2 {
        recover(st.wallet_mut().db_mut(), account, refund(i), height);
    }
    let observe = |st: &mut State, i: u64, deposit: &str, status, receipts, at| {
        observe_with(
            st.wallet_mut().db_mut(),
            account,
            refund(i),
            (deposit, now + 3_600),
            Observation {
                status,
                funded: true,
                receipts,
            },
            at,
        )
        .unwrap();
    };
    // R0 has two swaps: one ending with no refund leaves it watched for the other.
    observe(&mut st, 0, "a", Active, vec![], now);
    observe(&mut st, 0, "b", Active, vec![], now);
    observe(
        &mut st,
        0,
        "a",
        Terminal(ReceiptExpectation::None),
        vec![],
        now + 60,
    );
    assert!(watched(&st, 0), "the other swap may still refund");
    observe(
        &mut st,
        0,
        "b",
        Terminal(ReceiptExpectation::None),
        vec![],
        now + 60,
    );
    assert!(!watched(&st, 0));

    // R1 expects 150,000 and receives two reported refunds of 100,000.
    let first = pay_candidate(&mut st, refund(1));
    let second = pay_candidate(&mut st, refund(1));
    let owed = Terminal(ReceiptExpectation::Positive(Some(
        Zatoshis::const_from_u64(150_000),
    )));
    observe(&mut st, 1, "c", owed, vec![first.txid], now);
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false), (100_000, false)]);
    assert!(watched(&st, 1), "one reported refund falls short");
    observe(&mut st, 1, "c", owed, vec![second.txid], now + 60);
    assert!(!watched(&st, 1));
}

/// A witness whose advertised construction size the wallet's own tree contradicts is
/// refused before any of its siblings is used. A service that binds the wallet's next,
/// commitment-free block but claims 65,536 leaves would otherwise pass a payment at its
/// last leaf off as final, and the empty sibling after it, which matches the accepted root,
/// would be stored as a complete leaf that the next real commitment conflicts with. A
/// provisional witness claiming one leaf too many is refused the same way. In both cases
/// the payment stays pending, the scan continues over the next commitment, and the honest
/// witness admits the payment.
#[test]
fn a_witness_with_a_wrong_construction_size_is_refused() {
    for inflated in [true, false] {
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        let candidate = pay_candidate(&mut st, key8());
        st.generate_and_scan_empty_blocks(1);
        queue_late(&mut st, key8(), &candidate);
        let request = request_for(&st, key8(), &candidate);
        let honest = publication_at(&st, tip(&st).height).end;
        assert_eq!(honest.tree_size, u64::from(candidate.position) + 1);
        let claimed = PublicationEnd {
            tree_size: if inflated {
                1 << 16
            } else {
                honest.tree_size + 1
            },
            ..honest
        };
        let forged = answer(&request, &witness_at(&st, candidate.position), claimed);
        let token = status(st.wallet().db(), account).token;
        assert!(
            st.wallet_mut()
                .db_mut()
                .record_one_time_witness(account, token, request, &forged, clock_now())
                .unwrap()
        );
        assert!(one_time_notes(&st).is_empty(), "inflated {inflated}");
        let pending: u32 = value(
            st.wallet().conn(),
            "SELECT COUNT(*) FROM ironwood_one_time_payment_recovery",
            [],
        );
        assert_eq!(pending, 1, "inflated {inflated}");
        // The next real commitment lands where the forged path claimed an empty leaf.
        foreign_blocks(&mut st, 1);
        exec(
            st.wallet().conn(),
            "UPDATE ironwood_one_time_lookups SET next_attempt_at = 0",
            [],
        );
        let publication = publication_at(&st, tip(&st).height);
        drain(&mut st, account, publication);
        assert_eq!(
            one_time_notes(&st),
            [(100_000, false)],
            "inflated {inflated}"
        );
    }
}

/// A final witness is checked at the scanned tip whatever its construction height. The
/// payment's shard is full in the wallet's own tree, and the companion was built at a quiet
/// block the scan has not reached, so the wallet admits the payment at once rather than
/// waiting for the scan to reach that block.
#[test]
fn a_final_witness_built_ahead_of_the_scanned_tip_is_admitted() {
    let prefix = distinct_leaves(65_534);
    let mut st = wallet_after_leaves(&prefix);
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    assert_eq!(candidate.position, 65_534);
    // Leaf 65,535 completes shard zero and 65,536 starts shard one.
    foreign_blocks(&mut st, 2);
    queue_late(&mut st, key8(), &candidate);
    let scanned = tip(&st).height;
    for _ in 0..3 {
        st.generate_empty_block();
    }
    let ahead = scanned + 3;
    let request = request_for(&st, key8(), &candidate);
    let path = path_after(&st, &prefix, candidate.position);
    let complete = answer(&request, &path, publication_at(&st, ahead).end);
    let token = status(st.wallet().db(), account).token;
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_witness(account, token, request, &complete, clock_now())
            .unwrap()
    );
    assert_eq!(tip(&st).height, scanned);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// The wallet refuses a lookup step whose coverage or continuation does not follow from
/// what it read, and keeps its progress: one ending the request after page 0 of 2, one
/// whose cursor jumps from shard 0 to shard 2 past shard 1, and one claiming coverage
/// through the inventory's end while still reading shard 1. The one valid step from the
/// same position is taken.
#[test]
fn malformed_lookup_steps_cannot_advance_coverage() {
    for shape in ["early end", "jump", "over-claim"] {
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        pay_candidate(&mut st, key8());
        pay_candidate(&mut st, key8());
        let height = tip(&st).height;
        recover(st.wallet_mut().db_mut(), account, key8(), height - 1);
        let publication = publication_at(&st, height);
        assert!(
            st.wallet_mut()
                .db_mut()
                .begin_one_time_recovery(account, publication, false)
                .unwrap()
        );
        let work = work_of(&st, key8());
        let fvk = get_key(st.wallet().db(), account, key8()).unwrap().unwrap();
        let records = oracle(&st, work.work.receiver, fvk.full_viewing_key());
        assert_eq!(records.len(), 2);
        let end = publication.end.height;
        let shard = |index: u32, start_height, end_height, excluded| StepShard {
            index,
            start_height,
            end_height,
            segments: 1,
            excluded,
        };
        let cursor = |shard, last| {
            Some(LookupCursor {
                inventory: publication.id,
                shard,
                segment: 0,
                last,
            })
        };
        let first = Some(records[0].clone());
        let (malformed, valid) = match shape {
            "early end" => (
                whole(publication, vec![records[0].clone()]),
                LookupPage {
                    checked_through: None,
                    next: cursor(0, first),
                    ..whole(publication, vec![records[0].clone()])
                },
            ),
            "jump" => {
                let read = LookupPage {
                    inventory_shards: 3,
                    shards: vec![shard(0, publication.start_height, end - 2, false)],
                    records: vec![],
                    checked_through: Some(end - 2),
                    next: cursor(2, None),
                    ..whole(publication, vec![])
                };
                let valid = LookupPage {
                    next: cursor(1, None),
                    ..read.clone()
                };
                (read, valid)
            }
            _ => {
                let reading = LookupPage {
                    inventory_shards: 3,
                    shards: vec![
                        shard(0, publication.start_height, end - 2, true),
                        shard(1, end - 1, end - 1, false),
                    ],
                    segment: Some(SegmentRef {
                        shard: 1,
                        ..segment_ref(publication)
                    }),
                    records: vec![records[0].clone()],
                    checked_through: Some(end),
                    next: cursor(1, first),
                    ..whole(publication, vec![])
                };
                let valid = LookupPage {
                    checked_through: Some(end - 2),
                    ..reading.clone()
                };
                (reading, valid)
            }
        };
        let id = key_ref(&st.wallet().db().conn, account, key8()).unwrap();
        let progress = |st: &State| -> (Option<u32>, Option<Vec<u8>>, Option<u32>, bool) {
            row(
                st.wallet().conn(),
                "SELECT checked_height, inventory, done_height, read_complete
                 FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
                [id],
            )
        };
        let before = progress(&st);
        assert!(
            matches!(
                st.wallet_mut().db_mut().record_one_time_lookup(
                    account,
                    &work,
                    &malformed,
                    clock_now()
                ),
                Err(SqliteClientError::InvalidOneTimeIvkInput(_))
            ),
            "{shape}"
        );
        assert_eq!(progress(&st), before, "{shape}");
        assert!(
            st.wallet_mut()
                .db_mut()
                .record_one_time_lookup(account, &work, &valid, clock_now())
                .unwrap(),
            "{shape}"
        );
    }
}

/// Answers due lookups as a two-shard inventory whose sealed shard 0 ends at `split` and
/// whose recent shard 1 runs to the publication's end, the way the network step reads it:
/// from the shard reaching the request's first unchecked height, each shard's records
/// numbered within it. Witnesses are answered as `drain` answers them.
fn drain_sharded(
    st: &mut State,
    account: AccountUuid,
    publication: RecoveryPublication,
    split: BlockHeight,
) {
    let ends = [split, publication.end.height];
    for _ in 0..256 {
        let state = status(st.wallet().db(), account);
        if let Some(work) = state.lookups.first() {
            let shard = match &work.cursor {
                Some(c) if c.inventory == publication.id => c.shard,
                _ => u32::from(work.from > split),
            };
            let fvk = get_key(st.wallet().db(), account, work.work.key)
                .unwrap()
                .unwrap();
            let lower = if shard == 0 { 0 } else { u32::from(split) + 1 };
            let upper = u32::from(ends[shard as usize]);
            let mut records: Vec<DirectoryRecord> =
                oracle(st, work.work.receiver, fvk.full_viewing_key())
                    .into_iter()
                    .filter(|r| (lower..=upper).contains(&r.payment.height))
                    .collect();
            let total = records.len() as u32;
            for (page, record) in (0..).zip(records.iter_mut()) {
                (record.page, record.total, record.ordinal) = (page, total, page);
            }
            let page = LookupPage {
                publication,
                inventory_shards: 2,
                shards: vec![StepShard {
                    index: shard,
                    start_height: if shard == 0 {
                        publication.start_height
                    } else {
                        split + 1
                    },
                    end_height: ends[shard as usize],
                    segments: 1,
                    excluded: false,
                }],
                segment: Some(SegmentRef {
                    shard,
                    ..segment_ref(publication)
                }),
                records,
                checked_through: Some(ends[shard as usize]),
                next: (shard == 0).then(|| LookupCursor {
                    inventory: publication.id,
                    shard: 1,
                    segment: 0,
                    last: None,
                }),
            };
            assert!(
                st.wallet_mut()
                    .db_mut()
                    .record_one_time_lookup(account, work, &page, clock_now())
                    .unwrap()
            );
            continue;
        }
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

/// A genuine receipt admitted under a wrong label is disputed after a status update moved
/// that label's transaction to a later height. The true record lies in a sealed shard
/// ending before that height, so the repair reads the key's history again from
/// activation, not from the label's mutable height, and the receipt moves to its true
/// transaction with the dispute cleared.
#[test]
fn a_dispute_after_its_label_moved_rereads_the_whole_history() {
    use zcash_client_backend::data_api::wallet::decrypt_and_store_transaction;
    let Mislabeled {
        mut st,
        candidate,
        forged,
        wrong,
    } = mislabeled(Mislabel::OtherTransaction);
    let account = st.test_account().unwrap().id();
    let network = *st.network();
    let [(note, _, false)] = receipts(&st)[..] else {
        panic!("one receipt under the wrong label");
    };
    st.generate_and_scan_empty_blocks(3);
    // A later mined status for the label's transaction moves it, as status updates do for
    // a transaction the wallet does not hold.
    exec(
        st.wallet().conn(),
        "UPDATE transactions SET mined_height = ?2, block = ?2 WHERE txid = ?1",
        rusqlite::params![forged.txid.as_ref(), u32::from(tip(&st).height)],
    );
    decrypt_and_store_transaction(&network, st.wallet_mut(), &wrong, None).unwrap();
    assert_eq!(receipts(&st), [(note, forged.txid.as_ref().to_vec(), true)]);
    let publication = publication_at(&st, tip(&st).height);
    drain_sharded(&mut st, account, publication, candidate.height);
    assert_eq!(
        receipts(&st),
        [(note, candidate.txid.as_ref().to_vec(), false)]
    );
}

/// A fresh request, and one whose cursor names a replaced inventory, must start at the shard
/// holding its first unchecked height. A step that visits only the last shard, excluded by
/// its filter, and claims the history complete would skip the shards before it, so the
/// wallet refuses it and keeps its progress, in both cases.
#[test]
fn a_step_that_skips_the_required_shards_is_refused() {
    for replaced in [false, true] {
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        pay_candidate(&mut st, key8());
        st.generate_and_scan_empty_blocks(3);
        let height = tip(&st).height;
        recover(st.wallet_mut().db_mut(), account, key8(), height - 1);
        let publication = publication_at(&st, height);
        assert!(
            st.wallet_mut()
                .db_mut()
                .begin_one_time_recovery(account, publication, false)
                .unwrap()
        );
        let end = publication.end.height;
        let shard = |index: u32, start_height, end_height, excluded| StepShard {
            index,
            start_height,
            end_height,
            segments: 1,
            excluded,
        };
        let mut work = work_of(&st, key8());
        let mut current = publication;
        if replaced {
            // The first shard is excluded under one inventory, leaving a cursor there.
            let first = LookupPage {
                inventory_shards: 3,
                shards: vec![shard(0, publication.start_height, end - 2, true)],
                segment: None,
                records: vec![],
                checked_through: Some(end - 2),
                next: Some(LookupCursor {
                    inventory: publication.id,
                    shard: 1,
                    segment: 0,
                    last: None,
                }),
                ..whole(publication, vec![])
            };
            assert!(
                st.wallet_mut()
                    .db_mut()
                    .record_one_time_lookup(account, &work, &first, clock_now())
                    .unwrap()
            );
            // The saved position: shard 1 of that inventory, from the height after shard 0.
            work = LookupWork {
                from: end - 1,
                cursor: Some(LookupCursor {
                    inventory: publication.id,
                    shard: 1,
                    segment: 0,
                    last: None,
                }),
                ..work
            };
            current = RecoveryPublication {
                id: [0xb2; 32],
                ..publication
            };
        }
        let id = key_ref(&st.wallet().db().conn, account, key8()).unwrap();
        let progress = |st: &State| -> (Option<u32>, Option<Vec<u8>>, Option<u32>, bool) {
            row(
                st.wallet().conn(),
                "SELECT checked_height, inventory, done_height, read_complete
                 FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
                [id],
            )
        };
        let before = progress(&st);
        let skipping = LookupPage {
            publication: current,
            inventory_shards: 3,
            shards: vec![shard(2, end, end, true)],
            segment: None,
            records: vec![],
            checked_through: Some(end),
            next: None,
        };
        assert!(
            matches!(
                st.wallet_mut().db_mut().record_one_time_lookup(
                    account,
                    &work,
                    &skipping,
                    clock_now()
                ),
                Err(SqliteClientError::InvalidOneTimeIvkInput(_))
            ),
            "replaced {replaced}"
        );
        assert_eq!(progress(&st), before, "replaced {replaced}");
    }
}

/// Every scan batch looks for deferred raw receipt checks. The query starts from that
/// queue, which a wallet without one-time state never fills, so its cost does not grow with
/// the wallet's transaction history.
#[test]
fn the_deferred_receipt_check_starts_from_its_queue() {
    let st = scanned_wallet();
    let plan: Vec<String> = st
        .wallet()
        .conn()
        .prepare(&format!(
            "EXPLAIN QUERY PLAN {}",
            crate::wallet::one_time_ivk::restore::queue::DEFERRED_RECEIPTS
        ))
        .unwrap()
        .query_map([], |r| r.get(3))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(plan[0].starts_with("SCAN u"), "{plan:?}");
    assert!(plan[1].starts_with("SEARCH t"), "{plan:?}");
}

/// An account that never enabled one-time recovery gains no progress row from any public
/// one-time call: reads, pausing, recovery steps, history checks, upgrade reports and every
/// swap call report disabled, refuse or do nothing, so scanning does none of the
/// per-account recovery work. View-only accounts with no Orchard key, one imported from a
/// Sapling-only key and one from an incoming viewing key, read and pause as disabled too,
/// and the calls that would issue keys refuse them. Enabling, pausing and enabling again
/// still behave as before.
#[test]
fn a_never_enabled_account_reads_as_disabled_without_state() {
    use zcash_client_backend::data_api::{
        Account as _, AccountBirthday, AccountPurpose, AccountSource, chain::ChainState,
    };
    use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
    let mut st = restored_wallet();
    let network = *st.network();
    let rows = |st: &State| -> u32 {
        value(
            st.wallet().conn(),
            "SELECT COUNT(*) FROM ironwood_one_time_recovery",
            [],
        )
    };
    let anchor = tip(&st);
    let birthday = AccountBirthday::from_parts(ChainState::empty(anchor.height, anchor.hash), None);
    let mut accounts = vec![(st.test_account().unwrap().id(), true)];
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
        accounts.push((account.id(), false));
    }
    let publication = publication_at(&st, anchor.height);
    let work = LookupWork {
        token: zcash_client_backend::data_api::one_time_ivk::restore::RecoveryToken {
            generation: 0,
            history_revision: 0,
        },
        work: zcash_client_backend::data_api::one_time_ivk::restore::DiscoveryWork {
            key: key8(),
            receiver: [0; 43],
        },
        from: publication.start_height,
        through: publication.end.height,
        cursor: None,
    };
    let page = whole(publication, vec![]);
    let request = WitnessRequest {
        key: key8(),
        position: 0,
        cmx: [0; 32],
        payments: [1; 32],
        witnesses: [7; 32],
        ordinal: 0,
    };
    let answer = WitnessAnswer {
        payments: [1; 32],
        revision: [7; 32],
        context: publication.end,
        payload: [0; 512],
    };
    for (account, orchard) in accounts {
        let db = st.wallet_mut().db_mut();
        // Receivers come first: with no progress row they must still read as disabled.
        let (_, receivers) = db.one_time_receivers(account).unwrap();
        assert!(receivers.is_empty());
        assert_eq!(db.one_time_direct_query_count(account).unwrap(), 0);
        db.set_one_time_recovery_enabled(account, false).unwrap();
        let state = db.one_time_recovery(account, clock_now()).unwrap();
        assert!(!state.enabled && state.lookups.is_empty() && state.witnesses.is_empty());
        assert!(
            !db.begin_one_time_recovery(account, publication, true)
                .unwrap()
        );
        assert!(
            !db.check_one_time_history(account, publication, Some(4))
                .unwrap()
        );
        let _ = db.cancel_one_time_history(account);
        db.require_one_time_upgrade(account).unwrap();
        let token = db.one_time_recovery(account, clock_now()).unwrap().token;
        let _ = db.record_one_time_filters(account, token, 0, &[], &[]);
        let _ = db.defer_one_time_lookup(account, &work, clock_now());
        let _ = db.record_one_time_lookup(account, &work, &page, clock_now());
        let _ = db.record_one_time_witness(account, token, request, &answer, clock_now());
        let _ = db.refresh_one_time_witness(account, token, request);
        let issued = [
            db.prepare_receive_reservation(account, clock_now())
                .map(|r| r.map(drop)),
            db.reserve_refund_key(account, anchor.height)
                .map(|r| r.map(drop)),
            db.begin_receive_operation(account, 0, clock_now() + 60, clock_now())
                .map(|r| r.map(drop)),
            db.start_receive_operation(account, "request", clock_now())
                .map(|r| r.map(drop)),
        ];
        for result in issued {
            if orchard {
                assert!(matches!(result, Ok(Err(ReservationPolicy::Disabled))));
            } else {
                assert!(matches!(result, Err(SqliteClientError::BadAccountData(_))));
            }
        }
        assert!(
            db.record_refund_operation(account, 0, "deposit", clock_now() + 60, clock_now())
                .is_err()
        );
        let _ = db.finish_receive_operation(account, "request", &OperationOutcome::Rejected);
        let observation = Observation {
            status: OperationStatus::Active,
            funded: false,
            receipts: vec![],
        };
        let _ = db.record_operation_status(account, "deposit", None, observation, clock_now());
        let _ = db.refund_funding_memo(account, 0, "deposit");
        if !orchard {
            assert!(matches!(
                db.set_one_time_recovery_enabled(account, true),
                Err(SqliteClientError::BadAccountData(_))
            ));
        }
        assert_eq!(rows(&st), 0, "orchard {orchard}");
    }
    st.generate_and_scan_empty_blocks(2);
    assert_eq!(rows(&st), 0);

    // Only enabling creates progress, and pausing and enabling again keep their behavior.
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(account, true).unwrap();
    assert!(db.one_time_recovery(account, clock_now()).unwrap().enabled);
    db.set_one_time_recovery_enabled(account, false).unwrap();
    assert!(!db.one_time_recovery(account, clock_now()).unwrap().enabled);
    assert_eq!(
        db.prepare_receive_reservation(account, clock_now())
            .unwrap()
            .map(drop),
        Err(ReservationPolicy::Disabled)
    );
    db.set_one_time_recovery_enabled(account, true).unwrap();
    assert!(db.one_time_recovery(account, clock_now()).unwrap().enabled);
    assert_ne!(
        db.prepare_receive_reservation(account, clock_now())
            .unwrap()
            .map(drop),
        Err(ReservationPolicy::Disabled)
    );
    assert_eq!(rows(&st), 1);
}

/// Pausing an account that is not enabled, or reporting an upgrade it already waits for, only
/// reads: both succeed on a read-only connection, before and after the account has a row.
#[test]
fn pausing_a_disabled_account_needs_no_write() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let read_only = |st: &mut State, on: bool| {
        st.wallet()
            .conn()
            .pragma_update(None, "query_only", on)
            .unwrap()
    };
    read_only(&mut st, true);
    let db = st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(account, false).unwrap();
    db.require_one_time_upgrade(account).unwrap();
    read_only(&mut st, false);
    let db = st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(account, true).unwrap();
    db.set_one_time_recovery_enabled(account, false).unwrap();
    db.require_one_time_upgrade(account).unwrap();
    read_only(&mut st, true);
    let db = st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(account, false).unwrap();
    db.require_one_time_upgrade(account).unwrap();
    read_only(&mut st, false);
}
