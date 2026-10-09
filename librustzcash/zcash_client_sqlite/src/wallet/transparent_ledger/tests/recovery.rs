//! Candidate recovery: watched addresses, commits, rewinds, window growth, and isolation.

use rusqlite::{Connection, types::Value};
use sapling::zip32::ExtendedSpendingKey;
use transparent::{address::TransparentAddress, bundle::OutPoint, keys::TransparentKeyScope};
use zcash_client_backend::data_api::{
    Account as _, WalletRead as _, WalletWrite as _,
    testing::{AddressType, TestBuilder},
    transparent_ledger::{
        AddressRange, CandidateBlocker, CandidateRecovery, CommitOutcome, CommitRejection,
        IntegrityFailure, InvalidCommit, PageRequest, PublicationAnchor, ReceiveEvent,
        RecoveryRevision, SpendEvent, StaleCommit, TransparentLedgerCommit,
        TransparentLedgerMode::{self, PrivateRequired, Public},
        TransparentLedgerRead as _, TransparentLedgerWrite as _, TransparentWatchSet, WatchOrigin,
    },
};
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::{
    consensus::BlockHeight,
    value::{MAX_MONEY, Zatoshis},
};

use super::{State, conn, wallet_state};
use crate::{
    AccountUuid,
    error::SqliteClientError,
    testing::{BlockCache, db::TestDbFactory},
    wallet::transparent_ledger::forget_reattributed_script,
};

/// A wallet with one account and ten scanned blocks, under a durable `PrivateRequired` policy.
fn recovery_wallet() -> (State, AccountUuid) {
    let mut st = wallet_state(TestDbFactory::default());
    scan_new_blocks(&mut st, 10);
    set_policy(&mut st, PrivateRequired);
    let account = st.test_account().unwrap().id();
    (st, account)
}

fn scan_new_blocks(st: &mut State, count: usize) {
    static NOT_OUR_KEY: std::sync::OnceLock<sapling::zip32::DiversifiableFullViewingKey> =
        std::sync::OnceLock::new();
    let not_our_key = NOT_OUR_KEY
        .get_or_init(|| ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key());
    let value = Zatoshis::const_from_u64(10_000);
    let (start, _, _) = st.generate_next_block(not_our_key, AddressType::DefaultExternal, value);
    for _ in 1..count {
        st.generate_next_block(not_our_key, AddressType::DefaultExternal, value);
    }
    st.scan_cached_blocks(start, count);
}

fn set_policy(st: &mut State, mode: TransparentLedgerMode) {
    let db = st.wallet_mut().db_mut();
    db.apply_transparent_policy(mode).unwrap();
    db.set_transparent_ledger_mode(mode);
}

/// Runs `write` as public discovery, which only `Public` permits, then applies
/// `PrivateRequired` again. Leaving `PrivateRequired` demotes every active account.
fn publicly<T>(st: &mut State, write: impl FnOnce(&mut State) -> T) -> T {
    set_policy(st, Public);
    let result = write(st);
    set_policy(st, PrivateRequired);
    result
}

fn watch(st: &State, account: AccountUuid) -> TransparentWatchSet<AccountUuid> {
    st.wallet().db().transparent_watch_set(account).unwrap()
}

fn recovery(st: &State, account: AccountUuid) -> CandidateRecovery<AccountUuid> {
    st.wallet()
        .db()
        .transparent_candidate_recovery(account)
        .unwrap()
}

fn apply(
    st: &mut State,
    commit: TransparentLedgerCommit<AccountUuid>,
) -> Result<CommitOutcome, SqliteClientError> {
    st.wallet_mut()
        .db_mut()
        .apply_transparent_ledger_commit(commit)
}

/// Applies `commit` and returns why it was rejected.
///
/// An integrity rejection quarantines its source and account; this asserts that it did, then
/// lifts the quarantine, so that one wallet can probe several contradictions in turn.
fn rejected(st: &mut State, commit: TransparentLedgerCommit<AccountUuid>) -> CommitRejection {
    let rejection = match apply(st, commit) {
        Err(SqliteClientError::TransparentLedgerCommitRejected(rejection)) => rejection,
        other => panic!("expected a rejected commit, got {other:?}"),
    };
    if matches!(rejection, CommitRejection::Integrity(_)) {
        assert!(count(st, "tpir_quarantined_sources") > 0);
        assert!(count(st, "tpir_quarantined_accounts") > 0);
        lift_quarantine(st);
    }
    rejection
}

/// Clears every quarantine, standing in for the verification that is not implemented yet.
pub(super) fn lift_quarantine(st: &State) {
    conn(st)
        .execute_batch(
            "DELETE FROM tpir_quarantined_sources; DELETE FROM tpir_quarantined_accounts;",
        )
        .unwrap();
}

fn revision(lineage: u64, sealed: bool) -> RecoveryRevision {
    RecoveryRevision {
        source: b"fixture".to_vec(),
        revision: format!("r{lineage}").into_bytes(),
        lineage,
        sealed,
        publication: PublicationAnchor {
            height: BlockHeight::from_u32(10_000_000),
            hash: BlockHash([7; 32]),
        },
    }
}

/// An empty commit for the watch set's context, anchored at its target.
fn commit(ws: &TransparentWatchSet<AccountUuid>) -> TransparentLedgerCommit<AccountUuid> {
    TransparentLedgerCommit {
        context: ws.context().unwrap(),
        revision: revision(1, true),
        anchor: ws.target.unwrap(),
        receives: vec![],
        spends: vec![],
        coverage: vec![],
        unsupported: vec![],
        opened_pages: vec![],
        completed_pages: vec![],
    }
}

/// Coverage of every watched address from its required start through the target.
fn full_coverage(ws: &TransparentWatchSet<AccountUuid>) -> Vec<AddressRange> {
    ws.addresses
        .iter()
        .map(|watched| AddressRange {
            address: watched.address,
            from: watched.required_from,
            through: ws.target.unwrap().height,
        })
        .collect()
}

fn external(ws: &TransparentWatchSet<AccountUuid>) -> TransparentAddress {
    ws.addresses
        .iter()
        .find(|w| {
            matches!(
                w.origin,
                WatchOrigin::Derived { scope, .. } if scope == TransparentKeyScope::EXTERNAL
            )
        })
        .unwrap()
        .address
}

fn below_target(ws: &TransparentWatchSet<AccountUuid>, depth: u32) -> BlockHeight {
    ws.target.unwrap().height - depth
}

fn receive(tag: u8, address: TransparentAddress, value: u64, at: BlockHeight) -> ReceiveEvent {
    ReceiveEvent {
        metadata: None,
        outpoint: OutPoint::new([tag; 32], 0),
        address,
        value: Zatoshis::const_from_u64(value),
        coinbase: false,
        mined_height: at,
    }
}

fn spend(tag: u8, prevout: &ReceiveEvent, at: BlockHeight) -> SpendEvent {
    SpendEvent {
        metadata: None,
        spending_txid: TxId::from_bytes([tag; 32]),
        input_index: 0,
        prevout: prevout.outpoint.clone(),
        prevout_address: prevout.address,
        mined_height: at,
    }
}

fn count(st: &State, table: &str) -> i64 {
    conn(st)
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

/// Every row of every table other than the transparent ledger's, in a canonical order.
fn production_dump(conn: &Connection) -> Vec<(String, Vec<String>)> {
    let tables: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table'
             AND name NOT LIKE 'tpir!_%' ESCAPE '!'
             AND name NOT LIKE 'sqlite!_%' ESCAPE '!'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let mut stmt = conn.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
            let columns = stmt.column_count();
            let mut rows: Vec<String> = stmt
                .query_map([], |row| {
                    (0..columns)
                        .map(|i| row.get::<_, Value>(i))
                        .collect::<Result<Vec<_>, _>>()
                        .map(|values| format!("{values:?}"))
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            rows.sort();
            (table, rows)
        })
        .collect()
}

#[test]
fn watch_set_lists_every_scope_from_the_birthday() {
    let (st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let birthday = st.test_account().unwrap().birthday().height();

    let target = ws.target.unwrap();
    assert_eq!(
        Some(target.height),
        crate::wallet::fully_scanned_height(conn(&st)).unwrap()
    );
    assert_eq!(ws.policy_generation, 1);
    assert!(ws.pending_pages.is_empty());
    assert!(ws.addresses.iter().all(|w| w.required_from == birthday));
    for scope in [
        TransparentKeyScope::EXTERNAL,
        TransparentKeyScope::INTERNAL,
        TransparentKeyScope::EPHEMERAL,
    ] {
        assert!(
            ws.addresses.iter().any(|w| matches!(
                w.origin,
                WatchOrigin::Derived { scope: s, .. } if s == scope
            )),
            "no watched address in {scope:?}"
        );
    }
    // The account's receiving address is watched.
    let taddr = *st
        .wallet()
        .get_last_generated_address_matching(
            account,
            zcash_keys::keys::UnifiedAddressRequest::AllAvailableKeys,
        )
        .unwrap()
        .unwrap()
        .transparent()
        .unwrap();
    assert!(ws.addresses.iter().any(|w| w.address == taddr));

    // Reads are stable.
    assert_eq!(watch(&st, account), ws);
}

#[test]
fn per_event_lookups_use_indexes() {
    let (st, _) = recovery_wallet();
    for (query, index) in [
        (
            "SELECT 1 FROM tpir_spend_events WHERE prevout_txid = X'00' AND prevout_output_index = 0",
            "idx_tpir_spend_events_prevout",
        ),
        (
            "SELECT 1 FROM tpir_coverage WHERE account_id = 1 AND script = X'00'",
            "idx_tpir_coverage_script",
        ),
        (
            "SELECT script FROM tpir_receive_events WHERE account_id = 1",
            "idx_tpir_receive_events_account",
        ),
        (
            "SELECT prevout_script FROM tpir_spend_events WHERE account_id = 1",
            "idx_tpir_spend_events_account",
        ),
    ] {
        let plan: Vec<String> = conn(&st)
            .prepare(&format!("EXPLAIN QUERY PLAN {query}"))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            plan.iter().any(|step| step.contains(index)),
            "{query} does not use {index}: {plan:?}"
        );
    }
}

#[test]
fn no_target_before_scanning() {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    set_policy(&mut st, PrivateRequired);
    let account = st.test_account().unwrap().id();

    let ws = watch(&st, account);
    assert_eq!(ws.target, None);
    assert_eq!(ws.context(), None);
    let recovery = recovery(&st, account);
    assert!(recovery.blockers.contains(&CandidateBlocker::ChainUnknown));
    assert_eq!(recovery.covered_through, None);
}

#[test]
fn commits_require_a_private_policy() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    set_policy(&mut st, Public);
    let ws_public = watch(&st, account);

    let mut c = commit(&ws_public);
    c.coverage = full_coverage(&ws);
    assert!(matches!(
        apply(&mut st, c),
        Err(SqliteClientError::TransparentRecoveryNotEnabled)
    ));
    assert_eq!(count(&st, "tpir_coverage"), 0);
    assert_eq!(count(&st, "tpir_revisions"), 0);

    // A private handle alone is not enough: the durable policy must authorize recovery too.
    st.wallet_mut()
        .db_mut()
        .set_transparent_ledger_mode(PrivateRequired);
    let mut c = commit(&ws_public);
    c.coverage = full_coverage(&ws);
    assert!(matches!(
        apply(&mut st, c),
        Err(SqliteClientError::TransparentRecoveryNotEnabled)
    ));
}

#[test]
fn receive_then_spend_is_idempotent_and_complete() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let received = receive(1, taddr, 50_000, below_target(&ws, 5));

    let mut c = commit(&ws);
    c.receives = vec![received.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c.clone()).unwrap();
    // Replaying the same commit changes nothing.
    let tables = [
        "tpir_receive_events",
        "tpir_receive_observations",
        "tpir_coverage",
    ];
    let before: Vec<i64> = tables.iter().map(|t| count(&st, t)).collect();
    apply(&mut st, c).unwrap();
    assert_eq!(
        tables.iter().map(|t| count(&st, t)).collect::<Vec<_>>(),
        before
    );

    // Window growth after the receive adds uncovered addresses; cover them too.
    let ws = watch(&st, account);
    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();

    let r = recovery(&st, account);
    assert_eq!(r.blockers, vec![]);
    assert_eq!(r.covered_through, Some(ws.target.unwrap().height));
    assert_eq!(r.receives, vec![received.clone()]);
    assert_eq!(r.unspent, vec![received.outpoint.clone()]);
    assert_eq!(
        r.recovered_unverified,
        Some(Zatoshis::const_from_u64(50_000))
    );

    let mut c = commit(&ws);
    c.spends = vec![spend(2, &received, below_target(&ws, 2))];
    apply(&mut st, c).unwrap();
    let r = recovery(&st, account);
    assert_eq!(r.unspent, vec![]);
    assert_eq!(r.recovered_unverified, Some(Zatoshis::ZERO));
    assert_eq!(r.unresolved_spends, 0);
}

#[test]
fn spend_before_receive_stays_unresolved_until_the_output_arrives() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let received = receive(1, external(&ws), 20_000, below_target(&ws, 5));

    let mut c = commit(&ws);
    c.spends = vec![spend(2, &received, below_target(&ws, 1))];
    apply(&mut st, c).unwrap();
    let r = recovery(&st, account);
    assert_eq!(r.unresolved_spends, 1);
    assert!(r.blockers.contains(&CandidateBlocker::UnresolvedSpends));

    let mut c = commit(&ws);
    c.receives = vec![received];
    apply(&mut st, c).unwrap();
    let r = recovery(&st, account);
    assert_eq!(r.unresolved_spends, 0);
    assert_eq!(r.unspent, vec![]);
}

#[test]
fn recovered_total_above_max_money_stays_readable() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let max = MAX_MONEY;

    let mut c = commit(&ws);
    c.receives = vec![receive(1, taddr, max, below_target(&ws, 3))];
    apply(&mut st, c).unwrap();
    assert_eq!(
        recovery(&st, account).recovered_unverified,
        Some(Zatoshis::const_from_u64(MAX_MONEY))
    );

    // A second full-supply receive is valid evidence while its spend is unrecovered.
    let mut c = commit(&ws);
    c.receives = vec![receive(2, taddr, max, below_target(&ws, 2))];
    apply(&mut st, c).unwrap();
    let r = recovery(&st, account);
    assert_eq!(r.unspent.len(), 2);
    assert_eq!(r.recovered_unverified, None);
}

#[test]
fn contradictions_are_refused_without_partial_writes() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let received = receive(1, taddr, 20_000, below_target(&ws, 5));
    let mut c = commit(&ws);
    c.receives = vec![received.clone()];
    apply(&mut st, c).unwrap();
    let coverage_before = count(&st, "tpir_coverage");

    // Different content for the same outpoint; the commit's coverage must not land either.
    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws);
    c.receives = vec![ReceiveEvent {
        value: Zatoshis::const_from_u64(1),
        ..received.clone()
    }];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::ReceiveContent(received.outpoint.clone()))
    );
    assert_eq!(count(&st, "tpir_coverage"), coverage_before);

    // The same receive mined at another height on the local chain.
    let mut c = commit(&ws);
    c.receives = vec![ReceiveEvent {
        mined_height: below_target(&ws, 4),
        ..received.clone()
    }];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::ReceivePlacement(
            received.outpoint.clone()
        ))
    );

    // A spend naming another watched address for this output.
    let other = ws
        .addresses
        .iter()
        .map(|w| w.address)
        .find(|a| *a != taddr)
        .unwrap();
    let mut c = commit(&ws);
    c.spends = vec![SpendEvent {
        prevout_address: other,
        ..spend(2, &received, below_target(&ws, 1))
    }];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::SpendAddress(received.outpoint.clone()))
    );

    // Two different mined spends of one output.
    let mut c = commit(&ws);
    c.spends = vec![
        spend(2, &received, below_target(&ws, 1)),
        spend(3, &received, below_target(&ws, 1)),
    ];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::ConflictingSpends(
            received.outpoint.clone()
        ))
    );
    assert_eq!(count(&st, "tpir_spend_events"), 0);

    // A spend identity with a different outpoint.
    let mut c = commit(&ws);
    c.spends = vec![spend(2, &received, below_target(&ws, 1))];
    apply(&mut st, c).unwrap();
    let elsewhere = receive(9, taddr, 1, below_target(&ws, 5));
    let mut c = commit(&ws);
    c.spends = vec![spend(2, &elsewhere, below_target(&ws, 1))];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::SpendContent {
            spending_txid: TxId::from_bytes([2; 32]),
            input_index: 0,
        })
    );
}

#[test]
fn malformed_commits_are_invalid() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let target = ws.target.unwrap().height;

    let mut c = commit(&ws);
    c.receives = vec![receive(1, taddr, 1, target + 1)];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Invalid(InvalidCommit::AboveAnchor)
    );

    let mut c = commit(&ws);
    c.coverage = vec![AddressRange {
        address: taddr,
        from: target,
        through: target - 1,
    }];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Invalid(InvalidCommit::EmptyRange)
    );

    let mut c = commit(&ws);
    c.revision.source = vec![];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Invalid(InvalidCommit::Identifier)
    );

    let mut c = commit(&ws);
    c.revision.lineage = u64::MAX;
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Invalid(InvalidCommit::Lineage)
    );
}

#[test]
fn stale_context_is_refused() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);

    // An address the account does not watch.
    let mut c = commit(&ws);
    let stranger = TransparentAddress::PublicKeyHash([0xAB; 20]);
    c.coverage = vec![AddressRange {
        address: stranger,
        from: ws.target.unwrap().height,
        through: ws.target.unwrap().height,
    }];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Stale(StaleCommit::AddressNotWatched(stranger))
    );

    // A target that is not a local block.
    let mut c = commit(&ws);
    c.context.target.hash = BlockHash([0xEE; 32]);
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Stale(StaleCommit::TargetNotAccepted)
    );
    let mut c = commit(&ws);
    c.anchor.hash = BlockHash([0xEE; 32]);
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Stale(StaleCommit::AnchorNotAccepted)
    );

    // Completing a page that is not open.
    let mut c = commit(&ws);
    c.completed_pages = vec![b"missing".to_vec()];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Stale(StaleCommit::UnknownPage(b"missing".to_vec()))
    );

    // A policy transition after capture.
    set_policy(&mut st, Public);
    set_policy(&mut st, PrivateRequired);
    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws);
    assert!(matches!(
        apply(&mut st, c),
        Err(SqliteClientError::StaleTransparentPolicy { .. })
    ));

    // A deleted account.
    let ws = watch(&st, account);
    st.wallet_mut().delete_account(account).unwrap();
    assert_eq!(
        rejected(&mut st, commit(&ws)),
        CommitRejection::Stale(StaleCommit::AccountUnknown)
    );
    assert_eq!(count(&st, "tpir_revisions"), 0);
}

#[test]
fn provisional_revisions_are_superseded_and_sealed_ones_are_not() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);

    let mut c = commit(&ws);
    c.revision = revision(1, false);
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    let provisional_coverage = count(&st, "tpir_coverage");
    assert!(provisional_coverage > 0);

    // Observing a newer revision preserves provisional evidence until explicitly trusted.
    let mut c = commit(&ws);
    c.revision = revision(2, false);
    apply(&mut st, c).unwrap();
    assert_eq!(count(&st, "tpir_coverage"), provisional_coverage);
    st.wallet_mut()
        .db_mut()
        .qualify_transparent_revision(&revision(2, false))
        .unwrap();
    assert_eq!(count(&st, "tpir_coverage"), 0);

    let mut c = commit(&ws);
    c.revision = revision(1, false);
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Stale(StaleCommit::SupersededRevision)
    );

    // An older sealed revision stays acceptable.
    let mut c = commit(&ws);
    c.revision = revision(0, true);
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    assert_eq!(count(&st, "tpir_coverage"), provisional_coverage);

    // A known revision with other metadata, or a second revision at a used lineage.
    let mut c = commit(&ws);
    c.revision = RecoveryRevision {
        sealed: true,
        ..revision(2, false)
    };
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::RevisionMismatch)
    );
    let mut c = commit(&ws);
    c.revision = RecoveryRevision {
        revision: b"other".to_vec(),
        ..revision(2, false)
    };
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::RevisionMismatch)
    );
}

#[test]
fn supersession_retracts_only_events_without_independent_observations() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let address = external(&ws);
    let shared = receive(1, address, 5_000, below_target(&ws, 2));
    let retracted = receive(2, address, 6_000, below_target(&ws, 2));
    let retracted_spend = spend(3, &shared, below_target(&ws, 1));

    let mut c = commit(&ws);
    c.revision = revision(1, false);
    c.receives = vec![shared.clone(), retracted.clone()];
    c.spends = vec![retracted_spend];
    apply(&mut st, c).unwrap();

    let mut c = commit(&watch(&st, account));
    c.revision = RecoveryRevision {
        source: b"independent".to_vec(),
        ..revision(1, true)
    };
    c.receives = vec![shared.clone()];
    apply(&mut st, c).unwrap();

    let ws = watch(&st, account);
    let mut c = commit(&ws);
    st.wallet_mut()
        .db_mut()
        .qualify_transparent_revision(&revision(2, false))
        .unwrap();
    c.revision = revision(2, false);
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();

    let recovered = recovery(&st, account);
    assert!(recovered.blockers.is_empty());
    assert_eq!(recovered.receives, vec![shared.clone()]);
    assert!(recovered.spends.is_empty());
    assert_eq!(recovered.unspent, vec![shared.outpoint.clone()]);
    assert_eq!(count(&st, "tpir_receive_observations"), 1);
    assert_eq!(count(&st, "tpir_spend_observations"), 0);

    // A corrected receive may reuse an outpoint whose only old observation was retracted.
    let mut c = commit(&watch(&st, account));
    c.revision = revision(2, false);
    c.receives = vec![ReceiveEvent {
        value: Zatoshis::const_from_u64(7_000),
        ..retracted
    }];
    apply(&mut st, c).unwrap();
    assert_eq!(recovery(&st, account).receives.len(), 2);
}

#[test]
fn pending_pages_block_their_addresses_and_resume() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let target = ws.target.unwrap().height;
    let page = PageRequest {
        page: b"p1".to_vec(),
        addresses: vec![taddr],
        from: target - 3,
        through: target,
    };

    let mut c = commit(&ws);
    c.opened_pages = vec![page.clone()];
    apply(&mut st, c).unwrap();

    // Replaying the opening is harmless, but reopening it with other addresses is refused
    // rather than merged.
    let mut c = commit(&ws);
    c.opened_pages = vec![page.clone()];
    apply(&mut st, c).unwrap();
    let other = ws
        .addresses
        .iter()
        .map(|w| w.address)
        .find(|a| *a != taddr)
        .unwrap();
    for addresses in [vec![other], vec![taddr, other]] {
        let mut c = commit(&ws);
        c.opened_pages = vec![PageRequest {
            addresses,
            ..page.clone()
        }];
        assert_eq!(
            rejected(&mut st, c),
            CommitRejection::Invalid(InvalidCommit::Page)
        );
    }

    // The open page survives, is listed for resumption, and blocks completeness.
    let ws = watch(&st, account);
    assert_eq!(ws.pending_pages.len(), 1);
    assert_eq!(ws.pending_pages[0].request, page);
    assert_eq!(ws.pending_pages[0].revision, revision(1, true));
    let r = recovery(&st, account);
    assert!(r.blockers.contains(&CandidateBlocker::PendingPages));

    // Coverage cannot span the unfinished page.
    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws);
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Invalid(InvalidCommit::PendingPageOverlap(taddr))
    );

    // Completing it alongside its results unblocks the account.
    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws);
    c.completed_pages = vec![page.page.clone()];
    apply(&mut st, c).unwrap();
    let r = recovery(&st, account);
    assert_eq!(r.pending_pages, 0);
    assert_eq!(r.blockers, vec![]);

    // A policy transition removes open pages. (This revision now covers the page's range,
    // so another source opens it.)
    let mut c = commit(&ws);
    c.revision = RecoveryRevision {
        source: b"other source".to_vec(),
        ..revision(0, true)
    };
    c.opened_pages = vec![page];
    apply(&mut st, c).unwrap();
    assert_eq!(watch(&st, account).pending_pages.len(), 1);
    set_policy(&mut st, Public);
    set_policy(&mut st, PrivateRequired);
    assert!(watch(&st, account).pending_pages.is_empty());
}

#[test]
fn a_pending_page_retains_its_revision_and_target_when_the_tip_advances() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let original = ws.target.unwrap();
    let address = external(&ws);
    let mut c = commit(&ws);
    let opened_by = c.revision.clone();
    let page = PageRequest {
        page: b"older-target".to_vec(),
        addresses: vec![address],
        from: below_target(&ws, 2),
        through: original.height,
    };
    c.opened_pages.push(page.clone());
    apply(&mut st, c).unwrap();

    // The watch set lists the page with the revision and target it was opened under.
    scan_new_blocks(&mut st, 1);
    let ws = watch(&st, account);
    let tip = ws.target.unwrap().height;
    assert!(tip > original.height);
    let [pending] = &ws.pending_pages[..] else {
        panic!("the page must stay pending")
    };
    assert_eq!(pending.target, original);
    assert_eq!(pending.revision, opened_by);
    assert_eq!(pending.request, page);

    // Resuming it under that revision and anchor completes it.
    let mut c = commit(&ws);
    c.revision = pending.revision.clone();
    c.anchor = pending.target;
    c.completed_pages.push(pending.request.page.clone());
    c.coverage.push(AddressRange {
        address,
        from: page.from,
        through: page.through,
    });
    apply(&mut st, c).unwrap();
    assert!(watch(&st, account).pending_pages.is_empty());

    // The page covered its address only through its own target: with everything else
    // covered, the new block is all that is missing.
    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws);
    for range in c.coverage.iter_mut().filter(|r| r.address == address) {
        range.through = page.from - 1;
    }
    apply(&mut st, c).unwrap();
    let r = recovery(&st, account);
    assert_eq!(r.covered_through, Some(original.height));
    assert_eq!(r.blockers, vec![CandidateBlocker::IncompleteCoverage]);
    let mut c = commit(&ws);
    c.coverage.push(AddressRange {
        address,
        from: original.height + 1,
        through: tip,
    });
    apply(&mut st, c).unwrap();
    assert_eq!(recovery(&st, account).covered_through, Some(tip));
    assert_eq!(recovery(&st, account).blockers, vec![]);
}

#[test]
fn unsupported_ranges_block_until_covered() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let target = ws.target.unwrap().height;

    // One source cannot check the most recent range of an address.
    let mut c = commit(&ws);
    c.unsupported = vec![AddressRange {
        address: taddr,
        from: target - 2,
        through: target,
    }];
    apply(&mut st, c).unwrap();
    let r = recovery(&st, account);
    assert!(r.blockers.contains(&CandidateBlocker::UnsupportedRanges));

    // Another source covers it.
    let mut c = commit(&ws);
    c.revision = RecoveryRevision {
        source: b"other source".to_vec(),
        ..revision(0, true)
    };
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    assert_eq!(recovery(&st, account).blockers, vec![]);
}

#[test]
fn spends_cannot_precede_their_outputs() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);

    // The output arrives first.
    let earlier = receive(1, taddr, 1_000, below_target(&ws, 3));
    let mut c = commit(&ws);
    c.receives = vec![earlier.clone()];
    apply(&mut st, c).unwrap();
    let mut c = commit(&ws);
    c.spends = vec![spend(2, &earlier, below_target(&ws, 4))];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::SpendBeforeOutput(
            earlier.outpoint.clone()
        ))
    );

    // The spend arrives first.
    let later = receive(3, taddr, 1_000, below_target(&ws, 2));
    let mut c = commit(&ws);
    c.spends = vec![spend(4, &later, below_target(&ws, 5))];
    apply(&mut st, c).unwrap();
    let mut c = commit(&ws);
    c.receives = vec![later.clone()];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::SpendBeforeOutput(later.outpoint.clone()))
    );

    // A spend in the output's own block is valid.
    let same_block = receive(5, taddr, 1_000, below_target(&ws, 1));
    let mut c = commit(&ws);
    c.receives = vec![same_block.clone()];
    c.spends = vec![spend(6, &same_block, below_target(&ws, 1))];
    apply(&mut st, c).unwrap();
}

#[test]
fn truncation_invalidates_candidate_state_above_the_rescan_floor() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let target = ws.target.unwrap().height;
    let in_suffix = receive(1, taddr, 1_000, target - 3);
    let mut c = commit(&ws);
    c.receives = vec![in_suffix.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();

    // A rewind that keeps a checkpoint above the floor still requeues the blocks above the
    // floor, so candidate state there is invalidated too.
    let (retained, floor) = (target - 2, target - 5);
    let network = *st.network();
    let db = st.wallet_mut().db_mut();
    let tx = db.conn.transaction().unwrap();
    crate::wallet::truncate_to_height_internal(
        &tx,
        &network,
        &zcash_keys::keys::transparent::gap_limits::GapLimits::default(),
        retained,
        floor,
    )
    .unwrap();
    tx.commit().unwrap();

    let max_anchor: u32 = conn(&st)
        .query_row("SELECT MAX(anchor_height) FROM tpir_coverage", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(max_anchor, u32::from(floor));
    assert_eq!(recovery(&st, account).receives, vec![]);
}

#[test]
fn rewind_clips_coverage_and_clears_placements() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let target = ws.target.unwrap().height;
    let late = receive(1, taddr, 30_000, target - 1);
    let early = receive(2, taddr, 10_000, target - 8);

    let mut c = commit(&ws);
    c.receives = vec![late.clone(), early.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    let mut c = commit(&ws);
    c.opened_pages = vec![PageRequest {
        page: b"p1".to_vec(),
        addresses: vec![taddr],
        from: target - 1,
        through: target,
    }];
    // A second source leaves a page open at the tip.
    c.revision = RecoveryRevision {
        source: b"other source".to_vec(),
        ..revision(0, true)
    };
    apply(&mut st, c).unwrap();

    let retained = target - 4;
    st.truncate_to_height(retained);

    let (max_through, min_anchor, max_anchor): (u32, u32, u32) = conn(&st)
        .query_row(
            "SELECT MAX(through_height), MIN(anchor_height), MAX(anchor_height)
             FROM tpir_coverage",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (max_through, min_anchor, max_anchor),
        (
            u32::from(retained),
            u32::from(retained),
            u32::from(retained)
        )
    );
    assert_eq!(count(&st, "tpir_pending_pages"), 0);

    let r = recovery(&st, account);
    assert_eq!(r.target.map(|t| t.height), Some(retained));
    assert_eq!(r.receives, vec![early.clone()]);

    // The replaced receive can be placed again on the new chain, at a new height.
    scan_new_blocks(&mut st, 3);
    let ws = watch(&st, account);
    let remined = ReceiveEvent {
        mined_height: retained + 2,
        ..late
    };
    let mut c = commit(&ws);
    c.receives = vec![remined.clone(), early.clone()];
    apply(&mut st, c).unwrap();
    assert_eq!(recovery(&st, account).receives, vec![remined, early]);
}

#[test]
fn window_growth_stays_out_of_the_address_table() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let (edge, edge_index) = ws
        .addresses
        .iter()
        .filter_map(|w| match w.origin {
            WatchOrigin::Derived { scope, index } if scope == TransparentKeyScope::EXTERNAL => {
                Some((w.address, index))
            }
            _ => None,
        })
        .max_by_key(|(_, index)| *index)
        .unwrap();
    let addresses_before = count(&st, "addresses");
    let next_address = st
        .wallet()
        .get_last_generated_address_matching(
            account,
            zcash_keys::keys::UnifiedAddressRequest::AllAvailableKeys,
        )
        .unwrap();

    let mut c = commit(&ws);
    c.receives = vec![receive(1, edge, 1_000, below_target(&ws, 1))];
    c.coverage = full_coverage(&ws);
    assert!(apply(&mut st, c).unwrap().window_grew);

    let grown = watch(&st, account);
    let window: Vec<_> = grown
        .addresses
        .iter()
        .filter(|w| matches!(w.origin, WatchOrigin::CandidateWindow { .. }))
        .collect();
    assert!(!window.is_empty());
    assert!(window.iter().all(|w| matches!(
        w.origin,
        WatchOrigin::CandidateWindow { scope, index }
            if scope == TransparentKeyScope::EXTERNAL && index > edge_index
    )));
    // The new addresses are uncovered until the next pass.
    let r = recovery(&st, account);
    assert!(r.blockers.contains(&CandidateBlocker::IncompleteCoverage));
    let mut c = commit(&grown);
    c.coverage = full_coverage(&grown);
    assert!(!apply(&mut st, c).unwrap().window_grew);
    assert_eq!(recovery(&st, account).blockers, vec![]);

    // Production addresses are unchanged.
    assert_eq!(count(&st, "addresses"), addresses_before);
    assert_eq!(
        st.wallet()
            .get_last_generated_address_matching(
                account,
                zcash_keys::keys::UnifiedAddressRequest::AllAvailableKeys,
            )
            .unwrap(),
        next_address
    );
}

#[test]
fn candidate_recovery_leaves_production_state_untouched() {
    let (mut st, account) = recovery_wallet();
    let before = production_dump(conn(&st));

    let ws = watch(&st, account);
    let taddr = external(&ws);
    let received = receive(1, taddr, 40_000, below_target(&ws, 6));
    let mut c = commit(&ws);
    c.receives = vec![received.clone()];
    c.spends = vec![spend(2, &received, below_target(&ws, 3))];
    c.coverage = full_coverage(&ws);
    // A page left open at the target, beside coverage through the block below it.
    c.opened_pages = vec![PageRequest {
        page: b"p".to_vec(),
        addresses: vec![taddr],
        from: ws.target.unwrap().height,
        through: ws.target.unwrap().height,
    }];
    c.coverage
        .iter_mut()
        .for_each(|r| r.through = r.through - 1);
    apply(&mut st, c).unwrap();
    let grown = watch(&st, account);
    let mut c = commit(&grown);
    c.coverage = full_coverage(&grown)
        .into_iter()
        .filter(|r| r.address != taddr)
        .collect();
    apply(&mut st, c).unwrap();

    assert_eq!(production_dump(conn(&st)), before);
}

#[test]
fn account_deletion_removes_its_candidate_state() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let received = receive(1, external(&ws), 5_000, below_target(&ws, 2));
    let mut c = commit(&ws);
    c.receives = vec![received.clone()];
    c.spends = vec![spend(2, &received, below_target(&ws, 1))];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();

    st.wallet_mut().delete_account(account).unwrap();
    for table in [
        "tpir_candidate_windows",
        "tpir_coverage",
        "tpir_receive_events",
        "tpir_receive_observations",
        "tpir_spend_events",
        "tpir_spend_observations",
        "tpir_pending_pages",
    ] {
        assert_eq!(count(&st, table), 0, "{table}");
    }
}

#[test]
fn reattribution_forgets_the_previous_accounts_evidence() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let other = ws
        .addresses
        .iter()
        .map(|w| w.address)
        .find(|a| *a != taddr)
        .unwrap();
    let mut c = commit(&ws);
    c.receives = vec![
        receive(1, taddr, 5_000, below_target(&ws, 2)),
        receive(2, other, 5_000, below_target(&ws, 2)),
    ];
    c.coverage = full_coverage(&ws);
    c.coverage
        .iter_mut()
        .for_each(|r| r.through = r.through - 1);
    c.opened_pages = vec![PageRequest {
        page: b"p".to_vec(),
        addresses: vec![taddr],
        from: ws.target.unwrap().height,
        through: ws.target.unwrap().height,
    }];
    apply(&mut st, c).unwrap();
    let coverage_before = count(&st, "tpir_coverage");

    let account_ref = st.test_account().unwrap().account().internal_id();
    forget_reattributed_script(conn(&st), account_ref, &taddr).unwrap();

    let r = recovery(&st, account);
    assert_eq!(r.receives.len(), 1);
    assert_eq!(r.receives[0].address, other);
    assert_eq!(count(&st, "tpir_coverage"), coverage_before - 1);
    // The page answered only for the forgotten script.
    assert_eq!(count(&st, "tpir_pending_pages"), 0);
}

#[test]
fn pages_and_coverage_of_one_revision_never_overlap() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let target = ws.target.unwrap().height;
    let page = PageRequest {
        page: b"p1".to_vec(),
        addresses: vec![taddr],
        from: target - 3,
        through: target,
    };
    let other_source = RecoveryRevision {
        source: b"other source".to_vec(),
        ..revision(0, true)
    };

    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();

    // The same revision cannot reopen retrieval over a range it already covered.
    let mut c = commit(&ws);
    c.opened_pages = vec![page.clone()];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Invalid(InvalidCommit::PendingPageOverlap(taddr))
    );

    // Another source's unfinished page does not retract that coverage, and its own coverage
    // may later overlap a page of the first source.
    let mut c = commit(&ws);
    c.revision = other_source.clone();
    c.opened_pages = vec![page.clone()];
    apply(&mut st, c).unwrap();
    let mut c = commit(&ws);
    c.revision = other_source;
    c.coverage = full_coverage(&ws);
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Invalid(InvalidCommit::PendingPageOverlap(taddr))
    );
    let mut c = commit(&ws);
    c.revision = revision(2, true);
    c.opened_pages = vec![page];
    c.opened_pages[0].page = b"p2".to_vec();
    apply(&mut st, c).unwrap();
    let mut c = commit(&ws);
    c.revision = revision(1, true);
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
}

#[test]
fn one_transaction_has_one_placement() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let first = receive(1, taddr, 1_000, below_target(&ws, 3));
    let mut c = commit(&ws);
    c.receives = vec![first.clone()];
    apply(&mut st, c).unwrap();

    // Another output of the same transaction, placed in another block.
    let mut c = commit(&ws);
    c.receives = vec![ReceiveEvent {
        outpoint: OutPoint::new([1; 32], 1),
        mined_height: below_target(&ws, 2),
        ..first.clone()
    }];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::TransactionPlacement(TxId::from_bytes(
            [1; 32]
        )))
    );

    // A spend by that transaction, placed in another block.
    let earlier = receive(2, taddr, 1_000, below_target(&ws, 6));
    let mut c = commit(&ws);
    c.receives = vec![earlier.clone()];
    c.spends = vec![spend(1, &earlier, below_target(&ws, 4))];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::TransactionPlacement(TxId::from_bytes(
            [1; 32]
        )))
    );

    // In the same block, both are consistent.
    let mut c = commit(&ws);
    c.receives = vec![
        earlier.clone(),
        ReceiveEvent {
            outpoint: OutPoint::new([1; 32], 1),
            ..first.clone()
        },
    ];
    c.spends = vec![spend(1, &earlier, first.mined_height)];
    apply(&mut st, c).unwrap();
}

#[test]
fn anchors_stay_within_the_publication() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let anchor = ws.target.unwrap();

    let mut c = commit(&ws);
    c.revision.publication = PublicationAnchor {
        height: anchor.height - 1,
        hash: BlockHash([7; 32]),
    };
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Invalid(InvalidCommit::AnchorOutsidePublication)
    );

    let mut c = commit(&ws);
    c.revision.publication = PublicationAnchor {
        height: anchor.height,
        hash: BlockHash([7; 32]),
    };
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Invalid(InvalidCommit::AnchorOutsidePublication)
    );

    let mut c = commit(&ws);
    c.revision.publication = PublicationAnchor {
        height: anchor.height,
        hash: anchor.hash,
    };
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
}

#[test]
fn unsupported_ranges_block_only_within_the_required_interval() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let required = ws.addresses[0].required_from;

    // One source cannot check history before the birthday, nor a range straddling it.
    let mut c = commit(&ws);
    c.unsupported = vec![
        AddressRange {
            address: taddr,
            from: required - 5,
            through: required - 1,
        },
        AddressRange {
            address: taddr,
            from: required - 2,
            through: required,
        },
    ];
    apply(&mut st, c).unwrap();
    // Another covers everything from the birthday.
    let mut c = commit(&ws);
    c.revision = RecoveryRevision {
        source: b"other source".to_vec(),
        ..revision(0, true)
    };
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    assert_eq!(recovery(&st, account).blockers, vec![]);
}

#[test]
fn one_revision_cannot_both_check_and_not_check_a_range() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let target = ws.target.unwrap().height;
    let unsupported = AddressRange {
        address: taddr,
        from: target - 2,
        through: target,
    };
    let contradiction = CommitRejection::Invalid(InvalidCommit::SupportContradiction(taddr));

    // Within one commit.
    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws);
    c.unsupported = vec![unsupported];
    assert_eq!(rejected(&mut st, c), contradiction);

    // Across commits of one revision, in either order.
    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    let mut c = commit(&ws);
    c.unsupported = vec![unsupported];
    assert_eq!(rejected(&mut st, c), contradiction);

    let mut c = commit(&ws);
    c.revision = revision(2, true);
    c.unsupported = vec![unsupported];
    apply(&mut st, c).unwrap();
    let mut c = commit(&ws);
    c.revision = revision(2, true);
    c.coverage = full_coverage(&ws);
    assert_eq!(rejected(&mut st, c), contradiction);
}

#[test]
fn an_account_born_above_the_target_needs_no_coverage_yet() {
    let (mut st, _) = recovery_wallet();
    let target = watch(&st, st.test_account().unwrap().id()).target.unwrap();
    let ufvk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
        st.network(),
        &[7; 32],
        zip32::AccountId::ZERO,
    )
    .unwrap()
    .to_unified_full_viewing_key();
    let birthday = zcash_client_backend::data_api::AccountBirthday::from_parts(
        zcash_client_backend::data_api::chain::ChainState::empty(
            target.height + 10,
            BlockHash([9; 32]),
        ),
        None,
    );
    let later = st
        .wallet_mut()
        .import_account_ufvk(
            "later",
            &ufvk,
            &birthday,
            zcash_client_backend::data_api::AccountPurpose::ViewOnly,
            None,
        )
        .unwrap()
        .id();

    let r = recovery(&st, later);
    let target = r.target.unwrap().height;
    assert!(target < birthday.height());
    assert_eq!(r.covered_through, Some(target));
    assert_eq!(r.blockers, vec![]);
}

#[test]
fn the_first_candidate_commit_requires_a_recovery_aware_reader() {
    let (mut st, account) = recovery_wallet();
    let reader = |st: &State| -> i64 {
        conn(st)
            .query_row("SELECT min_reader_version FROM tpir_meta", [], |row| {
                row.get(0)
            })
            .unwrap()
    };
    let before = reader(&st);
    assert!(before < 3);

    // A refused commit persists nothing, including the requirement.
    let ws = watch(&st, account);
    let mut c = commit(&ws);
    c.anchor.hash = BlockHash([0xEE; 32]);
    assert!(apply(&mut st, c).is_err());
    assert_eq!(reader(&st), before);

    apply(&mut st, commit(&ws)).unwrap();
    assert_eq!(reader(&st), 6);
    // This build still reads the wallet.
    watch(&st, account);
}

#[test]
fn coinbase_is_a_property_of_the_transaction() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let taddr = external(&ws);
    let at = below_target(&ws, 3);
    let coinbase = ReceiveEvent {
        coinbase: true,
        ..receive(1, taddr, 1_000, at)
    };
    let mut c = commit(&ws);
    c.receives = vec![coinbase.clone()];
    apply(&mut st, c).unwrap();
    let coinbase_txid = TxId::from_bytes([1; 32]);

    // Another output of the same transaction, classified differently.
    let mut c = commit(&ws);
    c.receives = vec![ReceiveEvent {
        outpoint: OutPoint::new([1; 32], 1),
        coinbase: false,
        ..coinbase.clone()
    }];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::TransactionCoinbase(coinbase_txid))
    );

    // A coinbase transaction as a spender.
    let earlier = receive(2, taddr, 1_000, below_target(&ws, 5));
    let mut c = commit(&ws);
    c.receives = vec![earlier.clone()];
    c.spends = vec![spend(1, &earlier, at)];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::TransactionCoinbase(coinbase_txid))
    );

    // The same, when the spend is recorded first.
    let mut c = commit(&ws);
    c.receives = vec![earlier.clone()];
    c.spends = vec![spend(3, &earlier, below_target(&ws, 1))];
    apply(&mut st, c).unwrap();
    let mut c = commit(&ws);
    c.receives = vec![ReceiveEvent {
        outpoint: OutPoint::new([3; 32], 0),
        coinbase: true,
        ..receive(3, taddr, 1_000, below_target(&ws, 1))
    }];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::TransactionCoinbase(TxId::from_bytes(
            [3; 32]
        )))
    );
}

mod activation;
