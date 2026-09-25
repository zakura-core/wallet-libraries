use super::*;

fn anchor(height: u32) -> ChainAnchor {
    ChainAnchor {
        height: height.into(),
        hash: [height as u8; 32],
    }
}

fn zats(value: u64) -> Zatoshis {
    Zatoshis::from_u64(value).unwrap()
}

fn terminal(expectation: ReceiptExpectation) -> Lifecycle {
    let mut state = Lifecycle::default();
    state
        .observe_terminal(
            anchor(200),
            21_600,
            expectation,
            CompletionPolicy::default(),
        )
        .unwrap();
    state
}

fn reopen(state: &Lifecycle) -> Lifecycle {
    let observation = state.terminal().map(|t| {
        TerminalObservation::from_parts(
            t.tip(),
            t.observed_at(),
            t.grace_target(),
            t.reconcile_after(),
        )
        .unwrap()
    });
    Lifecycle::from_parts(observation, state.expectation(), state.reconciliation()).unwrap()
}

fn result(target: ChainAnchor) -> ReconciliationResult {
    ReconciliationResult {
        target,
        covered_from: 100.into(),
        covered_through: target.height,
        all_payments_resolved: true,
    }
}

#[test]
fn terminal_on_reopen_waits_for_history_and_preserves_first_deadlines() {
    // The app was closed for six hours. Status is terminal, but the wallet has
    // only scanned through block 150. Time offline cannot replace missing blocks.
    let mut state = terminal(ReceiptExpectation::None);
    let saved = state.terminal().unwrap();
    assert_eq!(saved.grace_target(), BlockHeight::from_u32(210));
    assert_eq!(saved.reconcile_after(), 64_800);
    assert_eq!(
        state.scan_decision(
            100.into(),
            &[100.into()..151.into()],
            ReceiptAccounting::Unresolved
        ),
        ScanDecision::MissingCoverage
    );

    state = reopen(&state);
    state
        .observe_terminal(
            anchor(205),
            25_200,
            ReceiptExpectation::None,
            CompletionPolicy {
                grace_blocks: 20,
                reconciliation_delay_secs: 99_999,
            },
        )
        .unwrap();
    assert_eq!(state.terminal(), Some(saved));
    assert_eq!(
        state.scan_decision(
            100.into(),
            &[100.into()..210.into()],
            ReceiptAccounting::Unresolved
        ),
        ScanDecision::MissingCoverage
    );
    assert_eq!(
        state.scan_decision(
            100.into(),
            &[100.into()..211.into()],
            ReceiptAccounting::Unresolved
        ),
        ScanDecision::Retire
    );
    // Stopping trial decryption does not cancel the still-due directory check.
    assert_eq!(
        state.begin_reconciliation(64_799, anchor(230), 100.into()),
        None
    );
    assert_eq!(
        state.begin_reconciliation(64_800, anchor(209), 100.into()),
        None
    );
    assert_eq!(
        state.begin_reconciliation(64_800, anchor(230), 100.into()),
        Some(anchor(230))
    );
    state = reopen(&state);
    assert_eq!(
        state.begin_reconciliation(90_000, anchor(300), 100.into()),
        Some(anchor(230))
    );
    assert!(
        state
            .finish_reconciliation(100.into(), result(anchor(230)))
            .unwrap()
    );
    assert_eq!(
        state.begin_reconciliation(99_000, anchor(400), 100.into()),
        None
    );
}

#[test]
fn expected_receipts_need_confirmed_notes_and_unambiguous_value() {
    let mut state = terminal(ReceiptExpectation::Positive(Some(zats(50_000))));
    let coverage = [100.into()..211.into()];
    for accounting in [
        ReceiptAccounting::Unresolved,
        ReceiptAccounting::Resolved {
            note_count: 0,
            total: zats(50_000),
        },
        ReceiptAccounting::Resolved {
            note_count: 1,
            total: zats(49_999),
        },
    ] {
        assert_eq!(
            state.scan_decision(100.into(), &coverage, accounting),
            ScanDecision::UnresolvedReceipt
        );
    }
    assert_eq!(
        state.scan_decision(
            100.into(),
            &coverage,
            ReceiptAccounting::Resolved {
                note_count: 2,
                total: zats(50_000)
            }
        ),
        ScanDecision::Retire
    );

    // An empty directory result cannot override a positive expected receipt.
    let target = state
        .begin_reconciliation(70_000, anchor(250), 100.into())
        .unwrap();
    state
        .finish_reconciliation(100.into(), result(target))
        .unwrap();
    assert_eq!(
        state.scan_decision(100.into(), &coverage, ReceiptAccounting::Unresolved),
        ScanDecision::UnresolvedReceipt
    );

    state
        .observe_terminal(
            anchor(260),
            75_000,
            ReceiptExpectation::Positive(None),
            CompletionPolicy::default(),
        )
        .unwrap();
    assert_eq!(state.reconciliation(), Reconciliation::NotStarted);
    assert_eq!(
        state.scan_decision(
            100.into(),
            &coverage,
            ReceiptAccounting::Resolved {
                note_count: 1,
                total: Zatoshis::ZERO
            }
        ),
        ScanDecision::UnresolvedReceipt
    );
    assert_eq!(
        state.scan_decision(
            100.into(),
            &coverage,
            ReceiptAccounting::Resolved {
                note_count: 1,
                total: zats(1)
            }
        ),
        ScanDecision::Retire
    );
    // Reorged or ambiguously attributed notes are supplied as unresolved again.
    assert_eq!(
        state.scan_decision(100.into(), &coverage, ReceiptAccounting::Unresolved),
        ScanDecision::UnresolvedReceipt
    );
}

#[test]
fn unknown_receipts_require_complete_directory_coverage_and_every_payment() {
    let mut state = terminal(ReceiptExpectation::Unknown);
    let coverage = [90.into()..251.into()];
    let empty_receipts = ReceiptAccounting::Resolved {
        note_count: 0,
        total: Zatoshis::ZERO,
    };
    assert_eq!(
        state.scan_decision(100.into(), &coverage, empty_receipts),
        ScanDecision::UnresolvedReceipt
    );
    let target = state
        .begin_reconciliation(70_000, anchor(250), 100.into())
        .unwrap();
    for incomplete in [
        ReconciliationResult {
            covered_from: 101.into(),
            ..result(target)
        },
        ReconciliationResult {
            covered_through: 249.into(),
            ..result(target)
        },
        ReconciliationResult {
            all_payments_resolved: false,
            ..result(target)
        },
    ] {
        assert!(!state.finish_reconciliation(100.into(), incomplete).unwrap());
        assert_eq!(state.reconciliation(), Reconciliation::Pending(target));
    }
    assert!(
        state
            .finish_reconciliation(100.into(), result(target))
            .unwrap()
    );
    assert_eq!(
        state.scan_decision(100.into(), &coverage, empty_receipts),
        ScanDecision::Retire
    );
    assert_eq!(
        state.scan_decision(90.into(), &coverage, empty_receipts),
        ScanDecision::UnresolvedReceipt
    );
    let new_target = state
        .begin_reconciliation(80_000, anchor(270), 90.into())
        .unwrap();
    assert!(
        state
            .finish_reconciliation(
                90.into(),
                ReconciliationResult {
                    covered_from: 90.into(),
                    ..result(new_target)
                }
            )
            .unwrap()
    );
    assert_eq!(
        state.scan_decision(90.into(), &coverage, empty_receipts),
        ScanDecision::Retire
    );
    assert_eq!(
        state.scan_decision(90.into(), &coverage, ReceiptAccounting::Unresolved),
        ScanDecision::UnresolvedReceipt
    );
}

#[test]
fn rewinds_and_status_regressions_resume_work_and_reject_stale_responses() {
    let mut state = terminal(ReceiptExpectation::Unknown);
    let saved = state.terminal();
    let old_target = state
        .begin_reconciliation(70_000, anchor(250), 100.into())
        .unwrap();
    state
        .finish_reconciliation(100.into(), result(old_target))
        .unwrap();
    state.rewind(205.into());
    assert_eq!(state.terminal(), saved);
    assert_eq!(state.reconciliation(), Reconciliation::NotStarted);
    assert_eq!(
        state.scan_decision(
            100.into(),
            &[100.into()..206.into()],
            ReceiptAccounting::Unresolved
        ),
        ScanDecision::MissingCoverage
    );
    let new_tip = ChainAnchor {
        hash: [7; 32],
        ..old_target
    };
    state
        .begin_reconciliation(80_000, new_tip, 100.into())
        .unwrap();
    let before = state.clone();
    assert_eq!(
        state.finish_reconciliation(100.into(), result(old_target)),
        Err(LifecycleError::StaleTarget)
    );
    assert_eq!(state, before);

    state.rewind(199.into());
    assert_eq!(state, Lifecycle::default());
    assert_eq!(
        state.scan_decision(
            100.into(),
            &[100.into()..251.into()],
            ReceiptAccounting::Unresolved
        ),
        ScanDecision::NoTerminalStatus
    );
    state
        .observe_terminal(
            anchor(220),
            90_000,
            ReceiptExpectation::None,
            CompletionPolicy::default(),
        )
        .unwrap();
    assert_eq!(
        state.terminal().unwrap().grace_target(),
        BlockHeight::from_u32(230)
    );
    state.resume();
    assert_eq!(state, Lifecycle::default());
}

#[test]
fn all_operations_and_unknown_uses_keep_shared_keys_active() {
    assert!(key_needs_scanning([], false));
    assert!(key_needs_scanning([ScanDecision::Retire], true));
    for reason in [
        ScanDecision::NoTerminalStatus,
        ScanDecision::MissingCoverage,
        ScanDecision::UnresolvedReceipt,
    ] {
        assert!(key_needs_scanning([ScanDecision::Retire, reason], false));
    }
    assert!(!key_needs_scanning(
        [ScanDecision::Retire, ScanDecision::Retire],
        false
    ));
}

#[test]
fn out_of_order_scanning_does_not_hide_a_gap() {
    let state = terminal(ReceiptExpectation::None);
    for coverage in [
        vec![],
        vec![200.into()..211.into()],
        vec![100.into()..150.into(), 151.into()..211.into()],
    ] {
        assert_eq!(
            state.scan_decision(100.into(), &coverage, ReceiptAccounting::Unresolved),
            ScanDecision::MissingCoverage
        );
    }
    assert_eq!(
        state.scan_decision(
            100.into(),
            &[100.into()..150.into(), 150.into()..211.into()],
            ReceiptAccounting::Unresolved
        ),
        ScanDecision::Retire
    );
    assert_eq!(
        state.scan_decision(
            100.into(),
            &[90.into()..180.into(), 170.into()..211.into()],
            ReceiptAccounting::Unresolved
        ),
        ScanDecision::Retire
    );
    assert_eq!(
        state.scan_decision(
            211.into(),
            &[100.into()..220.into()],
            ReceiptAccounting::Unresolved
        ),
        ScanDecision::MissingCoverage
    );
}

#[test]
fn invalid_restores_and_deadline_overflow_fail_without_mutation() {
    let mut state = Lifecycle::default();
    for (tip, now, expectation) in [
        (anchor(u32::MAX), 0, ReceiptExpectation::None),
        (anchor(200), u64::MAX, ReceiptExpectation::None),
        (
            anchor(200),
            0,
            ReceiptExpectation::Positive(Some(Zatoshis::ZERO)),
        ),
    ] {
        assert!(
            state
                .observe_terminal(tip, now, expectation, CompletionPolicy::default())
                .is_err()
        );
        assert_eq!(state, Lifecycle::default());
    }
    assert_eq!(
        TerminalObservation::from_parts(anchor(200), 5, 199.into(), 10),
        Err(LifecycleError::InvalidState)
    );
    assert_eq!(
        TerminalObservation::from_parts(anchor(200), 5, 210.into(), 4),
        Err(LifecycleError::InvalidState)
    );
    assert!(
        Lifecycle::from_parts(None, ReceiptExpectation::None, Reconciliation::NotStarted).is_err()
    );
    let observation = terminal(ReceiptExpectation::Unknown).terminal();
    assert!(
        Lifecycle::from_parts(
            observation,
            ReceiptExpectation::Unknown,
            Reconciliation::Pending(anchor(209))
        )
        .is_err()
    );
    assert!(
        Lifecycle::from_parts(
            observation,
            ReceiptExpectation::Unknown,
            Reconciliation::Complete {
                target: anchor(220),
                covered_from: 221.into()
            }
        )
        .is_err()
    );
    assert_eq!(
        state.finish_reconciliation(100.into(), result(anchor(220))),
        Err(LifecycleError::NoPendingReconciliation)
    );
}
