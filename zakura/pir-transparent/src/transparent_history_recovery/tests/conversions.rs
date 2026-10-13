use super::*;

#[test]
fn report_outcomes_map_to_progress() {
    let incomplete = |reason| Completion::Incomplete { reason, pending: 3 };
    for (completion, outcome) in [
        (Completion::Complete, Outcome::Complete),
        (incomplete(IncompleteReason::QueryBudget), Outcome::More),
        (incomplete(IncompleteReason::ByteBudget), Outcome::More),
        (incomplete(IncompleteReason::PendingLimit), Outcome::More),
        (
            incomplete(IncompleteReason::PublicationBehind { height: 9 }),
            Outcome::Behind,
        ),
        (
            incomplete(IncompleteReason::Overloaded { shard_id: 1 }),
            Outcome::Overloaded,
        ),
        (
            incomplete(IncompleteReason::ChainUnknown { height: 9 }),
            Outcome::Stalled,
        ),
        (
            incomplete(IncompleteReason::UnresolvedSpends),
            Outcome::Stalled,
        ),
        (
            incomplete(IncompleteReason::DiscoveryUnbounded),
            Outcome::Stalled,
        ),
        (
            incomplete(IncompleteReason::ContentFailed),
            Outcome::Stalled,
        ),
    ] {
        let mut report = report(completion);
        report.covered_through = 77;
        assert_eq!(
            Progress::from_sync_report(&report, false),
            Progress {
                covered_through: 77,
                outcome,
            }
        );
        // A pass clamped to the publication's end is behind even when it
        // completes; an incomplete one keeps its reason.
        let clamped = if outcome == Outcome::Complete {
            Outcome::Behind
        } else {
            outcome
        };
        assert_eq!(
            Progress::from_sync_report(&report, true),
            Progress {
                covered_through: 77,
                outcome: clamped,
            }
        );
    }
}

/// A report's failed entries are counted, and those at three failures counted again
/// as held.
#[test]
fn failed_entries_are_counted_from_the_report() {
    let mut report = report(Completion::Incomplete {
        reason: IncompleteReason::ContentFailed,
        pending: 0,
    });
    assert_eq!(FailedEntries::of(&report), FailedEntries::default());
    report.failed_entries = [(0, 1), (0, 3), (2, 2), (4, 3)]
        .into_iter()
        .map(|(shard_id, failures)| transparent_wallet::FailedEntry {
            shard_id,
            script: vec![failures as u8],
            failures,
        })
        .collect();
    assert_eq!(
        FailedEntries::of(&report),
        FailedEntries {
            entries: 4,
            held: 2
        }
    );
}

#[test]
fn metadata_conversion_preserves_exact_zero_unknown_and_coinbase() {
    for fee in [
        FeeState::Exact(0),
        FeeState::Unknown,
        FeeState::NotApplicable,
    ] {
        let converted = ledger_metadata(Some(transparent_events::TransactionMetadata {
            fee,
            transparent_input_count: 0,
            has_shielded_components: true,
        }))
        .unwrap()
        .unwrap();
        assert!(converted.has_shielded_components);
        match fee {
            FeeState::Exact(_) => {
                assert_eq!(converted.fee, WholeTransactionFee::Exact(Zatoshis::ZERO))
            }
            FeeState::Unknown => assert_eq!(converted.fee, WholeTransactionFee::Unknown),
            FeeState::NotApplicable => {
                assert_eq!(converted.fee, WholeTransactionFee::NotApplicable)
            }
        }
    }
    assert_eq!(ledger_metadata(None).unwrap(), None);
    assert!(
        ledger_metadata(Some(transparent_events::TransactionMetadata {
            fee: FeeState::Exact(u64::MAX),
            transparent_input_count: 1,
            has_shielded_components: false
        }))
        .is_err()
    );
}
