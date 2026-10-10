//! An account's receipt of a transaction: its history view and transparent detail view, and
//! the display-level conclusions they support together.
//!
//! Only this read combines display facts with history. Nothing here is stored, and the history
//! view it returns is the one [`transaction_history_details`] gives without display facts.
//! These rules reproduce the receipt conclusions Vizor drew from the same views.

use std::collections::BTreeMap;

use rusqlite::Connection;
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::transparent_ledger::{
    AccountActivity, Attribution, FeeState, OutputRef, ReceiptAttribution, ReceiptSource,
    SourcePool, TransactionHistoryDetails, TransactionReceipt, TransparentDisplayAddress,
    TransparentDisplayDetails, TransparentDisplayOmission, TransparentDisplaySource,
    TransparentDisplayView, TransparentDisplayViewSender, TransparentLedgerMode,
};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::{PoolType, consensus};

use crate::{AccountUuid, error::SqliteClientError};

use super::super::history::{ReceiptEvidence, receipt_evidence, transaction_history_details};
use super::view::view;

#[cfg(feature = "transparent-inputs")]
use zcash_keys::keys::transparent::gap_limits::GapLimits;

/// Returns `account`'s receipt of `txid`, or `None` when it has no history entry for it. The
/// caller provides the read snapshot.
pub(crate) fn receipt<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    #[cfg(feature = "transparent-inputs")] gap_limits: &GapLimits,
    configured: Option<TransparentLedgerMode>,
    account: AccountUuid,
    txid: TxId,
) -> Result<Option<TransactionReceipt>, SqliteClientError> {
    let Some(details) = transaction_history_details(
        conn,
        params,
        #[cfg(feature = "transparent-inputs")]
        gap_limits,
        configured,
        account,
        &[txid],
    )?
    .pop() else {
        return Ok(None);
    };
    let evidence = receipt_evidence(conn, account, &txid)?.ok_or_else(|| {
        SqliteClientError::CorruptedData("history entry without its transaction".into())
    })?;
    let display = view(conn, params, configured, account, txid)?;
    let attribution = attribution(params, &details, display.as_ref(), &evidence);
    Ok(Some(TransactionReceipt {
        details,
        display,
        attribution,
    }))
}

/// What the history view and the transparent detail view establish together; see
/// [`ReceiptAttribution`] for each rule.
pub(super) fn attribution<P: consensus::Parameters>(
    params: &P,
    details: &TransactionHistoryDetails,
    display: Option<&TransparentDisplayView>,
    evidence: &ReceiptEvidence,
) -> ReceiptAttribution {
    let available = match display {
        Some(TransparentDisplayView::Available(view)) => Some(view),
        _ => None,
    };
    let effects_settled = details.effects.iter().all(|e| e.completeness.is_settled())
        && details.mined_height.is_some()
        && !evidence.unknown_transparent_scope;
    // The account's fee, or the whole fee when it spent and its share is not attributed.
    let fee = match details.fee {
        FeeState::Known(fee) | FeeState::Unattributed { whole: fee } => Some(fee.into_u64()),
        FeeState::Unknown | FeeState::NotApplicable => None,
    };
    let accounts_for_movement =
        available.is_some_and(|view| rows_account_for_movement(details, view, fee));

    let recipient = match available {
        Some(view) if fee.is_some() && accounts_for_movement => recipient(view),
        _ => Attribution::NotEstablished,
    };
    let recipient_completes = matches!(recipient, Attribution::Established(_)) && effects_settled;

    let source = source(params, evidence.raw.as_deref(), available);
    let received_row: &[OutputRef] = match &details.activity {
        AccountActivity::Outputs {
            received: Some(rows),
            ..
        }
        | AccountActivity::InferredOutgoing {
            received: Some(rows),
            ..
        } => &rows.outputs,
        _ => &[],
    };
    let receive_completes = effects_settled
        && source.is_known()
        && !received_row.is_empty()
        && received_row
            .iter()
            .all(|output| output.pool == PoolType::Transparent)
        && accounts_for_movement;

    ReceiptAttribution {
        effects_settled,
        accounts_for_movement,
        recipient,
        recipient_completes,
        source,
        receive_completes,
    }
}

/// Whether the view's rows account for the account's whole effect: no shared or mixed funding
/// is reported, every transparent output is listed, and the account's balance moved by exactly
/// what they say: minus `fee` and the outputs it does not own, or, without a fee, the outputs it
/// owns.
fn rows_account_for_movement(
    details: &TransactionHistoryDetails,
    view: &TransparentDisplayDetails,
    fee: Option<u64>,
) -> bool {
    if view.outputs.is_empty()
        || view.outputs.len() != view.output_count as usize
        || view.omissions.iter().any(|omission| {
            matches!(
                omission,
                TransparentDisplayOmission::SharedFunding
                    | TransparentDisplayOmission::ShieldedAndTransparentFunding
            )
        })
    {
        return false;
    }
    let sum = |owned: bool| -> i128 {
        view.outputs
            .iter()
            .filter(|output| output.owned == owned)
            .map(|output| i128::from(output.value.into_u64()))
            .sum()
    };
    let expected = match fee {
        Some(fee) => -(sum(false) + i128::from(fee)),
        None => sum(true),
    };
    details.account_movement.net() == expected
}

/// The only row the account does not own; with none, its own address when the rows it owns
/// have exactly one.
fn recipient(view: &TransparentDisplayDetails) -> Attribution<TransparentDisplayAddress> {
    let others: Vec<_> = view.outputs.iter().filter(|output| !output.owned).collect();
    let recipient = match others.as_slice() {
        [one] => one.address.clone(),
        [] => {
            let own: BTreeMap<&str, &TransparentDisplayAddress> = view
                .outputs
                .iter()
                .filter_map(|output| output.address.as_ref())
                .map(|address| (address.encoded.as_str(), address))
                .collect();
            match own.into_values().collect::<Vec<_>>().as_slice() {
                [address] => Some((*address).clone()),
                _ => None,
            }
        }
        _ => None,
    };
    recipient.map_or(Attribution::NotEstablished, Attribution::Established)
}

/// The receipt's source: the raw transaction's reading, completed by the view's.
fn source<P: consensus::Parameters>(
    params: &P,
    raw: Option<&[u8]>,
    view: Option<&TransparentDisplayDetails>,
) -> ReceiptSource {
    let mut source = raw_source(params, raw);
    if source.address.is_some() {
        return source;
    }
    let Some(view) = view else {
        return source;
    };
    match (&view.sender, source.pool) {
        // Raw bytes already decided a shielded source when present.
        (TransparentDisplayViewSender::Shielded, SourcePool::Unknown)
            if matches!(view.source, TransparentDisplaySource::Display(_)) =>
        {
            source.pool = SourcePool::Shielded;
        }
        // A transparent source the raw reading could not name (a P2SH or uncompressed-key
        // spend) gains the view's address.
        (
            TransparentDisplayViewSender::Address {
                address,
                owned: false,
            },
            SourcePool::Unknown | SourcePool::Transparent,
        ) => {
            source.address = Some(address.clone());
            source.pool = SourcePool::Transparent;
        }
        _ => {}
    }
    source
}

/// The stored raw transaction's source: shielded without a transparent input, else the first
/// input whose unlocking script ends with a compressed public key.
fn raw_source<P: consensus::Parameters>(params: &P, raw: Option<&[u8]>) -> ReceiptSource {
    let unknown = ReceiptSource {
        pool: SourcePool::Unknown,
        address: None,
    };
    let Some(raw) = raw else {
        return unknown;
    };
    let Ok(tx) = Transaction::read(raw, consensus::BranchId::Sapling) else {
        return unknown;
    };
    let Some(bundle) = tx.transparent_bundle().filter(|b| !b.vin.is_empty()) else {
        return ReceiptSource {
            pool: SourcePool::Shielded,
            address: None,
        };
    };
    ReceiptSource {
        pool: SourcePool::Transparent,
        address: bundle.vin.iter().find_map(|input| {
            let key = compressed_key(&input.script_sig().0.0)?;
            let address = TransparentAddress::PublicKeyHash(transparent::util::hash160::hash(key));
            Some(TransparentDisplayAddress {
                encoded: zcash_keys::encoding::encode_transparent_address_p(params, &address),
                address,
            })
        }),
    }
}

/// The last 33-byte push starting with `0x02` or `0x03` of a script of direct pushes.
fn compressed_key(script: &[u8]) -> Option<&[u8]> {
    let mut pushes = Vec::new();
    let mut index = 0;
    while index < script.len() {
        let opcode = script[index];
        index += 1;
        let len = match opcode {
            0x01..=0x4b => usize::from(opcode),
            0x4c => {
                let len = usize::from(*script.get(index)?);
                index += 1;
                len
            }
            0x4d => {
                let bytes = script.get(index..index + 2)?;
                index += 2;
                usize::from(u16::from_le_bytes([bytes[0], bytes[1]]))
            }
            _ => return None,
        };
        pushes.push(script.get(index..index + len)?);
        index += len;
    }
    pushes
        .into_iter()
        .rev()
        .find(|push| push.len() == 33 && matches!(push.first(), Some(0x02 | 0x03)))
}

#[cfg(test)]
mod tests {
    //! Vizor's receipt regressions, ported to these rules. Integration tests through the read
    //! are in `tests/recovery/activation/transparent_detail.rs`.

    use transparent::address::TransparentAddress;
    use zcash_client_backend::data_api::transparent_ledger::{
        AccountActivity, AccountMovement, ActivityOutputs, AggregatePayment, Attribution,
        DetailCompleteness, EffectCompleteness, FeeState, FundingStepEvidence,
        HistoryClassification, OutputRef, PoolEffect, ReceiptAttribution, ReceiptSource,
        SourcePool, TransactionHistoryDetails, TransparentDisplayAddress,
        TransparentDisplayDetails, TransparentDisplayOmission, TransparentDisplayProvenance,
        TransparentDisplaySource, TransparentDisplayView, TransparentDisplayViewOutput,
        TransparentDisplayViewSender, WholeTransactionFee,
    };
    use zcash_primitives::transaction::TxId;
    use zcash_protocol::{
        PoolType,
        consensus::{BlockHeight, Network},
        value::Zatoshis,
    };

    use super::{attribution, compressed_key};
    use crate::wallet::transparent_ledger::history::ReceiptEvidence;

    const PAYEE: u8 = 1;
    const OTHER_PAYEE: u8 = 2;
    const SELF: u8 = 3;
    const FUNDER: u8 = 4;

    fn zat(value: u64) -> Zatoshis {
        Zatoshis::const_from_u64(value)
    }

    fn address(tag: u8) -> TransparentDisplayAddress {
        TransparentDisplayAddress {
            address: TransparentAddress::PublicKeyHash([tag; 20]),
            encoded: format!("t1-{tag}"),
        }
    }

    fn row(index: u32, tag: u8, value: u64, owned: bool) -> TransparentDisplayViewOutput {
        TransparentDisplayViewOutput {
            index,
            value: zat(value),
            address: Some(address(tag)),
            owned,
        }
    }

    fn display_facts() -> TransparentDisplaySource {
        TransparentDisplaySource::Display(TransparentDisplayProvenance {
            shard_id: 0,
            revision: 0,
            map_sha256: [0; 32],
            looked_up_height: BlockHeight::from_u32(1),
        })
    }

    fn view_with(
        outputs: Vec<TransparentDisplayViewOutput>,
        output_count: u32,
        omissions: Vec<TransparentDisplayOmission>,
        sender: TransparentDisplayViewSender,
    ) -> TransparentDisplayView {
        TransparentDisplayView::Available(TransparentDisplayDetails {
            coinbase: false,
            fee: WholeTransactionFee::Unknown,
            input_count: 1,
            output_count,
            shielded: true,
            sender,
            outputs,
            omissions,
            source: display_facts(),
        })
    }

    fn view(outputs: Vec<TransparentDisplayViewOutput>, count: u32) -> TransparentDisplayView {
        view_with(
            outputs,
            count,
            vec![],
            TransparentDisplayViewSender::NonStandard,
        )
    }

    fn funder() -> TransparentDisplayViewSender {
        TransparentDisplayViewSender::Address {
            address: address(FUNDER),
            owned: false,
        }
    }

    /// A mined transaction whose net movement is `net`, the account having spent `spent` of it,
    /// whose activity's received row counts `received` (pool and value), and whose effects are
    /// settled or not.
    fn details(
        net: i128,
        spent: u64,
        fee: FeeState,
        received: Option<(PoolType, u64)>,
        settled: bool,
    ) -> TransactionHistoryDetails {
        let completeness = if settled {
            EffectCompleteness::Complete
        } else {
            EffectCompleteness::Incomplete
        };
        let received_value = u64::try_from(net + i128::from(spent)).unwrap();
        TransactionHistoryDetails {
            has_transparent_outputs: None,
            transaction_metadata: None,
            whole_fee: None,
            aggregate_payment: AggregatePayment::Unknown,
            inferred_outgoing: None,
            account_movement: AccountMovement {
                received: received_value,
                spent,
                complete: settled,
            },
            txid: TxId::from_bytes([7; 32]),
            mined_height: Some(BlockHeight::from_u32(100)),
            effects: vec![PoolEffect {
                pool: PoolType::Transparent,
                received: zat(received_value),
                spent: zat(spent),
                completeness,
            }],
            payment_details: DetailCompleteness::Incomplete,
            fee,
            classification: HistoryClassification::Provisional,
            activity: AccountActivity::Outputs {
                sent: None,
                received: received.map(|(pool, value)| ActivityOutputs {
                    amount: zat(value),
                    outputs: vec![OutputRef { pool, index: 0 }],
                }),
            },
            funding_step: FundingStepEvidence::default(),
            pending_private_details: vec![],
        }
    }

    const EVIDENCE: ReceiptEvidence = ReceiptEvidence {
        unknown_transparent_scope: false,
        raw: None,
    };

    fn attribute(
        details: &TransactionHistoryDetails,
        view: &TransparentDisplayView,
    ) -> ReceiptAttribution {
        attribution(&Network::MainNetwork, details, Some(view), &EVIDENCE)
    }

    fn known(fee: u64) -> FeeState {
        FeeState::Known(zat(fee))
    }

    #[test]
    fn shared_or_mixed_funding_keeps_receipt_attribution_incomplete() {
        for omission in [
            TransparentDisplayOmission::SharedFunding,
            TransparentDisplayOmission::ShieldedAndTransparentFunding,
        ] {
            for received in [false, true] {
                // A foreign input of 50 000 can pay an unseen shielded output of 50 000 without
                // changing the equality for this account: its debit still matches its
                // transparent outputs and fee.
                let (details, rows) = if received {
                    (
                        details(
                            -10_000,
                            110_000,
                            known(10_000),
                            Some((PoolType::Transparent, 100_000)),
                            true,
                        ),
                        vec![row(0, SELF, 100_000, true)],
                    )
                } else {
                    (
                        details(-110_000, 110_000, known(10_000), None, true),
                        vec![row(0, PAYEE, 100_000, false)],
                    )
                };
                let control = attribute(&details, &view_with(rows.clone(), 1, vec![], funder()));
                assert!(control.accounts_for_movement && control.recipient_completes);
                assert_eq!(control.receive_completes, received);

                let shared = attribute(&details, &view_with(rows, 1, vec![omission], funder()));
                assert_eq!(
                    shared.recipient,
                    Attribution::NotEstablished,
                    "{omission:?}"
                );
                assert!(!shared.accounts_for_movement, "{omission:?}");
                assert!(!shared.recipient_completes && !shared.receive_completes);
            }
        }
    }

    #[test]
    fn display_recipient_names_the_only_payee_of_a_private_send() {
        let recipient = |details: TransactionHistoryDetails,
                         rows: Vec<TransparentDisplayViewOutput>,
                         count: u32| {
            let a = attribute(&details, &view(rows, count));
            // An established recipient, and only that, completes a settled send.
            assert_eq!(
                a.recipient_completes,
                matches!(a.recipient, Attribution::Established(_))
            );
            a.recipient
        };
        let send = |net: i128, spent: u64, fee| details(net, spent, fee, None, true);
        // Unshielding to the account's own address: the balance moved by the fee only.
        assert_eq!(
            recipient(
                send(-15_000, 1_015_000, known(15_000)),
                vec![row(0, SELF, 1_000_000, true)],
                1
            ),
            Attribution::Established(address(SELF))
        );
        // A regular send, and a zcashd send with transparent change.
        assert_eq!(
            recipient(
                send(-60_000, 60_000, known(10_000)),
                vec![row(0, PAYEE, 50_000, false)],
                1
            ),
            Attribution::Established(address(PAYEE))
        );
        assert_eq!(
            recipient(
                send(-60_000, 67_000, known(10_000)),
                vec![row(0, PAYEE, 50_000, false), row(1, SELF, 7_000, true)],
                2
            ),
            Attribution::Established(address(PAYEE))
        );
        // The whole fee stands in for an unattributed share.
        assert_eq!(
            recipient(
                send(
                    -60_000,
                    60_000,
                    FeeState::Unattributed { whole: zat(10_000) }
                ),
                vec![row(0, PAYEE, 50_000, false)],
                1
            ),
            Attribution::Established(address(PAYEE))
        );
        // Value the listed outputs do not account for went to an unseen payee; two payees;
        // outputs beyond the listed ones; an unknown fee.
        for (details, rows, count) in [
            (
                send(-60_000, 67_000, known(10_000)),
                vec![row(0, SELF, 7_000, true)],
                1,
            ),
            (
                send(-60_000, 60_000, known(10_000)),
                vec![
                    row(0, PAYEE, 25_000, false),
                    row(1, OTHER_PAYEE, 25_000, false),
                ],
                2,
            ),
            (
                send(-60_000, 60_000, known(10_000)),
                vec![row(0, PAYEE, 50_000, false)],
                3,
            ),
            (
                send(-60_000, 60_000, FeeState::Unknown),
                vec![row(0, PAYEE, 50_000, false)],
                1,
            ),
        ] {
            assert_eq!(recipient(details, rows, count), Attribution::NotEstablished);
        }
        // The only payee of an unsettled send is named, but it completes nothing: the balance
        // can still change. So for an unmined send or an owned output of unknown scope.
        let regular = view(vec![row(0, PAYEE, 50_000, false)], 1);
        let mut unmined = send(-60_000, 60_000, known(10_000));
        unmined.mined_height = None;
        for (details, evidence) in [
            (
                details(-60_000, 60_000, known(10_000), None, false),
                EVIDENCE,
            ),
            (unmined, EVIDENCE),
            (
                send(-60_000, 60_000, known(10_000)),
                ReceiptEvidence {
                    unknown_transparent_scope: true,
                    raw: None,
                },
            ),
        ] {
            let a = attribution(&Network::MainNetwork, &details, Some(&regular), &evidence);
            assert_eq!(a.recipient, Attribution::Established(address(PAYEE)));
            assert!(!a.effects_settled && !a.recipient_completes);
        }
        // Without a fee, a receive names no recipient.
        assert_eq!(
            recipient(
                details(5, 0, FeeState::NotApplicable, None, true),
                vec![row(0, SELF, 5, true)],
                1
            ),
            Attribution::NotEstablished
        );
    }

    #[test]
    fn display_details_complete_a_receive_they_account_for() {
        let completes = |details: TransactionHistoryDetails, sender| {
            let display = view_with(vec![row(0, SELF, 1_000_000, true)], 1, vec![], sender);
            attribute(&details, &display).receive_completes
        };
        let receive = |net, spent, fee, pool, settled| {
            details(net, spent, fee, Some((pool, 1_000_000)), settled)
        };
        let shielded = TransparentDisplayViewSender::Shielded;
        // The receive leg of an unshielding to the account's own address, and a receive from
        // another wallet's address: complete once settled.
        for settled in [true, false] {
            assert_eq!(
                completes(
                    receive(
                        -15_000,
                        1_015_000,
                        known(15_000),
                        PoolType::Transparent,
                        settled
                    ),
                    shielded.clone()
                ),
                settled
            );
            assert_eq!(
                completes(
                    receive(
                        1_000_000,
                        0,
                        FeeState::NotApplicable,
                        PoolType::Transparent,
                        settled
                    ),
                    funder()
                ),
                settled
            );
        }
        // An owned effect the rows do not show, an unknown source, a shielded receipt (its memo
        // is unknown privately).
        assert!(!completes(
            receive(
                1_500_000,
                0,
                FeeState::NotApplicable,
                PoolType::Transparent,
                true
            ),
            funder()
        ));
        assert!(!completes(
            receive(
                1_000_000,
                0,
                FeeState::NotApplicable,
                PoolType::Transparent,
                true
            ),
            TransparentDisplayViewSender::NonStandard
        ));
        assert!(!completes(
            receive(-15_000, 1_015_000, known(15_000), PoolType::ORCHARD, true),
            shielded
        ));
    }

    #[test]
    fn display_source_only_fills_an_unknown_source() {
        let details = details(
            1_000_000,
            0,
            FeeState::NotApplicable,
            Some((PoolType::Transparent, 1_000_000)),
            true,
        );
        let source = |sender, source: TransparentDisplaySource| {
            let TransparentDisplayView::Available(mut facts) =
                view_with(vec![row(0, SELF, 1_000_000, true)], 1, vec![], sender)
            else {
                unreachable!()
            };
            facts.source = source;
            attribute(&details, &TransparentDisplayView::Available(facts)).source
        };
        let unknown = ReceiptSource {
            pool: SourcePool::Unknown,
            address: None,
        };
        // Validated display facts fill a shielded source; a raw transaction already decided
        // it, so its view adds none.
        assert_eq!(
            source(TransparentDisplayViewSender::Shielded, display_facts()),
            ReceiptSource {
                pool: SourcePool::Shielded,
                address: None
            }
        );
        assert_eq!(
            source(
                TransparentDisplayViewSender::Shielded,
                TransparentDisplaySource::RawTransaction
            ),
            unknown
        );
        // A funding address the account does not own fills an unknown source, from either.
        for from in [display_facts(), TransparentDisplaySource::RawTransaction] {
            assert_eq!(
                source(funder(), from),
                ReceiptSource {
                    pool: SourcePool::Transparent,
                    address: Some(address(FUNDER)),
                }
            );
        }
        // An address the account owns, no address, or coinbase name no source.
        for sender in [
            TransparentDisplayViewSender::Address {
                address: address(SELF),
                owned: true,
            },
            TransparentDisplayViewSender::NonStandard,
            TransparentDisplayViewSender::Coinbase,
        ] {
            assert_eq!(source(sender, display_facts()), unknown);
        }
        // Without available details nothing is established.
        for display in [
            None,
            Some(TransparentDisplayView::Pending),
            Some(TransparentDisplayView::NotCovered),
        ] {
            let a = attribution(&Network::MainNetwork, &details, display.as_ref(), &EVIDENCE);
            assert_eq!(a.source, unknown);
            assert!(!a.accounts_for_movement && !a.receive_completes);
            assert_eq!(a.recipient, Attribution::NotEstablished);
        }
    }

    #[test]
    fn a_raw_source_is_the_last_compressed_key_pushed() {
        let key = [[0x02].as_slice(), &[7; 32]].concat();
        let signature = [0x30; 71];
        let script = [&[71u8][..], &signature, &[33], &key].concat();
        assert_eq!(compressed_key(&script), Some(key.as_slice()));
        // An uncompressed key, or a script that is not only direct pushes, has none.
        let uncompressed = [&[65u8][..], &[0x04; 65]].concat();
        assert_eq!(compressed_key(&uncompressed), None);
        assert_eq!(compressed_key(&[0x00]), None);
    }
}
