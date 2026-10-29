//! Normalizes NEAR Intents 1Click execution statuses into the provider-neutral
//! [`Observation`] that one-time IVK stores record. Apps fetch statuses
//! themselves and pass the fields that set local operation ownership and receipt
//! expectations as a [`NearStatus`]. A status never proves or discovers a payment.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use zakura_one_time_ivk::{
    Purpose,
    swap::{Observation, OperationStatus, ReceiptExpectation},
};
use zcash_protocol::{TxId, value::Zatoshis};

/// The fields of a NEAR 1Click status response that set operation ownership and
/// receipt expectations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NearStatus<'a> {
    /// The `status` string.
    pub status: &'a str,
    /// The quote request's `swapType`, such as `EXACT_OUTPUT`.
    pub swap_type: Option<&'a str>,
    /// `swapDetails.refundedAmount` in the origin asset's base units.
    pub refunded_amount: Option<Zatoshis>,
    /// `swapDetails.amountOut` in the destination asset's base units.
    pub amount_out: Option<Zatoshis>,
    /// The `hash` of each `swapDetails.originChainTxHashes` entry. On a refund key's
    /// Zcash-origin swap these include the refund as well as the wallet's own deposit,
    /// which pays the deposit address rather than the refund key.
    pub origin_tx_hashes: &'a [&'a str],
    /// The `hash` of each `swapDetails.destinationChainTxHashes` entry, which holds an
    /// incoming swap's Zcash payout.
    pub destination_tx_hashes: &'a [&'a str],
}

/// Normalizes a NEAR status response for a key of `purpose`. An unrecognized
/// status counts as active, so it neither releases an address nor settles an
/// expected receipt.
///
/// A refund key expects ZEC whenever the provider reports a positive refunded
/// amount. Without a reported amount, an exact-output `SUCCESS` still expects one,
/// since it returns unused input once the swap completes. Any other `SUCCESS` with
/// no positive refunded amount expects none, so its refund key can retire. 1Click
/// refunds a `FAILED` swap's deposit like a `REFUNDED` one, and a refund on the
/// source chain is not a Zcash receipt. A zero payout amount is treated as
/// unreported. Every status from `KNOWN_DEPOSIT_TX` on, including `FAILED`,
/// implies a deposit; `PENDING_DEPOSIT` and an unrecognized status do not.
///
/// An incoming key's receipts are the destination-chain transactions. A refund key's
/// are the origin-chain ones plus the destination-chain ones, since NEAR sometimes
/// files a ZEC refund under the destination, as the receiver indexer also allows. A
/// hash from the other chain only names a candidate that never pays the key. Each hash
/// is read as a canonical Zcash transaction ID, and one that is not is skipped.
pub fn near_observation(purpose: Purpose, status: &NearStatus<'_>) -> Observation {
    use OperationStatus::*;
    use ReceiptExpectation::Positive;
    let refund = status.refunded_amount.filter(|v| !v.is_zero());
    let refund_reported = status.refunded_amount.is_some();
    let outcome = match (status.status, purpose) {
        ("PENDING_DEPOSIT", _) => AwaitingDeposit,
        // INCOMPLETE_DEPOSIT is not final: an underpayment is refunded around the deadline.
        ("KNOWN_DEPOSIT_TX" | "INCOMPLETE_DEPOSIT" | "PROCESSING", _) => Active,
        ("SUCCESS", Purpose::Receive) => {
            Terminal(Positive(status.amount_out.filter(|v| !v.is_zero())))
        }
        ("SUCCESS", Purpose::Refund) => Terminal(match (refund, status.swap_type) {
            (Some(value), _) => Positive(Some(value)),
            (None, Some("EXACT_OUTPUT")) if !refund_reported => Positive(None),
            (None, _) => ReceiptExpectation::None,
        }),
        ("REFUNDED" | "FAILED", Purpose::Refund) => Terminal(Positive(refund)),
        ("REFUNDED" | "FAILED", Purpose::Receive) => Terminal(ReceiptExpectation::None),
        _ => Active,
    };
    let funded = matches!(
        status.status,
        "KNOWN_DEPOSIT_TX"
            | "INCOMPLETE_DEPOSIT"
            | "PROCESSING"
            | "SUCCESS"
            | "REFUNDED"
            | "FAILED"
    );
    let hashes: &[&[&str]] = match purpose {
        Purpose::Receive => &[status.destination_tx_hashes],
        Purpose::Refund => &[status.origin_tx_hashes, status.destination_tx_hashes],
        _ => &[],
    };
    let mut receipts: Vec<TxId> = vec![];
    for txid in hashes
        .iter()
        .copied()
        .flatten()
        .filter_map(|h| TxId::from_hex(h))
    {
        if !receipts.contains(&txid) {
            receipts.push(txid);
        }
    }
    Observation {
        status: outcome,
        funded,
        receipts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_one_time_ivk::Purpose::*;

    /// The normalized status of `status` for a key of `purpose`.
    fn observe(purpose: Purpose, status: NearStatus<'_>) -> Option<OperationStatus> {
        Some(near_observation(purpose, &status).status)
    }

    #[test]
    fn provider_outcomes_preserve_direction_and_unknowns() {
        let status = |status| NearStatus {
            status,
            ..Default::default()
        };
        let positive = |v| Some(OperationStatus::Terminal(ReceiptExpectation::Positive(v)));
        assert_eq!(
            observe(Refund, status("PROCESSING")),
            Some(OperationStatus::Active)
        );
        assert_eq!(
            observe(Receive, status("PENDING_DEPOSIT")),
            Some(OperationStatus::AwaitingDeposit)
        );
        assert_eq!(observe(Refund, status("REFUNDED")), positive(None));
        assert_eq!(
            observe(Receive, status("REFUNDED")),
            Some(OperationStatus::Terminal(ReceiptExpectation::None))
        );
        assert_eq!(observe(Receive, status("SUCCESS")), positive(None));
        assert_eq!(
            observe(Refund, status("SUCCESS")),
            Some(OperationStatus::Terminal(ReceiptExpectation::None))
        );
        // 1Click returns a failed swap's deposit to the refund address on the origin chain.
        assert_eq!(observe(Refund, status("FAILED")), positive(None));
        assert_eq!(
            observe(Receive, status("FAILED")),
            Some(OperationStatus::Terminal(ReceiptExpectation::None))
        );
        assert_eq!(
            observe(Refund, status("NEW_STATE")),
            Some(OperationStatus::Active)
        );
    }

    /// A deposit seen but not yet swapped stays in progress for either key purpose. An
    /// underpayment (`INCOMPLETE_DEPOSIT`) is refunded around the deadline, so treating
    /// it as final could settle a refund key's expected receipt before the refund arrives.
    #[test]
    fn deposits_in_progress_are_not_final() {
        for status in ["KNOWN_DEPOSIT_TX", "INCOMPLETE_DEPOSIT", "PROCESSING"] {
            for purpose in [Refund, Receive] {
                let observed = observe(
                    purpose,
                    NearStatus {
                        status,
                        ..Default::default()
                    },
                );
                assert_eq!(observed, Some(OperationStatus::Active), "{status}");
            }
        }
    }

    #[test]
    fn amounts_set_receipt_expectations() {
        let amount = Zatoshis::const_from_u64(1_000);
        let positive = |v| Some(OperationStatus::Terminal(ReceiptExpectation::Positive(v)));
        // Excess deposits come back after SUCCESS.
        let refunded = NearStatus {
            status: "SUCCESS",
            refunded_amount: Some(amount),
            ..Default::default()
        };
        assert_eq!(observe(Refund, refunded), positive(Some(amount)));
        let failed = NearStatus {
            status: "FAILED",
            refunded_amount: Some(amount),
            ..Default::default()
        };
        assert_eq!(observe(Refund, failed), positive(Some(amount)));
        assert_eq!(
            observe(Receive, failed),
            Some(OperationStatus::Terminal(ReceiptExpectation::None))
        );
        // A source-chain refund on an incoming swap is never a Zcash receipt.
        let incoming_refund = NearStatus {
            status: "REFUNDED",
            refunded_amount: Some(amount),
            ..Default::default()
        };
        assert_eq!(
            observe(Receive, incoming_refund),
            Some(OperationStatus::Terminal(ReceiptExpectation::None))
        );
        let zero_payout = NearStatus {
            status: "SUCCESS",
            amount_out: Some(Zatoshis::ZERO),
            ..Default::default()
        };
        assert_eq!(observe(Receive, zero_payout), positive(None));
        let payout = NearStatus {
            status: "SUCCESS",
            amount_out: Some(amount),
            ..Default::default()
        };
        assert_eq!(
            near_observation(Receive, &payout),
            Observation {
                status: OperationStatus::Terminal(ReceiptExpectation::Positive(Some(amount))),
                funded: true,
                receipts: vec![],
            }
        );
    }

    #[test]
    fn statuses_after_a_deposit_are_funded() {
        for purpose in [Receive, Refund] {
            for (status, funded) in [
                ("PENDING_DEPOSIT", false),
                ("NEW_STATE", false),
                ("KNOWN_DEPOSIT_TX", true),
                ("INCOMPLETE_DEPOSIT", true),
                ("PROCESSING", true),
                ("SUCCESS", true),
                ("REFUNDED", true),
                ("FAILED", true),
            ] {
                let status = NearStatus {
                    status,
                    ..Default::default()
                };
                assert_eq!(
                    near_observation(purpose, &status).funded,
                    funded,
                    "{purpose:?} {status:?}"
                );
            }
        }
    }

    /// A refund `SUCCESS` is conclusive. Without a positive refunded amount it expects no
    /// refund, whatever the swap type, except that an exact-output swap with no reported
    /// amount still expects its unused input back.
    #[test]
    fn refund_success_expects_a_refund_only_when_one_is_due() {
        use ReceiptExpectation::{None as NoReceipt, Positive};
        let amount = Zatoshis::const_from_u64(1_000);
        // The expectations with an absent and a zero refunded amount.
        let cases = [
            (None, NoReceipt, NoReceipt),
            (Some(""), NoReceipt, NoReceipt),
            (Some("FLEX_INPUT"), NoReceipt, NoReceipt),
            (Some("EXACT_INPUT"), NoReceipt, NoReceipt),
            // A reported zero is the exact-output refund, so none is expected.
            (Some("EXACT_OUTPUT"), Positive(None), NoReceipt),
        ];
        for (swap_type, absent, zero) in cases {
            for (refunded_amount, expected) in [(None, absent), (Some(Zatoshis::ZERO), zero)] {
                let status = NearStatus {
                    status: "SUCCESS",
                    swap_type,
                    refunded_amount,
                    ..Default::default()
                };
                assert_eq!(
                    observe(Refund, status),
                    Some(OperationStatus::Terminal(expected)),
                    "{swap_type:?} {refunded_amount:?}"
                );
            }
            // A positive refunded amount is authoritative whatever the swap type.
            let status = NearStatus {
                status: "SUCCESS",
                swap_type,
                refunded_amount: Some(amount),
                ..Default::default()
            };
            assert_eq!(
                observe(Refund, status),
                Some(OperationStatus::Terminal(Positive(Some(amount)))),
                "{swap_type:?}"
            );
        }
    }

    /// A payout is read from the destination side, and a refund from both sides,
    /// skipping any hash that is not a txid and any repeat.
    #[test]
    fn receipts_come_from_the_zcash_side_of_the_swap() {
        let payout = TxId::from_bytes([1; 32]);
        let refund = TxId::from_bytes([2; 32]);
        let (payout_hex, refund_hex) = (payout.to_string(), refund.to_string());
        let destination = [payout_hex.as_str(), "0xnot-a-txid"];
        let origin = [refund_hex.as_str()];
        let status = NearStatus {
            status: "SUCCESS",
            origin_tx_hashes: &origin,
            destination_tx_hashes: &destination,
            ..Default::default()
        };
        assert_eq!(near_observation(Receive, &status).receipts, [payout]);
        assert_eq!(near_observation(Refund, &status).receipts, [refund, payout]);
    }

    /// A ZEC refund NEAR filed under the destination hashes is still a refund receipt.
    #[test]
    fn a_refund_listed_under_the_destination_is_read() {
        let refund = TxId::from_bytes([2; 32]);
        let refund_hex = refund.to_string();
        let both = [refund_hex.as_str()];
        let status = NearStatus {
            status: "REFUNDED",
            origin_tx_hashes: &[],
            destination_tx_hashes: &both,
            ..Default::default()
        };
        assert_eq!(near_observation(Refund, &status).receipts, [refund]);
        let twice = NearStatus {
            origin_tx_hashes: &both,
            ..status
        };
        assert_eq!(near_observation(Refund, &twice).receipts, [refund]);
    }
}
