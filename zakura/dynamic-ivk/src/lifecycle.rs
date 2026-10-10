//! Shared completion policy for keys that receive swap payouts and refunds. Wallet
//! storage owns canonical-chain validation, receipt attribution, and atomic
//! persistence of this state with scanning.

use zcash_protocol::value::Zatoshis;

/// Seconds a key found only by a restore sweep keeps scanning, for a payout or
/// refund from a swap in flight at restore. Like [`COMPLETION_LIMIT_SECS`], a
/// wallet convention, not a consensus parameter.
pub const RESTORE_WATCH_SECS: i64 = 24 * 60 * 60;

/// Seconds after the quote deadline, or after registration when no deadline is
/// known, after which a key stops scanning whatever the provider reports.
pub const COMPLETION_LIMIT_SECS: i64 = 30 * 24 * 60 * 60;

/// The route adapter's interpretation of the expected Zcash receipt.
/// Incoming source-chain refunds must not be interpreted as Zcash refunds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptExpectation {
    /// The supported route explicitly establishes that no Zcash receipt is expected.
    None,
    /// A positive receipt is expected. `None` means its amount is unavailable.
    Positive(Option<Zatoshis>),
    /// Receipt details are missing, malformed, or otherwise inconclusive.
    Unknown,
}

/// Provider outcome normalized by direction. It schedules scanning but never
/// establishes ownership, inclusion, or an on-chain amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationStatus {
    /// The provider is waiting for a deposit it has not seen.
    AwaitingDeposit,
    /// The provider has a deposit and the operation is in progress.
    Active,
    /// The provider reports completion with the route's receipt expectation.
    Terminal(ReceiptExpectation),
}

/// The fields of a NEAR 1Click status response that affect scanning.
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
    /// The quote deadline as a Unix timestamp.
    pub deadline: Option<i64>,
}

/// A normalized provider observation and the deadline that bounds scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    /// The direction-specific outcome.
    pub status: OperationStatus,
    /// The quote deadline, if the response carried one.
    pub deadline: Option<i64>,
}

/// Normalizes a NEAR status response for a key of `purpose`. An unrecognized
/// status counts as active, so it neither releases an address nor ends scanning.
///
/// A refund key expects ZEC whenever the provider reports a positive refunded
/// amount, and after an exact-output `SUCCESS`, which returns unused input once
/// the swap completes. Otherwise an exact-input `SUCCESS` expects none, and a
/// missing or unrecognized swap type is [`ReceiptExpectation::Unknown`]. A refund
/// on the source chain is not a Zcash receipt. A zero payout amount is treated as
/// unreported.
pub fn near_observation(purpose: crate::Purpose, status: &NearStatus<'_>) -> Observation {
    use crate::Purpose;
    use OperationStatus::*;
    use ReceiptExpectation::{Positive, Unknown};
    let refund = status.refunded_amount.filter(|v| !v.is_zero());
    let outcome = match (status.status, purpose) {
        ("PENDING_DEPOSIT", _) => AwaitingDeposit,
        ("KNOWN_DEPOSIT_TX" | "INCOMPLETE_DEPOSIT" | "PROCESSING", _) => Active,
        ("SUCCESS", Purpose::Receive) => {
            Terminal(Positive(status.amount_out.filter(|v| !v.is_zero())))
        }
        ("SUCCESS", Purpose::Refund) => Terminal(match (refund, status.swap_type) {
            (Some(value), _) => Positive(Some(value)),
            (None, Some("EXACT_OUTPUT")) => Positive(None),
            (None, Some("EXACT_INPUT")) => ReceiptExpectation::None,
            (None, _) => Unknown,
        }),
        ("REFUNDED", Purpose::Refund) => Terminal(Positive(refund)),
        ("REFUNDED", Purpose::Receive) => Terminal(ReceiptExpectation::None),
        ("FAILED", _) => Terminal(Unknown),
        _ => Active,
    };
    Observation {
        status: outcome,
        deadline: status.deadline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Purpose::*;

    /// The normalized status of `status` for a key of `purpose`.
    fn observe(purpose: crate::Purpose, status: NearStatus<'_>) -> Option<OperationStatus> {
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
            Some(OperationStatus::Terminal(ReceiptExpectation::Unknown))
        );
        assert_eq!(
            observe(Refund, status("FAILED")),
            Some(OperationStatus::Terminal(ReceiptExpectation::Unknown))
        );
        assert_eq!(
            observe(Refund, status("NEW_STATE")),
            Some(OperationStatus::Active)
        );
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
            deadline: Some(42),
            ..Default::default()
        };
        assert_eq!(
            near_observation(Receive, &payout),
            Observation {
                status: OperationStatus::Terminal(ReceiptExpectation::Positive(Some(amount))),
                deadline: Some(42),
            }
        );
    }

    #[test]
    fn refund_success_requires_a_recognized_swap_type() {
        use ReceiptExpectation::{None as NoReceipt, Positive, Unknown};
        let amount = Zatoshis::const_from_u64(1_000);
        // The expectation without a positive refunded amount.
        let cases = [
            (None, Unknown),
            (Some(""), Unknown),
            (Some("FLEX_INPUT"), Unknown),
            (Some("EXACT_INPUT"), NoReceipt),
            (Some("EXACT_OUTPUT"), Positive(None)),
        ];
        for (swap_type, without_refund) in cases {
            for refunded_amount in [None, Some(Zatoshis::ZERO)] {
                let status = NearStatus {
                    status: "SUCCESS",
                    swap_type,
                    refunded_amount,
                    ..Default::default()
                };
                assert_eq!(
                    observe(Refund, status),
                    Some(OperationStatus::Terminal(without_refund)),
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
}
