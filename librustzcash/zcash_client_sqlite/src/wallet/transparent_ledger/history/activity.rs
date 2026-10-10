//! What a transaction shows in the account's activity list: the [`AccountActivity`] rules,
//! from the entry's evidence and the account's outputs in the transaction.
//!
//! These rules reproduce the activity classification Vizor applied on top of this history,
//! decision for decision; changing what they establish belongs in its own change.

use rusqlite::named_params;
use zcash_client_backend::data_api::transparent_ledger::{
    AccountActivity, ActivityOutputs, FeeState, FundingStepEvidence, HistoryClassification,
    OutputRef,
};
use zcash_protocol::value::Zatoshis;

use crate::{AccountUuid, error::SqliteClientError, wallet::encoding::parse_pool_code};

const TRANSPARENT_POOL: i64 = 0;
const SAPLING_POOL: i64 = 2;
const ORCHARD_POOL: i64 = 3;
const IRONWOOD_POOL: i64 = 4;
/// The `orchard_received_notes.note_version` of an Ironwood note.
const IRONWOOD_NOTE_VERSION: i64 = 3;

/// One output of the transaction the account sent or received.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ActivityOutput {
    pub(super) pool: i64,
    pub(super) index: u32,
    pub(super) value: u64,
    /// A sent-note record of the account created it.
    pub(super) from_own: bool,
    /// No account's sent-note record created it.
    pub(super) from_unknown: bool,
    /// The account received it.
    pub(super) to_own: bool,
    /// The key scope of the account's address it pays, when the address is known: 0 external,
    /// 1 internal, 2 ephemeral, -1 imported.
    pub(super) to_key_scope: Option<i64>,
    /// The account's sent-note record of it names a recipient address.
    pub(super) sent_to_address: bool,
    /// Its note is an Orchard-table note of the Ironwood version.
    pub(super) ironwood_note: bool,
}

impl ActivityOutput {
    fn key(&self) -> Result<OutputRef, SqliteClientError> {
        Ok(OutputRef {
            pool: parse_pool_code(self.pool)?,
            index: self.index,
        })
    }

    fn is_shielded(&self) -> bool {
        matches!(self.pool, SAPLING_POOL | ORCHARD_POOL | IRONWOOD_POOL)
    }

    fn is_ironwood(&self) -> bool {
        self.pool == IRONWOOD_POOL || self.ironwood_note
    }

    /// An owned transparent output whose receiver's key scope is not one the wallet uses.
    pub(super) fn has_unknown_transparent_scope(&self) -> bool {
        self.pool == TRANSPARENT_POOL && self.to_own && !matches!(self.to_key_scope, Some(-1..=2))
    }

    /// A self-output a user would recognise: a transparent output to an external or imported
    /// address, or a shielded one to such an address or with a recorded recipient address.
    /// Internal and ephemeral receivers are change and funding mechanics.
    fn is_user_visible_self_output(&self) -> bool {
        let external = matches!(self.to_key_scope, Some(0) | Some(-1));
        match self.pool {
            TRANSPARENT_POOL => external,
            SAPLING_POOL | ORCHARD_POOL | IRONWOOD_POOL => external || self.sent_to_address,
            _ => false,
        }
    }
}

/// Reads the outputs of the transaction that `account` sent or received, ordered by pool and
/// index.
pub(super) fn read_outputs(
    conn: &rusqlite::Connection,
    account: AccountUuid,
    account_id: i64,
    transaction_id: i64,
) -> Result<Vec<ActivityOutput>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT txo.output_pool, txo.output_index, txo.value,
                txo.from_account_uuid = :uuid, txo.from_account_uuid IS NULL,
                txo.to_account_uuid IS NOT NULL AND txo.to_account_uuid = :uuid,
                (SELECT a.key_scope FROM accounts acc
                 JOIN addresses a ON a.account_id = acc.id
                 WHERE acc.uuid = txo.to_account_uuid
                 AND (a.address = txo.to_address
                      OR a.cached_transparent_receiver_address = txo.to_address)
                 LIMIT 1),
                EXISTS (SELECT 1 FROM sent_notes sn
                        WHERE sn.transaction_id = txo.transaction_id
                        AND sn.from_account_id = :account_id
                        AND sn.output_pool = txo.output_pool
                        AND sn.output_index = txo.output_index
                        AND sn.to_address IS NOT NULL),
                EXISTS (SELECT 1 FROM orchard_received_notes orn
                        WHERE txo.output_pool IN (3, 4)
                        AND orn.transaction_id = txo.transaction_id
                        AND orn.action_index = txo.output_index
                        AND orn.note_version = :ironwood_version)
         FROM v_tx_outputs txo
         WHERE txo.transaction_id = :transaction_id
         AND (txo.from_account_uuid = :uuid OR txo.to_account_uuid = :uuid)
         ORDER BY txo.output_pool, txo.output_index",
    )?;
    let rows = stmt.query_map(
        named_params![
            ":uuid": account.0,
            ":account_id": account_id,
            ":transaction_id": transaction_id,
            ":ironwood_version": IRONWOOD_NOTE_VERSION,
        ],
        |row| {
            Ok(ActivityOutput {
                pool: row.get(0)?,
                index: row.get(1)?,
                value: row.get::<_, i64>(2)?.unsigned_abs(),
                from_own: row.get::<_, Option<bool>>(3)?.unwrap_or(false),
                from_unknown: row.get(4)?,
                to_own: row.get(5)?,
                to_key_scope: row.get(6)?,
                sent_to_address: row.get(7)?,
                ironwood_note: row.get(8)?,
            })
        },
    )?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Whether the account's recorded effects meet the shielding shape of `v_transactions`: it
/// spent outputs, all transparent; it received outputs, none transparent; and it recorded no
/// sent output that is not received as change.
pub(super) fn has_shielding_shape(
    conn: &rusqlite::Connection,
    account_id: i64,
    transaction_id: i64,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT
             EXISTS (SELECT 1 FROM v_received_outputs ro
                     WHERE ro.account_id = :account_id AND ro.transaction_id = :transaction_id)
             AND NOT EXISTS (SELECT 1 FROM v_received_outputs ro
                             WHERE ro.account_id = :account_id
                             AND ro.transaction_id = :transaction_id AND ro.pool = 0)
             AND EXISTS (SELECT 1 FROM v_received_outputs ro
                         JOIN v_received_output_spends ros
                              ON ros.pool = ro.pool AND ros.received_output_id = ro.id_within_pool_table
                         WHERE ro.account_id = :account_id AND ros.transaction_id = :transaction_id)
             AND NOT EXISTS (SELECT 1 FROM v_received_outputs ro
                             JOIN v_received_output_spends ros
                                  ON ros.pool = ro.pool
                                  AND ros.received_output_id = ro.id_within_pool_table
                             WHERE ro.account_id = :account_id
                             AND ros.transaction_id = :transaction_id AND ro.pool != 0)
             AND NOT EXISTS (SELECT 1 FROM sent_notes sn
                             LEFT JOIN v_received_outputs ro ON ro.sent_note_id = sn.id
                             WHERE sn.from_account_id = :account_id
                             AND sn.transaction_id = :transaction_id
                             AND COALESCE(ro.is_change, 0) = 0)",
        named_params![":account_id": account_id, ":transaction_id": transaction_id],
        |row| row.get(0),
    )?)
}

/// Whether some wallet account spent a version-2 Orchard note in the transaction.
pub(super) fn has_orchard_spend(
    conn: &rusqlite::Connection,
    transaction_id: i64,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM orchard_received_note_spends s
             JOIN orchard_received_notes n ON n.id = s.orchard_received_note_id
             WHERE s.transaction_id = :transaction_id AND n.note_version = 2
         )",
        named_params![":transaction_id": transaction_id],
        |row| row.get(0),
    )?)
}

/// The entry's facts the rules read.
#[derive(Clone, Debug)]
pub(super) struct ActivityEvidence {
    /// The account's recorded effects meet the shielding shape ([`has_shielding_shape`]).
    pub(super) shielding_shape: bool,
    /// Some wallet account spent a version-2 Orchard note in it.
    pub(super) orchard_spend: bool,
    /// The transaction is mined.
    pub(super) mined: bool,
    /// The account's recorded spent and received values, and their difference.
    pub(super) spent: u64,
    pub(super) received: u64,
    pub(super) net: i128,
    /// The payment details are complete.
    pub(super) details_complete: bool,
    /// The classification is provisional or an effect is not settled.
    pub(super) provisional: bool,
    /// Every effect is settled.
    pub(super) effects_settled: bool,
    pub(super) classification: HistoryClassification,
    pub(super) fee: FeeState,
    /// The exact whole fee, when the account spent in the transaction.
    pub(super) whole_fee: Option<u64>,
    /// The exact payment of a transparent-only transaction the account alone funded, when it
    /// did not create the transaction.
    pub(super) inferred_payment: Option<u64>,
    pub(super) inferred_outgoing: Option<u64>,
}

impl ActivityEvidence {
    /// Only complete, final payment details show that the account moved its transparent funds
    /// into its shielded pools and paid no one.
    fn is_shielding(&self) -> bool {
        self.shielding_shape
            && self.details_complete
            && !self.provisional
            && self.classification != HistoryClassification::Provisional
    }

    /// The fee subtracted from a movement: the attributed fee, or nothing.
    fn known_fee_or_zero(&self) -> u64 {
        match self.fee {
            FeeState::Known(fee) => fee.into_u64(),
            _ => 0,
        }
    }

    /// The fee that identifies a fully funded self-transfer: the attributed fee, or the whole
    /// fee when the account's share is not attributed. It is never shown as the account's.
    fn reconstruction_fee(&self) -> Option<u64> {
        match self.fee {
            FeeState::Known(fee) | FeeState::Unattributed { whole: fee } => Some(fee.into_u64()),
            FeeState::Unknown | FeeState::NotApplicable => None,
        }
    }

    fn debit(&self) -> u64 {
        u64::try_from(self.net.unsigned_abs()).unwrap_or(u64::MAX)
    }

    /// An exact zero payment outside the account and a debit that is exactly the whole fee
    /// and the account's: a fully funded recovered self-transfer.
    fn recovered_self_transfer(&self) -> bool {
        let debit = self.debit();
        self.inferred_payment == Some(0)
            && self.net < 0
            && self.whole_fee == Some(debit)
            && self.reconstruction_fee() == Some(debit)
    }
}

#[derive(Clone, Debug, Default)]
struct Group {
    amount: u64,
    count: usize,
    outputs: Vec<OutputRef>,
}

impl Group {
    fn add(&mut self, output: &ActivityOutput) -> Result<(), SqliteClientError> {
        self.amount = self.amount.saturating_add(output.value);
        self.count += 1;
        self.outputs.push(output.key()?);
        Ok(())
    }

    fn rows(&self) -> Result<ActivityOutputs, SqliteClientError> {
        Ok(ActivityOutputs {
            amount: zatoshis(self.amount)?,
            outputs: self.outputs.clone(),
        })
    }
}

/// The account's outputs, by the role each plays in its activity.
#[derive(Debug, Default)]
pub(super) struct Summary {
    sent: Group,
    received: Group,
    /// Owned transparent receipts, excluding internal ones.
    received_transparent: Group,
    /// Owned internal and ephemeral transparent outputs, excluded from an outgoing value.
    internal_transparent: Group,
    /// An owned transparent receiver may later prove to be change rather than a receipt.
    pub(super) unknown_transparent_scope: bool,
    shielded: Group,
    internal_ironwood_transition: Group,
    own_transparent: u64,
    has_own_transparent: bool,
    external_transparent_send: bool,
}

/// Sorts the account's outputs into their activity roles.
pub(super) fn summarize(
    ev: &ActivityEvidence,
    outputs: &[ActivityOutput],
) -> Result<Summary, SqliteClientError> {
    let mut summary = Summary::default();
    // Whether the account paid anyone else. A self-payment then shows only as the receive it
    // is; without another recipient it is the whole payment and shows as a send and a receive.
    let pays_others = outputs.iter().any(|o| o.from_own && !o.to_own);
    let recovered_self_transfer = ev.recovered_self_transfer();
    let is_shielding = ev.is_shielding();

    for output in outputs {
        let (from_own, to_own) = (output.from_own, output.to_own);
        // Private recovery can establish an owned output before it links the sender. Only
        // account-funded recovery treats an unlinked owned output as the account's own.
        let recovered_from_own =
            output.from_unknown && (ev.inferred_outgoing.is_some() || recovered_self_transfer);

        if output.has_unknown_transparent_scope() {
            summary.unknown_transparent_scope = true;
        }

        if is_shielding {
            if to_own && output.is_shielded() {
                summary.shielded.add(output)?;
            }
            continue;
        }

        if from_own && to_own && ev.orchard_spend && output.is_ironwood() {
            summary.internal_ironwood_transition.add(output)?;
            continue;
        }

        if output.pool == TRANSPARENT_POOL && from_own && to_own {
            summary.has_own_transparent = true;
            summary.own_transparent = summary.own_transparent.saturating_add(output.value);
        }

        if output.pool == TRANSPARENT_POOL
            && to_own
            && (from_own || recovered_from_own)
            && matches!(output.to_key_scope, Some(1) | Some(2))
        {
            summary.internal_transparent.add(output)?;
            continue;
        }

        let visible_self_output = (from_own || (recovered_self_transfer && recovered_from_own))
            && to_own
            && output.is_user_visible_self_output();
        let visible_sent = (from_own && (!to_own || (visible_self_output && !pays_others)))
            || (recovered_self_transfer && visible_self_output && !pays_others);
        let visible_received = to_own && (!from_own || visible_self_output);

        if visible_sent {
            summary.sent.add(output)?;
            if output.pool == TRANSPARENT_POOL && !to_own {
                summary.external_transparent_send = true;
            }
        }
        if visible_received {
            summary.received.add(output)?;
            if output.pool == TRANSPARENT_POOL {
                summary.received_transparent.add(output)?;
            }
        }
    }
    Ok(summary)
}

impl Summary {
    /// What the transaction contributes to funding-step grouping.
    pub(super) fn funding_step(&self) -> Result<FundingStepEvidence, SqliteClientError> {
        Ok(FundingStepEvidence {
            own_transparent_outputs: if self.has_own_transparent {
                Some(zatoshis(self.own_transparent)?)
            } else {
                None
            },
            external_transparent_send: self.external_transparent_send,
        })
    }
}

/// The activity of a transaction, in the order of [`AccountActivity`]'s variants.
pub(super) fn activity(
    ev: &ActivityEvidence,
    summary: &Summary,
) -> Result<AccountActivity, SqliteClientError> {
    if ev.is_shielding() {
        let amount = if summary.shielded.amount > 0 {
            summary.shielded.amount
        } else {
            ev.received
        };
        return Ok(AccountActivity::Shielding {
            amount: zatoshis(amount)?,
            outputs: summary.shielded.outputs.clone(),
        });
    }

    // Owned Ironwood outputs do not prove an internal move when a positive outgoing value was
    // reconciled: they may be change from an Orchard-funded payment.
    if !ev.inferred_outgoing.is_some_and(|amount| amount > 0)
        && ev.orchard_spend
        && ev.spent > 0
        && summary.internal_ironwood_transition.amount > 0
        && summary.sent.amount == 0
        && summary.received.amount == 0
    {
        return Ok(AccountActivity::PoolMigration {
            amount: zatoshis(summary.internal_ironwood_transition.amount)?,
            outputs: summary.internal_ironwood_transition.outputs.clone(),
        });
    }

    // The exact payment of a transparent-only debit the account fully funded, without its
    // recipients: no output it paid is visible, so the outputs it knows of are change.
    if let Some(payment) = ev.inferred_payment {
        if payment > 0 && ev.net < 0 && summary.sent.count == 0 {
            return Ok(AccountActivity::InferredPayment {
                amount: zatoshis(payment)?,
            });
        }
        // Without a visible self-payment, the only amount a recovered self-transfer shows is
        // its fee.
        let debit = ev.debit();
        if payment == 0
            && ev.net < 0
            && summary.sent.count == 0
            && ev.whole_fee == Some(debit)
            && ev.reconstruction_fee() == Some(debit)
        {
            return Ok(AccountActivity::FeeOnly {
                fee: zatoshis(debit)?,
            });
        }
    }

    // The reconciled outgoing value includes owned transparent outputs. Exclude internal
    // change and funding, and show other transparent receipts separately.
    if let Some(outgoing) = ev.inferred_outgoing
        && outgoing > 0
        && summary.sent.count == 0
    {
        let visible = outgoing.checked_sub(summary.internal_transparent.amount);
        // A fully accounted funding step has no visible payment.
        if visible == Some(0) && summary.received_transparent.count == 0 {
            return Ok(AccountActivity::HiddenFundingStep);
        }
        // Inconsistent evidence must not underflow or erase a debit.
        let shown = visible.filter(|amount| *amount > 0).unwrap_or(outgoing);
        let settled = ev.effects_settled
            && ev.mined
            && !summary.unknown_transparent_scope
            && visible
                .is_some_and(|value| value > 0 && value >= summary.received_transparent.amount);
        return Ok(AccountActivity::InferredOutgoing {
            outgoing: zatoshis(shown)?,
            received: if summary.received_transparent.count > 0 {
                Some(summary.received_transparent.rows()?)
            } else {
                None
            },
            settled,
        });
    }

    // Discovery found this debit but not where the value went: the outputs it knows of can
    // only be change. A visible sent output, even a zero-value one, keeps its own row below.
    if ev.provisional && ev.net < 0 && summary.sent.count == 0 {
        return Ok(AccountActivity::MovementDebit {
            amount: zatoshis(ev.debit().saturating_sub(ev.known_fee_or_zero()))?,
        });
    }

    // A visible output makes a row even at zero value: that is how memo-only payments travel.
    // Before enhancement links zero-value change to its send, the change looks like a receipt,
    // so a zero-value receipt needs a transaction that spent nothing or also has a sent row.
    let sent = (summary.sent.count > 0)
        .then(|| summary.sent.rows())
        .transpose()?;
    let zero_value_receipt_allowed = ev.spent == 0 || summary.sent.count > 0;
    let received = (summary.received.amount > 0
        || (summary.received.count > 0 && zero_value_receipt_allowed))
        .then(|| summary.received.rows())
        .transpose()?;
    if sent.is_some() || received.is_some() {
        return Ok(AccountActivity::Outputs { sent, received });
    }

    if !ev.mined && ev.net < 0 && ev.spent > 0 {
        let amount = ev.debit().saturating_sub(ev.known_fee_or_zero());
        if amount > 0 {
            return Ok(AccountActivity::MovementDebit {
                amount: zatoshis(amount)?,
            });
        }
    }
    if ev.spent > 0 && ev.received > 0 {
        return Ok(AccountActivity::ChangeOnly);
    }
    if ev.net > 0 {
        return Ok(AccountActivity::MovementCredit {
            amount: zatoshis(u64::try_from(ev.net).unwrap_or(u64::MAX))?,
        });
    }
    Ok(AccountActivity::Unknown)
}

fn zatoshis(value: u64) -> Result<Zatoshis, SqliteClientError> {
    Zatoshis::from_u64(value)
        .map_err(|_| SqliteClientError::CorruptedData(format!("invalid activity amount {value}")))
}

#[cfg(test)]
mod tests {
    //! Vizor's activity classification regressions, ported to these rules: each case gives
    //! the facts Vizor's fixture gave and expects the rows it expected.

    use zcash_client_backend::data_api::transparent_ledger::{
        AccountActivity, ActivityOutputs, FeeState, HistoryClassification, OutputRef,
    };
    use zcash_protocol::{PoolType, value::Zatoshis};

    use super::{
        ActivityEvidence, ActivityOutput, IRONWOOD_POOL, ORCHARD_POOL, TRANSPARENT_POOL, activity,
        summarize,
    };

    fn zat(value: u64) -> Zatoshis {
        Zatoshis::const_from_u64(value)
    }

    fn known(fee: u64) -> FeeState {
        FeeState::Known(zat(fee))
    }

    /// Vizor's `tx_base_for_history`: a mined, fully reconstructed 6.25 ZEC Orchard debit
    /// with a 20 000 fee, in which a version-2 Orchard note is spent.
    fn base() -> ActivityEvidence {
        ActivityEvidence {
            shielding_shape: false,
            orchard_spend: true,
            mined: true,
            spent: 625_000_000,
            received: 0,
            net: -625_000_000,
            details_complete: true,
            provisional: false,
            effects_settled: true,
            classification: HistoryClassification::Reconstructed,
            fee: known(20_000),
            whole_fee: None,
            inferred_payment: None,
            inferred_outgoing: None,
        }
    }

    /// Vizor's `provisional_debit`: discovery found a 1 ZEC debit with 0.3 ZEC of change but
    /// not where the rest went.
    fn provisional_debit() -> ActivityEvidence {
        ActivityEvidence {
            orchard_spend: false,
            spent: 100_000_000,
            received: 30_000_000,
            net: -70_000_000,
            details_complete: false,
            provisional: true,
            effects_settled: false,
            classification: HistoryClassification::Provisional,
            fee: FeeState::Unknown,
            ..base()
        }
    }

    /// An output the account received with no sent-note record: discovered, not created.
    fn received(pool: i64, index: u32, value: u64, scope: Option<i64>) -> ActivityOutput {
        ActivityOutput {
            pool,
            index,
            value,
            from_unknown: true,
            to_own: true,
            to_key_scope: scope,
            ..ActivityOutput::default()
        }
    }

    /// An output the account sent itself, by its own record.
    fn own(pool: i64, index: u32, value: u64, scope: Option<i64>) -> ActivityOutput {
        ActivityOutput {
            from_own: true,
            from_unknown: false,
            ..received(pool, index, value, scope)
        }
    }

    /// An output the account sent someone else.
    fn paid(pool: i64, index: u32, value: u64) -> ActivityOutput {
        ActivityOutput {
            pool,
            index,
            value,
            from_own: true,
            ..ActivityOutput::default()
        }
    }

    fn row(amount: u64, outputs: &[(i64, u32)]) -> Option<ActivityOutputs> {
        Some(ActivityOutputs {
            amount: zat(amount),
            outputs: outputs
                .iter()
                .map(|&(pool, index)| OutputRef {
                    pool: match pool {
                        TRANSPARENT_POOL => PoolType::Transparent,
                        ORCHARD_POOL => PoolType::ORCHARD,
                        IRONWOOD_POOL => PoolType::IRONWOOD,
                        _ => PoolType::SAPLING,
                    },
                    index,
                })
                .collect(),
        })
    }

    fn classify(ev: &ActivityEvidence, outputs: &[ActivityOutput]) -> AccountActivity {
        activity(ev, &summarize(ev, outputs).unwrap()).unwrap()
    }

    #[test]
    fn classify_internal_ironwood_transition_as_migration() {
        let outputs = [own(IRONWOOD_POOL, 0, 624_980_000, None)];
        for outgoing in [None, Some(0)] {
            let ev = ActivityEvidence {
                inferred_outgoing: outgoing,
                ..base()
            };
            assert_eq!(
                classify(&ev, &outputs),
                AccountActivity::PoolMigration {
                    amount: zat(624_980_000),
                    outputs: vec![OutputRef {
                        pool: PoolType::IRONWOOD,
                        index: 0,
                    }],
                }
            );
        }
        // An Ironwood note kept in the Orchard table is the same move; an unmined one too.
        let legacy = ActivityOutput {
            ironwood_note: true,
            ..own(ORCHARD_POOL, 0, 624_980_000, None)
        };
        let ev = ActivityEvidence {
            mined: false,
            ..base()
        };
        assert!(matches!(
            classify(&ev, &[legacy]),
            AccountActivity::PoolMigration { .. }
        ));
        // Without the sent-note record the account's Ironwood output is a receipt.
        assert!(matches!(
            classify(&base(), &[received(IRONWOOD_POOL, 0, 624_980_000, None)]),
            AccountActivity::Outputs { sent: None, .. }
        ));
    }

    #[test]
    fn private_orchard_unshielding_with_ironwood_change_matches_public_activity() {
        for change_pool in [ORCHARD_POOL, IRONWOOD_POOL] {
            for owned_receipt in [false, true] {
                let ev = ActivityEvidence {
                    spent: 1_000_000,
                    received: 735_000 + if owned_receipt { 250_000 } else { 0 },
                    net: if owned_receipt { -15_000 } else { -265_000 },
                    details_complete: false,
                    provisional: true,
                    effects_settled: false,
                    classification: HistoryClassification::Provisional,
                    fee: FeeState::Unattributed { whole: zat(15_000) },
                    whole_fee: Some(15_000),
                    inferred_outgoing: Some(250_000),
                    ..base()
                };
                let change = ActivityOutput {
                    ironwood_note: true,
                    ..own(change_pool, 0, 735_000, Some(1))
                };
                let mut private_outputs = vec![change.clone()];
                if owned_receipt {
                    private_outputs.push(received(TRANSPARENT_POOL, 0, 250_000, Some(0)));
                }
                let private = classify(&ev, &private_outputs);
                assert_eq!(
                    private,
                    AccountActivity::InferredOutgoing {
                        outgoing: zat(250_000),
                        received: if owned_receipt {
                            row(250_000, &[(TRANSPARENT_POOL, 0)])
                        } else {
                            None
                        },
                        settled: false,
                    }
                );

                let public = ActivityEvidence {
                    inferred_outgoing: None,
                    provisional: false,
                    details_complete: true,
                    classification: HistoryClassification::Reconstructed,
                    fee: known(15_000),
                    ..ev
                };
                let recipient = if owned_receipt {
                    own(TRANSPARENT_POOL, 0, 250_000, Some(0))
                } else {
                    paid(TRANSPARENT_POOL, 0, 250_000)
                };
                let rows = row(250_000, &[(TRANSPARENT_POOL, 0)]);
                assert_eq!(
                    classify(&public, &[change, recipient]),
                    AccountActivity::Outputs {
                        sent: rows.clone(),
                        received: if owned_receipt { rows } else { None },
                    }
                );
            }
        }
    }

    #[test]
    fn compact_enhanced_outgoing_matches_public_activity_with_or_without_owned_receipt() {
        for owned_receipt in [false, true] {
            let ev = ActivityEvidence {
                spent: 107_485_000,
                received: 107_220_000 + if owned_receipt { 250_000 } else { 0 },
                net: if owned_receipt { -15_000 } else { -265_000 },
                whole_fee: Some(15_000),
                inferred_outgoing: Some(250_000),
                ..provisional_debit()
            };
            // The shielded change is a visible receipt in the unreconciled outputs too.
            let mut outputs = vec![received(IRONWOOD_POOL, 0, 107_220_000, None)];
            if owned_receipt {
                outputs.push(received(TRANSPARENT_POOL, 0, 250_000, Some(0)));
            }
            assert_eq!(
                classify(&ev, &outputs),
                AccountActivity::InferredOutgoing {
                    outgoing: zat(250_000),
                    received: if owned_receipt {
                        row(250_000, &[(TRANSPARENT_POOL, 0)])
                    } else {
                        None
                    },
                    settled: false,
                }
            );
        }
    }

    /// Vizor's `compact_funding_base`: a provisional debit of the whole fee whose inferred
    /// outgoing value is `amount`.
    fn compact_funding(amount: u64) -> ActivityEvidence {
        ActivityEvidence {
            spent: 1_000_000 + amount + 15_000,
            received: 1_000_000 + amount,
            net: -15_000,
            whole_fee: Some(15_000),
            inferred_outgoing: Some(amount),
            ..provisional_debit()
        }
    }

    #[test]
    fn recovered_activity_hides_funding_steps_and_keeps_external_self_payments() {
        for amount in [20_000, 110_000] {
            for scope in [1, 2] {
                assert_eq!(
                    classify(
                        &compact_funding(amount),
                        &[received(TRANSPARENT_POOL, 0, amount, Some(scope))]
                    ),
                    AccountActivity::HiddenFundingStep
                );
            }
        }
        for scope in [0, -1] {
            assert_eq!(
                classify(
                    &compact_funding(250_000),
                    &[received(TRANSPARENT_POOL, 0, 250_000, Some(scope))]
                ),
                AccountActivity::InferredOutgoing {
                    outgoing: zat(250_000),
                    received: row(250_000, &[(TRANSPARENT_POOL, 0)]),
                    settled: false,
                }
            );
        }
    }

    #[test]
    fn recovered_activity_subtracts_only_known_internal_funding() {
        assert_eq!(
            classify(
                &compact_funding(270_000),
                &[
                    received(TRANSPARENT_POOL, 0, 20_000, Some(2)),
                    received(TRANSPARENT_POOL, 1, 250_000, Some(0)),
                ]
            ),
            AccountActivity::InferredOutgoing {
                outgoing: zat(250_000),
                received: row(250_000, &[(TRANSPARENT_POOL, 1)]),
                settled: false,
            }
        );
        assert_eq!(
            classify(
                &compact_funding(220_000),
                &[received(TRANSPARENT_POOL, 0, 20_000, Some(1))]
            ),
            AccountActivity::InferredOutgoing {
                outgoing: zat(200_000),
                received: None,
                settled: false,
            }
        );
    }

    #[test]
    fn recovered_activity_does_not_hide_unknown_scope_or_erase_conflicting_debits() {
        let ev = ActivityEvidence {
            effects_settled: true,
            ..compact_funding(20_000)
        };
        let shown = |output| classify(&ev, &[output]);
        assert_eq!(
            shown(received(TRANSPARENT_POOL, 0, 20_000, None)),
            AccountActivity::InferredOutgoing {
                outgoing: zat(20_000),
                received: row(20_000, &[(TRANSPARENT_POOL, 0)]),
                settled: false,
            }
        );
        assert_eq!(
            shown(received(TRANSPARENT_POOL, 0, 30_000, Some(2))),
            AccountActivity::InferredOutgoing {
                outgoing: zat(20_000),
                received: None,
                settled: false,
            }
        );
        assert_eq!(
            shown(received(TRANSPARENT_POOL, 0, 30_000, Some(0))),
            AccountActivity::InferredOutgoing {
                outgoing: zat(20_000),
                received: row(30_000, &[(TRANSPARENT_POOL, 0)]),
                settled: false,
            }
        );
        // Settled once the receipt fits under the outgoing value.
        assert_eq!(
            shown(received(TRANSPARENT_POOL, 0, 20_000, Some(0))),
            AccountActivity::InferredOutgoing {
                outgoing: zat(20_000),
                received: row(20_000, &[(TRANSPARENT_POOL, 0)]),
                settled: true,
            }
        );
    }

    #[test]
    fn recovered_activity_keeps_unrelated_incoming_on_internal_receivers() {
        let ev = ActivityEvidence {
            spent: 0,
            received: 20_000,
            net: 20_000,
            ..provisional_debit()
        };
        assert_eq!(
            classify(&ev, &[received(TRANSPARENT_POOL, 0, 20_000, Some(2))]),
            AccountActivity::Outputs {
                sent: None,
                received: row(20_000, &[(TRANSPARENT_POOL, 0)]),
            }
        );
    }

    /// Vizor's recovered self-transfer: the account spent 110 000 and got 100 000 back, the
    /// exact payment outside it is zero, and the 10 000 debit is the whole fee and its own.
    fn recovered_self_transfer() -> ActivityEvidence {
        ActivityEvidence {
            orchard_spend: false,
            spent: 110_000,
            received: 100_000,
            net: -10_000,
            details_complete: false,
            fee: known(10_000),
            whole_fee: Some(10_000),
            inferred_payment: Some(0),
            ..base()
        }
    }

    #[test]
    fn recovered_activity_restores_visible_transparent_self_transfer_instead_of_fee_only() {
        let rows = row(100_000, &[(TRANSPARENT_POOL, 0)]);
        for scope in [0, -1] {
            assert_eq!(
                classify(
                    &recovered_self_transfer(),
                    &[received(TRANSPARENT_POOL, 0, 100_000, Some(scope))]
                ),
                AccountActivity::Outputs {
                    sent: rows.clone(),
                    received: rows.clone(),
                }
            );
        }
        // An internal receiver is not a self-payment: the fee is all there is to show.
        assert_eq!(
            classify(
                &recovered_self_transfer(),
                &[received(TRANSPARENT_POOL, 0, 100_000, Some(1))]
            ),
            AccountActivity::FeeOnly { fee: zat(10_000) }
        );
    }

    #[test]
    fn a_recovered_self_transfer_is_its_network_fee() {
        // Its outputs are change no user would recognise as a payment.
        let outputs = [received(ORCHARD_POOL, 0, 100_000, None)];
        assert_eq!(
            classify(&recovered_self_transfer(), &outputs),
            AccountActivity::FeeOnly { fee: zat(10_000) }
        );
        // An exact zero payment with a recorded zero-value send keeps its sent row.
        let sent = [paid(ORCHARD_POOL, 1, 0)];
        assert_eq!(
            classify(&recovered_self_transfer(), &sent),
            AccountActivity::Outputs {
                sent: row(0, &[(ORCHARD_POOL, 1)]),
                received: None,
            }
        );
    }

    #[test]
    fn an_inexact_self_transfer_is_not_shown_as_its_fee() {
        let outputs = [received(ORCHARD_POOL, 0, 100_000, None)];
        let receipt = AccountActivity::Outputs {
            sent: None,
            received: row(100_000, &[(ORCHARD_POOL, 0)]),
        };
        for ev in [
            // A public self-transfer: no exact payment.
            ActivityEvidence {
                inferred_payment: None,
                whole_fee: None,
                ..recovered_self_transfer()
            },
            // No exact whole fee.
            ActivityEvidence {
                whole_fee: None,
                ..recovered_self_transfer()
            },
            // A whole fee that is not the movement.
            ActivityEvidence {
                whole_fee: Some(20_000),
                ..recovered_self_transfer()
            },
        ] {
            assert_eq!(classify(&ev, &outputs), receipt);
        }
    }

    #[test]
    fn a_recovered_send_with_change_is_its_exact_payment_not_a_receive() {
        let ev = ActivityEvidence {
            details_complete: false,
            provisional: false,
            effects_settled: true,
            fee: known(10_000),
            inferred_payment: Some(69_990_000),
            ..provisional_debit()
        };
        let change = [received(TRANSPARENT_POOL, 1, 30_000_000, Some(0))];
        let payment = AccountActivity::InferredPayment {
            amount: zat(69_990_000),
        };
        assert_eq!(classify(&ev, &change), payment);
        assert_eq!(classify(&ev, &[]), payment);
    }

    #[test]
    fn provisional_debits_are_their_movement() {
        let change = [received(TRANSPARENT_POOL, 1, 30_000_000, Some(0))];
        // One sent row of the net debit, fee included, never a receive.
        assert_eq!(
            classify(&provisional_debit(), &change),
            AccountActivity::MovementDebit {
                amount: zat(70_000_000)
            }
        );
        // An attributed fee is subtracted; an unattributed one is not.
        let ev = ActivityEvidence {
            fee: known(10_000),
            ..provisional_debit()
        };
        assert_eq!(
            classify(&ev, &change),
            AccountActivity::MovementDebit {
                amount: zat(69_990_000)
            }
        );
        let ev = ActivityEvidence {
            fee: FeeState::Unattributed { whole: zat(10_000) },
            ..provisional_debit()
        };
        assert_eq!(
            classify(&ev, &change),
            AccountActivity::MovementDebit {
                amount: zat(70_000_000)
            }
        );
        // A fee-only debit stays visible, with nothing to show as its amount.
        let ev = ActivityEvidence {
            net: -10_000,
            fee: known(10_000),
            ..provisional_debit()
        };
        assert_eq!(
            classify(&ev, &[]),
            AccountActivity::MovementDebit {
                amount: Zatoshis::ZERO
            }
        );
        // A zero-value send keeps its sent row.
        let ev = ActivityEvidence {
            net: -10_000,
            received: 90_000,
            details_complete: true,
            fee: known(10_000),
            ..provisional_debit()
        };
        assert_eq!(
            classify(&ev, &[paid(ORCHARD_POOL, 0, 0)]),
            AccountActivity::Outputs {
                sent: row(0, &[(ORCHARD_POOL, 0)]),
                received: None,
            }
        );
    }

    #[test]
    fn a_complete_debit_with_change_keeps_its_classification() {
        let ev = ActivityEvidence {
            details_complete: true,
            provisional: false,
            effects_settled: true,
            classification: HistoryClassification::Reconstructed,
            fee: known(10_000),
            ..provisional_debit()
        };
        assert_eq!(
            classify(&ev, &[received(TRANSPARENT_POOL, 1, 30_000_000, Some(0))]),
            AccountActivity::Outputs {
                sent: None,
                received: row(30_000_000, &[(TRANSPARENT_POOL, 1)]),
            }
        );
    }

    /// Vizor's net-reconstructed shielding: the account's 1 ZEC of transparent inputs became
    /// its Ironwood receipt and the 10 000 whole fee.
    fn net_shielding() -> ActivityEvidence {
        ActivityEvidence {
            shielding_shape: true,
            orchard_spend: false,
            spent: 100_000_000,
            received: 99_990_000,
            net: -10_000,
            details_complete: true,
            provisional: false,
            effects_settled: true,
            classification: HistoryClassification::NetReconstructed,
            fee: FeeState::Unattributed { whole: zat(10_000) },
            whole_fee: Some(10_000),
            ..base()
        }
    }

    #[test]
    fn only_complete_final_histories_justify_a_shielding() {
        let receipt = [received(IRONWOOD_POOL, 0, 99_990_000, None)];
        assert_eq!(
            classify(&net_shielding(), &receipt),
            AccountActivity::Shielding {
                amount: zat(99_990_000),
                outputs: vec![OutputRef {
                    pool: PoolType::IRONWOOD,
                    index: 0,
                }],
            }
        );
        // Without shielded receipts the amount is everything received.
        assert_eq!(
            classify(&net_shielding(), &[]),
            AccountActivity::Shielding {
                amount: zat(99_990_000),
                outputs: vec![],
            }
        );
        // Incomplete details, a provisional history, or no shielding shape justify none.
        for ev in [
            ActivityEvidence {
                details_complete: false,
                ..net_shielding()
            },
            ActivityEvidence {
                classification: HistoryClassification::Provisional,
                ..net_shielding()
            },
            ActivityEvidence {
                provisional: true,
                ..net_shielding()
            },
            ActivityEvidence {
                shielding_shape: false,
                ..net_shielding()
            },
        ] {
            assert!(!matches!(
                classify(&ev, &receipt),
                AccountActivity::Shielding { .. }
            ));
        }
    }

    #[test]
    fn fallbacks_without_visible_outputs() {
        // An unmined debit is its movement less an attributed fee.
        let ev = ActivityEvidence {
            mined: false,
            fee: known(10_000),
            net: -60_000,
            spent: 100_000,
            received: 40_000,
            ..base()
        };
        assert_eq!(
            classify(&ev, &[]),
            AccountActivity::MovementDebit {
                amount: zat(50_000)
            }
        );
        // A mined one with change only has no row.
        let ev = ActivityEvidence { mined: true, ..ev };
        assert_eq!(classify(&ev, &[]), AccountActivity::ChangeOnly);
        // A credit with no visible output is its movement; nothing else is unknown.
        let ev = ActivityEvidence {
            spent: 0,
            received: 5_000,
            net: 5_000,
            ..base()
        };
        assert_eq!(
            classify(&ev, &[]),
            AccountActivity::MovementCredit { amount: zat(5_000) }
        );
        let ev = ActivityEvidence {
            spent: 0,
            received: 0,
            net: 0,
            ..base()
        };
        assert_eq!(classify(&ev, &[]), AccountActivity::Unknown);
    }

    #[test]
    fn zero_value_receipts_need_a_send_or_no_spend() {
        let zero = [received(ORCHARD_POOL, 0, 0, None)];
        // Spending without a sent row: the zero-value output may be unlinked change.
        let ev = ActivityEvidence {
            spent: 10_000,
            received: 0,
            net: -10_000,
            mined: true,
            ..base()
        };
        assert_eq!(classify(&ev, &zero), AccountActivity::Unknown);
        // A receipt-only transaction keeps its memo-only receipt.
        let ev = ActivityEvidence {
            spent: 0,
            received: 0,
            net: 0,
            ..base()
        };
        assert_eq!(
            classify(&ev, &zero),
            AccountActivity::Outputs {
                sent: None,
                received: row(0, &[(ORCHARD_POOL, 0)]),
            }
        );
    }

    #[test]
    fn a_self_payment_is_only_received_when_the_account_also_paid_others() {
        let ev = ActivityEvidence {
            orchard_spend: false,
            ..base()
        };
        let self_payment = own(TRANSPARENT_POOL, 1, 50_000, Some(0));
        assert_eq!(
            classify(&ev, &[paid(ORCHARD_POOL, 0, 70_000), self_payment.clone()]),
            AccountActivity::Outputs {
                sent: row(70_000, &[(ORCHARD_POOL, 0)]),
                received: row(50_000, &[(TRANSPARENT_POOL, 1)]),
            }
        );
        assert_eq!(
            classify(&ev, &[self_payment]),
            AccountActivity::Outputs {
                sent: row(50_000, &[(TRANSPARENT_POOL, 1)]),
                received: row(50_000, &[(TRANSPARENT_POOL, 1)]),
            }
        );
    }
}
