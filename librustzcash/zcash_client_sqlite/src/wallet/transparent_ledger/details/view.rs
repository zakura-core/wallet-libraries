//! The detail view of a transaction for one account.

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension as _, named_params};
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::transparent_ledger::{
    TransparentDisplayAddress, TransparentDisplayDetails, TransparentDisplayFacts,
    TransparentDisplayOmission, TransparentDisplaySender, TransparentDisplaySource,
    TransparentDisplayView, TransparentDisplayViewOutput, TransparentDisplayViewSender,
    TransparentLedgerMode, WholeTransactionFee, transparent_display_address,
};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::{
    consensus,
    value::{ZatBalance, Zatoshis},
};

use crate::{AccountUuid, error::SqliteClientError, wallet::TxQueryType};

use super::super::{output_observation_condition, resolve_mode};
use super::codes::{NOT_COVERED, NOT_YET_PUBLISHED};
use super::script::spent_address;
use super::sql::listable_work_sql;
use super::store::stored_facts;

type OwnedInputScripts = BTreeMap<([u8; 32], u32), Vec<u8>>;

/// Spent outpoints whose ownership the account can affirm now, with their spent scripts.
/// The private branch is the per-account form of history's `has_ledger_spend`, adding the
/// spent script; `qualified_owned_spend_inputs` counts inputs without the active-account and
/// placement requirements.
/// Private evidence must be active, qualified, non-suspended and at the transaction's
/// accepted height. Independently recorded public or local spends retain their semantics;
/// ledger projection alone cannot bypass the private evidence checks.
pub(super) fn owned_inputs(
    conn: &Connection,
    id_tx: i64,
    txid: &[u8],
    account: Option<i64>,
) -> Result<OwnedInputScripts, SqliteClientError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT e.prevout_txid, e.prevout_output_index, e.prevout_script
         FROM tpir_spend_events e
         JOIN tpir_active_accounts a ON a.account_id = e.account_id
         JOIN transactions t ON t.txid = e.spending_txid AND t.mined_height = e.mined_height
         WHERE e.spending_txid = :txid AND e.account_id = :account
         AND NOT EXISTS (SELECT 1 FROM tpir_quarantined_accounts qa
                         WHERE qa.account_id = e.account_id)
         AND EXISTS (
             SELECT 1 FROM tpir_spend_observations so
             JOIN tpir_qualified_revisions q ON q.revision_id = so.revision_id
             JOIN tpir_revisions r ON r.id = so.revision_id
             WHERE so.spend_id = e.id
             AND NOT EXISTS (SELECT 1 FROM tpir_quarantined_sources qs
                             WHERE qs.source = r.source)
         )
         UNION
         SELECT ot.txid, o.output_index, o.script
         FROM transparent_received_output_spends s
         JOIN transparent_received_outputs o ON o.id = s.transparent_received_output_id
         JOIN transactions ot ON ot.id_tx = o.transaction_id
         WHERE s.transaction_id = :tx AND o.account_id = :account AND ({})
         AND EXISTS (
             SELECT 1 FROM tpir_spend_origins origin
             WHERE origin.spending_transaction_id = s.transaction_id
             AND origin.prevout_txid = ot.txid AND origin.prevout_output_index = o.output_index
             AND origin.origin IN (0, 1)
         )",
        output_observation_condition("o"),
    ))?;
    Ok(stmt
        .query_map(
            named_params![":tx": id_tx, ":txid": txid, ":account": account],
            |row| Ok(((row.get(0)?, row.get(1)?), row.get(2)?)),
        )?
        .collect::<Result<_, _>>()?)
}

/// The net value the shielded pools contribute to the transparent side: the sum of the shielded
/// value balances, which equals the fee plus the transparent outputs minus the transparent
/// inputs. `None` when it overflows.
fn shielded_contribution(transaction: &Transaction) -> Option<i64> {
    let zero = ZatBalance::zero();
    let total = [
        transaction
            .sprout_bundle()
            .map_or(Some(zero), |b| b.value_balance())?,
        transaction
            .sapling_bundle()
            .map_or(zero, |b| *b.value_balance()),
        transaction
            .orchard_bundle()
            .map_or(zero, |b| *b.value_balance()),
        transaction
            .ironwood_bundle()
            .map_or(zero, |b| *b.value_balance()),
    ]
    .iter()
    .sum::<Option<ZatBalance>>()?;
    Some(i64::from(total))
}

/// The omissions of a view, in their fixed order.
///
/// Several source scripts are this account's own send when it funded every input; when it
/// funded some, the rest came from inputs it does not own (shared funding). With one source
/// script, an account funding any input owns the script every input spends, so neither applies.
pub(super) fn omissions(
    sender: &TransparentDisplayViewSender,
    multiple_source_scripts: bool,
    owned_inputs: u32,
    input_count: u32,
    mixed_funding: bool,
    outputs: &[TransparentDisplayViewOutput],
    more_than_two_outputs: bool,
) -> Vec<TransparentDisplayOmission> {
    use TransparentDisplayOmission as O;
    let mut omissions = Vec::new();
    if *sender == TransparentDisplayViewSender::NonStandard {
        omissions.push(O::NonStandardSender);
    }
    if multiple_source_scripts {
        if owned_inputs == 0 {
            omissions.push(O::MultipleSourceScripts);
        } else if owned_inputs < input_count {
            omissions.push(O::SharedFunding);
        }
    }
    if mixed_funding {
        omissions.push(O::ShieldedAndTransparentFunding);
    }
    omissions.extend(
        outputs
            .iter()
            .filter(|o| o.address.is_none())
            .map(|o| O::NonStandardOutput { index: o.index }),
    );
    if more_than_two_outputs {
        omissions.push(O::MoreThanTwoOutputs);
    }
    omissions
}

/// What the wallet records of an account's part in a transaction's transparent side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Participation {
    /// The account has no part in the transaction, or the wallet records no transparent
    /// side of it.
    None,
    /// The account has a transparent output or spend in the transaction, or a shielded
    /// part in a transaction the wallet records as mixed.
    Recorded,
    /// The account has a shielded part in a transaction whose raw bytes the wallet holds;
    /// they show whether it has a transparent side.
    IfRawShowsOne,
}

/// The account's part in transaction `id_tx`'s transparent side.
///
/// Its own transparent outputs and spends, recovered or scanned, count. So does a shielded
/// part (a received, spent or sent note, a payment to a transparent recipient among them) in
/// a transaction the wallet durably records as mixed: by detail work, stored display facts or
/// the route-2 marker, which outlive the work they replace. Raw bytes replace work and
/// display facts alike, so for a shielded part in a transaction with raw bytes, those bytes
/// decide.
fn participation(
    conn: &Connection,
    id_tx: i64,
    account: i64,
) -> Result<Participation, SqliteClientError> {
    let (own, shielded, mixed, raw): (bool, bool, bool, bool) = conn.query_row(
        "SELECT
             EXISTS (
                 SELECT 1 FROM transparent_received_outputs o
                 WHERE o.transaction_id = t.id_tx AND o.account_id = :account
                 UNION ALL
                 SELECT 1 FROM transparent_received_output_spends s
                 JOIN transparent_received_outputs o ON o.id = s.transparent_received_output_id
                 WHERE s.transaction_id = t.id_tx AND o.account_id = :account
                 UNION ALL
                 SELECT 1 FROM tpir_receive_events r
                 WHERE r.txid = t.txid AND r.account_id = :account
                 UNION ALL
                 SELECT 1 FROM tpir_spend_events s
                 WHERE s.spending_txid = t.txid AND s.account_id = :account
             ),
             EXISTS (
                 SELECT 1 FROM sapling_received_notes n
                 WHERE n.transaction_id = t.id_tx AND n.account_id = :account
                 UNION ALL
                 SELECT 1 FROM orchard_received_notes n
                 WHERE n.transaction_id = t.id_tx AND n.account_id = :account
                 UNION ALL
                 SELECT 1 FROM ironwood_received_notes n
                 WHERE n.transaction_id = t.id_tx AND n.account_id = :account
                 UNION ALL
                 SELECT 1 FROM sapling_received_note_spends s
                 JOIN sapling_received_notes n ON n.id = s.sapling_received_note_id
                 WHERE s.transaction_id = t.id_tx AND n.account_id = :account
                 UNION ALL
                 SELECT 1 FROM orchard_received_note_spends s
                 JOIN orchard_received_notes n ON n.id = s.orchard_received_note_id
                 WHERE s.transaction_id = t.id_tx AND n.account_id = :account
                 UNION ALL
                 SELECT 1 FROM ironwood_received_note_spends s
                 JOIN ironwood_received_notes n ON n.id = s.ironwood_received_note_id
                 WHERE s.transaction_id = t.id_tx AND n.account_id = :account
                 UNION ALL
                 SELECT 1 FROM sent_notes n
                 WHERE n.transaction_id = t.id_tx AND n.from_account_id = :account
             ),
             EXISTS (
                 SELECT 1 FROM transparent_detail_work w WHERE w.transaction_id = t.id_tx
                 UNION ALL
                 SELECT 1 FROM transparent_tx_display d WHERE d.transaction_id = t.id_tx
                 UNION ALL
                 SELECT 1 FROM ironwood_enhance_routing r
                 WHERE r.transaction_id = t.id_tx AND r.route = 2
             ),
             t.raw IS NOT NULL
         FROM transactions t
         WHERE t.id_tx = :tx",
        named_params![":tx": id_tx, ":account": account],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(if own || (shielded && mixed) {
        Participation::Recorded
    } else if shielded && raw {
        Participation::IfRawShowsOne
    } else {
        Participation::None
    })
}

/// The detail view; see `TransparentDetailRead::transparent_display_view`.
///
/// The view comes from the first source the wallet holds: the raw transaction, then stored
/// display facts, then the state of the transaction's detail work.
pub(crate) fn view<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    configured: Option<TransparentLedgerMode>,
    account: AccountUuid,
    txid: TxId,
) -> Result<Option<TransparentDisplayView>, SqliteClientError> {
    let mode = resolve_mode(conn, configured)?;
    let row = conn
        .query_row(
            "SELECT id_tx, raw IS NOT NULL, fee FROM transactions WHERE txid = :txid",
            named_params![":txid": txid.as_ref()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, Option<u64>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((id_tx, has_raw, stored_fee)) = row else {
        return Ok(None);
    };
    let account_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM accounts WHERE uuid = :account",
            named_params![":account": account.0],
            |row| row.get(0),
        )
        .optional()?;
    let account_part = match account_id {
        Some(account_id) => participation(conn, id_tx, account_id)?,
        None => Participation::None,
    };
    if account_part == Participation::None {
        return Ok(None);
    }
    let owned_outputs: Vec<u32> = conn
        .prepare_cached(&format!(
            "SELECT o.output_index FROM transparent_received_outputs o
             WHERE o.transaction_id = :tx AND o.account_id IS :account AND ({})",
            output_observation_condition("o"),
        ))?
        .query_map(named_params![":tx": id_tx, ":account": account_id], |row| {
            row.get(0)
        })?
        .collect::<Result<_, _>>()?;
    let transaction = if has_raw {
        let Some((_, transaction)) = crate::wallet::get_transaction(conn, params, txid)? else {
            return Ok(None);
        };
        Some(transaction)
    } else {
        None
    };
    let mut owned_inputs = owned_inputs(conn, id_tx, txid.as_ref(), account_id)?;
    // A recorded link cannot attribute a raw sender unless the transaction actually spends
    // that outpoint. Unlocking scripts can reveal a previously used public key on their own.
    if let Some(transaction) = &transaction {
        owned_inputs.retain(|(hash, index), _| {
            transaction.transparent_bundle().is_some_and(|bundle| {
                bundle
                    .vin
                    .iter()
                    .any(|input| input.prevout().hash() == hash && input.prevout().n() == *index)
            })
        });
    }
    let account = AccountView {
        conn,
        params,
        account_id,
        owned_inputs,
        owned_outputs,
    };
    if let Some(transaction) = transaction {
        return view_from_raw(&account, account_part, &transaction, stored_fee);
    }
    if let Some(facts) = stored_facts(conn, id_tx)? {
        return view_from_stored_facts(&account, facts).map(Some);
    }
    view_from_work(conn, mode, id_tx, txid).map(Some)
}

/// The account's own part in one transaction, which marks senders and outputs as its own.
struct AccountView<'a, P> {
    conn: &'a Connection,
    params: &'a P,
    /// The account's internal id; `None` when the account is unknown.
    account_id: Option<i64>,
    /// The spent outpoints whose ownership the account can affirm, with their spent scripts.
    owned_inputs: OwnedInputScripts,
    /// The indices of the account's outputs that financial queries count.
    owned_outputs: Vec<u32>,
}

impl<P: consensus::Parameters> AccountView<'_, P> {
    fn display_address(&self, address: TransparentAddress) -> TransparentDisplayAddress {
        TransparentDisplayAddress {
            address,
            encoded: zcash_keys::encoding::encode_transparent_address_p(self.params, &address),
        }
    }

    /// The view of sender `found`, marked as the account's own when the account is known to
    /// have spent an output paying it here or, for a sender the publisher asserts from the
    /// spent outputs (`asserted`), when it is one of the account's addresses. An unlocking
    /// script alone can show any public key that has ever signed, so in a raw transaction
    /// only a known spend makes the sender the account's.
    fn sender(
        &self,
        found: TransparentAddress,
        asserted: bool,
    ) -> Result<TransparentDisplayViewSender, SqliteClientError> {
        let (conn, account_id) = (self.conn, self.account_id);
        let found = self.display_address(found);
        let owned = self
            .owned_inputs
            .values()
            .any(|script| transparent_display_address(script) == Some(found.address))
            || asserted
                && conn.query_row(
                    "SELECT EXISTS (SELECT 1 FROM addresses
                            WHERE account_id IS :account
                            AND cached_transparent_receiver_address = :address)",
                    named_params![":account": account_id, ":address": found.encoded],
                    |row| row.get(0),
                )?;
        Ok(TransparentDisplayViewSender::Address {
            address: found,
            owned,
        })
    }

    /// The view of output `index`, marked as the account's own when financial queries count it.
    fn output(
        &self,
        index: u32,
        value: Zatoshis,
        found: Option<TransparentAddress>,
    ) -> TransparentDisplayViewOutput {
        TransparentDisplayViewOutput {
            index,
            value,
            address: found.map(|address| self.display_address(address)),
            owned: self.owned_outputs.contains(&index),
        }
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The view read from the raw transaction. `None` when the account's part is only shielded and
/// the transaction has no transparent side.
fn view_from_raw<P: consensus::Parameters>(
    account: &AccountView<'_, P>,
    account_part: Participation,
    transaction: &Transaction,
    stored_fee: Option<u64>,
) -> Result<Option<TransparentDisplayView>, SqliteClientError> {
    let bundle = transaction.transparent_bundle();
    let coinbase = bundle.is_some_and(|b| b.is_coinbase());
    let vin = match bundle {
        Some(b) if !coinbase => &b.vin[..],
        _ => &[],
    };
    // The address each input spends, as far as its unlocking script shows it.
    let spent_addresses: Vec<Option<TransparentAddress>> = vin
        .iter()
        .map(|i| spent_address(&i.script_sig().0.0))
        .collect();
    let sender = if coinbase {
        TransparentDisplayViewSender::Coinbase
    } else if vin.is_empty() {
        TransparentDisplayViewSender::Shielded
    } else {
        match spent_addresses.iter().flatten().next() {
            Some(found) => account.sender(*found, false)?,
            None => TransparentDisplayViewSender::NonStandard,
        }
    };
    let outputs: Vec<_> = bundle
        .map(|b| {
            b.vout
                .iter()
                .zip(0u32..)
                .map(|(o, index)| {
                    account.output(
                        index,
                        o.value(),
                        transparent_display_address(&o.script_pubkey().0.0),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let owned = count(
        vin.iter()
            .filter(|i| {
                account
                    .owned_inputs
                    .contains_key(&(*i.prevout().hash(), i.prevout().n()))
            })
            .count(),
    );
    let input_count = count(vin.len());
    if account_part == Participation::IfRawShowsOne && outputs.is_empty() && input_count == 0 {
        return Ok(None);
    }
    let omissions = omissions(
        &sender,
        spent_addresses.windows(2).any(|w| w[0] != w[1]),
        owned,
        input_count,
        !vin.is_empty() && shielded_contribution(transaction).is_some_and(|c| c > 0),
        &outputs,
        false,
    );
    let fee = if coinbase {
        WholeTransactionFee::NotApplicable
    } else {
        stored_fee
            .and_then(|f| Zatoshis::from_u64(f).ok())
            .map_or(WholeTransactionFee::Unknown, WholeTransactionFee::Exact)
    };
    Ok(Some(TransparentDisplayView::Available(
        TransparentDisplayDetails {
            coinbase,
            fee,
            input_count,
            output_count: count(outputs.len()),
            shielded: transaction.sprout_bundle().is_some()
                || transaction.sapling_bundle().is_some()
                || transaction.orchard_bundle().is_some()
                || transaction.ironwood_bundle().is_some(),
            sender,
            outputs,
            omissions,
            source: TransparentDisplaySource::RawTransaction,
        },
    )))
}

/// The view read from stored display facts.
fn view_from_stored_facts<P: consensus::Parameters>(
    account: &AccountView<'_, P>,
    facts: TransparentDisplayFacts,
) -> Result<TransparentDisplayView, SqliteClientError> {
    let sender = match facts.sender {
        TransparentDisplaySender::Absent if facts.coinbase => {
            TransparentDisplayViewSender::Coinbase
        }
        TransparentDisplaySender::Absent => TransparentDisplayViewSender::Shielded,
        TransparentDisplaySender::Address(found) => account.sender(found, true)?,
        TransparentDisplaySender::NonStandard => TransparentDisplayViewSender::NonStandard,
    };
    let outputs: Vec<_> = facts
        .outputs
        .iter()
        .zip(0u32..)
        .map(|(o, index)| account.output(index, o.value, o.address))
        .collect();
    let omissions = omissions(
        &sender,
        facts.multiple_source_scripts,
        count(account.owned_inputs.len()),
        facts.input_count,
        facts.shielded_and_transparent_funding,
        &outputs,
        facts.more_than_two_outputs(),
    );
    Ok(TransparentDisplayView::Available(
        TransparentDisplayDetails {
            coinbase: facts.coinbase,
            fee: facts.metadata().fee,
            input_count: facts.input_count,
            output_count: facts.output_count,
            shielded: facts.shielded_components,
            sender,
            outputs,
            omissions,
            source: TransparentDisplaySource::Display(facts.provenance),
        },
    ))
}

/// The detail work the listing would return for a transaction.
enum ListedWork {
    /// No listable work: none is queued, or the listing would not return it.
    None,
    /// Listable work, with the outcome code of its last lookup; `None` before the first.
    Listed(Option<i64>),
}

/// The view of a transaction without raw bytes or stored facts, from its detail work.
fn view_from_work(
    conn: &Connection,
    mode: TransparentLedgerMode,
    id_tx: i64,
    txid: TxId,
) -> Result<TransparentDisplayView, SqliteClientError> {
    // Work counts only while the listing would return it, now or once the transaction is mined
    // again; otherwise the view is what it would be without work.
    let listed_work = conn
        .query_row(
            &format!(
                "SELECT w.last_outcome FROM transparent_detail_work w
                 JOIN transactions t ON t.id_tx = w.transaction_id
                 WHERE w.transaction_id = :tx AND {}",
                listable_work_sql()
            ),
            named_params![
                ":tx": id_tx,
                ":public": mode.retains_public_authority(),
                ":enhancement": TxQueryType::Enhancement.code(),
            ],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .map_or(ListedWork::None, ListedWork::Listed);
    Ok(match listed_work {
        ListedWork::Listed(None | Some(NOT_YET_PUBLISHED)) => TransparentDisplayView::Pending,
        ListedWork::Listed(Some(NOT_COVERED)) => TransparentDisplayView::NotCovered,
        ListedWork::Listed(Some(_)) => TransparentDisplayView::Unavailable,
        // Payload retrieval fetches the raw transaction only under public authority.
        ListedWork::None if !mode.retains_public_authority() => TransparentDisplayView::Unavailable,
        ListedWork::None => {
            let payload_owned: bool = conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM tx_retrieval_queue
                                WHERE txid = :txid AND query_type = :enhancement)",
                named_params![
                    ":txid": txid.as_ref(),
                    ":enhancement": TxQueryType::Enhancement.code(),
                ],
                |row| row.get(0),
            )?;
            if payload_owned {
                TransparentDisplayView::Pending
            } else {
                TransparentDisplayView::Unavailable
            }
        }
    })
}
