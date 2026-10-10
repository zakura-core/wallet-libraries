//! Checking display facts against everything the wallet holds about a transaction.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension as _, named_params};
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::transparent_ledger::{
    TransparentDisplayContradiction, TransparentDisplayFacts, TransparentDisplaySender,
    transparent_display_address,
};
use zcash_protocol::value::Zatoshis;

use crate::error::SqliteClientError;

use super::super::output_observation_condition;

/// What the wallet knows about one outpoint a transaction spends.
#[derive(Default)]
pub(super) struct KnownInput {
    /// The spending input's index, when a recovered spend names it.
    input_index: Option<u32>,
    /// The script of the spent output, when known.
    script: Option<Vec<u8>>,
    /// The value of the spent output, when known.
    value: Option<u64>,
}

/// Every distinct outpoint the wallet knows transaction `tx` (`txid`) spends, by outpoint:
/// recovered spends (with input index and script, and value once the output is recovered),
/// spend links to owned outputs (script and value only while financial queries count
/// the output), and public spend links from the spend map (the outpoint only).
/// These records can reject a contradiction even when they no longer establish ownership.
pub(super) fn known_inputs(
    conn: &Connection,
    tx: i64,
    txid: &[u8],
) -> Result<BTreeMap<([u8; 32], u32), KnownInput>, SqliteClientError> {
    let counted = output_observation_condition("o");
    let mut inputs: BTreeMap<([u8; 32], u32), KnownInput> = BTreeMap::new();
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT e.prevout_txid, e.prevout_output_index, e.input_index, e.prevout_script,
                (SELECT re.value_zat FROM tpir_receive_events re
                 WHERE re.txid = e.prevout_txid AND re.output_index = e.prevout_output_index)
         FROM tpir_spend_events e
         WHERE e.spending_txid = :txid
         UNION ALL
         SELECT ot.txid, o.output_index, NULL,
                CASE WHEN ({counted}) THEN o.script END,
                CASE WHEN ({counted}) THEN o.value_zat END
         FROM transparent_received_output_spends s
         JOIN transparent_received_outputs o ON o.id = s.transparent_received_output_id
         JOIN transactions ot ON ot.id_tx = o.transaction_id
         WHERE s.transaction_id = :tx
         UNION ALL
         SELECT m.prevout_txid, m.prevout_output_index, NULL, NULL, NULL
         FROM transparent_spend_map m
         WHERE m.spending_transaction_id = :tx"
    ))?;
    let mut rows = stmt.query(named_params![":tx": tx, ":txid": txid])?;
    while let Some(row) = rows.next()? {
        let outpoint = (row.get::<_, [u8; 32]>(0)?, row.get::<_, u32>(1)?);
        let known = inputs.entry(outpoint).or_default();
        known.input_index = known.input_index.or(row.get(2)?);
        if known.script.is_none() {
            known.script = row.get(3)?;
        }
        known.value = known.value.or(row.get(4)?);
    }
    Ok(inputs)
}

/// The address the first address-shaped input spends, when the wallet knows the index and
/// spent script of every input up to it: `Some(None)` when it knows all `count` inputs and
/// none is address-shaped, `None` when an input before the first address-shaped one is unknown.
pub(super) fn known_first_address(
    inputs: &BTreeMap<([u8; 32], u32), KnownInput>,
    count: u32,
) -> Option<Option<TransparentAddress>> {
    let by_index: BTreeMap<u32, Option<&[u8]>> = inputs
        .values()
        .filter_map(|i| i.input_index.map(|index| (index, i.script.as_deref())))
        .collect();
    for index in 0..count {
        let script = (*by_index.get(&index)?)?;
        if let Some(address) = transparent_display_address(script) {
            return Some(Some(address));
        }
    }
    Some(None)
}

/// Checks the sender and `multiple_source_scripts` against the spent scripts the wallet knows.
///
/// When it knows the script of every input, the flag must say whether they differ. When it
/// knows every input in order up to the first address-shaped one, the sender must be that
/// one's address; knowing every script but not every index, the sender must be one of them.
/// Otherwise it can only require the flag when it already knows two distinct scripts, and,
/// when the flag is clear, the sender to be the one script every input spends.
pub(super) fn sender_contradiction(
    facts: &TransparentDisplayFacts,
    inputs: &BTreeMap<([u8; 32], u32), KnownInput>,
) -> Option<TransparentDisplayContradiction> {
    use TransparentDisplayContradiction as C;
    let scripts: BTreeSet<&[u8]> = inputs
        .values()
        .filter_map(|i| i.script.as_deref())
        .collect();
    let all_known =
        inputs.len() == facts.input_count as usize && inputs.values().all(|i| i.script.is_some());
    if (scripts.len() > 1 && !facts.multiple_source_scripts)
        || (all_known && facts.multiple_source_scripts != (scripts.len() > 1))
    {
        return Some(C::SourceScripts);
    }

    let addressed: BTreeSet<TransparentAddress> = scripts
        .iter()
        .filter_map(|s| transparent_display_address(s))
        .collect();
    let consistent = match (facts.sender, known_first_address(inputs, facts.input_count)) {
        // Without inputs the wallet knows no spend (`InputCount`).
        (TransparentDisplaySender::Absent, _) => true,
        (TransparentDisplaySender::NonStandard, _) => addressed.is_empty(),
        (TransparentDisplaySender::Address(sender), Some(first)) => first == Some(sender),
        (TransparentDisplaySender::Address(sender), None) if all_known => {
            addressed.contains(&sender)
        }
        // Every input spends the one script the wallet may know.
        (TransparentDisplaySender::Address(sender), None) if !facts.multiple_source_scripts => {
            scripts
                .first()
                .is_none_or(|s| transparent_display_address(s) == Some(sender))
        }
        (TransparentDisplaySender::Address(_), None) => true,
    };
    (!consistent).then_some(C::Sender)
}

/// Checks the transparent value balance when the wallet knows the value of every input.
///
/// The shielded pools' net contribution is the fee plus the outputs minus the inputs. With
/// only the first two outputs given, the fee and those outputs bound it from below.
pub(super) fn funding_contradiction(
    facts: &TransparentDisplayFacts,
    inputs: &BTreeMap<([u8; 32], u32), KnownInput>,
) -> Option<TransparentDisplayContradiction> {
    if facts.input_count == 0 || inputs.len() != facts.input_count as usize {
        return None;
    }
    let spent: u128 = inputs
        .values()
        .map(|i| i.value.map(u128::from))
        .sum::<Option<u128>>()?;
    let paid = u128::from(facts.fee.into_u64())
        + facts
            .outputs
            .iter()
            .map(|o| u128::from(o.value.into_u64()))
            .sum::<u128>();
    let contradicted = if paid > spent {
        // The shielded pools paid part of it (or, without shielded components, it is
        // unbalanced: mixed funding requires them).
        !facts.shielded_and_transparent_funding
    } else if !facts.more_than_two_outputs() {
        // Every output is given: the shielded pools contributed nothing, and a transaction
        // without shielded components balances exactly.
        facts.shielded_and_transparent_funding || (!facts.shielded_components && paid != spent)
    } else {
        false
    };
    contradicted.then_some(TransparentDisplayContradiction::Funding)
}

/// Checks `facts` against everything the wallet holds about transaction `tx`.
pub(super) fn validate(
    conn: &Connection,
    tx: i64,
    tx_index: Option<u32>,
    stored_fee: Option<u64>,
    facts: &TransparentDisplayFacts,
) -> Result<Option<TransparentDisplayContradiction>, SqliteClientError> {
    use TransparentDisplayContradiction as C;
    let txid = facts.txid.as_ref();
    let inputs = known_inputs(conn, tx, txid)?;
    let known_spends = u32::try_from(inputs.len()).unwrap_or(u32::MAX);

    // Coinbase: the flag must agree with the known position and with recovered receive events.
    // A coinbase transaction spends nothing, so no known spend may name it, and pays no fee.
    let event_coinbase: Vec<bool> = conn
        .prepare_cached("SELECT DISTINCT coinbase FROM tpir_receive_events WHERE txid = :txid")?
        .query_map(named_params![":txid": txid], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    if tx_index.is_some_and(|i| (i == 0) != facts.coinbase)
        || event_coinbase.iter().any(|c| *c != facts.coinbase)
        || (facts.coinbase
            && (facts.fee != Zatoshis::ZERO || facts.input_count != 0 || known_spends > 0))
    {
        return Ok(Some(C::Coinbase));
    }
    if !facts.is_well_formed() {
        return Ok(Some(C::Malformed));
    }

    // Every owned output financial queries count, and every recovered receive, must be below
    // the output count; at index 0 or 1 it must match the given output by value and by
    // script (P2PKH and P2SH by address; any other script faces a slot without one).
    let owned: Vec<(u32, u64, Vec<u8>)> = conn
        .prepare_cached(&format!(
            "SELECT output_index, value_zat, script FROM transparent_received_outputs o
             WHERE transaction_id = :tx AND ({})
             UNION
             SELECT output_index, value_zat, script FROM tpir_receive_events WHERE txid = :txid
             ORDER BY 1",
            output_observation_condition("o"),
        ))?
        .query_map(named_params![":tx": tx, ":txid": txid], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<Result<_, _>>()?;
    for (index, value, script) in owned {
        if index >= facts.output_count {
            return Ok(Some(C::OutputIndexOutOfRange { index }));
        }
        if let Some(given) = facts.outputs.get(index as usize)
            && (given.value.into_u64() != value
                || given.address != transparent_display_address(&script))
        {
            return Ok(Some(C::OwnedOutput { index }));
        }
    }

    // Recovered metadata must agree. An unknown recovered fee asserts nothing.
    let metadata_conflict: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM tpir_transaction_metadata WHERE txid = :txid
         AND (input_count != :inputs OR shielded != :shielded
              OR (fee_state = 2) != :coinbase
              OR (fee_state = 0 AND fee_zat != :fee)))",
        named_params![
            ":txid": txid,
            ":inputs": facts.input_count,
            ":shielded": facts.shielded_components,
            ":coinbase": facts.coinbase,
            ":fee": facts.fee.into_u64() as i64,
        ],
        |row| row.get(0),
    )?;
    if metadata_conflict {
        return Ok(Some(C::Metadata));
    }

    // The stored fee must be equal; a coinbase transaction has none.
    if let Some(stored) = stored_fee
        && (facts.coinbase || facts.fee.into_u64() != stored)
    {
        return Ok(Some(C::Fee));
    }

    // A known shielded component, or a route-2 marker, requires the shielded bit.
    if !facts.shielded_components {
        let shielded: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sapling_received_notes WHERE transaction_id = :tx)
                 OR EXISTS (SELECT 1 FROM orchard_received_notes WHERE transaction_id = :tx)
                 OR EXISTS (SELECT 1 FROM ironwood_received_notes WHERE transaction_id = :tx)
                 OR EXISTS (SELECT 1 FROM sapling_received_note_spends WHERE transaction_id = :tx)
                 OR EXISTS (SELECT 1 FROM orchard_received_note_spends WHERE transaction_id = :tx)
                 OR EXISTS (SELECT 1 FROM ironwood_received_note_spends WHERE transaction_id = :tx)
                 OR EXISTS (SELECT 1 FROM sent_notes WHERE transaction_id = :tx AND output_pool != 0)
                 OR EXISTS (SELECT 1 FROM ironwood_enhance_routing
                            WHERE transaction_id = :tx AND route = 2)",
            named_params![":tx": tx],
            |row| row.get(0),
        )?;
        if shielded {
            return Ok(Some(C::Shielded));
        }
    }

    // Known spends must name an input below the transparent input count.
    let beyond: Option<u32> = conn
        .query_row(
            "SELECT MIN(input_index) FROM tpir_spend_events
             WHERE spending_txid = :txid AND input_index >= :inputs",
            named_params![":txid": txid, ":inputs": facts.input_count],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    if let Some(index) = beyond {
        return Ok(Some(C::InputIndex { index }));
    }
    // Public spend links carry no input index, but each names a distinct input.
    if known_spends > facts.input_count {
        return Ok(Some(C::InputCount {
            known: known_spends,
        }));
    }

    Ok(sender_contradiction(facts, &inputs).or_else(|| funding_contradiction(facts, &inputs)))
}
