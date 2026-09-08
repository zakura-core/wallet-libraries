//! Turning a recovered ledger into rows the wallet can commit.
//!
//! The arithmetic is upstream's and is not repeated here: [`Ledger`] takes
//! events and produces a UTXO set, a set of spends and a set of contradictions.
//! This translates that result into the store's vocabulary and attaches the
//! coverage that explains it.
//!
//! Two things are deliberately not smoothed over on the way through. An
//! unresolved spend — one whose consumed output the run never saw — is carried
//! into the wallet rather than dropped, because dropping it leaves an output in
//! the balance that something has already spent. And a script's coverage is
//! written per script rather than as one number for the run, because the run
//! may have read several ranges on behalf of several scripts.

use transparent_wallet::{Ledger, SyncOutcome};
use zakura_wallet_core::AccountId;
use zakura_wallet_store::{
    ProvisionalRevision, RecoveredOutput, RecoveredSpend, ScriptCoverage, TransparentLedger,
    UnresolvedSpend,
};
use zcash_protocol::{TxId, consensus::BlockHeight};

use transparent_filter::ScriptBytes;

/// Translates one run's outcome into rows to commit.
///
/// `scripts` is the group this run covered; each of them earns the run's
/// coverage, including the ones that matched nothing. A script that matched
/// nothing has been read over that range just as much as one that did, and
/// refusing to record that is what would make the next run re-read it.
pub fn into_ledger(
    outcome: &SyncOutcome,
    account: AccountId,
    scripts: &[ScriptBytes],
) -> TransparentLedger {
    TransparentLedger {
        outputs: outputs(&outcome.ledger),
        spends: spends(&outcome.ledger),
        unresolved: unresolved(&outcome.ledger),
        coverage: scripts
            .iter()
            .map(|script| ScriptCoverage {
                script: script.as_slice().to_vec(),
                account,
                settled_through: height(outcome.settled_through),
                covered_through: height(outcome.covered_through),
            })
            .collect(),
        provisional: outcome
            .provisional
            .iter()
            .map(|revision| ProvisionalRevision {
                shard_id: revision.shard_id,
                revision: revision.revision,
                manifest_digest: revision.manifest_digest.clone(),
                end_height: height(revision.end_height),
            })
            .collect(),
    }
}

/// Every output the run recovered, spent or not.
///
/// Spent ones included, and they are the awkward half. A `ConfirmedSpend`
/// carries the value and the script of what it consumed but not the height at
/// which that output was created, so the row is written without one. Leaving
/// the output out entirely would be worse in two ways: the spend would have
/// nothing to attach to, and a receive-and-spend that both fall inside the
/// covered range would appear in the history as neither.
fn outputs(ledger: &Ledger) -> Vec<RecoveredOutput> {
    let mut out: Vec<RecoveredOutput> = ledger
        .utxos()
        .map(|utxo| RecoveredOutput {
            txid: TxId::from_bytes(utxo.txid.0),
            output_index: utxo.output_index,
            script: utxo.script.clone(),
            value: utxo.value,
            mined_height: Some(height(u64::from(utxo.creation_height))),
            observed_at: height(u64::from(utxo.creation_height)),
            coinbase: Some(utxo.coinbase),
        })
        .collect();

    for spend in ledger.spends() {
        out.push(RecoveredOutput {
            txid: TxId::from_bytes(spend.spent_txid.0),
            output_index: spend.spent_output_index,
            script: spend.script.clone(),
            value: spend.value,
            // Unknown, and left unknown. See the note above.
            mined_height: None,
            // An output consumed at this height existed at this height, which
            // is all the gap limit needs.
            observed_at: height(u64::from(spend.height)),
            coinbase: None,
        });
    }
    out
}

fn spends(ledger: &Ledger) -> Vec<RecoveredSpend> {
    ledger
        .spends()
        .iter()
        .map(|spend| RecoveredSpend {
            spending_txid: TxId::from_bytes(spend.spending_txid.0),
            height: height(u64::from(spend.height)),
            spent_txid: TxId::from_bytes(spend.spent_txid.0),
            spent_output_index: spend.spent_output_index,
        })
        .collect()
}

fn unresolved(ledger: &Ledger) -> Vec<UnresolvedSpend> {
    ledger
        .unresolved()
        .iter()
        .map(|entry| UnresolvedSpend {
            spending_txid: TxId::from_bytes(entry.event.spending_txid.0),
            input_index: entry.event.input_index,
            spent_txid: TxId::from_bytes(entry.event.spent_txid.0),
            spent_output_index: entry.event.spent_output_index,
            height: height(u64::from(entry.event.height)),
            script: entry.script.clone(),
        })
        .collect()
}

/// A protocol height as the wallet's height type.
///
/// Saturating rather than fallible: a height above `u32::MAX` cannot occur on
/// this chain, and threading a failure through every conversion for a case that
/// cannot arise would obscure the ones that can.
fn height(value: u64) -> BlockHeight {
    BlockHeight::from_u32(u32::try_from(value).unwrap_or(u32::MAX))
}
