//! Per-pool effect completeness: what the account's discovery evidence establishes about its
//! part in a transaction, and the probes for evidence still missing.

use std::rc::Rc;

use rusqlite::{named_params, types::Value};
use zcash_client_backend::data_api::transparent_ledger::{EffectCompleteness, PoolEffect};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{PoolType, ShieldedPool, consensus::BlockHeight};

use crate::{
    error::SqliteClientError,
    wallet::{common::table_constants, encoding::pool_code},
};

use zcash_protocol::value::Zatoshis;

use super::evidence::{KnownPoolAmount, TransactionFacts};

#[cfg(feature = "transparent-inputs")]
use {
    super::super::recovery::account_ledger,
    crate::AccountUuid,
    zcash_client_backend::data_api::transparent_ledger::{AccountLifecycle, TransparentLedgerMode},
    zcash_keys::keys::transparent::gap_limits::GapLimits,
    zcash_primitives::transaction::TxId,
    zcash_protocol::consensus,
};

/// The pools this build supports, in the order history entries report them.
fn supported_pools() -> Vec<PoolType> {
    vec![
        #[cfg(feature = "transparent-inputs")]
        PoolType::Transparent,
        PoolType::SAPLING,
        #[cfg(feature = "orchard")]
        PoolType::ORCHARD,
        #[cfg(feature = "orchard")]
        PoolType::IRONWOOD,
    ]
}

/// What the account's transparent evidence can establish, independent of any one transaction.
#[cfg_attr(not(feature = "transparent-inputs"), allow(dead_code))]
pub(super) enum TransparentDiscovery {
    /// Public discovery holds authority.
    Public,
    /// Private authority applies. An active, unsuspended account's ledger covers every watched
    /// address through `covered_through`; otherwise nothing is covered.
    Private {
        covered_through: Option<BlockHeight>,
    },
}

/// What the account's transparent evidence establishes under `mode`: public discovery, or the
/// height its active, unsuspended ledger covers. The caller provides the read snapshot.
#[cfg(feature = "transparent-inputs")]
pub(super) fn transparent_discovery<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    mode: TransparentLedgerMode,
    account: AccountUuid,
) -> Result<TransparentDiscovery, SqliteClientError> {
    if mode.retains_public_authority() {
        return Ok(TransparentDiscovery::Public);
    }
    let ledger = account_ledger(conn, params, gap_limits, account)?;
    let covered_through = (ledger.lifecycle == AccountLifecycle::Active
        && !ledger.recovery_suspended)
        .then_some(ledger.status.covered_through)
        .flatten();
    Ok(TransparentDiscovery::Private { covered_through })
}

/// Payload ingestion links only notes whose nullifiers are already known. Later compact scanning
/// can discover a funding note without linking its unmined spender, since the reverse nullifier
/// map contains mined transactions only. A scanned chain tip therefore does not suffice: every
/// currently known owned nullifier in the payload must also have its spend link.
fn has_unlinked_shielded_spend(
    conn: &rusqlite::Connection,
    account_id: i64,
    transaction_id: i64,
    tx: &Transaction,
    pool: ShieldedPool,
) -> Result<bool, SqliteClientError> {
    let nullifiers: Vec<Value> = match pool {
        ShieldedPool::Sapling => tx
            .sapling_bundle()
            .iter()
            .flat_map(|bundle| bundle.shielded_spends())
            .map(|spend| Value::Blob(spend.nullifier().0.to_vec()))
            .collect(),
        #[cfg(feature = "orchard")]
        ShieldedPool::Orchard | ShieldedPool::Ironwood => {
            let bundle = match pool {
                ShieldedPool::Orchard => tx.orchard_bundle(),
                _ => tx.ironwood_bundle(),
            };
            bundle
                .iter()
                .flat_map(|bundle| bundle.actions().iter())
                .map(|action| Value::Blob(action.nullifier().to_bytes().to_vec()))
                .collect()
        }
        #[cfg(not(feature = "orchard"))]
        _ => {
            return Err(SqliteClientError::UnsupportedPoolType(PoolType::Shielded(
                pool,
            )));
        }
    };
    let prefix = table_constants::<SqliteClientError>(pool)?.table_prefix;
    Ok(conn.query_row(
        &format!(
            "SELECT EXISTS (
                 SELECT 1 FROM {prefix}_received_notes n
                 WHERE n.account_id = :account_id AND n.nf IN rarray(:nullifiers)
                 AND NOT EXISTS (
                     SELECT 1 FROM {prefix}_received_note_spends s
                     WHERE s.{prefix}_received_note_id = n.id
                     AND s.transaction_id = :transaction_id
                 )
             )"
        ),
        named_params![
            ":account_id": account_id,
            ":transaction_id": transaction_id,
            ":nullifiers": Rc::new(nullifiers),
        ],
        |row| row.get(0),
    )?)
}

/// Whether a shielded output the account received or sent in the transaction lacks its memo.
/// Compact scanning does not retrieve memos. For an owned sent output, a recovered received
/// memo satisfies the requirement only for the same account, transaction, pool, and output index.
/// A known empty memo is recovered; SQL NULL is unknown. Other received memos remain independent.
pub(super) fn has_unretrieved_memo(
    conn: &rusqlite::Connection,
    account_id: i64,
    transaction_id: i64,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM v_received_outputs
             WHERE account_id = :account_id AND transaction_id = :transaction_id
             AND pool != 0 AND memo IS NULL
         ) OR EXISTS (
             SELECT 1 FROM sent_notes s
             WHERE s.from_account_id = :account_id AND s.transaction_id = :transaction_id
             AND s.output_pool != 0 AND s.memo IS NULL
             AND NOT EXISTS (
                 SELECT 1 FROM v_received_outputs ro
                 WHERE ro.account_id = s.from_account_id
                 AND ro.transaction_id = s.transaction_id
                 AND ro.pool = s.output_pool AND ro.output_index = s.output_index
                 AND ro.memo IS NOT NULL
             )
         )",
        named_params![":account_id": account_id, ":transaction_id": transaction_id],
        |row| row.get(0),
    )?)
}

/// Whether the transaction has an output in `pool` that the wallet created for an external
/// address without recording its receipt. Local construction defers the receipt of a shielded
/// payment to one of the wallet's own external addresses until scanning or enhancement finds it,
/// so any such output may be an owned receipt not yet recorded.
fn has_unrecorded_sent_output(
    conn: &rusqlite::Connection,
    transaction_id: i64,
    pool: PoolType,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM sent_notes s
             WHERE s.transaction_id = :transaction_id AND s.output_pool = :pool
             AND s.to_account_id IS NULL
             AND NOT EXISTS (
                 SELECT 1 FROM v_received_outputs ro
                 WHERE ro.transaction_id = s.transaction_id
                 AND ro.pool = s.output_pool AND ro.output_index = s.output_index
             )
         )",
        named_params![":transaction_id": transaction_id, ":pool": pool_code(pool)],
        |row| row.get(0),
    )?)
}

/// Whether a parent of one of the transaction's unresolved transparent inputs is queued for
/// retrieval. Until it arrives, the input may spend one of the account's outputs.
#[cfg(feature = "transparent-inputs")]
fn has_pending_parent(
    conn: &rusqlite::Connection,
    transaction_id: i64,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tx_retrieval_queue q
             WHERE q.query_type = 1 AND q.dependent_transaction_id IS NOT NULL
             AND (
                 q.dependent_transaction_id = :transaction_id
                 OR q.txid IN (
                     SELECT m.prevout_txid FROM transparent_spend_map m
                     WHERE m.spending_transaction_id = :transaction_id
                 )
             )
         )",
        named_params![":transaction_id": transaction_id],
        |row| row.get(0),
    )?)
}

/// Whether the account's ledger records a spend in `txid` whose output it has not recovered.
/// Recovery's `unresolved_spends` count considers only placed spends, across transactions.
#[cfg(feature = "transparent-inputs")]
fn has_unresolved_spend(
    conn: &rusqlite::Connection,
    account_id: i64,
    txid: &TxId,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_spend_events s
             WHERE s.account_id = :account_id AND s.spending_txid = :txid
             AND NOT EXISTS (
                 SELECT 1 FROM tpir_receive_events r
                 WHERE r.account_id = :account_id AND r.mined_height IS NOT NULL
                 AND r.txid = s.prevout_txid AND r.output_index = s.prevout_output_index
             )
         )",
        named_params![":account_id": account_id, ":txid": txid.as_ref()],
        |row| row.get(0),
    )?)
}

/// What decides how complete one account's effect in each pool of one transaction is.
pub(super) struct EffectEvidence<'a> {
    pub(super) conn: &'a rusqlite::Connection,
    pub(super) account_id: i64,
    #[cfg(feature = "transparent-inputs")]
    pub(super) txid: &'a TxId,
    pub(super) tx_facts: &'a TransactionFacts,
    /// Contiguous scanning has reached the transaction's mined height.
    pub(super) scanned: bool,
    /// The full data of an unmined transaction, decoded when scanning has reached the tip and
    /// its spends can be checked for links to notes found since it was ingested.
    pub(super) unmined_data: Option<&'a Transaction>,
    /// The account's full viewing key lets scanning detect its shielded spends.
    pub(super) detects_shielded_spends: bool,
    #[cfg(feature = "transparent-inputs")]
    pub(super) discovery: &'a TransparentDiscovery,
}

impl EffectEvidence<'_> {
    /// How complete the account's recorded effect in `pool` is.
    pub(super) fn completeness(
        &self,
        pool: PoolType,
    ) -> Result<EffectCompleteness, SqliteClientError> {
        if self.tx_facts.constructed {
            // The wallet built and stored it, recording every input it spent and every
            // output to its own transparent or internal addresses. A shielded payment to one
            // of its external addresses is recorded only once scanning or enhancement finds
            // it.
            return Ok(match pool {
                PoolType::Shielded(_)
                    if !self.scanned
                        && has_unrecorded_sent_output(self.conn, self.tx_facts.id, pool)? =>
                {
                    EffectCompleteness::Incomplete
                }
                _ => EffectCompleteness::Complete,
            });
        }
        Ok(match pool {
            PoolType::Transparent => {
                #[cfg(feature = "transparent-inputs")]
                match self.discovery {
                    // Public discovery is authoritative only once its own pending input
                    // work is done.
                    TransparentDiscovery::Public
                        if has_pending_parent(self.conn, self.tx_facts.id)? =>
                    {
                        EffectCompleteness::Incomplete
                    }
                    TransparentDiscovery::Public => EffectCompleteness::PublicDiscovery,
                    TransparentDiscovery::Private { covered_through } => {
                        match (self.tx_facts.mined_height, *covered_through) {
                            (Some(mined), Some(covered))
                                if mined <= covered
                                    && !has_unresolved_spend(
                                        self.conn,
                                        self.account_id,
                                        self.txid,
                                    )? =>
                            {
                                EffectCompleteness::Complete
                            }
                            _ => EffectCompleteness::Incomplete,
                        }
                    }
                }
                #[cfg(not(feature = "transparent-inputs"))]
                EffectCompleteness::Incomplete
            }
            // Without a full viewing key, no amount of scanning reveals the account's spends.
            PoolType::Shielded(_) if !self.detects_shielded_spends => {
                EffectCompleteness::Incomplete
            }
            // Scanning a block finds every owned output and every spend of an output found
            // earlier, so everything through the contiguously scanned height is known. An
            // unmined transaction's full data reveals its owned outputs, but its spends are
            // linked only to notes already found. Once scanning reaches the tip, verify that
            // notes discovered after payload ingestion have their spend links too.
            PoolType::Shielded(pool) => match (self.tx_facts.mined_height, self.unmined_data) {
                (Some(_), _) if self.scanned => EffectCompleteness::Complete,
                (None, Some(data))
                    if !has_unlinked_shielded_spend(
                        self.conn,
                        self.account_id,
                        self.tx_facts.id,
                        data,
                        pool,
                    )? =>
                {
                    EffectCompleteness::Complete
                }
                _ => EffectCompleteness::Incomplete,
            },
        })
    }

    /// The account's effect in each pool this build supports, from its recorded amounts.
    pub(super) fn pool_effects(
        &self,
        recorded_amounts: &[KnownPoolAmount],
    ) -> Result<Vec<PoolEffect>, SqliteClientError> {
        let mut effects = vec![];
        for pool in supported_pools() {
            let (received, spent) = recorded_amounts
                .iter()
                .find(|amounts| amounts.pool == pool)
                .map_or((Zatoshis::ZERO, Zatoshis::ZERO), |amounts| {
                    (amounts.received, amounts.spent)
                });
            effects.push(PoolEffect {
                pool,
                received,
                spent,
                completeness: self.completeness(pool)?,
            });
        }
        Ok(effects)
    }
}
