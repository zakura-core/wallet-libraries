use incrementalmerkletree::Position;
use orchard::{
    keys::Diversifier,
    note::{Note, RandomSeed, Rho},
    value::NoteValue,
};
use rusqlite::{Connection, OptionalExtension, Transaction, named_params};
use uuid::Uuid;
use zcash_client_backend::data_api::{
    Account as _, PublicTransactionEnhancementRequest,
    enhance_pir::{
        EnhancePirRequest, EnhancePirStoreResult, EnhancePirSuspension, EnhancePirWork,
        EnhanceRecord, EnhancementMode, IronwoodEnhanceDiscoveryFailure,
        IronwoodEnhanceDiscoveryFailureReason, IronwoodEnhanceDiscoveryRequest,
        IronwoodEnhanceRequestId, TransactionEnhancementWork,
        storage::{
            EnhancePirStorage, IronwoodOutgoingResult, PendingIronwoodMemo,
            PendingIronwoodMetadata, PendingIronwoodOutgoing, StoredIronwoodMetadata,
            ValidatedIronwoodEnhancement,
        },
    },
};
use zcash_client_backend::wallet::{IronwoodEnhancementPlan, Recipient, WalletTx};
use zcash_keys::address::Receiver;
use zcash_primitives::transaction::TxId;
use zcash_protocol::{PoolType, ShieldedPool, consensus::Parameters};
use zip32::Scope;

use crate::{AccountUuid, error::SqliteClientError};

use super::transparent_ledger;
use super::{TxQueryType, get_account, memo_repr, orchard::parse_note_version};

use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode;

// SQL fragments are macros so that `concat!` can assemble constant statements.
// Defined before the submodules so that they can use them too.
macro_rules! private_protected {
    () => {
        0
    };
}

/// Joins transaction `t` to its routing row `r`, keeping only transactions that still await
/// private enhancement: protected route, no raw data, mined. Extend the WHERE with `AND`.
macro_rules! active_private_tx {
    () => {
        concat!(
            "JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
             WHERE r.route = ",
            private_protected!(),
            " AND t.raw IS NULL AND t.mined_height IS NOT NULL"
        )
    };
}

/// Like [`active_private_tx`], but also keeps transactions whose transparent details are
/// unsupported (route 2) while public authority is absent (`:public_authority` false). Only
/// received memos and received-note-bound shape metadata are retrieved for them. Note
/// decryption authenticates a memo without authenticating the service's shape assertion. Extend the WHERE with `AND`.
macro_rules! active_memo_tx {
    () => {
        concat!(
            "JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
             WHERE (r.route = ",
            private_protected!(),
            " OR (r.route = 2 AND NOT :public_authority))
             AND t.raw IS NULL AND t.mined_height IS NOT NULL"
        )
    };
}

/// Whether transaction `:tx` has queued memo, outgoing or metadata work.
macro_rules! has_private_work {
    () => {
        "(EXISTS(SELECT 1 FROM ironwood_memo_retrieval_queue q
                 JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
                 WHERE rn.transaction_id = :tx)
          OR EXISTS(SELECT 1 FROM ironwood_enhance_outgoing_queue WHERE transaction_id = :tx)
          OR EXISTS(SELECT 1 FROM ironwood_enhance_metadata_queue WHERE transaction_id = :tx))"
    };
}

pub(crate) mod discovery;
mod metadata;

// A route is transaction-wide. LwdRequired is sticky, including across rescans.
// PrivateProtected survives completion and rewinds; only an explicit LWD decision or
// transaction deletion with retrieval-intent cleanup ends protection. Route 2
// (PrivateDetailsUnsupported) is sticky under PrivateRequired; once public authority is
// current again it is ordinary public LWD work. Until then it keeps private memo work for
// its received Ironwood notes, including shape retrieval once their memos are known.
// See [`queue_unsupported_memos`].
// No row retains ordinary enhancement semantics for unclassified and legacy transactions. Its
// history expiry is display-only and never controls spendability.
const PRIVATE_PROTECTED: i64 = private_protected!();
const LWD_REQUIRED: i64 = 1;
const PRIVATE_DETAILS_UNSUPPORTED: i64 = 2;

type PendingOutgoingRow = ([u8; 32], u32, [u8; 32], [u8; 32], [u8; 32], [u8; 52]);

const ACTIVE_PRIVATE_TX: &str = active_private_tx!();
const ACTIVE_MEMO_TX: &str = active_memo_tx!();

const OUTSTANDING_OUTGOING: &str = concat!(
    "
    FROM ironwood_enhance_outgoing_queue q
    JOIN transactions t ON t.id_tx = q.transaction_id
    ",
    active_private_tx!()
);

fn retire_enhancement_if_complete(
    tx: &Connection,
    tx_ref: crate::TxRef,
) -> Result<(), SqliteClientError> {
    tx.execute(
        concat!(
            "DELETE FROM tx_retrieval_queue
         WHERE txid = (SELECT txid FROM transactions WHERE id_tx = :tx)
           AND query_type = :enhancement
           AND EXISTS (SELECT 1 FROM ironwood_enhance_routing
                       WHERE transaction_id = :tx AND route = ",
            private_protected!(),
            ")
           AND NOT ",
            has_private_work!(),
            "
           AND NOT EXISTS (
               SELECT 1 FROM ironwood_enhance_discovery_queue WHERE transaction_id = :tx)"
        ),
        named_params![
            ":tx": tx_ref.0,
            ":enhancement": TxQueryType::Enhancement.code(),
        ],
    )?;
    Ok(())
}

/// Selects the undecryptable outgoing candidates of `:tx` that the wallet's own value
/// accounting proves were funded by no account it holds: dummies, in the wallet's own sends.
///
/// An Ironwood bundle has one action per spend or output, whichever is more numerous, so a
/// transaction spending many notes to few recipients is padded with dummy outputs. Compact
/// data cannot tell a dummy from a payment, so each is queued as an outgoing candidate, and
/// OVK decryption of its record then fails with `NotRecoverable`. That result alone does not
/// prove a dummy: it could also be an OVK-discarded payment or corrupt service data.
///
/// Every other output of the transaction being recovered is what proves it. A privately
/// routed transaction is Ironwood-only with no transparent data, so its fee equals the value
/// of its spends minus its outputs. The rule applies when the wallet has at least one linked
/// spend, no discovery work remains, every decryptable output is recovered (no memo, metadata
/// or recoverable outgoing work), the fee is known, and
///
/// `sum(linked spent notes) = sum(recovered outputs) + fee`.
///
/// This proves the remaining outputs were funded by nothing the wallet currently holds: their
/// value equals the inputs of which the wallet has no linked spend. Those are either another
/// party's inputs or the notes of an account deleted since the transaction was scanned (the
/// deletion cascades away its notes and spend links, while the remaining accounts keep the
/// candidates alive). Neither is this wallet's sent history to recover: another party's
/// outputs cannot be decrypted with this wallet's OVKs, and a deleted account's sent notes
/// are deleted with it. Re-importing that account links its spends again, which reopens the
/// transaction and rebuilds its candidates. Rows orphaned by account deletion (no funding
/// account left) are never retired, and they block the transaction.
///
/// Exclusions, by design:
/// - An undecryptable output that really is a zero-value payment (for example a memo-only
///   output built with its OVK discarded) is indistinguishable from a dummy and is retired
///   with them. Decryptable zero-value outputs are unaffected: they are recovered normally
///   before this rule can apply.
/// - The fee is PIR metadata. A service that inflates it by the value of a withheld output
///   could make that output look like a dummy; this is an accepted risk.
const VALUE_BALANCED_DUMMIES: &str = concat!(
    "ironwood_enhance_outgoing_queue
     WHERE transaction_id = :tx AND not_recoverable = 1
       AND EXISTS (SELECT 1 FROM transactions t ",
    active_private_tx!(),
    " AND t.id_tx = :tx AND t.fee IS NOT NULL)
       AND NOT EXISTS (
           SELECT 1 FROM ironwood_enhance_outgoing_queue o
           WHERE o.transaction_id = :tx
             AND (o.not_recoverable = 0 OR NOT EXISTS (
                 SELECT 1 FROM ironwood_enhance_outgoing_accounts a
                 WHERE a.commitment_tree_position = o.commitment_tree_position)))
       AND NOT EXISTS (
           SELECT 1 FROM ironwood_memo_retrieval_queue q
           JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
           WHERE rn.transaction_id = :tx)
       AND NOT EXISTS (SELECT 1 FROM ironwood_enhance_metadata_queue WHERE transaction_id = :tx)
       AND NOT EXISTS (SELECT 1 FROM ironwood_enhance_discovery_queue WHERE transaction_id = :tx)
       AND EXISTS (SELECT 1 FROM ironwood_received_note_spends WHERE transaction_id = :tx)
       AND (SELECT COALESCE(SUM(rn.value), 0)
            FROM ironwood_received_note_spends s
            JOIN ironwood_received_notes rn ON rn.id = s.ironwood_received_note_id
            WHERE s.transaction_id = :tx)
         = (SELECT fee FROM transactions WHERE id_tx = :tx)
         + (SELECT COALESCE(SUM(value), 0) FROM (
                SELECT value FROM sent_notes
                WHERE transaction_id = :tx AND output_pool = :ironwood_pool
                UNION ALL
                SELECT rn.value FROM ironwood_received_notes rn
                WHERE rn.transaction_id = :tx
                  AND NOT EXISTS (
                      SELECT 1 FROM sent_notes sn
                      WHERE sn.transaction_id = :tx AND sn.output_pool = :ironwood_pool
                        AND sn.output_index = rn.action_index)))"
);

/// Deletes the outgoing candidates selected by [`VALUE_BALANCED_DUMMIES`], so they stop being
/// reported as suspended work and no longer hold the transaction's retrieval request open.
///
/// A later compact rescan rebuilds the outgoing queue from the scanned candidates, so retired
/// dummies are queried once more and retired again. Nothing is lost by that; recovered
/// outputs are never requeued.
fn retire_value_balanced_dummies(
    conn: &Connection,
    tx_ref: crate::TxRef,
) -> Result<(), SqliteClientError> {
    // Select once: deleting account rows would make the remaining queue rows look orphaned.
    let positions = conn
        .prepare(&format!(
            "SELECT commitment_tree_position FROM {VALUE_BALANCED_DUMMIES}"
        ))?
        .query_map(
            named_params![
                ":tx": tx_ref.0,
                ":ironwood_pool": super::pool_code(PoolType::Shielded(ShieldedPool::Ironwood)),
            ],
            |row| row.get::<_, i64>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    for position in positions {
        // Explicit rather than relying on ON DELETE CASCADE.
        conn.execute(
            "DELETE FROM ironwood_enhance_outgoing_accounts WHERE commitment_tree_position = ?",
            [position],
        )?;
        conn.execute(
            "DELETE FROM ironwood_enhance_outgoing_queue WHERE commitment_tree_position = ?",
            [position],
        )?;
    }
    Ok(())
}

/// Re-evaluates every suspended transaction after an account is deleted.
///
/// Suspended candidates are never queried again, so `apply` never revisits them. Deleting a
/// funding account removes its spend links and sent notes, which can leave the remaining
/// accounts' side exactly balanced; without this pass such a transaction would keep its
/// suspension and retrieval request until a rescan.
pub(crate) fn retire_after_account_deletion(conn: &Connection) -> Result<(), SqliteClientError> {
    let transactions = conn
        .prepare(
            "SELECT DISTINCT transaction_id FROM ironwood_enhance_outgoing_queue
             WHERE not_recoverable = 1",
        )?
        .query_map([], |row| row.get(0).map(crate::TxRef))?
        .collect::<Result<Vec<_>, _>>()?;
    for tx_ref in transactions {
        retire_value_balanced_dummies(conn, tx_ref)?;
        retire_enhancement_if_complete(conn, tx_ref)?;
    }
    Ok(())
}

/// Clears private work without removing recovered data or an ordinary request.
pub(crate) fn clear_work(conn: &Connection, tx_ref: crate::TxRef) -> Result<(), SqliteClientError> {
    super::ironwood_hooks::clear_ironwood_enhancement_work(conn, tx_ref)
}

fn route(conn: &Connection, tx_ref: crate::TxRef) -> Result<Option<i64>, SqliteClientError> {
    conn.query_row(
        "SELECT route FROM ironwood_enhance_routing WHERE transaction_id = :tx",
        named_params![":tx": tx_ref.0],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

/// Writes the public LWD route and restores an ordinary enhancement request.
///
/// Callers that lack public authority must use [`require_private_details_unsupported`] instead.
fn require_lwd(
    conn: &Connection,
    tx_ref: crate::TxRef,
    expected_generation: u64,
) -> Result<(), SqliteClientError> {
    transparent_ledger::ensure_policy_generation(conn, expected_generation)?;
    conn.execute(
        "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (:tx, :route)
         ON CONFLICT(transaction_id) DO UPDATE SET route = excluded.route",
        named_params![":tx": tx_ref.0, ":route": LWD_REQUIRED],
    )?;
    clear_work(conn, tx_ref)?;
    // Keep (or restore after earlier partial completion) the normal request. Stamp the
    // current generation; do not refresh it on conflict.
    conn.execute(
        "INSERT INTO tx_retrieval_queue (txid, query_type, policy_generation)
         SELECT txid, :enhancement, :generation FROM transactions WHERE id_tx = :tx AND raw IS NULL
         ON CONFLICT(txid, query_type) DO NOTHING",
        named_params![
            ":tx": tx_ref.0,
            ":enhancement": TxQueryType::Enhancement.code(),
            ":generation": i64::try_from(expected_generation).map_err(|_| {
                SqliteClientError::CorruptedData("policy_generation does not fit i64".into())
            })?,
        ],
    )?;
    Ok(())
}

/// Marks a mixed or otherwise publicly unrecoverable transaction under PrivateRequired.
/// Clears retryable PIR jobs without deleting financial facts or inserting a public request,
/// then requeues the memos of its received Ironwood notes, which remain privately recoverable.
fn require_private_details_unsupported(
    conn: &Connection,
    tx_ref: crate::TxRef,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (:tx, :route)
         ON CONFLICT(transaction_id) DO UPDATE SET route = excluded.route",
        named_params![":tx": tx_ref.0, ":route": PRIVATE_DETAILS_UNSUPPORTED],
    )?;
    clear_work(conn, tx_ref)?;
    transparent_ledger::details::enqueue_tx(
        conn,
        tx_ref,
        zcash_client_backend::data_api::transparent_ledger::TransparentDetailReasons::MIXED,
    )?;
    queue_unsupported_memos(conn, Some(tx_ref))
}

/// Queues the unknown memos of the received Ironwood notes of route-2 transactions (all of them,
/// or only `tx_ref`) for private retrieval.
///
/// Decrypting the scanned note authenticates its memo whether or not the transaction has
/// transparent data, so a memo is recoverable even though the transaction's transparent details
/// are not. Retrieval queries a commitment tree position, never the transaction ID, and is
/// dispatched only while public authority is absent; with public authority, route 2 is ordinary
/// LWD work instead. Recovering a memo never changes the route: the transaction stays marked as
/// having unsupported details. A position another note already claims is left to it.
pub(crate) fn queue_unsupported_memos(
    conn: &Connection,
    tx_ref: Option<crate::TxRef>,
) -> Result<(), SqliteClientError> {
    super::ironwood_hooks::queue_ironwood_output_shape(conn, tx_ref)?;
    Ok(())
}

/// Routes a transaction that needs ordinary transparent enhancement: public LWD when
/// authority is current, otherwise a private-details marker with no public request.
fn require_transparent_details(
    conn: &Connection,
    configured: Option<TransparentLedgerMode>,
    tx_ref: crate::TxRef,
    expected_generation: u64,
) -> Result<EnhancePirStoreResult, SqliteClientError> {
    transparent_ledger::ensure_policy_generation(conn, expected_generation)?;
    if transparent_ledger::retains_public_authority(conn, configured)? {
        require_lwd(conn, tx_ref, expected_generation)?;
        Ok(EnhancePirStoreResult::LwdRequired)
    } else {
        require_private_details_unsupported(conn, tx_ref)?;
        Ok(EnhancePirStoreResult::PrivateDetailsUnsupported)
    }
}

/// Like [`require_transparent_details`], for scan-time paths that do not return a store result.
pub(super) fn route_transparent_details(
    conn: &Connection,
    configured: Option<TransparentLedgerMode>,
    tx_ref: crate::TxRef,
) -> Result<(), SqliteClientError> {
    let expected = transparent_ledger::capture_policy_generation(conn)?;
    let _ = require_transparent_details(conn, configured, tx_ref, expected)?;
    Ok(())
}

/// Test helper: writes the public LWD route under the current generation.
#[cfg(test)]
pub(crate) fn require_lwd_for_test(
    conn: &Connection,
    tx_ref: crate::TxRef,
) -> Result<(), SqliteClientError> {
    let expected = transparent_ledger::capture_policy_generation(conn)?;
    require_lwd(conn, tx_ref, expected)
}

pub(crate) fn is_protected(conn: &Connection, txid: TxId) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        concat!(
            "SELECT EXISTS(SELECT 1 FROM ironwood_enhance_routing r
         JOIN transactions t ON t.id_tx = r.transaction_id WHERE t.txid = :txid AND r.route = ",
            private_protected!(),
            ")"
        ),
        named_params![":txid": txid.as_ref()],
        |row| row.get(0),
    )?)
}

// Row kinds of the work statement, in scheduling order.
const REDISCOVER: u8 = 0;
const QUERY: u8 = 1;
const PUBLIC: u8 = 2;
const DISCOVERY_SUSPENDED: u8 = 3;
const OUTGOING_SUSPENDED: u8 = 4;

/// Selects enhancement rows from `tx_retrieval_queue q` (joined with `transactions t`) that may use
/// ordinary public transport. When `:protect_ironwood` is set, privately protected transactions
/// (`ironwood_enhance_routing.route = 0`) are excluded. Sticky route 2 (mixed details under a
/// non-public handle) is ordinary public LWD work once public authority is current, so it is not
/// excluded here; under `PrivateRequired` `:public_authority` is false and no public rows appear.
/// Private rows use the complementary `route = 0` predicate, so the two transports partition
/// payload work. Public rows also require a matching `policy_generation`.
const PUBLIC_ENHANCEMENT_ROUTE: &str = "(
    :public_authority
    AND q.policy_generation = :current_generation
    AND (
        NOT :protect_ironwood
        OR NOT EXISTS (
            SELECT 1
            FROM ironwood_enhance_routing p
            WHERE p.transaction_id = t.id_tx AND p.route = 0
        )
    )
)";

/// Builds one statement over the private queues and, optionally, the public enhancement queue.
/// Private rows require `route = 0`; public rows use [`PUBLIC_ENHANCEMENT_ROUTE`], which
/// excludes `route = 0` when `:protect_ironwood` is set, so each transaction takes one route.
fn transaction_enhancement_work_sql(private: bool, public: bool) -> String {
    let private_rows = format!(
        "SELECT DISTINCT {REDISCOVER} AS kind, height AS ordinal, hash AS identity,
                         NULL AS output_index, NULL AS reason, NULL AS tx_index
         FROM discovery WHERE reason IS NULL
         UNION ALL
         SELECT {QUERY}, position, txid, output_index, NULL, NULL FROM queries
         UNION ALL
         SELECT DISTINCT {DISCOVERY_SUSPENDED}, height, txid, NULL, reason, tx_index
         FROM discovery WHERE reason IS NOT NULL
         UNION ALL
         SELECT {OUTGOING_SUSPENDED}, q.commitment_tree_position, t.txid, q.output_index, NULL, NULL
           {OUTSTANDING_OUTGOING} AND q.not_recoverable = 1"
    );
    let public_rows = format!(
        "SELECT {PUBLIC} AS kind, 0 AS ordinal, q.txid AS identity, NULL AS output_index,
                NULL AS reason, NULL AS tx_index
         FROM tx_retrieval_queue q
         LEFT JOIN transactions t ON t.txid = q.txid
         WHERE q.query_type = :enhancement_type AND {}",
        PUBLIC_ENHANCEMENT_ROUTE
    );
    let rows = match (private, public) {
        (true, true) => format!("{private_rows} UNION ALL {public_rows}"),
        (true, false) => private_rows,
        (false, true) => public_rows,
        (false, false) => unreachable!("callers select at least one route"),
    };
    format!(
        "WITH discovery_jobs AS (
             SELECT transaction_id, suspended FROM ironwood_enhance_discovery_queue
             UNION ALL SELECT transaction_id, 0 FROM ironwood_enhance_metadata_queue WHERE commitment_tree_position IS NULL
         ), discovery AS (
             SELECT t.txid, t.mined_height AS height, t.tx_index, b.hash,
                    CASE WHEN q.suspended = 1 THEN 0
                         WHEN b.ironwood_commitment_tree_size IS NULL
                           OR (t.mined_height != 0 AND prior.ironwood_commitment_tree_size IS NULL)
                         THEN 1 ELSE NULL END AS reason
             FROM discovery_jobs q
             JOIN transactions t ON t.id_tx = q.transaction_id
             LEFT JOIN blocks b ON b.height = t.mined_height
             LEFT JOIN blocks prior ON prior.height = t.mined_height - 1
             {ACTIVE_PRIVATE_TX}
         ), queries AS (
             SELECT q.commitment_tree_position AS position, t.txid, rn.action_index AS output_index
             FROM ironwood_memo_retrieval_queue q
             JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
             JOIN transactions t ON t.id_tx = rn.transaction_id
             {ACTIVE_MEMO_TX}
               AND rn.memo IS NULL AND rn.commitment_tree_position = q.commitment_tree_position
             UNION
             SELECT q.commitment_tree_position, t.txid, q.output_index {OUTSTANDING_OUTGOING}
               AND q.not_recoverable = 0
             UNION
             SELECT q.commitment_tree_position, t.txid, q.output_index
             FROM ironwood_enhance_metadata_queue q
             JOIN transactions t ON t.id_tx = q.transaction_id
             {ACTIVE_MEMO_TX}
               AND q.commitment_tree_position IS NOT NULL
         )
         {rows}
         ORDER BY kind, ordinal, tx_index, identity, output_index"
    )
}

fn read_work(
    stmt: &mut rusqlite::CachedStatement<'_>,
    params: &[(&str, &dyn rusqlite::ToSql)],
) -> Result<Vec<TransactionEnhancementWork>, SqliteClientError> {
    stmt.query_map(params, |row| {
        let kind: u8 = row.get(0)?;
        let identity: [u8; 32] = row.get(2)?;
        let private_request = |ordinal: u64| -> rusqlite::Result<_> {
            Ok(EnhancePirRequest::new(
                ordinal.into(),
                IronwoodEnhanceRequestId::new(TxId::from_bytes(identity), row.get(3)?),
            ))
        };
        Ok(match kind {
            REDISCOVER => TransactionEnhancementWork::Private(EnhancePirWork::Rediscover(
                IronwoodEnhanceDiscoveryRequest {
                    height: zcash_protocol::consensus::BlockHeight::from_u32(row.get(1)?),
                    block_hash: zcash_primitives::block::BlockHash(identity),
                },
            )),
            QUERY => TransactionEnhancementWork::Private(EnhancePirWork::Query(private_request(
                row.get(1)?,
            )?)),
            PUBLIC => TransactionEnhancementWork::Public(PublicTransactionEnhancementRequest::new(
                TxId::from_bytes(identity),
            )),
            DISCOVERY_SUSPENDED => TransactionEnhancementWork::Private(EnhancePirWork::Suspended(
                EnhancePirSuspension::Discovery(IronwoodEnhanceDiscoveryFailure {
                    txid: TxId::from_bytes(identity),
                    reason: match row.get::<_, u8>(4)? {
                        0 => IronwoodEnhanceDiscoveryFailureReason::NoFundingAccounts,
                        1 => IronwoodEnhanceDiscoveryFailureReason::AnchorUnavailable,
                        _ => unreachable!("closed SQL CASE"),
                    },
                }),
            )),
            OUTGOING_SUSPENDED => TransactionEnhancementWork::Private(EnhancePirWork::Suspended(
                EnhancePirSuspension::OutgoingNotRecoverable(private_request(row.get(1)?)?),
            )),
            _ => unreachable!("closed SQL UNION"),
        })
    })?
    .collect::<Result<_, _>>()
    .map_err(Into::into)
}

/// Mode-independent private queue contents from one statement, for storage tests. Route-2 memo
/// work is included, as it is without public authority.
#[cfg(test)]
pub(crate) fn work(conn: &Connection) -> Result<Vec<EnhancePirWork>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(&transaction_enhancement_work_sql(true, false))?;
    Ok(
        read_work(&mut stmt, named_params![":public_authority": false])?
            .into_iter()
            .map(|work| match work {
                TransactionEnhancementWork::Private(work) => work,
                TransactionEnhancementWork::Public(_) => unreachable!("public rows not selected"),
            })
            .collect(),
    )
}

/// Routes public and private payload work from one snapshot: resolved mode, generation, and
/// queued rows are read together so a concurrent `PrivateRequired` transition cannot pair stale
/// public authority with a newer generation.
///
/// `Standard` exposes every ordinary enhancement request and no private work. `PrivateIronwood`
/// exposes private work for protected transactions and ordinary requests for all others.
/// Public rows require a resolved mode that retains public authority and a matching generation;
/// route 2 never appears as public work.
pub(crate) fn transaction_enhancement_work(
    conn: &Connection,
    mode: EnhancementMode,
    configured: Option<TransparentLedgerMode>,
) -> Result<Vec<TransactionEnhancementWork>, SqliteClientError> {
    transparent_ledger::with_read_snapshot(conn, |conn| {
        let private = mode == EnhancementMode::PrivateIronwood;
        let public_authority = transparent_ledger::retains_public_authority(conn, configured)?;
        let current_generation = transparent_ledger::durable_policy(conn)?
            .map(|p| p.generation)
            .unwrap_or(0);
        let mut stmt = conn.prepare_cached(&transaction_enhancement_work_sql(private, true))?;
        read_work(
            &mut stmt,
            named_params![
                ":enhancement_type": TxQueryType::Enhancement.code(),
                ":protect_ironwood": private,
                ":public_authority": public_authority,
                ":current_generation": i64::try_from(current_generation).map_err(|_| {
                    SqliteClientError::CorruptedData("policy_generation does not fit i64".into())
                })?,
            ],
        )
    })
}

/// Authentication context and writes share the transaction owned by the public operation.
struct Storage<'a, 'conn, P> {
    tx: &'a Transaction<'conn>,
    params: &'a P,
    configured: Option<TransparentLedgerMode>,
    expected_generation: u64,
}

impl<P: Parameters> EnhancePirStorage for Storage<'_, '_, P> {
    type AccountId = AccountUuid;
    type Account = super::Account;
    type Error = SqliteClientError;

    fn ironwood_transaction_metadata(
        &self,
        txid: TxId,
    ) -> Result<Option<StoredIronwoodMetadata>, Self::Error> {
        self.tx
            .query_row(
                "SELECT fee, expiry_height FROM transactions WHERE txid = ?",
                [txid.as_ref()],
                |r| {
                    Ok(StoredIronwoodMetadata {
                        fee_zatoshis: r.get(0)?,
                        expiry_height: r.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn pending_ironwood_metadata(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodMetadata<AccountUuid>>, Self::Error> {
        metadata::pending(self.tx, self.params, position)
    }

    fn get_account(&self, id: AccountUuid) -> Result<Option<Self::Account>, Self::Error> {
        super::get_account(self.tx, self.params, id)
    }

    fn pending_ironwood_memo(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodMemo<AccountUuid>>, Self::Error> {
        let public_authority =
            transparent_ledger::retains_public_authority(self.tx, self.configured)?;
        pending_note(self.tx, self.params, position, false, public_authority)
    }

    fn pending_ironwood_outgoing(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodOutgoing<AccountUuid>>, Self::Error> {
        pending_outgoing(self.tx, position)
    }

    fn compare_and_apply_ironwood_enhancement(
        &mut self,
        enhancement: ValidatedIronwoodEnhancement<AccountUuid>,
    ) -> Result<EnhancePirStoreResult, Self::Error> {
        apply(
            self.tx,
            self.params,
            self.configured,
            self.expected_generation,
            enhancement,
        )
    }
}

pub(crate) fn apply_records<P: Parameters>(
    tx: &Transaction<'_>,
    params: &P,
    configured: Option<TransparentLedgerMode>,
    records: &[(EnhancePirRequest, EnhanceRecord)],
) -> Result<zcash_client_backend::data_api::enhance_pir::EnhancePirBatchResult, SqliteClientError> {
    let expected_generation = transparent_ledger::capture_policy_generation(tx)?;
    zcash_client_backend::data_api::enhance_pir::storage::validate_and_apply_records(
        &mut Storage {
            tx,
            params,
            configured,
            expected_generation,
        },
        records,
    )
}

pub(crate) fn pending_outgoing(
    conn: &Connection,
    position: Position,
) -> Result<Option<PendingIronwoodOutgoing<AccountUuid>>, SqliteClientError> {
    let action: Option<PendingOutgoingRow> = conn
        .query_row(
            &format!(
                "SELECT t.txid, q.output_index, q.nullifier, q.cmx,
                        q.ephemeral_key, q.compact_ciphertext
                 {OUTSTANDING_OUTGOING}
                   AND q.commitment_tree_position = :position
                   AND q.not_recoverable = 0"
            ),
            named_params![":position": u64::from(position)],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((txid, output_index, nullifier, cmx, ephemeral_key, compact_ciphertext)) = action
    else {
        return Ok(None);
    };
    let mut stmt = conn.prepare_cached(
        "SELECT a.uuid
         FROM ironwood_enhance_outgoing_accounts oa
         JOIN accounts a ON a.id = oa.account_id
         WHERE oa.commitment_tree_position = :position
         ORDER BY a.uuid",
    )?;
    let account_ids = stmt
        .query_map(named_params![":position": u64::from(position)], |row| {
            row.get::<_, Uuid>(0).map(AccountUuid::from_uuid)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(PendingIronwoodOutgoing {
        request_id: IronwoodEnhanceRequestId::new(TxId::from_bytes(txid), output_index),
        account_ids,
        nullifier,
        cmx,
        ephemeral_key,
        compact_ciphertext,
    }))
}

/// Runs exactly once per scanned wallet transaction, after its notes are stored.
pub(crate) fn queue_scanned(
    conn: &Connection,
    configured: Option<TransparentLedgerMode>,
    tx_ref: crate::TxRef,
    tx: &WalletTx<AccountUuid>,
) -> Result<(), SqliteClientError> {
    // A wallet-funded mixed transaction may have no received Ironwood note
    // (for example, unshielding with only dummy Ironwood outputs). Its positive
    // LWD decision must still survive a later scan with omitted transparent data.
    if matches!(
        tx.ironwood_enhancement_plan(),
        IronwoodEnhancementPlan::Ineligible
    ) && (!tx.ironwood_spends().is_empty() || !tx.ironwood_outputs().is_empty())
    {
        return route_transparent_details(conn, configured, tx_ref);
    }
    // Ordinary rescans load only unspent nullifiers. They must not erase outgoing work
    // merely because an already-linked spend is absent from this scan's account set.
    let scanned_accounts = tx
        .ironwood_spends()
        .iter()
        .map(|s| *s.account_id())
        .collect::<std::collections::HashSet<_>>();
    if discovery::funding(conn, tx_ref)?
        .iter()
        .any(|(account, _)| !scanned_accounts.contains(account))
    {
        discovery::queue(conn, configured, tx_ref)?;
    }
    queue_transaction(conn, configured, tx_ref, tx.ironwood_enhancement_plan())
}

fn queue_transaction(
    conn: &Connection,
    configured: Option<TransparentLedgerMode>,
    tx_ref: crate::TxRef,
    plan: &IronwoodEnhancementPlan<AccountUuid>,
) -> Result<(), SqliteClientError> {
    let (has_raw, mined): (bool, bool) = conn.query_row(
        "SELECT raw IS NOT NULL, mined_height IS NOT NULL FROM transactions WHERE id_tx = :tx",
        named_params![":tx": tx_ref.0],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if has_raw || !mined {
        return clear_work(conn, tx_ref);
    }
    let route = route(conn, tx_ref)?;
    if route == Some(LWD_REQUIRED) || route == Some(PRIVATE_DETAILS_UNSUPPORTED) {
        return route_transparent_details(conn, configured, tx_ref);
    }
    let candidates = match plan {
        IronwoodEnhancementPlan::Eligible { outgoing } => outgoing,
        IronwoodEnhancementPlan::Ineligible => {
            let has_notes: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes WHERE transaction_id = :tx)",
                named_params![":tx": tx_ref.0],
                |row| row.get(0),
            )?;
            if route.is_some() || has_notes {
                route_transparent_details(conn, configured, tx_ref)?;
            }
            return Ok(());
        }
    };

    // A position identifies one action globally. Rewinds remove obsolete claims
    // before positions can be reused, so another transaction owning one of these
    // positions is an integrity failure, not an upsert target.
    for candidate in candidates {
        if outgoing_position_owned_by_other(conn, tx_ref, u64::from(candidate.position()))? {
            return Err(SqliteClientError::CorruptedData(format!(
                "Ironwood commitment tree position {} is already owned by another transaction",
                u64::from(candidate.position())
            )));
        }
    }

    // Reconcile incoming work only after every note in this transaction exists.
    // Rewinds have already evicted position claims left by a prior chain branch.
    conn.execute(
        "DELETE FROM ironwood_memo_retrieval_queue
         WHERE received_note_id IN (SELECT id FROM ironwood_received_notes WHERE transaction_id = :tx)",
        named_params![":tx": tx_ref.0],
    )?;
    conn.execute(
        "INSERT INTO ironwood_memo_retrieval_queue (received_note_id, commitment_tree_position)
         SELECT id, commitment_tree_position FROM ironwood_received_notes
         WHERE transaction_id = :tx AND memo IS NULL AND note_version = 3
           AND commitment_tree_position IS NOT NULL
         ON CONFLICT(commitment_tree_position) DO UPDATE SET received_note_id = excluded.received_note_id",
        named_params![":tx": tx_ref.0],
    )?;
    // Rebuild the candidates recognized by this scan so newly decrypted received/change
    // actions do not retain outgoing jobs. queue_scanned records a durable discovery
    // obligation first if spent funding was omitted; this list alone cannot prove completion.
    // Reconstruction also retries previously suspended candidates.
    conn.execute(
        "DELETE FROM ironwood_enhance_outgoing_queue WHERE transaction_id = :tx",
        named_params![":tx": tx_ref.0],
    )?;
    for candidate in candidates {
        let position = u64::from(candidate.position());
        // Replayed compact scans must not undo an already recovered sent output.
        let recovered: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sent_notes
             WHERE transaction_id = :tx AND output_pool = :pool AND output_index = :index)",
            named_params![":tx": tx_ref.0, ":pool": super::pool_code(PoolType::Shielded(ShieldedPool::Ironwood)), ":index": candidate.output_index()],
            |row| row.get(0),
        )?;
        if recovered {
            continue;
        }
        let changed = conn.execute(
            "INSERT INTO ironwood_enhance_outgoing_queue (
                 commitment_tree_position, transaction_id, output_index, nullifier, cmx,
                 ephemeral_key, compact_ciphertext
             ) VALUES (
                 :position, :tx, :output_index, :nullifier, :cmx,
                 :ephemeral_key, :compact_ciphertext
             )
             ON CONFLICT(commitment_tree_position) DO UPDATE SET
                 transaction_id = excluded.transaction_id,
                 output_index = excluded.output_index,
                 nullifier = excluded.nullifier,
                 cmx = excluded.cmx,
                 ephemeral_key = excluded.ephemeral_key,
                 compact_ciphertext = excluded.compact_ciphertext,
                 not_recoverable = 0
             WHERE ironwood_enhance_outgoing_queue.transaction_id = excluded.transaction_id",
            named_params![
                ":position": position,
                ":tx": tx_ref.0,
                ":output_index": i64::try_from(candidate.output_index()).expect("output index fits"),
                ":nullifier": candidate.nullifier(),
                ":cmx": candidate.cmx(),
                ":ephemeral_key": candidate.ephemeral_key(),
                ":compact_ciphertext": candidate.compact_ciphertext(),
            ],
        )?;
        if changed != 1 {
            return Err(SqliteClientError::CorruptedData(format!(
                "Ironwood commitment tree position {position} became owned by another transaction"
            )));
        }
        conn.execute(
            "DELETE FROM ironwood_enhance_outgoing_accounts
             WHERE commitment_tree_position = :position",
            named_params![":position": position],
        )?;
        for account in candidate.funding_accounts() {
            conn.execute(
                "INSERT INTO ironwood_enhance_outgoing_accounts (
                     commitment_tree_position, account_id
                 ) SELECT :position, id FROM accounts WHERE uuid = :uuid",
                named_params![
                    ":position": position,
                    ":uuid": account.expose_uuid(),
                ],
            )?;
        }
    }

    metadata::queue(conn, tx_ref, candidates)?;

    let has_work: bool = conn.query_row(
        concat!("SELECT ", has_private_work!()),
        named_params![":tx": tx_ref.0],
        |row| row.get(0),
    )?;
    if has_work {
        conn.execute(
            "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (:tx, :route)
             ON CONFLICT(transaction_id) DO NOTHING",
            named_params![":tx": tx_ref.0, ":route": PRIVATE_PROTECTED],
        )?;
    }
    // No route + no work is not proof of completion. A previously completed
    // private transaction, however, must not gain a txid request on replay.
    retire_enhancement_if_complete(conn, tx_ref)
}

pub(super) fn outgoing_position_owned_by_other(
    conn: &Connection,
    tx_ref: crate::TxRef,
    position: u64,
) -> Result<bool, SqliteClientError> {
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM ironwood_enhance_outgoing_queue
             WHERE commitment_tree_position = :position AND transaction_id != :tx
         ) OR EXISTS (SELECT 1 FROM ironwood_enhance_metadata_queue
             WHERE commitment_tree_position = :position AND transaction_id != :tx)
           OR EXISTS (SELECT 1 FROM ironwood_received_notes rn JOIN transactions t ON t.id_tx = rn.transaction_id
             WHERE rn.commitment_tree_position = :position AND rn.transaction_id != :tx AND t.mined_height IS NOT NULL)",
        named_params![":position": position, ":tx": tx_ref.0],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

/// The pending memo work at `position`, with public authority decided by the durable policy.
#[cfg(test)]
pub(crate) fn pending<P: zcash_protocol::consensus::Parameters>(
    conn: &Connection,
    params: &P,
    position: Position,
) -> Result<Option<PendingIronwoodMemo<AccountUuid>>, SqliteClientError> {
    let public_authority = transparent_ledger::retains_public_authority(conn, None)?;
    pending_note(conn, params, position, false, public_authority)
}

/// Test helper for the received-note binding of metadata-only private work.
#[cfg(test)]
pub(crate) fn pending_metadata_note<P: Parameters>(
    conn: &Connection,
    params: &P,
    position: Position,
) -> Result<Option<PendingIronwoodMemo<AccountUuid>>, SqliteClientError> {
    let public_authority = transparent_ledger::retains_public_authority(conn, None)?;
    pending_note(conn, params, position, true, public_authority)
}

/// Memo work (`metadata_only` false) includes route-2 transactions while `public_authority` is
/// false; received-note-bound metadata uses the same authority guard.
fn pending_note<P: Parameters>(
    conn: &Connection,
    params: &P,
    position: Position,
    metadata_only: bool,
    public_authority: bool,
) -> Result<Option<PendingIronwoodMemo<AccountUuid>>, SqliteClientError> {
    #[allow(clippy::type_complexity)]
    let raw: Option<(
        [u8; 32],
        u32,
        Uuid,
        [u8; 11],
        u64,
        [u8; 32],
        [u8; 32],
        i64,
        i64,
        [u8; 32],
        [u8; 52],
    )> = conn
        .query_row(
            concat!(
                "WITH q AS (
                SELECT received_note_id, commitment_tree_position FROM ironwood_memo_retrieval_queue WHERE NOT :metadata
                UNION ALL
                SELECT rn.id, m.commitment_tree_position FROM ironwood_enhance_metadata_queue m
                JOIN ironwood_received_notes rn ON rn.transaction_id = m.transaction_id AND rn.action_index = m.output_index
                WHERE :metadata AND rn.commitment_tree_position = m.commitment_tree_position
             )
             SELECT t.txid, rn.action_index, a.uuid, rn.diversifier, rn.value,
                    rn.rho, rn.rseed, rn.note_version, rn.recipient_key_scope, rn.ephemeral_key, rn.compact_ciphertext
             FROM q
             JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
             JOIN transactions t ON t.id_tx = rn.transaction_id
             JOIN accounts a ON a.id = rn.account_id
             ",
                active_memo_tx!(),
                "
               AND q.commitment_tree_position = :position
               AND (:metadata OR rn.memo IS NULL)
               AND rn.commitment_tree_position = q.commitment_tree_position"
            ),
            named_params![
                ":position": u64::from(position),
                ":metadata": metadata_only,
                ":public_authority": public_authority,
            ],
            |row| {
                let value = u64::try_from(row.get::<_, i64>(4)?)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(4, i64::MIN))?;
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    value,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )
        .optional()?;
    let Some((
        txid,
        output_index,
        account_uuid,
        diversifier,
        value,
        rho,
        rseed,
        version,
        scope,
        ephemeral_key,
        compact_ciphertext,
    )) = raw
    else {
        return Ok(None);
    };
    let account_id = AccountUuid::from_uuid(account_uuid);
    let scope = match scope {
        0 => Scope::External,
        1 => Scope::Internal,
        _ => {
            return Err(SqliteClientError::CorruptedData(
                "Invalid Ironwood note key scope".to_owned(),
            ));
        }
    };
    let account =
        get_account(conn, params, account_id)?.ok_or(SqliteClientError::AccountUnknown)?;
    let diversifier = Diversifier::from_bytes(diversifier);
    let recipient = match scope {
        Scope::External => account
            .uivk()
            .orchard()
            .as_ref()
            .map(|ivk| ivk.address(diversifier)),
        Scope::Internal => account
            .ufvk()
            .and_then(|ufvk| ufvk.orchard())
            .map(|fvk| fvk.to_ivk(Scope::Internal).address(diversifier)),
    }
    .ok_or_else(|| {
        SqliteClientError::CorruptedData(
            "Account cannot reconstruct queued Ironwood note".to_owned(),
        )
    })?;
    let rho = Option::from(Rho::from_bytes(&rho)).ok_or_else(|| {
        SqliteClientError::CorruptedData("Invalid queued Ironwood rho".to_owned())
    })?;
    let rseed = Option::from(RandomSeed::from_bytes(rseed, &rho)).ok_or_else(|| {
        SqliteClientError::CorruptedData("Invalid queued Ironwood rseed".to_owned())
    })?;
    let version = parse_note_version(version).ok_or_else(|| {
        SqliteClientError::CorruptedData("Invalid queued Ironwood note version".to_owned())
    })?;
    let note = Option::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        rho,
        rseed,
        version,
    ))
    .ok_or_else(|| SqliteClientError::CorruptedData("Invalid queued Ironwood note".to_owned()))?;
    Ok(Some(PendingIronwoodMemo {
        request_id: IronwoodEnhanceRequestId::new(TxId::from_bytes(txid), output_index),
        account_id,
        note,
        scope,
        ephemeral_key,
        compact_ciphertext,
    }))
}

/// The sole mutation boundary for a network response. The caller owns this SQL
/// transaction, so memo writes, outgoing writes, queue changes, and routing roll
/// back together if any operation fails.
pub(crate) fn apply<P: Parameters>(
    tx: &Transaction<'_>,
    params: &P,
    configured: Option<TransparentLedgerMode>,
    expected_generation: u64,
    enhancement: ValidatedIronwoodEnhancement<AccountUuid>,
) -> Result<EnhancePirStoreResult, SqliteClientError> {
    let zcash_client_backend::data_api::enhance_pir::storage::IronwoodEnhancementData {
        request,
        has_transparent,
        has_transparent_outputs,
        metadata,
        expected_metadata,
        incoming,
        outgoing,
    } = enhancement.into_parts();
    let id = request.request_id();
    let public_authority = transparent_ledger::retains_public_authority(tx, configured)?;
    let target: Option<(crate::TxRef, i64)> = tx
        .query_row(
            concat!(
                "SELECT t.id_tx, r.route FROM transactions t ",
                active_memo_tx!(),
                " AND t.txid = :txid"
            ),
            named_params![":txid": id.txid().as_ref(), ":public_authority": public_authority],
            |row| Ok((crate::TxRef(row.get(0)?), row.get(1)?)),
        )
        .optional()?;
    let Some((tx_ref, route)) = target else {
        return Ok(EnhancePirStoreResult::AlreadyResolved);
    };
    let memo_id: Option<i64> = tx.query_row(
        "SELECT rn.id FROM ironwood_memo_retrieval_queue q
         JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
         WHERE q.commitment_tree_position = :position AND rn.transaction_id = :tx
           AND rn.action_index = :index AND rn.memo IS NULL
           AND rn.commitment_tree_position = :position",
        named_params![":position": u64::from(request.position()), ":tx": tx_ref.0, ":index": id.output_index()],
        |row| row.get(0),
    ).optional()?;
    let has_outgoing: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_enhance_outgoing_queue
         WHERE commitment_tree_position = :position AND transaction_id = :tx
           AND output_index = :index AND not_recoverable = 0)",
        named_params![":position": u64::from(request.position()), ":tx": tx_ref.0, ":index": id.output_index()],
        |row| row.get(0),
    )?;
    let has_metadata: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_enhance_metadata_queue WHERE transaction_id = :tx
         AND commitment_tree_position = :position AND output_index = :index)",
        named_params![":tx": tx_ref.0, ":position": u64::from(request.position()), ":index": id.output_index()], |r| r.get(0))?;
    let expects_outgoing = !matches!(outgoing, IronwoodOutgoingResult::NotRequested);
    if memo_id.is_some() != incoming.is_some()
        || has_outgoing != expects_outgoing
        || (memo_id.is_none() && !has_outgoing && !has_metadata)
    {
        return Ok(EnhancePirStoreResult::AlreadyResolved);
    }
    if let IronwoodOutgoingResult::Recovered { from_account, .. } = &outgoing {
        let still_candidate: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_enhance_outgoing_accounts oa
             JOIN accounts a ON a.id = oa.account_id
             WHERE oa.commitment_tree_position = :position AND a.uuid = :uuid)",
            named_params![":position": u64::from(request.position()), ":uuid": from_account.expose_uuid()],
            |row| row.get(0),
        )?;
        if !still_candidate {
            return Ok(EnhancePirStoreResult::AlreadyResolved);
        }
    }
    // Crucially, no routing mutation happens before the identity rechecks.
    if has_transparent || route == PRIVATE_DETAILS_UNSUPPORTED {
        transparent_ledger::ensure_policy_generation(tx, expected_generation)?;
        if public_authority {
            // Only a protected transaction can be the target here.
            require_lwd(tx, tx_ref, expected_generation)?;
            return Ok(EnhancePirStoreResult::LwdRequired);
        }
        return store_unsupported_details(
            tx,
            tx_ref,
            route,
            has_transparent_outputs,
            metadata,
            expected_metadata,
            memo_id.zip(incoming),
        );
    }
    let Some(expected) = expected_metadata else {
        return Ok(EnhancePirStoreResult::Rejected);
    };
    if !expected.agrees_with(metadata) {
        return Ok(EnhancePirStoreResult::Rejected);
    }
    // Reject conflicting service assertions before any fee or history write.
    // All reads and writes share the caller's SQL transaction.
    let displayed_expiry: Option<u32> = tx.query_row(
        "SELECT history_expiry_height FROM ironwood_enhance_routing WHERE transaction_id = :tx",
        named_params![":tx": tx_ref.0],
        |row| row.get(0),
    )?;
    if displayed_expiry.is_some_and(|expiry| expiry != metadata.expiry_height()) {
        return Ok(EnhancePirStoreResult::Rejected);
    }
    // Compare the exact captured snapshot and fill only an unknown fee in one statement.
    // The surrounding transaction also contains every memo, outgoing and queue write.
    // Do not put PIR expiry in the authoritative transaction column:
    // unauthenticated zero or far-future heights could pin spent notes after a reorg.
    let filled = expected.filled_from(metadata);
    let updated = tx.execute(
        "UPDATE transactions SET fee = COALESCE(fee, :fee),
            expiry_height = COALESCE(expiry_height, :expiry)
         WHERE id_tx = :tx AND fee IS :expected_fee AND expiry_height IS :expected_expiry",
        named_params![":fee": filled.fee_zatoshis, ":expiry": filled.expiry_height,
            ":tx": tx_ref.0, ":expected_fee": expected.fee_zatoshis,
            ":expected_expiry": expected.expiry_height],
    )?;
    if updated != 1 {
        return Ok(EnhancePirStoreResult::Rejected);
    }
    // The authoritative transaction expiry remains untouched by PIR. A failed
    // routing update is an integrity error so the caller rolls back the fee fill.
    if tx.execute(
        "UPDATE ironwood_enhance_routing
         SET history_expiry_height = COALESCE(history_expiry_height, :expiry)
         WHERE transaction_id = :tx AND route = :private
           AND (history_expiry_height IS NULL OR history_expiry_height = :expiry)",
        named_params![
            ":expiry": metadata.expiry_height(),
            ":tx": tx_ref.0,
            ":private": PRIVATE_PROTECTED,
        ],
    )? != 1
    {
        return Err(SqliteClientError::CorruptedData(
            "Ironwood enhancement routing changed during response application".into(),
        ));
    }
    tx.execute(
        "DELETE FROM ironwood_enhance_metadata_queue WHERE transaction_id = ?",
        [tx_ref.0],
    )?;
    if let (Some(note_id), Some(memo)) = (memo_id, incoming) {
        tx.execute(
            "UPDATE ironwood_received_notes SET memo = :memo WHERE id = :id",
            named_params![":memo": memo_repr(Some(&memo)), ":id": note_id],
        )?;
        tx.execute(
            "DELETE FROM ironwood_memo_retrieval_queue WHERE received_note_id = :id",
            named_params![":id": note_id],
        )?;
    }
    let result = match outgoing {
        IronwoodOutgoingResult::NotRequested => EnhancePirStoreResult::Stored,
        IronwoodOutgoingResult::NotRecoverable => {
            // Could be a dummy, OVK discard, or corrupt server fields. Suspend
            // retries but retain this row so it cannot masquerade as completion.
            tx.execute(
                "UPDATE ironwood_enhance_outgoing_queue SET not_recoverable = 1
                 WHERE commitment_tree_position = :position",
                named_params![":position": u64::from(request.position())],
            )?;
            EnhancePirStoreResult::NotRecoverable
        }
        IronwoodOutgoingResult::Recovered {
            from_account,
            recipient,
            value,
            memo,
        } => {
            let receiver = Receiver::Orchard(recipient);
            let recipient_address =
                super::select_receiving_address(tx, params, from_account, &receiver)?
                    .unwrap_or_else(|| receiver.to_zcash_address(params.network_type()));
            super::put_sent_output(
                tx,
                params,
                from_account,
                tx_ref,
                id.output_index() as usize,
                &Recipient::External {
                    recipient_address,
                    output_pool: PoolType::Shielded(ShieldedPool::Ironwood),
                },
                value,
                Some(&memo),
            )?;
            tx.execute(
                "DELETE FROM ironwood_enhance_outgoing_queue WHERE commitment_tree_position = :position",
                named_params![":position": u64::from(request.position())],
            )?;
            EnhancePirStoreResult::Stored
        }
    };
    // Records arrive in any order: the last real output, or the last dummy, can close the
    // value balance.
    retire_value_balanced_dummies(tx, tx_ref)?;
    retire_enhancement_if_complete(tx, tx_ref)?;
    Ok(result)
}

/// Applies a response for a transaction whose transparent details are unsupported without public
/// authority: one with transparent data (by the response's flags, or an earlier decision), or with
/// a non-Ironwood bundle (by the compact scan). Called after the identity rechecks of [`apply`],
/// inside its SQL transaction, with `route` the transaction's current route.
///
/// Keeps only details that do not depend on the transparent data:
/// - the memo of the authenticated received note at this action, if requested;
/// - the whole-transaction fee, filled only when unknown. The fee is trusted service metadata,
///   as for Ironwood-only transactions. Like those, the response must agree with every known
///   fee, expiry, and displayed expiry, and the captured snapshot must still be current;
///   otherwise nothing changes and the response is `Rejected`. A response without a fee keeps
///   only the memo.
///
/// Outgoing and discovery work cannot be completed privately for such a transaction, and its
/// metadata work is answered by this response. A protected transaction therefore takes the
/// sticky route-2 marker here, keeping memo work for its other received notes, and every later
/// response for it lands in this function again. The marker stays when every memo is known:
/// its transparent details remain unsupported, and history keeps reporting them as pending.
fn store_unsupported_details(
    tx: &Transaction<'_>,
    tx_ref: crate::TxRef,
    route: i64,
    has_transparent_outputs: bool,
    metadata: zcash_client_backend::data_api::enhance_pir::EnhanceTransactionMetadata,
    expected_metadata: Option<StoredIronwoodMetadata>,
    memo: Option<(i64, zcash_protocol::memo::MemoBytes)>,
) -> Result<EnhancePirStoreResult, SqliteClientError> {
    let Some(expected) = expected_metadata else {
        return Ok(EnhancePirStoreResult::Rejected);
    };
    if metadata
        .fee_zatoshis()
        .is_some_and(|fee| expected.fee_zatoshis.is_some_and(|known| known != fee))
        || expected
            .expiry_height
            .is_some_and(|expiry| expiry != metadata.expiry_height())
    {
        return Ok(EnhancePirStoreResult::Rejected);
    }
    let displayed_expiry: Option<u32> = tx.query_row(
        "SELECT history_expiry_height FROM ironwood_enhance_routing WHERE transaction_id = :tx",
        named_params![":tx": tx_ref.0],
        |row| row.get(0),
    )?;
    if displayed_expiry.is_some_and(|expiry| expiry != metadata.expiry_height()) {
        return Ok(EnhancePirStoreResult::Rejected);
    }
    let known_outputs: Option<bool> = tx.query_row(
        "SELECT has_transparent_outputs FROM ironwood_enhance_routing WHERE transaction_id = :tx",
        named_params![":tx": tx_ref.0],
        |row| row.get(0),
    )?;
    if known_outputs.is_some_and(|known| known != has_transparent_outputs) {
        return Ok(EnhancePirStoreResult::Rejected);
    }
    // One compare-and-fill, as for Ironwood-only responses. A NULL fee leaves the known fee.
    if tx.execute(
        "UPDATE transactions SET fee = COALESCE(fee, :fee)
         WHERE id_tx = :tx AND fee IS :expected_fee AND expiry_height IS :expected_expiry",
        named_params![
            ":fee": metadata.fee_zatoshis(),
            ":tx": tx_ref.0,
            ":expected_fee": expected.fee_zatoshis,
            ":expected_expiry": expected.expiry_height,
        ],
    )? != 1
    {
        return Ok(EnhancePirStoreResult::Rejected);
    }
    if tx.execute(
        "UPDATE ironwood_enhance_routing
         SET history_expiry_height = COALESCE(history_expiry_height, :expiry),
             has_transparent_outputs = COALESCE(has_transparent_outputs, :outputs)
         WHERE transaction_id = :tx AND route = :route
           AND (history_expiry_height IS NULL OR history_expiry_height = :expiry)",
        named_params![
            ":expiry": metadata.expiry_height(),
            ":outputs": has_transparent_outputs,
            ":tx": tx_ref.0,
            ":route": route,
        ],
    )? != 1
    {
        return Err(SqliteClientError::CorruptedData(
            "Ironwood enhancement routing changed during response application".into(),
        ));
    }
    if let Some((note_id, memo)) = memo {
        tx.execute(
            "UPDATE ironwood_received_notes SET memo = :memo WHERE id = :id AND memo IS NULL",
            named_params![":memo": memo_repr(Some(&memo)), ":id": note_id],
        )?;
        tx.execute(
            "DELETE FROM ironwood_memo_retrieval_queue WHERE received_note_id = :id",
            named_params![":id": note_id],
        )?;
    }
    tx.execute(
        "DELETE FROM ironwood_enhance_metadata_queue WHERE transaction_id = ?",
        [tx_ref.0],
    )?;
    if route == PRIVATE_PROTECTED {
        require_private_details_unsupported(tx, tx_ref)?;
    }
    Ok(EnhancePirStoreResult::PrivateDetailsUnsupported)
}

#[cfg(test)]
mod tests;
