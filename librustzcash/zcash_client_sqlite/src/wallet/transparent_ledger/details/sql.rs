//! SQL conditions over detail work rows `w` and their transactions `t`.

use super::super::output_observation_condition;
use super::codes::{NOT_COVERED, UNSUPPORTED};
use super::schedule::CONTENT_FAILURE_LIMIT;

/// Whether the wallet still records an effect of transaction `t`: an owned output or a spend
/// of one that financial queries count (a withdrawn ledger-only receive does not), a spend link,
/// or a route-2 marker.
pub(super) fn related_transaction_sql() -> String {
    format!(
        "(
            EXISTS (SELECT 1 FROM transparent_received_outputs o
                    WHERE o.transaction_id = t.id_tx AND ({}))
            OR EXISTS (SELECT 1 FROM transparent_received_output_spends s
                       JOIN transparent_received_outputs so
                           ON so.id = s.transparent_received_output_id
                       WHERE s.transaction_id = t.id_tx AND ({}))
            OR EXISTS (SELECT 1 FROM transparent_spend_map m
                       WHERE m.spending_transaction_id = t.id_tx)
            OR EXISTS (SELECT 1 FROM ironwood_enhance_routing r
                       WHERE r.transaction_id = t.id_tx AND r.route = 2)
        )",
        output_observation_condition("o"),
        output_observation_condition("so"),
    )
}

/// Rows of `transparent_detail_work w` the listing returns for transaction `t` once it is mined,
/// before timing: without raw bytes, still related, not owned by public payload work, and not
/// given up after [`CONTENT_FAILURE_LIMIT`] content failures unless mined at another height
/// since.
///
/// Under public authority (`:public`), payload retrieval already fetches transactions queued
/// in `tx_retrieval_queue`, and a privately protected Ironwood transaction (route 0) must not
/// be fetched publicly.
pub(super) fn listable_work_sql() -> String {
    format!(
        "t.raw IS NULL AND {}
         AND (w.content_failures < {CONTENT_FAILURE_LIMIT} OR {REARMED})
         AND NOT (:public AND (
             EXISTS (SELECT 1 FROM tx_retrieval_queue q
                     WHERE q.txid = t.txid AND q.query_type = :enhancement)
             OR EXISTS (SELECT 1 FROM ironwood_enhance_routing p
                        WHERE p.transaction_id = t.id_tx AND p.route = 0)
         ))",
        related_transaction_sql()
    )
}

/// Rows the listing may return now, before timing: [`listable_work_sql`] and mined.
pub(super) fn eligible_work_sql() -> String {
    format!("t.mined_height IS NOT NULL AND {}", listable_work_sql())
}

/// The mined height changed since the last attempt: due at once, with a fresh backoff.
pub(super) const REARMED: &str =
    "(w.attempted_height IS NOT NULL AND w.attempted_height != t.mined_height)";

/// Parked under caller map `:map`: `NotCovered` until the map differs from the one that
/// produced it, `Unsupported` until any map is seen; never past the backstop.
///
/// Content outcomes, `Contradiction` among them, are never parked: they all retry on one
/// timer, so the schedule does not tell them apart.
///
/// Only without public authority (`:public`): a map is the private source's, and a public
/// lookup answers with the raw transaction whatever the publication covers, so under public
/// authority these rows are due at their ordinary retry.
pub(super) fn parked_work_sql() -> String {
    format!(
        "NOT :public
         AND ((w.last_outcome = {NOT_COVERED}
           AND (:map IS NULL OR w.last_map_sha256 IS :map))
          OR (w.last_outcome = {UNSUPPORTED} AND :map IS NULL))
         AND IFNULL(w.attempted_at, 0) + :backstop > :now"
    )
}

pub(super) const ROUTE_TWO: &str = "EXISTS (SELECT 1 FROM ironwood_enhance_routing r
                                 WHERE r.transaction_id = t.id_tx AND r.route = 2)";
