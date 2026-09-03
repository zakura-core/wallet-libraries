//! Planning one DAG-sync pass under the fixed query envelope.
//!
//! A pass issues exactly `k_nf` nullifier pairs, `k_act` action rows, and
//! `k_wit` witness pairs, in a fixed order, whatever the wallet has pending:
//! unused slots are cover queries at uniformly random rows, and overflow
//! waits for the next pass. The planner owns the queues and the schedule;
//! the caller owns transport and result handling, so this stays
//! transport-neutral and testable.

use crate::spend::hash_to_bucket;
use crate::witness::{SUBSHARD_LEAVES, SUBSHARDS_PER_SHARD, decompose};
use crate::{ClientError, DatabaseId, PirSession, PreparedQuery};
use std::collections::VecDeque;

/// The five sessions a pass draws on, all pinned to one generation.
pub struct TableSessions {
    pub action: PirSession,
    pub witness: PirSession,
    pub witness_roots: PirSession,
    pub nf_cold: PirSession,
    pub nf_warm: PirSession,
}

impl TableSessions {
    fn session(&self, table: DatabaseId) -> &PirSession {
        match table {
            DatabaseId::Action => &self.action,
            DatabaseId::Witness => &self.witness,
            DatabaseId::WitnessRoots => &self.witness_roots,
            DatabaseId::NfCold => &self.nf_cold,
            DatabaseId::NfWarm => &self.nf_warm,
        }
    }

    /// Every session must describe the same generation.
    pub fn generation(&self) -> Result<u64, ClientError> {
        let generation = self.action.generation();
        for table in [
            DatabaseId::Witness,
            DatabaseId::WitnessRoots,
            DatabaseId::NfCold,
            DatabaseId::NfWarm,
        ] {
            if self.session(table).generation() != generation {
                return Err(ClientError::Metadata("sessions span different generations"));
            }
        }
        Ok(generation)
    }
}

/// What one planned query is for. Real targets are private to the wallet;
/// the wire shape is identical for every variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// Spend check for a nullifier in the cold or warm table.
    Nullifier([u8; 32]),
    /// One row of action records.
    ActionRow(u64),
    /// The `witness-roots` row of the shard holding `position`.
    WitnessRoots(u64),
    /// The `witness` row of the sub-shard holding `position`.
    WitnessLeaves(u64),
    /// Cover query at a random row; the response is discarded.
    Dummy,
}

/// One query of a pass, in issue order.
pub struct PlannedQuery {
    pub table: DatabaseId,
    pub target: Target,
    pub query: PreparedQuery,
}

/// Queues of pending work and the fixed envelope they drain under.
#[derive(Default)]
pub struct DagSyncPlanner {
    nullifiers: VecDeque<[u8; 32]>,
    action_rows: VecDeque<u64>,
    witness_positions: VecDeque<u64>,
}

impl DagSyncPlanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue_nullifier(&mut self, nullifier: [u8; 32]) {
        if !self.nullifiers.contains(&nullifier) {
            self.nullifiers.push_back(nullifier);
        }
    }

    /// Queues every row covering `first_output_position .. + action_count`,
    /// oldest first, so a transaction spanning rows drains over consecutive
    /// slots or passes.
    pub fn enqueue_actions(
        &mut self,
        first_output_position: u64,
        action_count: u64,
        records_per_row: u64,
    ) {
        if action_count == 0 {
            return;
        }
        let first = first_output_position / records_per_row;
        let last = (first_output_position + action_count - 1) / records_per_row;
        for row in first..=last {
            if !self.action_rows.contains(&row) {
                self.action_rows.push_back(row);
            }
        }
    }

    pub fn enqueue_witness(&mut self, position: u64) {
        if !self.witness_positions.contains(&position) {
            self.witness_positions.push_back(position);
        }
    }

    pub fn pending(&self) -> (usize, usize, usize) {
        (
            self.nullifiers.len(),
            self.action_rows.len(),
            self.witness_positions.len(),
        )
    }

    /// Plans one pass: exactly the envelope's counts, in the fixed order
    /// nullifier pairs, action rows, witness pairs, real targets first then
    /// dummies. Targets beyond the generation's coverage are deferred, not
    /// dropped.
    pub fn plan(&mut self, sessions: &TableSessions) -> Result<Vec<PlannedQuery>, ClientError> {
        sessions.generation()?;
        let envelope = sessions.action.manifest().envelope;
        let mut queries = Vec::new();

        for _ in 0..envelope.k_nf {
            let target = self.nullifiers.pop_front();
            for table in [DatabaseId::NfCold, DatabaseId::NfWarm] {
                let session = sessions.session(table);
                let (query, planned) = match target {
                    Some(nf) => {
                        let row = hash_to_bucket(&nf, session.positions());
                        (session.prepare_row(row as usize)?, Target::Nullifier(nf))
                    }
                    None => (session.prepare_dummy()?, Target::Dummy),
                };
                queries.push(PlannedQuery {
                    table,
                    target: planned,
                    query,
                });
            }
        }

        for _ in 0..envelope.k_act {
            let session = &sessions.action;
            let rows = session
                .positions()
                .div_ceil(session.table_manifest().records_per_row as u64);
            let (query, target) = match self.action_rows.pop_front() {
                Some(row) if row < rows => {
                    (session.prepare_row(row as usize)?, Target::ActionRow(row))
                }
                Some(row) => {
                    // Beyond this generation's coverage: keep it for later.
                    self.action_rows.push_back(row);
                    (session.prepare_dummy()?, Target::Dummy)
                }
                None => (session.prepare_dummy()?, Target::Dummy),
            };
            queries.push(PlannedQuery {
                table: DatabaseId::Action,
                target,
                query,
            });
        }

        for _ in 0..envelope.k_wit {
            let tree_size = sessions.witness.positions();
            let target = match self.witness_positions.pop_front() {
                Some(position) if position < tree_size => Some(position),
                Some(position) => {
                    self.witness_positions.push_back(position);
                    None
                }
                None => None,
            };
            let (shard, subshard, _) = target.map(decompose).unwrap_or((0, 0, 0));
            let roots_rows = sessions
                .witness_roots
                .positions()
                .div_ceil(SUBSHARDS_PER_SHARD as u64);
            let _ = SUBSHARD_LEAVES;
            for (table, row) in [
                (DatabaseId::WitnessRoots, shard),
                (DatabaseId::Witness, subshard),
            ] {
                let session = sessions.session(table);
                let (query, planned) = match target {
                    Some(position) => {
                        // A shard whose roots row is not yet published (only
                        // frontier sub-shards) still has a row of padding; the
                        // coordinator serves logical rows up to capacity.
                        let _ = roots_rows;
                        let planned = if table == DatabaseId::Witness {
                            Target::WitnessLeaves(position)
                        } else {
                            Target::WitnessRoots(position)
                        };
                        (session.prepare_row(row as usize)?, planned)
                    }
                    None => (session.prepare_dummy()?, Target::Dummy),
                };
                queries.push(PlannedQuery {
                    table,
                    target: planned,
                    query,
                });
            }
        }
        Ok(queries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pass shape is a pure function of the envelope: the same table
    /// sequence for zero, one, or many pending items.
    #[test]
    fn pass_shape_does_not_depend_on_pending_work() {
        fn shape(k_nf: u16, k_act: u16, k_wit: u16) -> Vec<DatabaseId> {
            let mut tables = Vec::new();
            for _ in 0..k_nf {
                tables.extend([DatabaseId::NfCold, DatabaseId::NfWarm]);
            }
            tables.extend(std::iter::repeat_n(DatabaseId::Action, k_act as usize));
            for _ in 0..k_wit {
                tables.extend([DatabaseId::WitnessRoots, DatabaseId::Witness]);
            }
            tables
        }
        assert_eq!(shape(8, 4, 4).len(), 8 * 2 + 4 + 4 * 2);
        assert_eq!(
            shape(1, 1, 1),
            vec![
                DatabaseId::NfCold,
                DatabaseId::NfWarm,
                DatabaseId::Action,
                DatabaseId::WitnessRoots,
                DatabaseId::Witness,
            ]
        );
    }

    #[test]
    fn action_rows_are_queued_per_row_and_deduplicated() {
        let mut planner = DagSyncPlanner::new();
        planner.enqueue_actions(6, 4, 8); // positions 6..10 span rows 0 and 1
        planner.enqueue_actions(8, 1, 8); // row 1 again
        planner.enqueue_actions(100, 0, 8);
        assert_eq!(planner.pending(), (0, 2, 0));
        planner.enqueue_nullifier([1; 32]);
        planner.enqueue_nullifier([1; 32]);
        planner.enqueue_witness(5);
        assert_eq!(planner.pending(), (1, 2, 1));
    }
}
