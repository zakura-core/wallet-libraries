//! Synthetic manifest shared by unit tests and, via `#[path]`, integration tests.
//! Relies on the includer's `types` module path (the crate's, or an imported one).
use super::types::{
    Geometry, Lifecycle, Manifest, PROTOCOL_REVISION, QueryShard, SCHEMA_VERSION, SessionRef,
    UnitIdentity, parameter_id, setup_seed, unit_parameter_id,
};
use sha2::{Digest, Sha256};

/// A valid generation-1 mainnet manifest covering `records` with default geometry.
/// Callers set the anchor fields their scenario needs.
pub fn synthetic_manifest(
    records: u64,
    public_params_sha256: impl Fn(&QueryShard) -> String,
    content_sha256: &str,
) -> Manifest {
    let coverage = Lifecycle::default()
        .coverage(records, Geometry::default())
        .unwrap();
    let sessions = coverage
        .shards
        .iter()
        .map(|shard| SessionRef {
            shard_id: shard.id,
            public_params_sha256: public_params_sha256(shard),
            parameter_id: parameter_id(shard.logical_rows).unwrap(),
        })
        .collect();
    let unit_identities = coverage
        .shards
        .iter()
        .map(|shard| {
            (
                shard.id,
                shard
                    .units
                    .iter()
                    .map(|unit| UnitIdentity {
                        recovery_epoch: 0,
                        table: "enhance".into(),
                        shard_id: shard.id,
                        local_row_start: unit.local_row_start,
                        allocated_rows: unit.allocated_rows,
                        setup_sha256: hex::encode(Sha256::digest(setup_seed(shard.id))),
                        parameter_id: unit_parameter_id(unit.allocated_rows).unwrap(),
                        content_sha256: content_sha256.into(),
                    })
                    .collect(),
            )
        })
        .collect();
    Manifest {
        recovery_epoch: 0,
        placement_revision: 1,
        domain_recovery_epochs: coverage
            .shards
            .iter()
            .map(|shard| (shard.id, "0".into()))
            .collect(),
        schema_version: SCHEMA_VERSION,
        protocol_revision: PROTOCOL_REVISION.into(),
        network: "main".into(),
        pool: "ironwood".into(),
        generation: 1,
        anchor_height: 0,
        anchor_block_hash: "00".repeat(32),
        geometry: Geometry::default(),
        coverage,
        sessions,
        unit_identities,
    }
}
