//! Build with the pinned wallet-pir checkout as described in README.md.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use enhance_pir::v4::{
    parameter_id, parameters, setup_seed, unit_parameter_id, Geometry, Lifecycle, Manifest,
    SessionRef, ShardSession, UnitIdentity, PROTOCOL_REVISION, SCHEMA_VERSION,
};
use ipir_sp::modulus_switch::published_c1_len;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Serialize)]
struct Fixture {
    server_revision: &'static str,
    ipir_sp_revision: &'static str,
    manifest: Manifest,
    session: ShardSession,
}

fn main() {
    let geometry = Geometry::default();
    let coverage = Lifecycle::default().coverage(67, geometry).unwrap();
    let shard = coverage.shards[0].clone();
    let (rlwe, params) = ipir_sp::params_for_simplepir_profile(
        shard.logical_rows,
        enhance_pir::ITEM_SIZE_BITS,
        ipir_sp::SimplePirProfile::P16Q48,
    )
    .unwrap();
    assert_eq!(params, parameters(shard.logical_rows).unwrap());
    let public = vec![0u8; params.db_cols / rlwe.d * published_c1_len(rlwe.d, rlwe.q)];
    let public_hash = hex::encode(Sha256::digest(&public));
    let units = shard
        .units
        .iter()
        .map(|unit| UnitIdentity {
            table: "enhance".into(),
            shard_id: shard.id,
            local_row_start: unit.local_row_start,
            allocated_rows: unit.allocated_rows,
            setup_sha256: hex::encode(Sha256::digest(setup_seed(shard.id))),
            parameter_id: unit_parameter_id(unit.allocated_rows).unwrap(),
            content_sha256: "00".repeat(32),
        })
        .collect();
    let manifest = Manifest {
        schema_version: SCHEMA_VERSION,
        protocol_revision: PROTOCOL_REVISION.into(),
        network: "main".into(),
        pool: "ironwood".into(),
        generation: 7,
        anchor_height: 3_428_143,
        anchor_block_hash: "42".repeat(32),
        geometry,
        coverage,
        sessions: vec![SessionRef {
            shard_id: shard.id,
            parameter_id: parameter_id(shard.logical_rows).unwrap(),
            public_params_sha256: public_hash,
        }],
        unit_identities: BTreeMap::from([(shard.id, units)]),
    };
    manifest.validate().unwrap();
    let session = ShardSession {
        generation: manifest.generation,
        shard_id: shard.id,
        params,
        public_params_base64: STANDARD.encode(public),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&Fixture {
            server_revision: "436dcc7efda3e09a6734342fd4f55e07bf1d9d95",
            ipir_sp_revision: "225972648cc2982abfac66ba5b7a3930b223051a",
            manifest,
            session,
        })
        .unwrap()
    );
}
