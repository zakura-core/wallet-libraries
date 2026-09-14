//! Run in a temporary Cargo project as described in README.md.
#[allow(dead_code)]
mod upstream {
    include!(concat!(
        env!("ENHANCE_PIR_CHECKOUT"),
        "/pir/enhance/src/types.rs"
    ));
}

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use upstream::*;

fn main() {
    let (rlwe, params) = ipir_sp::params_for_simplepir(SHARD_ROWS as u64, ITEM_SIZE_BITS).unwrap();
    // Synthetic public coefficients: this fixture checks the JSON contract, not decryption.
    let public_params =
        vec![0; params.instances * ipir_sp::modulus_switch::published_c1_len(rlwe.d, rlwe.q)];
    let digest = Sha256::digest(&public_params);
    let session = EnhanceSession {
        generation: EnhanceGeneration {
            schema_version: SCHEMA_VERSION,
            protocol_revision: PROTOCOL_REVISION.into(),
            network: NETWORK.into(),
            pool: POOL.into(),
            anchor_height: ACTIVATION_HEIGHT,
            anchor_block_hash: hex::encode([0x42; 32]),
            ironwood_tree_size: SHARD_POSITIONS as u64,
            generation: 7,
            record_bytes: RECORD_BYTES as u32,
            records_per_row: RECORDS_PER_ROW as u32,
            row_bytes: ROW_BYTES as u32,
            shard_rows: SHARD_ROWS as u32,
            used_rows: used_rows_for(SHARD_POSITIONS as u64),
            logical_rows: logical_rows_for(SHARD_ROWS as u64),
            parameter_id: "upstream-conformance-fixture".into(),
            setup_seed: ENHANCE_SETUP_SEED,
            public_params_epoch: hex::encode(&digest[..8]),
            public_params_sha256: hex::encode(digest),
            shards: vec![ShardDescriptor {
                shard_id: 0,
                global_row_start: 0,
                populated_positions: SHARD_POSITIONS as u64,
                rows_sha256: hex::encode([0x24; 32]),
                sealed: true,
                worker: "opaque-group-a".into(),
            }],
        },
        params,
        public_params_base64: STANDARD.encode(public_params),
    };
    println!("{}", serde_json::to_string_pretty(&session).unwrap());
}
