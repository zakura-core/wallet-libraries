//! Generates synthetic wallet v6 parameters; does not assert server interoperability.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ipir_sp::{SimplePirProfile, modulus_switch::published_c1_len};
use sha2::{Digest, Sha256};
use zakura_pir_enhance::{
    ITEM_SIZE_BITS, PROTOCOL_REVISION, SCHEMA_VERSION,
    types::{parameter_id, unit_parameter_id},
};

fn main() {
    let mut fixture: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/upstream-session.json")).unwrap();
    fixture.as_object_mut().unwrap().remove("server_revision");
    fixture["ipir_sp_revision"] = "b1c540f90f62e112c834a0f57f025e3c605e55d1".into();
    fixture["provenance"] = "Synthetic wallet schema-11 fixture; not emitted by a v6 server".into();
    fixture["manifest"]["schema_version"] = SCHEMA_VERSION.into();
    fixture["manifest"]["protocol_revision"] = PROTOCOL_REVISION.into();
    let (rlwe, params) =
        ipir_sp::params_for_simplepir_profile(4096, ITEM_SIZE_BITS, SimplePirProfile::P16Q49)
            .unwrap();
    let public = vec![0; params.db_cols / rlwe.d * published_c1_len(rlwe.d, rlwe.q)];
    fixture["session"]["params"] = serde_json::to_value(params).unwrap();
    fixture["session"]["public_params_base64"] = STANDARD.encode(&public).into();
    fixture["manifest"]["sessions"][0]["public_params_sha256"] =
        hex::encode(Sha256::digest(&public)).into();
    fixture["manifest"]["sessions"][0]["parameter_id"] = parameter_id(4096).unwrap().into();
    fixture["manifest"]["unit_identities"]["0"][0]["parameter_id"] =
        unit_parameter_id(2048).unwrap().into();
    // Unit setup identity is derived from the retained public setup domain.
    fixture["manifest"]["unit_identities"]["0"][0]["setup_sha256"] =
        hex::encode(Sha256::digest(zakura_pir_enhance::types::setup_seed(0))).into();
    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
}
