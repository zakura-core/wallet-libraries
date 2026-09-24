//! Generates synthetic wallet v7 parameters; does not assert server interoperability.
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
    fixture.as_object_mut().unwrap().remove("ipir_sp_revision");
    fixture["ipir_sp_version"] = "0.1.0-rc.3".into();
    fixture["provenance"] = "Synthetic wallet schema-11 fixture; not emitted by a v7 server".into();
    fixture["manifest"]["schema_version"] = SCHEMA_VERSION.into();
    fixture["manifest"]["protocol_revision"] = PROTOCOL_REVISION.into();
    let (rlwe, params) =
        ipir_sp::params_for_simplepir_profile(4096, ITEM_SIZE_BITS, SimplePirProfile::P16Q48)
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
    fixture["manifest"]["recovery_epoch"] = "0".into();
    fixture["manifest"]["placement_revision"] = 1.into();
    fixture["manifest"]["domain_recovery_epochs"] = serde_json::json!({"0":"0"});
    fixture["manifest"]["coverage"]
        .as_object_mut()
        .unwrap()
        .remove("loan");
    fixture["manifest"]["coverage"]["routes"] =
        serde_json::json!([{"global_start":0,"global_end":3,"domain_id":0,"local_start":0}]);
    fixture["manifest"]["unit_identities"]["0"][0]["recovery_epoch"] = "0".into();
    let manifest: zakura_pir_enhance::Manifest =
        serde_json::from_value(fixture["manifest"].clone()).unwrap();
    manifest.validate().unwrap();
    fixture["session"]["session_id"] = hex::encode(manifest.session_id(0).unwrap()).into();
    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
}
