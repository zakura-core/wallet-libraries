use sha2::{Digest, Sha256};
use zakura_pir_enhance::types::*;

fn manifest(records: u64) -> Manifest {
    let coverage = Lifecycle::default()
        .coverage(records, Geometry::default())
        .unwrap();
    let sessions = coverage
        .shards
        .iter()
        .map(|s| SessionRef {
            shard_id: s.id,
            public_params_sha256: "ab".repeat(32),
            parameter_id: parameter_id(s.logical_rows).unwrap(),
        })
        .collect();
    let unit_identities = coverage
        .shards
        .iter()
        .map(|s| {
            (
                s.id,
                s.units
                    .iter()
                    .map(|u| UnitIdentity {
                        recovery_epoch: 0,
                        table: "enhance".into(),
                        shard_id: s.id,
                        local_row_start: u.local_row_start,
                        allocated_rows: u.allocated_rows,
                        setup_sha256: hex::encode(Sha256::digest(setup_seed(s.id))),
                        parameter_id: unit_parameter_id(u.allocated_rows).unwrap(),
                        content_sha256: "cd".repeat(32),
                    })
                    .collect(),
            )
        })
        .collect();
    Manifest {
        recovery_epoch: 0,
        placement_revision: 1,
        domain_recovery_epochs: coverage.shards.iter().map(|s| (s.id, "0".into())).collect(),
        schema_version: SCHEMA_VERSION,
        protocol_revision: PROTOCOL_REVISION.into(),
        network: "main".into(),
        pool: "ironwood".into(),
        generation: 1,
        anchor_height: 1000,
        anchor_block_hash: "ef".repeat(32),
        geometry: Geometry::default(),
        coverage,
        sessions,
        unit_identities,
    }
}

#[test]
fn session_identity_separates_content_routing_and_recovery() {
    let original = manifest(32768 * 33 + 1);
    original.validate().unwrap();
    let id = original.session_id(0).unwrap();
    let mut moved = original.clone();
    moved.generation += 1;
    moved.placement_revision += 1;
    moved.anchor_height += 1;
    moved.anchor_block_hash = "11".repeat(32);
    moved.coverage.shards[0].state = ShardState::Sealed;
    assert_eq!(moved.session_id(0).unwrap(), id);
    moved.validate().unwrap();
    moved.recovery_epoch = 1;
    assert_eq!(
        moved.session_id(0).unwrap(),
        id,
        "unaffected domain must survive global recovery"
    );
    moved.domain_recovery_epochs.insert(0, "1".into());
    for unit in moved.unit_identities.get_mut(&0).unwrap() {
        unit.recovery_epoch = 1;
    }
    moved.validate().unwrap();
    assert_ne!(moved.session_id(0).unwrap(), id);
    for change in 0..4 {
        let mut changed = original.clone();
        match change {
            0 => changed.unit_identities.get_mut(&0).unwrap()[0].content_sha256 = "11".repeat(32),
            1 => changed.sessions[0].public_params_sha256 = "11".repeat(32),
            2 => changed.unit_identities.get_mut(&0).unwrap().reverse(),
            _ => changed.unit_identities.get_mut(&0).unwrap()[0].allocated_rows /= 2,
        }
        assert_ne!(changed.session_id(0).unwrap(), id);
    }
}

#[test]
fn strict_wire_rejects_aliases_epochs_and_unknown_fields() {
    let original = manifest(32768 * 33 + 1);
    for mutation in 0..7 {
        let mut value = serde_json::to_value(&original).unwrap();
        match mutation {
            0 => value["recovery_epoch"] = serde_json::json!(0),
            1 => value["recovery_epoch"] = "00".into(),
            2 => value["recovery_epoch"] = "18446744073709551616".into(),
            3 => value["unknown"] = true.into(),
            4 => value["coverage"]["routes"][1]["local_start"] = 0.into(),
            5 => value["coverage"]["routes"][0]["global_end"] = 32768.into(),
            _ => value["domain_recovery_epochs"]["1"] = "1".into(),
        }
        assert!(serde_json::from_value::<Manifest>(value).map_or(true, |m| m.validate().is_err()));
    }
    let mut max = original.clone();
    max.recovery_epoch = u64::MAX;
    let wire = serde_json::to_string(&max).unwrap();
    assert!(wire.contains("\"recovery_epoch\":\"18446744073709551615\""));
    serde_json::from_str::<Manifest>(&wire)
        .unwrap()
        .validate()
        .unwrap();
}

#[test]
fn multi_boundary_blocks_and_partial_threshold_use_canonical_coordinates() {
    let span = 32768 * 33;
    let floor = 4096 * 33;
    for records in [
        span,
        span + 1,
        span + floor - 33,
        span + floor - 32,
        3 * span + 7,
        24 * span,
    ] {
        let m = manifest(records);
        m.validate().unwrap();
        for position in [0, records - 1, span - 1] {
            assert!(m.coverage.locate(position).is_some());
        }
        assert!(m.coverage.locate(records).is_none());
    }
    let before = manifest(span + floor - 33);
    let after = manifest(span + floor - 32);
    assert!(before.coverage.shards[1].composed());
    assert!(!after.coverage.shards[1].composed());
    assert_eq!(before.coverage.locate(span).unwrap().1, 0);
    assert_eq!(after.coverage.locate(span).unwrap().1, 0);
    assert_eq!(before.session_id(0).unwrap(), after.session_id(0).unwrap());
    assert!(
        Lifecycle::default()
            .coverage(24 * span + 1, Geometry::default())
            .is_err()
    );
}

#[test]
fn identity_vector_matches_frozen_bytes() {
    let m = manifest(67);
    // An independent Python encoder checks the serialized fixture as well.
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/v7-session.json")).unwrap();
    assert_eq!(serde_json::to_value(&m).unwrap(), fixture["manifest"]);
    assert_eq!(
        hex::encode(m.session_id(0).unwrap()),
        fixture["session_id"].as_str().unwrap()
    );
}
