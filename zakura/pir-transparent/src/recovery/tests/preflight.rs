use super::*;

#[test]
fn companion_binding_rejects_account_and_origin_changes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("companion.sqlite");
    drop(ReferenceRecovery::open(&path, config()).unwrap());
    for which in 0..3 {
        let mut different = config();
        match which {
            0 => different.account_binding = vec![2],
            1 => different.origin.push_str("/different"),
            _ => different.source = b"another-fixture-source".to_vec(),
        }
        assert!(matches!(
            ReferenceRecovery::open(&path, different),
            Err(RecoveryError::Invalid(_))
        ));
    }
    ReferenceRecovery::open(&path, config()).unwrap();
}

#[test]
fn a_companion_bound_to_another_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("companion.sqlite");
    drop(ReferenceRecovery::open(&path, config()).unwrap());
    let config = config();
    let rebind = |schema: &str| {
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE pir_bridge_binding SET value=?1 WHERE key='account-source'",
                [catalog::companion_binding([
                    &config.source,
                    &config.account_binding,
                    config.origin.as_bytes(),
                    schema.as_bytes(),
                ])
                .to_vec()],
            )
            .unwrap()
    };
    assert_eq!(rebind("transparent-shard-v10"), 1);
    assert!(matches!(
        ReferenceRecovery::open(&path, config.clone()),
        Err(RecoveryError::Invalid(_))
    ));
    assert_eq!(rebind(SCHEMA), 1);
    ReferenceRecovery::open(&path, config).unwrap();
}

#[test]
fn missing_or_unaccepted_targets_and_oversized_watch_sets_fail_before_retrieval() {
    let dir = tempfile::tempdir().unwrap();
    let mut adapter =
        ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
    let map = map();
    let unknown = StaticChain::default();
    let accepted = StaticChain::from_map(&map);
    let mut filters = CountingFilters::default();
    let mut shards = CountingShards::serving(SCHEMA);
    let mut missing = watch();
    missing.target = None;
    let mut oversized = watch();
    oversized.addresses = (0..=40)
        .map(|i| WatchedAddress {
            address: TransparentAddress::PublicKeyHash([i; 20]),
            ..oversized.addresses[0]
        })
        .collect();
    let mut duplicated = watch();
    duplicated.addresses.push(duplicated.addresses[0]);
    for (watch, chain) in [
        (&watch(), &unknown),
        (&missing, &accepted),
        (&oversized, &accepted),
        (&duplicated, &accepted),
    ] {
        assert!(matches!(
            adapter.recover(watch, chain, &mut filters, &mut shards),
            Err(RecoveryError::Invalid(_))
        ));
    }
    assert_eq!((filters.calls(), shards.calls()), (0, 0));

    // Scripts the companion already retains count against the same limit.
    let dir = tempfile::tempdir().unwrap();
    let mut crowded =
        ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
    crowded.store.bind_set(&SetIdentity::of(&map)).unwrap();
    crowded
        .store
        .add_scripts(
            &(0..=40)
                .map(|i| ScriptEntry {
                    script: address_script(TransparentAddress::ScriptHash([i; 20])),
                    origin: ScriptOrigin::Imported,
                    required_from: map.start_height,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
    assert!(matches!(
        crowded.recover(&watch(), &accepted, &mut filters, &mut shards),
        Err(RecoveryError::Invalid(_))
    ));
    assert_eq!((filters.calls(), shards.calls()), (0, 0));

    // Once every check passes, the same pass reaches the caller's transports.
    assert!(matches!(
        adapter.recover(&watch(), &accepted, &mut filters, &mut shards),
        Err(RecoveryError::Failure(_))
    ));
    assert_eq!((filters.maps, shards.inits), (1, 1));
    assert!(filters.filters > 0);
}

#[test]
fn parent_filter_sources_are_refused_before_retrieval() {
    let dir = tempfile::tempdir().unwrap();
    let mut adapter =
        ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
    let mut filters = CountingFilters {
        parents: true,
        ..Default::default()
    };
    let mut shards = CountingShards::serving(SCHEMA);
    assert!(matches!(
        adapter.recover(
            &watch(),
            &StaticChain::from_map(&map()),
            &mut filters,
            &mut shards
        ),
        Err(RecoveryError::Invalid(_))
    ));
    assert_eq!(filters.parent_checks.get(), 1);
    assert_eq!((filters.maps, filters.filters, shards.calls()), (0, 0, 0));
}

#[test]
fn a_service_with_another_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut adapter =
        ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
    let mut filters = CountingFilters::default();
    let mut shards = CountingShards::serving("transparent-shard-v10");
    assert!(matches!(
        adapter.recover(
            &watch(),
            &StaticChain::from_map(&map()),
            &mut filters,
            &mut shards
        ),
        Err(RecoveryError::Invalid(_))
    ));
    assert_eq!((filters.maps, shards.inits), (1, 1));
    assert_eq!(
        (
            filters.filters,
            shards.manifests,
            shards.setups,
            shards.queries
        ),
        (0, 0, 0, 0)
    );
    // Nothing reached the companion: it is still bound to no publication.
    assert!(adapter.store.set_identity().unwrap().is_none());
}
