//! Explicit server selection across config refreshes and restarts.

mod support;

use support::{MIRROR_A, anchor_for, bytes, dynamic_json, mainnet_config, static_json};
use zakura_pir_config::{
    SelectionError, ServerBase, ServerSelection, ServerSelectionOutcome, WalletPirConfigProfile,
    resolve_dynamic_config,
};

/// Persists and reloads a selection the way an application would.
fn restart(selection: &ServerSelection) -> ServerSelection {
    serde_json::from_str(&serde_json::to_string(selection).unwrap()).unwrap()
}

#[test]
fn defaults_to_the_first_server_only_without_a_prior_selection() {
    let config = mainnet_config(&[("A", "https://a.example"), ("B", "https://b.example")]);
    let outcome = config.reconcile_selection(None);
    let ServerSelectionOutcome::Defaulted(selection) = &outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(selection.base().as_str(), "https://a.example");
    assert_eq!(outcome.selection(), Some(selection));

    let empty = mainnet_config(&[]);
    assert_eq!(
        empty.reconcile_selection(None),
        ServerSelectionOutcome::NoServers
    );
    assert_eq!(empty.reconcile_selection(None).selection(), None);
}

#[test]
fn an_explicit_choice_survives_label_and_order_changes() {
    let config = mainnet_config(&[("A", "https://a.example"), ("B", "https://b.example/pir")]);
    let chosen = config
        .select_server(&ServerBase::parse("HTTPS://B.EXAMPLE/pir/").unwrap())
        .unwrap();
    let persisted = restart(&chosen);

    let refreshed = mainnet_config(&[
        ("Renamed B", "https://b.example/pir"),
        ("A", "https://a.example"),
    ]);
    assert_eq!(
        refreshed.reconcile_selection(Some(&persisted)),
        ServerSelectionOutcome::Kept(chosen.clone())
    );
    assert_eq!(refreshed.server(&persisted).unwrap().label, "Renamed B");
}

#[test]
fn removal_requires_a_user_choice_and_never_fails_over() {
    let config = mainnet_config(&[("A", "https://a.example"), ("B", "https://b.example")]);
    let chosen = config
        .select_server(&ServerBase::parse("https://b.example").unwrap())
        .unwrap();

    let without_b = mainnet_config(&[("A", "https://a.example"), ("C", "https://c.example")]);
    let required = ServerSelectionOutcome::SelectionRequired {
        removed: chosen.base().clone(),
    };
    assert_eq!(without_b.reconcile_selection(Some(&chosen)), required);
    assert_eq!(
        without_b.reconcile_selection(Some(&chosen)).selection(),
        None
    );
    assert_eq!(without_b.server(&chosen), None);
    // The application keeps the persisted selection, so a restart is still
    // a lost selection rather than a fresh default.
    assert_eq!(
        without_b.reconcile_selection(Some(&restart(&chosen))),
        required
    );
    // Even when the list becomes empty.
    assert_eq!(
        mainnet_config(&[]).reconcile_selection(Some(&chosen)),
        required
    );

    let rechosen = without_b
        .select_server(&ServerBase::parse("https://c.example").unwrap())
        .unwrap();
    assert_eq!(
        without_b.reconcile_selection(Some(&rechosen)),
        ServerSelectionOutcome::Kept(rechosen.clone())
    );
}

#[test]
fn only_advertised_servers_can_be_chosen() {
    let config = mainnet_config(&[("A", "https://a.example")]);
    let base = ServerBase::parse("https://elsewhere.example").unwrap();
    assert_eq!(
        config.select_server(&base),
        Err(SelectionError::NotAdvertised { base })
    );
}

#[test]
fn selections_from_another_source_scope_are_not_reused() {
    let config = mainnet_config(&[("A", "https://a.example"), ("B", "https://b.example")]);
    let chosen = config
        .select_server(&ServerBase::parse("https://b.example").unwrap())
        .unwrap();

    // A new static document means a new pin and so a new scope.
    let mut rotated_static = static_json("mainnet");
    rotated_static["dynamic_config_urls"] = serde_json::json!([MIRROR_A]);
    let rotated = resolve_dynamic_config(
        &WalletPirConfigProfile::https_transport(),
        &anchor_for(&rotated_static),
        MIRROR_A,
        &bytes(&dynamic_json(
            "mainnet",
            &[("A", "https://a.example"), ("B", "https://b.example")],
        )),
    )
    .unwrap();
    assert_ne!(rotated.scope(), config.scope());
    assert_eq!(rotated.server(&chosen), None);
    let outcome = rotated.reconcile_selection(Some(&chosen));
    let ServerSelectionOutcome::Defaulted(selection) = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(selection.scope(), rotated.scope());
    assert_eq!(selection.base().as_str(), "https://a.example");
}

#[test]
fn persisted_selections_are_revalidated_on_load() {
    let tampered = r#"{"scope":"00","base":"http://a.example"}"#;
    assert!(serde_json::from_str::<ServerSelection>(tampered).is_err());
}
