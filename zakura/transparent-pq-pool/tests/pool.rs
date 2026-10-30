use std::collections::HashSet;
use std::num::NonZeroU32;

use transparent_pq_keys::{Branch, KeyOrigin, Network, ParameterSet, PublicKey, WalletSeed};
use transparent_pq_pool::{
    AccountPool, Error, KeyRange, PoolState, PublicKeySource, SIGNATURE_WARNING_THRESHOLD,
    SourceError,
};

const PARAMETERS: ParameterSet = ParameterSet::Sha2_128f;

fn window(size: u32) -> NonZeroU32 {
    NonZeroU32::new(size).unwrap()
}

fn origin(branch: Branch, index: u32) -> KeyOrigin {
    KeyOrigin::new(PARAMETERS, Network::Testnet, 0, branch, index)
}

/// A stand-in public key that differs per origin; pool rules never generate keys.
fn key(origin: KeyOrigin) -> PublicKey {
    let mut bytes = [0u8; 32];
    bytes[..12].copy_from_slice(&origin.to_bytes());
    PublicKey::from_bytes(origin.parameters(), &bytes).unwrap()
}

/// Answers with stand-in keys, at most `limit` per request, and records each request.
#[derive(Default)]
struct StandIn {
    limit: Option<usize>,
    requests: Vec<KeyRange>,
}

impl PublicKeySource for StandIn {
    type Error = &'static str;

    fn public_keys(&mut self, range: KeyRange) -> Result<Vec<(KeyOrigin, PublicKey)>, Self::Error> {
        self.requests.push(range);
        let take = self.limit.unwrap_or(usize::MAX);
        Ok(range.origins().take(take).map(|o| (o, key(o))).collect())
    }
}

fn pool(size: u32) -> AccountPool {
    let mut pool = AccountPool::new(PARAMETERS, Network::Testnet, 0, window(size));
    pool.replenish(Branch::Receive, &mut StandIn::default())
        .unwrap();
    pool.replenish(Branch::Change, &mut StandIn::default())
        .unwrap();
    pool
}

fn issue_index(pool: &mut AccountPool, branch: Branch) -> (u32, bool) {
    let issued = pool.issue(branch).unwrap();
    assert_eq!(issued.public_key, key(issued.origin));
    (issued.origin.index(), issued.fresh)
}

#[test]
fn issues_the_window_then_repeats_the_last_key_without_leaving_it() {
    let mut pool = pool(3);
    assert_eq!(issue_index(&mut pool, Branch::Receive), (0, true));
    assert_eq!(issue_index(&mut pool, Branch::Receive), (1, true));
    assert_eq!(issue_index(&mut pool, Branch::Receive), (2, true));
    // Handing out addresses does not move the window; only payments do.
    assert_eq!(pool.replenish_request(Branch::Receive), None);
    assert_eq!(issue_index(&mut pool, Branch::Receive), (2, false));
    assert_eq!(issue_index(&mut pool, Branch::Receive), (2, false));
    assert_eq!(pool.public_keys(Branch::Receive).count(), 3);
}

#[test]
fn issuing_before_any_replenishment_fails() {
    let mut pool = AccountPool::new(PARAMETERS, Network::Testnet, 0, window(3));
    assert_eq!(
        pool.issue(Branch::Receive),
        Err(Error::NothingProvisioned(Branch::Receive))
    );
}

#[test]
fn a_payment_widens_the_window_by_exactly_the_keys_past_it() {
    let mut pool = pool(3);
    for _ in 0..3 {
        pool.issue(Branch::Receive).unwrap();
    }
    pool.record_received(origin(Branch::Receive, 1)).unwrap();
    let request = pool.replenish_request(Branch::Receive).unwrap();
    assert_eq!(request.first(), origin(Branch::Receive, 3));
    assert_eq!(request.count().get(), 2);
    pool.replenish(Branch::Receive, &mut StandIn::default())
        .unwrap();
    assert_eq!(issue_index(&mut pool, Branch::Receive), (3, true));
    assert_eq!(issue_index(&mut pool, Branch::Receive), (4, true));
    assert_eq!(issue_index(&mut pool, Branch::Receive), (4, false));
}

#[test]
fn change_and_receiving_indices_move_independently() {
    let mut pool = pool(3);
    assert_eq!(issue_index(&mut pool, Branch::Change), (0, true));
    assert_eq!(issue_index(&mut pool, Branch::Change), (1, true));
    pool.record_received(origin(Branch::Change, 1)).unwrap();
    assert_eq!(issue_index(&mut pool, Branch::Receive), (0, true));
    assert_eq!(pool.state().receive.highest_used, None);
    assert_eq!(
        pool.replenish_request(Branch::Change).map(|r| r.first()),
        Some(origin(Branch::Change, 3))
    );
    assert_eq!(pool.replenish_request(Branch::Receive), None);
}

#[test]
fn a_key_used_elsewhere_is_not_offered_as_fresh() {
    let mut pool = pool(3);
    // Another copy of the wallet handed out and received at index 1.
    pool.record_received(origin(Branch::Receive, 1)).unwrap();
    assert_eq!(issue_index(&mut pool, Branch::Receive), (2, true));
}

#[test]
fn saved_state_resumes_without_reissuing_an_index_as_fresh() {
    let mut pool = pool(3);
    pool.issue(Branch::Receive).unwrap();
    pool.issue(Branch::Receive).unwrap();
    pool.record_received(origin(Branch::Receive, 0)).unwrap();
    pool.set_confirmed_signatures(origin(Branch::Receive, 0), 2)
        .unwrap();
    let saved: PoolState = pool.state().clone();
    drop(pool);

    let mut resumed = AccountPool::from_state(saved.clone()).unwrap();
    assert_eq!(resumed.state(), &saved);
    assert_eq!(issue_index(&mut resumed, Branch::Receive), (2, true));
}

#[test]
fn saved_state_that_breaks_an_invariant_is_rejected() {
    let mut pool = pool(3);
    pool.issue(Branch::Receive).unwrap();
    pool.record_received(origin(Branch::Receive, 0)).unwrap();
    let good = pool.state().clone();
    let broken = |change: fn(&mut PoolState)| {
        let mut state = good.clone();
        change(&mut state);
        AccountPool::from_state(state)
    };

    assert!(matches!(
        broken(|s| s.receive.issued_end = 5),
        Err(Error::InconsistentState(_))
    ));
    assert!(matches!(
        broken(|s| s.receive.highest_used = Some(2)),
        Err(Error::InconsistentState(_))
    ));
    assert!(matches!(
        broken(|s| {
            s.change.confirmed_signatures.insert(0, 1);
        }),
        Err(Error::InconsistentState(_))
    ));
    assert!(matches!(
        broken(|s| s.window = NonZeroU32::new(1).unwrap()),
        Err(Error::InconsistentState(_))
    ));
    assert!(matches!(
        broken(|s| s.receive.public_keys[1] =
            PublicKey::from_bytes(ParameterSet::Sha2_192s, &[0; 48]).unwrap()),
        Err(Error::InconsistentState(_))
    ));
    assert!(AccountPool::from_state(good).is_ok());
}

#[test]
fn partial_batches_accumulate_and_replayed_batches_change_nothing() {
    let mut pool = AccountPool::new(PARAMETERS, Network::Testnet, 0, window(4));
    let mut one_at_a_time = StandIn {
        limit: Some(1),
        ..StandIn::default()
    };
    pool.replenish(Branch::Receive, &mut one_at_a_time).unwrap();
    assert_eq!(one_at_a_time.requests.len(), 4);
    assert_eq!(
        one_at_a_time
            .requests
            .iter()
            .map(|r| r.count().get())
            .collect::<Vec<_>>(),
        [4, 3, 2, 1]
    );

    let before = pool.state().clone();
    let replay: Vec<_> = (0..4)
        .map(|i| (origin(Branch::Receive, i), key(origin(Branch::Receive, i))))
        .collect();
    pool.apply_batch(&replay).unwrap();
    assert_eq!(pool.state(), &before);
}

#[test]
fn a_rejected_batch_changes_nothing() {
    let mut pool = AccountPool::new(PARAMETERS, Network::Testnet, 0, window(3));
    let entry = |o: KeyOrigin| (o, key(o));
    let first = entry(origin(Branch::Receive, 0));
    let mainnet = KeyOrigin::new(PARAMETERS, Network::Mainnet, 0, Branch::Receive, 1);
    let other_account = KeyOrigin::new(PARAMETERS, Network::Testnet, 1, Branch::Receive, 1);
    let cases = [
        (entry(mainnet), Error::ForeignKey(mainnet)),
        (entry(other_account), Error::ForeignKey(other_account)),
        (
            entry(origin(Branch::Receive, 2)),
            Error::NotContiguous(origin(Branch::Receive, 2)),
        ),
        (
            entry(origin(Branch::Receive, 3)),
            Error::OutsideWindow(origin(Branch::Receive, 3)),
        ),
        (
            (
                origin(Branch::Receive, 1),
                PublicKey::from_bytes(ParameterSet::Sha2_192s, &[0; 48]).unwrap(),
            ),
            Error::PublicKeyParameters(origin(Branch::Receive, 1)),
        ),
        (
            (origin(Branch::Receive, 0), key(origin(Branch::Receive, 9))),
            Error::ConflictingKey(origin(Branch::Receive, 0)),
        ),
    ];
    for (bad, expected) in cases {
        let before = pool.state().clone();
        assert_eq!(pool.apply_batch(&[first, bad]), Err(expected));
        assert_eq!(pool.state(), &before, "{expected:?}");
    }
}

#[test]
fn a_source_that_returns_nothing_new_stops_replenishment() {
    struct Silent;
    impl PublicKeySource for Silent {
        type Error = &'static str;
        fn public_keys(&mut self, _: KeyRange) -> Result<Vec<(KeyOrigin, PublicKey)>, Self::Error> {
            Ok(Vec::new())
        }
    }
    let mut pool = AccountPool::new(PARAMETERS, Network::Testnet, 0, window(2));
    let request = pool.replenish_request(Branch::Receive).unwrap();
    assert_eq!(
        pool.replenish(Branch::Receive, &mut Silent),
        Err(SourceError::NoProgress(request))
    );

    struct Failing;
    impl PublicKeySource for Failing {
        type Error = &'static str;
        fn public_keys(&mut self, _: KeyRange) -> Result<Vec<(KeyOrigin, PublicKey)>, Self::Error> {
            Err("device disconnected")
        }
    }
    assert_eq!(
        pool.replenish(Branch::Receive, &mut Failing),
        Err(SourceError::Source("device disconnected"))
    );
}

#[test]
fn observations_require_a_provisioned_key_of_this_pool() {
    let mut pool = pool(2);
    let unknown = origin(Branch::Receive, 2);
    let foreign = KeyOrigin::new(
        ParameterSet::Sha2_192s,
        Network::Testnet,
        0,
        Branch::Receive,
        0,
    );
    assert_eq!(
        pool.record_received(unknown),
        Err(Error::UnknownKey(unknown))
    );
    assert_eq!(
        pool.record_received(foreign),
        Err(Error::ForeignKey(foreign))
    );
    assert_eq!(
        pool.set_confirmed_signatures(unknown, 1),
        Err(Error::UnknownKey(unknown))
    );
    assert_eq!(
        pool.signing_permission(unknown, false),
        Err(Error::UnknownKey(unknown))
    );
}

#[test]
fn restore_finds_every_used_key_and_stops_after_a_full_window_unused() {
    // Gaps of one and two unused keys stay inside a window of three.
    let used: HashSet<KeyOrigin> = [
        origin(Branch::Receive, 0),
        origin(Branch::Receive, 2),
        origin(Branch::Receive, 5),
        origin(Branch::Change, 0),
    ]
    .into();
    let mut checked = HashSet::new();
    let pool = AccountPool::discover(
        PARAMETERS,
        Network::Testnet,
        0,
        window(3),
        &mut StandIn::default(),
        |o, k| {
            assert_eq!(*k, key(o));
            assert!(checked.insert(o), "{o:?} checked twice");
            used.contains(&o)
        },
    )
    .unwrap();

    let receive = &pool.state().receive;
    assert_eq!(receive.highest_used, Some(5));
    assert_eq!(receive.public_keys.len(), 9);
    assert_eq!(receive.issued_end, 6);
    let change = &pool.state().change;
    assert_eq!(change.highest_used, Some(0));
    assert_eq!(change.public_keys.len(), 4);
    assert_eq!(
        checked
            .iter()
            .filter(|o| o.branch() == Branch::Receive)
            .count(),
        9
    );
    assert_eq!(pool.replenish_request(Branch::Receive), None);
}

#[test]
fn restore_never_looks_past_a_full_window_of_unused_keys() {
    // Index 4 sits past three unused keys, so no wallet following the window paid it.
    let used: HashSet<KeyOrigin> = [origin(Branch::Receive, 0), origin(Branch::Receive, 4)].into();
    let mut checked = HashSet::new();
    let pool = AccountPool::discover(
        PARAMETERS,
        Network::Testnet,
        0,
        window(3),
        &mut StandIn::default(),
        |o, _| {
            checked.insert(o);
            used.contains(&o)
        },
    )
    .unwrap();
    assert_eq!(pool.state().receive.highest_used, Some(0));
    assert!(!checked.contains(&origin(Branch::Receive, 4)));
}

#[test]
fn restore_reproduces_the_keys_a_wallet_handed_out() {
    let mut seed = WalletSeed::from_bytes(&[7; 32]).unwrap();
    let mut wallet = AccountPool::new(PARAMETERS, Network::Testnet, 0, window(2));
    let mut paid = HashSet::new();
    for _ in 0..5 {
        wallet.replenish(Branch::Receive, &mut seed).unwrap();
        let issued = wallet.issue(Branch::Receive).unwrap();
        assert!(issued.fresh);
        wallet.record_received(issued.origin).unwrap();
        paid.insert(issued.public_key);
    }
    wallet.replenish(Branch::Receive, &mut seed).unwrap();

    let mut restored_seed = WalletSeed::from_bytes(&[7; 32]).unwrap();
    let restored = AccountPool::discover(
        PARAMETERS,
        Network::Testnet,
        0,
        window(2),
        &mut restored_seed,
        |_, k| paid.contains(k),
    )
    .unwrap();
    assert_eq!(restored.state().receive, wallet.state().receive);
}

#[test]
fn the_seed_source_returns_each_origins_derived_public_key() {
    for parameters in [ParameterSet::Sha2_128f, ParameterSet::Sha2_192s] {
        let mut seed = WalletSeed::from_bytes(&[3; 32]).unwrap();
        let mut pool = AccountPool::new(parameters, Network::Regtest, 4, window(1));
        pool.replenish(Branch::Change, &mut seed).unwrap();
        let (origin, public_key) = pool.public_keys(Branch::Change).next().unwrap();
        assert_eq!(seed.derive_key(origin).public_key(), public_key);
        assert_eq!(origin.account(), 4);
    }
}

#[test]
fn the_warning_threshold_is_eighty_percent_of_two_to_the_sixty_four() {
    assert_eq!(SIGNATURE_WARNING_THRESHOLD, 14_757_395_258_967_641_292);
}

#[test]
fn a_key_at_the_threshold_needs_force_to_sign_and_is_not_shown_again() {
    let mut pool = pool(1);
    let only = origin(Branch::Receive, 0);
    assert_eq!(issue_index(&mut pool, Branch::Receive), (0, true));

    pool.set_confirmed_signatures(only, SIGNATURE_WARNING_THRESHOLD - 1)
        .unwrap();
    assert_eq!(pool.signing_permission(only, false), Ok(()));
    // Not replenished after the payment, so the pool can only repeat this key.
    assert_eq!(issue_index(&mut pool, Branch::Receive), (0, false));

    pool.set_confirmed_signatures(only, SIGNATURE_WARNING_THRESHOLD)
        .unwrap();
    assert_eq!(
        pool.signing_permission(only, false),
        Err(Error::ForceRequired(only))
    );
    assert_eq!(pool.signing_permission(only, true), Ok(()));
    assert_eq!(
        pool.issue(Branch::Receive),
        Err(Error::AddressWithheld(only))
    );
}

#[test]
fn a_nonzero_signature_total_records_the_key_as_used() {
    let mut pool = pool(2);
    pool.set_confirmed_signatures(origin(Branch::Change, 1), 1)
        .unwrap();
    assert_eq!(pool.state().change.highest_used, Some(1));
    assert_eq!(pool.state().change.issued_end, 2);
}
