use std::{convert::Infallible, num::NonZeroUsize};

use zcash_client_backend::{
    data_api::{
        InputSource as _, OutputLockStore as _,
        wallet::{
            ConfirmationsPolicy, TargetHeight,
            input_selection::{
                GreedyInputSelector, LockFilter, LockedInputPolicy, NonEmptyBTreeSet,
                NoteSelection, SpendPolicy,
            },
        },
    },
    fees::{DustOutputPolicy, SplitPolicy, zip317::MultiOutputChangeStrategy},
    wallet::{LockOwner, OutputRef, OvkPolicy},
};
use zcash_protocol::{PoolType, ShieldedPool};

use super::*;

/// Where a test note sits for selection under `PreferUnlocked`.
#[derive(Clone, Copy, PartialEq)]
enum At {
    /// Unlocked, in the preferred tier.
    Free,
    /// Locked by the selecting owner, in the less-preferred tier.
    Owned,
    /// Locked by another owner, so ineligible.
    Foreign,
    /// Excluded by the caller.
    Excluded,
    /// Short of the default policy's confirmations.
    Unconfirmed,
}

const O: bool = false;
const T: bool = true;

/// Mines and scans `notes`, each a value paid to a refund key when `.1` and to the test
/// account's ordinary address otherwise, then selects consolidation funding for `target` under
/// `PreferUnlocked` and the default confirmations policy. Returns the sorted funding values.
fn funding(specs: &[(u64, bool, At)], target: u64) -> Vec<u64> {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let refund = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, start());
    let (first, _) = st.generate_empty_block();
    let mine = |st: &mut State, unconfirmed| {
        let mined = specs
            .iter()
            .filter(|n| (n.2 == At::Unconfirmed) == unconfirmed);
        for (value, one_time, _) in mined {
            let fvk = if *one_time {
                refund.full_viewing_key().clone()
            } else {
                parent(st)
            };
            let value = Zatoshis::const_from_u64(*value);
            st.generate_next_block(&IronwoodFvk(fvk), AddressType::DefaultExternal, value);
        }
    };
    mine(&mut st, false);
    for _ in 0..10 {
        st.generate_empty_block();
    }
    mine(&mut st, true);
    let tip = st.generate_empty_block().0;
    st.scan_cached_blocks_with_one_time_ivks(first, specs.len() + 12);

    let (owner, foreign) = (LockOwner::new([1; 32]), LockOwner::new([2; 32]));
    let mut exclude = vec![];
    for note in notes(&st, tip) {
        let value = note.note().value().inner();
        let at = specs.iter().find(|n| n.0 == value).unwrap().2;
        let output = OutputRef::new(*note.txid(), PoolType::IRONWOOD, note.output_index().into());
        let db = st.wallet_mut().db_mut();
        let mut lock = |owner| db.lock_outputs(&[output], owner, BlockHeight::from(u32::MAX));
        match at {
            At::Owned => assert_eq!(lock(owner).unwrap(), 1),
            At::Foreign => assert_eq!(lock(foreign).unwrap(), 1),
            At::Excluded => exclude.push(*note.internal_note_id()),
            At::Free | At::Unconfirmed => {}
        }
    }

    let policy = LockedInputPolicy::PreferUnlocked(NonEmptyBTreeSet::singleton(owner));
    let (funding, _) = st
        .wallet()
        .db()
        .select_spendable_notes_for_consolidation(
            account,
            Zatoshis::const_from_u64(target),
            ShieldedPool::Ironwood,
            TargetHeight::from(tip + 1),
            ConfirmationsPolicy::default(),
            &exclude,
            LockFilter::Policy(&policy),
            4,
        )
        .unwrap()
        .into_parts();
    let mut values: Vec<_> = funding
        .ironwood()
        .iter()
        .map(|note| note.note().value().inner())
        .collect();
    values.sort_unstable();
    values
}

/// Largest-first funding swaps eligible one-time-key notes in for notes of the same lock tier
/// while as many notes still cover the target, never adding a note or drawing on a less-preferred
/// tier.
#[test]
fn funding_swaps_in_one_time_key_notes_without_adding_notes() {
    use At::*;
    let both = [
        (1_000_000, O, Free),
        (900_000, O, Free),
        (800_000, T, Free),
        (700_000, T, Free),
        (100_000, T, Free),
    ];
    for (notes, target, expected) in [
        // Two one-time-key notes replace both ordinary notes at exactly the target, and one at a
        // zatoshi more.
        (&both[..], 1_500_000, &[700_000, 800_000][..]),
        (&both, 1_500_001, &[800_000, 1_000_000]),
        // Covering with one-time-key notes alone would take two notes, not one.
        (
            &[(2_000_000, O, Free), (900_000, T, Free), (800_000, T, Free)],
            1_000_000,
            &[2_000_000],
        ),
        // Only the last tier's notes are swapped, here the less-preferred one after every
        // preferred note...
        (
            &[(600_000, O, Free), (500_000, O, Owned), (400_000, T, Owned)],
            1_000_000,
            &[400_000, 600_000],
        ),
        (
            &[
                (600_000, O, Free),
                (300_000, T, Free),
                (500_000, O, Owned),
                (400_000, T, Owned),
            ],
            1_200_000,
            &[300_000, 400_000, 600_000],
        ),
        // ...and a less-preferred tier's notes are never swapped in.
        (
            &[(1_200_000, O, Free), (1_100_000, T, Owned)],
            1_000_000,
            &[1_200_000],
        ),
        // Only an eligible, confirmed one-time-key note is swapped in.
        (
            &[(1_000_000, O, Free), (950_000, T, Free)],
            900_000,
            &[950_000],
        ),
        (
            &[(1_000_000, O, Free), (950_000, T, Foreign)],
            900_000,
            &[1_000_000],
        ),
        (
            &[(1_000_000, O, Free), (950_000, T, Excluded)],
            900_000,
            &[1_000_000],
        ),
        (
            &[(1_000_000, O, Free), (950_000, T, Unconfirmed)],
            900_000,
            &[1_000_000],
        ),
    ] {
        assert_eq!(
            funding(notes, target),
            expected,
            "{target} from {:?}",
            notes.iter().map(|n| n.0).collect::<Vec<_>>()
        );
    }
}

/// Pays the test account's ordinary address `ordinary` and a refund key `one_time` (zatoshis),
/// then proposes, mines and scans an Ironwood payment of `value` with
/// `NoteSelection::PreferConsolidation` and change split by `split`. Returns the sorted input
/// values, the transaction's Ironwood action count and the one-time key of each unspent note
/// afterwards.
fn spend(
    ordinary: &[u64],
    one_time: &[u64],
    value: u64,
    split: SplitPolicy,
) -> (Vec<u64>, usize, Vec<Option<KeyId>>) {
    let mut st = ironwood_wallet();
    let account = st.test_account().cloned().unwrap();
    let refund = reserve_key(
        st.wallet_mut().db_mut(),
        account.id(),
        Purpose::Refund,
        start(),
    );
    let (first, _) = st.generate_empty_block();
    let paid = one_time
        .iter()
        .map(|v| (refund.full_viewing_key().clone(), v));
    let paid = paid.chain(ordinary.iter().map(|v| (parent(&st), v)));
    for (fvk, value) in paid.collect::<Vec<_>>() {
        let value = Zatoshis::const_from_u64(*value);
        st.generate_next_block(&IronwoodFvk(fvk), AddressType::DefaultExternal, value);
    }
    st.scan_cached_blocks_with_one_time_ivks(first, ordinary.len() + one_time.len() + 1);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(5);

    let to = payment(&unified(foreign_receiver()), value, None);
    let request = zip321::TransactionRequest::new(vec![to]).unwrap();
    let change_strategy = MultiOutputChangeStrategy::<_, TestDb>::new(
        zcash_primitives::transaction::fees::zip317::FeeRule::standard(),
        None,
        ShieldedPool::Ironwood,
        DustOutputPolicy::default(),
        split,
    );
    let policy = SpendPolicy::shielded_pools([ShieldedPool::Ironwood])
        .with_note_selection(NoteSelection::PreferConsolidation);
    let proposal = st
        .propose_transfer_with_policy(
            account.id(),
            &GreedyInputSelector::new(),
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
            &policy,
        )
        .unwrap();
    let inputs = proposal.steps().first().shielded_inputs().unwrap().notes();
    let mut inputs: Vec<_> = inputs.iter().map(|n| u64::from(n.note().value())).collect();
    inputs.sort_unstable();

    let created = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();
    let tx = st.wallet().get_transaction(created[0]).unwrap().unwrap();
    let actions = tx.ironwood_bundle().unwrap().actions().len();
    let (height, _) = st.generate_next_block_including(created[0]);
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
    (inputs, actions, unspent_keys(&st, height))
}

/// Funding and spare input slots spend one-time-key notes first, into ordinary change, but never
/// with more actions than plain largest-first funding alone: a one-time-key note that would
/// change the change split is skipped, and later candidates take its slot.
#[test]
fn one_time_key_notes_are_spent_first_without_adding_actions() {
    let split = SplitPolicy::with_min_output_value(
        NonZeroUsize::new(4).unwrap(),
        Zatoshis::const_from_u64(100_000),
    );
    let single = SplitPolicy::single_output();
    // The last column is the action count of the transaction plain largest-first funding builds.
    for (ordinary, one_time, value, split, expected, plain_actions) in [
        // The largest note funds the payment alone, and the one-time-key note takes the spare slot
        // instead of the smaller ordinary note.
        (
            &[1_000_000, 100_000][..],
            &[200_000][..],
            300_000,
            single,
            &[200_000, 1_000_000][..],
            2,
        ),
        // Two inputs fill both actions, so no slot is spare, but the one-time-key note replaces
        // the smaller ordinary note.
        (
            &[2_000_000, 1_200_000],
            &[1_000_000],
            2_500_000,
            single,
            &[1_000_000, 2_000_000],
            2,
        ),
        // Change splitting does not count the one-time-key note as one the wallet keeps, so
        // spending it adds no change output, and the four change outputs leave room for all.
        (
            &[2_000_000, 20_000, 20_000],
            &[1_000_000],
            1_500_000,
            split,
            &[20_000, 20_000, 1_000_000, 2_000_000],
            5,
        ),
        // Here its value would split the change into four outputs, so an ordinary note takes the
        // one spare slot instead.
        (
            &[2_000_000, 20_000, 20_000],
            &[1_000_000],
            1_850_000,
            split,
            &[20_000, 2_000_000],
            2,
        ),
        // The first one-time-key note fits one of two spare slots, but adding the second would
        // split the change further, so an ordinary note takes the other slot.
        (
            &[3_000_000, 20_000],
            &[50_000, 1_000_000],
            2_765_000,
            split,
            &[20_000, 50_000, 3_000_000],
            3,
        ),
    ] {
        let (inputs, actions, unspent) = spend(ordinary, one_time, value, split);
        assert_eq!(inputs, expected, "paying {value}");
        assert_eq!(actions, plain_actions, "paying {value}");
        let unspent_one_time = one_time.iter().filter(|v| !inputs.contains(v)).count();
        assert_eq!(
            unspent.iter().flatten().count(),
            unspent_one_time,
            "paying {value}"
        );
    }
}
