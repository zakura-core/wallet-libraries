//! The salt rule: per-block retries, fresh budgets, sealing before a block
//! that defeats every attempt, and agreement however often publication runs.
use super::*;
use sha2::{Digest, Sha256};
use zakura_pir_protocol::directory::choice::SeedPolicy;

fn receiver(i: u32) -> ReceiverBytes {
    let mut r = [0x5a; 43];
    r[..4].copy_from_slice(&i.to_le_bytes());
    r
}

fn block(i: u32) -> Hash {
    Sha256::digest(i.to_le_bytes()).into()
}

/// Tags that put `new` on `existing`'s tag under each of `salts`.
fn colliding(
    salts: Vec<Hash>,
    new: ReceiverBytes,
    existing: ReceiverBytes,
) -> impl FnMut(&Hash, &[u8]) -> Tag {
    move |salt, key| match salts.contains(salt) && key == new {
        true => tag(salt, &existing),
        false => tag(salt, key),
    }
}

/// A projection holding receivers 0 and 1 under its initial salt.
fn started() -> Projection {
    let mut p = Projection::new(initial_salt(&[2; 32], 0));
    assert_eq!(
        p.project(&[receiver(0), receiver(1), receiver(0)], &block(0)),
        Ok(0)
    );
    p
}

/// A new receiver colliding with a held tag places the segment again under
/// the block's first retry salt, which is committed.
#[test]
fn a_collision_replaces_under_the_first_retry_salt() {
    let mut p = started();
    let committed = *p.salt();
    let forced = colliding(vec![committed], receiver(2), receiver(0));
    assert_eq!(p.project_by(&[receiver(2)], &block(1), forced), Ok(1));
    assert_eq!(*p.salt(), retry_salt(&committed, 1, &block(1)));
    assert_eq!(p.tags.len(), 3);
    assert_eq!(p.taken.len(), 3);
}

/// Retry 8 is the last a block may use; a block that collides under all nine
/// attempts seals the segment before it and changes nothing.
#[test]
fn retry_eight_is_the_last_attempt() {
    let p = started();
    let committed = *p.salt();
    let salts = |n| {
        (0..n)
            .map(|r| retry_salt(&committed, r, &block(1)))
            .collect::<Vec<_>>()
    };
    let mut last = p.clone();
    let forced = colliding(salts(8), receiver(2), receiver(0));
    assert_eq!(last.project_by(&[receiver(2)], &block(1), forced), Ok(8));
    let mut sealed = p.clone();
    let forced = colliding(salts(9), receiver(2), receiver(0));
    assert_eq!(
        sealed.project_by(&[receiver(2)], &block(1), forced),
        Err(SealBefore)
    );
    assert_eq!(*sealed.salt(), committed);
    assert_eq!(
        sealed.placement().collect::<Vec<_>>(),
        p.placement().collect::<Vec<_>>()
    );
}

/// Each forcing block gets a fresh budget: twelve blocks in a row that each
/// collide under their committed salt each re-place once and never seal.
#[test]
fn every_forcing_block_has_a_fresh_budget() {
    let mut p = started();
    for i in 2..14 {
        let committed = *p.salt();
        let forced = colliding(vec![committed], receiver(i), receiver(0));
        assert_eq!(
            p.project_by(&[receiver(i)], &block(i), forced),
            Ok(1),
            "block {i}"
        );
        assert_eq!(*p.salt(), retry_salt(&committed, 1, &block(i)));
    }
}

/// A block that fails placement under the committed salt but fits under a
/// retry salt commits that salt; a block that cannot fit under any of its nine
/// attempts seals the segment before it.
#[test]
fn placement_failures_retry_and_then_seal() {
    let start = || {
        let mut p = Projection::with_rows(initial_salt(&[2; 32], 0), 4, 2);
        assert_eq!(p.project(&[receiver(0), receiver(1)], &block(0)), Ok(0));
        p
    };
    let retried = (2..400)
        .find_map(|i| {
            let mut p = start();
            let paid: Vec<_> = (i..i + 5).map(receiver).collect();
            p.project(&paid, &block(i)).ok().filter(|r| *r > 0)
        })
        .expect("some block fails the committed salt and fits a retry");
    assert!(retried <= MAX_SALT_RETRIES);
    let mut full = start();
    let before = *full.salt();
    let paid: Vec<_> = (2..9).map(receiver).collect();
    assert_eq!(full.project(&paid, &block(1)), Err(SealBefore));
    assert_eq!((*full.salt(), full.tags.len()), (before, 2));
}

/// The same chain, with forced re-placements at two blocks, gives identical
/// tables whether published after every block or once after replaying every
/// block as a restart would.
#[test]
fn publication_cadence_and_restart_agree() {
    let blocks: Vec<Vec<ReceiverBytes>> = (0..12)
        .map(|b| (0..3).map(|i| receiver(b * 2 + i)).collect())
        .collect();
    let replay = |p: &mut Projection, b: usize| {
        let committed = *p.salt();
        let forced = colliding(vec![committed], blocks[b][2], blocks[b][0]);
        let expected = u32::from(b == 3 || b == 8);
        let result = match expected {
            1 => p.project_by(&blocks[b], &block(b as u32), forced),
            _ => p.project(&blocks[b], &block(b as u32)),
        };
        assert_eq!(result, Ok(expected));
    };
    let coverage = Coverage {
        genesis: [1; 32],
        history_revision: 0,
        start_height: 100,
        start_parent: [2; 32],
        start_position: 0,
        end_height: 111,
        end_hash: [3; 32],
        end_position: 1_000,
    };
    let tree = Tree {
        height: 111,
        hash: [3; 32],
        size: 1_000,
    };
    let payment = |b: usize, i: usize, r: ReceiverBytes| -> Paid {
        let height = 100 + b as u32;
        let payment = Payment {
            height,
            block_hash: if height == 111 {
                [3; 32]
            } else {
                [height as u8; 32]
            },
            txid: [(b * 3 + i) as u8; 32],
            tx_index: 1 + i as u32,
            action_index: 0,
            position: (b * 3 + i) as u64,
            action_nullifier: [5; 32],
            cmx: [6; 32],
            ephemeral_key: [7; 32],
            ciphertext_prefix: [8; 52],
        };
        (r, payment, [0; PAYLOAD_BYTES])
    };
    let publish = |p: &Projection, through: usize| {
        let paid: Vec<Paid> = (0..=through)
            .flat_map(|b| {
                blocks[b]
                    .iter()
                    .enumerate()
                    .map(move |(i, r)| payment(b, i, *r))
            })
            .collect();
        let mut coverage = coverage.clone();
        coverage.end_height = 100 + through as u32;
        coverage.end_hash = if through == 11 {
            [3; 32]
        } else {
            [coverage.end_height as u8; 32]
        };
        let tree = Tree {
            height: coverage.end_height,
            hash: coverage.end_hash,
            ..tree
        };
        build(
            p,
            coverage,
            &block(through as u32),
            OPEN_SEED_ATTEMPTS,
            2048,
            tree,
            &paid,
        )
        .unwrap()
    };

    let mut every = Projection::new(initial_salt(&[2; 32], 0));
    let mut published = None;
    for b in 0..blocks.len() {
        replay(&mut every, b);
        published = Some(publish(&every, b));
    }
    let mut restarted = Projection::new(initial_salt(&[2; 32], 0));
    (0..blocks.len()).for_each(|b| replay(&mut restarted, b));
    let (a, b) = (published.unwrap(), publish(&restarted, 11));
    assert_eq!(a.directory.data, b.directory.data);
    assert_eq!(a.directory.choice, b.directory.choice);
    assert_eq!(a.directory.manifest, b.directory.manifest);
    assert_eq!(a.companion.manifest, b.companion.manifest);
}

/// Three receivers paid once each in one block, projected, with the
/// segment's coverage and tree.
fn choice_fixture() -> (Projection, Coverage, Tree, Vec<Paid>) {
    let coverage = Coverage {
        genesis: [1; 32],
        history_revision: 0,
        start_height: 100,
        start_parent: [2; 32],
        start_position: 0,
        end_height: 100,
        end_hash: [3; 32],
        end_position: 10,
    };
    let paid: Vec<Paid> = (0..3)
        .map(|i| {
            let payment = Payment {
                height: 100,
                block_hash: [3; 32],
                txid: [4; 32],
                tx_index: 1,
                action_index: i,
                position: i.into(),
                action_nullifier: [5; 32],
                cmx: [6; 32],
                ephemeral_key: [7; 32],
                ciphertext_prefix: [8; 52],
            };
            (receiver(i), payment, [0; PAYLOAD_BYTES])
        })
        .collect();
    let mut projection = Projection::new(initial_salt(&coverage.start_parent, 0));
    let receivers: Vec<_> = paid.iter().map(|p| p.0).collect();
    projection.project(&receivers, &[3; 32]).unwrap();
    let tree = Tree {
        height: 100,
        hash: [3; 32],
        size: 10,
    };
    (projection, coverage, tree, paid)
}

/// The seed a built segment's choice object settled on.
fn settled(segment: &Segment) -> u32 {
    let table = ChoiceTable::decode(&segment.directory.choice, SeedPolicy::Any).unwrap();
    table.seed()
}

/// Through the real build: when the open budget's 64 seeds all fail, the
/// build is `Error::Choice` after trying exactly those seeds and leaves the
/// projection as it was. The seal budget goes on to the 65th seed, and a new
/// tip's seeds recover an open build.
#[test]
fn choice_budgets_continue_past_sixty_four_only_at_a_seal() {
    let (projection, coverage, tree, paid) = choice_fixture();
    let salt = *projection.salt();
    let (tip, next) = (block(1), block(2));
    let open: Vec<u32> = candidate_seeds(&salt, &tip, 0..OPEN_SEED_ATTEMPTS).collect();
    let failing: HashSet<u32> = open.iter().copied().collect();
    let placement: Vec<_> = projection.placement().map(|(t, r)| (*t, r)).collect();

    let mut tried = Vec::new();
    let mut fails = |seed| {
        tried.push(seed);
        failing.contains(&seed)
    };
    let failed = build_with(
        &projection,
        coverage.clone(),
        &tip,
        OPEN_SEED_ATTEMPTS,
        2048,
        tree,
        &paid,
        &mut fails,
    );
    assert!(matches!(failed, Err(Error::Choice)));
    assert_eq!(tried, open);
    assert_eq!(*projection.salt(), salt);
    assert_eq!(
        projection
            .placement()
            .map(|(t, r)| (*t, r))
            .collect::<Vec<_>>(),
        placement
    );

    let mut fails = |seed| failing.contains(&seed);
    let sealed = build_with(
        &projection,
        coverage.clone(),
        &tip,
        SEAL_SEED_ATTEMPTS,
        2048,
        tree,
        &paid,
        &mut fails,
    );
    let expected = candidate_seeds(&salt, &tip, 0..SEAL_SEED_ATTEMPTS).nth(64);
    assert_eq!(Some(settled(&sealed.unwrap())), expected);

    let mut fails = |seed| failing.contains(&seed);
    let recovered = build_with(
        &projection,
        coverage,
        &next,
        OPEN_SEED_ATTEMPTS,
        2048,
        tree,
        &paid,
        &mut fails,
    );
    let expected =
        candidate_seeds(&salt, &next, 0..OPEN_SEED_ATTEMPTS).find(|s| !failing.contains(s));
    assert_eq!(Some(settled(&recovered.unwrap())), expected);
}

/// A seal whose every seed fails tries each distinct seed of its 2^16
/// attempts once, skipping repeats, and is `Error::Choice`.
#[test]
fn a_fully_exhausted_seal_fails_after_every_distinct_seed() {
    let (projection, coverage, tree, paid) = choice_fixture();
    let salt = *projection.salt();
    // A tip whose 2^16 attempts repeat a seed, so the skip is exercised.
    let (tip, distinct) = (0..64)
        .map(block)
        .find_map(|tip| {
            let seeds: Vec<u32> = candidate_seeds(&salt, &tip, 0..SEAL_SEED_ATTEMPTS).collect();
            (seeds.len() < SEAL_SEED_ATTEMPTS as usize).then_some((tip, seeds))
        })
        .expect("some tip repeats a seed within 2^16 attempts");
    let mut tried = Vec::new();
    let mut fails = |seed| {
        tried.push(seed);
        true
    };
    let failed = build_with(
        &projection,
        coverage,
        &tip,
        SEAL_SEED_ATTEMPTS,
        2048,
        tree,
        &paid,
        &mut fails,
    );
    assert!(matches!(failed, Err(Error::Choice)));
    assert_eq!(tried, distinct);
}
