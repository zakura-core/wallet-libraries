//! The salt rule: per-block retries, fresh budgets, sealing before a block
//! that defeats every attempt, and agreement however often publication runs.
use super::*;
use sha2::{Digest, Sha256};

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
