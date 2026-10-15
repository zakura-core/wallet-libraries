#![cfg(feature = "crypto")]
//! Common inclusion proofs, checked against an independent commitment tree.
mod common;
use common::{leaves, publication};
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::{note::ExtractedNoteCommitment, tree::MerkleHashOrchard};
use std::collections::BTreeSet;
use zakura_receiver_crypto::{
    Error, Hash,
    witness::{MAX_WITNESS_BYTES, Publication, WitnessCache, WitnessSnapshot},
};

/// An independent tree over `cmxs`.
fn tree(cmxs: &[Hash]) -> CommitmentTree<MerkleHashOrchard, 32> {
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    for cmx in cmxs {
        let cmx = ExtractedNoteCommitment::from_bytes(cmx).unwrap();
        tree.append(MerkleHashOrchard::from_cmx(&cmx)).unwrap();
    }
    tree
}

/// A reused cache must match a fresh build, whose root must match an independent tree.
fn compare(cache: &mut WitnessCache, cmxs: &[Hash], positions: BTreeSet<u32>) {
    let publication = publication(cmxs.len(), positions.len());
    let cached = cache.build(&publication, cmxs, &positions).unwrap();
    let full = WitnessSnapshot::build(&publication, cmxs, &positions).unwrap();
    assert_eq!(cached.encode(), full.encode());
    assert_eq!(full.root(), tree(cmxs).root().to_bytes());
    for position in positions {
        assert_eq!(
            cached.path(position, cmxs[position as usize]).unwrap(),
            full.path(position, cmxs[position as usize]).unwrap()
        );
    }
}

#[test]
fn common_witnesses_bind_positions_and_reject_corrupt_or_stale_data() {
    let commitments: Vec<[u8; 32]> = (1..=20u8).map(|i| [i; 32]).collect();
    let publication = publication(20, 5);
    let positions = [0, 5, 6, 18, 19].into_iter().collect();
    let snapshot = WitnessSnapshot::build(&publication, &commitments, &positions).unwrap();
    let encoded = snapshot.encode();
    // The header binds the publication's fields at fixed offsets.
    assert_eq!(&encoded[..8], b"IWPROOF1");
    assert_eq!(&encoded[8..40], &publication.genesis);
    assert_eq!(&encoded[40..72], &publication.directory_revision);
    assert_eq!(&encoded[72..76], &110u32.to_le_bytes());
    assert_eq!(&encoded[76..108], &publication.end_hash);
    assert_eq!(&encoded[108..116], &20u64.to_le_bytes());
    let restored = WitnessSnapshot::decode(&encoded, &publication).unwrap();
    for position in positions {
        let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
        let mut witness = None;
        for (index, cmx) in commitments.iter().enumerate() {
            let hash =
                MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from_bytes(cmx).unwrap());
            tree.append(hash).unwrap();
            if index == position as usize {
                witness = IncrementalWitness::from_tree(tree.clone());
            } else if let Some(w) = &mut witness {
                w.append(hash).unwrap();
            }
        }
        let expected = witness.unwrap().path().unwrap();
        assert_eq!(
            restored
                .path(position, commitments[position as usize])
                .unwrap()
                .as_slice(),
            expected
                .path_elems()
                .iter()
                .map(|h| h.to_bytes())
                .collect::<Vec<_>>()
        );
        assert!(restored.path(position, [31; 32]).is_err());
    }
    // Every bound field is checked against the publication.
    let stale: [fn(&mut Publication); 5] = [
        |p| p.genesis[0] ^= 1,
        |p| p.directory_revision[0] ^= 1,
        |p| p.end_height += 1,
        |p| p.end_hash[0] ^= 1,
        |p| p.end_position += 1,
    ];
    for edit in stale {
        let mut other = publication.clone();
        edit(&mut other);
        assert!(matches!(
            WitnessSnapshot::decode(&encoded, &other),
            Err(Error::Coverage)
        ));
    }
    assert!(WitnessSnapshot::decode(&encoded[..encoded.len() - 1], &publication).is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(WitnessSnapshot::decode(&trailing, &publication).is_err());
    let mut corrupt = encoded.clone();
    corrupt[152] = 32;
    assert!(WitnessSnapshot::decode(&corrupt, &publication).is_err());
    let mut corrupt = encoded.clone();
    corrupt[116] ^= 1;
    assert!(
        WitnessSnapshot::decode(&corrupt, &publication)
            .unwrap()
            .path(0, commitments[0])
            .is_err()
    );
    // A node hash that is not a field element.
    let mut corrupt = encoded.clone();
    corrupt[157..189].fill(255);
    assert!(matches!(
        WitnessSnapshot::decode(&corrupt, &publication),
        Err(Error::Malformed)
    ));
    // Nodes out of order.
    let mut corrupt = encoded.clone();
    let (first, second) = (corrupt[152..189].to_vec(), corrupt[189..226].to_vec());
    corrupt[152..189].copy_from_slice(&second);
    corrupt[189..226].copy_from_slice(&first);
    assert!(WitnessSnapshot::decode(&corrupt, &publication).is_err());
    assert_eq!(encoded, restored.encode());
    // Coverage no manifest can declare is refused before parsing.
    let mut impossible = publication.clone();
    impossible.records = 21;
    assert!(matches!(
        WitnessSnapshot::decode(&encoded, &impossible),
        Err(Error::Malformed)
    ));
    assert!(WitnessSnapshot::decode(&vec![0; MAX_WITNESS_BYTES + 1], &publication).is_err());
}

#[test]
fn appends_rewinds_and_forks_match_full_build_byte_for_byte() {
    let mut cache = WitnessCache::default();
    let all = leaves(130);
    // Odd pairs, power-of-two crossings, same-size forks, shorter forks and reappend.
    for len in [
        1, 2, 3, 7, 8, 9, 31, 32, 33, 64, 65, 129, 130, 129, 65, 64, 63, 1, 130,
    ] {
        compare(&mut cache, &all[..len], (0..len as u32).collect());
    }
    for (offset, len) in [(128, 130), (64, 130), (0, 130), (17, 65), (0, 1)] {
        let mut fork = all[..len].to_vec();
        fork[offset][8] = 1;
        compare(&mut cache, &fork, (0..len as u32).collect());
    }
}

#[test]
fn positions_and_publication_are_never_cached() {
    let mut cache = WitnessCache::default();
    let cmxs = leaves(31);
    compare(&mut cache, &cmxs, [0].into_iter().collect());
    compare(&mut cache, &cmxs, [1, 19, 30].into_iter().collect());
    compare(&mut cache, &cmxs, BTreeSet::new());
    let mut p = publication(cmxs.len(), 1);
    p.end_hash[0] ^= 1;
    p.end_height += 1;
    assert_eq!(
        cache
            .build(&p, &cmxs, &[30].into_iter().collect())
            .unwrap()
            .encode(),
        WitnessSnapshot::build(&p, &cmxs, &[30].into_iter().collect())
            .unwrap()
            .encode()
    );
}

#[test]
fn rejected_inputs_do_not_poison_later_builds() {
    let mut cache = WitnessCache::default();
    let cmxs = leaves(17);
    compare(&mut cache, &cmxs, [0, 16].into_iter().collect());
    let mut malformed = cmxs.clone();
    malformed[8] = [255; 32];
    assert!(
        cache
            .build(&publication(17, 0), &malformed, &BTreeSet::new())
            .is_err()
    );
    assert!(
        cache
            .build(&publication(17, 1), &cmxs, &[17].into_iter().collect())
            .is_err()
    );
    assert!(
        cache
            .build(&publication(18, 0), &cmxs, &BTreeSet::new())
            .is_err()
    );
    compare(&mut cache, &cmxs[..9], [0, 8].into_iter().collect());
}

/// A publication before the first commitment proves against the empty tree's root
/// with no nodes, and the cache moves into and out of it.
#[test]
fn an_empty_tree_binds_the_empty_root() {
    let mut cache = WitnessCache::default();
    compare(&mut cache, &[], BTreeSet::new());
    let p = publication(0, 0);
    let empty = WitnessSnapshot::build(&p, &[], &BTreeSet::new()).unwrap();
    let encoded = empty.encode();
    assert_eq!(encoded.len(), 152);
    assert_eq!(
        WitnessSnapshot::decode(&encoded, &p).unwrap().encode(),
        encoded
    );
    let cmxs = leaves(9);
    compare(&mut cache, &cmxs, [0, 8].into_iter().collect());
    compare(&mut cache, &[], BTreeSet::new());
    compare(&mut cache, &cmxs, [0, 8].into_iter().collect());
    // Zero records in a nonempty tree still bind that tree's root.
    compare(&mut cache, &cmxs, BTreeSet::new());
    let unpaid = cache.build(&publication(9, 0), &cmxs, &BTreeSet::new());
    assert_ne!(unpaid.unwrap().root(), empty.root());
    // Coverage inconsistent with its commitments is refused, leaving the cache usable.
    let cases: [(Publication, &[Hash], BTreeSet<u32>); 3] = [
        (publication(0, 1), &[], [0].into_iter().collect()),
        (publication(1, 0), &[], BTreeSet::new()),
        (publication(0, 0), &cmxs[..1], BTreeSet::new()),
    ];
    for (p, cmxs, positions) in cases {
        assert!(cache.build(&p, cmxs, &positions).is_err());
    }
    compare(&mut cache, &[], BTreeSet::new());
}

#[test]
fn positions_must_cover_exactly_the_publication_records() {
    let cmxs = leaves(17);
    let two: BTreeSet<u32> = [0, 16].into_iter().collect();
    let mut cache = WitnessCache::default();
    compare(&mut cache, &cmxs[..9], [0, 8].into_iter().collect());
    // An omitted position and an extra one, through the cached and fresh entrypoints.
    for (records, positions) in [(3, &two), (1, &two)] {
        assert!(matches!(
            cache.build(&publication(17, records), &cmxs, positions),
            Err(Error::Coverage)
        ));
        assert!(matches!(
            WitnessSnapshot::build(&publication(17, records), &cmxs, positions),
            Err(Error::Coverage)
        ));
    }
    // A history that does not start at the empty tree cannot be proven.
    let mut late = publication(17, 2);
    late.start_position = 1;
    assert!(matches!(
        cache.build(&late, &cmxs, &two),
        Err(Error::Coverage)
    ));
    // The rejections left the primed cache usable.
    compare(&mut cache, &cmxs, two);
}

#[test]
fn shared_path_checks_match_individual_path_calls() {
    /// The first failing [`WitnessSnapshot::path`] call, as a comparable string.
    fn individually(proof: &WitnessSnapshot, leaves: &[(u32, Hash)]) -> String {
        format!(
            "{:?}",
            leaves
                .iter()
                .try_for_each(|(p, cmx)| proof.path(*p, *cmx).map(|_| ()))
        )
    }
    let cmxs = leaves(70);
    let positions: BTreeSet<u32> = [0, 1, 2, 9, 33, 34, 35, 64, 69].into_iter().collect();
    let publication = publication(cmxs.len(), positions.len());
    let encoded = WitnessSnapshot::build(&publication, &cmxs, &positions)
        .unwrap()
        .encode();
    // The same file with its first level-0 node replaced by another valid hash, which
    // breaks only the paths that use it.
    let mut swapped = encoded.clone();
    swapped.copy_within(152 + 37 + 5..152 + 2 * 37, 152 + 5);
    let at = |p: u32| (p, cmxs[p as usize]);
    let all: Vec<_> = positions.iter().map(|p| at(*p)).collect();
    let mut wrong = all.clone();
    wrong[3].1 = cmxs[10];
    let mut invalid = all.clone();
    invalid[4].1 = [255; 32];
    let cases: Vec<Vec<(u32, Hash)>> = vec![
        all.clone(),
        all.iter().rev().copied().collect(),
        [all.clone(), all.clone()].concat(),
        // A verified position seen again with another commitment.
        vec![at(33), (33, cmxs[34])],
        wrong,
        invalid,
        // Missing a sibling, then outside the tree.
        vec![at(0), at(5)],
        vec![at(0), (70, cmxs[0])],
        vec![],
    ];
    for bytes in [&encoded, &swapped] {
        let proof = WitnessSnapshot::decode(bytes, &publication).unwrap();
        for leaves in &cases {
            assert_eq!(
                format!("{:?}", proof.check_paths(leaves.iter().copied())),
                individually(&proof, leaves),
                "{leaves:?}"
            );
        }
    }
    let proof = WitnessSnapshot::decode(&encoded, &publication).unwrap();
    proof.check_paths(all.clone()).unwrap();
    let proof = WitnessSnapshot::decode(&swapped, &publication).unwrap();
    assert!(matches!(proof.check_paths(all), Err(Error::Malformed)));
}
