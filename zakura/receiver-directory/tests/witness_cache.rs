use incrementalmerkletree::frontier::CommitmentTree;
use orchard::{note::ExtractedNoteCommitment, tree::MerkleHashOrchard};
use receiver_directory::{
    Hash,
    snapshot::{MIN_ROWS, Manifest, PROFILE},
    witness::{WitnessCache, WitnessSnapshot},
};
use std::collections::BTreeSet;

/// A manifest ending at `len` commitments that promises `records` records.
fn manifest(len: usize, records: usize) -> Manifest {
    Manifest {
        profile: PROFILE.into(),
        genesis: [1; 32],
        start_height: 100,
        start_parent: [2; 32],
        start_position: 0,
        end_height: 110,
        end_hash: [3; 32],
        end_position: len as u64,
        rows: MIN_ROWS,
        salt: [3; 32],
        records: records as u64,
        data_sha256: [0; 32],
        filters: vec![receiver_directory::snapshot::FilterSet {
            label: receiver_directory::filter::PAID.into(),
            count: 0,
            window_secs: None,
            since_unix: None,
            until_unix: None,
        }],
        filters_sha256: [0; 32],
    }
}
fn leaves(len: usize) -> Vec<Hash> {
    (0..len)
        .map(|i| {
            let mut cmx = [0; 32];
            cmx[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            cmx
        })
        .collect()
}
/// A reused cache must match a fresh build, whose root must match an independent tree.
fn compare(cache: &mut WitnessCache, cmxs: &[Hash], positions: BTreeSet<u32>) {
    let manifest = manifest(cmxs.len(), positions.len());
    let full = WitnessSnapshot::build(&manifest, cmxs, &positions).unwrap();
    let cached = cache.build(&manifest, cmxs, &positions).unwrap();
    assert_eq!(cached.encode(), full.encode());
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    for cmx in cmxs {
        let cmx = ExtractedNoteCommitment::from_bytes(cmx).unwrap();
        tree.append(MerkleHashOrchard::from_cmx(&cmx)).unwrap();
    }
    assert_eq!(full.root(), tree.root().to_bytes());
    for position in positions {
        assert_eq!(
            cached.path(position, cmxs[position as usize]).unwrap(),
            full.path(position, cmxs[position as usize]).unwrap()
        );
    }
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
fn positions_and_manifest_are_never_cached() {
    let mut cache = WitnessCache::default();
    let cmxs = leaves(31);
    compare(&mut cache, &cmxs, [0].into_iter().collect());
    compare(&mut cache, &cmxs, [1, 19, 30].into_iter().collect());
    compare(&mut cache, &cmxs, BTreeSet::new());
    let mut m = manifest(cmxs.len(), 1);
    m.end_hash[0] ^= 1;
    m.end_height += 1;
    assert_eq!(
        cache
            .build(&m, &cmxs, &[30].into_iter().collect())
            .unwrap()
            .encode(),
        WitnessSnapshot::build(&m, &cmxs, &[30].into_iter().collect())
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
            .build(&manifest(17, 0), &malformed, &BTreeSet::new())
            .is_err()
    );
    assert!(
        cache
            .build(&manifest(17, 1), &cmxs, &[17].into_iter().collect())
            .is_err()
    );
    assert!(
        cache
            .build(&manifest(18, 0), &cmxs, &BTreeSet::new())
            .is_err()
    );
    compare(&mut cache, &cmxs[..9], [0, 8].into_iter().collect());
}
/// A publication before the first commitment proves against the empty tree's root
/// with no nodes, and the cache moves into and out of it.
#[test]
fn an_empty_tree_binds_the_empty_root() {
    let mut cache = WitnessCache::default();
    // A fresh build, checked against the independent tree, then a round trip.
    compare(&mut cache, &[], BTreeSet::new());
    let m = manifest(0, 0);
    let empty = WitnessSnapshot::build(&m, &[], &BTreeSet::new()).unwrap();
    let encoded = empty.encode();
    assert_eq!(encoded.len(), 152);
    assert_eq!(
        WitnessSnapshot::decode(&encoded, &m).unwrap().encode(),
        encoded
    );
    // Nonempty, empty and nonempty again through one cache.
    let cmxs = leaves(9);
    compare(&mut cache, &cmxs, [0, 8].into_iter().collect());
    compare(&mut cache, &[], BTreeSet::new());
    compare(&mut cache, &cmxs, [0, 8].into_iter().collect());
    // Zero records in a nonempty tree still bind that tree's root.
    compare(&mut cache, &cmxs, BTreeSet::new());
    let unpaid = cache.build(&manifest(9, 0), &cmxs, &BTreeSet::new());
    assert_ne!(unpaid.unwrap().root(), empty.root());
    // Coverage inconsistent with its commitments is refused, leaving the cache usable.
    let cases: [(Manifest, &[Hash], BTreeSet<u32>); 3] = [
        (manifest(0, 1), &[], [0].into_iter().collect()),
        (manifest(1, 0), &[], BTreeSet::new()),
        (manifest(0, 0), &cmxs[..1], BTreeSet::new()),
    ];
    for (m, cmxs, positions) in cases {
        assert!(cache.build(&m, cmxs, &positions).is_err());
    }
    compare(&mut cache, &[], BTreeSet::new());
}
#[test]
fn positions_must_cover_exactly_the_manifest_records() {
    let cmxs = leaves(17);
    let two: BTreeSet<u32> = [0, 16].into_iter().collect();
    let mut cache = WitnessCache::default();
    compare(&mut cache, &cmxs[..9], [0, 8].into_iter().collect());
    // An omitted position and an extra one, through the cached and fresh entrypoints.
    for (records, positions) in [(3, &two), (1, &two)] {
        assert!(matches!(
            cache.build(&manifest(17, records), &cmxs, positions),
            Err(receiver_directory::Error::Coverage)
        ));
        assert!(matches!(
            WitnessSnapshot::build(&manifest(17, records), &cmxs, positions),
            Err(receiver_directory::Error::Coverage)
        ));
    }
    // The rejections left the primed cache usable.
    compare(&mut cache, &cmxs, two);
}
#[test]
fn shared_path_checks_match_individual_path_calls() {
    use receiver_directory::Error;
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
    let manifest = manifest(cmxs.len(), positions.len());
    let encoded = WitnessSnapshot::build(&manifest, &cmxs, &positions)
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
        let proof = WitnessSnapshot::decode(bytes, &manifest).unwrap();
        for leaves in &cases {
            assert_eq!(
                format!("{:?}", proof.check_paths(leaves.iter().copied())),
                individually(&proof, leaves),
                "{leaves:?}"
            );
        }
    }
    let proof = WitnessSnapshot::decode(&encoded, &manifest).unwrap();
    proof.check_paths(all.clone()).unwrap();
    let proof = WitnessSnapshot::decode(&swapped, &manifest).unwrap();
    assert!(matches!(proof.check_paths(all), Err(Error::Malformed)));
}
