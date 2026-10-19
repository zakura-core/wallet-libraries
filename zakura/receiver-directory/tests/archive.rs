//! Archive validation includes sparse history, immutable pages, fork and correction fences.
use receiver_directory::{
    archive::{
        ConnectedCoverage, Coverage, Head, Index, Page, Proof, SeenRef, INDEX_DEPTH,
        MAX_HEAD_BYTES, MAX_PAGE_BYTES, MAX_RANGE_BYTES,
    },
    blocks::{BlockFilter, BlockId},
    seen::SeenSet,
    Hash,
};
use sha2::{Digest, Sha256};

/// A deterministic block hash independent of index encoding.
fn hash(height: u32) -> Hash {
    Sha256::digest(height.to_le_bytes()).into()
}

/// Builds sparse hints with one receiver at every seventh height.
fn page(first: u32, last: u32) -> Page {
    Page::new(
        hash(first.wrapping_sub(1)),
        (first..=last)
            .map(|height| {
                BlockFilter::build(
                    [1; 32],
                    BlockId {
                        height,
                        hash: hash(height),
                    },
                    if height % 7 == 0 {
                        vec![&[3; 43]]
                    } else {
                        vec![]
                    },
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap()
}

/// Declares a complete range over a supplied index.
fn head(first: u32, last: u32, index: &Index) -> Head {
    Head {
        genesis: [1; 32],
        archive: [9; 32],
        epoch: 3,
        first_height: first,
        frontier: BlockId {
            height: last,
            hash: hash(last),
        },
        index_root: index.root(),
        seen: None,
    }
}

/// Sparse pages explicitly cover empty blocks and share the network and format envelope.
#[test]
fn complete_sparse_ranges_round_trip() {
    let pages = [page(100, 255), page(256, 511), page(512, 519)];
    let mut index = Index::default();
    for page in &pages {
        index
            .update(page.number(), Some(page.digest().unwrap()))
            .unwrap();
    }
    let head = head(100, 519, &index);
    assert_eq!(Head::decode(&head.encode().unwrap()).unwrap(), head);
    head.check_anchor(&[1; 32], head.frontier).unwrap();
    assert!(head.check_anchor(&[2; 32], head.frontier).is_err());
    assert!(head
        .check_anchor(
            &[1; 32],
            BlockId {
                hash: [0; 32],
                ..head.frontier
            }
        )
        .is_err());
    for page in &pages {
        let proof = index.proof(page.number()).unwrap();
        let bytes = proof.encode(page).unwrap();
        assert_eq!(Proof::decode(&head, page.number(), &bytes).unwrap(), *page);
        assert!(Proof::decode(&head, page.number() + 1, &bytes).is_err());
        assert_eq!(
            page.filters().len(),
            if page.number() == 0 {
                156
            } else if page.number() == 1 {
                256
            } else {
                8
            }
        );
        for filter in page.filters() {
            assert_eq!(
                filter.matches(&[[3; 43]])[0],
                filter.block().height % 7 == 0
            );
        }
    }
    assert!(head.page_span(3).is_err());
    assert!(head.page_span(1 << INDEX_DEPTH).is_err());
}

/// Every empty block remains covered without a full block-filter envelope per entry.
#[test]
fn empty_range_is_explicit_and_compact() {
    let filters = (0..256)
        .map(|height| {
            BlockFilter::build(
                [1; 32],
                BlockId {
                    height,
                    hash: hash(height),
                },
                [],
            )
            .unwrap()
        })
        .collect();
    let page = Page::new([0; 32], filters).unwrap();
    let bytes = page.encode().unwrap();
    assert!(bytes.len() < 10_000);
    assert_eq!(Page::decode(&bytes).unwrap(), page);
    let mut index = Index::default();
    index.update(0, Some(page.digest().unwrap())).unwrap();
    let head = head(0, 255, &index);
    assert!(Proof::decode(&head, 0, &[]).is_err());
    assert_eq!(
        Proof::decode(&head, 0, &index.proof(0).unwrap().encode(&page).unwrap())
            .unwrap()
            .filters()
            .len(),
        256
    );
}

/// The tree agrees with a separate recursive oracle, including extreme page positions.
#[test]
fn index_matches_independent_tree_and_removal() {
    /// Recomputes a small sparse tree without using the production index helpers.
    fn subtree(level: u8, position: u32, leaves: &[(u32, Hash)]) -> Hash {
        if level == 0 {
            return match leaves.iter().find(|(p, _)| *p == position) {
                Some((p, digest)) => Sha256::new()
                    .chain_update(b"ironwood-receiver/v1/index-leaf\0")
                    .chain_update(p.to_le_bytes())
                    .chain_update(digest)
                    .finalize()
                    .into(),
                None => Sha256::digest(b"ironwood-receiver/v1/index-empty\0").into(),
            };
        }
        let (left, right) = if leaves.iter().any(|(p, _)| (*p >> level) == position) {
            (
                subtree(level - 1, position * 2, leaves),
                subtree(level - 1, position * 2 + 1, leaves),
            )
        } else {
            let empty = subtree(level - 1, 0, &[]);
            (empty, empty)
        };
        Sha256::new()
            .chain_update(b"ironwood-receiver/v1/index-branch\0")
            .chain_update([level - 1])
            .chain_update(left)
            .chain_update(right)
            .finalize()
            .into()
    }
    let mut index = Index::default();
    let empty = index.root();
    let leaves = [
        (0, [1; 32]),
        (1, [2; 32]),
        (43, [3; 32]),
        ((1 << 24) - 1, [4; 32]),
    ];
    for &(number, digest) in &leaves {
        index.update(number, Some(digest)).unwrap();
    }
    assert_eq!(index.root(), subtree(INDEX_DEPTH as u8, 0, &leaves));
    for &(number, _) in &leaves {
        index.update(number, None).unwrap();
    }
    assert_eq!(index.root(), empty);
    assert!(index.update(1 << 24, Some([1; 32])).is_err());
    assert!(index.proof(1 << 24).is_err());
    let last = page(u32::MAX - 4, u32::MAX);
    index
        .update(last.number(), Some(last.digest().unwrap()))
        .unwrap();
    let head = head(u32::MAX - 4, u32::MAX, &index);
    index
        .proof(last.number())
        .unwrap()
        .verify(&head, &last)
        .unwrap();
}

/// Partial pages, foreign networks, moved leaves and old proofs cannot certify a range.
#[test]
fn gaps_and_replaced_history_are_rejected() {
    let first = page(0, 255);
    let mut index = Index::default();
    index.update(0, Some(first.digest().unwrap())).unwrap();
    let old = head(0, 255, &index);
    let proof = index.proof(0).unwrap();
    for partial in [page(1, 255), page(0, 254)] {
        assert!(proof.verify(&old, &partial).is_err());
    }
    let mut filters = first.filters().to_vec();
    filters[12] = BlockFilter::build(
        [1; 32],
        BlockId {
            height: 12,
            hash: [4; 32],
        },
        [&[8; 43]],
    )
    .unwrap();
    let replacement = Page::new(first.parent(), filters).unwrap();
    assert!(proof.verify(&old, &replacement).is_err());
    index
        .update(0, Some(replacement.digest().unwrap()))
        .unwrap();
    let corrected = Head {
        epoch: old.epoch + 1,
        index_root: index.root(),
        ..old.clone()
    };
    assert!(proof.verify(&corrected, &first).is_err());
    index
        .proof(0)
        .unwrap()
        .verify(&corrected, &replacement)
        .unwrap();
    let foreign = Head {
        genesis: [5; 32],
        ..old.clone()
    };
    assert!(proof.verify(&foreign, &first).is_err());
    let mut corrupt = proof.clone();
    corrupt.0[12][0] ^= 1;
    assert!(corrupt.verify(&old, &first).is_err());
    assert!(Page::new([0; 32], vec![]).is_err());
    assert!(Page::new(
        [0; 32],
        vec![first.filters()[0].clone(), first.filters()[2].clone()]
    )
    .is_err());
    assert!(Page::new(
        [0; 32],
        vec![
            first.filters()[255].clone(),
            page(256, 256).filters()[0].clone()
        ]
    )
    .is_err());
}

/// All truncations and surplus bytes are rejected, with bounds checked before parsing.
#[test]
fn malformed_archive_bytes_never_become_empty_coverage() {
    let page = page(0, 1);
    let mut index = Index::default();
    index.update(0, Some(page.digest().unwrap())).unwrap();
    let head = head(0, 1, &index);
    let bytes = index.proof(0).unwrap().encode(&page).unwrap();
    for end in 0..bytes.len() {
        assert!(Proof::decode(&head, 0, &bytes[..end]).is_err());
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(Proof::decode(&head, 0, &extra).is_err());
    let bytes = head.encode().unwrap();
    for end in 0..bytes.len() {
        assert!(Head::decode(&bytes[..end]).is_err());
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(Head::decode(&extra).is_err());
    assert!(Head::decode(&vec![0; MAX_HEAD_BYTES + 1]).is_err());
    assert!(Page::decode(&vec![0; MAX_PAGE_BYTES + 1]).is_err());
    assert!(Proof::decode(&head, 0, &vec![0; MAX_RANGE_BYTES + 1]).is_err());
    assert!(Head {
        archive: [0; 32],
        ..head.clone()
    }
    .encode()
    .is_err());
    assert!(Head {
        first_height: 2,
        ..head
    }
    .encode()
    .is_err());
}

/// A new target cannot be completed by an older epoch, shorter span or forked session.
#[test]
fn pir_completion_requires_epoch_and_connected_chain() {
    let head = head(100, 500, &Index::default());
    let coverage = Coverage {
        genesis: head.genesis,
        archive: head.archive,
        epoch: head.epoch,
        session: [6; 32],
        first_height: 100,
        frontier: BlockId {
            height: 510,
            hash: hash(510),
        },
    };
    let chain = ConnectedCoverage {
        genesis: head.genesis,
        target: head.frontier,
        publication: coverage.frontier,
    };
    coverage.check(&head, chain).unwrap();
    let bytes = coverage.encode().unwrap();
    assert_eq!(Coverage::decode(&bytes).unwrap(), coverage);
    for end in 0..bytes.len() {
        assert!(Coverage::decode(&bytes[..end]).is_err());
    }
    for wrong in [
        Coverage {
            epoch: 2,
            ..coverage.clone()
        },
        Coverage {
            archive: [2; 32],
            ..coverage.clone()
        },
        Coverage {
            genesis: [2; 32],
            ..coverage.clone()
        },
        Coverage {
            first_height: 101,
            ..coverage.clone()
        },
        Coverage {
            frontier: BlockId {
                height: 499,
                hash: hash(499),
            },
            ..coverage.clone()
        },
        Coverage {
            frontier: BlockId {
                hash: [4; 32],
                ..coverage.frontier
            },
            ..coverage.clone()
        },
    ] {
        assert!(wrong.check(&head, chain).is_err());
    }
    let fork = Head {
        frontier: BlockId {
            hash: [7; 32],
            ..head.frontier
        },
        ..head.clone()
    };
    assert!(coverage.check(&fork, chain).is_err());
    assert!(coverage.check(&Head { epoch: 4, ..fork }, chain).is_err());
}

/// Seen completeness is separate from payment history and bound to exact object bytes.
#[test]
fn seen_reference_binds_coverage_and_network() {
    let mut set = SeenSet::new([1; 32], 100).union([&[3; 43]]);
    set.until_unix = 200;
    let reference = SeenRef {
        digest: set.digest().unwrap(),
        since_unix: 100,
        until_unix: 200,
    };
    reference.check(&[1; 32], &set).unwrap();
    assert!(reference.check(&[2; 32], &set).is_err());
    set.until_unix = 201;
    assert!(reference.check(&[1; 32], &set).is_err());
    let head = Head {
        seen: Some(reference),
        ..head(0, 1, &Index::default())
    };
    assert_eq!(Head::decode(&head.encode().unwrap()).unwrap(), head);
    let invalid = Head {
        seen: Some(SeenRef {
            digest: [0; 32],
            since_unix: 2,
            until_unix: 1,
        }),
        ..head
    };
    assert!(invalid.encode().is_err());
}
