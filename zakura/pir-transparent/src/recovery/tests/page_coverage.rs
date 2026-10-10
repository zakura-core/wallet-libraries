use super::*;

#[test]
fn spans_needs_contiguous_coverage_of_the_address() {
    let (ours, theirs) = (
        TransparentAddress::PublicKeyHash([7; 20]),
        TransparentAddress::PublicKeyHash([8; 20]),
    );
    let range = |address, from: u64, through: u64| AddressRange {
        address,
        from: block(from).unwrap(),
        through: block(through).unwrap(),
    };
    let covers = |ranges: &[AddressRange], from, through| {
        spans(ranges, ours, block(from).unwrap(), block(through).unwrap())
    };
    // Adjacent ranges, in any order, cover their union.
    let adjacent = [range(ours, 20, 29), range(ours, 10, 19)];
    assert!(covers(&adjacent, 12, 25));
    assert!(covers(&adjacent, 10, 29));
    assert!(!covers(&adjacent, 9, 25));
    assert!(!covers(&adjacent, 12, 30));
    // A one-block gap, or another address's range filling it, does not.
    let gap = [
        range(ours, 10, 19),
        range(theirs, 20, 20),
        range(ours, 21, 29),
    ];
    assert!(!covers(&gap, 12, 25));
    assert!(covers(&gap, 21, 25));
    assert!(!covers(&[], 12, 12));
}

#[test]
fn page_continuation_identity_binds_revision_script_shard_and_first_row() {
    let first = page_id(0, "aa", &[1], 2);
    for other in [
        page_id(1, "aa", &[1], 2),
        page_id(0, "bb", &[1], 2),
        page_id(0, "aa", &[2], 2),
        page_id(0, "aa", &[1], 3),
    ] {
        assert_ne!(first, other);
    }
}
