use super::*;

#[test]
fn only_declarations_at_or_above_the_floor_count_against_the_shard_limit() {
    let (_, after) = recut_pair();
    let declared = after.recuts[0].superseded.len();
    assert_eq!(entries(&after, 0), after.shards.len() + declared);
    // A floor above S1 and S2 leaves S3 and the tail.
    let floor = after.recuts[0].superseded[2].start_height;
    assert_eq!(entries(&after, floor), after.shards.len() + 2);
    assert_eq!(entries(&after, u64::MAX), after.shards.len());
}

/// The pairwise scan the indexed declaration check replaced, kept as its
/// oracle.
fn pairwise_conflict(
    published: &[Published],
    declarations: &[Published],
) -> Option<WithdrawnCause> {
    for (index, declared) in declarations.iter().enumerate() {
        let ours = &declared.revision;
        for entry in published {
            let theirs = &entry.revision;
            if theirs.source != ours.source {
                continue;
            }
            if theirs.lineage == ours.lineage {
                return Some(WithdrawnCause::Equivocation);
            } else if theirs.lineage < ours.lineage {
                return Some(WithdrawnCause::Regression);
            }
        }
        if declarations[index + 1..].iter().any(|other| {
            other.revision.source == ours.source
                && other.revision.lineage == ours.lineage
                && other.revision != *ours
        }) {
            return Some(WithdrawnCause::Equivocation);
        }
    }
    None
}

#[test]
fn the_declaration_check_finds_what_a_pairwise_scan_finds() {
    // A fixed xorshift sequence over few sources, lineages and contents,
    // so revisions collide often, published ones included.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = |bound: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % bound
    };
    let mut revision = || Published {
        shard_id: 0,
        start_height: 0,
        end_height: 0,
        digest: String::new(),
        terminal: String::new(),
        revision: RecoveryRevision {
            source: vec![next(4) as u8],
            revision: vec![next(3) as u8],
            lineage: 1 + next(4),
            sealed: next(2) == 0,
            publication: PublicationAnchor {
                height: BlockHeight::from(0),
                hash: BlockHash([0; 32]),
            },
        },
    };
    let mut seen = [0usize; 3];
    for case in 0..20_000 {
        let published: Vec<_> = (0..case % 4).map(|_| revision()).collect();
        let declarations: Vec<_> = (0..case % 9).map(|_| revision()).collect();
        let cause = catalog::declaration_conflict(&published, &declarations);
        assert_eq!(
            cause,
            pairwise_conflict(&published, &declarations),
            "case {case}"
        );
        seen[match cause {
            None => 0,
            Some(WithdrawnCause::Equivocation) => 1,
            _ => 2,
        }] += 1;
    }
    assert!(seen.iter().all(|count| *count > 1_000), "{seen:?}");
}

#[test]
fn a_full_declaration_set_is_checked_quickly() {
    let map = forged(MAX_SUPERSEDED);
    map.check_shape().unwrap();
    let (binding, set) = ([7; 32], SetIdentity::of_schema(&map, SCHEMA));
    let published: Vec<_> = map
        .shards
        .iter()
        .map(|entry| Published::of(&binding, &set, entry).unwrap())
        .collect();
    let declarations: Vec<_> = map
        .recuts
        .iter()
        .flat_map(|recut| &recut.superseded)
        .map(|shard| Published::declared(&binding, &set, shard).unwrap())
        .collect();
    assert_eq!(declarations.len(), MAX_SUPERSEDED);
    // A pairwise scan of this many takes seconds; the indexed check, a few
    // milliseconds. Each contradiction involves the last declaration, so
    // nothing short of indexing every one finds it.
    let check = |declarations: &[Published]| {
        let started = std::time::Instant::now();
        let cause = catalog::declaration_conflict(&published, declarations);
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        cause
    };
    assert_eq!(check(&declarations), None);
    let last = declarations.len() - 1;
    // The superseded tail T at T′'s lineage, then above it.
    let tail = published.last().unwrap().revision.lineage;
    let mut level = declarations.clone();
    level[last].revision.lineage = tail;
    assert_eq!(check(&level), Some(WithdrawnCause::Equivocation));
    let mut above = declarations.clone();
    above[last].revision.lineage = tail + 1;
    assert_eq!(check(&above), Some(WithdrawnCause::Regression));
    // The first forged revision declared again, last, with other content.
    let mut again = declarations.clone();
    again[last] = declarations[0].clone();
    again[last].revision.revision = vec![0xee; 32];
    assert_eq!(check(&again), Some(WithdrawnCause::Equivocation));
}

#[test]
fn declarations_below_the_floor_count_against_a_separate_limit() {
    let (before, after) = recut_pair();
    let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
    let floor = required_floor(&watch, u64::MAX);
    let at_limit = forged(MAX_SUPERSEDED);
    at_limit.check_shape().unwrap();
    let over = forged(MAX_SUPERSEDED + 1);
    // None of the forged declarations reaches the floor, so the shard
    // limit alone would admit any number of them.
    assert_eq!(entries(&over, floor), entries(&after, floor));
    let dir = tempfile::tempdir().unwrap();
    let mut adapter =
        ReferenceRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
    adapter.check_limits(&at_limit, floor).unwrap();
    let mut filters = CountingFilters::serving(serde_json::to_vec(&over).unwrap());
    let mut shards = CountingShards::serving(SCHEMA);
    assert!(matches!(
        adapter.recover(&watch, &chain, &mut filters, &mut shards),
        Err(RecoveryError::Invalid(message))
            if message == "publication declaration limit exceeded"
    ));
    assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 0));
    assert!(adapter.store.set_identity().unwrap().is_none());

    // At the limit, a pass exports what it would without the forged
    // re-cut, and quickly.
    let (mut plain, _) = recut_companion(&dir.path().join("plain.sqlite"), &before, &after);
    let expected = recut_pass(&mut plain, &watch, &after, &chain);
    let (mut adapter, _) = recut_companion(&dir.path().join("forged.sqlite"), &before, &at_limit);
    let started = std::time::Instant::now();
    let batch = recut_pass(&mut adapter, &watch, &at_limit, &chain);
    let elapsed = started.elapsed();
    assert_eq!(batch.state, BatchState::Ready);
    assert_eq!(batch.commits, expected.commits);
    assert_eq!(batch.replaced, expected.replaced);
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
}
