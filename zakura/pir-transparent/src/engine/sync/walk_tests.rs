use super::shard::entry_in;
use super::walk::{check_head, check_run};
use super::*;
use crate::engine::store::RunCursor;
use transparent_events::TransparentEvent;
use transparent_events::{ReceiveEvent, SpendEvent, Txid};
use transparent_filter::ShardMapEntry;
use transparent_shard::build::candidate_rows;
use transparent_shard::build::{Block, Built, BuiltChild, BuiltDirectory, ShardStream};
use transparent_shard::layout::DECOUPLED_2K_8K;
use transparent_shard::manifest::{
    ManifestLayout, ManifestOccupancy, ManifestSeal, PageChildOccupancy, TableGeometry,
};
use transparent_shard::manifest::{PageChild, ShardManifest};
use transparent_shard::page_row::PageEntry;
use transparent_shard::page_row::RunLink;
use transparent_shard::records::DirectoryEntry;
use transparent_shard::seal::{DecoupledPolicy, Limit};

fn hash_at(height: u64) -> BlockHash {
    let mut bytes = [3u8; 32];
    bytes[..8].copy_from_slice(&height.to_le_bytes());
    BlockHash::from_internal_bytes(bytes)
}

fn script(tag: u32) -> Vec<u8> {
    let mut bytes = vec![0x76, 0xa9, 0x14];
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 16]);
    bytes.extend_from_slice(&[0x88, 0xac]);
    bytes
}

fn receive(height: u32, nonce: u32) -> TransparentEvent {
    let mut txid = [0u8; 32];
    txid[..4].copy_from_slice(&nonce.to_le_bytes());
    txid[4..8].copy_from_slice(&height.to_le_bytes());
    TransparentEvent::Receive(ReceiveEvent {
        metadata: None,
        height,
        txid: Txid(txid),
        transaction_index: 0,
        output_index: nonce,
        value: 1_000,
        coinbase: false,
    })
}

fn spend(height: u32, nonce: u32) -> TransparentEvent {
    let mut txid = [0u8; 32];
    txid[..4].copy_from_slice(&nonce.to_le_bytes());
    txid[4..8].copy_from_slice(&height.to_le_bytes());
    TransparentEvent::Spend(SpendEvent {
        metadata: None,
        height,
        spending_txid: Txid(txid),
        transaction_index: 1,
        input_index: nonce,
        spent_txid: Txid([7; 32]),
        spent_output_index: nonce,
    })
}

/// `count` blocks from `first`: four busy scripts, which build long
/// chains, and many quiet ones whose pushed-out events close page shards.
fn chain(first: u64, count: u64) -> Vec<Block> {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move |bound: u64| {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (z ^ (z >> 31)) % bound
    };
    let mut nonce = 0u32;
    (first..first + count)
        .map(|height| {
            let mut events = Vec::new();
            for _ in 0..1 + next(5) {
                let tag = if next(2) == 0 {
                    next(4) as u32
                } else {
                    100 + next(60) as u32
                };
                nonce += 1;
                let at = height as u32;
                let event = if next(3) == 0 {
                    spend(at, nonce)
                } else {
                    receive(at, nonce)
                };
                events.push((ScriptBytes::new(script(tag)), event));
            }
            (height, events)
        })
        .collect()
}

/// The chain every walk test reads: busy and quiet scripts, then two
/// blocks in which only the busiest script is active, so the open page
/// shard of the tail holds a run of a script with older runs.
fn blocks() -> Vec<Block> {
    let mut blocks = chain(1_000, 80);
    let last = blocks.last().unwrap().0;
    for (offset, nonce) in [(1u64, 900_001u32), (2, 900_002)] {
        let height = last + offset;
        blocks.push((
            height,
            vec![(ScriptBytes::new(script(0)), receive(height as u32, nonce))],
        ));
    }
    blocks
}

struct Directory {
    built: BuiltDirectory,
    children: Vec<BuiltChild>,
    manifest: std::sync::OnceLock<ShardManifest>,
}

/// [`blocks`] and what they build, once per test binary: building is
/// the slow part of every walk test.
fn fixture() -> &'static (Vec<Block>, Vec<Directory>) {
    static FIXTURE: std::sync::OnceLock<(Vec<Block>, Vec<Directory>)> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        let blocks = blocks();
        let directories = build(&blocks);
        (blocks, directories)
    })
}

/// Directory shards over `blocks` under a policy that closes a page shard
/// at two rows and a directory shard at 32 page shards. The last is a
/// tail whose last page shard is open.
fn build(blocks: &[Block]) -> Vec<Directory> {
    let policy = DecoupledPolicy {
        scripts: Limit::new(10_000, 20_000).unwrap(),
        directory_bytes: Limit::new(1_000_000, 2_000_000).unwrap(),
        page_rows: Limit::new(2, 4).unwrap(),
        max_children: 32,
        ..DecoupledPolicy::for_geometry(&DECOUPLED_2K_8K)
    };
    let genesis = BlockHash::from_display_hex(transparent_filter::MAINNET_GENESIS_DISPLAY).unwrap();
    let mut stream = ShardStream::with_policy(
        &DECOUPLED_2K_8K,
        policy,
        blocks[0].0,
        0,
        genesis,
        transparent_filter::RANGE_PROFILE,
    )
    .unwrap();
    let terminal = |height: u64| Some(hash_at(height));
    let mut out = Vec::new();
    for block in blocks {
        out.extend(stream.push_block(block.clone(), &terminal).unwrap());
    }
    out.extend(stream.finish(&terminal).unwrap());
    let mut directories = Vec::new();
    let mut children = Vec::new();
    for built in out {
        match built {
            Built::Child(child) => children.push(child),
            Built::Directory { built, .. } => directories.push(Directory {
                built,
                children: std::mem::take(&mut children),
                manifest: std::sync::OnceLock::new(),
            }),
        }
    }
    directories
}

fn manifest_of(directory: &Directory) -> ShardManifest {
    // These tables never change. Rehashing every child for each walk or
    // candidate script hid the behavior under test behind gigabytes of I/O.
    // Return an owned copy so malformed-manifest cases cannot alter a fixture.
    directory
        .manifest
        .get_or_init(|| build_manifest(directory))
        .clone()
}

fn build_manifest(directory: &Directory) -> ShardManifest {
    let built = &directory.built;
    let geometry = built.geometry;
    let page_children: Vec<PageChild> = directory
        .children
        .iter()
        .map(|child| PageChild {
            index: child.index,
            start_height: child.start_height,
            end_height: child.end_height,
            terminal_block_hash: child.terminal_block_hash.to_display_hex(),
            tag_salt_counter: child.tag_salt_counter,
            sealed: child.sealed,
            page_segments: child
                .segment_digests(geometry)
                .iter()
                .map(|digest| TableGeometry {
                    rows: geometry.page_rows,
                    row_bytes: geometry.page_row_bytes as u32,
                    sha256: hex::encode(digest),
                })
                .collect(),
            occupancy: PageChildOccupancy {
                page_rows: child.page_rows,
                fragments: child.fragments,
                runs: child.runs,
                events: child.events,
            },
        })
        .collect();
    ShardManifest {
        schema: transparent_shard::SCHEMA.to_string(),
        profile: transparent_filter::RANGE_PROFILE.to_string(),
        geometry: geometry.name.to_string(),
        network: "main".into(),
        genesis_hash: transparent_filter::MAINNET_GENESIS_DISPLAY.into(),
        shard_id: built.shard_id,
        start_height: built.start_height,
        end_height: built.end_height,
        parent_block_hash: hash_at(built.start_height - 1).to_display_hex(),
        terminal_block_hash: hash_at(built.end_height).to_display_hex(),
        tag_salt_counter: built.tag_salt_counter,
        parent_manifest_digest: String::new(),
        sealed: built.sealed,
        revision: 0,
        supersedes: String::new(),
        seal: ManifestSeal {
            scripts_target: 10_000,
            scripts_capacity: 20_000,
            directory_bytes_target: 1_000_000,
            directory_bytes_capacity: 2_000_000,
            page_rows_target: 2,
            page_rows_capacity: 4,
            max_page_children: 32,
        },
        layout: ManifestLayout::current(),
        filter_hash: "00".repeat(32),
        directory_segments: vec![TableGeometry {
            rows: geometry.directory_rows,
            row_bytes: geometry.directory_row_bytes as u32,
            sha256: "00".repeat(32),
        }],
        occupancy: ManifestOccupancy {
            scripts: built.scripts,
            page_rows: page_children.iter().map(|c| c.occupancy.page_rows).sum(),
            fragments: page_children.iter().map(|c| c.occupancy.fragments).sum(),
            events: built.events,
            blocks: built.end_height - built.start_height + 1,
            txids: built.txids,
            excluded_scripts: built.excluded_scripts,
        },
        page_children,
        directory_choice: None,
    }
}

fn entry_of(manifest: &ShardManifest) -> ShardMapEntry {
    ShardMapEntry {
        shard_id: manifest.shard_id,
        geometry: manifest.geometry.clone(),
        start_height: manifest.start_height,
        end_height: manifest.end_height,
        parent_block_hash: manifest.parent_block_hash.clone(),
        terminal_block_hash: manifest.terminal_block_hash.clone(),
        filter_hash: manifest.filter_hash.clone(),
        scripts: manifest.occupancy.scripts,
        page_rows: manifest.occupancy.page_rows,
        txids: 0,
        directory_segments: 1,
        page_segments: manifest.page_children.len() as u32,
        manifest_digest: manifest.digest(),
        revision: 0,
        sealed: manifest.sealed,
    }
}

fn target_of(manifest: &ShardManifest) -> Anchor {
    Anchor {
        height: manifest.end_height,
        hash: manifest.terminal_block_hash.clone(),
    }
}

/// The directory entry for `script`, read straight from the table.
fn directory_entry(directory: &Directory, script: &[u8]) -> Option<DirectoryEntry> {
    let built = &directory.built;
    let salt = transparent_shard::tag_salt(
        built.shard_id,
        &hash_at(built.end_height),
        built.tag_salt_counter,
    );
    let wanted = transparent_shard::script_tag(&salt, script);
    let rows = built.geometry.directory_rows;
    candidate_rows(built.shard_id, script, rows)
        .into_iter()
        .flat_map(|row| {
            transparent_shard::records::decode_directory_row(
                built.directory_row(row),
                built.children,
            )
            .unwrap()
        })
        .find(|entry| entry.tag == wanted)
}

/// Every event `script` has in `directory`'s range, oldest first.
fn history(blocks: &[Block], directory: &Directory, script: &[u8]) -> Vec<TransparentEvent> {
    let range = directory.built.start_height..=directory.built.end_height;
    let mut events: Vec<TransparentEvent> = blocks
        .iter()
        .filter(|(height, _)| range.contains(height))
        .flat_map(|(_, events)| events.iter())
        .filter(|(owner, _)| owner.as_slice() == script)
        .map(|(_, event)| *event)
        .collect();
    events.sort_by_key(TransparentEvent::sort_key);
    events
}

/// Page rows read straight from the built tables, recording every
/// request and round. Rows in `corrupt` reply with bytes that do not
/// decode; rows in `rewritten` reply with the segments given, which do.
/// Round `overloaded`, counted from zero, is refused as an overloaded
/// service refuses it.
struct Direct<'a> {
    children: &'a [BuiltChild],
    requests: Vec<RowRequest>,
    rounds: usize,
    /// Requests per round, in order.
    round_sizes: Vec<usize>,
    corrupt: std::collections::BTreeSet<(u32, u64)>,
    rewritten: BTreeMap<(u32, u64), Vec<Vec<u8>>>,
    overloaded: Option<usize>,
}

impl<'a> Direct<'a> {
    fn new(directory: &'a Directory) -> Self {
        Self {
            children: &directory.children,
            requests: Vec::new(),
            rounds: 0,
            round_sizes: Vec::new(),
            corrupt: Default::default(),
            rewritten: BTreeMap::new(),
            overloaded: None,
        }
    }

    /// The requests of round `round`, counted from zero.
    fn round(&self, round: usize) -> &[RowRequest] {
        let start: usize = self.round_sizes[..round].iter().sum();
        &self.requests[start..start + self.round_sizes[round]]
    }
}

impl RowSource for Direct<'_> {
    fn stopped(&self) -> Option<IncompleteReason> {
        None
    }

    fn fetch<S: WalletStore>(
        &mut self,
        _: &mut S,
        requests: &[RowRequest],
    ) -> Result<Vec<Reply>, SyncError> {
        if self.overloaded == Some(self.rounds) {
            self.overloaded = None;
            return Err(SyncError::Client(ClientError::Overloaded(
                crate::engine::transport::Overloaded { retry_after: None },
            )));
        }
        self.rounds += 1;
        self.round_sizes.push(requests.len());
        self.requests.extend_from_slice(requests);
        Ok(requests
            .iter()
            .map(|request| {
                let key = (request.child, request.row);
                let mut row = self.children[request.child as usize]
                    .page_row(&DECOUPLED_2K_8K, request.row)
                    .to_vec();
                if self.corrupt.contains(&key) {
                    row.iter_mut().for_each(|byte| *byte ^= 0xa5);
                }
                self.rewritten.get(&key).cloned().unwrap_or(vec![row])
            })
            .collect())
    }
}

/// The directory phase, without the directory query: the entry's inline
/// events committed and its walk recorded, as `retrieve_shard_into`
/// leaves them. Returns the walks owed.
fn directory_phase(
    store: &mut MemoryStore,
    directory: &Directory,
    manifest: &ShardManifest,
    scripts: &[Vec<u8>],
) -> Vec<PendingPages> {
    let entry = entry_of(manifest);
    let mut commit = ShardCommit {
        shard_id: entry.shard_id,
        revision_digest: entry.manifest_digest.clone(),
        sealed: entry.sealed,
        start_height: entry.start_height,
        end_height: entry.end_height,
        terminal_block_hash: entry.terminal_block_hash.clone(),
        ..Default::default()
    };
    for script in scripts {
        let found = directory_entry(directory, script).expect("an entry");
        let (child, row) = found.head().expect("a paged script");
        commit
            .events
            .extend(found.inline.iter().map(|event| StoredEvent {
                script: script.clone(),
                event: *event,
                shard_id: entry.shard_id,
                revision_digest: entry.manifest_digest.clone(),
            }));
        commit.pending_upsert.push(PendingPages {
            id: None,
            shard_id: entry.shard_id,
            revision_digest: entry.manifest_digest.clone(),
            script: script.clone(),
            cursor: RunCursor {
                child,
                row,
                older_runs: None,
            },
            fragments: Vec::new(),
            carried: found.inline.clone(),
            attempts: 0,
            target_anchor: Some(target_of(manifest)),
        });
    }
    let before: Vec<u64> = store
        .pending()
        .unwrap()
        .iter()
        .filter_map(|p| p.id)
        .collect();
    commit_bounded(store, &target_of(manifest), commit).unwrap();
    store
        .pending()
        .unwrap()
        .into_iter()
        .filter(|p| p.id.is_some_and(|id| !before.contains(&id)))
        .collect()
}

fn walk(
    store: &mut MemoryStore,
    manifest: &ShardManifest,
    owed: &[PendingPages],
    rows: &mut Direct<'_>,
) -> Result<Option<Completion>, SyncError> {
    let mut failures = Failures::default();
    let walked = walk_chains(
        store,
        &entry_of(manifest),
        manifest,
        owed,
        rows,
        &target_of(manifest),
        &mut failures,
    );
    assert!(
        failures.entries.is_empty(),
        "an honest walk fails nothing: {:?}",
        failures.entries
    );
    walked
}

/// [`walk`] where entries may fail: the entries that did.
fn walk_failing(
    store: &mut MemoryStore,
    manifest: &ShardManifest,
    owed: &[PendingPages],
    rows: &mut Direct<'_>,
) -> Vec<FailedEntry> {
    let mut failures = Failures::default();
    assert_eq!(
        walk_chains(
            store,
            &entry_of(manifest),
            manifest,
            owed,
            rows,
            &target_of(manifest),
            &mut failures,
        )
        .unwrap(),
        None
    );
    assert!(failures.owed.is_empty(), "every owed dummy was sent");
    failures.entries
}

fn stored(store: &MemoryStore, script: &[u8]) -> Vec<TransparentEvent> {
    store
        .events()
        .unwrap()
        .into_iter()
        .filter(|stored| stored.script == script)
        .map(|stored| stored.event)
        .collect()
}

/// The runs a script's chain has, newest first, read straight from the
/// tables: page shard and first row.
fn runs_of(directory: &Directory, script: &[u8]) -> Vec<(u8, u32)> {
    let manifest = manifest_of(directory);
    let mut runs = Vec::new();
    let mut next = directory_entry(directory, script).and_then(|e| e.head());
    while let Some((child, row)) = next {
        runs.push((child, row));
        let page = &manifest.page_children[child as usize];
        let salt = transparent_shard::page_tag_salt(
            manifest.shard_id,
            page.index,
            page.end_height,
            &BlockHash::from_display_hex(&page.terminal_block_hash).unwrap(),
            page.tag_salt_counter,
        );
        let tag = transparent_shard::script_tag(&salt, script);
        next = transparent_shard::decode_page_row(
            directory.children[child as usize].page_row(&DECOUPLED_2K_8K, u64::from(row)),
        )
        .unwrap()
        .into_iter()
        .find(|e| e.tag == tag && e.ordinal == 0)
        .unwrap()
        .link
        .previous();
    }
    runs
}

/// Paged scripts of `directory`, busiest chains first.
fn paged(directory: &Directory) -> Vec<Vec<u8>> {
    let mut paged: Vec<(usize, Vec<u8>)> = (0..4)
        .chain(100..160)
        .map(script)
        .map(|script| (runs_of(directory, &script).len(), script))
        .filter(|(runs, _)| *runs > 0)
        .collect();
    paged.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    paged.into_iter().map(|(_, script)| script).collect()
}

/// Every paged script's history comes back exactly, all walks sharing
/// rounds, in one round per run plus one; and the run cache is filled
/// for every run in a sealed page shard with that run's own events and
/// the run below it, which together rebuild the history back to the
/// directory shard's start.
#[test]
fn walking_every_chain_recovers_each_history_in_one_round_per_run() {
    let (blocks, directories) = fixture();
    let directory = &directories[0];
    let manifest = manifest_of(directory);
    manifest
        .check_children(DECOUPLED_2K_8K.page_rows, 4_096)
        .unwrap();
    let scripts = paged(directory);
    let longest = runs_of(directory, &scripts[0]).len();
    assert!(longest >= 3, "a chain long enough to walk: {longest}");

    let mut store = MemoryStore::new();
    let owed = directory_phase(&mut store, directory, &manifest, &scripts);
    let mut rows = Direct::new(directory);
    assert_eq!(walk(&mut store, &manifest, &owed, &mut rows).unwrap(), None);
    assert_eq!(rows.rounds, longest + 1);
    assert!(store.pending().unwrap().is_empty());
    let identities: Vec<String> = manifest.child_digests().iter().map(hex::encode).collect();
    for script in &scripts {
        let expected = history(blocks, directory, script);
        assert_eq!(stored(&store, script), expected);
        assert_eq!(store.coverage(script).unwrap().len(), 1);
        // Oldest run first: each cached run holds its own events and
        // names the run below it, and together they rebuild the history.
        let runs = runs_of(directory, script);
        let mut rebuilt = Vec::new();
        for (index, (child, _)) in runs.iter().enumerate().rev() {
            let cached = store
                .cached_run(&identities[usize::from(*child)], script)
                .unwrap();
            if manifest.page_children[usize::from(*child)].sealed {
                let cached = cached.expect("a sealed run is cached");
                assert_eq!(cached.shard_id, manifest.shard_id);
                assert_eq!(
                    cached.older,
                    runs.get(index + 1)
                        .map(|(older, _)| identities[usize::from(*older)].clone())
                );
                rebuilt.extend(cached.events);
                assert_eq!(rebuilt[..], expected[..rebuilt.len()]);
            } else {
                assert_eq!(cached, None);
            }
        }
    }
}

/// Tip catch-up: a walk whose newest run is in the open page shard reads
/// that run and stops at the cached run it links to; one whose newest run
/// is in a sealed page shard reads nothing at all.
#[test]
fn a_cached_run_stops_the_walk() {
    let (blocks, directories) = fixture();
    let tail = directories.last().unwrap();
    let manifest = manifest_of(tail);
    assert!(!manifest.sealed);
    let open = manifest.page_children.len() as u8 - 1;
    assert!(!manifest.page_children[open as usize].sealed);
    let scripts = paged(tail);
    let at_tip: Vec<Vec<u8>> = scripts
        .iter()
        .filter(|s| {
            let runs = runs_of(tail, s);
            runs.len() >= 2 && runs[0].0 == open
        })
        .cloned()
        .collect();
    let sealed_head: Vec<Vec<u8>> = scripts
        .iter()
        .filter(|s| runs_of(tail, s)[0].0 != open)
        .cloned()
        .collect();
    assert!(!at_tip.is_empty() && !sealed_head.is_empty());

    let mut store = MemoryStore::new();
    let owed = directory_phase(&mut store, tail, &manifest, &scripts);
    let mut first = Direct::new(tail);
    walk(&mut store, &manifest, &owed, &mut first).unwrap();

    // The same revision walked again from its directory entries.
    let owed = directory_phase(&mut store, tail, &manifest, &scripts);
    let mut again = Direct::new(tail);
    assert_eq!(
        walk(&mut store, &manifest, &owed, &mut again).unwrap(),
        None
    );
    assert!(
        again
            .requests
            .iter()
            .all(|request| request.child == u32::from(open))
    );
    // Every script whose newest run is in the open page shard reads that
    // run again, and nothing older.
    let head_fragments: usize = scripts
        .iter()
        .filter(|script| runs_of(tail, script)[0].0 == open)
        .map(|script| {
            let (child, row) = runs_of(tail, script)[0];
            let salt = transparent_shard::page_tag_salt(
                manifest.shard_id,
                u32::from(child),
                manifest.page_children[usize::from(child)].end_height,
                &hash_at(manifest.page_children[usize::from(child)].end_height),
                manifest.page_children[usize::from(child)].tag_salt_counter,
            );
            let tag = transparent_shard::script_tag(&salt, script);
            transparent_shard::decode_page_row(
                tail.children[usize::from(child)].page_row(&DECOUPLED_2K_8K, u64::from(row)),
            )
            .unwrap()
            .into_iter()
            .find(|e| e.tag == tag)
            .unwrap()
            .fragment_count as usize
        })
        .sum();
    assert_eq!(again.requests.len(), head_fragments);
    assert_eq!(again.rounds, 2, "the head run, then its rest");
    for script in &scripts {
        assert_eq!(stored(&store, script), history(blocks, tail, script));
    }

    // A head in a sealed page shard that is cached costs no page query.
    let mut fresh = MemoryStore::new();
    let owed = directory_phase(&mut fresh, tail, &manifest, &sealed_head);
    walk(&mut fresh, &manifest, &owed, &mut Direct::new(tail)).unwrap();
    let owed = directory_phase(&mut fresh, tail, &manifest, &sealed_head);
    let mut cached = Direct::new(tail);
    walk(&mut fresh, &manifest, &owed, &mut cached).unwrap();
    assert_eq!((cached.rounds, cached.requests.len()), (0, 0));
    assert!(fresh.pending().unwrap().is_empty());
}

/// A walk over a manifest that places a page shard's range elsewhere
/// finds the events of its runs pushed out while it was not open, and
/// refuses them: a content failure of the entry, counted, with the walk
/// still owed for a later sync.
#[test]
fn a_run_in_the_wrong_page_shard_is_refused() {
    let (_, directories) = fixture();
    let directory = &directories[0];
    let mut manifest = manifest_of(directory);
    let script = paged(directory).remove(0);
    let runs = runs_of(directory, &script);
    let (child, _) = runs[runs.len() - 1];
    // The oldest run's page shard, claimed to open only after its last
    // block: nothing could have been pushed into it. Its end, which its
    // tag salt is keyed on, stays.
    let page = &mut manifest.page_children[usize::from(child)];
    page.start_height = page.end_height + 1;
    let mut store = MemoryStore::new();
    let owed = directory_phase(
        &mut store,
        directory,
        &manifest,
        std::slice::from_ref(&script),
    );
    let failed = walk_failing(&mut store, &manifest, &owed, &mut Direct::new(directory));
    assert_eq!(
        failed,
        vec![FailedEntry {
            shard_id: manifest.shard_id,
            script: script.clone(),
            failures: 1,
        }]
    );
    assert_eq!(store.entry_failures(manifest.shard_id, &script).unwrap(), 1);
    assert_eq!(store.pending().unwrap().len(), 1, "the walk stays owed");
    assert_eq!(store.coverage(&script).unwrap(), vec![]);
    // Refused again, and counted again, on the next attempt.
    let owed = store.pending().unwrap();
    let failed = walk_failing(&mut store, &manifest, &owed, &mut Direct::new(directory));
    assert_eq!(failed[0].failures, 2);
}

/// The first fragment of `script`'s run at `(child, row)`, read straight
/// from the table.
fn run_head(directory: &Directory, script: &[u8], (child, row): (u8, u32)) -> PageEntry {
    let manifest = manifest_of(directory);
    let page = &manifest.page_children[usize::from(child)];
    let salt = transparent_shard::page_tag_salt(
        manifest.shard_id,
        page.index,
        page.end_height,
        &BlockHash::from_display_hex(&page.terminal_block_hash).unwrap(),
        page.tag_salt_counter,
    );
    let tag = transparent_shard::script_tag(&salt, script);
    transparent_shard::decode_page_row(
        directory.children[usize::from(child)].page_row(&DECOUPLED_2K_8K, u64::from(row)),
    )
    .unwrap()
    .into_iter()
    .find(|e| e.tag == tag && e.ordinal == 0)
    .unwrap()
}

fn sorted(requests: &[RowRequest]) -> Vec<(u32, u64)> {
    let mut requests: Vec<(u32, u64)> = requests.iter().map(|r| (r.child, r.row)).collect();
    requests.sort_unstable();
    requests
}

/// A fragment that does not decode, in the middle of a run, fails that
/// script's walk alone. Every round until that run ends sends what the
/// honest walk sends; the failed walk sends nothing after, and every
/// other script's history comes back exactly. The failure is counted,
/// and the walk stays owed from the run it failed in.
#[test]
fn a_corrupt_fragment_fails_only_its_walk() {
    // Script 0's one run spans several rows; script 1's is shorter.
    let blocks = vec![(
        1_000,
        (0..200)
            .map(|nonce| (ScriptBytes::new(script(0)), receive(1_000, nonce)))
            .chain((200..230).map(|nonce| (ScriptBytes::new(script(1)), receive(1_000, nonce))))
            .collect(),
    )];
    let directories = build(&blocks);
    let directory = &directories[0];
    let manifest = manifest_of(directory);
    let scripts = [script(0), script(1)];
    let victim = scripts[0].clone();
    let runs = runs_of(directory, &victim);
    let head = run_head(directory, &victim, runs[0]);
    assert!(head.fragment_count >= 3, "{}", head.fragment_count);
    let (child, row) = runs[0];

    let mut honest_store = MemoryStore::new();
    let owed = directory_phase(&mut honest_store, directory, &manifest, &scripts);
    let mut honest = Direct::new(directory);
    walk(&mut honest_store, &manifest, &owed, &mut honest).unwrap();

    let mut store = MemoryStore::new();
    let owed = directory_phase(&mut store, directory, &manifest, &scripts);
    let mut corrupt = Direct::new(directory);
    corrupt
        .corrupt
        .insert((u32::from(child), u64::from(row) + 1));
    let failed = walk_failing(&mut store, &manifest, &owed, &mut corrupt);
    assert_eq!(
        failed,
        vec![FailedEntry {
            shard_id: manifest.shard_id,
            script: victim.clone(),
            failures: 1,
        }]
    );
    // The run's head comes in the first round, the rest of it in the
    // second, where it ends: the transcript is the honest one.
    assert_eq!(corrupt.round_sizes, honest.round_sizes);
    assert_eq!(corrupt.requests, honest.requests);
    assert_eq!(
        stored(&store, &scripts[1]),
        history(&blocks, directory, &scripts[1])
    );
    assert_eq!(store.coverage(&scripts[1]).unwrap().len(), 1);
    let pending = store.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].script, victim);
    assert_eq!(
        (pending[0].cursor.child, pending[0].cursor.row),
        (child, row)
    );
    assert_eq!(pending[0].fragments.len(), 1, "the checked head is kept");
    assert_eq!(store.coverage(&victim).unwrap(), vec![]);
    assert_eq!(store.entry_failures(manifest.shard_id, &victim).unwrap(), 1);

    // The retry resumes after the kept head and, answered honestly,
    // finishes.
    walk(&mut store, &manifest, &pending, &mut Direct::new(directory)).unwrap();
    assert!(store.pending().unwrap().is_empty());
    assert_eq!(
        stored(&store, &victim),
        history(&blocks, directory, &victim)
    );
}

/// `victim`'s newest run in `directory`, its head and its row with the
/// victim's head entry replaced by what `rewrite` makes of it.
fn rewritten_head(
    directory: &Directory,
    victim: &[u8],
    rewrite: impl Fn(PageEntry) -> PageEntry,
) -> ((u8, u32), PageEntry, Vec<u8>) {
    rewritten_run(directory, victim, 0, rewrite)
}

/// [`rewritten_head`] for `victim`'s run `run`, counted from the newest.
fn rewritten_run(
    directory: &Directory,
    victim: &[u8],
    run: usize,
    rewrite: impl Fn(PageEntry) -> PageEntry,
) -> ((u8, u32), PageEntry, Vec<u8>) {
    let (child, row) = runs_of(directory, victim)[run];
    let head = run_head(directory, victim, (child, row));
    let entries: Vec<PageEntry> = transparent_shard::decode_page_row(
        directory.children[usize::from(child)].page_row(&DECOUPLED_2K_8K, u64::from(row)),
    )
    .unwrap()
    .into_iter()
    .map(|entry| {
        if entry.tag == head.tag && entry.ordinal == 0 {
            rewrite(entry)
        } else {
            entry
        }
    })
    .collect();
    let bytes = transparent_shard::page_row::encode_page_row(&entries).unwrap();
    ((child, row), head, bytes)
}

/// Walks every paged script of the fixture's first directory shard
/// honestly, and again with the head row of `victim`'s run at `at`
/// replaced by `segments`: both walks' requests, and the store the second
/// leaves.
fn honest_and_rewritten(
    victim: &[u8],
    at: (u8, u32),
    segments: Vec<Vec<u8>>,
) -> (
    Direct<'static>,
    Direct<'static>,
    MemoryStore,
    Vec<FailedEntry>,
) {
    let (_, directories) = fixture();
    let directory = &directories[0];
    let manifest = manifest_of(directory);
    let scripts = paged(directory);
    let mut honest_store = MemoryStore::new();
    let owed = directory_phase(&mut honest_store, directory, &manifest, &scripts);
    let mut honest = Direct::new(directory);
    walk(&mut honest_store, &manifest, &owed, &mut honest).unwrap();

    let mut store = MemoryStore::new();
    let owed = directory_phase(&mut store, directory, &manifest, &scripts);
    let mut bad = Direct::new(directory);
    bad.rewritten
        .insert((u32::from(at.0), u64::from(at.1)), segments);
    let failed = walk_failing(&mut store, &manifest, &owed, &mut bad);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].script, victim);
    for script in scripts.iter().filter(|script| **script != victim) {
        assert_eq!(
            stored(&store, script),
            history(&fixture().0, directory, script)
        );
    }
    // The head was not kept: the next attempt asks for it again.
    let pending = store.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!((pending[0].cursor.child, pending[0].cursor.row), at);
    assert!(pending[0].fragments.is_empty());
    (honest, bad, store, failed)
}

/// A paged script of `directory` whose chain is two runs, the older one
/// fragment long: its honest walk ends with the round that reads the
/// newer run's rest and the older run's head.
fn linked_once(directory: &Directory) -> Vec<u8> {
    paged(directory)
        .into_iter()
        .find(|script| {
            let runs = runs_of(directory, script);
            runs.len() == 2 && run_head(directory, script, runs[1]).fragment_count == 1
        })
        .expect("a script whose chain ends one fragment after its link")
}

/// A run whose head is otherwise valid but whose link is not fails its
/// walk when the head arrives. In the next round the walk still sends the
/// rest of that run and one query in the link's place, as dummies to the
/// run's own page shard, and then stops while every other walk finishes.
/// The victim's honest walk ends with that round too, so every round is
/// the honest round's size.
fn a_bad_link_is_padded(rewrite: impl Fn(RunLink) -> RunLink) {
    let (_, directories) = fixture();
    let directory = &directories[0];
    let victim = linked_once(directory);
    let ((child, row), head, bytes) = rewritten_head(directory, &victim, |entry| {
        let link = rewrite(entry.link);
        entry.with_link(link).unwrap()
    });
    let (honest, bad, ..) = honest_and_rewritten(&victim, (child, row), vec![bytes]);
    assert_eq!(bad.round_sizes, honest.round_sizes);
    assert_eq!(sorted(bad.round(0)), sorted(honest.round(0)));
    // The victim's honest second round: the rest of its newest run, and
    // the head of the run it links to.
    let mut theirs: Vec<(u32, u64)> = (1..head.fragment_count)
        .map(|ordinal| (u32::from(child), u64::from(row + ordinal)))
        .collect();
    let (older, older_row) = head.link.previous().expect("a linked run");
    theirs.push((u32::from(older), u64::from(older_row)));
    let mut expected = sorted(honest.round(1));
    for request in &theirs {
        let at = expected.iter().position(|held| held == request).unwrap();
        expected.remove(at);
    }
    expected.extend((0..head.fragment_count).map(|_| (u32::from(child), 0)));
    expected.sort_unstable();
    assert_eq!(sorted(bad.round(1)), expected);
    for round in 2..honest.round_sizes.len() {
        assert_eq!(sorted(bad.round(round)), sorted(honest.round(round)));
    }
}

/// A script whose only run is in page shard 0 has no earlier run. A bad
/// link on that head fails the walk, and the next round must not grow:
/// page shard 0 has nothing to link to, so the honest walk sends no head
/// after it. One extra query would tell the service this row was read.
#[test]
fn a_bad_link_on_the_only_run_in_page_shard_zero_owes_no_query() {
    let blocks = vec![(
        1_000,
        (0..8)
            .map(|nonce| (ScriptBytes::new(script(1)), receive(1_000, nonce)))
            .collect(),
    )];
    let directories = build(&blocks);
    assert_eq!(directories.len(), 1);
    let directory = &directories[0];
    let manifest = manifest_of(directory);
    assert_eq!(
        manifest.page_children.len(),
        1,
        "the run sits in page shard 0"
    );
    let victim = script(1);
    let runs = runs_of(directory, &victim);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].0, 0);
    let honest_head = run_head(directory, &victim, runs[0]);
    assert_eq!(honest_head.link.previous(), None);
    let ((child, row), _, bytes) = rewritten_head(directory, &victim, |entry| {
        entry
            .with_link(RunLink {
                prev_child: 0,
                prev_row: 1,
                older_runs: 1,
            })
            .unwrap()
    });
    assert_eq!(child, 0);

    let scripts = [victim.clone()];
    let mut honest_store = MemoryStore::new();
    let owed = directory_phase(&mut honest_store, directory, &manifest, &scripts);
    let mut honest = Direct::new(directory);
    walk(&mut honest_store, &manifest, &owed, &mut honest).unwrap();
    assert!(honest.requests.iter().all(|request| request.child == 0));
    assert_eq!(
        honest.requests.len(),
        honest_head.fragment_count as usize,
        "the honest walk reads this run and no link"
    );

    let mut store = MemoryStore::new();
    let owed = directory_phase(&mut store, directory, &manifest, &scripts);
    let mut bad = Direct::new(directory);
    bad.rewritten
        .insert((u32::from(child), u64::from(row)), vec![bytes]);
    let failed = walk_failing(&mut store, &manifest, &owed, &mut bad);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].script, victim);
    let sent = |sizes: &[usize]| sizes.iter().copied().filter(|n| *n > 0).collect::<Vec<_>>();
    assert_eq!(sent(&bad.round_sizes), sent(&honest.round_sizes));
    assert_eq!(bad.requests.len(), honest.requests.len());
    assert!(bad.requests.iter().all(|request| request.child == 0));
}

/// A bad link on the oldest run, which its chain promised no older run:
/// the honest walk sends the rest of that run and no head after it, so
/// the failed walk owes only the rest, as dummies.
#[test]
fn a_bad_link_on_the_oldest_run_owes_no_head() {
    let (_, directories) = fixture();
    let directory = &directories[0];
    let victim = paged(directory).remove(0);
    let runs = runs_of(directory, &victim).len();
    assert!(runs >= 2, "{runs} runs");
    let ((child, row), head, bytes) = rewritten_run(directory, &victim, runs - 1, |entry| {
        assert_eq!(entry.link.previous(), None, "the oldest run");
        entry
            .with_link(RunLink {
                prev_child: 0,
                prev_row: 1,
                older_runs: 1,
            })
            .unwrap()
    });
    let (honest, bad, ..) = honest_and_rewritten(&victim, (child, row), vec![bytes]);
    assert_eq!(bad.round_sizes, honest.round_sizes);
    let dummies = |walk: &Direct<'_>| {
        walk.requests
            .iter()
            .filter(|request| (request.child, request.row) == (u32::from(child), 0))
            .count()
    };
    // The rest of the run, in the round after its head, as dummies.
    let rest = head.fragment_count as usize - 1;
    assert_eq!(dummies(&bad), dummies(&honest) + rest);
}

/// Tip catch-up reads the open run and stops at the cached run below it.
/// A bad link on that open run owes the rest of the run and no head after
/// it: the honest catch-up sends none.
#[test]
fn a_bad_link_owes_no_head_when_the_next_run_is_cached() {
    bad_link_at_tip_matches_the_honest_catch_up(|gap| gap == 1);
}

/// The same when the previous run is cached in a page shard further
/// down, because the script had no run in the page shards between.
#[test]
fn a_bad_link_owes_no_head_when_an_older_cached_run_is_next() {
    bad_link_at_tip_matches_the_honest_catch_up(|gap| gap > 1);
}

/// Corrupts the link row of a tip script's open run, whose previous run
/// is `gap` page shards below and cached by an earlier sync, and checks
/// the catch-up sends exactly the honest transcript's queries.
fn bad_link_at_tip_matches_the_honest_catch_up(gap: impl Fn(u8) -> bool) {
    let (_, directories) = fixture();
    let tail = directories.last().unwrap();
    let manifest = manifest_of(tail);
    let open = manifest.page_children.len() as u8 - 1;
    assert!(!manifest.page_children[usize::from(open)].sealed);
    assert!(manifest.page_children[usize::from(open - 1)].sealed);
    let scripts = paged(tail);
    let victim = scripts
        .iter()
        .find(|script| {
            let runs = runs_of(tail, script);
            runs.len() >= 2 && runs[0].0 == open && gap(runs[0].0 - runs[1].0)
        })
        .cloned()
        .expect("a tip script whose previous run is that many page shards below");
    let ((child, row), head, bytes) = rewritten_head(tail, &victim, |entry| {
        let link = entry.link;
        entry
            .with_link(RunLink {
                prev_row: 60_000,
                ..link
            })
            .unwrap()
    });
    assert!(head.link.previous().is_some());

    let mut seeded = MemoryStore::new();
    let owed = directory_phase(&mut seeded, tail, &manifest, &scripts);
    walk(&mut seeded, &manifest, &owed, &mut Direct::new(tail)).unwrap();

    let mut honest_store = seeded.clone();
    let owed = directory_phase(&mut honest_store, tail, &manifest, &scripts);
    let mut honest = Direct::new(tail);
    walk(&mut honest_store, &manifest, &owed, &mut honest).unwrap();
    assert!(
        honest
            .requests
            .iter()
            .all(|request| request.child == u32::from(open))
    );

    let mut bad_store = seeded;
    let owed = directory_phase(&mut bad_store, tail, &manifest, &scripts);
    let mut bad = Direct::new(tail);
    bad.rewritten
        .insert((u32::from(child), u64::from(row)), vec![bytes]);
    let failed = walk_failing(&mut bad_store, &manifest, &owed, &mut bad);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].script, victim);
    assert_eq!(bad.round_sizes, honest.round_sizes);
    assert_eq!(sorted(bad.round(0)), sorted(honest.round(0)));
    let dummies = |walk: &Direct<'_>| {
        walk.requests
            .iter()
            .filter(|request| (request.child, request.row) == (u32::from(child), 0))
            .count()
    };
    let rest = head.fragment_count as usize - 1;
    assert_eq!(dummies(&bad), dummies(&honest) + rest);
    assert_eq!(bad.requests.len(), honest.requests.len());
}

/// A link to a row outside the page shard's table.
#[test]
fn a_link_outside_the_tables_fails_only_its_walk() {
    a_bad_link_is_padded(|link| RunLink {
        prev_row: 60_000,
        ..link
    });
}

/// A link to page table 7 of a shard that declares fewer: it is not an
/// earlier page shard, and is refused as one, but the walk still sends
/// what the honest walk would.
#[test]
fn a_link_to_an_undeclared_page_table_fails_only_its_walk() {
    let (_, directories) = fixture();
    let declared = manifest_of(&directories[0]).page_children.len();
    assert!((3..7).contains(&declared), "{declared} page shards");
    a_bad_link_is_padded(|link| RunLink {
        prev_child: 7,
        ..link
    });
}

/// An `older_runs` the chain did not promise is the link's defect too:
/// here more older runs than a directory shard has page shards.
#[test]
fn an_older_runs_mismatch_fails_only_its_walk() {
    a_bad_link_is_padded(|link| RunLink {
        older_runs: transparent_shard::layout::MAX_PAGE_CHILDREN as u8,
        ..link
    });
}

/// A head that cannot be believed at all, here held twice across the
/// reply's segments, fails its walk with nothing more sent for it: what
/// it would have committed the walk to is unknown.
#[test]
fn a_fragment_held_twice_fails_only_its_walk() {
    let (_, directories) = fixture();
    let directory = &directories[0];
    let victim = paged(directory).remove(0);
    let (at, head, bytes) = rewritten_head(directory, &victim, |entry| entry);
    // A second segment holding the victim's first fragment alone.
    let again = transparent_shard::page_row::encode_page_row(&[head]).unwrap();
    let (honest, bad, ..) = honest_and_rewritten(&victim, at, vec![bytes, again]);
    assert_eq!(bad.round(0), honest.round(0));
    assert!(bad.requests.len() < honest.requests.len());
}

/// The row a link located holds the fragment under another entry's tag,
/// not the victim's: the walk fails, and only it.
#[test]
fn a_fragment_owned_by_another_entry_fails_only_its_walk() {
    let (_, directories) = fixture();
    let directory = &directories[0];
    let victim = paged(directory).remove(0);
    let (at, _, bytes) = rewritten_head(directory, &victim, |mut entry| {
        entry.tag = [0xee; transparent_shard::SCRIPT_TAG_BYTES];
        entry
    });
    let (honest, bad, ..) = honest_and_rewritten(&victim, at, vec![bytes]);
    assert_eq!(bad.round(0), honest.round(0));
    assert!(bad.requests.len() < honest.requests.len());
}

/// An overload refusing the round a failed walk owed its dummies in does
/// not lose them: the retried read sends them first, and the failure is
/// counted once.
#[test]
fn dummies_owed_before_an_overload_are_sent_on_the_retry() {
    let (_, directories) = fixture();
    let directory = &directories[0];
    let manifest = manifest_of(directory);
    let scripts = paged(directory);
    let victim = scripts[0].clone();
    let ((child, row), head, bytes) = rewritten_head(directory, &victim, |entry| {
        let link = RunLink {
            prev_row: 60_000,
            ..entry.link
        };
        entry.with_link(link).unwrap()
    });
    let mut store = MemoryStore::new();
    let owed = directory_phase(&mut store, directory, &manifest, &scripts);
    let mut failures = Failures::default();
    let mut refused = Direct::new(directory);
    refused
        .rewritten
        .insert((u32::from(child), u64::from(row)), vec![bytes]);
    refused.overloaded = Some(1);
    let error = walk_chains(
        &mut store,
        &entry_of(&manifest),
        &manifest,
        &owed,
        &mut refused,
        &target_of(&manifest),
        &mut failures,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SyncError::Client(ClientError::Overloaded(_))
    ));
    assert_eq!(
        failures.owes(manifest.shard_id, &victim),
        Some((child, head.fragment_count))
    );

    let mut retry = Direct::new(directory);
    let owed = store.pending().unwrap();
    walk_chains(
        &mut store,
        &entry_of(&manifest),
        &manifest,
        &owed,
        &mut retry,
        &target_of(&manifest),
        &mut failures,
    )
    .unwrap();
    // The retried round is the honest walk's second, with the victim's
    // rest of its run and the head it links to sent as dummies.
    let mut honest_store = MemoryStore::new();
    let owed = directory_phase(&mut honest_store, directory, &manifest, &scripts);
    let mut honest = Direct::new(directory);
    walk(&mut honest_store, &manifest, &owed, &mut honest).unwrap();
    let theirs: Vec<(u32, u64)> = (1..head.fragment_count)
        .map(|ordinal| (u32::from(child), u64::from(row + ordinal)))
        .chain(
            head.link
                .previous()
                .map(|(older, older_row)| (u32::from(older), u64::from(older_row))),
        )
        .collect();
    assert_eq!(theirs.len(), head.fragment_count as usize, "a linked run");
    let mut expected = sorted(honest.round(1));
    for request in &theirs {
        let at = expected.iter().position(|held| held == request).unwrap();
        expected.remove(at);
    }
    expected.extend(theirs.iter().map(|_| (u32::from(child), 0)));
    expected.sort_unstable();
    assert_eq!(sorted(retry.round(0)), expected);
    let dummies = |round: &[RowRequest]| {
        round
            .iter()
            .filter(|request| (request.child, request.row) == (u32::from(child), 0))
            .count()
    };
    assert_eq!(
        dummies(retry.round(0)),
        dummies(honest.round(1)) + head.fragment_count as usize
    );
    assert!(failures.owed.is_empty());
    assert_eq!(failures.entries.len(), 1);
    assert_eq!(store.entry_failures(manifest.shard_id, &victim).unwrap(), 1);
}

/// A directory row whose content does not decode fails its entry, on
/// content, whichever candidate row it was; the honest replies find the
/// entry.
#[test]
fn a_corrupt_directory_reply_fails_only_its_entry() {
    let (_, directories) = fixture();
    let directory = &directories[0];
    let manifest = manifest_of(directory);
    let entry = entry_of(&manifest);
    let built = &directory.built;
    let script = paged(directory).remove(0);
    let salt = transparent_shard::tag_salt(
        built.shard_id,
        &hash_at(built.end_height),
        built.tag_salt_counter,
    );
    let wanted = transparent_shard::script_tag(&salt, &script);
    let replies = |corrupt: Option<usize>| -> Vec<(u64, Reply)> {
        candidate_rows(built.shard_id, &script, built.geometry.directory_rows)
            .into_iter()
            .enumerate()
            .map(|(index, row)| {
                let mut bytes = built.directory_row(row).to_vec();
                if corrupt == Some(index) {
                    bytes.iter_mut().for_each(|byte| *byte ^= 0xa5);
                }
                (row, vec![bytes])
            })
            .collect()
    };
    let found = entry_in(&entry, &manifest, built.geometry, &wanted, &replies(None))
        .unwrap()
        .expect("the entry");
    assert_eq!(
        found.head(),
        directory_entry(directory, &script).unwrap().head()
    );
    for corrupt in 0..2 {
        assert!(matches!(
            entry_in(
                &entry,
                &manifest,
                built.geometry,
                &wanted,
                &replies(Some(corrupt))
            ),
            Err(SyncError::Content(_))
        ));
    }
}

/// A walk resumes from its durable cursor after any round, and the
/// history it ends with is the same.
#[test]
fn a_walk_resumes_from_its_cursor() {
    let (blocks, directories) = fixture();
    let directory = &directories[0];
    let manifest = manifest_of(directory);
    let script = paged(directory).remove(0);
    let mut store = MemoryStore::new();
    let owed = directory_phase(
        &mut store,
        directory,
        &manifest,
        std::slice::from_ref(&script),
    );
    struct Limited<'a> {
        inner: Direct<'a>,
        rounds: usize,
    }
    impl RowSource for Limited<'_> {
        fn stopped(&self) -> Option<IncompleteReason> {
            (self.inner.rounds >= self.rounds).then_some(IncompleteReason::QueryBudget)
        }
        fn fetch<S: WalletStore>(
            &mut self,
            store: &mut S,
            requests: &[RowRequest],
        ) -> Result<Vec<Reply>, SyncError> {
            self.inner.fetch(store, requests)
        }
    }
    let mut limited = Limited {
        inner: Direct::new(directory),
        rounds: 2,
    };
    let stopped = walk_chains(
        &mut store,
        &entry_of(&manifest),
        &manifest,
        &owed,
        &mut limited,
        &target_of(&manifest),
        &mut Failures::default(),
    )
    .unwrap();
    assert!(matches!(
        stopped,
        Some(Completion::Incomplete {
            reason: IncompleteReason::QueryBudget,
            pending: 1
        })
    ));
    let resumed = store.pending().unwrap();
    assert!(resumed[0].cursor.older_runs.is_some());
    walk(&mut store, &manifest, &resumed, &mut Direct::new(directory)).unwrap();
    assert!(store.pending().unwrap().is_empty());
    assert_eq!(stored(&store, &script), history(blocks, directory, &script));
}

/// Every pass may read only one row, including when a run spans many rows.
/// Saved progress must eventually recover the same history without rereading rows.
#[test]
fn one_query_passes_finish_a_history_without_repeating_rows() {
    let (blocks, directories) = fixture();
    let directory = &directories[0];
    let manifest = manifest_of(directory);
    let script = paged(directory).remove(0);
    let mut store = MemoryStore::new();
    directory_phase(
        &mut store,
        directory,
        &manifest,
        std::slice::from_ref(&script),
    );
    struct OneQuery<'a> {
        inner: Direct<'a>,
    }
    impl RowSource for OneQuery<'_> {
        fn stopped(&self) -> Option<IncompleteReason> {
            (!self.inner.requests.is_empty()).then_some(IncompleteReason::QueryBudget)
        }
        fn fetch<S: WalletStore>(
            &mut self,
            store: &mut S,
            requests: &[RowRequest],
        ) -> Result<Vec<Reply>, SyncError> {
            let remaining = usize::from(self.inner.requests.is_empty());
            self.inner
                .fetch(store, &requests[..requests.len().min(remaining)])
        }
    }
    let mut queried = std::collections::BTreeSet::new();
    for _ in 0..500 {
        let owed = store.pending().unwrap();
        if owed.is_empty() {
            break;
        }
        let mut rows = OneQuery {
            inner: Direct::new(directory),
        };
        walk_chains(
            &mut store,
            &entry_of(&manifest),
            &manifest,
            &owed,
            &mut rows,
            &target_of(&manifest),
            &mut Failures::default(),
        )
        .unwrap();
        assert_eq!(rows.inner.requests.len(), 1);
        for request in rows.inner.requests {
            assert!(
                queried.insert((request.child, request.row)),
                "a pass repeated a saved fragment"
            );
        }
    }
    assert!(
        store.pending().unwrap().is_empty(),
        "one-query passes must finish"
    );
    assert_eq!(stored(&store, &script), history(blocks, directory, &script));
}

/// A short run with no remaining requests can finish after an earlier
/// script uses the last query of a truncated round.
#[test]
fn a_partial_round_finishes_a_later_run_without_requests() {
    let blocks = vec![(
        1_000,
        (0..200)
            .map(|nonce| (ScriptBytes::new(script(0)), receive(1_000, nonce)))
            .chain((200..230).map(|nonce| (ScriptBytes::new(script(1)), receive(1_000, nonce))))
            .collect(),
    )];
    let directories = build(&blocks);
    let directory = &directories[0];
    let manifest = manifest_of(directory);
    let scripts = [script(0), script(1)];
    for (script, multiple) in scripts.iter().zip([true, false]) {
        let runs = runs_of(directory, script);
        assert_eq!(runs.len(), 1);
        let (child, row) = runs[0];
        let entries = transparent_shard::decode_page_row(
            directory.children[child as usize].page_row(&DECOUPLED_2K_8K, row.into()),
        )
        .unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| entry.ordinal == 0 && (entry.fragment_count > 1) == multiple)
        );
    }
    let mut store = MemoryStore::new();
    let owed = directory_phase(&mut store, directory, &manifest, &scripts);
    struct ThreeQueries<'a> {
        inner: Direct<'a>,
    }
    impl RowSource for ThreeQueries<'_> {
        fn stopped(&self) -> Option<IncompleteReason> {
            (self.inner.requests.len() >= 3).then_some(IncompleteReason::QueryBudget)
        }
        fn fetch<S: WalletStore>(
            &mut self,
            store: &mut S,
            requests: &[RowRequest],
        ) -> Result<Vec<Reply>, SyncError> {
            let remaining = 3usize.saturating_sub(self.inner.requests.len());
            self.inner
                .fetch(store, &requests[..requests.len().min(remaining)])
        }
    }
    let mut rows = ThreeQueries {
        inner: Direct::new(directory),
    };
    walk_chains(
        &mut store,
        &entry_of(&manifest),
        &manifest,
        &owed,
        &mut rows,
        &target_of(&manifest),
        &mut Failures::default(),
    )
    .unwrap();
    assert_eq!(rows.inner.requests.len(), 3);
    assert_eq!(
        stored(&store, &scripts[1]),
        history(&blocks, directory, &scripts[1])
    );
    let pending = store.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].script, scripts[0]);
    walk(&mut store, &manifest, &pending, &mut Direct::new(directory)).unwrap();
    assert!(store.pending().unwrap().is_empty());
    for script in &scripts {
        assert_eq!(stored(&store, script), history(&blocks, directory, script));
    }
}

fn head(_child: u8, link: RunLink) -> PageEntry {
    PageEntry::new([1; 14], 0, 1, vec![receive(10, 1)])
        .unwrap()
        .with_link(link)
        .unwrap()
}

fn cursor(child: u8, older_runs: Option<u8>) -> RunCursor {
    RunCursor {
        child,
        row: 0,
        older_runs,
    }
}

fn link(prev_child: u8, prev_row: u32, older_runs: u8) -> RunLink {
    RunLink {
        prev_child,
        prev_row,
        older_runs,
    }
}

/// A chain that ends where its count says more runs remain is cut short.
#[test]
fn a_truncated_chain_is_refused() {
    let end = head(3, RunLink::default());
    assert!(check_head(&end, &cursor(3, Some(0))).is_ok());
    assert!(check_head(&end, &cursor(3, Some(1))).is_err());
    assert!(check_head(&end, &cursor(3, Some(2))).is_err());
}

/// `older_runs` drops by exactly one per hop, and never claims more runs
/// than there are earlier page shards.
#[test]
fn an_older_runs_mismatch_is_refused() {
    let linked = head(5, link(2, 9, 2));
    assert!(check_head(&linked, &cursor(5, Some(2))).is_ok());
    assert!(check_head(&linked, &cursor(5, None)).is_ok());
    assert!(check_head(&linked, &cursor(5, Some(1))).is_err());
    assert!(check_head(&linked, &cursor(5, Some(3))).is_err());
    // A chain that carries on where it should have ended.
    assert!(check_head(&linked, &cursor(5, Some(0))).is_err());
    // Two older runs need two earlier page shards.
    assert!(check_head(&head(1, link(0, 9, 2)), &cursor(1, None)).is_err());
}

/// A link points only to an earlier page shard.
#[test]
fn a_forward_or_self_pointer_is_refused() {
    assert!(check_head(&head(4, link(3, 1, 1)), &cursor(4, None)).is_ok());
    assert!(check_head(&head(4, link(4, 1, 1)), &cursor(4, None)).is_err());
    assert!(check_head(&head(4, link(5, 1, 1)), &cursor(4, None)).is_err());
}

fn page_child(start: u64, end: u64) -> PageChild {
    PageChild {
        index: 1,
        start_height: start,
        end_height: end,
        terminal_block_hash: "00".repeat(32),
        tag_salt_counter: 0,
        sealed: true,
        page_segments: Vec::new(),
        occupancy: PageChildOccupancy {
            page_rows: 0,
            fragments: 0,
            runs: 0,
            events: 0,
        },
    }
}

/// The design's worked example: P1 = 1300-1649 holds e2@1020, pushed by
/// e4@1400; P2 = 1650-1999 holds e3@1100 and e4@1400, pushed by e5@1700
/// and e6@1710. Anywhere else, or out of order, is refused.
#[test]
fn push_out_placement_and_order_are_checked() {
    let e = |height: u32| receive(height, height);
    let carried = [e(1700), e(1710)];
    assert!(check_run(&page_child(1650, 1999), &[e(1100), e(1400)], &carried).is_ok());
    assert!(check_run(&page_child(1300, 1649), &[e(1020)], &[e(1100), e(1400)]).is_ok());
    // e2 placed in P0 = 1000-1299 would have been pushed by e4@1400.
    assert!(check_run(&page_child(1000, 1299), &[e(1020)], &[e(1100), e(1400)]).is_err());
    assert!(check_run(&page_child(1705, 1999), &[e(1100), e(1400)], &carried).is_err());
    // Out of order, or not older than what follows.
    assert!(check_run(&page_child(1650, 1999), &[e(1400), e(1100)], &carried).is_err());
    assert!(check_run(&page_child(1650, 1999), &[e(1100), e(1705)], &carried).is_err());
    assert!(check_run(&page_child(1650, 1999), &[e(1100)], &carried[..1]).is_err());
}

#[test]
fn malformed_manifest_cases_do_not_change_the_shared_fixture() {
    let (_, directories) = fixture();
    let directory = &directories[0];
    let expected = build_manifest(directory);
    let mut changed = manifest_of(directory);
    assert_eq!(
        serde_json::to_vec(&changed).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    changed.page_children.clear();
    changed.schema.clear();
    assert_eq!(
        serde_json::to_vec(&manifest_of(directory)).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
}
