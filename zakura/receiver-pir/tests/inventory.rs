//! Sealed shard inventories: contiguous coverage, bounded chunks and complete capture.
mod common;
use common::manifest;
use receiver_directory::{
    snapshot::MIN_ROWS,
    witness::{Manifest as WitnessTable, PROFILE},
};
use receiver_pir::{
    inventory::{Chunk, FilterRef, Inventory, Shard, CHUNK_SHARDS, MAX_SEGMENTS},
    Manifest, Publication, WitnessManifest, PROTOCOL,
};

/// Session manifests for one empty segment covering heights `start..=end` and positions
/// `start..=end` (a toy position scale), with its companion witness table. Public setup
/// digests are placeholders: the inventory binds session IDs, not evaluation.
fn segment(start: u32, end: u32) -> Publication {
    let mut directory = manifest(MIN_ROWS);
    (directory.start_height, directory.end_height) = (start, end);
    directory.start_parent = parent(start);
    directory.end_hash = hash(end);
    (directory.start_position, directory.end_position) = (u64::from(start), u64::from(end) + 1);
    let table = WitnessTable {
        profile: PROFILE.into(),
        genesis: directory.genesis,
        history_revision: directory.history_revision,
        payments: directory.revision().unwrap(),
        payloads: 0,
        rows: MIN_ROWS,
        tree_height: directory.end_height,
        tree_hash: directory.end_hash,
        tree_size: directory.end_position,
        data_sha256: [0; 32],
    };
    Publication {
        payments: Manifest {
            protocol: PROTOCOL.into(),
            directory,
            public_digest: [7; 32],
        },
        witnesses: WitnessManifest {
            protocol: PROTOCOL.into(),
            table,
            public_digest: [8; 32],
        },
    }
}

/// A toy block hash for `height`.
fn hash(height: u32) -> [u8; 32] {
    let mut h = [0x33; 32];
    h[..4].copy_from_slice(&height.to_le_bytes());
    h
}

/// The parent hash of the block at `height`.
fn parent(height: u32) -> [u8; 32] {
    hash(height - 1)
}

/// A shard over `start..=end` with `segments` identical-coverage segments.
fn shard(start: u32, end: u32, sealed: bool, segments: usize) -> Shard {
    let one = segment(start, end);
    Shard {
        index: 0,
        sealed,
        start_height: start,
        start_parent: parent(start),
        start_position: u64::from(start),
        end_height: end,
        end_hash: hash(end),
        end_position: u64::from(end) + 1,
        segments: vec![one; segments],
        filter: sealed.then_some(FilterRef {
            digest: [9; 32],
            bytes: 100,
            receivers: 1,
        }),
    }
}

/// Contiguous sealed shards from height 100, then a recent tier.
fn shards(sealed: u32) -> Vec<Shard> {
    let mut out: Vec<_> = (0..sealed)
        .map(|i| shard(100 + 10 * i, 109 + 10 * i, true, 1))
        .collect();
    out.push(shard(100 + 10 * sealed, 104 + 10 * sealed, false, 1));
    out
}

#[test]
fn chunks_reassemble_into_the_identified_inventory() {
    let inventory = Inventory::build([1; 32], 0, shards(CHUNK_SHARDS as u32 + 3)).unwrap();
    let head = inventory.head().clone();
    assert_eq!(head.shards, CHUNK_SHARDS as u32 + 4);
    assert_eq!((head.start_height, head.end_height), (100, 294));
    let chunks = inventory.chunks().unwrap();
    assert_eq!(chunks.len(), 2);
    assert_eq!(head.chunks(), 2);
    let json: Vec<_> = chunks
        .iter()
        .map(|c| serde_json::to_vec(c).unwrap())
        .collect();
    let parsed: Vec<Chunk> = json
        .iter()
        .map(|j| serde_json::from_slice(j).unwrap())
        .collect();
    let captured = Inventory::from_chunks(head.clone(), parsed.clone()).unwrap();
    assert_eq!(captured.head(), inventory.head());
    assert_eq!(captured.shards().len(), inventory.shards().len());

    // A missing, reordered or substituted chunk is never a shorter history.
    assert!(Inventory::from_chunks(head.clone(), parsed[..1].to_vec()).is_err());
    let mut swapped = parsed.clone();
    swapped.swap(0, 1);
    assert!(Inventory::from_chunks(head.clone(), swapped).is_err());
    let mut substituted = parsed.clone();
    substituted[0].shards[3].filter = None;
    assert!(matches!(
        Inventory::from_chunks(head.clone(), substituted),
        Err(receiver_pir::Error::Revision)
    ));
    let mut other_head = head;
    other_head.inventory[0] ^= 1;
    assert!(Inventory::from_chunks(other_head, parsed).is_err());
}

#[test]
fn shards_are_contiguous_bounded_and_sealed_before_the_recent_tier() {
    Inventory::build([1; 32], 0, shards(2)).unwrap();
    // A gap in heights, an unsealed shard before the end, and a filter on the recent tier.
    let mut gap = shards(2);
    gap[1] = shard(111, 119, true, 1);
    assert!(Inventory::build([1; 32], 0, gap).is_err());
    let mut unsealed = shards(2);
    unsealed[0].sealed = false;
    unsealed[0].filter = None;
    assert!(Inventory::build([1; 32], 0, unsealed).is_err());
    let mut filtered = shards(1);
    filtered[1].filter = filtered[0].filter.clone();
    assert!(Inventory::build([1; 32], 0, filtered).is_err());
    // A segment must cover exactly its shard, under the inventory's network and correction.
    let mut wrong = shards(1);
    wrong[0].segments[0] = segment(100, 108);
    assert!(Inventory::build([1; 32], 0, wrong).is_err());
    assert!(Inventory::build([1; 32], 1, shards(1)).is_err());
    assert!(Inventory::build([2; 32], 0, shards(1)).is_err());
    // An oversized block's segments are bounded.
    let mut many = shards(1);
    many[0] = shard(100, 109, true, MAX_SEGMENTS);
    Inventory::build([1; 32], 0, many.clone()).unwrap();
    many[0] = shard(100, 109, true, MAX_SEGMENTS + 1);
    assert!(Inventory::build([1; 32], 0, many).is_err());
    assert!(Inventory::build([1; 32], 0, vec![]).is_err());
}

#[test]
fn acceptance_needs_the_wallet_anchor_and_required_start() {
    let inventory = Inventory::build([1; 32], 0, shards(2)).unwrap();
    inventory.accept(&[1; 32], 100, 124, &hash(124)).unwrap();
    inventory.accept(&[1; 32], 150, 124, &hash(124)).unwrap();
    assert!(inventory.accept(&[1; 32], 99, 124, &hash(124)).is_err());
    assert!(inventory.accept(&[1; 32], 100, 123, &hash(123)).is_err());
    assert!(inventory.accept(&[1; 32], 100, 124, &hash(1)).is_err());
    assert!(inventory.accept(&[2; 32], 100, 124, &hash(124)).is_err());
}

/// Serves an inventory's serialized chunks by URL, counting requests.
struct Chunks {
    inventory: [u8; 32],
    bodies: Vec<Vec<u8>>,
    requests: std::cell::Cell<usize>,
}

impl receiver_pir::transport::Transport for Chunks {
    /// Returns the requested chunk's bytes.
    async fn get(&self, url: &str, _: usize) -> Result<Vec<u8>, receiver_pir::Error> {
        self.requests.set(self.requests.get() + 1);
        let prefix = format!(
            "https://receiver/v1/receiver/inventory/{}/",
            hex::encode(self.inventory)
        );
        let index: usize = url.strip_prefix(&prefix).unwrap().parse().unwrap();
        Ok(self.bodies[index].clone())
    }

    /// Captures never open a PIR query.
    async fn post(&self, _: &str, _: Vec<u8>, _: usize) -> Result<Vec<u8>, receiver_pir::Error> {
        panic!("unexpected PIR request")
    }
}

/// Drives the immediately ready capture future without an async runtime.
fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("fixture unexpectedly suspended"),
    }
}

/// An inventory of three chunks and a transport serving `edit`ed copies of its chunks.
fn served(edit: impl Fn(usize, &mut Chunk)) -> (Inventory, Chunks) {
    let inventory = Inventory::build([1; 32], 0, shards(2 * CHUNK_SHARDS as u32 + 1)).unwrap();
    let bodies = inventory
        .chunks()
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(i, mut chunk)| {
            edit(i, &mut chunk);
            serde_json::to_vec(&chunk).unwrap()
        })
        .collect();
    let http = Chunks {
        inventory: inventory.head().inventory,
        bodies,
        requests: std::cell::Cell::new(0),
    };
    (inventory, http)
}

/// Each chunk is checked as it arrives: a malformed first chunk, or an invalid descriptor
/// in it, ends the capture before another chunk is requested.
#[test]
fn a_malformed_early_chunk_stops_the_capture() {
    use receiver_pir::transport::Inventories;
    let (inventory, http) = served(|_, _| {});
    let captured = ready(Inventories::capture(
        "https://receiver/",
        &http,
        inventory.head().clone(),
    ))
    .unwrap();
    assert_eq!(captured.shards().len(), inventory.shards().len());
    assert_eq!(http.requests.get(), 3);
    type Edit<'a> = &'a dyn Fn(usize, &mut Chunk);
    let edits: [Edit; 3] = [
        &|i, c| {
            if i == 0 {
                c.index = 1;
            }
        },
        &|i, c| {
            if i == 0 {
                c.shards[2].segments[0] = segment(100, 108);
            }
        },
        &|i, c| {
            if i == 0 {
                c.shards[5].start_height += 1;
            }
        },
    ];
    for (n, edit) in edits.iter().enumerate() {
        let (inventory, http) = served(edit);
        assert!(
            ready(Inventories::capture(
                "https://receiver/",
                &http,
                inventory.head().clone()
            ))
            .is_err(),
            "{n}"
        );
        assert_eq!(
            http.requests.get(),
            1,
            "{n}: no request after the bad chunk"
        );
    }
}

/// A capture stops once the chunks it retains pass its byte budget.
#[test]
fn a_capture_stops_at_its_byte_budget() {
    use receiver_pir::transport::Inventories;
    let (inventory, http) = served(|_, _| {});
    let first = http.bodies[0].len();
    assert!(ready(Inventories::capture_within(
        "https://receiver/",
        &http,
        inventory.head().clone(),
        first + 1,
    ))
    .is_err());
    assert_eq!(http.requests.get(), 2);
}
