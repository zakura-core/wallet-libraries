//! Incremental inventory capture: settled shard descriptors are reused from a host store
//! for whole chunks, the complete inventory is still proved against its head, and any
//! mismatch recaptures every chunk.
mod common;
use common::manifest;
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};
use zakura_pir_client::receiver::{
    inventory::{FilterRef, Inventory, Shard},
    session::{Error, Manifest, PROTOCOL, Publication, WitnessManifest},
    snapshot::MIN_ROWS,
    transport::{DescriptorStore, Inventories, Transport},
    witness::{Manifest as WitnessTable, PROFILE},
};

/// How a shard's companion witness table was built.
#[derive(Clone, Copy)]
enum Witness {
    /// At the shard's own end, before its Ironwood shard filled.
    Provisional,
    /// After its Ironwood shard filled; the value tells rebuilt tables apart.
    Final(u8),
}

/// One fixture chain: blocks at or above `fork` have other hashes, and every shard is
/// built under correction generation `revision`.
#[derive(Clone, Copy)]
struct Chain {
    fork: u32,
    revision: u64,
}

const MAIN: Chain = Chain {
    fork: u32::MAX,
    revision: 0,
};

impl Chain {
    /// The toy hash of the block at `height` on this chain.
    fn hash(&self, height: u32) -> [u8; 32] {
        let mut h = [0x33; 32];
        h[..4].copy_from_slice(&height.to_le_bytes());
        h[4] = u8::from(height >= self.fork);
        h
    }

    /// One empty segment over heights and toy positions `start..=end`, with its witness
    /// table.
    fn segment(&self, start: u32, end: u32, witness: Witness) -> Publication {
        let mut directory = manifest(MIN_ROWS);
        directory.history_revision = self.revision;
        (directory.start_height, directory.end_height) = (start, end);
        directory.start_parent = self.hash(start - 1);
        directory.end_hash = self.hash(end);
        (directory.start_position, directory.end_position) = (u64::from(start), u64::from(end) + 1);
        let (tree_height, tree_hash, tree_size) = match witness {
            Witness::Provisional => (end, directory.end_hash, directory.end_position),
            Witness::Final(v) => (end + 1, [v; 32], (1 << 16) + u64::from(v)),
        };
        let table = WitnessTable {
            profile: PROFILE.into(),
            genesis: directory.genesis,
            history_revision: self.revision,
            payments: directory.revision().unwrap(),
            payloads: 0,
            rows: MIN_ROWS,
            tree_height,
            tree_hash,
            tree_size,
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

    /// `sealed` contiguous ten-block sealed shards from height 100, shard `i` built with
    /// `witness(i)`, then a five-block recent tier.
    fn inventory(&self, sealed: u32, witness: impl Fn(u32) -> Witness) -> Inventory {
        let shard = |i: u32, sealed: bool, len: u32| {
            let (start, end) = (100 + 10 * i, 100 + 10 * i + len - 1);
            let witness = if sealed {
                witness(i)
            } else {
                Witness::Final(0)
            };
            Shard {
                index: 0,
                sealed,
                start_height: start,
                start_parent: self.hash(start - 1),
                start_position: u64::from(start),
                end_height: end,
                end_hash: self.hash(end),
                end_position: u64::from(end) + 1,
                segments: vec![self.segment(start, end, witness)],
                filter: sealed.then_some(FilterRef {
                    digest: [9; 32],
                    bytes: 100,
                    receivers: 1,
                }),
            }
        };
        let mut shards: Vec<_> = (0..sealed).map(|i| shard(i, true, 10)).collect();
        shards.push(shard(sealed, false, 5));
        Inventory::build([1; 32], self.revision, shards).unwrap()
    }
}

/// Every sealed shard final.
fn settled(_: u32) -> Witness {
    Witness::Final(0)
}

/// Serves the chunks of every published inventory by URL, counting requests.
#[derive(Default)]
struct Server {
    chunks: RefCell<HashMap<String, Vec<Vec<u8>>>>,
    requests: Cell<usize>,
}

impl Server {
    /// Serves `inventory`'s chunks and returns its head.
    fn publish(&self, inventory: &Inventory) -> zakura_pir_client::receiver::inventory::Head {
        let bodies = inventory
            .chunks()
            .unwrap()
            .iter()
            .map(|chunk| serde_json::to_vec(chunk).unwrap())
            .collect();
        self.chunks
            .borrow_mut()
            .insert(hex::encode(inventory.head().inventory), bodies);
        inventory.head().clone()
    }

    /// Requests made since the last call.
    fn take(&self) -> usize {
        self.requests.replace(0)
    }
}

impl Transport for Server {
    /// Returns the requested chunk's bytes.
    async fn get(&self, url: &str, _: usize) -> Result<Vec<u8>, Error> {
        self.requests.set(self.requests.get() + 1);
        let path = url
            .strip_prefix("https://receiver/v1/receiver/inventory/")
            .unwrap();
        let (inventory, index) = path.split_once('/').unwrap();
        let index: usize = index.parse().unwrap();
        Ok(self.chunks.borrow()[inventory][index].clone())
    }

    /// Captures never open a PIR query.
    async fn post(&self, _: &str, _: Vec<u8>, _: usize) -> Result<Vec<u8>, Error> {
        panic!("unexpected PIR request")
    }
}

/// An in-memory host store.
#[derive(Default)]
struct Store(RefCell<Option<Vec<u8>>>);

impl DescriptorStore for Store {
    /// The saved value.
    fn load(&self) -> Option<Vec<u8>> {
        self.0.borrow().clone()
    }

    /// Replaces the saved value.
    fn save(&self, value: &[u8]) {
        *self.0.borrow_mut() = Some(value.to_vec());
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

/// Captures `inventory` through `server` with `store`, checks it is exactly that
/// inventory, and returns the chunk requests it made.
fn capture(server: &Server, store: &Store, inventory: &Inventory) -> usize {
    let head = server.publish(inventory);
    server.take();
    let captured = ready(Inventories::capture_cached(
        "https://receiver/",
        server,
        head,
        store,
    ))
    .unwrap();
    assert_eq!(captured.head(), inventory.head());
    let digests = |i: &Inventory| serde_json::to_string(i.shards()).unwrap();
    assert_eq!(digests(&captured), digests(inventory));
    server.take()
}

/// A later inventory that appends shards downloads only the chunks holding new shards
/// and the recent tier; the settled chunks come from the cache.
#[test]
fn appended_shards_download_only_the_changed_chunks() {
    let (server, store) = (Server::default(), Store::default());
    assert_eq!(capture(&server, &store, &MAIN.inventory(32, settled)), 3);
    assert!(store.load().is_some());
    // Chunks 0 and 1 are unchanged; chunk 2 gains sealed shards and chunk 3 is new.
    assert_eq!(capture(&server, &store, &MAIN.inventory(48, settled)), 2);
    assert_eq!(capture(&server, &store, &MAIN.inventory(48, settled)), 1);
}

/// A sealed shard whose witnesses are still provisional is never cached, so its rebuilt
/// witness table is downloaded with its chunk. A settled shard replaced anyway fails the
/// inventory identity and recaptures every chunk.
#[test]
fn witness_replacement_in_a_sealed_shard_is_downloaded() {
    let (server, store) = (Server::default(), Store::default());
    let provisional = |i| {
        if i == 5 {
            Witness::Provisional
        } else {
            Witness::Final(0)
        }
    };
    assert_eq!(
        capture(&server, &store, &MAIN.inventory(32, provisional)),
        3
    );
    // Shard 5's table is rebuilt once its Ironwood shard filled: chunk 0 is downloaded.
    assert_eq!(capture(&server, &store, &MAIN.inventory(32, settled)), 2);
    // Settled shard 7 replaced: the cached chunk 0 fails the identity check, then all three.
    let replaced = |i| Witness::Final(u8::from(i == 7));
    assert_eq!(
        capture(&server, &store, &MAIN.inventory(32, replaced)),
        1 + 3
    );
    assert_eq!(capture(&server, &store, &MAIN.inventory(32, replaced)), 1);
}

/// A correction generation never reuses descriptors verified under another.
#[test]
fn a_correction_recaptures_every_chunk() {
    let (server, store) = (Server::default(), Store::default());
    assert_eq!(capture(&server, &store, &MAIN.inventory(32, settled)), 3);
    let corrected = Chain {
        fork: u32::MAX,
        revision: 1,
    };
    assert_eq!(
        capture(&server, &store, &corrected.inventory(32, settled)),
        3
    );
    assert_eq!(
        capture(&server, &store, &corrected.inventory(32, settled)),
        1
    );
}

/// A reorg replaces sealed shards under the same correction generation. Their cached
/// descriptors fail the new inventory's identity, so every chunk is recaptured and the
/// cache follows the new chain.
#[test]
fn a_reorg_recaptures_every_chunk() {
    let (server, store) = (Server::default(), Store::default());
    assert_eq!(capture(&server, &store, &MAIN.inventory(32, settled)), 3);
    let forked = Chain {
        fork: 255,
        revision: 0,
    };
    assert_eq!(
        capture(&server, &store, &forked.inventory(32, settled)),
        1 + 3
    );
    assert_eq!(capture(&server, &store, &forked.inventory(32, settled)), 1);
}

/// A saved value that does not parse is ignored, and one whose descriptors were altered
/// fails the inventory identity: both end in a correct full capture.
#[test]
fn a_corrupted_cache_recaptures_every_chunk() {
    let (server, store) = (Server::default(), Store::default());
    store.save(b"not a cache");
    assert_eq!(capture(&server, &store, &MAIN.inventory(32, settled)), 3);
    let mut saved: serde_json::Value = serde_json::from_slice(&store.load().unwrap()).unwrap();
    saved["shards"][3]["filter"]["receivers"] = 2.into();
    store.save(&serde_json::to_vec(&saved).unwrap());
    assert_eq!(
        capture(&server, &store, &MAIN.inventory(32, settled)),
        1 + 3
    );
    assert_eq!(capture(&server, &store, &MAIN.inventory(32, settled)), 1);
}

/// A saved descriptor whose payment or witness protocol was altered is a bad cache, not an
/// upgrade: capture falls back to every chunk, succeeds without `Unsupported`, and the
/// verified inventory replaces the saved value. A served inventory in an unknown protocol
/// still surfaces `Unsupported`, with a cache or without one.
#[test]
fn an_altered_cached_protocol_recaptures_and_replaces_the_cache() {
    for field in ["payments", "witnesses"] {
        let (server, store) = (Server::default(), Store::default());
        let inventory = MAIN.inventory(32, settled);
        assert_eq!(capture(&server, &store, &inventory), 3);
        let verified = store.load().unwrap();
        let mut saved: serde_json::Value = serde_json::from_slice(&verified).unwrap();
        saved["shards"][3]["segments"][0][field]["protocol"] = "future-protocol".into();
        store.save(&serde_json::to_vec(&saved).unwrap());
        // The altered descriptor is in the first chunk, refused before any download.
        assert_eq!(capture(&server, &store, &inventory), 3, "{field}");
        assert_eq!(store.load().unwrap(), verified, "{field}");
        assert_eq!(capture(&server, &store, &inventory), 1, "{field}");
    }

    let (server, store) = (Server::default(), Store::default());
    let inventory = MAIN.inventory(32, settled);
    assert_eq!(capture(&server, &store, &inventory), 3);
    let head = server.publish(&inventory);
    let key = hex::encode(head.inventory);
    let last = server.chunks.borrow()[&key].len() - 1;
    for cached in [true, false] {
        if !cached {
            *store.0.borrow_mut() = None;
        }
        let mut chunk: serde_json::Value =
            serde_json::from_slice(&server.chunks.borrow()[&key][last]).unwrap();
        chunk["shards"][0]["segments"][0]["payments"]["protocol"] = "future-protocol".into();
        server.chunks.borrow_mut().get_mut(&key).unwrap()[last] =
            serde_json::to_vec(&chunk).unwrap();
        let result = ready(Inventories::capture_cached(
            "https://receiver/",
            &server,
            head.clone(),
            &store,
        ));
        assert!(matches!(result, Err(Error::Unsupported)), "cached {cached}");
    }
}

/// A served inventory whose payment or witness profile a newer client may read surfaces
/// `Unsupported`, the host's upgrade outcome, while corrupted descriptor fields are not
/// `Unsupported`. A cached descriptor with an unknown profile is a bad cache: capture
/// falls back to every chunk and replaces it.
#[test]
fn an_unknown_session_profile_needs_a_newer_client() {
    let inventory = MAIN.inventory(32, settled);
    let served = |edit: &dyn Fn(&mut serde_json::Value)| {
        let (server, store) = (Server::default(), Store::default());
        let head = server.publish(&inventory);
        let key = hex::encode(head.inventory);
        let mut chunk: serde_json::Value =
            serde_json::from_slice(&server.chunks.borrow()[&key][0]).unwrap();
        edit(&mut chunk["shards"][0]["segments"][0]);
        server.chunks.borrow_mut().get_mut(&key).unwrap()[0] = serde_json::to_vec(&chunk).unwrap();
        ready(Inventories::capture_cached(
            "https://receiver/",
            &server,
            head,
            &store,
        ))
    };
    let payments =
        served(&|s| s["payments"]["directory"]["profile"] = "ironwood-receiver/v9".into());
    assert!(matches!(payments, Err(Error::Unsupported)));
    let witnesses = served(&|s| s["witnesses"]["table"]["profile"] = "ironwood-witness/v9".into());
    assert!(matches!(witnesses, Err(Error::Unsupported)));
    let corrupted = served(&|s| s["payments"]["directory"]["start_height"] = 999_999.into());
    assert!(!matches!(corrupted, Ok(_) | Err(Error::Unsupported)));

    let (server, store) = (Server::default(), Store::default());
    assert_eq!(capture(&server, &store, &inventory), 3);
    let verified = store.load().unwrap();
    let mut saved: serde_json::Value = serde_json::from_slice(&verified).unwrap();
    saved["shards"][3]["segments"][0]["payments"]["directory"]["profile"] =
        "ironwood-receiver/v9".into();
    store.save(&serde_json::to_vec(&saved).unwrap());
    assert_eq!(capture(&server, &store, &inventory), 3);
    assert_eq!(store.load().unwrap(), verified);
}

/// A directory format error a newer client handles is the client's `Unsupported`, the
/// same outcome as an unsupported protocol; other directory errors stay directory errors.
#[test]
fn directory_format_errors_map_to_unsupported() {
    assert!(matches!(
        Error::from(zakura_pir_client::receiver::Error::Unsupported),
        Error::Unsupported
    ));
    assert!(matches!(
        Error::from(zakura_pir_client::receiver::Error::Malformed),
        Error::Directory(zakura_pir_client::receiver::Error::Malformed)
    ));
}
