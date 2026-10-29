//! Production snapshot, witness, shard inventory, GCS and encrypted PIR codecs served
//! through a counted transport. History is sealed into shards every [`SEAL_BLOCKS`] blocks,
//! the last partial shard being the recent tier.
use super::chain::{ACTIVATION, Chain, GENESIS};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use zakura_pir_client::receiver::{
    RawRecord,
    blocks::{BlockId, Head, HeightSet, Range},
    inventory::{FilterRef, Inventory, Shard},
    session::{Error as DirectoryError, MIN_ROWS, Publication},
    shards::{Coverage, ShardFilter},
    snapshot::{Manifest, PROFILE, Snapshot},
    transport::Transport,
    witness,
};
use zakura_pir_publisher::receiver::{
    snapshot::{SnapshotPublisherExt, assign_ordinals},
    witness::{TablePublisherExt, payloads},
};
use zakura_pir_query_server::receiver::server::{Server, WitnessServer};

pub const ORIGIN: &str = "https://receiver.test";
/// Blocks per sealed shard.
pub const SEAL_BLOCKS: u32 = 32;

/// An immutable shard inventory and independently lagging rolling filter suffix.
pub struct Directory {
    inventory: Inventory,
    payments: Vec<Server>,
    witnesses: Vec<WitnessServer>,
    shard_filters: Vec<([u8; 32], Vec<u8>)>,
    head: Head,
    /// Nonempty block sets, ascending, and every block hash from `head.first - 1`.
    sets: Vec<HeightSet>,
    hashes: Vec<[u8; 32]>,
    counts: Mutex<(usize, u64, u64)>,
    pub unavailable: AtomicBool,
}

impl Directory {
    /// Builds real public material and private answers from the independent chain oracle.
    pub fn publish(
        chain: &Chain,
        pir_depth: u32,
        filter_depth: u32,
        retained: u32,
        revision: u64,
    ) -> Self {
        let end = chain.tip() - pir_depth;
        let (end_hash, end_size) = (chain.hash_at(end).0, chain.tree_size_at(end));
        let (mut payments, mut witnesses, mut shard_filters, mut shards) =
            (vec![], vec![], vec![], vec![]);
        let (mut start, mut parent, mut position) = (ACTIVATION, [0; 32], 0);
        while start <= u32::from(end) {
            let last = (start + SEAL_BLOCKS - 1).min(u32::from(end));
            let sealed = last - start + 1 == SEAL_BLOCKS && last < u32::from(end);
            let records: Vec<_> = chain
                .mined()
                .iter()
                .filter_map(|m| m.indexed.clone())
                .filter(|r| (start..=last).contains(&r.payment.height))
                .collect();
            let mut raw: Vec<RawRecord> = vec![];
            for r in &records {
                let mut r = RawRecord::decode(&r.encode().unwrap()).unwrap().unwrap();
                r.page = raw.iter().filter(|o| o.receiver == r.receiver).count() as u32;
                raw.push(r);
            }
            for i in 0..raw.len() {
                let receiver = raw[i].receiver;
                raw[i].total = raw.iter().filter(|o| o.receiver == receiver).count() as u32;
            }
            assign_ordinals(&mut raw);
            let (last_hash, last_size) = (
                chain.hash_at(last.into()).0,
                chain.tree_size_at(last.into()),
            );
            let snapshot = Snapshot::build(
                Manifest {
                    profile: PROFILE.into(),
                    history_revision: revision,
                    genesis: GENESIS,
                    start_height: start,
                    start_parent: parent,
                    start_position: position,
                    end_height: last,
                    end_hash: last_hash,
                    end_position: last_size,
                    rows: MIN_ROWS,
                    salt: [5; 32],
                    records: 0,
                    data_sha256: [0; 32],
                },
                &raw,
            )
            .unwrap();
            let mut positions: Vec<_> = raw.iter().map(|r| r.payment.position).collect();
            positions.sort_unstable();
            // Every witness table is built at the publication's end.
            let table = witness::Table::build(
                witness::Manifest {
                    profile: witness::PROFILE.into(),
                    genesis: GENESIS,
                    history_revision: revision,
                    payments: snapshot.manifest.revision().unwrap(),
                    payloads: 0,
                    rows: MIN_ROWS,
                    tree_height: end.into(),
                    tree_hash: end_hash,
                    tree_size: end_size,
                    data_sha256: [0; 32],
                },
                &payloads(&chain.commitments()[..end_size as usize], &positions).unwrap(),
            )
            .unwrap();
            let server = Server::new(snapshot).unwrap();
            let witness = WitnessServer::new(table, &server).unwrap();
            let filter = sealed.then(|| {
                let filter = ShardFilter::build(
                    GENESIS,
                    revision,
                    Coverage {
                        start_height: start,
                        end_height: last,
                        end_hash: last_hash,
                    },
                    records.iter().map(|r| r.receiver.as_bytes()),
                )
                .unwrap();
                shard_filters.push((filter.digest(), filter.bytes().to_vec()));
                FilterRef {
                    digest: filter.digest(),
                    bytes: filter.bytes().len() as u32,
                    receivers: filter.receivers() as u32,
                }
            });
            shards.push(Shard {
                index: 0,
                sealed,
                start_height: start,
                start_parent: parent,
                start_position: position,
                end_height: last,
                end_hash: last_hash,
                end_position: last_size,
                segments: vec![Publication {
                    payments: server.manifest().clone(),
                    witnesses: witness.manifest().clone(),
                }],
                filter,
            });
            payments.push(server);
            witnesses.push(witness);
            (start, parent, position) = (last + 1, last_hash, last_size);
        }
        let inventory = Inventory::build(GENESIS, revision, shards).unwrap();
        let tip = chain.tip() - filter_depth;
        let first = (u32::from(tip) + 1)
            .saturating_sub(retained)
            .max(ACTIVATION);
        let sets = (first..=u32::from(tip))
            .filter_map(|height| {
                let receivers: Vec<_> = chain
                    .mined()
                    .iter()
                    .filter_map(|m| m.indexed.as_ref())
                    .filter(|r| r.payment.height == height)
                    .map(|r| *r.receiver.as_bytes())
                    .collect();
                HeightSet::build(&GENESIS, height, &receivers).unwrap()
            })
            .collect();
        let hashes = (first - 1..=u32::from(tip))
            .map(|height| {
                if height < ACTIVATION {
                    [0; 32]
                } else {
                    chain.hash_at(height.into()).0
                }
            })
            .collect();
        Self {
            inventory,
            payments,
            witnesses,
            shard_filters,
            head: Head {
                genesis: GENESIS,
                revision,
                first,
                tip: BlockId {
                    height: tip.into(),
                    hash: chain.hash_at(tip).0,
                },
            },
            sets,
            hashes,
            counts: Mutex::new((0, 0, 0)),
            unavailable: AtomicBool::new(false),
        }
    }

    /// Observed encrypted query count, payment and witness alike, and actual
    /// request/response body bytes.
    pub fn counts(&self) -> (usize, u64, u64) {
        *self.counts.lock().unwrap()
    }

    /// Serves the public protocol while enforcing the client's response bound.
    fn answer(
        &self,
        url: &str,
        body: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(DirectoryError::Transport("unavailable".into()));
        }
        let route = url
            .strip_prefix(ORIGIN)
            .unwrap()
            .strip_prefix("/v1/receiver/")
            .unwrap();
        let mut counts = self.counts.lock().unwrap();
        let bytes = if let Some(body) = body {
            assert_eq!(route, "query");
            counts.0 += 1;
            counts.1 += body.len() as u64;
            let session = body.get(4..36);
            if let Some(w) = self.witnesses.iter().find(|w| session == Some(&w.id()[..])) {
                w.respond(body)?
            } else if let Some(p) = self.payments.iter().find(|p| session == Some(&p.id()[..])) {
                p.respond(body)?
            } else {
                return Err(DirectoryError::Revision);
            }
        } else if route == "inventory" {
            serde_json::to_vec(self.inventory.head()).unwrap()
        } else if let Some(request) = route.strip_prefix("inventory/") {
            let (id, chunk) = request.split_once('/').unwrap();
            if id != hex::encode(self.inventory.head().inventory) {
                return Err(DirectoryError::Revision);
            }
            let chunks = self.inventory.chunks().unwrap();
            serde_json::to_vec(&chunks[chunk.parse::<usize>().unwrap()]).unwrap()
        } else if let Some(digest) = route.strip_prefix("shard-filters/") {
            self.shard_filters
                .iter()
                .find(|(d, _)| hex::encode(d) == digest)
                .map(|(_, f)| f.clone())
                .ok_or_else(|| DirectoryError::Transport("unknown filter".into()))?
        } else if route == "block-filters/head" {
            serde_json::to_vec(&self.head).unwrap()
        } else if let Some(request) = route.strip_prefix("block-filters/") {
            let parts: Vec<u64> = request.split('/').map(|p| p.parse().unwrap()).collect();
            assert_eq!(parts.len(), 3);
            if parts[0] != self.head.revision {
                return Err(DirectoryError::Revision);
            }
            let from = parts[1] as u32;
            let limit = parts[2] as u32;
            self.head.check_range(from, limit)?;
            let end = from.saturating_add(limit - 1).min(self.head.tip.height);
            let hash = |height: u32| self.hashes[(height + 1 - self.head.first) as usize];
            let sets = self
                .sets
                .iter()
                .filter(|s| (from..=end).contains(&s.height()))
                .cloned()
                .collect();
            Range::new(
                self.head.revision,
                from,
                end - from + 1,
                hash(from - 1),
                hash(end),
                sets,
            )?
            .encode()?
        } else {
            let (material, id) = route.split_once('/').unwrap();
            let public = self
                .payments
                .iter()
                .find(|p| hex::encode(p.id()) == id)
                .map(|p| p.public())
                .or_else(|| {
                    self.witnesses
                        .iter()
                        .find(|w| hex::encode(w.id()) == id)
                        .map(|w| w.public())
                })
                .ok_or(DirectoryError::Revision)?;
            match material {
                "public" => public.to_vec(),
                _ => return Err(DirectoryError::Transport("unknown route".into())),
            }
        };
        if bytes.len() > limit {
            return Err(DirectoryError::Transport("response too large".into()));
        }
        counts.2 += bytes.len() as u64;
        Ok(bytes)
    }
}

impl Transport for Directory {
    /// Retrieves bounded public material.
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, DirectoryError> {
        self.answer(url, None, limit)
    }
    /// Evaluates an encrypted receiver query.
    async fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        self.answer(url, Some(&body), limit)
    }
}
