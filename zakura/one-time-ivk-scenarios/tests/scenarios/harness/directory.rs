//! Production snapshot, GCS and encrypted PIR codecs served through a counted transport.
use super::chain::{ACTIVATION, Chain, GENESIS};
use receiver_directory::{
    RawRecord,
    blocks::{Batch, BlockFilter, BlockId, Head},
    snapshot::{Manifest, PROFILE, Snapshot, assign_ordinals},
    witness,
};
use receiver_pir::{
    MIN_ROWS, Publication,
    server::{Server, WitnessServer},
};
use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use zakura_pir_receiver::{DirectoryError, Transport};
use zakura_receiver_crypto::witness::payloads;

pub const ORIGIN: &str = "https://receiver.test";

/// An immutable PIR publication and independently lagging rolling filter suffix.
pub struct Directory {
    server: Server,
    witnesses: WitnessServer,
    head: Head,
    filters: Vec<BlockFilter>,
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
        let mut records: Vec<_> = chain
            .mined()
            .iter()
            .filter_map(|m| m.indexed.clone())
            .filter(|r| r.payment.height <= u32::from(end))
            .collect();
        let mut totals = BTreeMap::new();
        for r in &records {
            *totals.entry(*r.receiver.as_bytes()).or_insert(0u32) += 1;
        }
        let mut pages = BTreeMap::new();
        for r in &mut records {
            let page = pages.entry(*r.receiver.as_bytes()).or_insert(0u32);
            r.page = *page;
            r.total = totals[r.receiver.as_bytes()];
            *page += 1;
        }
        let mut raw: Vec<_> = records
            .iter()
            .map(|r| RawRecord::decode(&r.encode().unwrap()).unwrap().unwrap())
            .collect();
        assign_ordinals(&mut raw);
        let manifest = Manifest {
            profile: PROFILE.into(),
            history_revision: revision,
            genesis: GENESIS,
            start_height: ACTIVATION,
            start_parent: [0; 32],
            start_position: 0,
            end_height: end.into(),
            end_hash: chain.hash_at(end).0,
            end_position: chain.tree_size_at(end),
            rows: MIN_ROWS,
            salt: [5; 32],
            records: 0,
            data_sha256: [0; 32],
        };
        let snapshot = Snapshot::build(manifest, &raw).unwrap();
        let m = &snapshot.manifest;
        let mut positions: Vec<_> = raw.iter().map(|r| r.payment.position).collect();
        positions.sort_unstable();
        let table = witness::Table::build(
            witness::Manifest {
                profile: witness::PROFILE.into(),
                genesis: GENESIS,
                history_revision: revision,
                payments: m.revision().unwrap(),
                payloads: 0,
                rows: MIN_ROWS,
                tree_height: m.end_height,
                tree_hash: m.end_hash,
                tree_size: m.end_position,
                data_sha256: [0; 32],
            },
            &payloads(&chain.commitments()[..m.end_position as usize], &positions).unwrap(),
        )
        .unwrap();
        let tip = chain.tip() - filter_depth;
        let first = (u32::from(tip) + 1)
            .saturating_sub(retained)
            .max(ACTIVATION);
        let filters = (first..=u32::from(tip))
            .map(|height| {
                let receivers: Vec<_> = chain
                    .mined()
                    .iter()
                    .filter_map(|m| m.indexed.as_ref())
                    .filter(|r| r.payment.height == height)
                    .map(|r| *r.receiver.as_bytes())
                    .collect();
                let parent = if height == ACTIVATION {
                    [0; 32]
                } else {
                    chain.hash_at((height - 1).into()).0
                };
                BlockFilter::build(
                    &GENESIS,
                    BlockId {
                        height,
                        hash: chain.hash_at(height.into()).0,
                    },
                    parent,
                    &receivers,
                )
                .unwrap()
            })
            .collect();
        let server = Server::new(snapshot).unwrap();
        Self {
            witnesses: WitnessServer::new(table, &server).unwrap(),
            server,
            head: Head {
                genesis: GENESIS,
                revision,
                first,
                tip: BlockId {
                    height: tip.into(),
                    hash: chain.hash_at(tip).0,
                },
            },
            filters,
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
            if body.get(4..36) == Some(&self.witnesses.id()[..]) {
                self.witnesses.respond(body)?
            } else {
                self.server.respond(body)?
            }
        } else if route == "init" {
            serde_json::to_vec(&Publication {
                payments: self.server.manifest().clone(),
                witnesses: self.witnesses.manifest().clone(),
            })
            .unwrap()
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
            self.head.check_request(from, limit)?;
            let filters = self
                .filters
                .iter()
                .filter(|f| f.block().height >= from)
                .take(limit as usize)
                .cloned()
                .collect();
            Batch::new(GENESIS, self.head.revision, filters)?.encode()?
        } else {
            let (material, id) = route.split_once('/').unwrap();
            let public = if id == hex::encode(self.server.id()) {
                self.server.public()
            } else if id == hex::encode(self.witnesses.id()) {
                self.witnesses.public()
            } else {
                return Err(DirectoryError::Revision);
            };
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
