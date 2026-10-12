//! The receiver directory, served in process over the real receiver routes and real
//! PIR.

use std::{
    cell::OnceCell,
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Mutex,
};

use axum::{Router, body::Body, http::Request};
use receiver_directory::{
    Record,
    snapshot::{Manifest, PROFILE, Snapshot},
    witness::WitnessSnapshot,
};
use receiver_pir::{MIN_ROWS, server::Server};
use receiver_pir_server::{Publication, Publications, router_with_publications};
use tower::ServiceExt as _;
use zakura_pir_receiver::{DirectoryError, Transport};

use super::{
    chain::{ACTIVATION, Chain, GENESIS},
    near::Near,
};

/// The origin wallets send requests to; the transport serves them in process.
pub const ORIGIN: &str = "https://receiver.test";

/// How a publication differs from a faithful index of the chain.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Blocks the publication trails the tip by. The live indexer publishes 2 below.
    pub depth: u32,
    /// Note positions the indexer left out.
    pub omit: BTreeSet<u64>,
}

/// A directory serving one publication, with injectable failures.
pub struct Directory {
    router: Router,
    requests: Mutex<Vec<String>>,
    faults: Mutex<VecDeque<u16>>,
    /// Request and response body bytes, as (sent, received).
    bytes: Mutex<(u64, u64)>,
}

impl Directory {
    /// Publishes every zero-OVK payment through `depth` blocks below the tip, with
    /// NEAR's sets as of `now`.
    pub fn publish(chain: &Chain, near: &Near, now: i64, options: &Options) -> Self {
        let depth = options.depth.max(2);
        let end = chain.tip() - depth;
        let end_height = u32::from(end);
        let mut pages: BTreeMap<[u8; 43], u32> = BTreeMap::new();
        let visible: Vec<&Record> = chain
            .mined()
            .iter()
            .filter_map(|m| m.indexed.as_ref())
            .filter(|r| r.payment.height <= end_height)
            .filter(|r| !options.omit.contains(&r.payment.position))
            .collect();
        for record in &visible {
            *pages.entry(*record.receiver.as_bytes()).or_default() += 1;
        }
        let mut next_page: BTreeMap<[u8; 43], u32> = BTreeMap::new();
        let records: Vec<Record> = visible
            .into_iter()
            .map(|record| {
                let receiver = *record.receiver.as_bytes();
                let page = next_page.entry(receiver).or_default();
                let mut record = record.clone();
                record.page = *page;
                record.total = pages[&receiver];
                *page += 1;
                record
            })
            .collect();
        let end_position = chain.tree_size_at(end);
        let manifest = Manifest {
            profile: PROFILE.into(),
            genesis: GENESIS,
            start_height: ACTIVATION,
            start_parent: [0; 32],
            start_position: 0,
            end_height,
            end_hash: chain.hash_at(end).0,
            end_position,
            rows: MIN_ROWS,
            salt: [5; 32],
            records: 0,
            data_sha256: [0; 32],
            filters: Vec::new(),
            filters_sha256: [0; 32],
        };
        let snapshot =
            Snapshot::build(manifest, &records, &near.sets(now)).expect("a valid publication");
        let commitments = &chain.commitments()[..usize::try_from(end_position).expect("fits")];
        let positions = records
            .iter()
            .map(|r| u32::try_from(r.payment.position).expect("small positions"))
            .collect();
        // A chain without Ironwood outputs has no witnesses to serve.
        let witnesses = (!commitments.is_empty()).then(|| {
            WitnessSnapshot::build(&snapshot.manifest, commitments, &positions)
                .expect("witnesses build")
                .encode()
        });
        let server = Server::new(snapshot).expect("the PIR server prepares");
        let publication = Publication::new(server, witnesses).expect("a publication");
        let publications = Publications::default();
        assert!(publications.publish(publication, publications.epoch()));
        Self {
            router: router_with_publications(publications),
            requests: Mutex::new(Vec::new()),
            faults: Mutex::new(VecDeque::new()),
            bytes: Mutex::new((0, 0)),
        }
    }

    /// Request and response body bytes so far, as (sent, received).
    pub fn bytes(&self) -> (u64, u64) {
        *self.bytes.lock().unwrap()
    }

    /// Answers the next `statuses.len()` requests with these HTTP statuses instead.
    pub fn fail_next(&self, statuses: &[u16]) {
        self.faults.lock().unwrap().extend(statuses.iter().copied());
    }

    /// Encrypted lookups served so far.
    pub fn lookups(&self) -> usize {
        let requests = self.requests.lock().unwrap();
        requests
            .iter()
            .filter(|r| *r == "POST /v1/receiver/query")
            .count()
    }

    /// Row-file downloads served so far, which replace lookups for large jobs.
    pub fn row_files(&self) -> usize {
        let requests = self.requests.lock().unwrap();
        requests
            .iter()
            .filter(|r| r.starts_with("GET /v1/receiver/rows/"))
            .count()
    }

    /// Every request so far.
    pub fn requests(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    async fn send(
        &self,
        method: &str,
        url: &str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        let path = url.strip_prefix(ORIGIN).expect("requests stay on the origin");
        self.requests
            .lock()
            .unwrap()
            .push(format!("{method} {path}"));
        self.bytes.lock().unwrap().0 += body.len() as u64;
        let fault = self.faults.lock().unwrap().pop_front();
        let status = match fault {
            Some(status) => status,
            None => {
                let request = Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::from(body))
                    .expect("a valid request");
                let response = self.router.clone().oneshot(request).await.expect("routes answer");
                let status = response.status().as_u16();
                let body = axum::body::to_bytes(response.into_body(), limit)
                    .await
                    .map_err(|_| DirectoryError::Transport("response over its limit".into()))?;
                if status == 200 {
                    self.bytes.lock().unwrap().1 += body.len() as u64;
                    return Ok(body.to_vec());
                }
                status
            }
        };
        // Vizor maps 409 and 410 to a new publication and everything else to a
        // retryable transport failure.
        match status {
            409 | 410 => Err(DirectoryError::Revision),
            status => Err(DirectoryError::Transport(format!("HTTP {status}"))),
        }
    }
}

impl Transport for Directory {
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, DirectoryError> {
        self.send("GET", url, Vec::new(), limit).await
    }

    async fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        self.send("POST", url, body, limit).await
    }
}

/// A directory published on its first request, so a sweep with nothing due pays for no
/// PIR setup. An unreachable directory refuses every request.
pub struct Served<'a> {
    make: Box<dyn Fn() -> Directory + 'a>,
    directory: OnceCell<Directory>,
    reachable: bool,
}

impl<'a> Served<'a> {
    /// A directory `make` publishes when first asked, or an unreachable one.
    pub fn new(reachable: bool, make: impl Fn() -> Directory + 'a) -> Self {
        Self {
            make: Box::new(make),
            directory: OnceCell::new(),
            reachable,
        }
    }

    /// The published directory, if a request needed it.
    pub fn published(&self) -> Option<&Directory> {
        self.directory.get()
    }

    fn get_or_publish(&self) -> Result<&Directory, DirectoryError> {
        if !self.reachable {
            return Err(DirectoryError::Transport("connection refused".into()));
        }
        Ok(self.directory.get_or_init(|| (self.make)()))
    }
}

impl Transport for Served<'_> {
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, DirectoryError> {
        self.get_or_publish()?.get(url, limit).await
    }

    async fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        self.get_or_publish()?.post(url, body, limit).await
    }
}
