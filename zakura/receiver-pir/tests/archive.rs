//! Transport contracts use caller routing and bind every response before returning it.
mod common;
use receiver_directory::{
    archive::{Coverage, Head, Index, Page, SeenRef},
    blocks::{BlockFilter, BlockId},
    seen::SeenSet,
};
use receiver_pir::{
    archive::ArchiveClient, transport::Transport, Error, Manifest, MIN_ROWS, PROTOCOL,
};
use std::{
    cell::RefCell,
    future::Future,
    task::{Context, Poll, Waker},
};

/// A caller transport records the exact public URL and streaming bound.
struct Http {
    body: Vec<u8>,
    requests: RefCell<Vec<(String, usize)>>,
}
impl Http {
    /// Supplies a deliberately unchecked body so the client must enforce decoding bounds too.
    fn new(body: Vec<u8>) -> Self {
        Self {
            body,
            requests: RefCell::new(vec![]),
        }
    }
}
impl Transport for Http {
    /// Returns the fixture body and records the requested limit.
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, Error> {
        self.requests.borrow_mut().push((url.into(), limit));
        Ok(self.body.clone())
    }
    /// Public archive reads must never POST a receiver or query.
    async fn post(&self, _: &str, _: Vec<u8>, _: usize) -> Result<Vec<u8>, Error> {
        panic!("unexpected POST")
    }
}

/// Polls fixtures that complete immediately without installing a networking runtime.
fn ready<F: Future>(future: F) -> F::Output {
    match std::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("unexpected pending fixture"),
    }
}

/// Supplies one complete canonical page and its head.
fn archive() -> (Head, Page, Index) {
    let page = Page::new(
        [2; 32],
        vec![BlockFilter::build(
            [1; 32],
            BlockId {
                height: 100,
                hash: [3; 32],
            },
            [],
        )
        .unwrap()],
    )
    .unwrap();
    let mut index = Index::default();
    index.update(0, Some(page.digest().unwrap())).unwrap();
    (
        Head {
            genesis: [1; 32],
            archive: [9; 32],
            epoch: 1,
            first_height: 100,
            frontier: BlockId {
                height: 100,
                hash: [3; 32],
            },
            index_root: index.root(),
            seen: None,
        },
        page,
        index,
    )
}

/// Head and page requests carry no recipient, and stale bytes fail under a new root.
#[test]
fn head_and_page_are_bounded_and_pinned() {
    let (head, page, index) = archive();
    let http = Http::new(head.encode().unwrap());
    assert_eq!(
        ready(ArchiveClient::head("https://example.test/", &http)).unwrap(),
        head
    );
    assert_eq!(
        http.requests.borrow()[0],
        ("https://example.test/v1/receiver/archive/head".into(), 1024)
    );
    let http = Http::new(index.proof(0).unwrap().encode(&page).unwrap());
    assert_eq!(
        ready(ArchiveClient::page(
            "https://example.test/",
            &http,
            &head,
            0
        ))
        .unwrap(),
        page
    );
    assert!(http.requests.borrow()[0]
        .0
        .ends_with(&format!("/range/{}/0", hex::encode(head.digest().unwrap()))));
    let changed = Head {
        index_root: [4; 32],
        ..head.clone()
    };
    assert!(ready(ArchiveClient::page(
        "https://example.test",
        &http,
        &changed,
        0
    ))
    .is_err());
    let oversized = Http::new(vec![0; receiver_directory::archive::MAX_HEAD_BYTES + 1]);
    assert!(ready(ArchiveClient::head("https://example.test", &oversized)).is_err());
}

/// Unfinished provider history is pending without a request, never an empty seen set.
#[test]
fn seen_absence_and_corrupt_bodies_are_not_empty() {
    let (mut head, _, _) = archive();
    let set = SeenSet::new(head.genesis, 100).union([&[3; 43]]);
    let http = Http::new(set.encode().unwrap());
    assert!(ready(ArchiveClient::seen("https://example.test", &http, &head)).is_err());
    assert!(http.requests.borrow().is_empty());
    head.seen = Some(SeenRef {
        digest: set.digest().unwrap(),
        since_unix: 100,
        until_unix: 100,
    });
    assert_eq!(
        ready(ArchiveClient::seen("https://example.test", &http, &head)).unwrap(),
        set
    );
    assert!(http.requests.borrow()[0]
        .0
        .ends_with(&hex::encode(set.digest().unwrap())));
    let corrupt = Http::new(SeenSet::new(head.genesis, 100).encode().unwrap());
    assert!(ready(ArchiveClient::seen("https://example.test", &corrupt, &head)).is_err());
}

/// Coverage binds the actual session geometry and separates correction epochs in its URL.
#[test]
fn coverage_pins_session_and_epoch() {
    let (mut head, _, _) = archive();
    head.frontier.height = 101;
    let manifest = Manifest {
        protocol: PROTOCOL.into(),
        directory: common::manifest(MIN_ROWS),
        public_digest: [7; 32],
    };
    let coverage = Coverage {
        genesis: head.genesis,
        archive: head.archive,
        epoch: head.epoch,
        session: manifest.id().unwrap(),
        first_height: 100,
        frontier: head.frontier,
    };
    let http = Http::new(coverage.encode().unwrap());
    assert_eq!(
        ready(ArchiveClient::coverage(
            "https://example.test",
            &http,
            &manifest,
            &head
        ))
        .unwrap(),
        coverage
    );
    assert!(http.requests.borrow()[0].0.ends_with(&format!(
        "/coverage/{}/1/{}",
        hex::encode(head.archive),
        hex::encode(coverage.session)
    )));
    head.epoch += 1;
    assert!(ready(ArchiveClient::coverage(
        "https://example.test",
        &http,
        &manifest,
        &head
    ))
    .is_err());
    head.epoch -= 1;
    for wrong in [
        Coverage {
            session: [1; 32],
            ..coverage.clone()
        },
        Coverage {
            first_height: 99,
            ..coverage.clone()
        },
        Coverage {
            frontier: BlockId {
                hash: [8; 32],
                ..coverage.frontier
            },
            ..coverage
        },
    ] {
        assert!(ready(ArchiveClient::coverage(
            "https://example.test",
            &Http::new(wrong.encode().unwrap()),
            &manifest,
            &head
        ))
        .is_err());
    }
}
