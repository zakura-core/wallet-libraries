use receiver_directory::blocks::{Batch, BlockFilter, BlockId, Head, MAX_BATCH_BYTES};
use receiver_pir::{
    transport::{DirectoryClient, Transport},
    Error,
};
use std::{
    cell::RefCell,
    future::Future,
    task::{Context, Poll, Waker},
};

/// Serves owned response bytes and records the exact public URL and enforced body bound.
struct Http {
    body: Vec<u8>,
    calls: RefCell<Vec<(String, usize)>>,
}
impl Transport for Http {
    /// Returns the fixture while retaining the requested response bound for assertion.
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, Error> {
        self.calls.borrow_mut().push((url.to_owned(), limit));
        Ok(self.body.clone())
    }
    /// Rejects unexpected private requests; fetching hints must not open a PIR query.
    async fn post(&self, _: &str, _: Vec<u8>, _: usize) -> Result<Vec<u8>, Error> {
        panic!("unexpected PIR request")
    }
}

/// Drives these immediately ready transport futures without adding an async runtime.
fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("fixture unexpectedly suspended"),
    }
}

/// Binds public metadata to the configured network and rejects oversized transport bodies.
#[test]
fn head_is_bounded_and_network_checked() {
    let head = Head {
        genesis: [9; 32],
        revision: 2,
        first: 1,
        tip: BlockId {
            height: 1,
            hash: [1; 32],
        },
    };
    let http = Http {
        body: serde_json::to_vec(&head).unwrap(),
        calls: RefCell::default(),
    };
    assert_eq!(
        ready(DirectoryClient::fetch_block_head(
            "https://receiver/",
            &http,
            &[9; 32]
        ))
        .unwrap(),
        head
    );
    assert_eq!(
        http.calls.borrow()[0],
        (
            "https://receiver/v1/receiver/block-filters/head".to_owned(),
            16 * 1024
        )
    );
    assert!(ready(DirectoryClient::fetch_block_head(
        "https://receiver",
        &http,
        &[8; 32]
    ))
    .is_err());
    let too_large = Http {
        body: vec![0; 16 * 1024 + 1],
        calls: RefCell::default(),
    };
    assert!(ready(DirectoryClient::fetch_block_head(
        "https://receiver",
        &too_large,
        &[9; 32]
    ))
    .is_err());
}

/// A real encoded filter travels through the public route without any receiver in the URL.
#[test]
fn batch_checks_session_range_and_payload() {
    let receiver = [7; 43];
    let head = Head {
        genesis: [9; 32],
        revision: 2,
        first: 1,
        tip: BlockId {
            height: 1,
            hash: [1; 32],
        },
    };
    let batch = Batch::new(
        head.genesis,
        2,
        vec![BlockFilter::build(&head.genesis, head.tip, head.genesis, [&receiver]).unwrap()],
    )
    .unwrap();
    let http = Http {
        body: batch.encode().unwrap(),
        calls: RefCell::default(),
    };
    let got = ready(DirectoryClient::fetch_block_batch(
        "https://receiver/",
        &http,
        &head,
        1,
        4,
    ))
    .unwrap();
    assert_eq!(got.matches(0, &[receiver]).unwrap(), [true]);
    assert_eq!(
        http.calls.borrow()[0],
        (
            "https://receiver/v1/receiver/block-filters/2/1/4".to_owned(),
            MAX_BATCH_BYTES
        )
    );
    assert!(ready(DirectoryClient::fetch_block_batch(
        "https://receiver",
        &http,
        &head,
        0,
        4
    ))
    .is_err());
    assert_eq!(
        http.calls.borrow().len(),
        1,
        "invalid request never reaches transport"
    );
    let mut changed = head;
    changed.revision = 3;
    assert!(ready(DirectoryClient::fetch_block_batch(
        "https://receiver",
        &http,
        &changed,
        1,
        4
    ))
    .is_err());
}
