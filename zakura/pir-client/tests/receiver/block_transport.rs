use std::{
    cell::RefCell,
    future::Future,
    task::{Context, Poll, Waker},
};
use zakura_pir_client::receiver::{
    blocks::{BlockId, Head, HeightSet, MAX_RANGE_BLOCKS, MAX_RANGE_BYTES, Range, RangeSize},
    session::Error,
    transport::{Inventories, Transport},
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

/// The served history at the root of these tests: heights 1 through 1 at revision 2.
fn head() -> Head {
    Head {
        genesis: [9; 32],
        revision: 2,
        first: 1,
        tip: BlockId {
            height: 1,
            hash: [1; 32],
        },
    }
}

/// Binds the head to the configured network and rejects oversized transport bodies.
#[test]
fn head_is_bounded_and_network_checked() {
    let http = Http {
        body: serde_json::to_vec(&head()).unwrap(),
        calls: RefCell::default(),
    };
    assert_eq!(
        ready(Inventories::block_head(
            "https://receiver/",
            &http,
            &[9; 32]
        ))
        .unwrap(),
        head()
    );
    assert_eq!(
        http.calls.borrow()[0],
        (
            "https://receiver/receiver/v1/block-filters/head".to_owned(),
            16 * 1024
        )
    );
    assert!(ready(Inventories::block_head("https://receiver", &http, &[8; 32])).is_err());
    let too_large = Http {
        body: vec![0; 16 * 1024 + 1],
        calls: RefCell::default(),
    };
    assert!(
        ready(Inventories::block_head(
            "https://receiver",
            &too_large,
            &[9; 32]
        ))
        .is_err()
    );
}

/// One range request covers the gap, names no receiver, and decodes into matches.
#[test]
fn range_checks_session_and_matches() {
    let receiver = [7; 43];
    let head = head();
    let set = HeightSet::build(&head.genesis, 1, [&receiver])
        .unwrap()
        .unwrap();
    let http = Http {
        body: Range::new(2, 1, 1, head.genesis, head.tip.hash, vec![set])
            .unwrap()
            .encode()
            .unwrap(),
        calls: RefCell::default(),
    };
    let base = "https://receiver/";
    let range = ready(Inventories::block_range(
        base,
        &http,
        &head,
        1,
        MAX_RANGE_BLOCKS,
    ))
    .unwrap();
    assert_eq!(
        http.calls.borrow()[0],
        (
            format!("https://receiver/receiver/v1/block-filters/2/1/{MAX_RANGE_BLOCKS}"),
            MAX_RANGE_BYTES
        )
    );
    assert_eq!(range.matches(&head.genesis, &[receiver]), [(1, 0)]);
    for (from, limit) in [(0, 4), (1, 0), (1, MAX_RANGE_BLOCKS + 1), (2, 1)] {
        assert!(ready(Inventories::block_range(base, &http, &head, from, limit)).is_err());
    }
    assert_eq!(
        http.calls.borrow().len(),
        1,
        "invalid request never reaches transport"
    );
    let changed = Head {
        revision: 3,
        ..head
    };
    assert!(ready(Inventories::block_range(base, &http, &changed, 1, 4)).is_err());
}

/// A size answer must belong to the captured revision and start exactly where asked.
#[test]
fn range_size_is_bound_to_the_head() {
    let head = head();
    let answer = |size: RangeSize| Http {
        body: serde_json::to_vec(&size).unwrap(),
        calls: RefCell::default(),
    };
    let good = answer(RangeSize {
        revision: 2,
        from: 1,
        bytes: 99,
    });
    let base = "https://receiver/";
    assert_eq!(
        ready(Inventories::range_size(base, &good, &head, 1))
            .unwrap()
            .bytes,
        99
    );
    assert_eq!(
        good.calls.borrow()[0].0,
        "https://receiver/receiver/v1/block-filters/size/2/1"
    );
    for bad in [
        RangeSize {
            revision: 1,
            from: 1,
            bytes: 0,
        },
        RangeSize {
            revision: 2,
            from: 0,
            bytes: 0,
        },
    ] {
        assert!(ready(Inventories::range_size(base, &answer(bad), &head, 1)).is_err());
    }
    let taller = Head {
        tip: BlockId {
            height: 5,
            hash: [5; 32],
        },
        ..head
    };
    ready(Inventories::range_size(base, &good, &taller, 1)).unwrap();
    assert!(
        ready(Inventories::range_size(base, &good, &taller, 2)).is_err(),
        "starts before the request"
    );
}

/// A server base with a path keeps it for every block-hint route, and a base that is not
/// an HTTP endpoint fails before any request.
#[test]
fn block_routes_stay_below_the_configured_base_path() {
    let http = Http {
        body: serde_json::to_vec(&head()).unwrap(),
        calls: RefCell::default(),
    };
    let base = "http://127.0.0.1:8080/edge/";
    ready(Inventories::block_head(base, &http, &[9; 32])).unwrap();
    // The body is not a range; only the requested URL matters here.
    assert!(ready(Inventories::block_range(base, &http, &head(), 1, 4)).is_err());
    let urls: Vec<_> = http
        .calls
        .borrow()
        .iter()
        .map(|(url, _)| url.clone())
        .collect();
    assert_eq!(
        urls,
        [
            "http://127.0.0.1:8080/edge/receiver/v1/block-filters/head",
            "http://127.0.0.1:8080/edge/receiver/v1/block-filters/2/1/4",
        ]
    );
    assert!(matches!(
        ready(Inventories::block_head("receiver.example", &http, &[9; 32])),
        Err(Error::Endpoint(_))
    ));
    assert_eq!(http.calls.borrow().len(), 2);
}
