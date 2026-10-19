//! Fetching the catalog and the objects it names over a caller's transport.
mod common;
use common::manifest;
use receiver_directory::{
    catalog::{BucketIndex, CatalogHead},
    paid::{PaidSet, Span, BUCKET_BLOCKS},
    seen::SeenSet,
    Hash,
};
use receiver_pir::{
    transport::{DirectoryClient, Transport},
    Error, Manifest, MIN_ROWS, PROTOCOL,
};
use std::{
    collections::HashMap,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

const ORIGIN: &str = "https://directory.example/";

/// Static objects by URL.
struct Objects(HashMap<String, Vec<u8>>);

impl Transport for Objects {
    /// The object at `url`, or a transport error if there is none or it exceeds `limit`.
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, Error> {
        match self.0.get(url) {
            Some(body) if body.len() <= limit => Ok(body.clone()),
            Some(_) => Err(Error::Transport("over the limit".into())),
            None => Err(Error::Transport(format!("no object at {url}"))),
        }
    }

    /// Never called: objects are only fetched.
    async fn post(&self, _: &str, _: Vec<u8>, _: usize) -> Result<Vec<u8>, Error> {
        unreachable!("objects are only fetched")
    }
}

/// Runs `future`, which [`Objects`] never leaves pending.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("pending"),
    }
}

/// The URL of the object with `digest` on `route`.
fn url(route: &str, digest: &Hash) -> String {
    format!(
        "https://directory.example/v1/receiver/{route}/{}",
        hex::encode(digest)
    )
}

/// A session manifest committing to a catalog of two buckets from 4,992, its objects
/// served at their routes.
fn publication() -> (Manifest, CatalogHead, Objects) {
    let mut directory = manifest(MIN_ROWS);
    let genesis = directory.genesis;
    let span = |start: u32| Span {
        start,
        start_hash: [start as u8; 32],
        end: start + BUCKET_BLOCKS,
        end_hash: [(start + BUCKET_BLOCKS) as u8; 32],
    };
    let buckets = [
        PaidSet::build(genesis, 2, span(4992), &[[1; 43], [2; 43]]).unwrap(),
        PaidSet::build(genesis, 2, span(5040), []).unwrap(),
    ];
    let index = BucketIndex::new(
        genesis,
        buckets
            .iter()
            .map(|b| (b.span().start, b.digest()))
            .collect(),
    )
    .unwrap();
    let paid = PaidSet::build(
        genesis,
        2,
        Span {
            start: 0,
            start_hash: genesis,
            ..span(5040)
        },
        &[[1; 43], [2; 43], [3; 43]],
    )
    .unwrap();
    let seen = SeenSet::new(genesis, 10).union(&[[4; 43]]);
    let head = CatalogHead {
        genesis,
        epoch: 2,
        oldest_start: 4992,
        latest_end: 5088,
        paid: paid.digest(),
        seen: seen.digest().unwrap(),
        index: index.digest(),
    };
    directory.catalog_sha256 = head.digest().unwrap();
    let mut objects = HashMap::from([
        (
            url("catalog", &head.digest().unwrap()),
            head.encode().unwrap(),
        ),
        (url("bucket-index", &index.digest()), index.encode()),
        (url("paid", &paid.digest()), paid.encode()),
        (url("seen", &seen.digest().unwrap()), seen.encode().unwrap()),
    ]);
    for bucket in &buckets {
        let route = format!("bucket/{}", bucket.span().start);
        objects.insert(url(&route, &bucket.digest()), bucket.encode());
    }
    let manifest = Manifest {
        protocol: PROTOCOL.into(),
        directory,
        public_digest: [0; 32],
    };
    (manifest, head, Objects(objects))
}

/// The catalog, index, every bucket, the cumulative set and the seen set are fetched
/// from their routes and pass their checks.
#[test]
fn every_object_is_fetched_by_digest_and_checked() {
    let (manifest, head, objects) = publication();
    // The catalog digest keeps the session manifest within its bound.
    manifest.validate().unwrap();
    let fetched = ready(DirectoryClient::fetch_catalog(ORIGIN, &objects, &manifest)).unwrap();
    assert_eq!(fetched, head);
    let index = ready(DirectoryClient::fetch_bucket_index(ORIGIN, &objects, &head)).unwrap();
    for (start, digest) in index.iter() {
        let bucket = ready(DirectoryClient::fetch_bucket(
            ORIGIN, &objects, &head, &index, start,
        ))
        .unwrap();
        assert_eq!(bucket.digest(), digest);
    }
    let paid = ready(DirectoryClient::fetch_paid(ORIGIN, &objects, &head)).unwrap();
    assert_eq!(paid.matches(&[[3; 43]]), [true]);
    let seen = ready(DirectoryClient::fetch_seen(ORIGIN, &objects, &head)).unwrap();
    assert_eq!(seen.matches(&[[4; 43]]), [true]);
}

/// An unlisted start, bytes that are not the named object and a catalog for another
/// network are refused.
#[test]
fn objects_that_do_not_match_their_digest_or_network_are_refused() {
    let (manifest, head, mut objects) = publication();
    let index = ready(DirectoryClient::fetch_bucket_index(ORIGIN, &objects, &head)).unwrap();

    // A start the index does not list is outside the catalog's coverage.
    assert!(matches!(
        ready(DirectoryClient::fetch_bucket(
            ORIGIN, &objects, &head, &index, 5088
        )),
        Err(Error::Directory(receiver_directory::Error::Coverage))
    ));

    // Bytes other than the named object are refused before decoding.
    let paid_url = url("paid", &head.paid);
    let seen_bytes = objects.0[&url("seen", &head.seen)].clone();
    objects.0.insert(paid_url, seen_bytes);
    assert!(matches!(
        ready(DirectoryClient::fetch_paid(ORIGIN, &objects, &head)),
        Err(Error::Malformed)
    ));

    // A catalog for another network is refused.
    let mut foreign = manifest.clone();
    foreign.directory.genesis = [9; 32];
    assert!(matches!(
        ready(DirectoryClient::fetch_catalog(ORIGIN, &objects, &foreign)),
        Err(Error::Directory(receiver_directory::Error::Coverage))
    ));
}

/// An index listing one digest at two starts cannot make a bucket fetched for the
/// second start return the first start's interval.
#[test]
fn an_aliased_index_cannot_return_another_interval() {
    let (_, head, mut objects) = publication();
    let index = ready(DirectoryClient::fetch_bucket_index(ORIGIN, &objects, &head)).unwrap();
    let (first, digest) = index.iter().next().unwrap();
    let aliased =
        BucketIndex::new(head.genesis, vec![(first, digest), (first + 48, digest)]).unwrap();
    let head = CatalogHead {
        index: aliased.digest(),
        ..head
    };
    head.check_index(&aliased).unwrap();
    let bytes = objects.0[&url(&format!("bucket/{first}"), &digest)].clone();
    objects
        .0
        .insert(url(&format!("bucket/{}", first + 48), &digest), bytes);
    let fetched = ready(DirectoryClient::fetch_bucket(
        ORIGIN, &objects, &head, &aliased, first,
    ))
    .unwrap();
    assert_eq!(fetched.span().start, first);
    assert!(matches!(
        ready(DirectoryClient::fetch_bucket(
            ORIGIN,
            &objects,
            &head,
            &aliased,
            first + 48
        )),
        Err(Error::Malformed)
    ));
}
