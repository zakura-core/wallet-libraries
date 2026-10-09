//! One txid display client per origin, shared by every lookup in a process.

use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, SystemTime};

use transparent_txid_client::{TxidDisplayClient, TxidError, TxidLookup};

use crate::display::map_sha256;
use crate::http::{HttpExchange, TxidHttp};

/// How often a lookup polls for the client another lookup holds.
const CLIENT_WAIT_STEP: Duration = Duration::from_millis(5);

/// The txid display client of one origin, for every lookup of a process.
///
/// `Send + Sync`: keep one per origin for the process's life, so the init
/// document, the map, manifests, setups and the costly native profiles are
/// derived once. Lookups take turns on the client; one waits for another only
/// while it is wanted. The map digest and the time of the last map check are
/// kept outside the client, so reading them never waits for a lookup, even
/// one its caller abandoned.
pub struct TxidDisplayService {
    client: Mutex<Client>,
    /// The digest of the map the client held after its last request.
    map: Mutex<Option<[u8; 32]>>,
    map_checked_at: Mutex<Option<SystemTime>>,
}

impl Default for TxidDisplayService {
    fn default() -> Self {
        Self::new()
    }
}

/// The client, and whether its last lookup found the display unsupported.
struct Client {
    client: TxidDisplayClient,
    unsupported: bool,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl TxidDisplayService {
    pub fn new() -> Self {
        Self {
            client: Mutex::new(Client {
                client: TxidDisplayClient::new(),
                unsupported: false,
            }),
            map: Mutex::new(None),
            map_checked_at: Mutex::new(None),
        }
    }

    /// Looks up `txid` (internal byte order) mined at `mined_height` through
    /// `exchange`; see [`TxidDisplayClient::lookup`]. `cancel` is polled
    /// before every request and while another lookup holds the client.
    ///
    /// A service that publishes a display this client does not support is
    /// asked again by the next lookup, so one that comes to support it is
    /// found once the wallet retries. The client keeps an unsupported init
    /// until a map is accepted, so after [`TxidLookup::Unsupported`] the next
    /// lookup first fetches the map, which drops that init and still refuses
    /// a map of another chain than the client pinned.
    pub fn lookup(
        &self,
        exchange: &impl HttpExchange,
        txid: [u8; 32],
        mined_height: u64,
        cancel: &dyn Fn() -> bool,
    ) -> Result<TxidLookup, TxidError> {
        self.with_client(cancel, |state| {
            let mut http = TxidHttp::new(exchange);
            if state.unsupported {
                state.client.refresh_map(&mut http, cancel)?;
                state.unsupported = false;
            }
            let found = state.client.lookup(&mut http, txid, mined_height, cancel);
            state.unsupported = matches!(found, Ok(TxidLookup::Unsupported));
            found
        })
    }

    /// Fetches the recent map now and returns its digest; see
    /// [`TxidDisplayClient::refresh_map`].
    pub fn refresh_map(
        &self,
        exchange: &impl HttpExchange,
        cancel: &dyn Fn() -> bool,
    ) -> Result<[u8; 32], TxidError> {
        self.with_client(cancel, |state| {
            let refreshed = state
                .client
                .refresh_map(&mut TxidHttp::new(exchange), cancel);
            // An accepted map drops an unsupported init.
            state.unsupported &= refreshed.is_err();
            refreshed
        })
    }

    /// The digest of the map the client held after its last request, without
    /// waiting for one in flight.
    pub fn map_sha256(&self) -> Option<[u8; 32]> {
        *lock(&self.map)
    }

    /// When a map check last started, if ever.
    pub fn map_checked_at(&self) -> Option<SystemTime> {
        *lock(&self.map_checked_at)
    }

    /// Records a map check starting at `now`. Record it before the check, so a
    /// failed or abandoned check counts too.
    pub fn map_check_started(&self, now: SystemTime) {
        *lock(&self.map_checked_at) = Some(now);
    }

    /// Runs `call` once the client is free, unless `cancel` holds first, and
    /// records the map digest the client holds afterwards.
    fn with_client<T>(
        &self,
        cancel: &dyn Fn() -> bool,
        call: impl FnOnce(&mut Client) -> Result<T, TxidError>,
    ) -> Result<T, TxidError> {
        let mut client = loop {
            match self.client.try_lock() {
                Ok(client) => break client,
                Err(TryLockError::Poisoned(client)) => break client.into_inner(),
                Err(TryLockError::WouldBlock) if cancel() => return Err(TxidError::Cancelled),
                Err(TryLockError::WouldBlock) => std::thread::sleep(CLIENT_WAIT_STEP),
            }
        };
        let result = call(&mut client);
        *lock(&self.map) = client.client.map_sha256().and_then(map_sha256);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpFailure, HttpReply, HttpRequest};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn assert_send_sync<T: Send + Sync>() {}

    struct Counting<A> {
        answer: A,
        sent: AtomicUsize,
    }

    impl<A: Fn(&HttpRequest) -> HttpReply + Sync> HttpExchange for Counting<A> {
        fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
            self.sent.fetch_add(1, Ordering::SeqCst);
            Ok((self.answer)(request))
        }
    }

    #[test]
    fn the_service_is_shared_across_threads() {
        assert_send_sync::<TxidDisplayService>();
    }

    /// Every request, by path, each answered by `answer`.
    struct Recording<A> {
        answer: A,
        paths: Mutex<Vec<String>>,
    }

    impl<A: Fn(&HttpRequest) -> HttpReply + Sync> HttpExchange for Recording<A> {
        fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
            lock(&self.paths).push(request.path.clone());
            Ok((self.answer)(request))
        }
    }

    fn unsupported_init() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": "transparent-txid-display-v0",
            "codec": "transparent-txid-display-v0",
            "bucket_domain": "",
            "native_schema": "",
            "geometries": [],
        }))
        .unwrap()
    }

    /// An init this client does not support is not kept: the next lookup
    /// fetches the map first, which drops it.
    #[test]
    fn an_unsupported_service_is_asked_again() {
        let init = unsupported_init();
        let exchange = Recording {
            answer: move |_: &HttpRequest| HttpReply {
                status: 200,
                body: init.clone(),
                ..HttpReply::default()
            },
            paths: Mutex::default(),
        };
        let service = TxidDisplayService::new();
        assert_eq!(
            service.lookup(&exchange, [7; 32], 3_460_000, &|| false),
            Ok(TxidLookup::Unsupported)
        );
        assert_eq!(*lock(&exchange.paths), ["/v1/txid/init"]);
        // This service answers the map with its init, which no map is.
        assert!(
            service
                .lookup(&exchange, [7; 32], 3_460_000, &|| false)
                .is_err()
        );
        assert_eq!(lock(&exchange.paths)[1], "/v1/txid/map");
    }

    /// Asking again keeps the chain the client pinned: after an unsupported
    /// display, a map of another genesis is still refused, and the first
    /// chain's publication is found once it is supported.
    #[cfg(feature = "testing")]
    #[test]
    fn an_unsupported_reset_keeps_the_chain_pin() {
        use crate::testing::TxidPublication;
        use std::sync::atomic::AtomicU8;
        use transparent_txid_client::ProtocolKind;

        let publication = TxidPublication::new(3_000_000, 3_000_009);
        let phase = AtomicU8::new(0);
        let exchange = Recording {
            answer: |request: &HttpRequest| {
                let reply = publication.answer(request.method, &request.path, &request.body);
                match (phase.load(Ordering::SeqCst), request.path.as_str()) {
                    (0, "/v1/txid/init") => HttpReply {
                        status: 200,
                        body: unsupported_init(),
                        ..HttpReply::default()
                    },
                    // The same map for another genesis block.
                    (1, "/v1/txid/map") => {
                        let body = String::from_utf8(reply.body)
                            .unwrap()
                            .replace(&"ee".repeat(32), &"ab".repeat(32))
                            .into_bytes();
                        HttpReply {
                            map_sha256: Some(hex::encode(sha2::Sha256::digest(&body))),
                            body,
                            ..reply
                        }
                    }
                    _ => reply,
                }
            },
            paths: Mutex::default(),
        };
        use sha2::Digest as _;
        let service = TxidDisplayService::new();
        let never = || false;
        // The first map pins the chain; the service's display is unsupported.
        service.refresh_map(&exchange, &never).unwrap();
        assert_eq!(
            service.lookup(&exchange, [7; 32], 3_000_005, &never),
            Ok(TxidLookup::Unsupported)
        );
        phase.store(1, Ordering::SeqCst);
        assert_eq!(
            service.lookup(&exchange, [7; 32], 3_000_005, &never),
            Err(TxidError::Protocol(ProtocolKind::Map))
        );
        phase.store(2, Ordering::SeqCst);
        assert_eq!(
            service.lookup(&exchange, [7; 32], 3_000_005, &never),
            Ok(TxidLookup::Absent)
        );
    }

    #[test]
    fn a_waiting_lookup_stops_at_cancellation() {
        let service = Arc::new(TxidDisplayService::new());
        let held = lock(&service.client);
        let cancelled = AtomicBool::new(false);
        let exchange = Counting {
            answer: |_: &HttpRequest| HttpReply::default(),
            sent: AtomicUsize::new(0),
        };
        std::thread::scope(|scope| {
            let waiting = scope.spawn(|| {
                service.lookup(&exchange, [7; 32], 3_460_000, &|| {
                    cancelled.load(Ordering::SeqCst)
                })
            });
            std::thread::sleep(Duration::from_millis(20));
            cancelled.store(true, Ordering::SeqCst);
            assert_eq!(waiting.join().unwrap(), Err(TxidError::Cancelled));
        });
        drop(held);
        assert_eq!(exchange.sent.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn map_reads_never_wait_for_the_client() {
        let service = TxidDisplayService::new();
        let _held = service.client.lock().unwrap();
        assert_eq!(service.map_sha256(), None);
        assert_eq!(service.map_checked_at(), None);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
        service.map_check_started(now);
        assert_eq!(service.map_checked_at(), Some(now));
    }
}
