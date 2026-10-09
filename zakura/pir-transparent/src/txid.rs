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
    client: Mutex<TxidDisplayClient>,
    /// The digest of the map the client held after its last request.
    map: Mutex<Option<[u8; 32]>>,
    map_checked_at: Mutex<Option<SystemTime>>,
}

impl Default for TxidDisplayService {
    fn default() -> Self {
        Self::new()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl TxidDisplayService {
    pub fn new() -> Self {
        Self {
            client: Mutex::new(TxidDisplayClient::new()),
            map: Mutex::new(None),
            map_checked_at: Mutex::new(None),
        }
    }

    /// Looks up `txid` (internal byte order) mined at `mined_height` through
    /// `exchange`; see [`TxidDisplayClient::lookup`]. `cancel` is polled
    /// before every request and while another lookup holds the client.
    ///
    /// A service that publishes a display this client does not support is
    /// asked again by the next lookup: after [`TxidLookup::Unsupported`] the
    /// client keeps only its derived native profiles, so a service that comes
    /// to support it is found once the wallet retries.
    pub fn lookup(
        &self,
        exchange: &impl HttpExchange,
        txid: [u8; 32],
        mined_height: u64,
        cancel: &dyn Fn() -> bool,
    ) -> Result<TxidLookup, TxidError> {
        self.with_client(cancel, |client| {
            let found = client.lookup(&mut TxidHttp::new(exchange), txid, mined_height, cancel);
            if matches!(found, Ok(TxidLookup::Unsupported)) {
                *client = TxidDisplayClient::with_profiles(client.profiles());
            }
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
        self.with_client(cancel, |client| {
            client.refresh_map(&mut TxidHttp::new(exchange), cancel)
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
        call: impl FnOnce(&mut TxidDisplayClient) -> Result<T, TxidError>,
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
        *lock(&self.map) = client.map_sha256().and_then(map_sha256);
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

    /// An init this client does not support is not kept: the next lookup asks
    /// for the init again.
    #[test]
    fn an_unsupported_service_is_asked_again() {
        let init = serde_json::to_vec(&serde_json::json!({
            "schema": "transparent-txid-display-v0",
            "codec": "transparent-txid-display-v0",
            "bucket_domain": "",
            "native_schema": "",
            "geometries": [],
        }))
        .unwrap();
        let exchange = Counting {
            answer: move |_: &HttpRequest| HttpReply {
                status: 200,
                body: init.clone(),
                ..HttpReply::default()
            },
            sent: AtomicUsize::new(0),
        };
        let service = TxidDisplayService::new();
        for sent in 1..=2 {
            assert_eq!(
                service.lookup(&exchange, [7; 32], 3_460_000, &|| false),
                Ok(TxidLookup::Unsupported)
            );
            assert_eq!(exchange.sent.load(Ordering::SeqCst), sent);
        }
    }

    #[test]
    fn a_waiting_lookup_stops_at_cancellation() {
        let service = Arc::new(TxidDisplayService::new());
        let held = service.client.lock().unwrap();
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
