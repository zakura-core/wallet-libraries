//! Transport-neutral HTTP scheduling for one wallet-accepted status generation.
use crate::{
    AcceptedAnchor, Client, Error, LocalCoverageContext, Manifest, Observation, response_len,
    session_len,
};
use std::future::Future;

pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// The application owns routing, timeouts, bounded collection, and cancellation.
/// Bodies longer than `max_bytes` must not be collected; session and query
/// responses pass their exact protocol length. Non-success HTTP responses must
/// be returned as `Unavailable`.
pub trait Transport {
    fn get(
        &self,
        url: &str,
        max_bytes: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send;
    fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        max_bytes: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send;
}

fn route(origin: &str, suffix: &str) -> Result<String, Error> {
    if !origin.starts_with("https://") || origin.contains('?') || origin.contains('#') {
        return Err(Error::Malformed);
    }
    Ok(format!(
        "{}/v1/status/{suffix}",
        origin.trim_end_matches('/')
    ))
}

/// A validated manifest that the wallet has not yet bound to its chain anchor.
/// `now_ms` is the wallet clock in Unix milliseconds; it is read after each
/// response and kept for the session.
pub struct PendingClient<C> {
    origin: String,
    manifest: Manifest,
    now_ms: C,
}

impl<C: Fn() -> u64> PendingClient<C> {
    pub async fn fetch(transport: &impl Transport, origin: &str, now_ms: C) -> Result<Self, Error> {
        let url = route(origin, "init")?;
        let bytes = transport.get(&url, MAX_MANIFEST_BYTES).await?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Malformed);
        }
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        manifest.fresh(now_ms())?;
        Ok(Self {
            origin: origin.to_owned(),
            manifest,
            now_ms,
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The anchor must come from independently verified wallet chain state.
    /// Reject it before fetching the public session material, and recheck
    /// freshness once that material arrives.
    pub async fn accept(
        self,
        transport: &impl Transport,
        anchor: &AcceptedAnchor,
    ) -> Result<StatusPirClient<C>, Error> {
        self.manifest.fresh((self.now_ms)())?;
        if self.manifest.network != anchor.network
            || self.manifest.anchor_height != anchor.height
            || self.manifest.anchor_hash != anchor.hash
        {
            return Err(Error::Malformed);
        }
        let url = route(
            &self.origin,
            &format!("session/{}", hex::encode(self.manifest.id())),
        )?;
        let public = transport.get(&url, session_len()?).await?;
        self.manifest.fresh((self.now_ms)())?;
        let client = Client::new(self.manifest, &public, anchor)?;
        Ok(StatusPirClient {
            origin: self.origin,
            client,
            now_ms: self.now_ms,
        })
    }
}

/// A session bound to the wallet's accepted anchor; the only way to observe.
pub struct StatusPirClient<C> {
    origin: String,
    client: Client,
    now_ms: C,
}

impl<C: Fn() -> u64> StatusPirClient<C> {
    pub fn manifest(&self) -> &Manifest {
        self.client.manifest()
    }

    /// The caller checks cancellation before and after this operation and
    /// interrupts the transport future when its operation is cancelled.
    pub async fn observe(
        &self,
        transport: &impl Transport,
        txid: &[u8; 32],
        coverage: LocalCoverageContext,
    ) -> Result<Observation, Error> {
        let mut query = self.client.prepare(txid, coverage, (self.now_ms)())?;
        let url = route(&self.origin, "query")?;
        let response = transport
            .post(&url, std::mem::take(&mut query.body), response_len()?)
            .await?;
        self.client.decode(query, &response, (self.now_ms)())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PROTOCOL;
    use sha2::{Digest, Sha256};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Serves a valid manifest and session. The clock advances to
    /// `observed_ms` during `/init` and to `session_clock` during the session.
    struct Fixture {
        manifest: Vec<u8>,
        public: Vec<u8>,
        session_clock: u64,
        clock: AtomicU64,
        limits: Mutex<Vec<usize>>,
    }

    impl Fixture {
        fn now(&self) -> u64 {
            self.clock.load(Ordering::SeqCst)
        }
        fn limits(&self) -> Vec<usize> {
            self.limits.lock().unwrap().clone()
        }
    }

    impl Transport for Fixture {
        async fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, Error> {
            self.limits.lock().unwrap().push(max_bytes);
            if url.ends_with("/init") {
                self.clock.fetch_max(1000, Ordering::SeqCst);
                Ok(self.manifest.clone())
            } else {
                self.clock.fetch_max(self.session_clock, Ordering::SeqCst);
                Ok(self.public.clone())
            }
        }

        async fn post(
            &self,
            _url: &str,
            _body: Vec<u8>,
            max_bytes: usize,
        ) -> Result<Vec<u8>, Error> {
            self.limits.lock().unwrap().push(max_bytes);
            Err(Error::Unavailable)
        }
    }

    fn fixture(session_clock: u64) -> (Fixture, AcceptedAnchor) {
        let public = vec![0; session_len().unwrap()];
        let manifest = Manifest {
            protocol: PROTOCOL.into(),
            network: [1; 32],
            salt: [2; 32],
            generation: 1,
            recovery_epoch: 0,
            coverage_start: 10,
            anchor_height: 20,
            anchor_hash: [3; 32],
            observed_ms: 1000,
            entries: 0,
            rows_digest: [4; 32],
            public_digest: Sha256::digest(&public).into(),
        };
        (
            Fixture {
                manifest: serde_json::to_vec(&manifest).unwrap(),
                public,
                session_clock,
                clock: AtomicU64::new(500),
                limits: Mutex::new(Vec::new()),
            },
            AcceptedAnchor {
                network: manifest.network,
                height: manifest.anchor_height,
                hash: manifest.anchor_hash,
            },
        )
    }

    #[tokio::test]
    async fn reject_wrong_anchor_before_session_fetch() {
        let (transport, mut anchor) = fixture(1000);
        let pending = PendingClient::fetch(&transport, "https://status.example", || 1000)
            .await
            .unwrap();
        anchor.hash[0] ^= 1;
        assert!(matches!(
            pending.accept(&transport, &anchor).await,
            Err(Error::Malformed)
        ));
        assert_eq!(transport.limits().len(), 1);
    }

    #[tokio::test]
    async fn stale_and_non_https_init_never_fetch_session() {
        let (transport, _) = fixture(1000);
        assert!(matches!(
            PendingClient::fetch(&transport, "http://status.example", || 1000).await,
            Err(Error::Malformed)
        ));
        assert_eq!(transport.limits().len(), 0);
        assert!(matches!(
            PendingClient::fetch(&transport, "https://status.example", || 21_001).await,
            Err(Error::Stale)
        ));
        assert_eq!(transport.limits().len(), 1);
    }

    #[tokio::test]
    async fn freshness_uses_the_clock_after_init_returns() {
        let (transport, _) = fixture(1000);
        let pending =
            PendingClient::fetch(&transport, "https://status.example", || transport.now())
                .await
                .unwrap();
        assert_eq!(pending.manifest().observed_ms, 1000);
    }

    #[tokio::test]
    async fn manifest_expiring_during_session_download_is_stale() {
        let (transport, anchor) = fixture(21_001);
        let pending =
            PendingClient::fetch(&transport, "https://status.example", || transport.now())
                .await
                .unwrap();
        assert!(matches!(
            pending.accept(&transport, &anchor).await,
            Err(Error::Stale)
        ));
    }

    #[tokio::test]
    async fn session_and_query_requests_are_bounded_to_exact_lengths() {
        let (transport, anchor) = fixture(1000);
        let client = PendingClient::fetch(&transport, "https://status.example", || transport.now())
            .await
            .unwrap()
            .accept(&transport, &anchor)
            .await
            .unwrap();
        assert_eq!(
            client
                .observe(&transport, &[9; 32], LocalCoverageContext::default())
                .await,
            Err(Error::Unavailable)
        );
        assert_eq!(
            transport.limits(),
            vec![
                MAX_MANIFEST_BYTES,
                session_len().unwrap(),
                response_len().unwrap()
            ]
        );
    }
}
