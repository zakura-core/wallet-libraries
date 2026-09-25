//! Transport-neutral HTTP scheduling for one wallet-accepted status generation.
use crate::{AcceptedAnchor, Client, Error, LocalCoverageContext, Manifest, Observation};
use std::future::Future;

pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_SESSION_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// The application owns routing, timeouts, bounded collection, and cancellation.
/// Non-success HTTP responses must be returned as `Unavailable`.
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

pub struct PendingClient {
    origin: String,
    manifest: Manifest,
}

impl PendingClient {
    /// `now_ms` is read once the `/init` response has arrived.
    pub async fn fetch(
        transport: &impl Transport,
        origin: &str,
        now_ms: impl Fn() -> u64,
    ) -> Result<Self, Error> {
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
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The anchor must come from independently verified wallet chain state.
    /// Reject it before fetching the large public session material.
    pub async fn accept(
        self,
        transport: &impl Transport,
        anchor: &AcceptedAnchor,
        now_ms: u64,
    ) -> Result<StatusPirClient, Error> {
        self.manifest.fresh(now_ms)?;
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
        let public = transport.get(&url, MAX_SESSION_BYTES).await?;
        if public.len() > MAX_SESSION_BYTES {
            return Err(Error::Malformed);
        }
        let client = Client::new(self.manifest, &public, anchor)?;
        Ok(StatusPirClient {
            origin: self.origin,
            client,
        })
    }
}

pub struct StatusPirClient {
    origin: String,
    client: Client,
}

impl StatusPirClient {
    pub fn manifest(&self) -> &Manifest {
        &self.client.manifest
    }

    /// The caller checks cancellation before and after this operation and
    /// interrupts the transport future when its operation is cancelled.
    pub async fn observe(
        &self,
        transport: &impl Transport,
        txid: &[u8; 32],
        coverage: LocalCoverageContext,
        now_ms: impl Fn() -> u64,
    ) -> Result<Observation, Error> {
        let mut query = self.client.prepare(txid, coverage, now_ms())?;
        let url = route(&self.origin, "query")?;
        let response = transport
            .post(&url, std::mem::take(&mut query.body), MAX_RESPONSE_BYTES)
            .await?;
        if response.len() > MAX_RESPONSE_BYTES {
            return Err(Error::Malformed);
        }
        self.client.decode(query, &response, now_ms())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PROTOCOL;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    struct Fixture {
        manifest: Vec<u8>,
        requests: AtomicUsize,
        clock: AtomicU64,
    }

    impl Transport for Fixture {
        async fn get(&self, url: &str, _max_bytes: usize) -> Result<Vec<u8>, Error> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            if url.ends_with("/init") {
                // The server observes the manifest while the request is in flight.
                self.clock.fetch_max(1000, Ordering::SeqCst);
                Ok(self.manifest.clone())
            } else {
                Err(Error::Unavailable)
            }
        }

        async fn post(
            &self,
            _url: &str,
            _body: Vec<u8>,
            _max_bytes: usize,
        ) -> Result<Vec<u8>, Error> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            Err(Error::Unavailable)
        }
    }

    fn fixture() -> (Fixture, AcceptedAnchor) {
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
            public_digest: [5; 32],
        };
        (
            Fixture {
                manifest: serde_json::to_vec(&manifest).unwrap(),
                requests: AtomicUsize::new(0),
                clock: AtomicU64::new(500),
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
        let (transport, mut anchor) = fixture();
        let pending = PendingClient::fetch(&transport, "https://status.example", || 1000)
            .await
            .unwrap();
        anchor.hash[0] ^= 1;
        assert!(matches!(
            pending.accept(&transport, &anchor, 1000).await,
            Err(Error::Malformed)
        ));
        assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stale_and_non_https_init_never_fetch_session() {
        let (transport, _) = fixture();
        assert!(matches!(
            PendingClient::fetch(&transport, "http://status.example", || 1000).await,
            Err(Error::Malformed)
        ));
        assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
        assert!(matches!(
            PendingClient::fetch(&transport, "https://status.example", || 11_001).await,
            Err(Error::Stale)
        ));
        assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn freshness_uses_the_clock_after_init_returns() {
        let (transport, _) = fixture();
        let pending = PendingClient::fetch(&transport, "https://status.example", || {
            transport.clock.load(Ordering::SeqCst)
        })
        .await
        .unwrap();
        assert_eq!(pending.manifest().observed_ms, 1000);
    }
}
