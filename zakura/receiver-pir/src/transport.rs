//! Receiver discovery over a caller-supplied, bounded transport.
use crate::{
    AcceptedCoverage, Client, Error, MAX_MANIFEST_BYTES, Manifest, check_next, public_bytes,
    response_bytes,
};
use receiver_directory::{
    Payment, Receiver,
    snapshot::{ROW_BYTES, lookup_row, row_for},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Hosts supply their route policy, cancellation, and timeout for every request.
/// Enforce `limit` while streaming, reject non-success responses, and map HTTP
/// 410 to [`Error::Revision`]. Do not follow redirects or retry in cleartext.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// GET `url`, returning a body of at most `limit` bytes.
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, Error>;
    /// POST `body` to `url`, returning a body of at most `limit` bytes.
    async fn post(&self, url: &str, body: Vec<u8>, limit: usize) -> Result<Vec<u8>, Error>;
}

impl<T: Transport> Transport for &T {
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, Error> {
        T::get(self, url, limit).await
    }
    async fn post(&self, url: &str, body: Vec<u8>, limit: usize) -> Result<Vec<u8>, Error> {
        T::post(self, url, body, limit).await
    }
}

/// Validated receiver session, independent of the wallet's networking stack.
pub struct DirectoryClient<T> {
    origin: String,
    http: T,
    /// Hex session ID that pins the setup, witness and row routes.
    id: String,
    session: DiscoverySession,
}

// One session per client, so the variant size difference does not matter.
#[allow(clippy::large_enum_variant)]
enum DiscoverySession {
    Pir(Client),
    File { manifest: Manifest, rows: Vec<u8> },
}

/// Pages one lookup reads over PIR; a receiver with more loads the row file instead.
/// Each page is one sequential request, and a publication is served for only about a
/// minute after the next replaces it, so a long walk could never finish in time.
pub const MAX_PIR_PAGES: u32 = 16;

/// Compares remaining uncached discovery traffic, including PIR uploads. Note
/// retrieval is separate. Historical swap count and sunk traffic are irrelevant.
pub fn prefer_directory_file(manifest: &Manifest, remaining_lookups: usize) -> Result<bool, Error> {
    manifest.validate()?;
    let file_bytes = u64::from(manifest.directory.rows) * ROW_BYTES as u64;
    let pir_bytes = (remaining_lookups as u64).saturating_mul(
        (crate::query_bytes(manifest.directory.rows)? + response_bytes(manifest.directory.rows)?)
            as u64,
    );
    Ok(pir_bytes >= file_bytes)
}

impl<T: Transport> DirectoryClient<T> {
    /// Use the exact advertised revision whose anchor the caller independently checked.
    /// `remaining_lookups` selects PIR or the row file for the job, and a long history
    /// can also load the file (see [`Self::lookup`]). Reuse the client across batches and
    /// reconnect for a new revision. A file failure is an error, never a
    /// receiver-dependent public request.
    pub async fn connect_manifest(
        origin: &str,
        http: T,
        accepted: AcceptedCoverage,
        manifest: Manifest,
        remaining_lookups: usize,
    ) -> Result<Self, Error> {
        let origin = origin.trim_end_matches('/').to_owned();
        accepted.check(&manifest.directory)?;
        let id = hex::encode(manifest.id()?);
        let session = if prefer_directory_file(&manifest, remaining_lookups)? {
            let rows = download_rows(&http, &origin, &id, &manifest).await?;
            DiscoverySession::File { manifest, rows }
        } else {
            let public = http
                .get(
                    &format!("{origin}/v1/receiver/public/{id}"),
                    public_bytes(manifest.directory.rows)?,
                )
                .await?;
            DiscoverySession::Pir(Client::new(manifest, &public, accepted)?)
        };
        Ok(Self {
            origin,
            http,
            id,
            session,
        })
    }

    /// Re-evaluate newly discovered work without discarding setup or a verified file.
    pub async fn use_file_for_work(&mut self, remaining_lookups: usize) -> Result<(), Error> {
        if prefer_directory_file(self.manifest(), remaining_lookups)? {
            self.load_rows().await?;
        }
        Ok(())
    }

    /// Switch to the verified row file, downloading it unless it is already loaded.
    async fn load_rows(&mut self) -> Result<(), Error> {
        if matches!(self.session, DiscoverySession::File { .. }) {
            return Ok(());
        }
        let manifest = self.manifest().clone();
        let rows = download_rows(&self.http, &self.origin, &self.id, &manifest).await?;
        self.session = DiscoverySession::File { manifest, rows };
        Ok(())
    }

    /// Fetch bounded public metadata before selecting the corresponding local chain anchor.
    pub async fn fetch_manifest(origin: &str, http: &T) -> Result<Manifest, Error> {
        let bytes = http
            .get(
                &format!("{}/v1/receiver/init", origin.trim_end_matches('/')),
                MAX_MANIFEST_BYTES,
            )
            .await?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Malformed);
        }
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Downloads `manifest`'s filters, identical for every wallet, so a wallet can test its
    /// receivers before deciding whether to look any up. The file must hold exactly the
    /// sets the manifest declares.
    pub async fn fetch_filters(
        origin: &str,
        http: &T,
        manifest: &Manifest,
    ) -> Result<receiver_directory::filter::Filters, Error> {
        let bytes = http
            .get(
                &format!(
                    "{}/v1/receiver/filters/{}",
                    origin.trim_end_matches('/'),
                    hex::encode(manifest.id()?)
                ),
                receiver_directory::filter::MAX_FILTERS_BYTES,
            )
            .await?;
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != manifest.directory.filters_sha256 {
            return Err(Error::Malformed);
        }
        let filters = receiver_directory::filter::Filters::decode(&bytes)?;
        manifest.directory.check_filters(&filters)?;
        Ok(filters)
    }

    /// The session manifest.
    pub fn manifest(&self) -> &Manifest {
        match &self.session {
            DiscoverySession::Pir(client) => client.manifest(),
            DiscoverySession::File { manifest, .. } => manifest,
        }
    }

    /// Download identical proof bytes for all wallets. This never contains a receiver in the request.
    pub async fn witnesses(&self) -> Result<receiver_directory::witness::WitnessSnapshot, Error> {
        let bytes = self
            .http
            .get(
                &format!("{}/v1/receiver/witness/{}", self.origin, self.id),
                receiver_directory::witness::MAX_WITNESS_BYTES,
            )
            .await?;
        Ok(receiver_directory::witness::WitnessSnapshot::decode(
            &bytes,
            &self.manifest().directory,
        )?)
    }

    /// Return every payment to `receiver` in one publication, or an error. No partial
    /// success or cleartext fallback. A PIR session reads up to [`MAX_PIR_PAGES`] pages
    /// over PIR and otherwise loads the file once and reads every page locally. Neither
    /// hides from the directory that a receiver has several payments. Revalidate the
    /// anchor before crediting results if the wallet's chain changes while awaiting I/O.
    pub async fn lookup(
        &mut self,
        receiver: Receiver,
        accepted: AcceptedCoverage,
    ) -> Result<Vec<Payment>, Error> {
        accepted.check(&self.manifest().directory)?;
        let mut records: Vec<receiver_directory::Record> = Vec::new();
        let mut outputs = BTreeSet::new();
        loop {
            let page = records.len() as u32;
            let record = match &self.session {
                DiscoverySession::File { manifest, rows } => {
                    // A crafted file can hold a very long history; stay cancellable.
                    if page % 256 == 255 {
                        yield_now().await;
                    }
                    let row = row_for(&manifest.directory, &receiver, page)?;
                    lookup_row(
                        &manifest.directory,
                        &receiver,
                        page,
                        &rows[row * ROW_BYTES..(row + 1) * ROW_BYTES],
                    )?
                }
                DiscoverySession::Pir(client) => {
                    let query = client.prepare(receiver, page)?;
                    let body = self
                        .http
                        .post(
                            &format!("{}/v1/receiver/query", self.origin),
                            query.body().to_vec(),
                            response_bytes(client.manifest().directory.rows)?,
                        )
                        .await?;
                    client.decode(query, &body)?
                }
            };
            let Some(record) = record else {
                // The row decoder permits absence only on page zero.
                return Ok(Vec::new());
            };
            if page == 0
                && record.total > MAX_PIR_PAGES
                && matches!(self.session, DiscoverySession::Pir(_))
            {
                // Read a long history from the row file instead.
                self.load_rows().await?;
                continue;
            }
            if let Some(previous) = records.last() {
                check_next(previous, &record)?;
            }
            if !outputs.insert((record.payment.txid, record.payment.action_index)) {
                return Err(Error::Malformed);
            }
            let complete = record.page + 1 == record.total;
            records.push(record);
            if complete {
                return Ok(records.into_iter().map(|r| r.payment).collect());
            }
        }
    }
}

/// Returns pending once, so a long synchronous walk lets the executor run timers and
/// cancellation without depending on a particular runtime.
async fn yield_now() {
    struct YieldNow(bool);
    impl std::future::Future for YieldNow {
        type Output = ();
        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            if self.0 {
                return std::task::Poll::Ready(());
            }
            self.0 = true;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    }
    YieldNow(false).await
}

// Every file entry point uses the same bound and digest check before decoding rows.
async fn download_rows(
    http: &impl Transport,
    origin: &str,
    id: &str,
    manifest: &Manifest,
) -> Result<Vec<u8>, Error> {
    let limit = manifest.directory.rows as usize * ROW_BYTES;
    let data = http
        .get(&format!("{origin}/v1/receiver/rows/{id}"), limit)
        .await?;
    if data.len() != limit
        || <[u8; 32]>::from(Sha256::digest(&data)) != manifest.directory.data_sha256
    {
        return Err(Error::Malformed);
    }
    Ok(data)
}
