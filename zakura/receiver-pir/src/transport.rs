//! Receiver discovery over a caller-supplied, bounded transport.
use crate::{
    public_bytes, response_bytes, AcceptedCoverage, Client, Error, Manifest, MAX_MANIFEST_BYTES,
};
use receiver_directory::{
    catalog::{BucketIndex, CatalogHead, MAX_CATALOG_BYTES, MAX_INDEX_BYTES},
    paid::{PaidSet, MAX_BUCKET_BYTES, MAX_PAID_BYTES},
    seen::{SeenSet, MAX_SEEN_BYTES},
    Hash, RawRecord, ReceiverBytes,
};
use sha2::{Digest, Sha256};

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
    /// Hex session ID that pins the setup and witness routes.
    id: String,
    client: Client,
}

/// The largest common proof file a client downloads.
pub const MAX_WITNESS_BYTES: usize = 64 * 1024 * 1024;

impl<T: Transport> DirectoryClient<T> {
    /// Use the exact advertised revision whose coverage the caller checked. Reuse the client
    /// across lookups and reconnect for a new revision.
    pub async fn connect_manifest(
        origin: &str,
        http: T,
        accepted: AcceptedCoverage,
        manifest: Manifest,
    ) -> Result<Self, Error> {
        let origin = origin.trim_end_matches('/').to_owned();
        accepted.check(&manifest.directory)?;
        let id = hex::encode(manifest.id()?);
        let public = http
            .get(
                &format!("{origin}/v1/receiver/public/{id}"),
                public_bytes(manifest.directory.rows)?,
            )
            .await?;
        let client = Client::new(manifest, &public, accepted)?;
        Ok(Self {
            origin,
            http,
            id,
            client,
        })
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

    /// Downloads the catalog head `manifest` commits to, identical for every wallet,
    /// from `/v1/receiver/catalog/<digest>`. Fails with
    /// [`receiver_directory::Error::Coverage`] if it names another network.
    pub async fn fetch_catalog(
        origin: &str,
        http: &T,
        manifest: &Manifest,
    ) -> Result<CatalogHead, Error> {
        let digest = manifest.directory.catalog_sha256;
        let bytes = fetch_object(origin, http, "catalog", MAX_CATALOG_BYTES, &digest).await?;
        let head = CatalogHead::decode(&bytes)?;
        if head.genesis != manifest.directory.genesis {
            return Err(receiver_directory::Error::Coverage.into());
        }
        Ok(head)
    }

    /// Downloads the bucket index `head` names from `/v1/receiver/bucket-index/<digest>`
    /// and checks it with [`CatalogHead::check_index`].
    pub async fn fetch_bucket_index(
        origin: &str,
        http: &T,
        head: &CatalogHead,
    ) -> Result<BucketIndex, Error> {
        let bytes =
            fetch_object(origin, http, "bucket-index", MAX_INDEX_BYTES, &head.index).await?;
        let index = BucketIndex::decode(&bytes)?;
        head.check_index(&index)?;
        Ok(index)
    }

    /// Downloads the bucket starting at `start` from `/v1/receiver/bucket/<start>/<digest>`,
    /// with the digest `index` lists, and checks that it starts at `start` and passes
    /// [`CatalogHead::check_bucket`]. A start `index` does not list fails with
    /// [`receiver_directory::Error::Coverage`]. The caller checks the boundary hashes
    /// against its own chain.
    pub async fn fetch_bucket(
        origin: &str,
        http: &T,
        head: &CatalogHead,
        index: &BucketIndex,
        start: u32,
    ) -> Result<PaidSet, Error> {
        let digest = index
            .get(start)
            .ok_or(receiver_directory::Error::Coverage)?;
        let route = format!("bucket/{start}");
        let bytes = fetch_object(origin, http, &route, MAX_BUCKET_BYTES, &digest).await?;
        let bucket = PaidSet::decode(&bytes)?;
        // An index listing one digest at two starts would otherwise return another
        // interval's bucket.
        if bucket.span().start != start {
            return Err(Error::Malformed);
        }
        head.check_bucket(index, &bucket)?;
        Ok(bucket)
    }

    /// Downloads the cumulative paid set `head` names from `/v1/receiver/paid/<digest>`
    /// and checks it with [`CatalogHead::check_paid`]. The caller checks the boundary
    /// hashes against its own chain.
    pub async fn fetch_paid(origin: &str, http: &T, head: &CatalogHead) -> Result<PaidSet, Error> {
        let bytes = fetch_object(origin, http, "paid", MAX_PAID_BYTES, &head.paid).await?;
        let paid = PaidSet::decode(&bytes)?;
        head.check_paid(&paid)?;
        Ok(paid)
    }

    /// Downloads the seen set `head` names from `/v1/receiver/seen/<digest>` and checks
    /// it with [`CatalogHead::check_seen`].
    pub async fn fetch_seen(origin: &str, http: &T, head: &CatalogHead) -> Result<SeenSet, Error> {
        let bytes = fetch_object(origin, http, "seen", MAX_SEEN_BYTES, &head.seen).await?;
        let seen = SeenSet::decode(&bytes)?;
        head.check_seen(&seen)?;
        Ok(seen)
    }

    /// The session manifest.
    pub fn manifest(&self) -> &Manifest {
        self.client.manifest()
    }

    /// Download the common proof file, identical for all wallets, of at most
    /// [`MAX_WITNESS_BYTES`]. The request never contains a receiver. The bytes are
    /// unchecked: the wallet verifies them against this session's manifest and its own
    /// chain before trusting any path.
    pub async fn witnesses(&self) -> Result<Vec<u8>, Error> {
        self.http
            .get(
                &format!("{}/v1/receiver/witness/{}", self.origin, self.id),
                MAX_WITNESS_BYTES,
            )
            .await
    }

    /// Reads page `page` of `receiver`'s history over PIR: one query, whose row choice is
    /// hidden in its encryption. Absence is `None` only on page zero, an empty history; a
    /// missing later page is an error. The record is checked structurally only.
    pub async fn page(
        &self,
        receiver: ReceiverBytes,
        page: u32,
    ) -> Result<Option<RawRecord>, Error> {
        let query = self.client.prepare(receiver, page)?;
        let body = self
            .http
            .post(
                &format!("{}/v1/receiver/query", self.origin),
                query.body().to_vec(),
                response_bytes(self.client.manifest().directory.rows)?,
            )
            .await?;
        self.client.decode(query, &body)
    }
}

/// GETs the immutable object at `<origin>/v1/receiver/<route>/<digest>`, the same bytes
/// for every wallet, failing unless it has at most `limit` bytes and SHA-256 `digest`.
async fn fetch_object<T: Transport>(
    origin: &str,
    http: &T,
    route: &str,
    limit: usize,
    digest: &Hash,
) -> Result<Vec<u8>, Error> {
    let url = format!(
        "{}/v1/receiver/{route}/{}",
        origin.trim_end_matches('/'),
        hex::encode(digest)
    );
    let bytes = http.get(&url, limit).await?;
    if bytes.len() > limit || Hash::from(Sha256::digest(&bytes)) != *digest {
        return Err(Error::Malformed);
    }
    Ok(bytes)
}
