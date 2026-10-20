//! Receiver discovery over a caller-supplied, bounded transport.
use crate::{
    public_bytes, response_bytes, AcceptedCoverage, Client, Error, Manifest, Publication,
    WitnessClient, MAX_MANIFEST_BYTES,
};
use receiver_directory::{witness::PAYLOAD_BYTES, RawRecord, ReceiverBytes};

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
    publication: Publication,
    client: Client,
    witnesses: WitnessClient,
}

impl<T: Transport> DirectoryClient<T> {
    /// Use the exact advertised payment and witness revisions whose coverage the caller
    /// checked. Reuse the client across lookups and reconnect for a new revision.
    pub async fn connect_manifest(
        origin: &str,
        http: T,
        accepted: AcceptedCoverage,
        publication: Publication,
    ) -> Result<Self, Error> {
        let origin = origin.trim_end_matches('/').to_owned();
        publication.validate()?;
        accepted.check(&publication.payments.directory)?;
        let payments = &publication.payments;
        let public = http
            .get(
                &format!(
                    "{origin}/v1/receiver/public/{}",
                    hex::encode(payments.id()?)
                ),
                public_bytes(payments.directory.rows)?,
            )
            .await?;
        let client = Client::new(payments.clone(), &public, accepted)?;
        let witness = &publication.witnesses;
        let public = http
            .get(
                &format!("{origin}/v1/receiver/public/{}", hex::encode(witness.id()?)),
                public_bytes(witness.table.rows)?,
            )
            .await?;
        let witnesses = WitnessClient::new(witness.clone(), &public)?;
        Ok(Self {
            origin,
            http,
            publication,
            client,
            witnesses,
        })
    }

    /// Fetch bounded public metadata before selecting the corresponding local chain anchor.
    pub async fn fetch_manifest(origin: &str, http: &T) -> Result<Publication, Error> {
        let bytes = http
            .get(
                &format!("{}/v1/receiver/init", origin.trim_end_matches('/')),
                MAX_MANIFEST_BYTES,
            )
            .await?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Malformed);
        }
        let publication: Publication = serde_json::from_slice(&bytes)?;
        publication.validate()?;
        Ok(publication)
    }

    /// Downloads rolling-hint availability without opening or waiting for a PIR session.
    pub async fn fetch_block_head(
        origin: &str,
        http: &T,
        genesis: &[u8; 32],
    ) -> Result<receiver_directory::blocks::Head, Error> {
        let bytes = http
            .get(
                &format!(
                    "{}/v1/receiver/block-filters/head",
                    origin.trim_end_matches('/')
                ),
                16 * 1024,
            )
            .await?;
        if bytes.len() > 16 * 1024 {
            return Err(Error::Malformed);
        }
        let head: receiver_directory::blocks::Head = serde_json::from_slice(&bytes)?;
        head.validate(genesis)?;
        Ok(head)
    }

    /// Fetches a bounded prefix for one captured head. Errors never mean an empty range.
    /// The wallet must verify returned block hashes against its own chain before advancing.
    pub async fn fetch_block_batch(
        origin: &str,
        http: &T,
        head: &receiver_directory::blocks::Head,
        from: u32,
        limit: u32,
    ) -> Result<receiver_directory::blocks::Batch, Error> {
        head.check_request(from, limit)?;
        let bytes = http
            .get(
                &format!(
                    "{}/v1/receiver/block-filters/{}/{}/{}",
                    origin.trim_end_matches('/'),
                    head.revision,
                    from,
                    limit
                ),
                receiver_directory::blocks::MAX_BATCH_BYTES,
            )
            .await?;
        let batch = receiver_directory::blocks::Batch::decode(&bytes)?;
        batch.check(head, from, limit)?;
        Ok(batch)
    }

    /// The payment session manifest.
    pub fn manifest(&self) -> &Manifest {
        self.client.manifest()
    }

    /// The payment and witness sessions this client answers from.
    pub fn publication(&self) -> &Publication {
        &self.publication
    }

    /// Reads the companion witness payload for `ordinal` over PIR: one query, whose row
    /// choice is hidden in its encryption. Only ordinals from this session's payment records
    /// are meaningful. The payload is unchecked: the wallet verifies it against its own tree.
    pub async fn witness(&self, ordinal: u32) -> Result<[u8; PAYLOAD_BYTES], Error> {
        let query = self.witnesses.prepare(ordinal)?;
        let body = self
            .http
            .post(
                &format!("{}/v1/receiver/query", self.origin),
                query.body().to_vec(),
                response_bytes(self.witnesses.manifest().table.rows)?,
            )
            .await?;
        self.witnesses.decode(query, &body)
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
