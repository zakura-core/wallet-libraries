//! Public archive transport, independent of session preparation and wallet block sync.
use crate::{transport::Transport, Error, Manifest};
use receiver_directory::{
    archive::{Coverage, Head, Page, Proof, MAX_HEAD_BYTES, MAX_RANGE_BYTES},
    blocks::BlockId,
    seen::{SeenSet, MAX_SEEN_BYTES},
};

/// Common public requests. Hosts supply the same privacy routing as receiver PIR.
/// Keep these awaits out of ordinary scanning and never hold a scan lock across them.
pub struct ArchiveClient;

impl ArchiveClient {
    /// Fetches a bounded head. The wallet must anchor it and reject stale identity/epoch state.
    pub async fn head(origin: &str, http: &impl Transport) -> Result<Head, Error> {
        let bytes = http
            .get(
                &format!("{}/v1/receiver/archive/head", origin.trim_end_matches('/')),
                MAX_HEAD_BYTES,
            )
            .await?;
        Ok(Head::decode(&bytes)?)
    }

    /// Fetches exactly one page under an already-anchored immutable head.
    pub async fn page(
        origin: &str,
        http: &impl Transport,
        head: &Head,
        number: u32,
    ) -> Result<Page, Error> {
        head.page_span(number)?;
        let bytes = http
            .get(
                &format!(
                    "{}/v1/receiver/archive/range/{}/{}",
                    origin.trim_end_matches('/'),
                    hex::encode(head.digest()?),
                    number
                ),
                MAX_RANGE_BYTES,
            )
            .await?;
        Ok(Proof::decode(head, number, &bytes)?)
    }

    /// Fetches the complete seen object advertised by a head, never treating absence as empty.
    /// Freshness and the supported provider-history floor remain issuance policy checks.
    pub async fn seen(origin: &str, http: &impl Transport, head: &Head) -> Result<SeenSet, Error> {
        head.validate()?;
        let expected = head.seen.as_ref().ok_or(Error::Revision)?;
        let bytes = http
            .get(
                &format!(
                    "{}/v1/receiver/archive/seen/{}",
                    origin.trim_end_matches('/'),
                    hex::encode(expected.digest)
                ),
                MAX_SEEN_BYTES,
            )
            .await?;
        let seen = SeenSet::decode(&bytes)?;
        expected.check(&head.genesis, &seen)?;
        Ok(seen)
    }

    /// Fetches a session declaration and binds it to that session's actual manifest.
    /// Before completion the caller also checks `Coverage::check` and its local generations.
    pub async fn coverage(
        origin: &str,
        http: &impl Transport,
        manifest: &Manifest,
        target: &Head,
    ) -> Result<Coverage, Error> {
        target.validate()?;
        let session = manifest.id()?;
        let bytes = http
            .get(
                &format!(
                    "{}/v1/receiver/archive/coverage/{}/{}/{}",
                    origin.trim_end_matches('/'),
                    hex::encode(target.archive),
                    target.epoch,
                    hex::encode(session)
                ),
                MAX_HEAD_BYTES,
            )
            .await?;
        let coverage = Coverage::decode(&bytes)?;
        let directory = &manifest.directory;
        if coverage.genesis != target.genesis
            || coverage.archive != target.archive
            || coverage.epoch != target.epoch
            || coverage.session != session
            || coverage.genesis != directory.genesis
            || coverage.first_height != directory.start_height
            || coverage.frontier
                != (BlockId {
                    height: directory.end_height,
                    hash: directory.end_hash,
                })
        {
            return Err(Error::Revision);
        }
        Ok(coverage)
    }
}
