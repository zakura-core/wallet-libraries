//! Compatible historical PIR sessions, separate from ordinary scanning and public-filter requests.
use crate::{DirectoryError, Transport, checked};
use receiver_directory::{
    RawRecord,
    archive::{ConnectedCoverage, Coverage, Head},
    snapshot::check_next,
};
use receiver_pir::{AcceptedCoverage, archive::ArchiveClient, transport::DirectoryClient};
use zakura_receiver_crypto::{
    Receiver,
    witness::{Publication, WitnessSnapshot},
};
use zcash_client_backend::data_api::one_time_ivk::restore::{
    DirectoryPayment, LookupWork, PublicationEnd,
};
use zcash_protocol::consensus::BlockHeight;

/// Pages read per bounded receiver request. The wallet persists the next offset.
pub(crate) const PAGES_PER_LOOKUP: u32 = 64;

/// Public metadata for a candidate session. Fetching it does not query any receiver.
pub struct SessionMetadata {
    head: Head,
    manifest: receiver_pir::Manifest,
    coverage: Coverage,
}

impl SessionMetadata {
    /// Binds an advertised session to the already accepted archive identity and epoch.
    pub async fn fetch(
        origin: &str,
        transport: &impl Transport,
        head: Head,
    ) -> Result<Self, DirectoryError> {
        let manifest = DirectoryClient::fetch_manifest(origin, &transport).await?;
        let coverage = ArchiveClient::coverage(origin, transport, &manifest, &head).await?;
        Ok(Self {
            head,
            manifest,
            coverage,
        })
    }

    /// Exposes the publication for independent wallet-chain anchoring before setup or querying.
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// Opens only a compatible session covering the captured target on the wallet's connected chain.
    /// The caller must still recheck account generations and chain anchors after subsequent awaits.
    pub async fn connect<T: Transport>(
        self,
        origin: &str,
        transport: T,
        chain: ConnectedCoverage,
    ) -> Result<RecoverySession<T>, DirectoryError> {
        self.coverage
            .check_through(&self.head, chain.target, chain)?;
        let accepted = AcceptedCoverage {
            genesis: chain.genesis,
            required_start: self.head.first_height,
            height: chain.publication.height,
            hash: chain.publication.hash,
        };
        let client =
            DirectoryClient::connect_manifest(origin, transport, accepted, self.manifest).await?;
        Ok(RecoverySession {
            head: self.head,
            coverage: self.coverage,
            client,
            witnesses: None,
        })
    }
}

/// A receiver session pinned to the compatible manifest actually used by PIR queries.
pub struct RecoverySession<T> {
    head: Head,
    coverage: Coverage,
    client: DirectoryClient<T>,
    witnesses: Option<WitnessSnapshot>,
}

/// One bounded history result. Ownership and canonical inclusion are still wallet checks.
pub struct HistoryPage {
    pub start: u32,
    pub records: Vec<DirectoryPayment>,
    pub complete: bool,
}

impl<T: Transport> RecoverySession<T> {
    /// Returns the archive history and exact session binding to persist with captured lookup work.
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// Returns the accepted filter head used to select this session's history.
    pub fn head(&self) -> &Head {
        &self.head
    }

    /// Returns the exact session's frontier and tree size for independent wallet validation.
    pub fn publication_end(&self) -> PublicationEnd {
        let directory = &self.client.manifest().directory;
        PublicationEnd {
            height: BlockHeight::from(directory.end_height),
            hash: directory.end_hash,
            tree_size: directory.end_position,
        }
    }

    /// Reads bounded consecutive records, never fetching aggregate filters or opening broad watches.
    /// The caller binds its cursor to this session and cancels the future when discovery is paused.
    pub async fn page(&self, lookup: &LookupWork) -> Result<HistoryPage, DirectoryError> {
        if u32::from(lookup.cutoff) > self.coverage.frontier.height {
            return Err(DirectoryError::Revision);
        }
        let walk = walk_history(&self.client, lookup).await;
        if let Some(error) = walk.error {
            return Err(error);
        }
        let records = walk
            .records
            .into_iter()
            .map(directory_payment)
            .collect::<Result<_, _>>()?;
        Ok(HistoryPage {
            start: walk.start,
            records,
            complete: walk.complete,
        })
    }

    /// Downloads and validates the common bounded witness file once for this exact session.
    pub async fn witnesses(&mut self) -> Result<&WitnessSnapshot, DirectoryError> {
        if self.witnesses.is_none() {
            let bytes = self.client.witnesses().await?;
            self.witnesses = Some(
                WitnessSnapshot::decode(&bytes, &publication(self.client.manifest())?)
                    .map_err(checked)?,
            );
        }
        Ok(self.witnesses.as_ref().expect("loaded witness file"))
    }
}

/// What a walk through one key's history read.
pub(crate) struct Walk {
    /// The page the records start at.
    pub(crate) start: u32,
    /// Consecutive records from `start`, at or below the cutoff.
    pub(crate) records: Vec<RawRecord>,
    /// Whether the walk read every record at or below the cutoff.
    pub(crate) complete: bool,
    /// Why the walk stopped early, if it did.
    pub(crate) error: Option<DirectoryError>,
}

/// Shares bounded, ordered receiver pagination with the retiring discovery adapter.
pub(crate) async fn walk_history<T: Transport>(
    session: &DirectoryClient<T>,
    lookup: &LookupWork,
) -> Walk {
    let cutoff = u32::from(lookup.cutoff);
    let mut walk = Walk {
        start: lookup.applied,
        records: vec![],
        complete: false,
        error: None,
    };
    let receiver = match Receiver::from_bytes(lookup.work.receiver) {
        Ok(receiver) => *receiver.as_bytes(),
        Err(e) => {
            walk.error = Some(checked(e));
            return walk;
        }
    };
    let mut previous = None;
    if walk.start > 0 {
        match session.page(receiver, walk.start - 1).await {
            Ok(Some(record))
                if Some((record.payment.position, record.payment.action_nullifier))
                    == lookup.last =>
            {
                // The history ends at the cursor: nothing new.
                if record.page + 1 == record.total {
                    walk.complete = true;
                    return walk;
                }
                previous = Some(record);
            }
            Ok(_) | Err(DirectoryError::Directory(receiver_directory::Error::MissingPage)) => {
                walk.start = 0;
            }
            Err(e) => {
                walk.error = Some(e);
                return walk;
            }
        }
    }
    for page in walk.start..walk.start.saturating_add(PAGES_PER_LOOKUP) {
        let record = match session.page(receiver, page).await {
            Ok(Some(record)) => record,
            // Absence is allowed only on page zero: an empty history.
            Ok(None) => {
                walk.complete = true;
                return walk;
            }
            Err(e) => {
                walk.error = Some(e);
                return walk;
            }
        };
        if let Some(previous) = walk.records.last().or(previous.as_ref())
            && let Err(e) = check_next(previous, &record)
        {
            walk.error = Some(e.into());
            return walk;
        }
        if record.payment.height > cutoff {
            walk.complete = true;
            return walk;
        }
        let last = record.page + 1 == record.total;
        walk.records.push(record);
        if last {
            walk.complete = true;
            return walk;
        }
    }
    walk
}
/// The fields of the session's validated manifest that its witness file binds to.
pub(crate) fn publication(
    manifest: &receiver_pir::Manifest,
) -> Result<Publication, DirectoryError> {
    let directory = &manifest.directory;
    directory.validate()?;
    Ok(Publication {
        genesis: directory.genesis,
        directory_revision: directory.revision()?,
        end_height: directory.end_height,
        end_hash: directory.end_hash,
        start_position: directory.start_position,
        end_position: directory.end_position,
        records: directory.records,
    })
}

/// A directory record's payment as the wallet takes it, after checking that its note
/// commitment and Action nullifier are canonical and its ephemeral key valid. The directory
/// crates parse records structurally only.
pub(crate) fn directory_payment(record: RawRecord) -> Result<DirectoryPayment, DirectoryError> {
    let payment = record.payment;
    zakura_receiver_crypto::Payment {
        height: payment.height,
        block_hash: payment.block_hash,
        txid: payment.txid,
        tx_index: payment.tx_index,
        action_index: payment.action_index,
        position: payment.position,
        action_nullifier: payment.action_nullifier,
        cmx: payment.cmx,
        ephemeral_key: payment.ephemeral_key,
        ciphertext_prefix: payment.ciphertext_prefix,
    }
    .check()
    .map_err(checked)?;
    Ok(DirectoryPayment {
        height: payment.height,
        block_hash: payment.block_hash,
        txid: payment.txid,
        tx_index: payment.tx_index,
        action_index: payment.action_index,
        position: payment.position,
        action_nullifier: payment.action_nullifier,
        cmx: payment.cmx,
        ephemeral_key: payment.ephemeral_key,
        ciphertext_prefix: payment.ciphertext_prefix,
    })
}
