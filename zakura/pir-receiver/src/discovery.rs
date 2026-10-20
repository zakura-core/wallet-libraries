//! Bounded network steps. Wallet queue mutations happen after these futures complete.
use crate::{DirectoryError, Transport, checked};
use receiver_pir::{Manifest, transport::DirectoryClient};
use zakura_receiver_crypto::{
    Receiver,
    witness::{Publication, WitnessSnapshot},
};
use zcash_client_backend::data_api::one_time_ivk::restore::{
    LookupPage, LookupWork, PublicationEnd, RECOVERY_PAGE_LIMIT, RecoveryPublication,
};
use zcash_protocol::consensus::BlockHeight;

/// Converts validated session metadata to the wallet's locally checked frontier.
/// The caller must still check network/activation coverage when opening the session.
pub fn publication(manifest: &Manifest) -> Result<RecoveryPublication, DirectoryError> {
    manifest.validate()?;
    let directory = &manifest.directory;
    Ok(RecoveryPublication {
        id: manifest.id()?,
        history_revision: directory.history_revision,
        start_height: BlockHeight::from(directory.start_height),
        end: PublicationEnd {
            height: BlockHeight::from(directory.end_height),
            hash: directory.end_hash,
            tree_size: directory.end_position,
        },
    })
}

/// Reads at most one bounded history step, with no database handle or wallet lock.
/// On session replacement the saved record is reread before advancing its cursor.
pub async fn lookup<T: Transport>(
    client: &DirectoryClient<T>,
    work: &LookupWork,
) -> Result<LookupPage, DirectoryError> {
    let publication = publication(client.manifest())?;
    if publication.history_revision != work.token.history_revision
        || publication.end.height < work.through
    {
        return Err(DirectoryError::Revision);
    }
    let receiver = *Receiver::from_bytes(work.work.receiver)
        .map_err(checked)?
        .as_bytes();
    let mut result = LookupPage {
        publication,
        previous: None,
        records: vec![],
        complete: false,
    };
    let start = if let Some(saved) = &work.last {
        result.previous = match client.page(receiver, saved.page).await {
            Ok(record) => record,
            Err(DirectoryError::Directory(receiver_directory::Error::MissingPage)) => None,
            Err(e) => return Err(e),
        };
        let Some(current) = result.previous.as_ref().filter(|current| {
            current.receiver == saved.receiver
                && current.page == saved.page
                && current.payment == saved.payment
                && current.total >= saved.total
        }) else {
            // The wallet resets this cursor atomically without counting the mismatch as empty.
            return Ok(result);
        };
        if current.page.checked_add(1) == Some(current.total) {
            result.complete = true;
            return Ok(result);
        }
        current
            .page
            .checked_add(1)
            .ok_or(DirectoryError::Malformed)?
    } else {
        0
    };
    for offset in 0..RECOVERY_PAGE_LIMIT as u32 {
        let page = start.checked_add(offset).ok_or(DirectoryError::Malformed)?;
        let Some(record) = client.page(receiver, page).await? else {
            if page != 0 {
                return Err(DirectoryError::Malformed);
            }
            result.complete = true;
            return Ok(result);
        };
        if let Some(previous) = result.records.last().or(result.previous.as_ref()) {
            receiver_directory::snapshot::check_next(previous, &record)?;
        }
        result.complete = record.page.checked_add(1) == Some(record.total);
        result.records.push(record);
        if result.complete {
            break;
        }
    }
    Ok(result)
}

/// Downloads and validates the common proof file once for an immutable session.
/// The file is shared by all receivers. Its paths still require the wallet's chain checks.
pub async fn witnesses<T: Transport>(
    client: &DirectoryClient<T>,
) -> Result<WitnessSnapshot, DirectoryError> {
    let manifest = client.manifest();
    let directory = &manifest.directory;
    let publication = Publication {
        genesis: directory.genesis,
        directory_revision: directory.revision()?,
        end_height: directory.end_height,
        end_hash: directory.end_hash,
        start_position: directory.start_position,
        end_position: directory.end_position,
        records: directory.records,
    };
    let bytes = client.witnesses().await?;
    WitnessSnapshot::decode(&bytes, &publication).map_err(checked)
}
