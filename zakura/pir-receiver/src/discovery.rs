//! Bounded network steps. Wallet queue mutations happen after these futures complete.
use crate::{DirectoryError, Transport, checked};
use receiver_pir::{Publication, transport::DirectoryClient};
use zakura_receiver_crypto::Receiver;
use zcash_client_backend::data_api::one_time_ivk::restore::{
    LookupPage, LookupWork, PublicationEnd, RECOVERY_PAGE_LIMIT, RecoveryPublication,
    WitnessAnswer, WitnessRequest,
};
use zcash_protocol::consensus::BlockHeight;

/// Converts validated session metadata to the wallet's locally checked frontier.
/// The caller must still check network/activation coverage when opening the session.
pub fn publication(publication: &Publication) -> Result<RecoveryPublication, DirectoryError> {
    publication.validate()?;
    let manifest = &publication.payments;
    let directory = &manifest.directory;
    Ok(RecoveryPublication {
        id: manifest.id()?,
        witnesses: publication.witnesses.id()?,
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
    let publication = publication(client.publication())?;
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

/// Reads one candidate's companion witness payload with one PIR query, with no database
/// handle or wallet lock. A request bound to another payment or witness session is
/// [`DirectoryError::Revision`]: the wallet must re-read the payment under this session
/// (see `refresh_one_time_witness`) rather than reinterpret its ordinal.
pub async fn witness<T: Transport>(
    client: &DirectoryClient<T>,
    request: &WitnessRequest,
) -> Result<WitnessAnswer, DirectoryError> {
    let publication = client.publication();
    if publication.payments.id()? != request.payments
        || publication.witnesses.id()? != request.witnesses
    {
        return Err(DirectoryError::Revision);
    }
    let table = &publication.witnesses.table;
    Ok(WitnessAnswer {
        payments: request.payments,
        revision: publication.witnesses.id()?,
        context: PublicationEnd {
            height: table.tree_height.into(),
            hash: table.tree_hash,
            tree_size: table.tree_size,
        },
        payload: client.witness(request.ordinal).await?,
    })
}
