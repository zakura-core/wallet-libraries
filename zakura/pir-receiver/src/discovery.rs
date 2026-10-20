//! Bounded network steps. Wallet queue mutations happen after these futures complete.
use crate::{DirectoryError, Transport, checked};
use receiver_pir::{
    inventory::Inventory,
    transport::{InventoryClient, Segment},
};
use zakura_receiver_crypto::Receiver;
use zcash_client_backend::data_api::one_time_ivk::restore::{
    LookupCursor, LookupPage, LookupWork, PublicationEnd, RECOVERY_PAGE_LIMIT, RecoveryPublication,
    SegmentRef, WitnessAnswer, WitnessRequest,
};
use zcash_protocol::consensus::BlockHeight;

/// Most shards one step may cover through negative filters before returning.
pub const FILTER_STEP_LIMIT: usize = 256;

/// The wallet's view of a captured inventory: its identity and locally checkable frontier.
/// The caller must still check network and activation coverage when capturing it.
pub fn publication(inventory: &Inventory) -> RecoveryPublication {
    let head = inventory.head();
    RecoveryPublication {
        id: head.inventory,
        history_revision: head.history_revision,
        start_height: BlockHeight::from(head.start_height),
        end: PublicationEnd {
            height: BlockHeight::from(head.end_height),
            hash: head.end_hash,
            tree_size: head.end_position,
        },
    }
}

/// Covers at most one bounded step of a request's required shards, with no database
/// handle or wallet lock. Every shard reaching `work.from` through the inventory's end is
/// required, including one that straddles it. A sealed shard whose validated filter excludes the receiver is covered
/// without PIR; any other required shard, including the recent tier and a shard whose
/// filter is missing, malformed or matching, is read in every segment through its final
/// page. A cursor from another inventory is never reinterpreted: the step starts again
/// from `work.from`.
pub async fn lookup<T: Transport>(
    client: &InventoryClient<T>,
    work: &LookupWork,
) -> Result<LookupPage, DirectoryError> {
    let inventory = client.inventory();
    let publication = publication(inventory);
    if publication.history_revision != work.token.history_revision
        || publication.end.height < work.through
    {
        return Err(DirectoryError::Revision);
    }
    let receiver = *Receiver::from_bytes(work.work.receiver)
        .map_err(checked)?
        .as_bytes();
    let shards = inventory.shards();
    let (mut shard, segment, last) = match &work.cursor {
        Some(cursor) if cursor.inventory == publication.id => {
            (cursor.shard, cursor.segment, cursor.last.clone())
        }
        _ => {
            let from = u32::from(work.from);
            let first = shards.partition_point(|s| s.end_height < from);
            (
                u32::try_from(first).map_err(|_| DirectoryError::Malformed)?,
                0,
                None,
            )
        }
    };
    let mut result = LookupPage {
        publication,
        segment: None,
        records: vec![],
        checked_through: None,
        next: None,
    };
    let cursor = |shard, segment, last| {
        Some(LookupCursor {
            inventory: publication.id,
            shard,
            segment,
            last,
        })
    };
    let mut filtered = 0;
    loop {
        let Some(descriptor) = shards.get(shard as usize) else {
            return Ok(result);
        };
        if segment == 0
            && last.is_none()
            && client.uses_filters()
            && descriptor.filter.is_some()
            && let Some(filter) = client.filter(shard).await
            && !filter.matches(&[receiver])[0]
        {
            result.checked_through = Some(BlockHeight::from(descriptor.end_height));
            shard += 1;
            filtered += 1;
            if filtered == FILTER_STEP_LIMIT {
                result.next = cursor(shard, 0, None);
                return Ok(result);
            }
            continue;
        }
        let connected = client.segment(shard, segment).await?;
        result.segment = Some(SegmentRef {
            shard,
            segment,
            payments: connected.publication().payments.id()?,
            witnesses: connected.publication().witnesses.id()?,
        });
        let finished = read_segment(client, &connected, receiver, last, &mut result).await?;
        result.next = if !finished {
            cursor(shard, segment, result.records.last().cloned())
        } else if (segment as usize) + 1 < descriptor.segments.len() {
            cursor(shard, segment + 1, None)
        } else {
            result.checked_through = Some(BlockHeight::from(descriptor.end_height));
            shards
                .get(shard as usize + 1)
                .and_then(|_| cursor(shard + 1, 0, None))
        };
        return Ok(result);
    }
}

/// Reads up to [`RECOVERY_PAGE_LIMIT`] consecutive pages of `receiver` in one segment after
/// `last`, appending them to `result`. True once the segment's final page (or an empty
/// history) has been read.
async fn read_segment<T: Transport>(
    client: &InventoryClient<T>,
    segment: &Segment,
    receiver: [u8; 43],
    last: Option<receiver_directory::RawRecord>,
    result: &mut LookupPage,
) -> Result<bool, DirectoryError> {
    let start = match &last {
        Some(saved) if saved.page.checked_add(1) == Some(saved.total) => return Ok(true),
        Some(saved) => saved.page + 1,
        None => 0,
    };
    for offset in 0..RECOVERY_PAGE_LIMIT as u32 {
        let page = start.checked_add(offset).ok_or(DirectoryError::Malformed)?;
        let Some(record) = client.page(segment, receiver, page).await? else {
            if page != 0 {
                return Err(DirectoryError::Malformed);
            }
            return Ok(true);
        };
        if let Some(previous) = result.records.last().or(last.as_ref()) {
            receiver_directory::snapshot::check_next(previous, &record)?;
        }
        let finished = record.page.checked_add(1) == Some(record.total);
        result.records.push(record);
        if finished {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Reads one candidate's companion witness payload with one PIR query, with no database
/// handle or wallet lock. A request whose payment and witness sessions this inventory does
/// not hold together is [`DirectoryError::Revision`]: the wallet must re-read the payment
/// under this inventory
/// (see `refresh_one_time_witness`) rather than reinterpret its ordinal.
pub async fn witness<T: Transport>(
    client: &InventoryClient<T>,
    request: &WitnessRequest,
) -> Result<WitnessAnswer, DirectoryError> {
    let (shard, segment) = client
        .find_segment(&request.payments)
        .ok_or(DirectoryError::Revision)?;
    let connected = client.segment(shard, segment).await?;
    let witnesses = &connected.publication().witnesses;
    if witnesses.id()? != request.witnesses {
        return Err(DirectoryError::Revision);
    }
    let table = &witnesses.table;
    Ok(WitnessAnswer {
        payments: request.payments,
        revision: witnesses.id()?,
        context: PublicationEnd {
            height: table.tree_height.into(),
            hash: table.tree_hash,
            tree_size: table.tree_size,
        },
        payload: client.witness(&connected, request.ordinal).await?,
    })
}
