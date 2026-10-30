//! Bounded network steps. Wallet queue mutations happen after these futures complete.
use super::{
    Entry, Publication, RawRecord, check_next, choose_row,
    crypto::Receiver,
    inventory::Inventory,
    lookup_entry, lookup_slot,
    session::Error as DirectoryError,
    slot_row, tag,
    transport::{InventoryClient, Transport},
    wire::PAYLOAD_BYTES,
};
use core::num::NonZeroUsize;
use zcash_client_backend::data_api::one_time_ivk::restore::{
    LookupCursor, LookupPage, LookupRecord, LookupWork, PublicationEnd, RECOVERY_PAGE_LIMIT,
    RecoveryPublication, SegmentRef, StepShard,
};
use zcash_protocol::consensus::BlockHeight;

/// The directory error for data a receiver check refuses: the same error the
/// directory's own decoding gave when it checked receivers, payments and witnesses.
fn checked(error: super::crypto::Error) -> DirectoryError {
    use super::crypto::Error;
    DirectoryError::Directory(match error {
        Error::Malformed => super::Error::Malformed,
        Error::Coverage => super::Error::Coverage,
        Error::Capacity => super::Error::Capacity,
    })
}

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

/// How one step may spend requests.
pub struct Pace {
    /// Most records the step reads, capped at [`RECOVERY_PAGE_LIMIT`]. A small cap lets a
    /// slow transport finish and record a step within its time budget.
    pub records: NonZeroUsize,
}

/// The receiver's entry in one segment: one directory query, for the row its choice
/// object names. `None` means the segment pays no receiver with its tag.
async fn read_entry<T: Transport>(
    client: &InventoryClient<T>,
    segment: &Publication,
    receiver: &[u8; 43],
) -> Result<Option<Entry>, DirectoryError> {
    let directory = &segment.directory;
    let tag = tag(&directory.manifest.salt, receiver);
    let choice = client.choice(&directory.manifest).await?;
    let session = client.open(directory).await?;
    let row = choose_row(&directory.manifest.salt, &choice, &tag);
    let bytes = client.query(&session, row).await?;
    Ok(lookup_entry(&directory.manifest, &bytes, &tag)?)
}

/// The record and payload in companion slot `slot`, checked against `entry`: one companion
/// query naming that slot's row.
async fn read_slot<T: Transport>(
    client: &InventoryClient<T>,
    segment: &Publication,
    entry: &Entry,
    slot: u32,
) -> Result<(RawRecord, [u8; PAYLOAD_BYTES]), DirectoryError> {
    let session = client.open(&segment.companion).await?;
    let bytes = client.query(&session, slot_row(slot)).await?;
    let (d, c) = (&segment.directory.manifest, &segment.companion.manifest);
    Ok(lookup_slot(d, c, entry, slot, &bytes)?)
}

/// [`lookup_with`] at the default pace: up to [`RECOVERY_PAGE_LIMIT`] records.
pub async fn lookup<T: Transport>(
    client: &InventoryClient<T>,
    work: &LookupWork,
) -> Result<LookupPage, DirectoryError> {
    let records = NonZeroUsize::new(RECOVERY_PAGE_LIMIT).expect("nonzero");
    lookup_with(client, work, Pace { records }).await
}

/// Covers at most one bounded step of a request's required shards, with no database handle
/// or wallet lock. Every shard reaching `work.from` through the inventory's end is
/// required, including one that straddles it. A sealed shard whose validated filter
/// excludes the receiver is covered without PIR. Any other required shard, including the
/// recent tier and a shard whose filter is missing, malformed or matching, is read in every
/// segment: one directory query, then, on a hit whose last payment is at or past
/// `max(work.from, work.birthday)`, one companion query per record. A hit below that is a
/// miss, read with no companion query. A cursor from another inventory is never
/// reinterpreted: the step starts again from `work.from`. A step resuming after a record
/// reads the receiver's entry again before its next records.
///
/// A step reads at most `pace.records` records and returns a cursor after its last one,
/// which the wallet records and the next step resumes from. It is all or nothing: each
/// request is sent once, and a failed request or data that fails a check, including a
/// record for another receiver at the queried tag, fails the step with an error and
/// nothing to record. Callers retry whole steps. [`DirectoryError::Revision`], HTTP 410,
/// means a session is gone: capture the inventory again.
pub async fn lookup_with<T: Transport>(
    client: &InventoryClient<T>,
    work: &LookupWork,
    pace: Pace,
) -> Result<LookupPage, DirectoryError> {
    let limit = pace.records.get().min(RECOVERY_PAGE_LIMIT) as u32;
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
    let floor = u32::from(work.from.max(work.birthday));
    let shards = inventory.shards();
    let (mut shard, segment, last) = match &work.cursor {
        Some(c) if c.inventory == publication.id => (c.shard, c.segment, c.last.clone()),
        _ => {
            let first = shards.partition_point(|s| s.end_height < u32::from(work.from));
            let first = u32::try_from(first).map_err(|_| DirectoryError::Malformed)?;
            (first, 0, None)
        }
    };
    let mut page = LookupPage {
        publication,
        inventory_shards: u32::try_from(shards.len()).map_err(|_| DirectoryError::Malformed)?,
        shards: vec![],
        segment: None,
        records: vec![],
        checked_through: None,
        next: None,
    };
    let cursor = |shard: u32, segment, last| {
        shards.get(shard as usize).map(|_| LookupCursor {
            inventory: publication.id,
            shard,
            segment,
            last,
        })
    };
    let mut filtered = 0;
    loop {
        let Some(descriptor) = shards.get(shard as usize) else {
            return checked_step(page, work);
        };
        let visited = StepShard {
            index: shard,
            start_height: BlockHeight::from(descriptor.start_height),
            end_height: BlockHeight::from(descriptor.end_height),
            segments: u32::try_from(descriptor.segments.len())
                .map_err(|_| DirectoryError::Malformed)?,
            excluded: false,
        };
        if segment == 0
            && last.is_none()
            && client.uses_filters()
            && descriptor.filter.is_some()
            && client
                .screen(shard, &[receiver])
                .await
                .is_some_and(|found| !found[0])
        {
            page.shards.push(StepShard {
                excluded: true,
                ..visited
            });
            page.checked_through = Some(BlockHeight::from(descriptor.end_height));
            shard += 1;
            filtered += 1;
            if filtered == FILTER_STEP_LIMIT {
                page.next = cursor(shard, 0, None);
                return checked_step(page, work);
            }
            continue;
        }
        let read = descriptor
            .segments
            .get(segment as usize)
            .ok_or(DirectoryError::Malformed)?;
        let entry = read_entry(client, read, &receiver).await?;
        let entry = match &last {
            // The same inventory serves the same entry, which must hold the pages left.
            Some(prior) => Some(
                entry
                    .filter(|e| u32::from(e.count) == prior.total && prior.page + 1 < prior.total)
                    .ok_or(DirectoryError::Malformed)?,
            ),
            None => entry.filter(|e| descriptor.start_height.saturating_add(e.last) >= floor),
        };
        let tree = read.companion.manifest.tree;
        page.shards.push(visited);
        page.segment = Some(SegmentRef {
            shard,
            segment,
            directory: read.directory.id()?,
            companion: read.companion.id()?,
            tree: PublicationEnd {
                height: BlockHeight::from(tree.height),
                hash: tree.hash,
                tree_size: tree.size,
            },
        });
        let mut previous = last;
        if let Some(entry) = &entry {
            let start = previous.as_ref().map_or(0, |r| r.page + 1);
            for p in start..(start + limit).min(u32::from(entry.count)) {
                let slot = entry.first + p;
                let (record, payload) = read_slot(client, read, entry, slot).await?;
                // A tag hit for another receiver is a bad pointer, never a miss.
                if record.receiver != receiver {
                    return Err(DirectoryError::Malformed);
                }
                if let Some(previous) = &previous {
                    check_next(previous, &record)?;
                }
                previous = Some(record.clone());
                page.records.push(LookupRecord { record, payload });
            }
        }
        let finished = entry.is_none_or(|e| {
            previous
                .as_ref()
                .is_some_and(|r| r.page + 1 == u32::from(e.count))
        });
        page.next = if !finished {
            cursor(shard, segment, previous)
        } else if (segment as usize) + 1 < descriptor.segments.len() {
            cursor(shard, segment + 1, None)
        } else {
            page.checked_through = Some(BlockHeight::from(descriptor.end_height));
            cursor(shard + 1, 0, None)
        };
        return checked_step(page, work);
    }
}

/// Screens every receiver in `works` against the filters of the sealed shards their next
/// steps may cover, traversing each filter once for all of them (see
/// `InventoryClient::screen`), so the steps that follow read remembered answers. Optional:
/// a step screens what it needs itself.
pub async fn screen<T: Transport>(client: &InventoryClient<T>, works: &[LookupWork]) {
    if !client.uses_filters() {
        return;
    }
    let inventory = client.inventory();
    let shards = inventory.shards();
    let mut wanted: std::collections::BTreeMap<u32, Vec<[u8; 43]>> = Default::default();
    for work in works {
        let first = match &work.cursor {
            Some(c) if c.inventory == inventory.head().inventory => {
                if c.segment != 0 || c.last.is_some() {
                    c.shard + 1
                } else {
                    c.shard
                }
            }
            _ => shards.partition_point(|s| s.end_height < u32::from(work.from)) as u32,
        };
        for shard in shards
            .iter()
            .skip(first as usize)
            .take(FILTER_STEP_LIMIT)
            .filter(|s| s.filter.is_some())
        {
            wanted
                .entry(shard.index)
                .or_default()
                .push(work.work.receiver);
        }
    }
    for (shard, receivers) in wanted {
        let _ = client.screen(shard, &receivers).await;
    }
}

/// Returns `page` only if it is the one step `work` can take (see
/// `LookupPage::valid_step`), so a directory answer that would skip history never reaches
/// the wallet.
fn checked_step(page: LookupPage, work: &LookupWork) -> Result<LookupPage, DirectoryError> {
    if page.valid_step(work) {
        Ok(page)
    } else {
        Err(DirectoryError::Malformed)
    }
}
