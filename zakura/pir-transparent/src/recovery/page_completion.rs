//! Page work: the identity of a page the store left unfinished, and the completion of
//! the wallet's pages once coverage spans them.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use transparent::address::TransparentAddress;
use transparent_wallet::{Acceptance, ChainView};
use zcash_client_backend::data_api::transparent_ledger::{
    AddressRange, ChainPoint, PageRequest, TransparentLedgerCommit, TransparentRecoveryContext,
    TransparentWatchSet,
};
use zcash_protocol::consensus::BlockHeight;

use crate::catalog::Published;
use crate::convert::block_hash;
use crate::error::RecoveryError;

pub(super) fn page_id(shard: u64, digest: &str, script: &[u8], first: u32) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"transparent-reference-page-v1");
    hash.update(shard.to_le_bytes());
    hash.update(digest.as_bytes());
    hash.update(script);
    hash.update(first.to_le_bytes());
    hash.finalize().to_vec()
}

/// Whether `ranges` of `address` together cover every height from `from`
/// through `through`.
pub(super) fn spans<'r>(
    ranges: impl IntoIterator<Item = &'r AddressRange>,
    address: TransparentAddress,
    from: BlockHeight,
    through: BlockHeight,
) -> bool {
    let mut ranges: Vec<(u32, u32)> = ranges
        .into_iter()
        .filter(|range| range.address == address)
        .map(|range| (u32::from(range.from), u32::from(range.through)))
        .collect();
    ranges.sort_unstable();
    // The lowest height not covered yet.
    let mut next = u32::from(from);
    for (start, end) in ranges {
        if start > next {
            break;
        }
        if end >= u32::from(through) {
            return true;
        }
        next = next.max(end + 1);
    }
    false
}

/// Completion-only commits for the wallet's pages that no commit of their own
/// revision covers by itself.
///
/// Every pending page blocks its account. A page under a source `published`
/// does not name, as after a set, origin or source-format change or a re-cut,
/// has no commit of its revision to follow, nor has one under a sealed
/// revision a re-cut declared superseded (in `declared`) whose source the map
/// still names, as a renumbered shard. A declared revision may also have a
/// commit of its own, from facts the store saved under it before the re-cut,
/// while the rest of its range was read again under the shard that now covers
/// it. Such a page is completed under its own revision once `commits` cover
/// each of its addresses over its whole range, in a completion-only commit the
/// caller places after `commits`, so the wallet applies the coverage first.
/// Its anchor is the wallet's block at the lower of the revision's publication
/// height and the target, which at the publication height must be the
/// publication's own block; a page whose anchor the wallet's chain does not
/// hold waits.
///
/// Any other page whose revision has a commit is left to that commit, which
/// completes it from its own coverage and otherwise reopens or keeps it, so no
/// page is completed twice. A named source's provisional revisions are left to
/// their successor, whose qualification withdraws them.
pub(super) fn complete_stranded<A: Copy>(
    watch: &TransparentWatchSet<A>,
    context: TransparentRecoveryContext<A>,
    published: &[Published],
    declared: &[Published],
    commits: &[TransparentLedgerCommit<A>],
    chain: &impl ChainView,
) -> Result<Vec<TransparentLedgerCommit<A>>, RecoveryError> {
    let named: BTreeSet<&[u8]> = published
        .iter()
        .map(|entry| entry.revision.source.as_slice())
        .collect();
    let covers = |commits: &[TransparentLedgerCommit<A>], request: &PageRequest| {
        request.addresses.iter().all(|address| {
            spans(
                commits.iter().flat_map(|commit| &commit.coverage),
                *address,
                request.from,
                request.through,
            )
        })
    };
    let mut stranded: Vec<TransparentLedgerCommit<A>> = vec![];
    for page in &watch.pending_pages {
        let superseded = declared.iter().any(|entry| entry.revision == page.revision);
        if let Some(own) = commits
            .iter()
            .find(|commit| commit.revision == page.revision)
        {
            // Its own commit settles it, unless the re-cut superseded its
            // revision and the coverage that completes it is under others.
            let done = own.completed_pages.contains(&page.request.page)
                || own
                    .opened_pages
                    .iter()
                    .any(|opened| opened.page == page.request.page);
            if !superseded || done {
                continue;
            }
        } else if named.contains(page.revision.source.as_slice()) && !superseded {
            // A named source's own revisions settle its pages, except a sealed
            // revision a re-cut superseded, which no successor withdraws.
            continue;
        }
        let request = &page.request;
        if !covers(commits, request) {
            continue;
        }
        if let Some(commit) = stranded
            .iter_mut()
            .find(|commit| commit.revision == page.revision)
        {
            commit.completed_pages.push(request.page.clone());
            continue;
        }
        let publication = page.revision.publication;
        let height = publication.height.min(context.target.height);
        let Some(hash) = chain.hash_at(u64::from(u32::from(height))) else {
            continue;
        };
        if chain.is_accepted(u64::from(u32::from(height)), &hash) != Acceptance::Accepted {
            continue;
        }
        let hash = block_hash(&hash)?;
        if height == publication.height && hash != publication.hash {
            continue;
        }
        stranded.push(TransparentLedgerCommit {
            context,
            revision: page.revision.clone(),
            anchor: ChainPoint { height, hash },
            receives: vec![],
            spends: vec![],
            coverage: vec![],
            unsupported: vec![],
            opened_pages: vec![],
            completed_pages: vec![request.page.clone()],
        });
    }
    Ok(stranded)
}
