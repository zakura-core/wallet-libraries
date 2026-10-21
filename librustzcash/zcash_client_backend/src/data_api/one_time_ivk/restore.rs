//! Resumable private recovery of derived receiver histories.
//!
//! Network work carries a generation captured before the request. Stores recheck it,
//! publication coverage and note inclusion before advancing progress or crediting funds.

use zakura_one_time_ivk::KeyId;
use zcash_protocol::consensus::BlockHeight;

use crate::data_api::transparent_ledger::ChainPoint;

pub mod recovery;

pub use zakura_receiver_crypto::wire::{
    PAYLOAD_BYTES as WITNESS_PAYLOAD_BYTES, Payment as DirectoryPayment,
    RawRecord as DirectoryRecord, decode_payload as decode_witness_payload,
    is_final as witness_is_final,
};

/// Maximum records accepted from one network step.
pub const RECOVERY_PAGE_LIMIT: usize = 32;
/// The receive issuance and seed-recovery gap, justified only by payments mined on the
/// wallet's current chain.
pub const RECEIVE_GAP: u64 = 4;

/// Account-local cancellation and same-chain correction fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryToken {
    pub generation: u64,
    pub history_revision: u64,
}

/// The locally checked end of a receiver publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationEnd {
    pub height: BlockHeight,
    pub hash: [u8; 32],
    pub tree_size: u64,
}

/// One captured inventory: its identity and the history it covers. Every cursor and
/// completion is relative to the inventory it was captured under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryPublication {
    /// The inventory identity.
    pub id: [u8; 32],
    pub history_revision: u64,
    pub start_height: BlockHeight,
    pub end: PublicationEnd,
}

/// A locally derived receiver. Its purpose and index never leave the wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryWork {
    pub key: KeyId,
    pub receiver: [u8; 43],
}

/// Where a request stopped inside one captured inventory: a shard, one of its segments,
/// and the last page read there. Meaningless under any other inventory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupCursor {
    pub inventory: [u8; 32],
    pub shard: u32,
    pub segment: u32,
    /// The last record read in that segment; pages are segment-local.
    pub last: Option<DirectoryRecord>,
}

/// One pending address history, independent of why it was queued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupWork {
    pub token: RecoveryToken,
    pub work: DiscoveryWork,
    /// History below this height is already checked for this request. A shard reaching
    /// it is read whole.
    pub from: BlockHeight,
    /// An answer below this height cannot complete the request.
    pub through: BlockHeight,
    pub cursor: Option<LookupCursor>,
}

/// The payment and witness sessions of the segment a step read, which bind its records'
/// ordinals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentRef {
    pub shard: u32,
    pub segment: u32,
    pub payments: [u8; 32],
    /// The segment's companion witness session, which its candidates must use.
    pub witnesses: [u8; 32],
}

/// One shard a lookup step visited, as the captured inventory lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepShard {
    pub index: u32,
    pub end_height: BlockHeight,
    pub segments: u32,
    /// The shard's validated filter excluded the receiver, so it was covered unread.
    pub excluded: bool,
}

/// One bounded step against one captured inventory: shards a negative filter excluded,
/// then consecutive pages of at most one segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupPage {
    pub publication: RecoveryPublication,
    /// The inventory's shard count.
    pub inventory_shards: u32,
    /// The shards this step visited, in order: any it covered by filter, then at most one
    /// it read from.
    pub shards: Vec<StepShard>,
    /// The segment `records` come from, if the step read one.
    pub segment: Option<SegmentRef>,
    pub records: Vec<DirectoryRecord>,
    /// Every required shard ending at or below this height is covered: excluded by a
    /// validated filter of this inventory or read through its final page in every segment.
    pub checked_through: Option<BlockHeight>,
    /// Where the next step resumes; `None` once every required shard is covered.
    pub next: Option<LookupCursor>,
}

impl LookupPage {
    /// Whether every shard the request needs is covered through the inventory's end.
    pub fn complete(&self) -> bool {
        self.next.is_none()
    }

    /// Whether this step is the only one `work` can take from its position: its visited
    /// shards continue that position in order, every shard before the last was covered by
    /// filter, and `checked_through` and `next` are exactly the coverage the visited shards
    /// and the records read justify. `checked_through` is the end of the last shard the
    /// step completed, or unset if it completed none. `next` continues the read segment
    /// after a record that is not its last page, or else moves to the next segment, the
    /// next shard, or completion at the inventory's last shard. Record contents are checked
    /// separately.
    pub fn valid_step(&self, work: &LookupWork) -> bool {
        let inventory = self.publication.id;
        let cursor = work.cursor.as_ref().filter(|c| c.inventory == inventory);
        let Some(last_shard) = self.shards.last() else {
            // Nothing is required past the inventory's end.
            return work.from > self.publication.end.height
                && self.segment.is_none()
                && self.records.is_empty()
                && self.checked_through.is_none()
                && self.next.is_none();
        };
        let first = cursor.map_or(self.shards[0].index, |c| c.shard);
        let resumes = |index: u32| cursor.filter(|c| c.shard == index);
        let ordered = (first..).zip(&self.shards).all(|(index, shard)| {
            shard.index == index
                && index < self.inventory_shards
                && shard.segments > 0
                && shard.end_height <= self.publication.end.height
        }) && self
            .shards
            .windows(2)
            .all(|w| w[0].end_height < w[1].end_height && w[0].excluded);
        if !ordered {
            return false;
        }
        // A filter covers a shard only from its start.
        if self.shards.iter().any(|s| {
            s.excluded && resumes(s.index).is_some_and(|c| c.segment > 0 || c.last.is_some())
        }) {
            return false;
        }
        let excluded_end = self
            .shards
            .iter()
            .rev()
            .find(|s| s.excluded)
            .map(|s| s.end_height);
        let continue_at = |shard: u32, segment: u32, last: Option<DirectoryRecord>| LookupCursor {
            inventory,
            shard,
            segment,
            last,
        };
        let completes = |shard: &StepShard| {
            (
                Some(shard.end_height),
                (shard.index + 1 < self.inventory_shards)
                    .then(|| continue_at(shard.index + 1, 0, None)),
            )
        };
        let expected = if last_shard.excluded {
            if self.segment.is_some() || !self.records.is_empty() {
                return false;
            }
            completes(last_shard)
        } else {
            let (segment, prior) =
                resumes(last_shard.index).map_or((0, None), |c| (c.segment, c.last.clone()));
            if self
                .segment
                .is_none_or(|s| (s.shard, s.segment) != (last_shard.index, segment))
                || segment >= last_shard.segments
            {
                return false;
            }
            let after = self.records.last().cloned().or(prior);
            match after {
                Some(record) if record.page.checked_add(1) != Some(record.total) => (
                    excluded_end,
                    Some(continue_at(last_shard.index, segment, Some(record))),
                ),
                _ if segment + 1 < last_shard.segments => (
                    excluded_end,
                    Some(continue_at(last_shard.index, segment + 1, None)),
                ),
                _ => completes(last_shard),
            }
        };
        if expected.1.is_none() && last_shard.end_height != self.publication.end.height {
            return false;
        }
        (self.checked_through, self.next.clone()) == expected
    }
}

/// A candidate waiting for its lower inclusion path. The ordinal is meaningful only in the
/// companion witness table of the payment table `payments` that returned the candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitnessRequest {
    pub key: KeyId,
    pub position: u32,
    pub cmx: [u8; 32],
    /// The identity of the payment session whose record carried `ordinal`.
    pub payments: [u8; 32],
    /// The companion witness session captured with that payment session. A witness-only
    /// replacement keeps `payments`, so this alone tells two companions apart.
    pub witnesses: [u8; 32],
    pub ordinal: u32,
}

/// An untrusted companion witness payload, with the witness revision and construction tree
/// it was served under. The wallet checks it against its own tree before crediting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessAnswer {
    /// The payment session the request named.
    pub payments: [u8; 32],
    /// The witness session that served `payload`.
    pub revision: [u8; 32],
    /// The block whose tree `payload` describes (see `decode_witness_payload`).
    pub context: PublicationEnd,
    pub payload: [u8; WITNESS_PAYLOAD_BYTES],
}

/// Resumable explicit historical search. Refund indexes are only the known funded keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManualProgress {
    pub active: bool,
    pub refunds_done: bool,
    pub next: u64,
    /// Exclusive receive-index bound, never shortened by the ordinary four-empty rule.
    pub receive_end: u64,
}

/// One account's durable progress and a bounded batch of due work.
/// With discovery disabled, work is restricted to repairing already-owned receipts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryStatus {
    pub enabled: bool,
    /// The receiver service needs a newer client. No work is exposed until a capture this
    /// client supports begins recovery again; every pending request is kept.
    pub upgrade_required: bool,
    pub token: RecoveryToken,
    pub filter_frontier: Option<ChainPoint>,
    /// Direct catch-up deliberately skipped completed old addresses through this height.
    pub skipped_through: Option<BlockHeight>,
    pub restore_next: u64,
    pub restore_gap: u8,
    pub restore_complete: bool,
    pub manual: Option<ManualProgress>,
    pub lookups: Vec<LookupWork>,
    pub witnesses: Vec<WitnessRequest>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_one_time_ivk::{KeyId, Purpose};

    const INVENTORY: [u8; 32] = [3; 32];

    /// Page `page` of a receiver history `total` pages long.
    fn record(page: u32, total: u32) -> DirectoryRecord {
        DirectoryRecord {
            receiver: [1; 43],
            page,
            total,
            payment: DirectoryPayment {
                height: 100 + page,
                block_hash: [0; 32],
                txid: [0; 32],
                tx_index: 1,
                action_index: 0,
                position: u64::from(page),
                action_nullifier: [0; 32],
                cmx: [0; 32],
                ephemeral_key: [0; 32],
                ciphertext_prefix: [0; 52],
            },
            ordinal: page,
        }
    }

    /// A shard of an inventory whose shard `i` ends at height `10 * (i + 1)`.
    fn shard(index: u32, segments: u32, excluded: bool) -> StepShard {
        StepShard {
            index,
            end_height: BlockHeight::from(10 * (index + 1)),
            segments,
            excluded,
        }
    }

    /// Work at `cursor` in an inventory, from height 1.
    fn work(cursor: Option<LookupCursor>) -> LookupWork {
        LookupWork {
            token: RecoveryToken {
                generation: 0,
                history_revision: 0,
            },
            work: DiscoveryWork {
                key: KeyId::new(Purpose::Receive, 0),
                receiver: [1; 43],
            },
            from: BlockHeight::from(1),
            through: BlockHeight::from(1),
            cursor,
        }
    }

    /// A cursor in the test inventory.
    fn at(shard: u32, segment: u32, last: Option<DirectoryRecord>) -> LookupCursor {
        LookupCursor {
            inventory: INVENTORY,
            shard,
            segment,
            last,
        }
    }

    /// A step in an inventory of `inventory_shards` shards that visits `shards`, reading
    /// `records` from the last one's `segment` unless it was excluded.
    fn step(
        inventory_shards: u32,
        shards: Vec<StepShard>,
        segment: Option<u32>,
        records: Vec<DirectoryRecord>,
        checked_through: Option<u32>,
        next: Option<LookupCursor>,
    ) -> LookupPage {
        let read = shards.last().unwrap().index;
        LookupPage {
            publication: RecoveryPublication {
                id: INVENTORY,
                history_revision: 0,
                start_height: BlockHeight::from(1),
                end: PublicationEnd {
                    height: BlockHeight::from(10 * inventory_shards),
                    hash: [0; 32],
                    tree_size: 1 << 20,
                },
            },
            inventory_shards,
            shards,
            segment: segment.map(|segment| SegmentRef {
                shard: read,
                segment,
                payments: [0; 32],
                witnesses: [0; 32],
            }),
            records,
            checked_through: checked_through.map(BlockHeight::from),
            next,
        }
    }

    /// A step that read page 0 of 2 and ended the request is refused: page 1 was never
    /// read, so neither completion nor coverage of the shard follows. The step that keeps
    /// its place after page 0 is the only valid one.
    #[test]
    fn a_step_cannot_complete_before_the_last_page() {
        let one = vec![shard(0, 1, false)];
        let early = step(1, one.clone(), Some(0), vec![record(0, 2)], Some(10), None);
        assert!(!early.valid_step(&work(None)));
        let kept = step(
            1,
            one,
            Some(0),
            vec![record(0, 2)],
            None,
            Some(at(0, 0, Some(record(0, 2)))),
        );
        assert!(kept.valid_step(&work(None)));
    }

    /// A step that finished shard 0's only segment continues at shard 1. A cursor with no
    /// saved record that jumps to shard 2, or to a later segment of the same shard, would
    /// skip history, so it is refused.
    #[test]
    fn a_step_cannot_jump_past_the_next_segment_or_shard() {
        let first = vec![shard(0, 1, false)];
        let valid = step(
            3,
            first.clone(),
            Some(0),
            vec![],
            Some(10),
            Some(at(1, 0, None)),
        );
        assert!(valid.valid_step(&work(None)));
        let jump = step(3, first, Some(0), vec![], Some(10), Some(at(2, 0, None)));
        assert!(!jump.valid_step(&work(None)));
        let two = vec![shard(0, 3, false)];
        assert!(
            step(3, two.clone(), Some(0), vec![], None, Some(at(0, 1, None)))
                .valid_step(&work(None))
        );
        assert!(!step(3, two, Some(0), vec![], None, Some(at(0, 2, None))).valid_step(&work(None)));
    }

    /// A step's coverage is exactly the end of the last shard it completed. One still
    /// reading shard 1 after excluding shard 0 covers through shard 0 only, and one that has
    /// not completed any shard covers nothing new.
    #[test]
    fn a_step_cannot_claim_coverage_past_what_it_completed() {
        let shards = vec![shard(0, 1, true), shard(1, 1, false)];
        let reading = Some(at(1, 0, Some(record(0, 2))));
        let valid = step(
            3,
            shards.clone(),
            Some(0),
            vec![record(0, 2)],
            Some(10),
            reading.clone(),
        );
        assert!(valid.valid_step(&work(None)));
        for claimed in [Some(20), Some(30), None] {
            let over = step(
                3,
                shards.clone(),
                Some(0),
                vec![record(0, 2)],
                claimed,
                reading.clone(),
            );
            assert!(!over.valid_step(&work(None)), "{claimed:?}");
        }
        let resumed = work(Some(at(1, 0, Some(record(0, 2)))));
        let unfinished = step(
            3,
            vec![shard(1, 1, false)],
            Some(0),
            vec![],
            Some(20),
            Some(at(1, 0, Some(record(0, 2)))),
        );
        assert!(!unfinished.valid_step(&resumed));
    }

    /// One reference step of an inventory where `excluded[i]` says shard `i`'s filter
    /// excludes the receiver and `histories[i][s]` is its page count in segment `s`, from
    /// `start`, reading at most `limit` pages: what the network step computes.
    fn reference(
        excluded: &[bool],
        histories: &[Vec<u32>],
        start: Option<LookupCursor>,
        limit: u32,
    ) -> (LookupWork, LookupPage) {
        let n = excluded.len() as u32;
        let (mut index, segment, last) = start
            .clone()
            .map_or((0, 0, None), |c| (c.shard, c.segment, c.last));
        let mut shards = vec![];
        let mut checked = None;
        loop {
            let segments = histories[index as usize].len() as u32;
            let visited = shard(index, segments, false);
            if excluded[index as usize] && segment == 0 && last.is_none()
                || excluded[index as usize] && index != start.as_ref().map_or(u32::MAX, |c| c.shard)
            {
                shards.push(StepShard {
                    excluded: true,
                    ..visited
                });
                checked = Some(visited.end_height);
                index += 1;
                if index == n {
                    let page = LookupPage {
                        checked_through: checked,
                        next: None,
                        ..step(n, shards, None, vec![], None, None)
                    };
                    return (work(start), page);
                }
                continue;
            }
            shards.push(visited);
            let segment = if Some(index) == start.as_ref().map(|c| c.shard) {
                segment
            } else {
                0
            };
            let prior = last
                .clone()
                .filter(|_| Some(index) == start.as_ref().map(|c| c.shard));
            let total = histories[index as usize][segment as usize];
            let from = prior.as_ref().map_or(0, |r| r.page + 1);
            let to = (from + limit).min(total);
            let records: Vec<_> = (from..to).map(|p| record(p, total)).collect();
            let finished = to == total;
            let next = if !finished {
                Some(at(index, segment, records.last().cloned().or(prior)))
            } else if segment + 1 < segments {
                Some(at(index, segment + 1, None))
            } else {
                checked = Some(visited.end_height);
                (index + 1 < n).then(|| at(index + 1, 0, None))
            };
            let page = step(n, shards, Some(segment), records, None, next);
            return (
                work(start),
                LookupPage {
                    checked_through: checked,
                    ..page
                },
            );
        }
    }

    /// How far a step leaves the request: its checked height, then its continuation.
    fn progress(page: &LookupPage) -> (Option<BlockHeight>, (u32, u32, i64)) {
        let next = page
            .next
            .as_ref()
            .map_or((u32::MAX, u32::MAX, i64::MAX), |c| {
                (
                    c.shard,
                    c.segment,
                    c.last.as_ref().map_or(-1, |r| i64::from(r.page)),
                )
            });
        (page.checked_through, next)
    }

    /// Random malformed versions of valid steps never advance coverage or position past
    /// what the step read: any mutation the validator accepts leaves both unchanged.
    #[test]
    fn mutated_steps_never_advance_past_what_was_read() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut below = |bound: u64| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) % bound
        };
        for _ in 0..2_000 {
            let n = 1 + below(4) as u32;
            let excluded: Vec<bool> = (0..n).map(|_| below(3) == 0).collect();
            let histories: Vec<Vec<u32>> = (0..n)
                .map(|_| (0..1 + below(3)).map(|_| below(4) as u32).collect())
                .collect();
            let start = (below(2) == 0).then(|| {
                let shard = below(u64::from(n)) as u32;
                let segment = below(histories[shard as usize].len() as u64) as u32;
                let total = histories[shard as usize][segment as usize];
                let last = (total > 1 && below(2) == 0)
                    .then(|| record(below(u64::from(total - 1)) as u32, total));
                at(shard, segment, last)
            });
            let (work, valid) = reference(&excluded, &histories, start, 1 + below(2) as u32);
            assert!(valid.valid_step(&work), "{valid:?} from {:?}", work.cursor);
            let mut mutated = valid.clone();
            match below(7) {
                0 => {
                    mutated.checked_through = Some(BlockHeight::from(below(50) as u32));
                }
                1 => mutated.checked_through = None,
                2 => mutated.next = None,
                3 => mutated.next = Some(at(below(u64::from(n) + 1) as u32, below(3) as u32, None)),
                4 => {
                    if let Some(r) = mutated.records.last_mut() {
                        r.total = r.page + 1;
                    }
                }
                5 => {
                    mutated.records.pop();
                }
                _ => {
                    if let Some(s) = mutated.shards.last_mut() {
                        s.excluded = !s.excluded;
                    }
                }
            }
            if mutated.valid_step(&work) {
                assert_eq!(
                    progress(&mutated),
                    progress(&valid),
                    "{mutated:?} accepted for {valid:?}"
                );
            }
        }
    }
}
