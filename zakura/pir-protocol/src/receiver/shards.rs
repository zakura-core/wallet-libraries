//! Sealed Receiver shard filters. A match schedules PIR; it never establishes ownership,
//! and an unavailable, malformed or mismatched filter means PIR, never absence.
//!
//! Each sealed shard keeps one GCS set of its distinct receivers for as long as its payment
//! history is served. A shard can hold far more receivers than one block, so these bounds
//! are separate from [`super::blocks::MAX_RECEIVERS`]. Decoding and matching stream the
//! set, so memory does not grow with the shard's population.
use super::{Error, Hash, ReceiverBytes, gcs};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, ops::ControlFlow};
use zakura_filters::GcsFilterWriter;

/// Golomb-Rice parameter and range multiplier, the block hints' false-positive rate.
pub const P: u8 = 20;
pub const M: u64 = 1_569_792;
/// Maximum distinct receivers in one shard filter.
pub const MAX_RECEIVERS: u32 = 1 << 23;
/// Maximum encoded filter, enforced by transports before buffering. Every receiver costs
/// at least `P + 1` bits, so this also bounds the count a filter can claim.
pub const MAX_FILTER_BYTES: usize = 24 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"IWSHARD1";
/// Magic, genesis, correction generation, the three coverage fields and the set length.
const HEADER: usize = 8 + 32 + 8 + 4 + 4 + 32 + 4;

/// The chain coverage a shard filter is keyed to: inclusive heights and the last block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coverage {
    pub start_height: u32,
    pub end_height: u32,
    pub end_hash: Hash,
}

/// One sealed shard's validated receiver set, kept encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardFilter {
    genesis: Hash,
    history_revision: u64,
    coverage: Coverage,
    count: u64,
    /// The whole encoding, which [`Self::digest`] covers.
    bytes: Vec<u8>,
}

/// The SipHash salt of a shard's set, fixed by network and chain coverage.
fn salt(genesis: &Hash, coverage: &Coverage) -> Hash {
    Sha256::new()
        .chain_update(b"ironwood-receiver/v1/shard-filter\0")
        .chain_update(genesis)
        .chain_update(coverage.start_height.to_le_bytes())
        .chain_update(coverage.end_height.to_le_bytes())
        .chain_update(coverage.end_hash)
        .finalize()
        .into()
}

impl ShardFilter {
    /// Encodes the distinct `receivers` of a shard. More than [`MAX_RECEIVERS`] or an
    /// encoding over [`MAX_FILTER_BYTES`] is [`Error::Capacity`].
    pub fn build<'a>(
        genesis: Hash,
        history_revision: u64,
        coverage: Coverage,
        receivers: impl IntoIterator<Item = &'a ReceiverBytes>,
    ) -> Result<Self, Error> {
        if coverage.start_height > coverage.end_height {
            return Err(Error::Coverage);
        }
        let mut distinct = BTreeSet::new();
        for receiver in receivers {
            distinct.insert(*receiver);
            if distinct.len() > MAX_RECEIVERS as usize {
                return Err(Error::Capacity);
            }
        }
        let (k0, k1) = gcs::keys(&salt(&genesis, &coverage));
        let mut set = Vec::new();
        let mut writer = GcsFilterWriter::new(&mut set, k0, k1, M, P);
        for receiver in &distinct {
            writer.add_element(receiver);
        }
        writer.finish().expect("in-memory filter");
        let mut bytes = MAGIC.to_vec();
        bytes.extend(genesis);
        bytes.extend(history_revision.to_le_bytes());
        bytes.extend(coverage.start_height.to_le_bytes());
        bytes.extend(coverage.end_height.to_le_bytes());
        bytes.extend(coverage.end_hash);
        bytes.extend((set.len() as u32).to_le_bytes());
        bytes.extend(set);
        if bytes.len() > MAX_FILTER_BYTES {
            return Err(Error::Capacity);
        }
        Self::decode(&bytes)
    }

    /// [`Self::decode`] for a body a shard descriptor names by `digest`. The digest is
    /// checked first, so a substituted body costs one hash, never a decode of its set: a
    /// mismatch is [`Error::Coverage`]. The caller must still check coverage.
    pub fn decode_named(bytes: &[u8], digest: &Hash) -> Result<Self, Error> {
        if bytes.len() > MAX_FILTER_BYTES {
            return Err(Error::Capacity);
        }
        if &<[u8; 32]>::from(Sha256::digest(bytes)) != digest {
            return Err(Error::Coverage);
        }
        Self::decode(bytes)
    }

    /// Strictly parses a filter, validating every bit with bounded memory. The caller must
    /// still check [`Self::digest`] and coverage against the shard it captured.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_FILTER_BYTES {
            return Err(Error::Capacity);
        }
        if bytes.len() < HEADER || &bytes[..8] != MAGIC {
            return Err(Error::Malformed);
        }
        let len = u32::from_le_bytes(bytes[HEADER - 4..HEADER].try_into().unwrap()) as usize;
        if bytes.len() - HEADER != len {
            return Err(Error::Malformed);
        }
        let coverage = Coverage {
            start_height: u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
            end_height: u32::from_le_bytes(bytes[52..56].try_into().unwrap()),
            end_hash: bytes[56..88].try_into().unwrap(),
        };
        if coverage.start_height > coverage.end_height {
            return Err(Error::Coverage);
        }
        let count = gcs::visit(&bytes[HEADER..], P, M, u64::from(MAX_RECEIVERS), |_| {
            ControlFlow::Continue(())
        })?;
        Ok(Self {
            genesis: bytes[8..40].try_into().unwrap(),
            history_revision: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            coverage,
            count,
            bytes: bytes.to_vec(),
        })
    }

    /// Checks that this filter is for `genesis`, correction `history_revision` and exactly
    /// `coverage`.
    pub fn check(
        &self,
        genesis: &Hash,
        history_revision: u64,
        coverage: &Coverage,
    ) -> Result<(), Error> {
        if &self.genesis != genesis
            || self.history_revision != history_revision
            || &self.coverage != coverage
        {
            return Err(Error::Coverage);
        }
        Ok(())
    }

    /// The canonical encoding.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 of the encoding, which a shard descriptor binds.
    pub fn digest(&self) -> Hash {
        Sha256::digest(&self.bytes).into()
    }

    /// Distinct receivers in the set.
    pub fn receivers(&self) -> u64 {
        self.count
    }

    /// Which of `receivers` may be in the set, in the same order, streaming the set once
    /// and stopping after the largest value any of them hashes to.
    pub fn matches(&self, receivers: &[ReceiverBytes]) -> Vec<bool> {
        self.matches_visiting(receivers).0
    }

    /// [`Self::matches`], with how many set values it decoded.
    fn matches_visiting(&self, receivers: &[ReceiverBytes]) -> (Vec<bool>, u64) {
        let keys = gcs::keys(&salt(&self.genesis, &self.coverage));
        let mut wanted: Vec<(u64, usize)> = receivers
            .iter()
            .enumerate()
            .map(|(i, r)| (gcs::value(keys, self.count, M, r), i))
            .collect();
        wanted.sort_unstable();
        let mut found = vec![false; receivers.len()];
        let mut next = 0;
        let mut visited = 0;
        if !wanted.is_empty() {
            gcs::visit(
                &self.bytes[HEADER..],
                P,
                M,
                u64::from(MAX_RECEIVERS),
                |value| {
                    visited += 1;
                    while next < wanted.len() && wanted[next].0 < value {
                        next += 1;
                    }
                    let mut i = next;
                    while i < wanted.len() && wanted[i].0 == value {
                        found[wanted[i].1] = true;
                        i += 1;
                    }
                    // Values only grow, so none past the last wanted one can match.
                    if next == wanted.len() || value >= wanted[wanted.len() - 1].0 {
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    }
                },
            )
            .expect("validated at decode");
        }
        (found, visited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Matching stops after the last value a wanted receiver could equal: a receiver that
    /// hashes near the start of the range decodes a few values, not the whole set, and the
    /// answer agrees with a full traversal.
    #[test]
    fn matching_stops_after_the_last_wanted_value() {
        let coverage = Coverage {
            start_height: 1,
            end_height: 9,
            end_hash: [2; 32],
        };
        let members: Vec<ReceiverBytes> = (0..10_000u32)
            .map(|i| {
                let mut r = [7; 43];
                r[..4].copy_from_slice(&i.to_le_bytes());
                r
            })
            .collect();
        let filter = ShardFilter::build([1; 32], 0, coverage, &members).unwrap();
        let keys = gcs::keys(&salt(&filter.genesis, &filter.coverage));
        let low = *members
            .iter()
            .min_by_key(|r| gcs::value(keys, filter.count, M, r))
            .unwrap();
        let (found, visited) = filter.matches_visiting(&[low]);
        assert_eq!(found, [true]);
        assert!(
            visited < 100,
            "{visited} of {} values decoded",
            filter.count
        );
        let (all, visited) = filter.matches_visiting(&members);
        assert!(all.iter().all(|m| *m));
        assert!(visited <= filter.count);
        assert_eq!(filter.matches_visiting(&[]).1, 0);
    }
}
