use super::{HEADER, MAX_WITNESS_BYTES, NODE, WitnessSnapshot};
use crate::{Error, Hash, snapshot::Manifest};
use incrementalmerkletree::Hashable;
use orchard::{note::ExtractedNoteCommitment, tree::MerkleHashOrchard};
use std::collections::{BTreeMap, BTreeSet};

/// Disposable tree nodes for successive publications. No cached chain anchor is trusted.
/// Nodes use about 64 bytes per leaf, plus spare vector capacity. A restart rebuilds them.
#[derive(Default)]
pub struct WitnessCache {
    levels: Vec<Vec<MerkleHashOrchard>>,
}

impl WitnessCache {
    /// Compare the complete canonical commitment prefix before reusing any tree nodes.
    /// Appends, shorter histories and replacement forks all recompute the affected suffix.
    /// `positions` must hold one position per manifest record, though a matching count
    /// cannot prove they are the right ones. Publication fencing and independent
    /// chain-root validation remain the caller's job. A file over
    /// [`MAX_WITNESS_BYTES`] is [`Error::Capacity`], found while collecting its nodes.
    pub fn build(
        &mut self,
        manifest: &Manifest,
        commitments: &[Hash],
        positions: &BTreeSet<u32>,
    ) -> Result<WitnessSnapshot, Error> {
        manifest.validate()?;
        if manifest.start_position != 0
            || manifest.end_position != commitments.len() as u64
            || positions.len() as u64 != manifest.records
            || positions
                .iter()
                .any(|p| u64::from(*p) >= manifest.end_position)
        {
            return Err(Error::Coverage);
        }
        // An empty tree, so no records or positions either, has no levels to combine.
        if commitments.is_empty() {
            self.levels.clear();
            return WitnessSnapshot::from_nodes(
                manifest,
                MerkleHashOrchard::empty_root(32.into()).to_bytes(),
                BTreeMap::new(),
            );
        }
        self.levels.resize_with(33, Vec::new);
        let shared = self.levels[0]
            .iter()
            .zip(commitments)
            .take_while(|(old, new)| old.to_bytes() == **new)
            .count();
        // Parse before mutating the cache so a malformed suffix cannot leave partial levels.
        let suffix = commitments[shared..]
            .iter()
            .map(|cmx| {
                Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(cmx))
                    .map(|c| MerkleHashOrchard::from_cmx(&c))
                    .ok_or(Error::Malformed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let changed = shared != self.levels[0].len() || shared != commitments.len();
        self.levels[0].truncate(shared);
        self.levels[0].extend(suffix);
        if changed {
            let mut first_changed = shared;
            for depth in 0..32 {
                let (lower, upper) = self.levels.split_at_mut(depth + 1);
                let children = &lower[depth];
                let parents = &mut upper[0];
                // Recompute the last surviving pair after a rewind too: its right
                // child may now be the empty subtree instead of an orphaned node.
                let first_parent = (first_changed / 2).min((children.len() - 1) / 2);
                parents.truncate(first_parent);
                let empty = MerkleHashOrchard::empty_root((depth as u8).into());
                parents.extend(children[first_parent * 2..].chunks(2).map(|pair| {
                    MerkleHashOrchard::combine(
                        (depth as u8).into(),
                        &pair[0],
                        pair.get(1).unwrap_or(&empty),
                    )
                }));
                first_changed = first_parent;
            }
        }
        let max_nodes = (MAX_WITNESS_BYTES - HEADER) / NODE;
        let mut nodes = BTreeMap::new();
        for depth in 0..32u8 {
            for position in positions {
                let index = (*position >> depth) ^ 1;
                if let Some(hash) = self.levels[depth as usize].get(index as usize) {
                    if nodes.insert((depth, index), *hash).is_none() && nodes.len() > max_nodes {
                        return Err(Error::Capacity);
                    }
                }
            }
        }
        WitnessSnapshot::from_nodes(manifest, self.levels[32][0].to_bytes(), nodes)
    }
}
