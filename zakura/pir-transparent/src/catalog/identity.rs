//! Stable identities: the companion's binding, a source, and a shard revision, and the
//! map entries they identify.

use sha2::{Digest, Sha256};
use transparent_filter::{ShardMapEntry, SupersededShard};
use transparent_wallet::SetIdentity;
use zcash_client_backend::data_api::transparent_ledger::{PublicationAnchor, RecoveryRevision};

use crate::convert::{block, block_hash};
use crate::error::{RecoveryError, failure};

/// The companion's binding: length-prefixed source, account binding, origin and
/// schema. Every source this companion derives includes it.
pub(crate) fn binding(parts: [&[u8]; 4]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for value in parts {
        length_prefixed(&mut hash, value);
    }
    hash.finalize().into()
}

fn length_prefixed(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_le_bytes());
    hash.update(value);
}

/// One shard revision a map publishes, or one a re-cut it declares superseded,
/// identified as the wallet and the catalog identify it.
#[derive(Clone)]
pub(crate) struct Published {
    /// The shard id it is published, or was published, under. Manifests bind
    /// the id, so a stored fact under this revision must name it.
    pub(crate) shard_id: u64,
    pub(crate) start_height: u64,
    pub(crate) end_height: u64,
    pub(crate) digest: String,
    /// The block the revision ends on, display hex.
    pub(crate) terminal: String,
    pub(crate) revision: RecoveryRevision,
}

impl Published {
    /// `entry` of a publication whose set identity is `set`, for a companion
    /// bound to `binding`.
    pub(crate) fn of(
        binding: &[u8; 32],
        set: &SetIdentity,
        entry: &ShardMapEntry,
    ) -> Result<Self, RecoveryError> {
        Self::new(
            binding,
            set,
            Shape {
                shard_id: entry.shard_id,
                geometry: &entry.geometry,
                start_height: entry.start_height,
                end_height: entry.end_height,
                terminal: &entry.terminal_block_hash,
                digest: &entry.manifest_digest,
                revision: entry.revision,
                sealed: entry.sealed,
            },
        )
    }

    /// A revision a re-cut of a publication whose set identity is `set`
    /// declares superseded, exactly as the wallet received it when it was
    /// published, for a companion bound to `binding`.
    pub(crate) fn declared(
        binding: &[u8; 32],
        set: &SetIdentity,
        shard: &SupersededShard,
    ) -> Result<Self, RecoveryError> {
        Self::new(
            binding,
            set,
            Shape {
                shard_id: shard.shard_id,
                geometry: &shard.geometry,
                start_height: shard.start_height,
                end_height: shard.end_height,
                terminal: &shard.terminal_block_hash,
                digest: &shard.manifest_digest,
                revision: shard.revision,
                sealed: shard.sealed,
            },
        )
    }

    fn new(binding: &[u8; 32], set: &SetIdentity, shape: Shape<'_>) -> Result<Self, RecoveryError> {
        Ok(Self {
            shard_id: shape.shard_id,
            start_height: shape.start_height,
            end_height: shape.end_height,
            digest: shape.digest.to_owned(),
            terminal: shape.terminal.to_owned(),
            revision: RecoveryRevision {
                source: source(binding, set, shape.geometry, shape.start_height)?.to_vec(),
                revision: revision(shape.digest, shape.sealed).to_vec(),
                // The publisher's revision number, offset so a first
                // publication is lineage 1.
                lineage: u64::from(shape.revision) + 1,
                sealed: shape.sealed,
                publication: PublicationAnchor {
                    height: block(shape.end_height)?,
                    hash: block_hash(shape.terminal)?,
                },
            },
        })
    }

    /// Where this revision's commit is kept while a pass builds its batch: two
    /// revisions of one source share a start height but not a digest.
    pub(crate) fn key(&self) -> (u64, String) {
        (self.start_height, self.digest.clone())
    }

    pub(super) fn height(&self) -> u32 {
        u32::from(self.revision.publication.height)
    }

    pub(super) fn hash(&self) -> &[u8] {
        self.revision.publication.hash.0.as_slice()
    }
}

/// The fields of a map entry, published or superseded, that identify it.
struct Shape<'a> {
    shard_id: u64,
    geometry: &'a str,
    start_height: u64,
    end_height: u64,
    terminal: &'a str,
    digest: &'a str,
    revision: u32,
    sealed: bool,
}

/// The stable identity of the shards of a publication that start at
/// `start_height` under `geometry`, for one companion binding.
///
/// It hashes the set-identity fields [`SetIdentity::continues`] holds fixed,
/// plus the geometry, that geometry's seal parameters and the start height,
/// and not the shard id. A re-cut renumbers every later shard and the tail
/// without changing where they start, so their next revisions stay in the
/// sources the wallet holds, while a re-cut range, which starts elsewhere or
/// under another geometry, gets new sources. A set growing into a new geometry
/// tier changes no existing source, and a set-identity change `continues`
/// refuses changes every source it affects.
pub(crate) fn source(
    binding: &[u8; 32],
    set: &SetIdentity,
    geometry: &str,
    start_height: u64,
) -> Result<[u8; 32], RecoveryError> {
    let seal = set
        .seal
        .get(geometry)
        .ok_or_else(|| RecoveryError::Invalid("shard geometry has no seal parameters".into()))?;
    // Canonical: serde writes the fields in declaration order.
    let seal = serde_json::to_vec(seal).map_err(failure)?;
    let mut hash = Sha256::new();
    hash.update(b"transparent-reference-source-v3");
    hash.update(binding);
    length_prefixed(&mut hash, set.shard_schema.as_bytes());
    length_prefixed(&mut hash, set.network.as_bytes());
    length_prefixed(&mut hash, set.genesis_hash.as_bytes());
    length_prefixed(&mut hash, set.profile.as_bytes());
    hash.update(set.range_envelope_version.to_le_bytes());
    hash.update(set.start_height.to_le_bytes());
    length_prefixed(&mut hash, geometry.as_bytes());
    length_prefixed(&mut hash, &seal);
    hash.update(start_height.to_le_bytes());
    Ok(hash.finalize().into())
}

/// A shard revision's identity: its manifest digest and whether it is sealed.
fn revision(digest: &str, sealed: bool) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"transparent-reference-revision-v2");
    hash.update(digest.as_bytes());
    hash.update([u8::from(sealed)]);
    hash.finalize().into()
}
