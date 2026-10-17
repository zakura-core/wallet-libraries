//! The revision numbering a publisher gives a shard it publishes again; the
//! manifest itself is [`zakura_transparent_private_shared::shard::manifest`].

/// What a shard id already has published, as the publisher reads it back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedRevision {
    pub digest: String,
    pub revision: u32,
    pub supersedes: String,
    pub sealed: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RevisionError {
    #[error("shard {0} is sealed; a sealed shard's content cannot change")]
    SealedChanged(u64),
}

impl PublishedRevision {
    /// The revision numbering a publication of this shard takes.
    ///
    /// `reproduced` says whether rebuilding under the published numbering
    /// produced the published digest — whether this is the same shard being
    /// published again, or a tail that has grown since.
    ///
    /// Republishing something identical must reproduce the identity it already
    /// has, or an idempotent re-run over the same journal would publish the
    /// same content under a second digest and the map would name the new one.
    /// A tail that has grown takes the next revision and records what it
    /// supersedes. A *sealed* shard whose content changed is neither: sealed
    /// shards are immutable, so that is an error rather than a revision.
    pub fn next(
        shard_id: u64,
        previous: Option<&PublishedRevision>,
        reproduced: bool,
    ) -> Result<(u32, String), RevisionError> {
        match previous {
            None => Ok((0, String::new())),
            Some(previous) if reproduced => Ok((previous.revision, previous.supersedes.clone())),
            Some(previous) if previous.sealed => Err(RevisionError::SealedChanged(shard_id)),
            Some(previous) => Ok((previous.revision + 1, previous.digest.clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_transparent_private_shared::shard::manifest::*;

    fn manifest() -> ShardManifest {
        ShardManifest {
            schema: SCHEMA.to_string(),
            profile: "zcash-transparent-range-v1".to_string(),
            geometry: "decoupled-2k-8k".to_string(),
            network: "main".to_string(),
            genesis_hash: "00".repeat(32),
            shard_id: 3,
            start_height: 3_428_143,
            end_height: 3_430_000,
            parent_block_hash: "11".repeat(32),
            terminal_block_hash: "22".repeat(32),
            tag_salt_counter: 0,
            parent_manifest_digest: "33".repeat(32),
            sealed: true,
            revision: 0,
            supersedes: String::new(),
            seal: ManifestSeal {
                scripts_target: 8_192,
                scripts_capacity: 16_384,
                directory_bytes_target: 7_000_000,
                directory_bytes_capacity: 8_000_000,
                page_rows_target: 2_048,
                page_rows_capacity: 4_096,
                max_page_children: 32,
            },
            layout: ManifestLayout {
                max_script_bytes: 40,
                inline_events: 2,
                events_per_page: zakura_transparent_private_shared::shard::EVENTS_PER_PAGE,
                page_row_header_bytes: 4,
                page_entry_header_bytes: 40,
                directory_choices: 2,
            },
            filter_hash: "44".repeat(32),
            directory_segments: vec![TableGeometry {
                rows: 2_048,
                row_bytes: 4_096,
                sha256: "55".repeat(32),
            }],
            page_children: vec![
                child(0, 3_428_143, 3_429_000, "77", 1_000, 1_500),
                child(1, 3_429_001, 3_430_000, "22", 879, 1_704),
            ],
            occupancy: ManifestOccupancy {
                scripts: 8_193,
                page_rows: 1_879,
                fragments: 3_204,
                events: 39_088,
                blocks: 1_858,
                txids: 10_355,
                excluded_scripts: 0,
            },
            directory_choice: None,
        }
    }

    fn child(
        index: u32,
        start_height: u64,
        end_height: u64,
        terminal: &str,
        page_rows: u64,
        fragments: u64,
    ) -> PageChild {
        PageChild {
            index,
            start_height,
            end_height,
            terminal_block_hash: terminal.repeat(32),
            tag_salt_counter: 0,
            sealed: true,
            page_segments: vec![TableGeometry {
                rows: 4_096,
                row_bytes: 4_096,
                sha256: format!("{:02x}", 0x66 + index).repeat(32),
            }],
            occupancy: PageChildOccupancy {
                page_rows,
                fragments,
                runs: 10,
                events: 20,
            },
        }
    }

    fn published(revision: u32, sealed: bool) -> PublishedRevision {
        PublishedRevision {
            digest: "aa".repeat(32),
            revision,
            supersedes: if revision == 0 {
                String::new()
            } else {
                "bb".repeat(32)
            },
            sealed,
        }
    }

    /// A first publication supersedes nothing.
    /// A manifest without a choice table serializes exactly as manifests did
    /// before the field existed, so no published digest moves; one with a
    /// table round-trips and is a different shard.
    #[test]
    fn an_absent_choice_table_leaves_the_canonical_bytes_unchanged() {
        let plain = manifest();
        let bytes = plain.canonical_bytes();
        assert!(!String::from_utf8_lossy(&bytes).contains("\"directory_choice\""));
        let parsed: ShardManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.directory_choice, None);
        assert_eq!(parsed.digest(), plain.digest());

        let mut tabled = plain.clone();
        tabled.occupancy.scripts = 1;
        tabled.directory_choice = Some(encode_directory_choice(
            &<zakura_transparent_private_shared::shard::ChoiceTable as crate::shard::ChoiceBuild>::build(3, &[(&[0x51][..], 1)]).unwrap(),
        ));
        let parsed: ShardManifest = serde_json::from_slice(&tabled.canonical_bytes()).unwrap();
        assert_eq!(parsed, tabled);
        assert!(parsed.directory_choice().unwrap().is_some());
        assert_ne!(tabled.digest(), plain.digest());
    }

    #[test]
    fn a_shard_published_for_the_first_time_is_revision_zero() {
        assert_eq!(
            PublishedRevision::next(3, None, false).unwrap(),
            (0, String::new())
        );
    }

    /// Re-running over the same journal must reproduce the identity already
    /// published, not publish the same content again under a new digest.
    #[test]
    fn republishing_the_same_shard_keeps_its_revision() {
        let previous = published(2, false);
        assert_eq!(
            PublishedRevision::next(3, Some(&previous), true).unwrap(),
            (2, previous.supersedes.clone())
        );
    }

    /// A tail that has grown is a new revision beside the old one, recording
    /// what it replaces so a wallet can tell replacement from extension.
    #[test]
    fn a_grown_tail_takes_the_next_revision_and_names_its_predecessor() {
        let previous = published(2, false);
        assert_eq!(
            PublishedRevision::next(3, Some(&previous), false).unwrap(),
            (3, previous.digest.clone())
        );
    }

    /// Sealed shards are immutable. Content that disagrees with a sealed shard
    /// is a build or journal fault, and publishing it as a revision would hide
    /// that behind a version number.
    #[test]
    fn a_sealed_shard_whose_content_changed_is_refused() {
        let previous = published(1, true);
        assert_eq!(
            PublishedRevision::next(3, Some(&previous), false),
            Err(RevisionError::SealedChanged(3))
        );
    }
}
