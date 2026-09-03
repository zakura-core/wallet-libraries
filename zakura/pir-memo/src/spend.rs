//! Nullifier lookups in the cold and warm bucket tables.
//!
//! A nullifier reveals nothing about the position of the note it spends, so
//! the tables are keyed by `hash(nf)`: one bucket per row, 112 entries of 41
//! bytes. A wallet always queries both tables for a nullifier, so which one
//! answers leaks nothing.

pub const NULLIFIER_ENTRY_BYTES: usize = 41;
pub const BUCKET_CAPACITY: usize = 112;
pub const BUCKET_BYTES: usize = BUCKET_CAPACITY * NULLIFIER_ENTRY_BYTES;

/// Where a nullifier's spending transaction sits in the chain and the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendMeta {
    pub spend_height: u32,
    /// Commitment-tree position of the spending transaction's first output.
    pub first_output_position: u32,
    /// Number of Ironwood actions in the spending transaction.
    pub action_count: u8,
}

/// Bucket (row) a nullifier lives in for a table of `num_buckets` rows. The
/// row count is the table's `positions` in the manifest.
pub fn hash_to_bucket(nullifier: &[u8; 32], num_buckets: u64) -> u64 {
    let prefix = u32::from_le_bytes(nullifier[..4].try_into().expect("four bytes"));
    u64::from(prefix) % num_buckets
}

/// Finds `nullifier` in one decoded bucket row.
pub fn scan_bucket(row: &[u8], nullifier: &[u8; 32]) -> Option<SpendMeta> {
    row.get(..BUCKET_BYTES)?
        .chunks_exact(NULLIFIER_ENTRY_BYTES)
        .find(|entry| &entry[..32] == nullifier)
        .map(|entry| SpendMeta {
            spend_height: u32::from_le_bytes(entry[32..36].try_into().expect("four bytes")),
            first_output_position: u32::from_le_bytes(
                entry[36..40].try_into().expect("four bytes"),
            ),
            action_count: entry[40],
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_an_entry_by_its_full_nullifier() {
        let mut row = vec![0u8; BUCKET_BYTES];
        let nf = [7u8; 32];
        let start = 3 * NULLIFIER_ENTRY_BYTES;
        row[start..start + 32].copy_from_slice(&nf);
        row[start + 32..start + 36].copy_from_slice(&3_428_200u32.to_le_bytes());
        row[start + 36..start + 40].copy_from_slice(&137_000u32.to_le_bytes());
        row[start + 40] = 3;
        assert_eq!(
            scan_bucket(&row, &nf),
            Some(SpendMeta {
                spend_height: 3_428_200,
                first_output_position: 137_000,
                action_count: 3
            })
        );
        let mut other = nf;
        other[31] ^= 1;
        assert_eq!(scan_bucket(&row, &other), None);
        assert_eq!(
            hash_to_bucket(
                &[
                    1, 0, 0, 0, 9, 9, 9, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0
                ],
                8
            ),
            1
        );
    }
}
