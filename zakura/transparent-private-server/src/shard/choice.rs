//! Building a directory shard's choice table; see
//! [`zakura_transparent_private_shared::shard::choice`].

use std::collections::BTreeMap;

use zakura_transparent_private_shared::shard::choice::{
    bit_bytes, positions, segment_length, ChoiceError, ChoiceTable, CHOICE_HEADER_BYTES,
    CHOICE_VERSION, MAX_KEYS, MAX_SEEDS,
};

/// Building a [`ChoiceTable`].
pub trait ChoiceBuild: Sized {
    /// Builds the table for `entries`, each a script and the candidate index
    /// (0 or 1) that holds it.
    ///
    /// Scripts must be distinct. Input order does not matter: entries are
    /// sorted first, so the peeling order and therefore the bytes depend only
    /// on the set.
    ///
    /// The table is returned as [`ChoiceTable::decode`] reads its published
    /// bytes, so a table that would not decode is never returned.
    fn build(shard_id: u64, entries: &[(&[u8], u8)]) -> Result<Self, ChoiceError>;
}

impl ChoiceBuild for ChoiceTable {
    fn build(shard_id: u64, entries: &[(&[u8], u8)]) -> Result<Self, ChoiceError> {
        if entries.len() > MAX_KEYS as usize {
            return Err(ChoiceError::TooManyKeys {
                keys: entries.len(),
            });
        }
        let mut sorted: BTreeMap<&[u8], u8> = BTreeMap::new();
        for (script, bit) in entries {
            if sorted.insert(script, bit & 1).is_some() {
                return Err(ChoiceError::Duplicate(hex::encode(script)));
            }
        }
        let keys = sorted.len() as u32;
        let segment = segment_length(keys);
        let slots = 3 * segment as usize;
        let sorted: Vec<(&[u8], u8)> = sorted.into_iter().collect();

        for seed in 0..MAX_SEEDS {
            let hashed: Vec<[usize; 3]> = sorted
                .iter()
                .map(|(script, _)| positions(shard_id, seed, segment, script))
                .collect();
            let Some(order) = peel(&hashed, slots) else {
                continue;
            };
            // Assign in reverse peeling order: each key's free position is set
            // last among the keys touching it, so its xor comes out right.
            let mut array = vec![0u8; slots];
            for &(key, free) in order.iter().rev() {
                let [a, b, c] = hashed[key];
                array[free] = 0;
                array[free] = sorted[key].1 ^ array[a] ^ array[b] ^ array[c];
            }
            let mut bits = vec![0u8; bit_bytes(segment)];
            for (i, bit) in array.iter().enumerate() {
                bits[i / 8] |= bit << (i % 8);
            }
            let mut encoded = Vec::with_capacity(CHOICE_HEADER_BYTES + bits.len());
            encoded.push(CHOICE_VERSION);
            encoded.extend_from_slice(&seed.to_le_bytes());
            encoded.extend_from_slice(&keys.to_le_bytes());
            encoded.extend_from_slice(&segment.to_le_bytes());
            encoded.extend_from_slice(&bits);
            return ChoiceTable::decode(&encoded);
        }
        Err(ChoiceError::Unpeelable {
            keys: keys as usize,
        })
    }
}

/// Peels the 3-hypergraph of `hashed` over `slots` positions.
///
/// Returns each key with the position it was peeled from, in peeling order, or
/// `None` if a core remains. Deterministic: positions are scanned in index order
/// and the stack is processed last in, first out.
fn peel(hashed: &[[usize; 3]], slots: usize) -> Option<Vec<(usize, usize)>> {
    let mut count = vec![0u32; slots];
    let mut xor = vec![0usize; slots];
    for (key, positions) in hashed.iter().enumerate() {
        for &at in positions {
            count[at] += 1;
            xor[at] ^= key;
        }
    }
    let mut stack: Vec<usize> = (0..slots).filter(|&at| count[at] == 1).collect();
    let mut order = Vec::with_capacity(hashed.len());
    while let Some(at) = stack.pop() {
        if count[at] != 1 {
            continue;
        }
        let key = xor[at];
        order.push((key, at));
        for &other in &hashed[key] {
            count[other] -= 1;
            xor[other] ^= key;
            if count[other] == 1 {
                stack.push(other);
            }
        }
    }
    (order.len() == hashed.len()).then_some(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(tag: u32) -> Vec<u8> {
        let mut bytes = vec![0x76, 0xa9, 0x14];
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&[0x88, 0xac]);
        bytes
    }

    fn bit(tag: u32) -> u8 {
        (tag.wrapping_mul(2_654_435_761) >> 7) as u8 & 1
    }

    fn fixture(count: u32) -> Vec<(Vec<u8>, u8)> {
        (0..count).map(|tag| (script(tag), bit(tag))).collect()
    }

    fn table(shard_id: u64, fixture: &[(Vec<u8>, u8)]) -> ChoiceTable {
        let entries: Vec<(&[u8], u8)> = fixture.iter().map(|(s, b)| (s.as_slice(), *b)).collect();
        ChoiceTable::build(shard_id, &entries).expect("builds")
    }

    #[test]
    fn every_indexed_script_returns_its_bit() {
        for count in [0, 1, 2, 14, 1_000, 45_454] {
            let fixture = fixture(count);
            let built = table(7, &fixture);
            assert_eq!(built.keys(), count);
            for (script, bit) in &fixture {
                assert_eq!(built.choice(7, script), *bit as usize, "{count} keys");
            }
        }
    }

    #[test]
    fn the_bytes_depend_on_the_set_not_the_order() {
        let fixture = fixture(5_000);
        let mut reversed = fixture.clone();
        reversed.reverse();
        assert_eq!(table(3, &fixture).encode(), table(3, &reversed).encode());
    }

    #[test]
    fn the_shard_id_keys_the_positions() {
        let fixture = fixture(5_000);
        assert_ne!(table(3, &fixture).encode(), table(4, &fixture).encode());
    }

    #[test]
    fn it_costs_about_one_and_a_quarter_bits_per_key() {
        let built = table(0, &fixture(45_454));
        let bytes = built.encode().len();
        // 45,454 keys at 1.23 bits plus the fixed 32 positions and header.
        assert!(bytes < 7_100, "{bytes} bytes");
        assert!(bytes > 6_900, "{bytes} bytes");
    }

    #[test]
    fn an_unindexed_script_still_names_one_candidate() {
        let built = table(1, &fixture(1_000));
        let mut seen = [0usize; 2];
        for tag in 1_000..3_000 {
            seen[built.choice(1, &script(tag))] += 1;
        }
        // Both answers occur: an absent script is not steered to either row.
        assert!(seen[0] > 800 && seen[1] > 800, "{seen:?}");
    }

    #[test]
    fn duplicates_are_refused() {
        let a = script(1);
        let entries: Vec<(&[u8], u8)> = vec![(&a, 0), (&a, 1)];
        assert!(matches!(
            ChoiceTable::build(0, &entries),
            Err(ChoiceError::Duplicate(_))
        ));
    }

    #[test]
    fn encoding_round_trips() {
        for count in [0, 1, 13, 4_000] {
            let built = table(9, &fixture(count));
            assert_eq!(ChoiceTable::decode(&built.encode()), Ok(built));
        }
    }

    #[test]
    fn malformed_bytes_are_refused_before_use() {
        let good = table(9, &fixture(1_001)).encode();
        let reject = |bytes: &[u8]| {
            assert!(
                matches!(ChoiceTable::decode(bytes), Err(ChoiceError::Malformed(_))),
                "accepted {} bytes",
                bytes.len()
            )
        };
        reject(&[]);
        reject(&good[..CHOICE_HEADER_BYTES - 1]);
        reject(&good[..good.len() - 1]);
        let mut long = good.clone();
        long.push(0);
        reject(&long);

        let mut version = good.clone();
        version[0] = 2;
        reject(&version);

        let mut seed = good.clone();
        seed[1..5].copy_from_slice(&MAX_SEEDS.to_le_bytes());
        reject(&seed);

        // A key count the segment does not match, including zero keys over a
        // nonzero array.
        let mut keys = good.clone();
        keys[5..9].copy_from_slice(&0u32.to_le_bytes());
        reject(&keys);

        let mut huge = good.clone();
        huge[5..9].copy_from_slice(&(MAX_KEYS + 1).to_le_bytes());
        reject(&huge);

        let mut segment = good.clone();
        let wrong = segment_length(1_001) + 1;
        segment[9..13].copy_from_slice(&wrong.to_le_bytes());
        reject(&segment);

        // Padding exists only when the array does not end on a byte boundary.
        let odd = table(9, &fixture(3)).encode();
        assert!(!(3 * segment_length(3)).is_multiple_of(8));
        let mut padding = odd.clone();
        *padding.last_mut().expect("bits") |= 0x80;
        reject(&padding);
    }
}
