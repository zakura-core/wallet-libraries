//! Cross both native profiles with the pinned pre-packaging implementation.
use candidate_client::native::ProfileClientExt;
use candidate_core::native::ProfilePublicationExt;
use candidate_protocol::native::{D, P8, P16, Q};
use candidate_query::native::ProfileQueryExt;

fn scan(database: &[Vec<u16>], selection: &[u64]) -> Vec<u64> {
    database
        .iter()
        .map(|column| {
            column
                .iter()
                .zip(selection)
                .fold(0u64, |sum, (&entry, &coefficient)| {
                    sum.wrapping_add(u64::from(entry).wrapping_mul(coefficient)) & (Q - 1)
                })
        })
        .collect()
}

fn main() {
    let (rows, cols, target) = (2 * D, D, 2 * D - 1);
    for profile in [P8, P16] {
        let previous = if profile == P8 {
            previous_native::P8
        } else {
            previous_native::P16
        };
        let database: Vec<Vec<u16>> = (0..cols)
            .map(|col| {
                (0..rows)
                    .map(|row| ((row * 17 + col * 3) % (1 << profile.p_bits)) as u16)
                    .collect()
            })
            .collect();
        let masks = profile.public_query_masks([3; 32], rows, cols).unwrap();
        assert_eq!(
            masks,
            previous.public_query_masks([3; 32], rows, cols).unwrap()
        );
        let setup = previous_native::NativeSetup::new(previous.params(), [9; 32]);
        let old_hint = previous_native::hint(&masks, rows, cols, |col| &database[col]).unwrap();
        let hint = candidate_core::native::hint(&masks, rows, cols, |col| &database[col]).unwrap();
        assert_eq!(hint, old_hint);
        let old_blocks = previous_native::preprocess(&setup, &old_hint).unwrap();
        let blocks = candidate_core::native::preprocess(&setup, &hint).unwrap();
        let old_public = previous.publish(&old_blocks).unwrap();
        let public = profile.publish(&blocks).unwrap();
        assert_eq!(public, old_public);
        let expected: Vec<u8> = database
            .iter()
            .flat_map(|column| {
                column[target]
                    .to_le_bytes()
                    .into_iter()
                    .take(profile.entry_bytes())
            })
            .collect();

        // An old client sends its original width to the new serving operations.
        let (secret, request) = previous.prepare(&setup, &masks, rows, target).unwrap();
        let (keys, selection) = profile.parse_accepted(&setup, &request, rows).unwrap();
        let response = profile
            .pack(&blocks, &keys, &scan(&database, &selection))
            .unwrap();
        assert_eq!(
            previous
                .decode_cols(&secret, &public, &response, cols)
                .unwrap(),
            expected
        );

        // The new client sends a dithered selection to the old serving operations.
        let (secret, request) = profile
            .prepare_dithered(&setup, &masks, rows, target)
            .unwrap();
        let (keys, selection) = previous.parse_accepted(&setup, &request, rows).unwrap();
        let response = previous
            .pack(&old_blocks, &keys, &scan(&database, &selection))
            .unwrap();
        assert_eq!(
            profile
                .decode_cols(&secret, &old_public, &response, cols)
                .unwrap(),
            expected
        );
        println!(
            "p{}: old client/new server and new client/old server passed",
            profile.p_bits
        );
    }
}
