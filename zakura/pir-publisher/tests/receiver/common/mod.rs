//! Fixtures shared by the receiver publication tests.

/// `len` distinct canonical commitments.
pub fn leaves(len: usize) -> Vec<[u8; 32]> {
    (0..len)
        .map(|i| {
            let mut cmx = [0; 32];
            cmx[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            cmx
        })
        .collect()
}
