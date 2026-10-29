// Deliberately simple, bit-by-bit packing for independently constructed golden
// requests. The verification-only provider probe checks this against IPIR at
// every served width; ordinary tests do not need the IPIR wrapper crates.
pub(super) fn u64s_to_contiguous_bytes(words: &[u64], width: usize) -> Vec<u8> {
    assert!((1..=64).contains(&width));
    let mut bytes = vec![0; (words.len() * width).div_ceil(8)];
    for (index, &word) in words.iter().enumerate() {
        for bit in 0..width {
            let offset = index * width + bit;
            bytes[offset / 8] |= (((word >> bit) & 1) as u8) << (offset % 8);
        }
    }
    bytes
}
