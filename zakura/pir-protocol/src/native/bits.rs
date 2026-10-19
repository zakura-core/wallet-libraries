//! Shared wire codec, moved unchanged from IPIR-SP revision 5ea080a.

/// Write the low `num_bits` bits of `val` into `data` at `bit_offs`, little-endian within bytes.
pub fn write_bits(data: &mut [u8], mut val: u64, bit_offs: usize, mut num_bits: usize) {
    let mut byte_index = bit_offs / 8;
    let mut bit_index = bit_offs % 8;

    while num_bits > 0 && byte_index < data.len() {
        let bits_to_write = std::cmp::min(8 - bit_index, num_bits);
        let bitmask = (1 << bits_to_write) - 1;
        let bits = (val & bitmask) << bit_index;

        data[byte_index] |= bits as u8;

        num_bits -= bits_to_write;
        bit_index += bits_to_write;

        if bit_index == 8 {
            byte_index += 1;
            bit_index = 0;
        }

        val >>= bits_to_write;
    }
}

/// Read `num_bits` bits from `data` at `bit_offs`, little-endian within bytes.
#[must_use]
pub fn read_bits(data: &[u8], bit_offs: usize, num_bits: usize) -> u64 {
    assert!(
        (1..=64).contains(&num_bits),
        "invalid number of bits: {num_bits}"
    );

    let byte_pos = bit_offs / 8;
    let mut bit_pos = bit_offs % 8;
    let mut result = 0u64;
    let mut remaining_bits = num_bits;

    for byte in data.iter().skip(byte_pos) {
        let can_take = std::cmp::min(8 - bit_pos, remaining_bits);
        let value = if can_take < 8 {
            (byte >> bit_pos) & ((1 << can_take) - 1)
        } else {
            byte >> bit_pos
        };

        result |= (value as u64) << (num_bits - remaining_bits);
        remaining_bits -= can_take;
        if remaining_bits == 0 {
            break;
        }

        bit_pos = 0;
    }

    result
}

/// Pack integers into a contiguous byte string using exactly `inp_mod_bits` bits per value.
#[must_use]
pub fn u64s_to_contiguous_bytes(data: &[u64], inp_mod_bits: usize) -> Vec<u8> {
    let total_sz = (data.len() * inp_mod_bits).div_ceil(8);
    let mut out = vec![0u8; total_sz];
    let mut bit_offs = 0;
    for val in data {
        write_bits(&mut out, *val, bit_offs, inp_mod_bits);
        bit_offs += inp_mod_bits;
    }
    out
}

/// Unpack a byte string produced by [`u64s_to_contiguous_bytes`].
#[must_use]
pub fn contiguous_bytes_to_u64s(data: &[u8], out_mod_bits: usize) -> Vec<u64> {
    let out_len = (data.len() * 8) / out_mod_bits;
    let mut out = vec![0u64; out_len];
    let mut bit_offs = 0;
    for val in &mut out {
        *val = read_bits(data, bit_offs, out_mod_bits);
        bit_offs += out_mod_bits;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_read_bits_match_ypir_layout() {
        let mut buffer = [0u8; 4];
        write_bits(&mut buffer, 0b11010101, 1, 6);
        assert_eq!(buffer, [0b00101010, 0, 0, 0]);

        let value = read_bits(&buffer, 1, 6);
        assert_eq!(value, 0b010101);
    }

    #[test]
    fn contiguous_roundtrip_handles_non_byte_widths() {
        let vals = [0, 1, 42, 8191, 1234, 7];
        let packed = u64s_to_contiguous_bytes(&vals, 13);
        assert_eq!(contiguous_bytes_to_u64s(&packed, 13), vals);
    }
}
