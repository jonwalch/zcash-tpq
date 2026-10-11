//! Fixed-profile versions of upstream `base_2b` and `split_digest`.

use crate::Node;

pub(crate) fn node(bytes: &[u8]) -> Node {
    bytes.try_into().expect("node slices have fixed length 16")
}

pub(crate) fn base_2b<const LEN: usize, const B: usize>(bytes: &[u8]) -> [u16; LEN] {
    let mut bits = 0;
    let mut offset = 0;
    let mut total = 0usize;
    std::array::from_fn(|_| {
        while bits < B {
            total = (total << 8) + usize::from(bytes[offset]);
            bits += 8;
            offset += 1;
        }
        bits -= B;
        let out = (total >> bits) & ((1 << B) - 1);
        // As in upstream, clear consumed bits to prevent accumulator overflow.
        total &= (1 << bits) - 1;
        u16::try_from(out).expect("fixed base widths are at most 12 bits")
    })
}

pub(crate) fn split_digest(digest: &[u8; 30]) -> (&[u8], u64, u32) {
    let mut tree_bytes = [0; 8];
    tree_bytes[1..].copy_from_slice(&digest[21..28]);
    let tree = u64::from_be_bytes(tree_bytes) & ((1u64 << 54) - 1);
    let leaf = u32::from(u16::from_be_bytes([digest[28], digest[29]])) & 0x1ff;
    (&digest[..21], tree, leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_masks_and_big_endian_digits() {
        let digest = [255; 30];
        let (message, tree, leaf) = split_digest(&digest);
        assert_eq!(message, &[255; 21]);
        assert_eq!(tree, (1u64 << 54) - 1);
        assert_eq!(leaf, 511);
        // Distinct bytes 1..=30 also pin each field's byte range, not only its mask.
        let digest: [u8; 30] = std::array::from_fn(|i| u8::try_from(i + 1).unwrap());
        let (message, tree, leaf) = split_digest(&digest);
        assert_eq!(message, &digest[..21]);
        assert_eq!(tree, 0x16_1718_191a_1b1c);
        assert_eq!(leaf, 0x11e);
        assert_eq!(base_2b::<2, 12>(&[0x12, 0x34, 0x56]), [0x123, 0x456]);
        assert_eq!(base_2b::<3, 4>(&[0x12, 0x30]), [1, 2, 3]);
    }
}
