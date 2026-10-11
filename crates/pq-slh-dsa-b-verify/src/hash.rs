//! Upstream BLAKE3 verification roles, with safe streaming concatenation.

use crate::{address::Address, Node};

fn xof<const OUT: usize>(parts: &[&[u8]]) -> [u8; OUT] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0; OUT];
    hasher.finalize_xof().fill(&mut out);
    out
}

pub(crate) fn h_msg(
    randomizer: &[u8],
    pk_seed: &Node,
    pk_root: &Node,
    message: &[&[u8]],
) -> [u8; 30] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(randomizer);
    hasher.update(pk_seed);
    hasher.update(pk_root);
    for part in message {
        hasher.update(part);
    }
    let mut out = [0; 30];
    hasher.finalize_xof().fill(&mut out);
    out
}

pub(crate) fn f(pk_seed: &Node, adrs: &impl Address, message: &[u8]) -> Node {
    xof(&[pk_seed, &adrs.bytes(), message])
}

pub(crate) fn h(pk_seed: &Node, adrs: &impl Address, left: &[u8], right: &[u8]) -> Node {
    xof(&[pk_seed, &adrs.bytes(), left, right])
}

pub(crate) fn t<const LEN: usize>(
    pk_seed: &Node,
    adrs: &impl Address,
    message: &[Node; LEN],
) -> Node {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pk_seed);
    hasher.update(&adrs.bytes());
    for node in message {
        hasher.update(node);
    }
    let mut out = [0; 16];
    hasher.finalize_xof().fill(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_unkeyed_empty_xof() {
        // First 64 bytes of the BLAKE3 team's official length-zero test vector.
        let expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
            .to_owned()
            + "e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a";
        let actual: String = xof::<64>(&[])
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn official_unkeyed_vector_streams_across_parts() {
        // First 32 bytes of the official length-1025 test vector, whose input
        // repeats 0..=250. Parts split it across an empty part and a chunk boundary.
        let input: Vec<u8> = (0..1025).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let actual = xof::<32>(&[&input[..7], &[], &input[7..1024], &input[1024..]]);
        assert_eq!(
            actual
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"
        );
    }
}
