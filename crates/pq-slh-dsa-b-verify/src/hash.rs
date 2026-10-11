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
}
