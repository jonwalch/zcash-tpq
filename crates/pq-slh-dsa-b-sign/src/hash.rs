//! Pinned unkeyed BLAKE3 roles, using safe streaming and clearing owned state.

use zeroize::Zeroizing;

use crate::{address::Address, Node};

fn xof_into(parts: &[&[u8]], out: &mut [u8]) {
    let mut hasher = Zeroizing::new(blake3::Hasher::new());
    for part in parts {
        hasher.update(part);
    }
    let mut reader = Zeroizing::new(hasher.finalize_xof());
    reader.fill(out);
}

fn xof<const LEN: usize>(parts: &[&[u8]]) -> [u8; LEN] {
    let mut out = [0; LEN];
    xof_into(parts, &mut out);
    out
}

pub(crate) fn prf_sk(pk_seed: &Node, sk_seed: &Node, adrs: &impl Address) -> Zeroizing<Node> {
    let mut out = Zeroizing::new([0; 16]);
    xof_into(&[pk_seed, &adrs.bytes(), sk_seed], out.as_mut());
    out
}

pub(crate) fn prf_msg(sk_prf: &Node, random: &Node, message: &[u8; 101]) -> Node {
    xof(&[sk_prf, random, &[0, 0], message])
}

pub(crate) fn h_msg(
    randomizer: &Node,
    pk_seed: &Node,
    pk_root: &Node,
    message: &[u8; 101],
) -> [u8; 30] {
    xof(&[randomizer, pk_seed, pk_root, &[0, 0], message])
}

pub(crate) fn f(pk_seed: &Node, adrs: &impl Address, message: &[u8]) -> Node {
    xof(&[pk_seed, &adrs.bytes(), message])
}

pub(crate) fn f_secret(pk_seed: &Node, adrs: &impl Address, message: &Node) -> Zeroizing<Node> {
    let mut out = Zeroizing::new([0; 16]);
    xof_into(&[pk_seed, &adrs.bytes(), message], out.as_mut());
    out
}

pub(crate) fn h(pk_seed: &Node, adrs: &impl Address, left: &[u8], right: &[u8]) -> Node {
    xof(&[pk_seed, &adrs.bytes(), left, right])
}

pub(crate) fn t<const LEN: usize>(
    pk_seed: &Node,
    adrs: &impl Address,
    message: &[Node; LEN],
) -> Node {
    let mut hasher = Zeroizing::new(blake3::Hasher::new());
    hasher.update(pk_seed);
    hasher.update(&adrs.bytes());
    for node in message {
        hasher.update(node);
    }
    let mut out = [0; 16];
    let mut reader = Zeroizing::new(hasher.finalize_xof());
    reader.fill(&mut out);
    out
}
