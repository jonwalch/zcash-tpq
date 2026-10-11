//! Fixed-profile upstream FORS, WOTS+, XMSS and hypertree recovery algorithms.
//!
//! Signature slices are borrowed from the already length-checked input. All loop
//! bounds and slice widths below are fixed profile constants, not input values.

use crate::{
    address::{ForsTree, WotsHash},
    hash, util, Node, A, D, H_PRIME, K, N, WOTS_BYTES, WOTS_LEN, XMSS_BYTES,
};

pub(crate) fn fors_pk_from_sig(
    signature: &[u8],
    md: &[u8],
    pk_seed: &Node,
    tree: u64,
    key_pair: u32,
) -> Node {
    let mut adrs = ForsTree {
        tree,
        key_pair,
        height: 0,
        index: 0,
    };
    let indices = util::base_2b::<K, A>(md);
    let mut roots = [[0; N]; K];
    for (i, (signature, index)) in signature
        .as_chunks::<{ (A + 1) * N }>()
        .0
        .iter()
        .zip(indices)
        .enumerate()
    {
        adrs.height = 0;
        adrs.index = (u32::try_from(i).expect("FORS has 14 trees") << A) + u32::from(index);
        let (secret, auth) = signature.split_at(N);
        let mut node = hash::f(pk_seed, &adrs, secret);
        for (j, sibling) in auth.as_chunks::<N>().0.iter().enumerate() {
            adrs.height = u32::try_from(j + 1).expect("FORS height is at most 12");
            adrs.index >>= 1;
            node = if (index >> j) & 1 == 0 {
                hash::h(pk_seed, &adrs, &node, sibling)
            } else {
                hash::h(pk_seed, &adrs, sibling, &node)
            };
        }
        roots[i] = node;
    }
    hash::t(pk_seed, &adrs.fors_roots(), &roots)
}

fn wots_chain(x: &[u8], start: u32, steps: u32, pk_seed: &Node, adrs: &WotsHash) -> Node {
    let mut tmp = util::node(x);
    let mut adrs = *adrs;
    for j in start..start + steps {
        adrs.hash = j;
        tmp = hash::f(pk_seed, &adrs, &tmp);
    }
    tmp
}

fn wots_pk_from_sig(signature: &[u8], message: &Node, pk_seed: &Node, adrs: &WotsHash) -> Node {
    let msg = util::base_2b::<32, 4>(message);
    let csum = msg.iter().map(|&digit| 15 - digit).sum::<u16>() << 4;
    let csum_chunks = util::base_2b::<3, 4>(&csum.to_be_bytes());
    let msg_csum = msg.iter().chain(csum_chunks.iter());
    let mut adrs = *adrs;
    let mut tmp = [[0; N]; WOTS_LEN];
    for (i, (signature, &digit)) in signature
        .as_chunks::<N>()
        .0
        .iter()
        .zip(msg_csum)
        .enumerate()
    {
        adrs.chain = u32::try_from(i).expect("WOTS has 35 chains");
        let digit = u32::from(digit);
        tmp[i] = wots_chain(signature, digit, 15 - digit, pk_seed, &adrs);
    }
    hash::t(pk_seed, &adrs.pk_adrs(), &tmp)
}

fn xmss_pk_from_sig(
    mut index: u32,
    signature: &[u8],
    message: &Node,
    pk_seed: &Node,
    adrs: &WotsHash,
) -> Node {
    let mut adrs = *adrs;
    adrs.key_pair = index;
    let (wots_signature, auth) = signature.split_at(WOTS_BYTES);
    let mut node = wots_pk_from_sig(wots_signature, message, pk_seed, &adrs);
    let mut adrs = adrs.tree_adrs();
    for (j, sibling) in auth.as_chunks::<N>().0.iter().enumerate() {
        adrs.height = u32::try_from(j + 1).expect("XMSS height is at most 9");
        let rem = index & 1;
        index >>= 1;
        adrs.index = index;
        node = if rem == 0 {
            hash::h(pk_seed, &adrs, &node, sibling)
        } else {
            hash::h(pk_seed, &adrs, sibling, &node)
        };
    }
    node
}

pub(crate) fn ht_root(
    message: &Node,
    signature: &[u8],
    pk_seed: &Node,
    mut idx_tree: u64,
    mut idx_leaf: u32,
) -> Node {
    let mut adrs = WotsHash {
        tree: idx_tree,
        ..WotsHash::default()
    };
    let mut root = xmss_pk_from_sig(idx_leaf, &signature[..XMSS_BYTES], message, pk_seed, &adrs);
    for j in 1..D {
        idx_leaf = u32::try_from(idx_tree & ((1 << H_PRIME) - 1))
            .expect("masked leaf index has at most 9 bits");
        idx_tree >>= H_PRIME;
        adrs.layer = u32::try_from(j).expect("hypertree has 7 layers");
        adrs.tree = idx_tree;
        root = xmss_pk_from_sig(
            idx_leaf,
            &signature[j * XMSS_BYTES..(j + 1) * XMSS_BYTES],
            &root,
            pk_seed,
            &adrs,
        );
    }
    root
}
