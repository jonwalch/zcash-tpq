//! Fixed-profile serial signing loops adapted from pinned Suite B algorithms.

use zeroize::Zeroizing;

use crate::{
    address::{ForsTree, WotsHash},
    hash, recovery, util, Node, A, D, H_PRIME, K, N, WOTS_BYTES, WOTS_LEN, XMSS_BYTES,
};

fn wots_chain(
    mut secret: Zeroizing<Node>,
    steps: u32,
    pk_seed: &Node,
    adrs: &WotsHash,
) -> Zeroizing<Node> {
    let mut adrs = *adrs;
    for j in 0..steps {
        adrs.hash = j;
        // Replacing the owner drops and clears the preceding chain state.
        secret = hash::f_secret(pk_seed, &adrs, &secret);
    }
    secret
}

fn wots_pk_gen(sk_seed: &Node, pk_seed: &Node, adrs: &WotsHash) -> Node {
    let mut adrs = *adrs;
    let mut sk_adrs = adrs.prf_adrs();
    let mut nodes = [[0; N]; WOTS_LEN];
    for (i, node) in nodes.iter_mut().enumerate() {
        let i = u32::try_from(i).expect("WOTS has 35 chains");
        sk_adrs.chain = i;
        adrs.chain = i;
        let secret = hash::prf_sk(pk_seed, sk_seed, &sk_adrs);
        node.copy_from_slice(&*wots_chain(secret, 15, pk_seed, &adrs));
    }
    hash::t(pk_seed, &adrs.pk_adrs(), &nodes)
}

fn wots_sign(
    message: &Node,
    sk_seed: &Node,
    pk_seed: &Node,
    adrs: &WotsHash,
    signature: &mut [u8],
) {
    let msg = util::base_2b::<32, 4>(message);
    let checksum = msg.iter().map(|&digit| 15 - digit).sum::<u16>() << 4;
    let checksum = util::base_2b::<3, 4>(&checksum.to_be_bytes());
    let mut adrs = *adrs;
    let mut sk_adrs = adrs.prf_adrs();
    for (i, (out, &digit)) in signature
        .as_chunks_mut::<N>()
        .0
        .iter_mut()
        .zip(msg.iter().chain(checksum.iter()))
        .enumerate()
    {
        let i = u32::try_from(i).expect("WOTS has 35 chains");
        sk_adrs.chain = i;
        adrs.chain = i;
        let secret = hash::prf_sk(pk_seed, sk_seed, &sk_adrs);
        out.copy_from_slice(&*wots_chain(secret, u32::from(digit), pk_seed, &adrs));
    }
}

pub(crate) fn xmss_node(
    sk_seed: &Node,
    node: u32,
    height: u32,
    pk_seed: &Node,
    adrs: &WotsHash,
) -> Node {
    if height == 0 {
        let mut adrs = *adrs;
        adrs.key_pair = node;
        wots_pk_gen(sk_seed, pk_seed, &adrs)
    } else {
        let left = xmss_node(sk_seed, 2 * node, height - 1, pk_seed, adrs);
        let right = xmss_node(sk_seed, 2 * node + 1, height - 1, pk_seed, adrs);
        let mut adrs = adrs.tree_adrs();
        adrs.height = height;
        adrs.index = node;
        hash::h(pk_seed, &adrs, &left, &right)
    }
}

fn xmss_sign(
    message: &Node,
    sk_seed: &Node,
    pk_seed: &Node,
    mut index: u32,
    adrs: &WotsHash,
    signature: &mut [u8],
) {
    let mut adrs = *adrs;
    adrs.key_pair = index;
    let (wots, auth) = signature.split_at_mut(WOTS_BYTES);
    wots_sign(message, sk_seed, pk_seed, &adrs, wots);
    for (j, sibling) in auth.as_chunks_mut::<N>().0.iter_mut().enumerate() {
        let height = u32::try_from(j).expect("XMSS height is at most 9");
        sibling.copy_from_slice(&xmss_node(sk_seed, index ^ 1, height, pk_seed, &adrs));
        index >>= 1;
    }
}

fn fors_node(sk_seed: &Node, index: u32, height: u32, pk_seed: &Node, adrs: &ForsTree) -> Node {
    let mut adrs = ForsTree {
        tree: adrs.tree,
        key_pair: adrs.key_pair,
        height,
        index,
    };
    if height == 0 {
        let secret = hash::prf_sk(pk_seed, sk_seed, &adrs.prf_adrs(index));
        hash::f(pk_seed, &adrs, secret.as_ref())
    } else {
        let left = fors_node(sk_seed, 2 * index, height - 1, pk_seed, &adrs);
        let right = fors_node(sk_seed, 2 * index + 1, height - 1, pk_seed, &adrs);
        adrs.height = height;
        adrs.index = index;
        hash::h(pk_seed, &adrs, &left, &right)
    }
}

pub(crate) fn fors_sign(
    message: &[u8],
    sk_seed: &Node,
    pk_seed: &Node,
    tree: u64,
    leaf: u32,
    signature: &mut [u8],
) {
    let adrs = ForsTree {
        tree,
        key_pair: leaf,
        height: 0,
        index: 0,
    };
    for (i, (out, index)) in signature
        .as_chunks_mut::<{ (A + 1) * N }>()
        .0
        .iter_mut()
        .zip(util::base_2b::<K, A>(message))
        .enumerate()
    {
        let i = u32::try_from(i).expect("FORS has 14 trees");
        let secret = hash::prf_sk(
            pk_seed,
            sk_seed,
            &adrs.prf_adrs((i << A) + u32::from(index)),
        );
        let (out_secret, auth) = out.split_at_mut(N);
        out_secret.copy_from_slice(secret.as_ref());
        for (j, sibling) in auth.as_chunks_mut::<N>().0.iter_mut().enumerate() {
            let node = (i << (A - j)) + u32::from((index >> j) ^ 1);
            let height = u32::try_from(j).expect("FORS height is at most 12");
            sibling.copy_from_slice(&fors_node(sk_seed, node, height, pk_seed, &adrs));
        }
    }
}

pub(crate) fn ht_sign(
    message: &Node,
    sk_seed: &Node,
    pk_seed: &Node,
    mut tree: u64,
    mut leaf: u32,
    signature: &mut [u8],
) {
    let mut root = *message;
    let mut adrs = WotsHash {
        tree,
        ..WotsHash::default()
    };
    for (layer, out) in signature
        .as_chunks_mut::<XMSS_BYTES>()
        .0
        .iter_mut()
        .enumerate()
    {
        if layer != 0 {
            leaf = u32::try_from(tree & ((1 << H_PRIME) - 1))
                .expect("masked leaf index has at most 9 bits");
            tree >>= H_PRIME;
            adrs.layer = u32::try_from(layer).expect("hypertree has 7 layers");
            adrs.tree = tree;
        }
        xmss_sign(&root, sk_seed, pk_seed, leaf, &adrs, out);
        if layer != D - 1 {
            root = recovery::xmss_pk_from_sig(leaf, out, &root, pk_seed, &adrs);
        }
    }
}
