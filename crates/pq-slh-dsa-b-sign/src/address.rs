//! Full 32-byte addresses, adapted from upstream `address.rs`.
//!
//! Explicit big-endian serialization replaces the upstream zerocopy layout.
//! Typed transitions retain exactly the fields retained by the upstream code.

pub(crate) trait Address {
    fn bytes(&self) -> [u8; 32];
}

fn encode(layer: u32, tree: u64, kind: u32, words: [u32; 3]) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..4].copy_from_slice(&layer.to_be_bytes());
    // The high 32 tree bits are always zero for this fixed profile.
    bytes[8..16].copy_from_slice(&tree.to_be_bytes());
    bytes[16..20].copy_from_slice(&kind.to_be_bytes());
    for (chunk, word) in bytes[20..].as_chunks_mut::<4>().0.iter_mut().zip(words) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    bytes
}

#[derive(Clone, Copy, Default)]
pub(crate) struct WotsHash {
    pub layer: u32,
    pub tree: u64,
    pub key_pair: u32,
    pub chain: u32,
    pub hash: u32,
}

impl Address for WotsHash {
    fn bytes(&self) -> [u8; 32] {
        encode(
            self.layer,
            self.tree,
            0,
            [self.key_pair, self.chain, self.hash],
        )
    }
}

impl WotsHash {
    pub fn prf_adrs(&self) -> WotsPrf {
        WotsPrf {
            layer: self.layer,
            tree: self.tree,
            key_pair: self.key_pair,
            chain: 0,
        }
    }

    pub fn pk_adrs(&self) -> WotsPk {
        WotsPk {
            layer: self.layer,
            tree: self.tree,
            key_pair: self.key_pair,
        }
    }

    pub fn tree_adrs(&self) -> HashTree {
        HashTree {
            layer: self.layer,
            tree: self.tree,
            height: 0,
            index: 0,
        }
    }
}

pub(crate) struct WotsPk {
    layer: u32,
    tree: u64,
    key_pair: u32,
}

impl Address for WotsPk {
    fn bytes(&self) -> [u8; 32] {
        encode(self.layer, self.tree, 1, [self.key_pair, 0, 0])
    }
}

pub(crate) struct HashTree {
    layer: u32,
    tree: u64,
    pub height: u32,
    pub index: u32,
}

impl Address for HashTree {
    fn bytes(&self) -> [u8; 32] {
        encode(self.layer, self.tree, 2, [0, self.height, self.index])
    }
}

pub(crate) struct ForsTree {
    pub tree: u64,
    pub key_pair: u32,
    pub height: u32,
    pub index: u32,
}

impl Address for ForsTree {
    fn bytes(&self) -> [u8; 32] {
        encode(0, self.tree, 3, [self.key_pair, self.height, self.index])
    }
}

impl ForsTree {
    pub fn prf_adrs(&self, index: u32) -> ForsPrf {
        ForsPrf {
            tree: self.tree,
            key_pair: self.key_pair,
            index,
        }
    }

    pub fn fors_roots(&self) -> ForsRoots {
        ForsRoots {
            tree: self.tree,
            key_pair: self.key_pair,
        }
    }
}

pub(crate) struct WotsPrf {
    layer: u32,
    tree: u64,
    key_pair: u32,
    pub chain: u32,
}

impl Address for WotsPrf {
    fn bytes(&self) -> [u8; 32] {
        encode(self.layer, self.tree, 5, [self.key_pair, self.chain, 0])
    }
}

pub(crate) struct ForsPrf {
    tree: u64,
    key_pair: u32,
    index: u32,
}

impl Address for ForsPrf {
    fn bytes(&self) -> [u8; 32] {
        encode(0, self.tree, 6, [self.key_pair, 0, self.index])
    }
}

pub(crate) struct ForsRoots {
    tree: u64,
    key_pair: u32,
}

impl Address for ForsRoots {
    fn bytes(&self) -> [u8; 32] {
        encode(0, self.tree, 4, [self.key_pair, 0, 0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_addresses_and_type_transitions() {
        let address = WotsHash {
            layer: 0x01020304,
            tree: 0x1112131415161718,
            key_pair: 0x21222324,
            chain: 0x31323334,
            hash: 0x41424344,
        };
        assert_eq!(
            address.bytes(),
            [
                1, 2, 3, 4, 0, 0, 0, 0, 17, 18, 19, 20, 21, 22, 23, 24, 0, 0, 0, 0, 33, 34, 35, 36,
                49, 50, 51, 52, 65, 66, 67, 68
            ]
        );
        let pk = address.pk_adrs().bytes();
        assert_eq!(&pk[..16], &address.bytes()[..16]);
        assert_eq!(
            &pk[16..],
            &[0, 0, 0, 1, 33, 34, 35, 36, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        let mut tree = address.tree_adrs();
        assert_eq!(&tree.bytes()[..16], &address.bytes()[..16]);
        assert_eq!(
            &tree.bytes()[16..],
            &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        (tree.height, tree.index) = (5, 9);
        assert_eq!(
            &tree.bytes()[16..],
            &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 9]
        );
        let prf = address.prf_adrs().bytes();
        assert_eq!(&prf[..16], &address.bytes()[..16]);
        assert_eq!(
            &prf[16..],
            &[0, 0, 0, 5, 33, 34, 35, 36, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        let fors = ForsTree {
            tree: address.tree,
            key_pair: address.key_pair,
            height: 12,
            index: 42,
        };
        // FORS addresses force layer 0 and keep the full tree address.
        assert_eq!(
            fors.bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 17, 18, 19, 20, 21, 22, 23, 24, 0, 0, 0, 3, 33, 34, 35, 36,
                0, 0, 0, 12, 0, 0, 0, 42
            ]
        );
        assert_eq!(&fors.fors_roots().bytes()[..16], &fors.bytes()[..16]);
        assert_eq!(
            &fors.fors_roots().bytes()[16..],
            &[0, 0, 0, 4, 33, 34, 35, 36, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(&fors.prf_adrs(42).bytes()[..16], &fors.bytes()[..16]);
        assert_eq!(
            &fors.prf_adrs(42).bytes()[16..],
            &[0, 0, 0, 6, 33, 34, 35, 36, 0, 0, 0, 0, 0, 0, 0, 42]
        );
    }
}
