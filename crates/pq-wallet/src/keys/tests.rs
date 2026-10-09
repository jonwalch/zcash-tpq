use std::num::NonZeroU32;

use rand_core::{CryptoRng, Error, RngCore};
use serde_json::Value;

use super::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/slh-dsa-b128s/wallet/vectors.json"
    )))
    .unwrap()
}

fn bytes<const LEN: usize>(value: &Value, field: &str) -> [u8; LEN] {
    hex::decode(value[field].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn independent_derivation_blocks_roots_and_suite_separation() {
    let vectors = vectors();
    let root = Root {
        bytes: Zeroizing::new(bytes(&vectors, "root")),
    };
    for case in vectors["cases"].as_array().unwrap() {
        let role = match case["role"].as_u64().unwrap() {
            0 => Role::Receive,
            1 => Role::Change,
            _ => panic!("fixture role"),
        };
        let path = KeyPath {
            role,
            index: u32::try_from(case["index"].as_u64().unwrap()).unwrap(),
        };
        assert_eq!(&*root.seed(path), &bytes::<48>(case, "seed"));
        assert_eq!(
            root.derive_key(path).public_key(),
            &bytes::<32>(case, "public_key")
        );

        let (prk, hkdf) = Hkdf::<Sha256>::extract(
            Some(b"ZcashTransparentPQ/wallet-root/v1\0"),
            root.bytes.as_ref(),
        );
        assert_eq!(prk.as_slice(), bytes::<32>(case, "prk"));
        let mut both_blocks = Zeroizing::new([0; 64]);
        hkdf.expand(
            &hex::decode(case["info"].as_str().unwrap()).unwrap(),
            both_blocks.as_mut(),
        )
        .unwrap();
        assert_eq!(&both_blocks[..32], &bytes::<32>(case, "t1"));
        assert_eq!(&both_blocks[32..], &bytes::<32>(case, "t2"));
    }
    let seed = root.seed(KeyPath {
        role: Role::Receive,
        index: 0,
    });
    for control in vectors["suite_separation"].as_array().unwrap() {
        assert_ne!(&*seed, &bytes::<48>(control, "seed"));
    }
}

struct FailingEntropy(usize);
impl CryptoRng for FailingEntropy {}
impl RngCore for FailingEntropy {
    fn next_u32(&mut self) -> u32 {
        panic!("root must use fallible entropy")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("root must use fallible entropy")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("root must use fallible entropy")
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Error> {
        self.0 += 1;
        assert_eq!(output.len(), 32);
        output.fill(0x55);
        Err(Error::from(NonZeroU32::new(Error::CUSTOM_START).unwrap()))
    }
}

#[test]
fn root_entropy_failure_returns_no_root() {
    let mut entropy = FailingEntropy(0);
    assert!(matches!(
        Root::generate_with_rng(&mut entropy),
        Err(RootEntropyError)
    ));
    assert_eq!(entropy.0, 1);
}

#[test]
fn operational_roots_are_independent() {
    let first = Root::generate().unwrap();
    let second = Root::generate().unwrap();
    assert_ne!(&first.bytes[..], &second.bytes[..]);
}
