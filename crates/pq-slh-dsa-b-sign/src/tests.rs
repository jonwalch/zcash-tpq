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

struct TestEntropy {
    bytes: [u8; 16],
    calls: usize,
    fail: bool,
}

impl CryptoRng for TestEntropy {}

impl RngCore for TestEntropy {
    fn next_u32(&mut self) -> u32 {
        panic!("signer must use fallible byte entropy")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("signer must use fallible byte entropy")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("signer must use fallible byte entropy")
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Error> {
        self.calls += 1;
        assert_eq!(output.len(), 16);
        output.copy_from_slice(&self.bytes);
        if self.fail {
            Err(Error::from(NonZeroU32::new(Error::CUSTOM_START).unwrap()))
        } else {
            Ok(())
        }
    }
}

#[test]
fn independent_keys_and_prescribed_randomness_signatures() {
    for case in vectors()["cases"].as_array().unwrap() {
        let key = SigningKey::from_seed(Zeroizing::new(bytes(case, "seed")));
        assert_eq!(key.public_key(), &bytes::<32>(case, "public_key"));
        if !case["signature"].is_string() {
            continue;
        }
        let message = bytes(case, "message");
        let mut entropy = TestEntropy {
            bytes: bytes(case, "randomness"),
            calls: 0,
            fail: false,
        };
        let signature = key.sign_with_rng(&message, &mut entropy).unwrap();
        assert_eq!(entropy.calls, 1);
        assert_eq!(&*signature, &bytes::<SIGNATURE_BYTES>(case, "signature"));
        assert!(
            zakura_pq_slh_dsa_b_verify::verify(key.public_key(), &*signature, &message, &[])
                .is_ok()
        );
        let mut wrong_message = message;
        wrong_message[100] ^= 1;
        assert!(zakura_pq_slh_dsa_b_verify::verify(
            key.public_key(),
            &*signature,
            &wrong_message,
            &[]
        )
        .is_err());
        let mut double_framed = vec![0, 0];
        double_framed.extend(message);
        assert!(zakura_pq_slh_dsa_b_verify::verify(
            key.public_key(),
            &*signature,
            &double_framed,
            &[]
        )
        .is_err());
    }
}

#[test]
fn entropy_failure_has_no_signature_or_fallback() {
    // Invalid key bytes deliberately prove the failure precedes cryptography.
    let key = SigningKey {
        seed: Zeroizing::new([0; SEED_BYTES]),
        public_key: [0; PUBLIC_KEY_BYTES],
    };
    let mut entropy = TestEntropy {
        bytes: [0x55; 16],
        calls: 0,
        fail: true,
    };
    assert_eq!(
        key.sign_with_rng(&[0; 101], &mut entropy),
        Err(SignError::Entropy)
    );
    assert_eq!(entropy.calls, 1);
}

#[test]
fn local_verification_failure_releases_no_signature() {
    let case = &vectors()["cases"][0];
    let mut key = SigningKey::from_seed(Zeroizing::new(bytes(case, "seed")));
    key.public_key[31] ^= 1;
    let mut entropy = TestEntropy {
        bytes: bytes(case, "randomness"),
        calls: 0,
        fail: false,
    };
    assert_eq!(
        key.sign_with_rng(&bytes(case, "message"), &mut entropy),
        Err(SignError::Verification)
    );
    assert_eq!(entropy.calls, 1);
}

#[test]
fn operational_calls_obtain_fresh_randomness_and_verify() {
    let case = &vectors()["cases"][0];
    let key = SigningKey::from_seed(Zeroizing::new(bytes(case, "seed")));
    let message = bytes(case, "message");
    let first = key.sign(&message).unwrap();
    let second = key.sign(&message).unwrap();
    assert_ne!(&first[..N], &second[..N]);
    for signature in [first, second] {
        assert!(
            zakura_pq_slh_dsa_b_verify::verify(key.public_key(), &*signature, &message, &[])
                .is_ok()
        );
    }
}
