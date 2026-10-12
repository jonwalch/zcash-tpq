//! Deterministic public fixture inputs. These seeds must never hold funds.
//! Generation and product signing for verification fixtures are untimed.

use zakura_pq_slh_dsa_b_sign::{SigningKey, MESSAGE_BYTES, SEED_BYTES, SIGNATURE_BYTES};
use zakura_pq_slh_dsa_b_verify::{verify, VerifyError};
use zeroize::Zeroizing;

const MESSAGE_DOMAIN: &[u8; 58] = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/message/v1\0";

pub fn seed(index: u32) -> Zeroizing<[u8; SEED_BYTES]> {
    let mut seed = Zeroizing::new([0; SEED_BYTES]);
    let mut hash = blake3::Hasher::new();
    hash.update(b"tpq-bench/public-fixture/key/v1\0");
    hash.update(&index.to_le_bytes());
    hash.finalize_xof().fill(seed.as_mut());
    seed
}

pub fn message(index: u32) -> [u8; MESSAGE_BYTES] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"tpq-bench/public-fixture/digest/v1\0");
    hash.update(&index.to_le_bytes());
    let mut message = [0; MESSAGE_BYTES];
    message[..58].copy_from_slice(MESSAGE_DOMAIN);
    message[58..61].copy_from_slice(&[0xf7, 2, 5]);
    message[61..65].copy_from_slice(&0x77190ad9u32.to_le_bytes());
    message[65..69].copy_from_slice(&0u32.to_le_bytes());
    message[69..].copy_from_slice(hash.finalize().as_bytes());
    message
}

pub struct SignatureFixture {
    pub message: [u8; MESSAGE_BYTES],
    pub signature: Box<[u8; SIGNATURE_BYTES]>,
}

impl SignatureFixture {
    pub fn prepare(key: &SigningKey, index: u32) -> Result<Self, String> {
        let message = message(index);
        let mut signature = key
            .sign(&message)
            .map_err(|error| format!("fixture signing failed: {error}"))?;
        preflight(key.public_key(), &mut *signature, &message)?;
        Ok(Self { message, signature })
    }

    pub fn corrupt(&mut self) {
        self.signature[SIGNATURE_BYTES - 1] ^= 1;
    }
}

fn preflight(public_key: &[u8], signature: &mut [u8], message: &[u8]) -> Result<(), String> {
    verify(public_key, signature, message, &[])
        .map_err(|error| format!("valid fixture preflight failed: {error}"))?;
    signature[SIGNATURE_BYTES - 1] ^= 1;
    let result = verify(public_key, signature, message, &[]);
    signature[SIGNATURE_BYTES - 1] ^= 1;
    if result != Err(VerifyError::InvalidSignature) {
        return Err("corrupted fixture preflight did not return InvalidSignature".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_inputs_vary_without_changing_the_protocol_frame() {
        let first = message(0);
        let next = message(1);
        assert_eq!(first.len(), 101);
        assert_eq!(&first[..58], MESSAGE_DOMAIN);
        assert_eq!(&first[58..61], &[0xf7, 2, 5]);
        assert_eq!(&first[61..65], &0x77190ad9u32.to_le_bytes());
        assert_eq!(&first[65..69], &[0; 4]);
        assert_eq!(&first[..69], &next[..69]);
        assert_ne!(&first[69..], &next[69..]);
        assert_eq!(message(0), first);
        assert_ne!(*seed(0), *seed(1));
        assert_eq!(*seed(0), *seed(0));
    }

    #[test]
    fn existing_public_transaction_fixture_passes_and_corruption_is_rejected() {
        // Consume the existing upstream-signed public fixture. No signing or
        // fixture generation occurs in this focused verifier control.
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/slh-dsa-b128s/fixtures/data/v5-1of1.json"
        )))
        .unwrap();
        let input = &fixture["inputs"][0];
        let record = &input["records"][0];
        let key = hex::decode(record["public_key_hex"].as_str().unwrap()).unwrap();
        let mut signature = hex::decode(record["signature_hex"].as_str().unwrap()).unwrap();
        let message = hex::decode(input["message_hex"].as_str().unwrap()).unwrap();
        assert_eq!(message.len(), MESSAGE_BYTES);
        assert_eq!(&message[..58], MESSAGE_DOMAIN);
        assert_eq!(signature.len(), SIGNATURE_BYTES);
        let original_signature = signature.clone();
        assert!(preflight(&key, &mut signature, &message).is_ok());
        assert_eq!(
            signature, original_signature,
            "preflight must restore the valid fixture"
        );
        signature[SIGNATURE_BYTES - 1] ^= 1;
        assert_eq!(
            verify(&key, &signature, &message, &[]),
            Err(VerifyError::InvalidSignature)
        );
    }
}
