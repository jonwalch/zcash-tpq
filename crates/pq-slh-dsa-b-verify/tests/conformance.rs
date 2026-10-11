//! Retained independent Pure KATs and bounded rejection/mutation checks.

use serde::Deserialize;
use zakura_pq_slh_dsa_b_verify::{verify, VerifyError, MAX_MESSAGE_BYTES, SIGNATURE_BYTES};

#[derive(Deserialize)]
struct KatFile {
    cases: Vec<Kat>,
}

#[derive(Deserialize)]
struct Kat {
    id: usize,
    public_key: String,
    signature: String,
    message: String,
    context: String,
}

fn decode(hex: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "KAT hex must contain complete bytes"
    );
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digits = std::str::from_utf8(pair).expect("KAT hex is ASCII");
            u8::from_str_radix(digits, 16).expect("retained KAT fields are hex")
        })
        .collect()
}

fn kats() -> Vec<Kat> {
    serde_json::from_str::<KatFile>(include_str!("data/pure-kats.json"))
        .expect("retained KAT file has its declared schema")
        .cases
}

#[test]
fn independent_pure_known_answers() {
    let cases = kats();
    assert_eq!(cases.len(), 3);
    for case in cases {
        assert_eq!(
            verify(
                &decode(&case.public_key),
                &decode(&case.signature),
                &decode(&case.message),
                &decode(&case.context)
            ),
            Ok(()),
            "KAT {}",
            case.id
        );
    }
}

#[test]
fn every_signature_node_and_both_key_halves_are_bound() {
    let case = &kats()[0];
    let pk = decode(&case.public_key);
    let mut signature = decode(&case.signature);
    let message = decode(&case.message);
    let context = decode(&case.context);
    assert_eq!(verify(&pk, &signature, &message, &context), Ok(()));
    // One mutation in each encoded 16-byte node: randomizer, all FORS secret and
    // authentication nodes, every WOTS chain, and every XMSS authentication node.
    for offset in (0..SIGNATURE_BYTES).step_by(16) {
        signature[offset] ^= 1;
        assert_eq!(
            verify(&pk, &signature, &message, &context),
            Err(VerifyError::InvalidSignature),
            "signature node at byte {offset}"
        );
        signature[offset] ^= 1;
    }
    // First and last byte of the seed and root halves.
    for offset in [0, 15, 16, 31] {
        let mut altered = pk.clone();
        altered[offset] ^= 1;
        assert_eq!(
            verify(&altered, &signature, &message, &context),
            Err(VerifyError::InvalidSignature)
        );
    }
}

#[test]
fn message_context_and_single_pure_wrapper_are_bound() {
    for case in kats() {
        let pk = decode(&case.public_key);
        let signature = decode(&case.signature);
        let mut message = decode(&case.message);
        let context = decode(&case.context);
        message.push(0);
        assert_eq!(
            verify(&pk, &signature, &message, &context),
            Err(VerifyError::InvalidSignature)
        );
        let mut changed_context = context.clone();
        if changed_context.is_empty() {
            changed_context.push(0);
        } else {
            changed_context[0] ^= 1;
        }
        assert_eq!(
            verify(&pk, &signature, &decode(&case.message), &changed_context),
            Err(VerifyError::InvalidSignature)
        );
        let mut already_framed = vec![0, u8::try_from(context.len()).expect("KAT context fits u8")];
        already_framed.extend_from_slice(&context);
        already_framed.extend_from_slice(&decode(&case.message));
        assert_eq!(
            verify(&pk, &signature, &already_framed, &context),
            Err(VerifyError::InvalidSignature)
        );
    }
}

#[test]
fn exact_lengths_and_public_bounds() {
    let case = &kats()[0];
    let pk = decode(&case.public_key);
    let signature = decode(&case.signature);
    for length in [0, 1, 15, 16, 31, 33, 64] {
        assert_eq!(
            verify(&vec![0; length], &signature, &[], &[]),
            Err(VerifyError::PublicKeyLength)
        );
    }
    for length in [0, 1, 15, 16, 2927, 2928, 7855, 7857] {
        assert_eq!(
            verify(&pk, &vec![0; length], &[], &[]),
            Err(VerifyError::SignatureLength)
        );
    }
    assert_eq!(
        verify(&pk, &signature, &vec![0; 65_536], &[]),
        Err(VerifyError::InvalidSignature)
    );
    assert_eq!(
        verify(&pk, &signature, &vec![0; 65_537], &[]),
        Err(VerifyError::MessageTooLong)
    );
    assert_eq!(MAX_MESSAGE_BYTES, 65_536);
    assert_eq!(
        verify(&pk, &signature, &[], &[0; 255]),
        Err(VerifyError::InvalidSignature)
    );
    assert_eq!(
        verify(&pk, &signature, &[], &[0; 256]),
        Err(VerifyError::ContextTooLong)
    );
    // Documented precedence: public key, signature, message, then context.
    assert_eq!(
        verify(&[], &[], &vec![0; 65_537], &[0; 256]),
        Err(VerifyError::PublicKeyLength)
    );
    assert_eq!(
        verify(&pk, &[], &vec![0; 65_537], &[0; 256]),
        Err(VerifyError::SignatureLength)
    );
    assert_eq!(
        verify(&pk, &signature, &vec![0; 65_537], &[0; 256]),
        Err(VerifyError::MessageTooLong)
    );
}
