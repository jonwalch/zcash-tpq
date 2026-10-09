//! Valid NIST SHA2/SHAKE signatures must fail the BLAKE3 profile at crypto.

use serde::Deserialize;
use zakura_pq_slh_dsa_b_verify::{verify, VerifyError, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};

#[derive(Deserialize)]
struct Controls {
    cases: Vec<Control>,
}

#[derive(Deserialize)]
struct Control {
    parameter_set: String,
    valid_in_source_profile: bool,
    public_key: String,
    signature: String,
    message: String,
    context: String,
}

fn decode(encoded: &str) -> Vec<u8> {
    assert!(encoded.len().is_multiple_of(2));
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
                .expect("public control contains valid hex")
        })
        .collect()
}

#[test]
fn source_valid_sha2_and_shake_signatures_reject_at_crypto() {
    let controls: Controls = serde_json::from_str(include_str!(
        "../../../tests/slh-dsa-b128s/primitive-controls/wrong-profiles.json"
    ))
    .expect("retained public controls have the expected schema");
    assert_eq!(controls.cases.len(), 2);
    assert_eq!(
        controls
            .cases
            .iter()
            .map(|case| case.parameter_set.as_str())
            .collect::<Vec<_>>(),
        ["SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s"]
    );
    for case in controls.cases {
        assert!(case.valid_in_source_profile);
        let public_key = decode(&case.public_key);
        let signature = decode(&case.signature);
        assert_eq!(public_key.len(), PUBLIC_KEY_BYTES);
        assert_eq!(signature.len(), SIGNATURE_BYTES);
        assert_eq!(
            verify(
                &public_key,
                &signature,
                &decode(&case.message),
                &decode(&case.context)
            ),
            Err(VerifyError::InvalidSignature),
            "{} is valid in its source profile, not BLAKE3",
            case.parameter_set
        );
    }
}
