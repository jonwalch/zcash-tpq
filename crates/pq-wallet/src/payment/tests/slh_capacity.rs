//! Compare actual product serialization with independent frozen W0 answers.
use super::*;
use zakura_chain::transparent::{Output, Script};

#[test]
fn all_120_policy_shapes_have_exact_sizes_and_current_fees() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
    ))
    .unwrap();
    for row in corpus["policies"].as_array().unwrap() {
        let entry = Entry {
            origins: vec![],
            policy_hex: row["policy_hex"].as_str().unwrap().into(),
            role: 0,
        };
        let authorization = row["authorization_bytes"].as_u64().unwrap() as usize;
        assert_eq!(
            entry.suite_policy().unwrap().authorization_size(),
            authorization
        );
        for version in [5, 6] {
            let input = Input::PrevOut {
                outpoint: OutPoint {
                    hash: zakura_chain::transaction::Hash([1; 32]),
                    index: 0,
                },
                unlock_script: Script::new(&[]),
                sequence: u32::MAX,
            };
            let output = Output {
                value: 1_000_000u64.try_into().unwrap(),
                lock_script: entry.suite_policy().unwrap().lock_script(),
            };
            let tx = review::transaction(version, vec![input.clone()], vec![output.clone(); 2], 20)
                .unwrap();
            let (bytes, fee) = review::estimate(&tx, &[&entry]).unwrap();
            let input_bytes = 40 + if authorization <= 65_535 { 3 } else { 5 } + authorization;
            assert_eq!(bytes, input_bytes + if version == 5 { 113 } else { 114 });
            assert_eq!(fee, (input_bytes as u64).div_ceil(150) * 400);
            if row["threshold"] == 15 && row["participants"] == 15 {
                assert_eq!(bytes, if version == 5 { 119_040 } else { 119_041 });
                let oversized =
                    review::transaction(version, vec![input; 3], vec![output; 2], 20).unwrap();
                assert!(matches!(
                    review::estimate(&oversized, &[&entry; 3]),
                    Err(Error::Limits)
                ));
            }
        }
    }
    let raw = corpus["partial_json"].as_str().unwrap().as_bytes();
    assert_eq!(raw.len(), 16_001);
    assert_eq!(Partial::from_json(raw).unwrap().to_json().unwrap(), raw);
    for slot in [15, u8::MAX] {
        let mut partial = Partial::from_json(raw).unwrap();
        partial.signer_index = slot;
        assert!(matches!(partial.to_json(), Err(Error::ProposalMismatch)));
    }
}

#[test]
fn recipient_dust_floor_is_2403_independent_of_signature_cost() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
    ))
    .unwrap();
    let receiver = corpus["policies"][0]["receiver"].as_str().unwrap();
    for amount in [2_402, 2_403, 2_404] {
        let intent = Intent {
            amount,
            max_fee: 100_000,
            receiver: receiver.into(),
            receiver_activation_height: None,
            remainder: Remainder::Keep,
            version: Some(6),
        };
        assert_eq!(intent.to_json().is_ok(), amount >= 2_403);
    }
}
