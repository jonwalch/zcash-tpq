use super::*;
use serde_json::Value;
use zakura_chain::serialization::ZcashDeserialize;

#[test]
fn only_frozen_suite_and_partial_identity_are_accepted() {
    let suite = Suite::SlhDsaB128sExpV1;
    assert_eq!(Suite::from_byte(0xf7).unwrap(), suite);
    assert_eq!(suite.byte(), 0xf7);
    assert_eq!(suite.template_version(), 0x53);
    assert_eq!(suite.key_and_signature_sizes(), (32, 7856));
    assert_eq!(
        Suite::from_partial_format(suite.partial_format()).unwrap(),
        suite
    );
    for byte in [0, 1, 0xf3, 0xf6, 0xf8, 255] {
        assert!(matches!(
            Suite::from_byte(byte),
            Err(Error::UnsupportedFormat)
        ));
    }
    for format in [
        "ZcashTransparentPQ/partial/v1",
        "ZcashTransparentPQ/experimental/sqisign-iii-exp-v1/partial/v1",
        "ZcashTransparentPQ/experimental/slh-dsa-b-128s/partial/v2",
    ] {
        assert!(matches!(
            Suite::from_partial_format(format),
            Err(Error::UnsupportedFormat)
        ));
    }
}

#[test]
fn every_policy_shape_reuses_native_codec_and_exact_capacity() {
    let mut shapes = 0;
    for participants in 1..=15u8 {
        for threshold in 1..=participants {
            let policy = SuitePolicy::new(
                Suite::SlhDsaB128sExpV1,
                threshold,
                (1..=participants).rev().map(|value| [value; 32]).collect(),
            )
            .unwrap();
            let descriptor = policy.encode();
            assert_eq!(SuitePolicy::decode(&descriptor).unwrap(), policy);
            assert_eq!(policy.key_commitments().len(), usize::from(participants));
            let records = (0..threshold)
                .map(|index| slh::Record {
                    index,
                    public_key: [index + 1; 32],
                    signature: vec![0; 7856].into_boxed_slice().try_into().unwrap(),
                })
                .collect();
            let encoded = slh::Authorization {
                policy: policy.policy().clone(),
                records,
            }
            .encode();
            assert_eq!(encoded.len(), policy.authorization_size());
            assert!(policy.authorization_size() <= 118_882);
            assert_eq!(
                slh::template_commitment(policy.lock_script().as_raw_bytes()),
                Some(policy.commitment())
            );
            let mut alternate = descriptor;
            alternate[1] = 1;
            assert!(SuitePolicy::decode(&alternate).is_err());
            shapes += 1;
        }
    }
    assert_eq!(shapes, 120);
    assert!(SuitePolicy::new(Suite::SlhDsaB128sExpV1, 1, vec![[1; 32]; 2]).is_err());
    assert!(SuitePolicy::new(
        Suite::SlhDsaB128sExpV1,
        16,
        (0..16).map(|v| [v; 32]).collect()
    )
    .is_err());
}

#[test]
fn partial_lengths_and_signer_slots_are_bounded_before_allocation() {
    let suite = Suite::SlhDsaB128sExpV1;
    let key = [8; 32];
    let signature = vec![9; 7856];
    let partial = SignerPartial::from_parts(suite, 14, &key, &signature).unwrap();
    assert_eq!(partial.suite(), suite);
    assert_eq!(partial.index(), 14);
    assert_eq!(partial.public_key(), key);
    assert_eq!(partial.signature(), signature);
    for (index, key_len, signature_len) in [
        (15, 32, 7856),
        (0, 31, 7856),
        (0, 33, 7856),
        (0, 32, 7855),
        (0, 32, 7857),
    ] {
        assert!(matches!(
            SignerPartial::from_parts(suite, index, &vec![0; key_len], &vec![0; signature_len]),
            Err(Error::Encoding)
        ));
    }
}

#[test]
fn retained_independent_v5_v6_partials_verify_and_reassemble() {
    for version in [5, 6] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../tests/slh-dsa-b128s/fixtures/data/v{version}-1of15-index14.json"
        ));
        let json: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let bytes = hex::decode(json["transaction_hex"].as_str().unwrap()).unwrap();
        let transaction = Transaction::zcash_deserialize(bytes.as_slice()).unwrap();
        let input = &json["inputs"][0];
        let previous = Arc::new(vec![Output {
            value: input["spent_output"]["value_zat"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            lock_script: Script::new(
                &hex::decode(input["spent_output"]["script_hex"].as_str().unwrap()).unwrap(),
            ),
        }]);
        let policy =
            SuitePolicy::decode(&hex::decode(input["descriptor_hex"].as_str().unwrap()).unwrap())
                .unwrap();
        let source = &input["records"][0];
        let partial = SignerPartial::from_parts(
            Suite::SlhDsaB128sExpV1,
            14,
            &hex::decode(source["public_key_hex"].as_str().unwrap()).unwrap(),
            &hex::decode(source["signature_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let signer = InputSigner::new(&transaction, previous.clone(), 0, &policy).unwrap();
        signer.verify_partial(&partial).unwrap();
        let zakura_chain::transparent::Input::PrevOut { unlock_script, .. } =
            &transaction.inputs()[0]
        else {
            panic!("public fixture input")
        };
        assert_eq!(
            &signer.assemble(vec![partial.clone()]).unwrap(),
            unlock_script
        );
        assert!(signer
            .assemble(vec![partial.clone(), partial.clone()])
            .is_err());
        let SignerPartial::SlhDsaB128sExpV1(mut bad) = partial;
        bad.signature[0] ^= 1;
        assert!(signer
            .verify_partial(&SignerPartial::SlhDsaB128sExpV1(bad))
            .is_err());
        verify_inputs(&transaction, previous.clone(), &[Suite::SlhDsaB128sExpV1]).unwrap();
        assert!(matches!(
            verify_inputs(&transaction, previous.clone(), &[]),
            Err(Error::InputContext)
        ));
        assert!(matches!(
            verify_inputs(
                &transaction,
                previous.clone(),
                &[Suite::SlhDsaB128sExpV1; 2]
            ),
            Err(Error::InputContext)
        ));
        let mut changed = previous.as_ref().clone();
        changed[0].value = (input["spent_output"]["value_zat"].as_u64().unwrap() + 1)
            .try_into()
            .unwrap();
        assert!(
            verify_inputs(&transaction, Arc::new(changed), &[Suite::SlhDsaB128sExpV1]).is_err()
        );
    }
}

#[test]
fn verification_rejects_a_bad_signature_in_each_input() {
    for version in [5, 6] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../tests/slh-dsa-b128s/fixtures/data/v{version}-16checks.json"
        ));
        let json: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let bytes = hex::decode(json["transaction_hex"].as_str().unwrap()).unwrap();
        let transaction = Transaction::zcash_deserialize(bytes.as_slice()).unwrap();
        let previous = Arc::new(
            json["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|input| Output {
                    value: input["spent_output"]["value_zat"]
                        .as_u64()
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    lock_script: Script::new(
                        &hex::decode(input["spent_output"]["script_hex"].as_str().unwrap())
                            .unwrap(),
                    ),
                })
                .collect::<Vec<_>>(),
        );
        assert_eq!(transaction.inputs().len(), 2);
        let suites = [Suite::SlhDsaB128sExpV1; 2];
        verify_inputs(&transaction, previous.clone(), &suites).unwrap();
        for input_index in 0..2 {
            let mut changed = transaction.clone();
            let (Transaction::V5 { inputs, .. } | Transaction::V6 { inputs, .. }) = &mut changed
            else {
                panic!("public fixture uses v5 or v6")
            };
            let zakura_chain::transparent::Input::PrevOut { unlock_script, .. } =
                &mut inputs[input_index]
            else {
                panic!("public fixture spends transparent outputs")
            };
            let mut authorization =
                slh::Authorization::decode(unlock_script.as_raw_bytes()).unwrap();
            authorization.records.last_mut().unwrap().signature[0] ^= 1;
            *unlock_script = Script::new(&authorization.encode());
            assert!(
                matches!(
                    verify_inputs(&changed, previous.clone(), &suites),
                    Err(Error::Authorization(slh::Rejection::Signature))
                ),
                "v{version}, input {input_index}"
            );
        }
    }
}
