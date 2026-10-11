//! Real signed v5/v6 authorization and partial-assembly boundary controls.
//!
//! Inputs come from the public offline corpus and remain synthetic. Loading an
//! ordered spent-output vector does not authenticate UTXOs or test node admission.
//! Independent digest and signature expectations live in the external checker.

use std::{cell::Cell, io::Cursor, path::Path, sync::Arc};

use serde_json::Value;
use zakura_chain::{
    parameters::NetworkUpgrade,
    serialization::{ZcashDeserialize, ZcashSerialize},
    transaction::Transaction,
    transparent::{Input, Output, Script},
};
use zakura_pq_slh_dsa_b_exp::{
    codec::MAX_AUTHORIZATION_SIZE, input_authorization, Authorization, InputSigningContext, Policy,
    Rejection, TransactionContext,
};
use zakura_pq_test_support::{inputs_mut, install, outputs_mut};
use zakura_pq_tx_context::NetworkDomain;

const CASES: [(&str, usize); 9] = [
    ("1of1", 1),
    ("2of3", 2),
    ("3of5", 3),
    ("8of10", 8),
    ("10of10", 10),
    ("15of15", 15),
    ("1of15-index14", 1),
    ("16checks", 16),
    ("17checks", 17),
];

struct Fixture {
    json: Value,
    transaction: Transaction,
    previous: Arc<Vec<Output>>,
    authorizations: Vec<Authorization>,
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("public fixture field is hex text"))
        .expect("public fixture has valid hex")
}

fn fixture(version: u8, case: &str) -> Fixture {
    let case_id = format!("v{version}-{case}");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/slh-dsa-b128s/fixtures/data")
        .join(format!("{case_id}.json"));
    let encoded = std::fs::read(path).expect("the retained public corpus must be present");
    assert!(encoded.len() <= 16 * 1024 * 1024);
    let json: Value = serde_json::from_slice(&encoded).expect("public artifact is JSON");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["contract"], "slh-dsa-b-128s-exp-v1");
    assert_eq!(json["public_fixture"], true);
    assert_eq!(json["context_provenance"], "synthetic-public-fixture");
    assert_eq!(json["case_id"], case_id);
    assert_eq!(json["network"], "Regtest");
    assert_eq!(json["transaction_version"], version);
    assert_eq!(json["expected"]["native_authorization"], "accept");

    let encoded = bytes(&json["transaction_hex"]);
    let mut cursor = Cursor::new(encoded.as_slice());
    let transaction = Transaction::zcash_deserialize(&mut cursor)
        .expect("public artifact contains a complete transparent transaction");
    assert_eq!(cursor.position(), u64::try_from(encoded.len()).unwrap());
    assert_eq!(transaction.zcash_serialize_to_vec().unwrap(), encoded);
    let inputs = json["inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), transaction.inputs().len());
    let previous = Arc::new(
        inputs
            .iter()
            .enumerate()
            .map(|(index, input)| {
                assert_eq!(input["input_index"], index);
                assert_eq!(input["context_hex"], "");
                Output {
                    value: input["spent_output"]["value_zat"]
                        .as_u64()
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    lock_script: Script::new(&bytes(&input["spent_output"]["script_hex"])),
                }
            })
            .collect::<Vec<_>>(),
    );
    let authorizations = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let authorization = input_authorization(&transaction, &previous, index)
                .expect("positive artifact has a bound canonical authorization");
            assert_eq!(
                authorization.policy.descriptor(),
                bytes(&input["descriptor_hex"])
            );
            let records = input["records"].as_array().unwrap();
            assert_eq!(records.len(), authorization.records.len());
            for (record, source) in authorization.records.iter().zip(records) {
                assert_eq!(source["signer_index"], record.index);
                assert_eq!(bytes(&source["public_key_hex"]), record.public_key);
                assert_eq!(bytes(&source["signature_hex"]), record.signature.as_slice());
            }
            authorization
        })
        .collect();
    Fixture {
        json,
        transaction,
        previous,
        authorizations,
    }
}

fn context<'a>(transaction: &'a Transaction, previous: Arc<Vec<Output>>) -> TransactionContext<'a> {
    TransactionContext::new(
        transaction,
        NetworkDomain::Regtest,
        NetworkUpgrade::Nu7,
        previous,
    )
    .unwrap()
}

#[test]
fn signed_corpus_verifies_and_reassembles_from_public_partials() {
    let mut signature_count = 0;
    for version in [5, 6] {
        for (case, expected_checks) in CASES {
            let fixture = fixture(version, case);
            let ctx = context(&fixture.transaction, fixture.previous.clone());
            let mut assembled = fixture.transaction.clone();
            for index in 0..fixture.authorizations.len() {
                install(&mut assembled, index, Script::new(&[]));
            }
            let total = Cell::new(0);
            for (index, authorization) in fixture.authorizations.iter().enumerate() {
                let message = ctx.message(index).unwrap();
                assert_eq!(
                    message.as_slice(),
                    bytes(&fixture.json["inputs"][index]["message_hex"])
                );
                let calls = Cell::new(0);
                let reserved = ctx
                    .reserve_input(index, |checks| {
                        calls.set(calls.get() + 1);
                        total.set(total.get() + checks);
                        assert_eq!(checks, usize::from(authorization.policy.threshold()));
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(calls.get(), 1);
                assert_eq!(reserved.input_index(), index);
                assert_eq!(reserved.checks().len(), authorization.records.len());
                assert_eq!(reserved.verify(), Ok(()));

                let signing = InputSigningContext::new(
                    &assembled,
                    NetworkDomain::Regtest,
                    NetworkUpgrade::Nu7,
                    fixture.previous.clone(),
                    index,
                    &authorization.policy,
                )
                .unwrap();
                assert_eq!(
                    signing.message(),
                    &message,
                    "authorizations are excluded from the digest"
                );
                for partial in &authorization.records {
                    assert_eq!(signing.verify_partial(partial), Ok(()));
                }
                let mut received = authorization.records.clone();
                received.reverse();
                let rebuilt = signing.authorization(received).unwrap();
                assert_eq!(
                    &rebuilt, authorization,
                    "assembly sorts valid received partials"
                );
                install(&mut assembled, index, Script::new(&rebuilt.encode()));
            }
            assert_eq!(total.get(), expected_checks);
            assert_eq!(
                fixture.json["expected"]["signature_checks"],
                expected_checks
            );
            assert_eq!(
                assembled.zcash_serialize_to_vec().unwrap(),
                fixture.transaction.zcash_serialize_to_vec().unwrap()
            );
            signature_count += expected_checks;
        }
    }
    assert_eq!(signature_count, 146, "fixed corpus signature inventory");
}

#[test]
fn signed_high_index_and_maximum_size_controls() {
    for (version, expected_bytes) in [(5, 119_040), (6, 119_041)] {
        let high = fixture(version, "1of15-index14");
        assert_eq!(high.authorizations[0].records[0].index, 14);
        assert_eq!(high.authorizations[0].encode()[0], 0x5e);
        assert_eq!(
            context(&high.transaction, high.previous).verify_input(0),
            Ok(())
        );

        let maximum = fixture(version, "15of15");
        let authorization = maximum.authorizations[0].encode();
        assert_eq!(authorization.len(), 118_882);
        assert_eq!(&authorization[34..37], &[0x4d, 0xb0, 0x1e]);
        assert_eq!(
            maximum.transaction.zcash_serialize_to_vec().unwrap().len(),
            expected_bytes
        );
        let input = maximum.transaction.inputs()[0]
            .zcash_serialize_to_vec()
            .unwrap();
        assert_eq!(input.len(), 118_927);
        // Outpoint is 36 bytes. The complete script needs CompactSize's u32
        // encoding even though each signature remains a PUSHDATA2 field.
        assert_eq!(input[36], 0xfe);
        assert_eq!(&input[37..41], &118_882_u32.to_le_bytes());
    }
}

#[test]
fn exact_and_excess_check_profiles_use_atomic_caller_reservations() {
    for version in [5, 6] {
        for (case, succeeds, remaining) in [("16checks", true, 0), ("17checks", false, 1)] {
            let fixture = fixture(version, case);
            let ctx = context(&fixture.transaction, fixture.previous);
            let available = Cell::new(16_usize);
            let mut accepted = true;
            for index in 0..fixture.transaction.inputs().len() {
                let result = ctx.reserve_input(index, |checks| {
                    let next = available
                        .get()
                        .checked_sub(checks)
                        .ok_or(Rejection::VerificationBudget)?;
                    available.set(next);
                    Ok(())
                });
                if let Err(error) = result {
                    assert_eq!(error, Rejection::VerificationBudget);
                    assert_eq!(index, 1);
                    accepted = false;
                }
            }
            assert_eq!(accepted, succeeds);
            assert_eq!(
                available.get(),
                remaining,
                "failed reservation does not partly deduct"
            );
        }
    }
}

#[test]
fn valid_partials_reject_wrong_count_index_key_and_signature() {
    for version in [5, 6] {
        let fixture = fixture(version, "2of3");
        let auth = &fixture.authorizations[0];
        let signing = InputSigningContext::new(
            &fixture.transaction,
            NetworkDomain::Regtest,
            NetworkUpgrade::Nu7,
            fixture.previous,
            0,
            &auth.policy,
        )
        .unwrap();
        assert_eq!(
            signing.authorization(vec![]),
            Err(Rejection::SignatureCount)
        );
        assert_eq!(
            signing.authorization(vec![auth.records[0].clone()]),
            Err(Rejection::SignatureCount)
        );
        assert_eq!(
            signing.authorization(vec![auth.records[0].clone(); 3]),
            Err(Rejection::SignatureCount)
        );
        assert_eq!(
            signing.authorization(vec![auth.records[0].clone(); 2]),
            Err(Rejection::SignerIndex)
        );
        let mut changed = auth.records[0].clone();
        changed.index = 3;
        assert_eq!(
            signing.verify_partial(&changed),
            Err(Rejection::SignerIndex)
        );
        changed = auth.records[0].clone();
        changed.public_key[0] ^= 1;
        assert_eq!(
            signing.verify_partial(&changed),
            Err(Rejection::KeyCommitment)
        );
        for offset in [0, 16, 2927, 2928, 3488, 7855] {
            let mut records = auth.records.clone();
            records[0].signature[offset] ^= 1;
            assert_eq!(
                signing.verify_partial(&records[0]),
                Err(Rejection::Signature)
            );
            assert_eq!(signing.authorization(records), Err(Rejection::Signature));
        }
    }
}

#[test]
fn every_signer_of_every_input_is_required_by_verification_and_assembly() {
    for version in [5, 6] {
        for (case, expected_counts) in [("15of15", &[15][..]), ("16checks", &[15, 1][..])] {
            let fixture = fixture(version, case);
            assert_eq!(
                fixture
                    .authorizations
                    .iter()
                    .map(|authorization| authorization.records.len())
                    .collect::<Vec<_>>(),
                expected_counts
            );
            for (input_index, authorization) in fixture.authorizations.iter().enumerate() {
                let signing = InputSigningContext::new(
                    &fixture.transaction,
                    NetworkDomain::Regtest,
                    NetworkUpgrade::Nu7,
                    fixture.previous.clone(),
                    input_index,
                    &authorization.policy,
                )
                .unwrap();
                assert_eq!(
                    context(&fixture.transaction, fixture.previous.clone())
                        .verify_input(input_index),
                    Ok(())
                );
                assert_eq!(
                    signing.authorization(authorization.records.clone()),
                    Ok(authorization.clone())
                );
                for record_index in 0..authorization.records.len() {
                    let mut changed = authorization.clone();
                    changed.records[record_index].signature[0] ^= 1;
                    let mut transaction = fixture.transaction.clone();
                    install(
                        &mut transaction,
                        input_index,
                        Script::new(&changed.encode()),
                    );
                    // Only authorization bytes change. Every other input must
                    // still verify, and the mutated input must reach crypto.
                    let ctx = context(&transaction, fixture.previous.clone());
                    for index in 0..fixture.authorizations.len() {
                        assert_eq!(
                            ctx.verify_input(index),
                            if index == input_index {
                                Err(Rejection::Signature)
                            } else {
                                Ok(())
                            },
                            "v{version}-{case}, input {input_index}, signer {record_index}, checked input {index}"
                        );
                    }
                    assert_eq!(
                        signing.authorization(changed.records),
                        Err(Rejection::Signature),
                        "v{version}-{case}, input {input_index}, signer {record_index}"
                    );
                }
            }
        }
    }
}

#[test]
fn canonicality_failures_on_real_signatures_precede_reservation() {
    for version in [5, 6] {
        let fixture = fixture(version, "2of3");
        let auth = &fixture.authorizations[0];
        let canonical = auth.encode();
        let mut mutations = Vec::new();
        let mut changed = canonical.clone();
        changed.push(0);
        mutations.push((changed, Rejection::Encoding));
        let mut changed = canonical.clone();
        changed.splice(1..2, [0x4c, 0x20]);
        mutations.push((changed, Rejection::Encoding));
        let mut changed = auth.clone();
        changed.records.reverse();
        mutations.push((changed.encode(), Rejection::SignerIndex));
        changed = auth.clone();
        changed.records[1].index = changed.records[0].index;
        mutations.push((changed.encode(), Rejection::SignerIndex));
        changed = auth.clone();
        changed.records.pop();
        mutations.push((changed.encode(), Rejection::SignatureCount));
        changed = auth.clone();
        changed.records[0].public_key[0] ^= 1;
        mutations.push((changed.encode(), Rejection::KeyCommitment));
        let mut changed = canonical.clone();
        let descriptor_start = changed.len() - auth.policy.descriptor().len();
        changed[descriptor_start + 1] = 0xf6;
        mutations.push((changed, Rejection::UnsupportedPolicy));
        mutations.push((
            vec![0; MAX_AUTHORIZATION_SIZE + 1],
            Rejection::AuthorizationSize,
        ));
        for (bytes, expected) in mutations {
            let mut transaction = fixture.transaction.clone();
            install(&mut transaction, 0, Script::new(&bytes));
            assert!(
                matches!(context(&transaction, fixture.previous.clone()).reserve_input(0, |_| {
                panic!("structural rejection must precede reservation")
            }), Err(actual) if actual == expected)
            );
        }
        for opcode in [0x51, 0x52] {
            let mut previous = fixture.previous.as_ref().clone();
            let mut script = previous[0].lock_script.as_raw_bytes().to_vec();
            script[0] = opcode;
            previous[0].lock_script = Script::new(&script);
            assert!(matches!(
                context(&fixture.transaction, Arc::new(previous)).reserve_input(0, |_| {
                    panic!("another template must reject before reservation")
                }),
                Err(Rejection::OutputTemplate)
            ));
        }
    }
}

#[test]
fn signed_authorizations_bind_effects_network_and_supplied_outputs() {
    for version in [5, 6] {
        let fixture = fixture(version, "2of3");
        for network in [NetworkDomain::Mainnet, NetworkDomain::Testnet] {
            let wrong = TransactionContext::new(
                &fixture.transaction,
                network,
                NetworkUpgrade::Nu7,
                fixture.previous.clone(),
            )
            .unwrap();
            assert_eq!(wrong.verify_input(0), Err(Rejection::Signature));
        }
        assert!(matches!(
            TransactionContext::new(
                &fixture.transaction,
                NetworkDomain::Regtest,
                NetworkUpgrade::Nu6_3,
                fixture.previous.clone(),
            ),
            Err(Rejection::ConsensusBranch)
        ));
        for mutation in 0..4 {
            let mut transaction = fixture.transaction.clone();
            let mut previous = fixture.previous.as_ref().clone();
            match mutation {
                0 => previous[0].value = 100_001.try_into().unwrap(),
                1 => outputs_mut(&mut transaction)[0].value = 20_001.try_into().unwrap(),
                2 => {
                    let Input::PrevOut { sequence, .. } = &mut inputs_mut(&mut transaction)[0]
                    else {
                        unreachable!()
                    };
                    *sequence -= 1;
                }
                3 => {
                    let Input::PrevOut { outpoint, .. } = &mut inputs_mut(&mut transaction)[0]
                    else {
                        unreachable!()
                    };
                    outpoint.index += 1;
                }
                _ => unreachable!(),
            }
            assert_eq!(
                context(&transaction, Arc::new(previous)).verify_input(0),
                Err(Rejection::Signature)
            );
        }
        // Change only the unused third commitment, retaining the two signing
        // participants and their indices, then bind the updated policy/output.
        let mut changed = fixture.authorizations[0].clone();
        let mut commitments = changed.policy.commitments().to_vec();
        commitments[2][31] ^= 1;
        changed.policy = Policy::new(2, commitments).unwrap();
        assert_eq!(
            &changed.policy.commitments()[..2],
            &fixture.authorizations[0].policy.commitments()[..2]
        );
        let mut previous = fixture.previous.as_ref().clone();
        previous[0].lock_script = changed.policy.lock_script();
        let mut transaction = fixture.transaction;
        install(&mut transaction, 0, Script::new(&changed.encode()));
        assert_eq!(
            context(&transaction, Arc::new(previous)).verify_input(0),
            Err(Rejection::Signature)
        );
    }
}

#[cfg(feature = "test-observer")]
#[test]
fn successful_reserved_checks_keep_their_observer_on_another_thread() {
    use std::sync::Mutex;
    use zakura_pq_slh_dsa_b_exp::test_observer::{observe, Event};
    let fixture = fixture(6, "2of3");
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    observe(
        Arc::new(move |event| sink.lock().unwrap().push(event)),
        || {
            let ctx = context(&fixture.transaction, fixture.previous);
            assert!(matches!(
                ctx.reserve_input(0, |_| Err(Rejection::VerificationBudget)),
                Err(Rejection::VerificationBudget)
            ));
            assert!(events.lock().unwrap().is_empty());
            let reserved = ctx.reserve_input(0, |_| Ok(())).unwrap();
            assert_eq!(&*events.lock().unwrap(), &[Event::Reserved { checks: 2 }]);
            std::thread::scope(|scope| {
                assert_eq!(scope.spawn(|| reserved.verify()).join().unwrap(), Ok(()));
            });
        },
    );
    assert_eq!(
        &*events.lock().unwrap(),
        &[
            Event::Reserved { checks: 2 },
            Event::CryptoStarted,
            Event::CryptoFinished { valid: true },
            Event::CryptoStarted,
            Event::CryptoFinished { valid: true },
        ]
    );
}

#[test]
fn signed_primitive_observation_counts_attempts_without_replacing_results() {
    for version in [5, 6] {
        for valid in [true, false] {
            let mut fixture = fixture(version, "1of1");
            if !valid {
                fixture.authorizations[0].records[0].signature[0] ^= 1;
                install(
                    &mut fixture.transaction,
                    0,
                    Script::new(&fixture.authorizations[0].encode()),
                );
            }
            let context = context(&fixture.transaction, fixture.previous);
            let reserved = context.reserve_input(0, |_| Ok(())).unwrap();
            let calls = Cell::new(0);
            let result =
                reserved.checks()[0].verify_with_observation(|| calls.set(calls.get() + 1));
            assert_eq!(calls.get(), 1);
            assert_eq!(
                result,
                if valid {
                    Ok(())
                } else {
                    Err(Rejection::Signature)
                }
            );
            assert_eq!(reserved.checks()[0].verify(), result);
        }
    }
}

#[test]
fn signed_observation_cannot_run_before_binding_and_reservation() {
    for version in [5, 6] {
        for malformed in [false, true] {
            let mut fixture = fixture(version, "1of1");
            if malformed {
                install(&mut fixture.transaction, 0, Script::new(&[]));
            }
            let context = context(&fixture.transaction, fixture.previous);
            let reservations = Cell::new(0);
            let entries = Cell::new(0);
            let result = context.reserve_input(0, |_| {
                reservations.set(reservations.get() + 1);
                Err(Rejection::VerificationBudget)
            });
            let result = result.and_then(|reserved| {
                reserved.checks()[0].verify_with_observation(|| entries.set(entries.get() + 1))
            });
            assert_eq!(entries.get(), 0);
            assert_eq!(reservations.get(), usize::from(!malformed));
            assert_eq!(
                result,
                Err(if malformed {
                    Rejection::Encoding
                } else {
                    Rejection::VerificationBudget
                })
            );
        }
    }
}
