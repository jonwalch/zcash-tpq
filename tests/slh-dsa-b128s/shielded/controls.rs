//! Offline SLH message and digest controls with existing public shielded bundles.
//!
//! These fixtures are synthetic and have no valid proof or SLH authorization
//! claim. Expected digests use a separate parser and digest implementation;
//! the native transaction and signing contexts are comparison targets only.

mod fields;
mod reference;
mod sources;

use std::sync::Arc;

use zakura_chain::{
    block::Height,
    orchard,
    parameters::NetworkUpgrade,
    sapling,
    serialization::{ZcashDeserialize, ZcashSerialize},
    transaction::{LockTime, Transaction},
    transparent::{OutPoint, Output, Script},
};
use zakura_pq_slh_dsa_b_exp::{InputSigningContext, Policy, TransactionContext};
use zakura_pq_test_support::{install, Spend, TransactionRecipe};
use zakura_pq_tx_context::{NetworkDomain, PreparedTransaction};
use zcash_protocol::consensus::BranchId;
use zcash_transparent::sighash::SighashType;

use sources::source;

const NETWORK: NetworkDomain = NetworkDomain::Regtest;
const UPGRADE: NetworkUpgrade = NetworkUpgrade::Nu7;

fn policy() -> Policy {
    // Only public policy binding is required: this target does not sign.
    Policy::new(1, vec![[42; 32]]).unwrap()
}

fn transaction(version: u8, pools: u8) -> (Transaction, Arc<Vec<Output>>) {
    assert!(pools <= if version == 5 { 3 } else { 7 });
    let policy = policy();
    let (mut tx, outputs) = TransactionRecipe {
        version,
        network_upgrade: UPGRADE,
        lock_time: LockTime::unlocked(),
        expiry_height: Height(140),
        spends: (0..2)
            .map(|index| Spend {
                outpoint: OutPoint {
                    hash: zakura_chain::transaction::Hash([1; 32]),
                    index,
                },
                sequence: u32::MAX - index,
                previous_output: Output {
                    value: (10_000_000_u64 + u64::from(index)).try_into().unwrap(),
                    lock_script: policy.lock_script(),
                },
            })
            .collect(),
        outputs: (0..2)
            .map(|index| Output {
                value: (1_000_000_u64 + index).try_into().unwrap(),
                lock_script: policy.lock_script(),
            })
            .collect(),
    }
    .build();
    let Transaction::V6 {
        sapling_shielded_data: mut sapling,
        ..
    } = source("sapling")
    else {
        unreachable!()
    };
    let Transaction::V6 {
        sapling_shielded_data: Some(output_bundle),
        ..
    } = source("sapling_output")
    else {
        unreachable!()
    };
    let sapling::TransferData::SpendsAndMaybeOutputs { maybe_outputs, .. } =
        &mut sapling.as_mut().unwrap().transfers
    else {
        unreachable!()
    };
    maybe_outputs.extend(output_bundle.outputs().cloned());
    assert!(!maybe_outputs.is_empty());
    let Transaction::V6 {
        orchard_shielded_data: orchard,
        ..
    } = source("orchard")
    else {
        unreachable!()
    };
    let Transaction::V6 {
        ironwood_shielded_data: ironwood,
        ..
    } = source("ironwood")
    else {
        unreachable!()
    };
    match &mut tx {
        Transaction::V5 {
            sapling_shielded_data,
            orchard_shielded_data,
            ..
        } => {
            if pools & 1 != 0 {
                *sapling_shielded_data = sapling;
            }
            if pools & 2 != 0 {
                *orchard_shielded_data = orchard;
            }
        }
        Transaction::V6 {
            sapling_shielded_data,
            orchard_shielded_data,
            ironwood_shielded_data,
            ..
        } => {
            if pools & 1 != 0 {
                *sapling_shielded_data = sapling;
            }
            if pools & 2 != 0 {
                *orchard_shielded_data = orchard;
            }
            if pools & 4 != 0 {
                *ironwood_shielded_data = ironwood;
            }
        }
        _ => unreachable!(),
    }
    (tx, outputs)
}

fn assert_messages(tx: &Transaction, outputs: Arc<Vec<Output>>) {
    let native = TransactionContext::new(tx, NETWORK, UPGRADE, outputs.clone()).unwrap();
    let prepared = PreparedTransaction::new(tx, NETWORK, UPGRADE, outputs.clone()).unwrap();
    for index in 0..outputs.len() {
        let expected = reference::message(tx, &outputs, index, NETWORK);
        assert_eq!(prepared.input_digest(index).unwrap().digest, expected[69..]);
        assert_eq!(native.message(index).unwrap(), expected);
        let signing =
            InputSigningContext::new(tx, NETWORK, UPGRADE, outputs.clone(), index, &policy())
                .unwrap();
        assert_eq!(signing.message(), &expected);
    }
}

fn assert_effect(
    tx: &Transaction,
    changed: &Transaction,
    outputs: Arc<Vec<Output>>,
    commits: bool,
) {
    assert_ne!(
        tx.zcash_serialize_to_vec().unwrap(),
        changed.zcash_serialize_to_vec().unwrap()
    );
    for index in 0..outputs.len() {
        let original = reference::message(tx, &outputs, index, NETWORK);
        let changed_message = reference::message(changed, &outputs, index, NETWORK);
        assert_eq!(
            original != changed_message,
            commits,
            "v{}, input {index}",
            tx.version()
        );
    }
    assert_messages(tx, outputs.clone());
    assert_messages(changed, outputs);
}

#[test]
fn all_supported_shielded_pool_combinations_match_reference_digests() {
    let mut shapes = 0;
    for version in [5, 6] {
        for pools in 1..=if version == 5 { 3 } else { 7 } {
            let (tx, outputs) = transaction(version, pools);
            assert_messages(&tx, outputs.clone());
            let encoded = tx.zcash_serialize_to_vec().unwrap();
            let decoded = Transaction::zcash_deserialize(encoded.as_slice()).unwrap();
            assert_eq!(decoded, tx);
            assert_messages(&decoded, outputs);
            shapes += 1;
        }
    }
    assert_eq!(shapes, 10);
}

#[test]
fn shielded_shapes_bind_all_previous_outputs_and_the_transparent_input() {
    for version in [5, 6] {
        let (tx, outputs) = transaction(version, if version == 5 { 3 } else { 7 });
        assert_messages(&tx, outputs.clone());
        for index in 0..outputs.len() {
            let expected = reference::message(&tx, &outputs, index, NETWORK);
            for mode in [
                SighashType::NONE,
                SighashType::SINGLE,
                SighashType::ALL_ANYONECANPAY,
            ] {
                let wrong = reference::digest(&tx, &outputs, BranchId::Nu7, mode, Some(index));
                assert_ne!(expected[69..], wrong);
            }
            let shielded = reference::digest(&tx, &outputs, BranchId::Nu7, SighashType::ALL, None);
            assert_ne!(expected[69..], shielded);
            let other = reference::message(&tx, &outputs, 1 - index, NETWORK);
            assert_ne!(expected[69..], other[69..]);

            // A supplied previous output remains part of every SIGHASH_ALL,
            // even when it belongs to the other transparent input.
            for spent in 0..outputs.len() {
                let mut changed = outputs.as_ref().clone();
                changed[spent].value = 10_000_100.try_into().unwrap();
                let changed = Arc::new(changed);
                assert_ne!(reference::message(&tx, &changed, index, NETWORK), expected);
                assert_messages(&tx, changed);
            }
            for network in [NetworkDomain::Mainnet, NetworkDomain::Testnet] {
                let changed = reference::message(&tx, &outputs, index, network);
                assert_ne!(changed, expected);
                assert_eq!(changed[69..], expected[69..]);
                assert_eq!(
                    TransactionContext::new(&tx, network, UPGRADE, outputs.clone())
                        .unwrap()
                        .message(index)
                        .unwrap(),
                    changed,
                );
            }
        }
    }
}

#[test]
fn transparent_authorization_bytes_remain_excluded_next_to_shielded_bundles() {
    for version in [5, 6] {
        let (tx, outputs) = transaction(version, if version == 5 { 3 } else { 7 });
        for index in 0..outputs.len() {
            let mut changed = tx.clone();
            install(&mut changed, index, Script::new(&[0xff, 0x4d, 1, 0, 42]));
            assert_effect(&tx, &changed, outputs.clone(), false);
        }
    }
}

#[test]
fn retained_public_sources_match_the_pinned_upstream_cases() {
    use sha2::{Digest, Sha256};
    let inventory: serde_json::Value = serde_json::from_str(include_str!("sources.json")).unwrap();
    let upstream =
        include_str!("../../../crates/zakura-chain/src/transaction/tests/ironwood_v6_tx_hash.rs");
    let files = [
        ("sapling_anchor_a", include_str!("data/sapling-source.hex")),
        (
            "sapling_negative_value_balance",
            include_str!("data/sapling-output-source.hex"),
        ),
        ("orchard_anchor_a", include_str!("data/orchard-source.hex")),
        (
            "ironwood_anchor_a",
            include_str!("data/ironwood-source.hex"),
        ),
    ];
    assert_eq!(inventory["fixtures"].as_array().unwrap().len(), files.len());
    for ((scenario, encoded), entry) in files
        .into_iter()
        .zip(inventory["fixtures"].as_array().unwrap())
    {
        assert_eq!(entry["scenario"], scenario);
        assert_eq!(
            entry["file_sha256"],
            hex::encode(Sha256::digest(encoded.as_bytes()))
        );
        let bytes = hex::decode(encoded.split_whitespace().collect::<String>()).unwrap();
        assert_eq!(entry["wire_sha256"], hex::encode(Sha256::digest(&bytes)));
        assert_eq!(entry["wire_bytes"], bytes.len());
        let start = upstream
            .split_once(&format!("scenario: \"{scenario}\","))
            .unwrap()
            .1;
        let raw = start
            .split_once("tx: &[")
            .unwrap()
            .1
            .split_once(']')
            .unwrap()
            .0;
        let upstream_bytes: Vec<u8> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| u8::from_str_radix(s.strip_prefix("0x").unwrap(), 16).unwrap())
            .collect();
        assert_eq!(bytes, upstream_bytes, "{scenario}");
    }
    let lock = include_str!("../../../Cargo.lock");
    let dependencies = inventory["reference_dependencies"].as_array().unwrap();
    assert_eq!(dependencies.len(), 3);
    for dependency in dependencies {
        let field = |name: &str| dependency[name].as_str().unwrap();
        let locked = format!(
            "name = \"{}\"\nversion = \"{}\"\nsource = \"{}\"\nchecksum = \"{}\"\n",
            field("name"),
            field("version"),
            field("source"),
            field("checksum")
        );
        assert!(lock.contains(&locked), "{locked}");
    }
}

#[test]
fn sapling_effects_and_authorizing_fields_have_version_specific_commitments() {
    for version in [5, 6] {
        let (tx, outputs) = transaction(version, 1);
        for field in [
            "balance",
            "anchor",
            "nullifier",
            "spend_proof",
            "spend_signature",
            "binding_signature",
        ] {
            let mut changed = tx.clone();
            let (Transaction::V5 {
                sapling_shielded_data: Some(bundle),
                ..
            }
            | Transaction::V6 {
                sapling_shielded_data: Some(bundle),
                ..
            }) = &mut changed
            else {
                unreachable!()
            };
            let sapling::TransferData::SpendsAndMaybeOutputs {
                shared_anchor,
                spends,
                ..
            } = &mut bundle.transfers
            else {
                panic!("fixture contains a Sapling spend")
            };
            match field {
                "balance" => {
                    bundle.value_balance = if bundle.value_balance == 0_i64 { 1 } else { 0 }
                        .try_into()
                        .unwrap()
                }
                "anchor" => {
                    let anchor = [42; 32].try_into().unwrap();
                    assert_ne!(*shared_anchor, anchor);
                    *shared_anchor = anchor;
                }
                "nullifier" => {
                    let nullifier = [42; 32].into();
                    assert_ne!(spends.iter_mut().next().unwrap().nullifier, nullifier);
                    spends.iter_mut().next().unwrap().nullifier = nullifier;
                }
                "spend_proof" => spends.iter_mut().next().unwrap().zkproof.0[0] ^= 1,
                "spend_signature" => {
                    let signature = [42; 64].into();
                    assert_ne!(spends.iter_mut().next().unwrap().spend_auth_sig, signature);
                    spends.iter_mut().next().unwrap().spend_auth_sig = signature;
                }
                _ => {
                    let signature = [42; 64].into();
                    assert_ne!(bundle.binding_sig, signature);
                    bundle.binding_sig = signature;
                }
            }
            let commits =
                matches!(field, "balance" | "nullifier") || (field == "anchor" && version == 5);
            assert_effect(&tx, &changed, outputs.clone(), commits);
        }
    }
}

#[test]
fn orchard_and_ironwood_actions_and_authorization_are_distinguished() {
    for (version, pool) in [(5, 2), (6, 2), (6, 4)] {
        let (tx, outputs) = transaction(version, pool);
        for field in [
            "balance",
            "anchor",
            "nullifier",
            "ciphertext",
            "flags",
            "proof",
            "spend_signature",
            "binding_signature",
        ] {
            let mut changed = tx.clone();
            let bundle = match &mut changed {
                Transaction::V5 {
                    orchard_shielded_data: Some(bundle),
                    ..
                } => bundle,
                Transaction::V6 {
                    orchard_shielded_data,
                    ironwood_shielded_data,
                    ..
                } => {
                    if pool == 2 {
                        orchard_shielded_data.as_mut().unwrap()
                    } else {
                        ironwood_shielded_data.as_mut().unwrap()
                    }
                }
                _ => unreachable!(),
            };
            match field {
                "balance" => {
                    bundle.value_balance = if bundle.value_balance == 0_i64 { 1 } else { 0 }
                        .try_into()
                        .unwrap()
                }
                "anchor" => {
                    let anchor = [42; 32].try_into().unwrap();
                    assert_ne!(bundle.shared_anchor, anchor);
                    bundle.shared_anchor = anchor;
                }
                "nullifier" => {
                    let nullifier = [42; 32].try_into().unwrap();
                    assert_ne!(
                        bundle.actions.iter_mut().next().unwrap().action.nullifier,
                        nullifier
                    );
                    bundle.actions.iter_mut().next().unwrap().action.nullifier = nullifier;
                }
                "ciphertext" => {
                    let ciphertext = [42; 580].into();
                    let action = &mut bundle.actions.iter_mut().next().unwrap().action;
                    assert_ne!(action.enc_ciphertext, ciphertext);
                    action.enc_ciphertext = ciphertext;
                }
                "flags" => bundle.flags.toggle(orchard::Flags::ENABLE_OUTPUTS),
                "proof" => bundle.proof.0[0] ^= 1,
                "spend_signature" => {
                    let signature = [42; 64].into();
                    assert_ne!(
                        bundle.actions.iter_mut().next().unwrap().spend_auth_sig,
                        signature
                    );
                    bundle.actions.iter_mut().next().unwrap().spend_auth_sig = signature;
                }
                _ => {
                    let signature = [42; 64].into();
                    assert_ne!(bundle.binding_sig, signature);
                    bundle.binding_sig = signature;
                }
            }
            let commits = matches!(field, "balance" | "nullifier" | "ciphertext" | "flags")
                || (field == "anchor" && version == 5);
            assert_effect(&tx, &changed, outputs.clone(), commits);
        }
    }
}

#[test]
fn sapling_output_ciphertexts_are_committed_but_output_proofs_are_excluded() {
    for version in [5, 6] {
        let (tx, outputs) = transaction(version, if version == 5 { 3 } else { 7 });
        for field in ["encrypted_note", "wrapped_key", "proof"] {
            let mut changed = tx.clone();
            let (Transaction::V5 {
                sapling_shielded_data: Some(bundle),
                ..
            }
            | Transaction::V6 {
                sapling_shielded_data: Some(bundle),
                ..
            }) = &mut changed
            else {
                unreachable!()
            };
            let sapling::TransferData::SpendsAndMaybeOutputs { maybe_outputs, .. } =
                &mut bundle.transfers
            else {
                unreachable!()
            };
            let output = &mut maybe_outputs[0];
            match field {
                "encrypted_note" => {
                    let ciphertext = [42; 580].into();
                    assert_ne!(output.enc_ciphertext, ciphertext);
                    output.enc_ciphertext = ciphertext;
                }
                "wrapped_key" => {
                    let ciphertext = [42; 80].into();
                    assert_ne!(output.out_ciphertext, ciphertext);
                    output.out_ciphertext = ciphertext;
                }
                _ => output.zkproof.0[0] ^= 1,
            }
            assert_effect(&tx, &changed, outputs.clone(), field != "proof");
        }
    }
}
