//! Public test-only P2SH funding, adapted from pinned research legacy helpers.
//! Never pass real funds: the keys below are public and deliberately fixed.
use super::*;
use ripemd::Ripemd160;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use zakura_chain::{parameters::NetworkKind, transaction::HashType, transparent::Address};

fn keys(kind: &str) -> Result<Vec<SecretKey>> {
    let seeds: &[u8] = match kind {
        "single" => &[91],
        "multisig" => &[91, 92, 93],
        _ => return fail("schema", "classical_kind"),
    };
    Ok(seeds
        .iter()
        .map(|seed| {
            SecretKey::from_slice(&[*seed; 32])
                .expect("fixed public test scalar is nonzero and in range")
        })
        .collect())
}

pub(super) fn scripts(kind: &str) -> Result<(Script, Vec<u8>, Address)> {
    let secp = Secp256k1::new();
    let keys = keys(kind)?;
    let mut redeem = Vec::new();
    if kind == "multisig" {
        redeem.push(0x52);
    }
    for key in keys {
        redeem.push(33);
        redeem.extend(PublicKey::from_secret_key(&secp, &key).serialize());
    }
    if kind == "multisig" {
        redeem.extend([0x53, 0xae]);
    } else {
        redeem.push(0xac);
    }
    let hash: [u8; 20] = Ripemd160::digest(Sha256::digest(&redeem)).into();
    let mut lock = vec![0xa9, 20];
    lock.extend(hash);
    lock.push(0x87);
    Ok((
        Script::new(&lock),
        redeem,
        Address::from_script_hash(NetworkKind::Regtest, hash),
    ))
}

pub(super) fn info(kind: &str) -> Result<Value> {
    let (lock, redeem, address) = scripts(kind)?;
    Ok(
        json!({"kind":kind,"material":"public-test-only","address":address.to_string(),
        "script_hex":hex::encode(lock.as_raw_bytes()),"redeem_script_hex":hex::encode(redeem),
        "ecdsa_checks":if kind == "multisig" { 2 } else { 1 },"slh_checks":0}),
    )
}

fn push(bytes: &[u8], script: &mut Vec<u8>) -> Result<()> {
    require(bytes.len() <= 255, "generation", "classical_push")?;
    if bytes.len() > 75 {
        script.push(0x4c);
    }
    script.push(u8::try_from(bytes.len()).expect("push bounded to u8"));
    script.extend(bytes);
    Ok(())
}

pub(super) fn signature(
    tx: &Transaction,
    previous: Arc<Vec<ChainOutput>>,
    kind: &str,
    input_index: usize,
) -> Result<Script> {
    let (_, redeem, _) = scripts(kind)?;
    let digest = tx
        .sighasher(NetworkUpgrade::Nu7, previous)
        .map_err(|_| Failure {
            stage: "generation",
            reason: "classical_sighash",
        })?
        .sighash(HashType::ALL, Some((input_index, redeem.clone())))
        .0;
    let secp = Secp256k1::new();
    let message = Message::from_digest(digest);
    let mut script = Vec::new();
    if kind == "multisig" {
        script.push(0);
    } // CHECKMULTISIG's historical dummy.
    for key in keys(kind)?
        .into_iter()
        .take(if kind == "multisig" { 2 } else { 1 })
    {
        let signature = secp.sign_ecdsa(&message, &key);
        require(
            secp.verify_ecdsa(
                &message,
                &signature,
                &PublicKey::from_secret_key(&secp, &key),
            )
            .is_ok(),
            "generation",
            "classical_signature",
        )?;
        let mut encoded = signature.serialize_der().to_vec();
        encoded.push(1); // SIGHASH_ALL.
        push(&encoded, &mut script)?;
    }
    push(&redeem, &mut script)?;
    Ok(Script::new(&script))
}

pub(super) fn spend(recipe: &ClassicalRecipe) -> Result<Value> {
    spend_inner(recipe, false)
}

/// Explicit negative-control funding; no alternate authorization backend exists.
pub(super) fn control_spend(recipe: &ClassicalRecipe) -> Result<Value> {
    spend_inner(recipe, true)
}

fn spend_inner(recipe: &ClassicalRecipe, unsupported_templates: bool) -> Result<Value> {
    require(
        matches!(recipe.transaction_version, 5 | 6)
            && recipe.lock_time < 500_000_000
            && recipe.expiry_height > recipe.lock_time
            && (1..=63).contains(&recipe.outputs.len()),
        "schema",
        "classical_shape",
    )?;
    let parent = decode_transaction(&bounded_hex(&recipe.parent_hex, MAX_TX)?)?;
    let previous = parent
        .outputs()
        .get(usize::try_from(recipe.output_index).map_err(|_| Failure {
            stage: "schema",
            reason: "classical_outpoint",
        })?)
        .ok_or(Failure {
            stage: "schema",
            reason: "classical_outpoint",
        })?
        .clone();
    let (lock, _, _) = scripts(&recipe.kind)?;
    require(
        previous.lock_script == lock,
        "schema",
        "classical_previous_script",
    )?;
    let mut outputs = Vec::new();
    for output in &recipe.outputs {
        let bytes = bounded_hex(&output.script_hex, 35)?;
        require(
            bytes == lock.as_raw_bytes()
                || (bytes.len() == 35
                    && bytes[1] == 0x20
                    && bytes[34] == 0xc0
                    && (bytes[0] == 0x53
                        || unsupported_templates && matches!(bytes[0], 0x51 | 0x52))),
            "schema",
            "classical_destination",
        )?;
        outputs.push(chain_output(output.value_zat, bytes)?);
    }
    value_sum(
        outputs
            .iter()
            .map(|output| u64::from(output.value))
            .chain([recipe.fee_zat]),
    )?;
    let spent = outputs
        .iter()
        .map(|output| u64::from(output.value))
        .sum::<u64>()
        + recipe.fee_zat;
    let change = u64::from(previous.value)
        .checked_sub(spent)
        .ok_or(Failure {
            stage: "schema",
            reason: "classical_value",
        })?;
    require(
        change >= 2403 && recipe.fee_zat >= 800,
        "schema",
        "classical_fee_or_change",
    )?;
    outputs.push(chain_output(change, lock.as_raw_bytes().to_vec())?);
    let point = OutPoint {
        hash: parent.hash(),
        index: recipe.output_index,
    };
    let (mut transaction, previous) = TransactionRecipe {
        version: recipe.transaction_version,
        network_upgrade: NetworkUpgrade::Nu7,
        lock_time: LockTime::Height(Height(recipe.lock_time)),
        expiry_height: Height(recipe.expiry_height),
        spends: vec![Spend {
            outpoint: point,
            sequence: 0xffff_fffe,
            previous_output: previous,
        }],
        outputs,
    }
    .build();
    let unlock = signature(&transaction, previous, &recipe.kind, 0)?;
    install(&mut transaction, 0, unlock);
    let bytes = transaction.zcash_serialize_to_vec().map_err(|_| Failure {
        stage: "generation",
        reason: "serialization",
    })?;
    require(
        decode_transaction(&bytes)? == transaction,
        "generation",
        "classical_roundtrip",
    )?;
    Ok(
        json!({"material":"public-test-only","transaction_hex":hex::encode(&bytes),
        "transaction_sha256":strict::hash(&bytes),"txid":transaction.hash().to_string(),
        "outpoint":outpoint_fields(&point),"outputs":output_fields(&transaction),
        "ecdsa_checks":if recipe.kind == "multisig" {2} else {1},"slh_checks":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(kind: &str, version: u8) -> ClassicalRecipe {
        let (lock, _, _) = scripts(kind).unwrap();
        let (parent, _) = TransactionRecipe {
            version: 5,
            network_upgrade: NetworkUpgrade::Nu7,
            lock_time: LockTime::Height(Height(1)),
            expiry_height: Height(500),
            spends: vec![],
            outputs: vec![chain_output(10_000_000, lock.as_raw_bytes().to_vec()).unwrap()],
        }
        .build();
        ClassicalRecipe {
            kind: kind.into(),
            transaction_version: version,
            lock_time: 5,
            expiry_height: 25,
            parent_hex: hex::encode(parent.zcash_serialize_to_vec().unwrap()),
            output_index: 0,
            outputs: vec![ScriptOutput {
                value_zat: 3_000_000,
                script_hex: format!("5320{}c0", "11".repeat(32)),
            }],
            fee_zat: 20_000,
        }
    }
    #[test]
    fn funding_is_classical_and_signatures_bind_exact_outputs() {
        for kind in ["single", "multisig"] {
            for version in [5, 6] {
                let recipe = fixture(kind, version);
                let result = spend(&recipe).unwrap();
                assert_eq!(result["slh_checks"], 0);
                let tx = decode_transaction(
                    &hex::decode(result["transaction_hex"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
                let parent = decode_transaction(&hex::decode(&recipe.parent_hex).unwrap()).unwrap();
                let (_, redeem, _) = scripts(kind).unwrap();
                let digest = tx
                    .sighasher(NetworkUpgrade::Nu7, Arc::new(parent.outputs().to_vec()))
                    .unwrap()
                    .sighash(HashType::ALL, Some((0, redeem.clone())))
                    .0;
                let ChainInput::PrevOut { unlock_script, .. } = &tx.inputs()[0] else {
                    panic!("previous output")
                };
                let script = unlock_script.as_raw_bytes();
                let mut cursor = usize::from(kind == "multisig");
                if kind == "multisig" {
                    assert_eq!(script[0], 0);
                }
                for key in
                    keys(kind)
                        .unwrap()
                        .into_iter()
                        .take(if kind == "multisig" { 2 } else { 1 })
                {
                    let length = usize::from(script[cursor]);
                    cursor += 1;
                    assert_eq!(script[cursor + length - 1], 1);
                    let signature =
                        secp256k1::ecdsa::Signature::from_der(&script[cursor..cursor + length - 1])
                            .unwrap();
                    let public = PublicKey::from_secret_key(&Secp256k1::new(), &key);
                    assert!(Secp256k1::new()
                        .verify_ecdsa(&Message::from_digest(digest), &signature, &public)
                        .is_ok());
                    let mut wrong = digest;
                    wrong[0] ^= 1;
                    assert!(Secp256k1::new()
                        .verify_ecdsa(&Message::from_digest(wrong), &signature, &public)
                        .is_err());
                    cursor += length;
                }
                if kind == "multisig" {
                    assert_eq!(&script[cursor..cursor + 2], &[0x4c, 105]);
                    cursor += 2;
                } else {
                    assert_eq!(script[cursor], 35);
                    cursor += 1;
                }
                assert_eq!(&script[cursor..], redeem);
            }
        }
    }
    #[test]
    fn unsupported_templates_require_the_explicit_public_control_operation() {
        for prefix in [0x51, 0x52] {
            let mut recipe = fixture("multisig", 5);
            recipe.outputs[0].script_hex = format!("{prefix:02x}20{}c0", "11".repeat(32));
            assert_eq!(spend(&recipe).unwrap_err().reason, "classical_destination");
            assert_eq!(control_spend(&recipe).unwrap()["ecdsa_checks"], 2);
            recipe.outputs[0].script_hex.push_str("00");
            assert!(control_spend(&recipe).is_err());
        }
        let mut recipe = fixture("single", 6);
        recipe.outputs[0].value_zat = 2402;
        assert!(spend(&recipe).is_ok()); // Dust is relay policy, not fixture validity.
        recipe.outputs[0].script_hex = format!("5020{}c0", "11".repeat(32));
        assert!(control_spend(&recipe).is_err());
    }

    #[test]
    fn funding_rejects_foreign_parents_and_unbounded_shapes() {
        let mut recipe = fixture("single", 5);
        recipe.kind = "multisig".into();
        assert!(spend(&recipe).is_err());
        let mut recipe = fixture("single", 5);
        recipe.parent_hex.push_str("00");
        assert!(spend(&recipe).is_err());
        let mut recipe = fixture("single", 5);
        recipe.output_index = 1;
        assert!(spend(&recipe).is_err());
        let mut recipe = fixture("single", 5);
        recipe.outputs[0].value_zat = u64::MAX;
        assert!(spend(&recipe).is_err());
        let mut recipe = fixture("single", 5);
        recipe.outputs[0].script_hex = "51".into();
        assert!(spend(&recipe).is_err());
        let mut recipe = fixture("single", 5);
        recipe.transaction_version = 4;
        assert!(spend(&recipe).is_err());
    }
}
