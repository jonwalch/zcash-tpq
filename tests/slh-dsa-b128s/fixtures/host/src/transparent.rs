//! Exact public authorization controls; no signing backend or UTXO authority.
//! The research same-TXID controls mutate only authorizing data. Reuse the
//! existing native codec and fixed public classical signer for those mutations.
use super::*;
use zakura_pq_slh_dsa_b_exp::codec::{push, push_prefix};

fn transaction(raw: &str) -> Result<Transaction> {
    let tx = decode_transaction(&bounded_hex(raw, MAX_TX)?)?;
    require(
        matches!(tx, Transaction::V5 { .. } | Transaction::V6 { .. })
            && tx.network_upgrade() == Some(NetworkUpgrade::Nu7)
            && !tx.is_coinbase()
            && !tx.has_shielded_inputs()
            && !tx.has_shielded_outputs()
            && (1..=16).contains(&tx.inputs().len()),
        "schema",
        "control_transparent_shape",
    )?;
    Ok(tx)
}

fn unlock(tx: &Transaction, index: usize) -> Result<&[u8]> {
    match tx.inputs().get(index) {
        Some(ChainInput::PrevOut { unlock_script, .. }) => Ok(unlock_script.as_raw_bytes()),
        _ => fail("schema", "control_input_index"),
    }
}

/// Only the exact public 2-of-3 script produced by classical::signature.
fn classical_parts(bytes: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<u8>)> {
    require(
        bytes.first() == Some(&0),
        "schema",
        "control_multisig_dummy",
    )?;
    let mut rest = &bytes[1..];
    let mut signatures = Vec::new();
    for _ in 0..2 {
        let length = usize::from(*rest.first().ok_or(Failure {
            stage: "schema",
            reason: "control_classical_signature",
        })?);
        require(
            (9..=73).contains(&length) && rest.len() > length,
            "schema",
            "control_classical_signature",
        )?;
        let signature = &rest[1..=length];
        require(
            signature.last() == Some(&1)
                && secp256k1::ecdsa::Signature::from_der(&signature[..length - 1]).is_ok(),
            "schema",
            "control_classical_signature",
        )?;
        signatures.push(signature.to_vec());
        rest = &rest[length + 1..];
    }
    let (_, redeem, _) = classical::scripts("multisig")?;
    let mut expected = Vec::new();
    push(&mut expected, &redeem);
    require(rest == expected, "schema", "control_multisig_redeem")?;
    Ok((signatures, redeem))
}

fn slh(bytes: &[u8]) -> Result<Authorization> {
    Authorization::decode(bytes).map_err(|_| Failure {
        stage: "schema",
        reason: "control_slh_authorization",
    })
}

pub(super) fn authorization(recipe: &ControlAuthorizationRecipe) -> Result<Value> {
    use AuthorizationVariant::*;
    let original = transaction(&recipe.transaction_hex)?;
    let index = usize::try_from(recipe.input_index).map_err(|_| Failure {
        stage: "schema",
        reason: "control_input_index",
    })?;
    let original_script = unlock(&original, index)?;
    let needs_donor = matches!(recipe.variant, SlhOnClassical | ClassicalOnSlh);
    require(
        needs_donor == recipe.donor_transaction_hex.is_some(),
        "schema",
        "control_donor",
    )?;
    let donor = recipe
        .donor_transaction_hex
        .as_deref()
        .map(transaction)
        .transpose()?;
    let (script, rejection) = match recipe.variant {
        MissingClassicalQuorum | SlhOnClassical => {
            let (mut signatures, redeem) = classical_parts(original_script)?;
            if let Some(donor) = &donor {
                let authorization = slh(unlock(donor, 0)?)?;
                signatures[1] = authorization.records[0].signature.to_vec();
            } else {
                signatures.pop();
            }
            let mut bytes = vec![0];
            for signature in signatures {
                push(&mut bytes, &signature);
            }
            push(&mut bytes, &redeem);
            (bytes, "script")
        }
        ClassicalOnSlh => {
            let authorization = slh(original_script)?;
            let (signatures, _) =
                classical_parts(unlock(donor.as_ref().expect("required donor"), 0)?)?;
            let record = &authorization.records[0];
            let start = 1 + push_prefix(record.public_key.len()) + record.public_key.len();
            let end = start + push_prefix(record.signature.len()) + record.signature.len();
            let mut replacement = Vec::new();
            push(&mut replacement, &signatures[0]);
            let mut bytes = original_script.to_vec();
            bytes.splice(start..end, replacement);
            require(
                Authorization::decode(&bytes) == Err(Rejection::Encoding),
                "generation",
                "control_wrong_family_encoding",
            )?;
            (bytes, "encoding")
        }
        CorruptSlh => {
            let mut authorization = slh(original_script)?;
            authorization.records[0].signature[0] ^= 1;
            (authorization.encode(), "signature")
        }
    };
    let mut changed = original.clone();
    install(&mut changed, index, Script::new(&script));
    let bytes = changed.zcash_serialize_to_vec().map_err(|_| Failure {
        stage: "generation",
        reason: "serialization",
    })?;
    require(
        bytes.len() <= MAX_TX
            && decode_transaction(&bytes)? == changed
            && changed.hash() == original.hash()
            && changed.auth_digest() != original.auth_digest(),
        "generation",
        "control_authorization_identity",
    )?;
    Ok(
        json!({"material":"public-test-only","variant":recipe.variant,
        "transaction_hex":hex::encode(&bytes),"transaction_sha256":strict::hash(&bytes),
        "txid":changed.hash().to_string(),
        "auth_digest":changed.auth_digest().expect("v5/v6 checked").to_string(),
        "positive_auth_digest":original.auth_digest().expect("v5/v6 checked").to_string(),
        "positive_transaction_sha256":strict::hash(&bounded_hex(&recipe.transaction_hex, MAX_TX)?),
        "input_index":recipe.input_index,"expected_consensus_reason":rejection,
        "outputs":output_fields(&changed)}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slh_fixture(version: u8) -> Artifact {
        serde_json::from_str(if version == 5 {
            include_str!("../../data/v5-1of1.json")
        } else {
            include_str!("../../data/v6-1of1.json")
        })
        .unwrap()
    }

    fn classical_fixture(version: u8) -> Value {
        let (lock, _, _) = classical::scripts("multisig").unwrap();
        let (parent, _) = TransactionRecipe {
            version,
            network_upgrade: NetworkUpgrade::Nu7,
            lock_time: LockTime::Height(Height(0)),
            expiry_height: Height(140),
            spends: vec![],
            outputs: vec![chain_output(10_000_000, lock.as_raw_bytes().to_vec()).unwrap()],
        }
        .build();
        classical::spend(&ClassicalRecipe {
            kind: "multisig".into(),
            transaction_version: version,
            lock_time: 0,
            expiry_height: 140,
            parent_hex: hex::encode(parent.zcash_serialize_to_vec().unwrap()),
            output_index: 0,
            outputs: vec![ScriptOutput {
                value_zat: 3_000_000,
                script_hex: hex::encode(lock.as_raw_bytes()),
            }],
            fee_zat: 20_000,
        })
        .unwrap()
    }

    #[test]
    fn controls_change_authorization_but_preserve_exact_transaction_effects() {
        use AuthorizationVariant::*;
        for version in [5, 6] {
            let valid = slh_fixture(version);
            assert_eq!(check(&valid).unwrap(), valid.expected);
            let classical = classical_fixture(version);
            let classical_raw = classical["transaction_hex"].as_str().unwrap();
            for (variant, raw, donor, reason) in [
                (MissingClassicalQuorum, classical_raw, None, "script"),
                (
                    SlhOnClassical,
                    classical_raw,
                    Some(valid.transaction_hex.clone()),
                    "script",
                ),
                (
                    ClassicalOnSlh,
                    valid.transaction_hex.as_str(),
                    Some(classical_raw.to_owned()),
                    "encoding",
                ),
                (
                    CorruptSlh,
                    valid.transaction_hex.as_str(),
                    None,
                    "signature",
                ),
            ] {
                let request = ControlAuthorizationRecipe {
                    transaction_hex: raw.into(),
                    input_index: 0,
                    variant,
                    donor_transaction_hex: donor,
                };
                let output = authorization(&request).unwrap();
                let original = transaction(raw).unwrap();
                let changed = transaction(output["transaction_hex"].as_str().unwrap()).unwrap();
                assert_eq!(output["txid"], original.hash().to_string());
                assert_eq!(changed.outputs(), original.outputs());
                assert_ne!(changed.auth_digest(), original.auth_digest());
                assert_eq!(output["expected_consensus_reason"], reason);
                if matches!(variant, CorruptSlh) {
                    let previous = valid
                        .inputs
                        .iter()
                        .map(|i| {
                            chain_output(
                                i.spent_output.value_zat,
                                hex::decode(&i.spent_output.script_hex).unwrap(),
                            )
                            .unwrap()
                        })
                        .collect();
                    assert_eq!(
                        TransactionContext::new(
                            &changed,
                            NetworkDomain::Regtest,
                            NetworkUpgrade::Nu7,
                            Arc::new(previous)
                        )
                        .unwrap()
                        .verify_input(0),
                        Err(Rejection::Signature)
                    );
                }
                if matches!(variant, MissingClassicalQuorum) {
                    let bytes = unlock(&changed, 0).unwrap();
                    let end = 2 + usize::from(bytes[1]);
                    let (_, redeem, _) = classical::scripts("multisig").unwrap();
                    let mut expected = Vec::new();
                    push(&mut expected, &redeem);
                    assert_eq!(&bytes[end..], expected);
                }
                let before = unlock(&original, 0).unwrap();
                let after = unlock(&changed, 0).unwrap();
                if matches!(variant, SlhOnClassical) {
                    // Dummy and first ECDSA push stay; the donor SLH signature is the
                    // second push (OP_PUSHDATA2); the 105-byte redeem push stays last.
                    let donor = hex::decode(&valid.inputs[0].records[0].signature_hex).unwrap();
                    assert_eq!(donor.len(), 7856);
                    let first = 2 + usize::from(before[1]);
                    let mut expected = before[..first].to_vec();
                    expected.extend([0x4d, 0xb0, 0x1e]);
                    expected.extend(donor);
                    expected.extend(&before[before.len() - 107..]);
                    assert_eq!(
                        &before[before.len() - 107..before.len() - 105],
                        &[0x4c, 105]
                    );
                    assert_eq!(after, expected);
                }
                if matches!(variant, ClassicalOnSlh) {
                    // Record 0 (OP_0, 32-byte key push) keeps its key; the donor's first
                    // ECDSA push replaces the 7,856-byte signature push.
                    assert_eq!(Authorization::decode(after), Err(Rejection::Encoding));
                    let donor = unlock(&transaction(classical_raw).unwrap(), 0)
                        .unwrap()
                        .to_vec();
                    let ecdsa = &donor[1..2 + usize::from(donor[1])];
                    let mut expected = before[..34].to_vec();
                    expected.extend(ecdsa);
                    expected.extend(&before[34 + 3 + 7856..]);
                    assert_eq!(&before[34..37], &[0x4d, 0xb0, 0x1e]);
                    assert_eq!(after, expected);
                }
            }
        }
    }

    #[test]
    fn public_control_operations_preserve_strict_envelope_and_required_null_fields() {
        let mut request = json!({"schema_version":1,"contract":CONTRACT,"public_fixture":true,
            "op":"control-authorization", "recipe":{"transaction_hex":slh_fixture(5).transaction_hex,
                "input_index":0,"variant":"corrupt-slh","donor_transaction_hex":null}});
        let result = handle(&serde_json::to_vec(&request).unwrap());
        assert_eq!(result["op"], "control-authorization");
        assert_eq!(result["ok"], true);
        request["public_fixture"] = json!(false);
        assert_eq!(
            handle(&serde_json::to_vec(&request).unwrap())["error"]["reason"],
            "envelope"
        );
        request["public_fixture"] = json!(true);
        request["recipe"]
            .as_object_mut()
            .unwrap()
            .remove("donor_transaction_hex");
        assert_eq!(
            handle(&serde_json::to_vec(&request).unwrap())["error"]["reason"],
            "fields"
        );
        let classical = classical_fixture(5);
        let mut funding = json!({"schema_version":1,"contract":CONTRACT,"public_fixture":true,
            "op":"control-funding", "recipe":{"kind":"multisig","transaction_version":5,
                "lock_time":0,"expiry_height":140,"parent_hex":classical["transaction_hex"],
                "output_index":0,"outputs":[{"value_zat":1_000_000,"script_hex":format!("5120{}c0", "11".repeat(32))}],
                "fee_zat":20_000}});
        let result = handle(&serde_json::to_vec(&funding).unwrap());
        assert_eq!(result["op"], "control-funding");
        assert_eq!(result["ok"], true);
        funding["public_fixture"] = json!(false);
        let result = handle(&serde_json::to_vec(&funding).unwrap());
        assert_eq!(result["op"], "control-funding");
        assert_eq!(result["error"]["reason"], "envelope");
    }

    #[test]
    fn controls_reject_foreign_shapes_and_unexpected_donors() {
        let valid = slh_fixture(5);
        let mut recipe = ControlAuthorizationRecipe {
            transaction_hex: valid.transaction_hex,
            input_index: 0,
            variant: AuthorizationVariant::MissingClassicalQuorum,
            donor_transaction_hex: None,
        };
        // An SLH authorization is not the fixed public 2-of-3 classical script.
        let reason =
            |recipe: &ControlAuthorizationRecipe| authorization(recipe).unwrap_err().reason;
        assert_eq!(reason(&recipe), "control_classical_signature");
        recipe.variant = AuthorizationVariant::CorruptSlh;
        recipe.input_index = u32::MAX;
        assert_eq!(reason(&recipe), "control_input_index");
        recipe.input_index = 0;
        recipe.donor_transaction_hex = Some(recipe.transaction_hex.clone());
        assert_eq!(reason(&recipe), "control_donor");
        recipe.variant = AuthorizationVariant::ClassicalOnSlh;
        assert_eq!(reason(&recipe), "control_classical_signature");
        recipe.donor_transaction_hex = None;
        assert_eq!(reason(&recipe), "control_donor");
    }
}
