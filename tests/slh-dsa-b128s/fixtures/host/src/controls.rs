//! Public mixed-input and block controls adapted from pinned research fixtures.
//! Parent bytes are supplied evidence, not authenticated UTXOs; the driver checks
//! those against both nodes before requesting a fixture. No secret keys enter here.
use super::*;
use hex::FromHex;
use zakura_chain::{
    block::{Block, ChainHistoryBlockTxAuthCommitmentHash, ChainHistoryMmrRootHash, Header},
    parameters::{
        subsidy::miner_fee_share,
        testnet::{ConfiguredActivationHeights, RegtestParameters},
        Network,
    },
    serialization::BytesInDisplayOrder,
    work::{difficulty::CompactDifficulty, equihash::Solution},
};

fn parent(input: &ParentOutput) -> Result<Spend> {
    let transaction = decode_transaction(&bounded_hex(&input.parent_hex, MAX_TX)?)?;
    let index = usize::try_from(input.output_index).map_err(|_| Failure {
        stage: "schema",
        reason: "control_outpoint",
    })?;
    let previous = transaction.outputs().get(index).ok_or(Failure {
        stage: "schema",
        reason: "control_outpoint",
    })?;
    Ok(Spend {
        outpoint: OutPoint {
            hash: transaction.hash(),
            index: input.output_index,
        },
        sequence: 0xffff_fffe,
        previous_output: previous.clone(),
    })
}

fn mixed(recipe: &MixedRecipe) -> Result<(Transaction, Arc<Vec<ChainOutput>>, Policy, usize)> {
    require(
        matches!(recipe.transaction_version, 5 | 6) && recipe.expiry_height > 0,
        "schema",
        "mixed_shape",
    )?;
    let public = fixed_hex::<32>(&recipe.public_key_hex)?;
    let policy = Policy::new(1, vec![key_commitment(&public)]).map_err(|_| Failure {
        stage: "schema",
        reason: "mixed_policy",
    })?;
    let classical = parent(&recipe.classical)?;
    let slh = parent(&recipe.slh)?;
    let (other_lock, lock) = match recipe.kind.as_str() {
        "unsupported51" | "unsupported52" => {
            let mut bytes = policy.lock_script().as_raw_bytes().to_vec();
            bytes[0] = if recipe.kind == "unsupported51" {
                0x51
            } else {
                0x52
            };
            (Script::new(&bytes), classical::scripts("single")?.0)
        }
        _ => {
            let lock = classical::scripts(&recipe.kind)?.0;
            (lock.clone(), lock)
        }
    };
    require(
        classical.previous_output.lock_script == other_lock
            && slh.previous_output.lock_script == policy.lock_script()
            && classical.outpoint != slh.outpoint,
        "schema",
        "mixed_previous_outputs",
    )?;
    value_sum(
        [
            u64::from(classical.previous_output.value),
            u64::from(slh.previous_output.value),
        ]
        .into_iter(),
    )?;
    let total = u64::from(classical.previous_output.value) + u64::from(slh.previous_output.value);
    let value = total.checked_sub(recipe.fee_zat).ok_or(Failure {
        stage: "schema",
        reason: "mixed_value",
    })?;
    require(
        recipe.fee_zat >= 800 && value >= 2403,
        "schema",
        "mixed_fee_or_value",
    )?;
    let slh_index = usize::from(recipe.classical_first);
    let spends = if recipe.classical_first {
        vec![classical, slh]
    } else {
        vec![slh, classical]
    };
    let (transaction, previous) = TransactionRecipe {
        version: recipe.transaction_version,
        network_upgrade: NetworkUpgrade::Nu7,
        lock_time: LockTime::Height(Height(0)),
        expiry_height: Height(recipe.expiry_height),
        spends,
        outputs: vec![chain_output(value, lock.as_raw_bytes().to_vec())?],
    }
    .build();
    Ok((transaction, previous, policy, slh_index))
}

pub(super) fn mixed_prepare(recipe: &MixedRecipe) -> Result<Value> {
    let (transaction, previous, policy, index) = mixed(recipe)?;
    let context = InputSigningContext::new(
        &transaction,
        NetworkDomain::Regtest,
        NetworkUpgrade::Nu7,
        previous,
        index,
        &policy,
    )
    .map_err(|_| Failure {
        stage: "generation",
        reason: "mixed_context",
    })?;
    Ok(
        json!({"slh_input_index":index,"message_hex":hex::encode(context.message()),
        "public_key_hex":recipe.public_key_hex,"signer_index":0}),
    )
}

pub(super) fn mixed_assemble(recipe: &MixedRecipe, entry: &Record) -> Result<Value> {
    let (mut transaction, previous, policy, index) = mixed(recipe)?;
    let context = InputSigningContext::new(
        &transaction,
        NetworkDomain::Regtest,
        NetworkUpgrade::Nu7,
        previous.clone(),
        index,
        &policy,
    )
    .map_err(|_| Failure {
        stage: "generation",
        reason: "mixed_context",
    })?;
    let authorization = context
        .authorization(vec![record(entry)?])
        .map_err(|_| Failure {
            stage: "generation",
            reason: "mixed_authorization",
        })?;
    install(
        &mut transaction,
        index,
        Script::new(&authorization.encode()),
    );
    let classical_index = 1 - index;
    let unsupported = matches!(recipe.kind.as_str(), "unsupported51" | "unsupported52");
    if !unsupported {
        let signature = classical::signature(
            &transaction,
            previous.clone(),
            &recipe.kind,
            classical_index,
        )?;
        install(&mut transaction, classical_index, signature);
    }
    TransactionContext::new(
        &transaction,
        NetworkDomain::Regtest,
        NetworkUpgrade::Nu7,
        previous.clone(),
    )
    .and_then(|context| context.verify_input(index))
    .map_err(|_| Failure {
        stage: "generation",
        reason: "mixed_native_recheck",
    })?;
    let bytes = transaction.zcash_serialize_to_vec().map_err(|_| Failure {
        stage: "generation",
        reason: "serialization",
    })?;
    require(
        decode_transaction(&bytes)? == transaction,
        "generation",
        "mixed_roundtrip",
    )?;
    Ok(
        json!({"material":"public-test-only","transaction_hex":hex::encode(&bytes),
        "transaction_sha256":strict::hash(&bytes),"txid":transaction.hash().to_string(),
        "slh_input_index":index,"classical_input_index":classical_index,
        "slh_checks":1,"ecdsa_checks":if unsupported {0} else if recipe.kind == "multisig" {2} else {1},
        "message_hex":hex::encode(context.message()),"outputs":output_fields(&transaction)}),
    )
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name].as_str().ok_or(Failure {
        stage: "schema",
        reason: "block_template_field",
    })
}

/// Research `block()` narrowed to an empty-mempool, transparent NU7 template.
/// Fees are explicit fixture inputs; the driver independently binds them to the
/// actual authenticated parents and exact transaction outputs.
pub(super) fn block(recipe: &ControlBlockRecipe) -> Result<Value> {
    block_inner(recipe, false, false)
}

/// Explicit human shielded controls reuse the same block/header construction.
#[cfg(feature = "shielded-fixtures")]
pub(super) fn shielded_block(recipe: &ControlBlockRecipe) -> Result<Value> {
    block_inner(recipe, true, false)
}

/// Separate spend-fixture entry; existing output and transparent modes stay narrow.
#[cfg(feature = "shielded-fixtures")]
pub(super) fn shielded_spend_block(recipe: &ControlBlockRecipe) -> Result<Value> {
    block_inner(recipe, true, true)
}

fn block_inner(
    recipe: &ControlBlockRecipe,
    shielded_outputs: bool,
    shielded_spends: bool,
) -> Result<Value> {
    let template = &recipe.template;
    require(
        template["transactions"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && (1..=5).contains(&recipe.transactions.len()),
        "schema",
        "control_block_shape",
    )?;
    let mut coinbase = decode_transaction(&bounded_hex(
        field(&template["coinbasetxn"], "data")?,
        MAX_TX,
    )?)?;
    require(
        coinbase.is_coinbase()
            && coinbase.network_upgrade() == Some(NetworkUpgrade::Nu7)
            && !coinbase.has_shielded_inputs()
            && !coinbase.has_shielded_outputs(),
        "schema",
        "control_transparent_coinbase",
    )?;
    let network = Network::new_regtest(RegtestParameters {
        activation_heights: ConfiguredActivationHeights {
            nu6_3: Some(1),
            nu7: Some(105),
            ..Default::default()
        },
        ..Default::default()
    });
    let height = match coinbase.inputs().first() {
        Some(ChainInput::Coinbase { height, .. }) => *height,
        _ => return fail("schema", "block_height"),
    };
    require(
        height.0 >= 105 && template["height"].as_u64() == Some(u64::from(height.0)),
        "schema",
        "block_height",
    )?;
    value_sum(recipe.transactions.iter().map(|t| t.fee_zat))?;
    let fees = recipe.transactions.iter().map(|t| t.fee_zat).sum::<u64>();
    let fees = fees.try_into().map_err(|_| Failure {
        stage: "schema",
        reason: "block_fees",
    })?;
    let (lock, _, _) = classical::scripts(&recipe.kind)?;
    let outputs = match &mut coinbase {
        Transaction::V5 { outputs, .. } | Transaction::V6 { outputs, .. } => outputs,
        _ => return fail("schema", "control_coinbase_version"),
    };
    require(
        outputs
            .iter()
            .filter(|output| output.lock_script == lock)
            .count()
            == 1,
        "schema",
        "control_miner_output",
    )?;
    let miner = outputs
        .iter_mut()
        .find(|output| output.lock_script == lock)
        .expect("one matching miner output");
    miner.value = (miner.value + miner_fee_share(height, &network, fees)).map_err(|_| Failure {
        stage: "schema",
        reason: "block_fees",
    })?;
    let mut transactions = vec![Arc::new(coinbase)];
    for entry in &recipe.transactions {
        let bytes = bounded_hex(&entry.transaction_hex, MAX_TX)?;
        let transaction = decode_transaction(&bytes)?;
        require(
            !transaction.is_coinbase()
                && transaction.network_upgrade() == Some(NetworkUpgrade::Nu7)
                && (shielded_spends || !transaction.has_shielded_inputs())
                && (shielded_outputs || !transaction.has_shielded_outputs())
                && (!shielded_outputs
                    || (transaction.inputs().len() == 1
                        && transaction.sapling_nullifiers().count() <= 1
                        && transaction.sapling_outputs().count() <= 2
                        && transaction.orchard_actions().count() <= 2
                        && transaction.ironwood_actions().count() <= 2)),
            "schema",
            "control_transparent_transaction",
        )?;
        transactions.push(Arc::new(transaction));
    }
    let mut nonce = [0; 32];
    nonce[..8].copy_from_slice(&recipe.nonce.to_le_bytes());
    let number = |name: &str| {
        template[name].as_u64().ok_or(Failure {
            stage: "schema",
            reason: "block_template_field",
        })
    };
    let time = u32::try_from(number("curtime")?).map_err(|_| Failure {
        stage: "schema",
        reason: "block_time",
    })?;
    let mut block = Block {
        header: Arc::new(Header {
            version: u32::try_from(number("version")?).map_err(|_| Failure {
                stage: "schema",
                reason: "block_version",
            })?,
            previous_block_hash: field(template, "previousblockhash")?.parse().map_err(|_| {
                Failure {
                    stage: "schema",
                    reason: "block_parent",
                }
            })?,
            merkle_root: transactions.iter().collect(),
            commitment_bytes: [0; 32].into(),
            time: std::time::UNIX_EPOCH
                .checked_add(std::time::Duration::from_secs(u64::from(time)))
                .ok_or(Failure {
                    stage: "schema",
                    reason: "block_time",
                })?
                .into(),
            difficulty_threshold: CompactDifficulty::from_hex(field(template, "bits")?).map_err(
                |_| Failure {
                    stage: "schema",
                    reason: "block_bits",
                },
            )?,
            nonce: nonce.into(),
            solution: Solution::for_proposal_for_network(&network),
        }),
        transactions,
    };
    let history =
        ChainHistoryMmrRootHash::from_hex(field(&template["defaultroots"], "chainhistoryroot")?)
            .map_err(|_| Failure {
                stage: "schema",
                reason: "block_history",
            })?;
    Arc::make_mut(&mut block.header).commitment_bytes =
        ChainHistoryBlockTxAuthCommitmentHash::from_commitments(&history, &block.auth_data_root())
            .bytes_in_serialized_order()
            .into();
    let bytes = block.zcash_serialize_to_vec().map_err(|_| Failure {
        stage: "generation",
        reason: "serialization",
    })?;
    require(bytes.len() <= MAX_TX, "schema", "block_size")?;
    Ok(
        json!({"block_hex":hex::encode(&bytes),"block_sha256":strict::hash(&bytes),
        "block_hash":block.hash().to_string(),"height":height.0,
        "txids":block.transactions.iter().skip(1).map(|t|t.hash().to_string()).collect::<Vec<_>>(),
        "aggregate_fee_zat":u64::from(fees)}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn recipe(first: bool, version: u8) -> MixedRecipe {
        let key = [7; 32];
        let policy = Policy::new(1, vec![key_commitment(&key)]).unwrap();
        let (classical, _, _) = classical::scripts("single").unwrap();
        let (parent, _) = TransactionRecipe {
            version,
            network_upgrade: NetworkUpgrade::Nu7,
            lock_time: LockTime::Height(Height(0)),
            expiry_height: Height(130),
            spends: vec![],
            outputs: vec![
                chain_output(3_000_000, classical.as_raw_bytes().to_vec()).unwrap(),
                chain_output(3_000_000, policy.lock_script().as_raw_bytes().to_vec()).unwrap(),
            ],
        }
        .build();
        let raw = hex::encode(parent.zcash_serialize_to_vec().unwrap());
        MixedRecipe {
            kind: "single".into(),
            transaction_version: version,
            expiry_height: 130,
            classical_first: first,
            classical: ParentOutput {
                parent_hex: raw.clone(),
                output_index: 0,
            },
            slh: ParentOutput {
                parent_hex: raw,
                output_index: 1,
            },
            public_key_hex: hex::encode(key),
            fee_zat: 100_000,
        }
    }
    #[test]
    fn mixed_messages_bind_order_parent_outputs_and_version() {
        let mut seen = HashSet::new();
        for version in [5, 6] {
            for first in [false, true] {
                let recipe = recipe(first, version);
                let prepared = mixed_prepare(&recipe).unwrap();
                assert_eq!(prepared["slh_input_index"], usize::from(first));
                assert!(seen.insert(prepared["message_hex"].as_str().unwrap().to_string()));
                let (tx, previous, _, index) = mixed(&recipe).unwrap();
                assert_eq!(previous.len(), 2);
                assert_eq!(previous[index].lock_script.as_raw_bytes().len(), 35);
                assert_eq!(u64::from(tx.outputs()[0].value), 5_900_000);
            }
        }
    }
    #[test]
    fn unsupported_mixed_templates_bind_both_input_orders_without_other_backends() {
        for version in [5, 6] {
            for first in [false, true] {
                for prefix in [0x51, 0x52] {
                    let mut request = recipe(first, version);
                    request.kind = format!("unsupported{prefix:02x}");
                    let mut parent =
                        decode_transaction(&hex::decode(&request.classical.parent_hex).unwrap())
                            .unwrap();
                    let mut bytes = parent.outputs()[1].lock_script.as_raw_bytes().to_vec();
                    bytes[0] = prefix;
                    match &mut parent {
                        Transaction::V5 { outputs, .. } | Transaction::V6 { outputs, .. } => {
                            outputs[0].lock_script = Script::new(&bytes)
                        }
                        _ => unreachable!("fixture v5/v6"),
                    }
                    let raw = hex::encode(parent.zcash_serialize_to_vec().unwrap());
                    request.classical.parent_hex = raw.clone();
                    request.slh.parent_hex = raw;
                    assert_eq!(
                        mixed_prepare(&request).unwrap()["slh_input_index"],
                        usize::from(first)
                    );
                    let (_, previous, _, slh_index) = mixed(&request).unwrap();
                    assert_eq!(
                        previous[1 - slh_index].lock_script.as_raw_bytes()[0],
                        prefix
                    );
                    let entry = Record {
                        signer_index: 0,
                        public_key_hex: request.public_key_hex.clone(),
                        signature_hex: "00".repeat(7856),
                    };
                    assert!(mixed_assemble(&request, &entry).is_err());
                    request.kind = "unsupported50".into();
                    assert!(mixed_prepare(&request).is_err());
                }
            }
        }
    }

    #[test]
    fn mixed_parents_and_partial_are_checked() {
        let mut recipe = recipe(true, 5);
        recipe.classical.output_index = 1;
        assert!(mixed_prepare(&recipe).is_err());
        recipe.classical.output_index = 0;
        let entry = Record {
            signer_index: 0,
            public_key_hex: recipe.public_key_hex.clone(),
            signature_hex: "00".repeat(7856),
        };
        assert!(mixed_assemble(&recipe, &entry).is_err());
        recipe.fee_zat = u64::MAX;
        assert!(mixed_prepare(&recipe).is_err());
    }
    #[test]
    fn control_block_rejects_nonempty_templates_and_unbounded_inputs() {
        let recipe = ControlBlockRecipe {
            template: json!({"transactions":[{}]}),
            kind: "single".into(),
            nonce: 1,
            transactions: vec![],
        };
        assert!(block(&recipe).is_err());
    }

    #[test]
    fn control_block_roundtrips_and_commits_exact_transactions_and_fee_share() {
        for (version, height) in [5, 6]
            .into_iter()
            .flat_map(|v| [104, 105, 106, 107, 108, 109, 111].map(|h| (v, h)))
        {
            let (lock, _, _) = classical::scripts("single").unwrap();
            let (mut coinbase, _) = TransactionRecipe {
                version,
                network_upgrade: NetworkUpgrade::Nu7,
                lock_time: LockTime::Height(Height(0)),
                expiry_height: Height(height),
                spends: vec![],
                outputs: vec![chain_output(100_000_000, lock.as_raw_bytes().to_vec()).unwrap()],
            }
            .build();
            match &mut coinbase {
                Transaction::V5 { inputs, .. } | Transaction::V6 { inputs, .. } => {
                    inputs.push(ChainInput::Coinbase {
                        height: Height(height),
                        data: vec![],
                        sequence: u32::MAX,
                    })
                }
                _ => unreachable!("fixture v5/v6"),
            }
            let (transaction, _, _, _) = mixed(&recipe(true, version)).unwrap();
            let transaction_bytes = transaction.zcash_serialize_to_vec().unwrap();
            let request = ControlBlockRecipe {
                template: json!({"transactions":[],"coinbasetxn":{"data":hex::encode(coinbase.zcash_serialize_to_vec().unwrap())},
                    "height":height,"version":4,"previousblockhash":"11".repeat(32),"curtime":1_700_000_000,
                    "bits":"200f0f0f","defaultroots":{"chainhistoryroot":"22".repeat(32)}}),
                kind: "single".into(),
                nonce: 64,
                transactions: vec![ControlTransaction {
                    transaction_hex: hex::encode(&transaction_bytes),
                    fee_zat: 100_000,
                }],
            };
            if height == 104 {
                assert_eq!(block(&request).unwrap_err().reason, "block_height");
                continue;
            }
            let result = block(&request).unwrap();
            let bytes = hex::decode(result["block_hex"].as_str().unwrap()).unwrap();
            let parsed = Block::zcash_deserialize(bytes.as_slice()).unwrap();
            assert_eq!(parsed.zcash_serialize_to_vec().unwrap(), bytes);
            assert_eq!(
                parsed.transactions[1].zcash_serialize_to_vec().unwrap(),
                transaction_bytes
            );
            assert_eq!(parsed.coinbase_height(), Some(Height(height)));
            assert!(parsed
                .transactions
                .iter()
                .all(|transaction| { transaction.network_upgrade() == Some(NetworkUpgrade::Nu7) }));
            assert_eq!(
                parsed.header.merkle_root,
                parsed.transactions.iter().collect()
            );
            let history = ChainHistoryMmrRootHash::from_hex("22".repeat(32)).unwrap();
            assert_eq!(
                parsed.header.commitment_bytes,
                ChainHistoryBlockTxAuthCommitmentHash::from_commitments(
                    &history,
                    &parsed.auth_data_root()
                )
                .bytes_in_serialized_order()
                .into()
            );
            // NU7 contributes floor(6 * aggregate_fees / 10) to NSM.
            // This retained arithmetic answer is independent of miner_fee_share.
            assert_eq!(
                u64::from(parsed.transactions[0].outputs()[0].value),
                100_040_000
            );
            assert_eq!(result["block_hash"], parsed.hash().to_string());
            assert_eq!(result["txids"], json!([transaction.hash().to_string()]));
        }
    }
}
