//! Bounded human-only proof fixtures, selectively adapted from research e759cb86.
//! See SHIELDED_ATTRIBUTION.md. Fixed keys are PUBLIC; never use real funds.
use super::*;
use orchard::{
    builder::{Builder, BundleType},
    bundle::{BatchValidator, BundleVersion, Flags},
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendingKey},
    value::NoteValue,
    Anchor,
};
use sha2::{Digest, Sha256};
use zakura_chain::{
    orchard::{Action, AuthorizedAction, ShieldedData},
    primitives::Halo2Proof,
    sapling::{self, OutputInTransactionV4, SharedAnchor, TransferData},
    transaction::HashType,
};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::value::ZatBalance;

const DEPOSIT: u64 = 50_000;
const FEE: u64 = 100_000;
const POOLS: [&str; 3] = ["sapling", "orchard", "ironwood"];

pub(super) fn converted<T, E>(value: std::result::Result<T, E>) -> Result<T> {
    value.map_err(|_| Failure {
        stage: "shielded",
        reason: "construction",
    })
}
pub(super) fn needed<T>(value: Option<T>) -> Result<T> {
    value.ok_or(Failure {
        stage: "shielded",
        reason: "missing_bundle",
    })
}
fn deposit(pools: &[String]) -> u64 {
    DEPOSIT
        * u64::try_from(pools.iter().filter(|p| p.as_str() != "orchard").count())
            .expect("three bounded pools")
}
pub(super) fn validate_shape(recipe: &ShieldedRecipe) -> Result<()> {
    require(recipe.human_run, "schema", "human_run_required")?;
    require(
        matches!(recipe.transaction_version, 5 | 6)
            && (111..=1000).contains(&recipe.expiry_height)
            && !recipe.pools.is_empty()
            && recipe.pools.len() <= 3,
        "schema",
        "shielded_shape",
    )?;
    let expected: Vec<_> = POOLS
        .iter()
        .filter(|p| recipe.pools.iter().any(|q| q == **p))
        .copied()
        .collect();
    require(
        recipe.pools.iter().map(String::as_str).eq(expected)
            && (recipe.transaction_version == 6 || !recipe.pools.iter().any(|p| p == "ironwood")),
        "schema",
        "shielded_pools",
    )?;
    require(
        matches!(recipe.authorization.as_str(), "slh" | "single" | "multisig")
            && (recipe.authorization == "slh") == recipe.public_key_hex.is_some(),
        "schema",
        "shielded_authorization",
    )?;
    require(
        recipe.pools.iter().any(|p| p == "sapling") == recipe.sapling_parameters.is_some(),
        "schema",
        "sapling_parameters",
    )?;
    if let Some(parameters) = &recipe.sapling_parameters {
        for (path, hash) in [
            (&parameters.spend_path, &parameters.spend_sha256),
            (&parameters.output_path, &parameters.output_sha256),
        ] {
            fixed_hex::<32>(hash)?;
            require(
                path.len() <= 4096 && std::path::Path::new(path).is_absolute(),
                "schema",
                "parameter_path",
            )?;
        }
    }
    Ok(())
}
pub(super) fn context(
    recipe: &ShieldedRecipe,
) -> Result<(Transaction, Arc<Vec<ChainOutput>>, Option<Policy>)> {
    validate_shape(recipe)?;
    let parent = decode_transaction(&bounded_hex(&recipe.parent_hex, MAX_TX)?)?;
    let previous = needed(
        parent
            .outputs()
            .get(usize::try_from(recipe.output_index).map_err(|_| Failure {
                stage: "schema",
                reason: "parent_index",
            })?)
            .cloned(),
    )?;
    let policy = recipe
        .public_key_hex
        .as_ref()
        .map(|key| {
            Policy::new(1, vec![key_commitment(&fixed_hex::<32>(key)?)]).map_err(|_| Failure {
                stage: "schema",
                reason: "policy",
            })
        })
        .transpose()?;
    let lock = match &policy {
        Some(policy) => policy.lock_script(),
        None => classical::scripts(&recipe.authorization)?.0,
    };
    require(
        previous.lock_script == lock,
        "schema",
        "shielded_parent_script",
    )?;
    let change = u64::from(previous.value)
        .checked_sub(FEE + deposit(&recipe.pools))
        .ok_or(Failure {
            stage: "schema",
            reason: "shielded_parent_value",
        })?;
    require(change >= 2403, "schema", "shielded_change")?;
    let (tx, previous) = TransactionRecipe {
        version: recipe.transaction_version,
        network_upgrade: NetworkUpgrade::Nu7,
        lock_time: LockTime::unlocked(),
        expiry_height: Height(recipe.expiry_height),
        spends: vec![Spend {
            outpoint: OutPoint {
                hash: parent.hash(),
                index: recipe.output_index,
            },
            sequence: u32::MAX,
            previous_output: previous,
        }],
        outputs: vec![chain_output(change, lock.as_raw_bytes().to_vec())?],
    }
    .build();
    Ok((tx, previous, policy))
}
fn parameter_bytes(path: &str, expected: &str) -> Result<Vec<u8>> {
    let file = converted(std::fs::File::open(path))?;
    let metadata = converted(file.metadata())?;
    require(
        metadata.is_file() && (1..=64 * 1024 * 1024).contains(&metadata.len()),
        "schema",
        "parameter_size",
    )?;
    let mut bytes = Vec::new();
    converted(file.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes))?;
    require(
        bytes.len() <= 64 * 1024 * 1024 && hex::encode(Sha256::digest(&bytes)) == expected,
        "integrity",
        "parameter_hash",
    )?;
    Ok(bytes)
}
pub(super) fn prover(parameters: &SaplingParameters) -> Result<LocalTxProver> {
    let spend = parameter_bytes(&parameters.spend_path, &parameters.spend_sha256)?;
    let output = parameter_bytes(&parameters.output_path, &parameters.output_sha256)?;
    // The pinned parser additionally checks the established parameter hashes.
    // Caller-provided SHA256 alone is never accepted as a proving-key identity.
    converted(std::panic::catch_unwind(|| {
        LocalTxProver::from_bytes(&spend, &output)
    }))
}
pub(super) fn sapling_slot(
    tx: &mut Transaction,
) -> &mut Option<sapling::ShieldedData<SharedAnchor>> {
    match tx {
        Transaction::V5 {
            sapling_shielded_data,
            ..
        }
        | Transaction::V6 {
            sapling_shielded_data,
            ..
        } => sapling_shielded_data,
        _ => unreachable!("version checked"),
    }
}
pub(super) fn action_slot<'a>(tx: &'a mut Transaction, pool: &str) -> &'a mut Option<ShieldedData> {
    match tx {
        Transaction::V5 {
            orchard_shielded_data,
            ..
        } if pool == "orchard" => orchard_shielded_data,
        Transaction::V6 {
            orchard_shielded_data,
            ironwood_shielded_data,
            ..
        } => {
            if pool == "orchard" {
                orchard_shielded_data
            } else {
                ironwood_shielded_data
            }
        }
        _ => unreachable!("pool/version checked"),
    }
}
// Both library versions use the same wire fields. Keep one conversion for
// current bundles and the fixture-only pre-NU6.3 funding builder.
macro_rules! chain_action_adapter {
    ($name:ident, $library:ident) => {
        pub(super) fn $name(
            bundle: &$library::Bundle<$library::bundle::Authorized, ZatBalance>,
        ) -> Result<ShieldedData> {
            let actions = bundle
                .actions()
                .iter()
                .map(|action| {
                    let mut bytes = Vec::new();
                    bytes.extend(action.cv_net().to_bytes());
                    bytes.extend(action.nullifier().to_bytes());
                    bytes.extend(<[u8; 32]>::from(action.rk()));
                    bytes.extend(action.cmx().to_bytes());
                    bytes.extend(action.encrypted_note().epk_bytes);
                    bytes.extend(action.encrypted_note().enc_ciphertext);
                    bytes.extend(action.encrypted_note().out_ciphertext);
                    Ok(AuthorizedAction::from_parts(
                        converted(Action::zcash_deserialize(bytes.as_slice()))?,
                        <[u8; 64]>::from(action.authorization()).into(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(ShieldedData {
                flags: needed(zakura_chain::orchard::Flags::from_bits(bundle.flag_byte()))?,
                value_balance: converted(i64::from(*bundle.value_balance()).try_into())?,
                shared_anchor: converted(bundle.anchor().to_bytes().try_into())?,
                proof: Halo2Proof(bundle.authorization().proof().as_ref().to_vec()),
                actions: converted(actions.try_into())?,
                binding_sig: <[u8; 64]>::from(bundle.authorization().binding_signature()).into(),
            })
        }
    };
}
chain_action_adapter!(chain_action, orchard);
chain_action_adapter!(chain_legacy_action, orchard_legacy);
pub(super) fn chain_sapling(
    bundle: &sapling_crypto::Bundle<sapling_crypto::bundle::Authorized, ZatBalance>,
) -> Result<sapling::ShieldedData<SharedAnchor>> {
    let outputs = bundle
        .shielded_outputs()
        .iter()
        .map(|output| {
            let mut bytes = Vec::new();
            bytes.extend(output.cv().to_bytes());
            bytes.extend(output.cmu().to_bytes());
            bytes.extend(output.ephemeral_key().0);
            bytes.extend(output.enc_ciphertext());
            bytes.extend(output.out_ciphertext());
            bytes.extend(output.zkproof());
            Ok(converted(OutputInTransactionV4::zcash_deserialize(bytes.as_slice()))?.0)
        })
        .collect::<Result<Vec<_>>>()?;
    let spends = bundle
        .shielded_spends()
        .iter()
        .map(|spend| {
            let mut bytes = Vec::new();
            bytes.extend(spend.cv().to_bytes());
            bytes.extend(spend.nullifier().0);
            bytes.extend(<[u8; 32]>::from(*spend.rk()));
            Ok(sapling::Spend::from_v5_parts(
                converted(sapling::SpendPrefixInTransactionV5::zcash_deserialize(
                    bytes.as_slice(),
                ))?,
                zakura_chain::primitives::Groth16Proof(*spend.zkproof()),
                <[u8; 64]>::from(*spend.spend_auth_sig()).into(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let transfers = if let Some(first) = bundle.shielded_spends().first() {
        TransferData::SpendsAndMaybeOutputs {
            shared_anchor: converted(first.anchor().to_bytes().try_into())?,
            spends: converted(spends.try_into())?,
            maybe_outputs: outputs,
        }
    } else {
        TransferData::JustOutputs {
            outputs: converted(outputs.try_into())?,
        }
    };
    Ok(sapling::ShieldedData {
        value_balance: converted(i64::from(*bundle.value_balance()).try_into())?,
        transfers,
        binding_sig: <[u8; 64]>::from(bundle.authorization().binding_sig).into(),
    })
}
pub(super) fn digest(tx: &Transaction, previous: Arc<Vec<ChainOutput>>) -> Result<[u8; 32]> {
    Ok(converted(tx.sighasher(NetworkUpgrade::Nu7, previous))?
        .sighash(HashType::ALL, None)
        .0)
}
pub(super) fn checks(
    tx: &Transaction,
    previous: Arc<Vec<ChainOutput>>,
    prover: Option<&LocalTxProver>,
    vk: &VerifyingKey,
) -> Result<Value> {
    let hasher = converted(tx.sighasher(NetworkUpgrade::Nu7, previous))?;
    let digest = hasher.sighash(HashType::ALL, None).0;
    let mut result = serde_json::Map::new();
    if let Some(bundle) = hasher.sapling_bundle() {
        let (spend_vk, output_vk) = needed(prover)?.verifying_keys();
        let mut batch = sapling_crypto::BatchValidator::default();
        let structural = batch.check_bundle(bundle, digest);
        result.insert(
            "sapling".into(),
            json!(structural && batch.validate(&spend_vk, &output_vk, rand_10::rng())),
        );
    }
    for (pool, bundle) in [
        ("orchard", hasher.orchard_bundle()),
        ("ironwood", hasher.ironwood_bundle()),
    ] {
        if let Some(bundle) = bundle {
            let mut batch = BatchValidator::new(vk);
            let valid = batch.add_bundle(&bundle, digest).is_ok() && batch.validate(rand_10::rng());
            result.insert(pool.into(), json!(valid));
        }
    }
    Ok(Value::Object(result))
}
pub(super) fn wire(tx: &Transaction, previous: Arc<Vec<ChainOutput>>) -> Result<Value> {
    let bytes = converted(tx.zcash_serialize_to_vec())?;
    require(
        bytes.len() <= 262_144 && decode_transaction(&bytes)? == *tx,
        "shielded",
        "roundtrip",
    )?;
    let message = converted(TransactionContext::new(
        tx,
        NetworkDomain::Regtest,
        NetworkUpgrade::Nu7,
        previous,
    ))?
    .message(0)
    .map_err(|_| Failure {
        stage: "shielded",
        reason: "message",
    })?;
    Ok(
        json!({"transaction_hex": hex::encode(&bytes), "transaction_sha256": strict::hash(&bytes),
        "txid":tx.hash().to_string(), "auth_digest":needed(tx.auth_digest())?.to_string(),
        "message_hex":hex::encode(message), "outputs":output_fields(tx),
        "sapling_outputs":tx.sapling_outputs().count(), "orchard_actions":tx.orchard_actions().count(),
        "ironwood_actions":tx.ironwood_actions().count()}),
    )
}

fn action_builder(pool: &str) -> Result<Builder> {
    let (version, bundle_type) = if pool == "orchard" {
        (
            BundleVersion::orchard_v3(),
            BundleType::Transactional {
                bundle_required: true,
                pad_to_minimum: Some(2),
            },
        )
    } else {
        (BundleVersion::ironwood_v3(), BundleType::DEFAULT)
    };
    let flags = needed(Flags::from_byte(
        if pool == "orchard" { 2 } else { 6 },
        version,
    ))?;
    let mut builder = converted(Builder::new(
        bundle_type,
        version,
        flags,
        Anchor::empty_tree(),
    ))?;
    // Orchard v3 rejects even zero-valued ordinary outputs when cross-address
    // transfers are disabled. Its required bundle uses paired dummy padding only.
    if pool != "orchard" {
        let recipient =
            FullViewingKey::from(&SpendingKey::from_bytes([42; 32]).expect("fixed public key"))
                .address_at(0u32, Scope::External);
        converted(builder.add_output(None, recipient, NoteValue::from_raw(DEPOSIT), [0; 512]))?;
    }
    Ok(builder)
}

pub(super) fn prepare(recipe: &ShieldedRecipe) -> Result<Value> {
    let (mut tx, previous, _) = context(recipe)?; // All bounds/parents checked before proving.
    let sapling_prover = recipe.sapling_parameters.as_ref().map(prover).transpose()?;
    let mut rng = rand_10::rng();
    let pk = converted(ProvingKey::build(OrchardCircuitVersion::PostNu6_3))?;
    let vk = pk.verifying_key();
    let prove_action = |pool: &str, rng: &mut rand_10::rngs::ThreadRng| {
        let unsigned = needed(converted(
            action_builder(pool)?.build::<ZatBalance>(&mut *rng),
        )?)?
        .0;
        converted(unsigned.create_proof(&pk, rng))
    };
    let mut actions = Vec::new();
    for pool in recipe.pools.iter().filter(|p| p.as_str() != "sapling") {
        let proven = prove_action(pool, &mut rng)?;
        let wrong = converted(proven.clone().apply_signatures(&mut rng, [0; 32], &[]))?;
        *action_slot(&mut tx, pool) = Some(chain_action(&wrong)?);
        actions.push((pool, proven, wrong));
    }
    let sapling = if let Some(prover) = sapling_prover.as_ref() {
        let key = sapling_crypto::zip32::ExtendedSpendingKey::master(&[42; 32]);
        let mut builder = sapling_crypto::builder::Builder::new(
            sapling_crypto::note_encryption::Zip212Enforcement::On,
            sapling_crypto::builder::BundleType::DEFAULT,
            sapling_crypto::Anchor::empty_tree(),
        );
        converted(builder.add_output(
            None,
            key.default_address().1,
            sapling_crypto::value::NoteValue::from_raw(DEPOSIT),
            [0; 512],
        ))?;
        let unsigned = needed(converted(
            builder.build::<LocalTxProver, LocalTxProver, _, ZatBalance>(&[], &mut rng),
        )?)?
        .0;
        let proven = unsigned.create_proofs(prover, prover, &mut rng, ());
        let wrong = converted(proven.clone().apply_signatures(&mut rng, [0; 32], &[]))?;
        *sapling_slot(&mut tx) = Some(chain_sapling(&wrong)?);
        Some((proven, wrong))
    } else {
        None
    };
    let final_digest = digest(&tx, previous.clone())?;
    let mut replacements = Vec::new();
    for (pool, proven, wrong) in actions {
        let authorized = converted(proven.apply_signatures(&mut rng, final_digest, &[]))?;
        *action_slot(&mut tx, pool) = Some(chain_action(&authorized)?);
        let donor =
            converted(prove_action(pool, &mut rng)?.apply_signatures(&mut rng, final_digest, &[]))?;
        require(donor.verify_proof(&vk).is_ok(), "shielded", "donor_proof")?;
        replacements.push((pool.clone(), chain_action(&wrong)?, chain_action(&donor)?));
    }
    let wrong_sapling = if let Some((proven, wrong)) = sapling {
        *sapling_slot(&mut tx) = Some(chain_sapling(&converted(proven.apply_signatures(
            &mut rng,
            final_digest,
            &[],
        ))?)?);
        Some(chain_sapling(&wrong)?)
    } else {
        None
    };
    require(
        digest(&tx, previous.clone())? == final_digest,
        "shielded",
        "changed_effects",
    )?;
    let positive_checks = checks(&tx, previous.clone(), sapling_prover.as_ref(), &vk)?;
    require(
        positive_checks
            .as_object()
            .is_some_and(|rows| rows.values().all(|v| v == true)),
        "shielded",
        "positive_verification",
    )?;
    let positive = wire(&tx, previous.clone())?;
    let mut variants = Vec::new();
    for pool in &recipe.pools {
        for mutation in ["binding", "proof"] {
            let mut changed = tx.clone();
            if pool == "sapling" {
                let data = needed(sapling_slot(&mut changed).as_mut())?;
                if mutation == "binding" {
                    data.binding_sig = needed(wrong_sapling.as_ref())?.binding_sig;
                } else {
                    let TransferData::JustOutputs { outputs } = &mut data.transfers else {
                        unreachable!("output-only")
                    };
                    // The builder's padding supplies a second real randomized output proof.
                    let donor = outputs
                        .iter()
                        .nth(1)
                        .ok_or(Failure {
                            stage: "shielded",
                            reason: "sapling_padding",
                        })?
                        .zkproof;
                    needed(outputs.iter_mut().next())?.zkproof = donor;
                }
            } else {
                let (_, wrong, donor) = needed(replacements.iter().find(|row| &row.0 == pool))?;
                let data = needed(action_slot(&mut changed, pool).as_mut())?;
                if mutation == "binding" {
                    data.binding_sig = wrong.binding_sig;
                } else {
                    data.proof = donor.proof.clone();
                }
            }
            let verdicts = checks(&changed, previous.clone(), sapling_prover.as_ref(), &vk)?;
            require(
                recipe
                    .pools
                    .iter()
                    .all(|name| verdicts[name] == (name != pool)),
                "shielded",
                "mutation_verification",
            )?;
            let mut row = wire(&changed, previous.clone())?;
            require(
                row["txid"] == positive["txid"]
                    && row["message_hex"] == positive["message_hex"]
                    && row["auth_digest"] != positive["auth_digest"],
                "shielded",
                "mutation_identity",
            )?;
            row["pool"] = json!(pool);
            row["mutation"] = json!(mutation);
            row["pool_valid"] = verdicts;
            variants.push(row);
        }
    }
    Ok(
        json!({"material":"public-test-only", "version":recipe.transaction_version,
        "pools":recipe.pools, "parent_txid":tx.inputs()[0].outpoint().expect("known prevout").hash.to_string(),
        "parent_index":recipe.output_index, "parent_value_zat":u64::from(previous[0].value),
        "parent_script_hex":hex::encode(previous[0].lock_script.as_raw_bytes()),
        "parent_transaction_sha256":strict::hash(&bounded_hex(&recipe.parent_hex, MAX_TX)?),
        "fee_zat":FEE,"deposit_zat":deposit(&recipe.pools),"orchard_value_zat":0,
        "proof_profile":"output-only-post-nu6.3", "parameters":recipe.sapling_parameters,
        "positive":positive,"positive_pool_valid":positive_checks,"variants":variants}),
    )
}

pub(super) fn finalize(
    recipe: &ShieldedRecipe,
    raw: &str,
    entry: Option<&Record>,
) -> Result<Value> {
    let (base, previous, policy) = context(recipe)?;
    let mut tx = decode_transaction(&bounded_hex(raw, 262_144)?)?;
    require(
        tx.version() == base.version()
            && tx.network_upgrade() == Some(NetworkUpgrade::Nu7)
            && tx.lock_time() == base.lock_time()
            && tx.expiry_height() == base.expiry_height()
            && tx.inputs() == base.inputs()
            && tx.outputs() == base.outputs()
            && !tx.has_shielded_inputs(),
        "correspondence",
        "shielded_effects",
    )?;
    for pool in POOLS {
        let present = match pool {
            "sapling" => tx.has_sapling_shielded_data(),
            "orchard" => tx.has_orchard_shielded_data(),
            _ => tx.has_ironwood_shielded_data(),
        };
        require(
            present == recipe.pools.iter().any(|p| p == pool),
            "correspondence",
            "shielded_pools",
        )?;
    }
    require(
        tx.sapling_outputs().count() <= 2
            && tx.orchard_actions().count() <= 2
            && tx.ironwood_actions().count() <= 2,
        "correspondence",
        "shielded_counts",
    )?;
    if let Some(data) = sapling_slot(&mut tx).as_ref() {
        require(
            i64::from(data.value_balance) == -50_000,
            "correspondence",
            "sapling_balance",
        )?;
    }
    for (pool, expected) in [("orchard", 0), ("ironwood", -50_000)] {
        if let Some(data) = action_slot(&mut tx, pool).as_ref() {
            require(
                i64::from(data.value_balance) == expected
                    && !data
                        .flags
                        .contains(zakura_chain::orchard::Flags::ENABLE_SPENDS)
                    && data.shared_anchor == converted(Anchor::empty_tree().to_bytes().try_into())?,
                "correspondence",
                "action_context",
            )?;
        }
        if tx.version() == 5 {
            break;
        } // No Ironwood slot exists in v5.
    }
    authorize(
        &mut tx,
        previous.clone(),
        policy.as_ref(),
        &recipe.authorization,
        entry,
    )?;
    let mut result = wire(&tx, previous)?;
    result["slh_checks"] = json!(usize::from(recipe.authorization == "slh"));
    result["ecdsa_checks"] = json!(match recipe.authorization.as_str() {
        "slh" => 0,
        "multisig" => 2,
        _ => 1,
    });
    result["fee_zat"] = json!(FEE);
    result["deposit_zat"] = json!(deposit(&recipe.pools));
    Ok(result)
}

pub(super) fn authorize(
    tx: &mut Transaction,
    previous: Arc<Vec<ChainOutput>>,
    policy: Option<&Policy>,
    kind: &str,
    entry: Option<&Record>,
) -> Result<()> {
    if let Some(policy) = policy {
        let context = converted(InputSigningContext::new(
            tx,
            NetworkDomain::Regtest,
            NetworkUpgrade::Nu7,
            previous.clone(),
            0,
            policy,
        ))?;
        let authorization = converted(context.authorization(vec![record(needed(entry)?)?]))?;
        install(tx, 0, Script::new(&authorization.encode()));
        converted(
            TransactionContext::new(
                tx,
                NetworkDomain::Regtest,
                NetworkUpgrade::Nu7,
                previous.clone(),
            )
            .and_then(|context| context.verify_input(0)),
        )?;
    } else {
        require(entry.is_none(), "schema", "classical_record")?;
        let signature = classical::signature(tx, previous.clone(), kind, 0)?;
        install(tx, 0, signature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orchard_outputs_use_paired_dummy_padding_without_proving() {
        let mut rng = rand_10::rng();
        let version = BundleVersion::orchard_v3();
        let flags = Flags::from_byte(2, version).unwrap();
        let recipient = FullViewingKey::from(&SpendingKey::from_bytes([42; 32]).unwrap())
            .address_at(0u32, Scope::External);
        let mut ordinary =
            Builder::new(BundleType::DEFAULT, version, flags, Anchor::empty_tree()).unwrap();
        assert!(matches!(
            ordinary.add_output(None, recipient, NoteValue::ZERO, [0; 512]),
            Err(orchard::builder::OutputError::CrossAddressDisabled)
        ));

        let (bundle, metadata) = action_builder("orchard")
            .unwrap()
            .build_for_pczt(&mut rng)
            .unwrap();
        assert_eq!(bundle.flag_byte(), 2);
        assert_eq!(bundle.actions().len(), 2);
        assert_eq!(i64::try_from(*bundle.value_sum()).unwrap(), 0);
        assert_eq!(*bundle.anchor(), Anchor::empty_tree());
        assert!(bundle.zkproof().is_none());
        assert!(metadata.output_action_index(0).is_none());
        bundle.verify_cross_address_restriction().unwrap();
        for action in bundle.actions() {
            assert!(action.spend().dummy_sk().is_some());
            assert_eq!(action.spend().value(), &Some(NoteValue::ZERO));
            assert_eq!(action.output().value(), &Some(NoteValue::ZERO));
            assert_eq!(action.spend().recipient(), action.output().recipient());
        }

        for (pool, flag_byte, balance) in [("orchard", 2, 0), ("ironwood", 6, -50_000)] {
            let (unsigned, _) = action_builder(pool)
                .unwrap()
                .build::<ZatBalance>(&mut rng)
                .unwrap()
                .unwrap();
            assert_eq!(unsigned.actions().len(), 2);
            assert_eq!(unsigned.flag_byte(), flag_byte);
            assert_eq!(i64::from(*unsigned.value_balance()), balance);
            assert_eq!(*unsigned.anchor(), Anchor::empty_tree());
        }
    }

    fn recipe(version: u8, pools: &[&str]) -> ShieldedRecipe {
        ShieldedRecipe {
            human_run: true,
            transaction_version: version,
            pools: pools.iter().map(|p| p.to_string()).collect(),
            parent_hex: String::new(),
            output_index: 0,
            expiry_height: 210,
            authorization: "single".into(),
            public_key_hex: None,
            sapling_parameters: pools.contains(&"sapling").then(|| SaplingParameters {
                spend_path: "/public/spend.params".into(),
                spend_sha256: "11".repeat(32),
                output_path: "/public/output.params".into(),
                output_sha256: "22".repeat(32),
            }),
        }
    }
    #[test]
    fn supported_combinations_are_bounded_before_any_proving() {
        for version in [5, 6] {
            for mask in 1..(if version == 5 { 4 } else { 8 }) {
                let pools = POOLS
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, p)| *p)
                    .collect::<Vec<_>>();
                let request = recipe(version, &pools);
                validate_shape(&request).unwrap();
                // Sapling and Ironwood each receive 50,000 zatoshis; Orchard receives zero.
                assert_eq!(
                    deposit(&request.pools),
                    [0, 50_000, 0, 50_000, 50_000, 100_000, 50_000, 100_000][mask]
                );
                // Empty parent fails before parameter reads/key construction/proofs.
                assert_eq!(
                    prepare(&request).unwrap_err().reason,
                    "transaction_encoding"
                );
            }
        }
        for (pools, reason) in [
            (vec!["ironwood"], "shielded_pools"),
            (vec!["sapling", "sapling"], "shielded_pools"),
            (vec!["orchard", "sapling"], "shielded_pools"),
            (vec!["bogus"], "shielded_pools"),
            (vec![], "shielded_shape"),
        ] {
            assert_eq!(
                validate_shape(&recipe(5, &pools)).unwrap_err().reason,
                reason
            );
        }
    }
    #[test]
    fn human_gate_identity_and_parameter_schema_fail_closed() {
        let mut request = recipe(6, &["sapling"]);
        request.human_run = false;
        assert_eq!(prepare(&request).unwrap_err().reason, "human_run_required");
        request.human_run = true;
        request.public_key_hex = Some("00".repeat(32));
        let reason = |request: &ShieldedRecipe| validate_shape(request).unwrap_err().reason;
        assert_eq!(reason(&request), "shielded_authorization");
        request.public_key_hex = None;
        request.sapling_parameters.as_mut().unwrap().spend_path = "relative.params".into();
        assert_eq!(reason(&request), "parameter_path");
        request.sapling_parameters = None;
        assert_eq!(reason(&request), "sapling_parameters");
        let mut value = encode(
            json!({"human_run":true,"transaction_version":6,"pools":["orchard"],
            "parent_hex":"", "output_index":0, "expiry_height":210,"authorization":"single",
            "public_key_hex":null,"sapling_parameters":null}),
        );
        assert!(serde_json::from_value::<ShieldedRecipe>(value.clone()).is_ok());
        value["unknown"] = json!(1);
        assert!(serde_json::from_value::<ShieldedRecipe>(value).is_err());
    }
    #[test]
    fn exact_raw_parent_amount_and_script_bind_before_proving() {
        for version in [5, 6] {
            let mut request = recipe(version, &["orchard"]);
            let (lock, _, _) = classical::scripts("single").unwrap();
            let (parent, _) = TransactionRecipe {
                version,
                network_upgrade: NetworkUpgrade::Nu7,
                lock_time: LockTime::unlocked(),
                expiry_height: Height(210),
                spends: vec![Spend {
                    outpoint: outpoint(&"11".repeat(32), 0).unwrap(),
                    sequence: u32::MAX,
                    previous_output: chain_output(3_000_000, lock.as_raw_bytes().to_vec()).unwrap(),
                }],
                outputs: vec![chain_output(2_000_000, lock.as_raw_bytes().to_vec()).unwrap()],
            }
            .build();
            request.parent_hex = hex::encode(parent.zcash_serialize_to_vec().unwrap());
            let (tx, previous, _) = context(&request).unwrap();
            assert_eq!(tx.inputs()[0].outpoint().unwrap().hash, parent.hash());
            assert_eq!(u64::from(previous[0].value), 2_000_000);
            assert_eq!(u64::from(tx.outputs()[0].value), 1_900_000);
            // The unsigned base lacks the requested Orchard bundle.
            assert_eq!(
                finalize(
                    &request,
                    &hex::encode(tx.zcash_serialize_to_vec().unwrap()),
                    None
                )
                .unwrap_err()
                .reason,
                "shielded_pools"
            );
            let reason = |request: &ShieldedRecipe| context(request).err().unwrap().reason;
            request.output_index = 1;
            assert_eq!(reason(&request), "missing_bundle");
            request.output_index = 0;
            request.authorization = "multisig".into();
            assert_eq!(reason(&request), "shielded_parent_script");
        }
    }
    #[test]
    fn parameter_integrity_is_checked_without_parsing_or_proving() {
        let path = std::env::temp_dir().join(format!("slh-public-params-{}", std::process::id()));
        std::fs::write(&path, b"public bad parameters").unwrap();
        let checked = parameter_bytes(path.to_str().unwrap(), &"00".repeat(32));
        std::fs::remove_file(path).unwrap();
        assert_eq!(checked.unwrap_err().reason, "parameter_hash");
    }
}
