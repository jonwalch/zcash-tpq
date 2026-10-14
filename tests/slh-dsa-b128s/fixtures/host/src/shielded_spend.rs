//! Genuine public-note spends with final native SLH effects. See SPEND_ATTRIBUTION.md.
use super::shielded::{
    action_slot, authorize, chain_action, chain_legacy_action, chain_sapling, checks, converted,
    digest, needed, prover, sapling_slot, wire,
};
use super::*;
use orchard::{
    builder::{Builder, BundleType},
    bundle::{BundleVersion, Flags},
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
};
use zakura_chain::{sapling::TransferData, transaction::HashType};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::value::ZatBalance;
mod history;
const NOTE_VALUE: u64 = 50_000;
const FEE: u64 = 100_000;
fn action_key() -> SpendingKey {
    SpendingKey::from_bytes([42; 32]).expect("fixed public key")
}
fn sapling_key() -> sapling_crypto::zip32::ExtendedSpendingKey {
    sapling_crypto::zip32::ExtendedSpendingKey::master(&[42; 32])
}
fn output_recipe(recipe: &ShieldedSpendRecipe) -> ShieldedRecipe {
    ShieldedRecipe {
        human_run: recipe.human_run,
        transaction_version: recipe.transaction_version,
        pools: recipe.pools.clone(),
        parent_hex: recipe.parent_hex.clone(),
        output_index: recipe.output_index,
        expiry_height: recipe.expiry_height,
        authorization: recipe.authorization.clone(),
        public_key_hex: recipe.public_key_hex.clone(),
        sapling_parameters: recipe.sapling_parameters.clone(),
    }
}
struct Context {
    tx: Transaction,
    previous: Arc<Vec<ChainOutput>>,
    policy: Option<Policy>,
    history: history::History,
    notes: Vec<history::Funding>,
}
fn context(recipe: &ShieldedSpendRecipe) -> Result<Context> {
    let output = output_recipe(recipe);
    shielded::validate_shape(&output)?;
    let history = history::parse(&recipe.history)?;
    require(
        recipe.expiry_height > history.tip_height,
        "history",
        "expired_spend",
    )?;
    let actual = history.parent(&recipe.parent_hex, recipe.output_index)?;
    let (mut tx, previous, policy) = shielded::context(&output)?;
    require(previous[0] == actual, "history", "parent_correspondence")?;
    let notes = history::recover(&history, recipe)?;
    let value = u64::from(actual.value)
        .checked_add(NOTE_VALUE * u64::try_from(notes.len()).expect("three pools"))
        .and_then(|v| v.checked_sub(FEE))
        .ok_or(Failure {
            stage: "history",
            reason: "spend_value",
        })?;
    let change = chain_output(value, actual.lock_script.as_raw_bytes().to_vec())?;
    match &mut tx {
        Transaction::V5 { outputs, .. } | Transaction::V6 { outputs, .. } => outputs[0] = change,
        _ => unreachable!("version checked"),
    }
    Ok(Context {
        tx,
        previous,
        policy,
        history,
        notes,
    })
}

/// Copy one field only; used both for mutations and full-transaction repair checks.
fn replace(
    tx: &mut Transaction,
    donor: &mut Transaction,
    pool: &str,
    mutation: &str,
    index: usize,
) -> Result<()> {
    if pool == "sapling" {
        let target = needed(sapling_slot(tx).as_mut())?;
        let source = needed(sapling_slot(donor).as_mut())?;
        if mutation == "binding" {
            target.binding_sig = source.binding_sig;
        } else {
            let TransferData::SpendsAndMaybeOutputs { spends: target, .. } = &mut target.transfers
            else {
                return fail("shielded", "spend_missing");
            };
            let TransferData::SpendsAndMaybeOutputs { spends: source, .. } = &mut source.transfers
            else {
                return fail("shielded", "spend_missing");
            };
            let target = needed(target.iter_mut().nth(index))?;
            let source = needed(source.iter().nth(index))?;
            match mutation {
                "spend_auth" => target.spend_auth_sig = source.spend_auth_sig,
                "proof" => target.zkproof = source.zkproof,
                _ => return fail("schema", "mutation"),
            }
        }
    } else {
        let target = needed(action_slot(tx, pool).as_mut())?;
        let source = needed(action_slot(donor, pool).as_mut())?;
        match mutation {
            "binding" => target.binding_sig = source.binding_sig,
            "proof" => target.proof = source.proof.clone(),
            "spend_auth" => {
                needed(target.actions.iter_mut().nth(index))?.spend_auth_sig =
                    needed(source.actions.iter().nth(index))?.spend_auth_sig
            }
            _ => return fail("schema", "mutation"),
        }
    }
    Ok(())
}
fn components(
    tx: &Transaction,
    previous: Arc<Vec<ChainOutput>>,
    vk: &VerifyingKey,
) -> Result<Value> {
    let hasher = converted(tx.sighasher(NetworkUpgrade::Nu7, previous))?;
    let sighash = hasher.sighash(HashType::ALL, None).0;
    let mut result = serde_json::Map::new();
    if let Some(bundle) = hasher.sapling_bundle() {
        let spends = bundle
            .shielded_spends()
            .iter()
            .map(|s| s.rk().verify(&sighash, s.spend_auth_sig()).is_ok())
            .collect::<Vec<_>>();
        let cv = bundle
            .shielded_spends()
            .iter()
            .map(|s| s.cv())
            .sum::<sapling_crypto::value::CommitmentSum>()
            - bundle
                .shielded_outputs()
                .iter()
                .map(|o| o.cv())
                .sum::<sapling_crypto::value::CommitmentSum>();
        let binding = cv
            .into_bvk(*bundle.value_balance())
            .verify(&sighash, &bundle.authorization().binding_sig)
            .is_ok();
        result.insert(
            "sapling".into(),
            json!({"spend_auth":spends,"binding":binding,"proof":null}),
        );
    }
    for (pool, bundle) in [
        ("orchard", hasher.orchard_bundle()),
        ("ironwood", hasher.ironwood_bundle()),
    ] {
        if let Some(bundle) = bundle {
            let spends = bundle
                .actions()
                .iter()
                .map(|a| a.rk().verify(&sighash, a.authorization()).is_ok())
                .collect::<Vec<_>>();
            let binding = bundle
                .binding_validating_key()
                .verify(&sighash, bundle.authorization().binding_signature())
                .is_ok();
            result.insert(pool.into(),json!({"spend_auth":spends,"binding":binding,"proof":bundle.verify_proof(vk).is_ok()}));
        }
    }
    Ok(Value::Object(result))
}

pub(super) fn prepare(recipe: &ShieldedSpendRecipe) -> Result<Value> {
    // Every history, root, ownership and transparent-parent check precedes proving.
    let Context {
        mut tx,
        previous,
        history,
        mut notes,
        ..
    } = context(recipe)?;
    let sapling_prover = recipe.sapling_parameters.as_ref().map(prover).transpose()?;
    let mut rng = rand_10::rng();
    let pk = converted(ProvingKey::build(OrchardCircuitVersion::PostNu6_3))?;
    let vk = pk.verifying_key();
    let key = action_key();
    let ask = SpendAuthorizingKey::from(&key);
    let prove_action =
        |pool: &str, note: &history::ActionNote, rng: &mut rand_10::rngs::ThreadRng| {
            let version = if pool == "orchard" {
                BundleVersion::orchard_v3()
            } else {
                BundleVersion::ironwood_v3()
            };
            let flags = needed(Flags::from_byte(
                if pool == "orchard" { 1 } else { 5 },
                version,
            ))?;
            let mut builder = converted(Builder::new(
                BundleType::DEFAULT,
                version,
                flags,
                note.anchor,
            ))?;
            converted(builder.add_spend(FullViewingKey::from(&key), note.note, note.path.clone()))?;
            let (unsigned, metadata) = needed(converted(builder.build::<ZatBalance>(&mut *rng))?)?;
            let real = needed(metadata.spend_action_index(0))?;
            require(
                metadata.spend_action_index(1).is_none()
                    && i64::from(*unsigned.value_balance()) == 50_000
                    && unsigned.actions()[real].nullifier()
                        == &note.note.nullifier(&FullViewingKey::from(&key)),
                "shielded",
                "real_action",
            )?;
            Ok((converted(unsigned.create_proof(&pk, rng))?, real))
        };
    let sk = sapling_key();
    let prove_sapling = |note: &history::SaplingNote, rng: &mut rand_10::rngs::ThreadRng| {
        let prover = needed(sapling_prover.as_ref())?;
        let mut builder = sapling_crypto::builder::Builder::new(
            sapling_crypto::note_encryption::Zip212Enforcement::On,
            sapling_crypto::builder::BundleType::DEFAULT,
            note.anchor,
        );
        converted(builder.add_spend(
            sk.to_diversifiable_full_viewing_key().fvk().clone(),
            note.note.clone(),
            note.path.clone(),
        ))?;
        let (unsigned, metadata) = needed(converted(
            builder.build::<LocalTxProver, LocalTxProver, _, ZatBalance>(
                std::slice::from_ref(&sk),
                &mut *rng,
            ),
        )?)?;
        let real = needed(metadata.spend_index(0))?;
        require(
            real == 0
                && metadata.spend_index(1).is_none()
                && i64::from(*unsigned.value_balance()) == 50_000,
            "shielded",
            "real_sapling_spend",
        )?;
        Ok((unsigned.create_proofs(prover, prover, rng, ()), real))
    };
    let mut actions = Vec::new();
    let mut sapling = None;
    for funding in &mut notes {
        match &funding.note {
            history::Note::Action(note) => {
                let (proven, real) = prove_action(&funding.pool, note, &mut rng)?;
                let wrong = converted(proven.clone().apply_signatures(
                    &mut rng,
                    [0; 32],
                    std::slice::from_ref(&ask),
                ))?;
                *action_slot(&mut tx, &funding.pool) = Some(chain_action(&wrong)?);
                funding.metadata["real_spend_index"] = json!(real);
                actions.push((funding.pool.clone(), proven, wrong, real));
            }
            history::Note::Sapling(note) => {
                let (proven, real) = prove_sapling(note, &mut rng)?;
                let wrong = converted(proven.clone().apply_signatures(
                    &mut rng,
                    [0; 32],
                    std::slice::from_ref(&sk.expsk.ask),
                ))?;
                *sapling_slot(&mut tx) = Some(chain_sapling(&wrong)?);
                funding.metadata["real_spend_index"] = json!(real);
                sapling = Some((proven, wrong));
            }
        }
    }
    let final_digest = digest(&tx, previous.clone())?;
    require(
        final_digest != [0; 32],
        "shielded",
        "wrong_digest_collision",
    )?;
    let mut replacements = Vec::new();
    for (pool, proven, wrong, real) in actions {
        let authorized =
            converted(proven.apply_signatures(&mut rng, final_digest, std::slice::from_ref(&ask)))?;
        *action_slot(&mut tx, &pool) = Some(chain_action(&authorized)?);
        let mut wrong_tx = tx.clone();
        *action_slot(&mut wrong_tx, &pool) = Some(chain_action(&wrong)?);
        let funding = needed(notes.iter().find(|n| n.pool == pool))?;
        let history::Note::Action(note) = &funding.note else {
            unreachable!("pool type checked")
        };
        let (donor, _) = prove_action(&pool, note, &mut rng)?;
        let donor =
            converted(donor.apply_signatures(&mut rng, final_digest, std::slice::from_ref(&ask)))?;
        require(donor.verify_proof(&vk).is_ok(), "shielded", "donor_proof")?;
        let mut donor_tx = tx.clone();
        *action_slot(&mut donor_tx, &pool) = Some(chain_action(&donor)?);
        require(
            donor_tx.hash() != tx.hash(),
            "shielded",
            "donor_public_inputs",
        )?;
        replacements.push((pool, wrong_tx, donor_tx, real));
    }
    if let Some((proven, wrong)) = sapling {
        let authorized = converted(proven.apply_signatures(
            &mut rng,
            final_digest,
            std::slice::from_ref(&sk.expsk.ask),
        ))?;
        *sapling_slot(&mut tx) = Some(chain_sapling(&authorized)?);
        let mut wrong_tx = tx.clone();
        *sapling_slot(&mut wrong_tx) = Some(chain_sapling(&wrong)?);
        let funding = needed(notes.iter().find(|n| n.pool == "sapling"))?;
        let history::Note::Sapling(note) = &funding.note else {
            unreachable!("pool checked")
        };
        let (donor, _) = prove_sapling(note, &mut rng)?;
        let mut donor_tx = tx.clone();
        *sapling_slot(&mut donor_tx) = Some(chain_sapling(&converted(donor.apply_signatures(
            &mut rng,
            final_digest,
            std::slice::from_ref(&sk.expsk.ask),
        ))?)?);
        // Verify the genuine donor's proof and signatures at the explicitly used
        // message. This is a donor-bundle check, not a donor-transaction acceptance.
        let hasher = converted(donor_tx.sighasher(NetworkUpgrade::Nu7, previous.clone()))?;
        let (spend_vk, output_vk) = needed(sapling_prover.as_ref())?.verifying_keys();
        let mut batch = sapling_crypto::BatchValidator::default();
        require(
            batch.check_bundle(needed(hasher.sapling_bundle())?, final_digest)
                && batch.validate(&spend_vk, &output_vk, rand_10::rng()),
            "shielded",
            "sapling_donor_proof",
        )?;
        require(
            donor_tx.hash() != tx.hash(),
            "shielded",
            "donor_public_inputs",
        )?;
        replacements.push(("sapling".into(), wrong_tx, donor_tx, 0));
    }
    require(
        digest(&tx, previous.clone())? == final_digest,
        "shielded",
        "changed_effects",
    )?;
    let positive_checks = checks(&tx, previous.clone(), sapling_prover.as_ref(), &vk)?;
    require(
        recipe.pools.iter().all(|p| positive_checks[p] == true),
        "shielded",
        "positive_verification",
    )?;
    let positive = wire(&tx, previous.clone())?;
    let positive_components = components(&tx, previous.clone(), &vk)?;
    let mut variants = Vec::new();
    for pool in &recipe.pools {
        let (_, wrong, donor, real) = needed(replacements.iter().find(|r| &r.0 == pool))?;
        for mutation in ["spend_auth", "binding", "proof"] {
            let mut changed = tx.clone();
            replace(
                &mut changed,
                &mut if mutation == "proof" {
                    donor.clone()
                } else {
                    wrong.clone()
                },
                pool,
                mutation,
                *real,
            )?;
            let mut repaired = changed.clone();
            replace(&mut repaired, &mut tx.clone(), pool, mutation, *real)?;
            require(
                repaired == tx && changed != tx,
                "shielded",
                "mutation_isolation",
            )?;
            let verdicts = checks(&changed, previous.clone(), sapling_prover.as_ref(), &vk)?;
            require(
                recipe.pools.iter().all(|p| verdicts[p] == (p != pool)),
                "shielded",
                "mutation_verification",
            )?;
            let component = components(&changed, previous.clone(), &vk)?;
            for p in &recipe.pools {
                let mut expected = positive_components[p].clone();
                if p == pool {
                    match mutation {
                        "spend_auth" => expected["spend_auth"][*real] = json!(false),
                        "binding" => expected["binding"] = json!(false),
                        "proof" if p != "sapling" => expected["proof"] = json!(false),
                        _ => {}
                    }
                }
                require(component[p] == expected, "shielded", "component_isolation")?;
            }
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
            row["components"] = component;
            variants.push(row);
        }
    }
    Ok(
        json!({"material":"public-test-only","version":recipe.transaction_version,"pools":recipe.pools,
        "parent_txid":tx.inputs()[0].outpoint().expect("known prevout").hash.to_string(),"parent_index":recipe.output_index,
        "parent_value_zat":u64::from(previous[0].value),"parent_script_hex":hex::encode(previous[0].lock_script.as_raw_bytes()),
        "parent_transaction_sha256":strict::hash(&bounded_hex(&recipe.parent_hex,MAX_TX)?),"fee_zat":FEE,"deposit_zat":0,
        "withdrawal_zat":NOTE_VALUE*u64::try_from(notes.len()).expect("three pools"),"orchard_value_zat":if recipe.pools.iter().any(|p| p=="orchard") {NOTE_VALUE} else {0},
        "proof_profile":"real-spend-post-nu6.3","parameters":recipe.sapling_parameters,
        "history_sha256":history.sha256,"anchor_height":history.tip_height,"anchor_block_hash":history.tip_hash,
        "notes":notes.iter().map(|n| &n.metadata).collect::<Vec<_>>(),"positive":positive,"positive_pool_valid":positive_checks,
        "positive_components":positive_components,"variants":variants}),
    )
}

pub(super) fn finalize(
    recipe: &ShieldedSpendRecipe,
    raw: &str,
    entry: Option<&Record>,
) -> Result<Value> {
    let Context {
        tx: base,
        previous,
        policy,
        notes,
        ..
    } = context(recipe)?;
    let mut tx = decode_transaction(&bounded_hex(raw, 262_144)?)?;
    require(
        tx.version() == base.version()
            && tx.network_upgrade() == base.network_upgrade()
            && tx.lock_time() == base.lock_time()
            && tx.expiry_height() == base.expiry_height()
            && tx.inputs() == base.inputs()
            && tx.outputs() == base.outputs(),
        "correspondence",
        "spend_effects",
    )?;
    for pool in ["sapling", "orchard", "ironwood"] {
        let present = match pool {
            "sapling" => tx.has_sapling_shielded_data(),
            "orchard" => tx.has_orchard_shielded_data(),
            _ => tx.has_ironwood_shielded_data(),
        };
        require(
            present == recipe.pools.iter().any(|p| p == pool),
            "correspondence",
            "spend_pools",
        )?;
    }
    for funding in &notes {
        let nf = fixed_hex::<32>(needed(funding.metadata["nullifier"].as_str())?)?;
        let anchor = fixed_hex::<32>(needed(funding.metadata["anchor"].as_str())?)?;
        if funding.pool == "sapling" {
            let data = needed(sapling_slot(&mut tx).as_ref())?;
            let TransferData::SpendsAndMaybeOutputs {
                shared_anchor,
                spends,
                maybe_outputs,
            } = &data.transfers
            else {
                return fail("correspondence", "sapling_spend");
            };
            require(
                i64::from(data.value_balance) == 50_000
                    && shared_anchor.bytes_in_display_order() == anchor
                    && spends.len() == 1
                    && maybe_outputs.len() == 2
                    && <[u8; 32]>::from(spends.iter().next().expect("one spend checked").nullifier)
                        == nf,
                "correspondence",
                "sapling_spend",
            )?;
        } else {
            let data = needed(action_slot(&mut tx, &funding.pool).as_ref())?;
            let expected_flags = if funding.pool == "orchard" { 1 } else { 5 };
            require(
                i64::from(data.value_balance) == 50_000
                    && <[u8; 32]>::from(data.shared_anchor) == anchor
                    && data.flags.bits() == expected_flags
                    && data.actions.len() == 2
                    && data
                        .actions
                        .iter()
                        .filter(|a| <[u8; 32]>::from(a.action.nullifier) == nf)
                        .count()
                        == 1,
                "correspondence",
                "action_spend",
            )?;
        }
    }
    authorize(
        &mut tx,
        previous.clone(),
        policy.as_ref(),
        &recipe.authorization,
        entry,
    )?;
    let mut row = wire(&tx, previous)?;
    row["slh_checks"] = json!(usize::from(recipe.authorization == "slh"));
    row["ecdsa_checks"] = json!(match recipe.authorization.as_str() {
        "slh" => 0,
        "multisig" => 2,
        _ => 1,
    });
    row["fee_zat"] = json!(FEE);
    row["deposit_zat"] = json!(0);
    row["withdrawal_zat"] = json!(NOTE_VALUE * u64::try_from(notes.len()).expect("three pools"));
    Ok(row)
}

fn funding_context(
    recipe: &ShieldedSpendFundingRecipe,
) -> Result<(Transaction, Arc<Vec<ChainOutput>>)> {
    require(recipe.human_run, "schema", "human_run_required")?;
    require(
        recipe.expiry_height == 103 && matches!(recipe.kind.as_str(), "single" | "multisig"),
        "schema",
        "orchard_funding_profile",
    )?;
    let parent = decode_transaction(&bounded_hex(&recipe.parent_hex, MAX_TX)?)?;
    let previous = needed(
        parent
            .outputs()
            .get(usize::try_from(recipe.output_index).expect("u32 fits usize")),
    )?
    .clone();
    let (lock, _, _) = classical::scripts(&recipe.kind)?;
    require(
        previous.lock_script == lock,
        "schema",
        "orchard_funding_parent",
    )?;
    let change = u64::from(previous.value)
        .checked_sub(FEE + NOTE_VALUE)
        .ok_or(Failure {
            stage: "schema",
            reason: "orchard_funding_value",
        })?;
    require(change >= 2403, "schema", "orchard_funding_value")?;
    Ok(TransactionRecipe {
        version: 5,
        network_upgrade: NetworkUpgrade::Nu6_2,
        lock_time: LockTime::unlocked(),
        expiry_height: Height(103),
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
    .build())
}
/// Use the previous pinned builder for the historical funding circuit only.
fn legacy_funding_builder() -> Result<orchard_legacy::builder::Builder> {
    use orchard_legacy::{
        builder::{Builder, BundleType},
        bundle::{BundleVersion, Flags},
        keys::{FullViewingKey, Scope, SpendingKey},
        value::NoteValue,
    };
    let mut builder = converted(Builder::new(
        BundleType::DEFAULT,
        BundleVersion::orchard_v2(),
        Flags::SPENDS_DISABLED,
        orchard_legacy::Anchor::empty_tree(),
    ))?;
    converted(
        builder.add_output(
            None,
            FullViewingKey::from(&SpendingKey::from_bytes([42; 32]).expect("fixed public key"))
                .address_at(0u32, Scope::External),
            NoteValue::from_raw(NOTE_VALUE),
            [0; 512],
        ),
    )?;
    Ok(builder)
}

/// The only nonzero Orchard deposit profile; mined at 102, before NU6.3 at 104.
pub(super) fn funding(recipe: &ShieldedSpendFundingRecipe) -> Result<Value> {
    let (mut tx, previous) = funding_context(recipe)?;
    let mut rng = rand_10::rng();
    let pk = orchard_legacy::circuit::ProvingKey::build(
        orchard_legacy::circuit::OrchardCircuitVersion::FixedPostNu6_2,
    );
    let builder = legacy_funding_builder()?;
    let unsigned = needed(converted(builder.build::<ZatBalance>(&mut rng))?)?.0;
    let proven = converted(unsigned.create_proof(&pk, &mut rng))?;
    let wrong = converted(proven.clone().apply_signatures(&mut rng, [0; 32], &[]))?;
    *action_slot(&mut tx, "orchard") = Some(chain_legacy_action(&wrong)?);
    let final_digest = converted(tx.sighasher(NetworkUpgrade::Nu6_2, previous.clone()))?
        .sighash(HashType::ALL, None)
        .0;
    let authorized = converted(proven.apply_signatures(&mut rng, final_digest, &[]))?;
    let vk = pk.verifying_key();
    let mut batch = orchard_legacy::bundle::BatchValidator::new(&vk);
    require(
        batch.add_bundle(&authorized, final_digest).is_ok() && batch.validate(rand_10::rng()),
        "shielded",
        "orchard_funding_proof",
    )?;
    *action_slot(&mut tx, "orchard") = Some(chain_legacy_action(&authorized)?);
    let signature = classical::signature_at(
        &tx,
        previous.clone(),
        &recipe.kind,
        0,
        NetworkUpgrade::Nu6_2,
    )?;
    install(&mut tx, 0, signature);
    let bytes = converted(tx.zcash_serialize_to_vec())?;
    require(
        decode_transaction(&bytes)? == tx,
        "shielded",
        "funding_roundtrip",
    )?;
    Ok(
        json!({"transaction_hex":hex::encode(&bytes),"transaction_sha256":strict::hash(&bytes),"txid":tx.hash().to_string(),
        "auth_digest":needed(tx.auth_digest())?.to_string(),"outputs":output_fields(&tx),"sapling_outputs":0,"orchard_actions":2,"ironwood_actions":0,
        "material":"public-test-only","version":5,"parent_txid":tx.inputs()[0].outpoint().expect("known prevout").hash.to_string(),
        "parent_index":recipe.output_index,"parent_value_zat":u64::from(previous[0].value),"parent_script_hex":hex::encode(previous[0].lock_script.as_raw_bytes()),
        "parent_transaction_sha256":strict::hash(&bounded_hex(&recipe.parent_hex,MAX_TX)?),"fee_zat":FEE,"deposit_zat":NOTE_VALUE,"orchard_value_zat":NOTE_VALUE,
        "proof_profile":"orchard-pre-nu6.3","pool_valid":{"orchard":true},"ecdsa_checks":if recipe.kind == "multisig" {2} else {1},"slh_checks":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn funding_gate_and_branch_checks_precede_any_proof() {
        let mut recipe = ShieldedSpendFundingRecipe {
            human_run: false,
            parent_hex: String::new(),
            output_index: 0,
            expiry_height: 103,
            kind: "single".into(),
        };
        assert_eq!(funding(&recipe).unwrap_err().reason, "human_run_required");
        recipe.human_run = true;
        recipe.expiry_height = 104;
        assert_eq!(
            funding(&recipe).unwrap_err().reason,
            "orchard_funding_profile"
        );
        recipe.expiry_height = 103;
        assert!(funding(&recipe).is_err());
        let (lock, _, _) = classical::scripts("single").unwrap();
        let (mut tx, previous) = TransactionRecipe {
            version: 5,
            network_upgrade: NetworkUpgrade::Nu6_2,
            lock_time: LockTime::unlocked(),
            expiry_height: Height(103),
            spends: vec![Spend {
                outpoint: outpoint(&"11".repeat(32), 0).unwrap(),
                sequence: u32::MAX,
                previous_output: chain_output(300_000, lock.as_raw_bytes().to_vec()).unwrap(),
            }],
            outputs: vec![chain_output(200_000, lock.as_raw_bytes().to_vec()).unwrap()],
        }
        .build();
        assert!(
            classical::signature_at(&tx, previous.clone(), "single", 0, NetworkUpgrade::Nu6_2)
                .is_ok()
        );
        assert_eq!(
            classical::signature_at(&tx, previous.clone(), "single", 0, NetworkUpgrade::Nu7)
                .unwrap_err()
                .reason,
            "classical_deposit_branch"
        );
        if let Transaction::V5 {
            network_upgrade, ..
        } = &mut tx
        {
            *network_upgrade = NetworkUpgrade::Nu7;
        }
        assert_eq!(
            classical::signature_at(&tx, previous, "single", 0, NetworkUpgrade::Nu6_2)
                .unwrap_err()
                .reason,
            "classical_deposit_branch"
        );
    }
    #[test]
    fn strict_spend_request_rejects_unknown_fields_and_empty_history_before_proof() {
        let mut value = json!({"human_run":true,"transaction_version":6,"pools":["ironwood"],"parent_hex":"","output_index":0,"expiry_height":210,
            "authorization":"single","public_key_hex":null,"sapling_parameters":null,"history":{"blocks":[],"treestate":{}},"funding_txids":[{"pool":"ironwood","txid":"00".repeat(32)}]});
        let recipe: ShieldedSpendRecipe = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(prepare(&recipe).unwrap_err().reason, "height_bound");
        value["history"]["trusted_amount"] = json!(3000000);
        assert!(serde_json::from_value::<ShieldedSpendRecipe>(value).is_err());
    }
}
