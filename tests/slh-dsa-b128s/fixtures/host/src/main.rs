//! Public transaction fixtures only: no secret material or signing operations.
#![forbid(unsafe_code)]

mod model;
mod strict;

use model::*;
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    io::{self, Cursor, Read, Write},
    sync::Arc,
};
use zakura_chain::{
    block::Height,
    parameters::NetworkUpgrade,
    serialization::{ZcashDeserialize, ZcashSerialize},
    transaction::{Hash, LockTime, Transaction},
    transparent::{Input as ChainInput, OutPoint, Output as ChainOutput, Script},
};
use zakura_pq_slh_dsa_b_exp::{
    codec::key_commitment, contract::CONTRACT, input_authorization, Authorization,
    InputSigningContext, Policy, Record as NativeRecord, Rejection, TransactionContext,
};
use zakura_pq_test_support::{install, Spend, TransactionRecipe};
use zakura_pq_tx_context::NetworkDomain;

const MAX_MONEY: u64 = 2_100_000_000_000_000;
const NU7: u32 = 0x77190ad9;
const MAX_TX: usize = 2_000_000;
type Result<T> = std::result::Result<T, Failure>;
#[derive(Debug)]
struct Failure {
    stage: &'static str,
    reason: &'static str,
}
fn fail<T>(stage: &'static str, reason: &'static str) -> Result<T> {
    Err(Failure { stage, reason })
}
fn require(ok: bool, stage: &'static str, reason: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        fail(stage, reason)
    }
}
fn encode<T: serde::Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("public schema serializes")
}
fn envelope(version: u64, contract: &str, public: bool) -> Result<()> {
    require(
        version == 1 && contract == CONTRACT && public,
        "schema",
        "envelope",
    )
}
fn bounded_hex(s: &str, max: usize) -> Result<Vec<u8>> {
    require(
        s.len() <= max * 2
            && s.len().is_multiple_of(2)
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "schema",
        "hex",
    )?;
    hex::decode(s).map_err(|_| Failure {
        stage: "schema",
        reason: "hex",
    })
}
fn fixed_hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    bounded_hex(s, N)?.try_into().map_err(|_| Failure {
        stage: "schema",
        reason: "hex_length",
    })
}
fn network(name: &str) -> Result<NetworkDomain> {
    match name {
        "Mainnet" => Ok(NetworkDomain::Mainnet),
        "Testnet" => Ok(NetworkDomain::Testnet),
        "Regtest" => Ok(NetworkDomain::Regtest),
        _ => fail("schema", "network"),
    }
}
fn identity(case: &str, version: u8, inputs: usize, outputs: usize) -> Result<()> {
    require(
        !case.is_empty()
            && case.len() <= 64
            && case
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b)),
        "schema",
        "case_id",
    )?;
    require(
        matches!(version, 5 | 6) && (1..=32).contains(&inputs) && (1..=64).contains(&outputs),
        "schema",
        "transaction_shape",
    )
}
fn value_sum(values: impl Iterator<Item = u64>) -> Result<()> {
    let mut sum = 0u64;
    for value in values {
        sum = sum.checked_add(value).ok_or(Failure {
            stage: "schema",
            reason: "amount",
        })?;
        require(value <= MAX_MONEY && sum <= MAX_MONEY, "schema", "amount")?;
    }
    Ok(())
}
fn chain_output(value: u64, script: Vec<u8>) -> Result<ChainOutput> {
    Ok(ChainOutput {
        value: value.try_into().map_err(|_| Failure {
            stage: "schema",
            reason: "amount",
        })?,
        lock_script: Script::new(&script),
    })
}
fn producer(value: &Producer) -> Result<()> {
    require(
        value.zakura_revision == "9b175e9d3d46a6aa4cfb5552517c3d828852ecbc"
            && value.algorithm_revision == "b392fe82d2d9770142477a576a758a233888bc0a"
            && value.blake3_version == "1.8.5",
        "schema",
        "producer_pin",
    )?;
    for hash in [
        &value.host_source_inventory_sha256,
        &value.host_lock_sha256,
        &value.host_binary_sha256,
        &value.signer_source_inventory_sha256,
        &value.signer_lock_sha256,
        &value.signer_binary_sha256,
    ] {
        fixed_hex::<32>(hash)?;
    }
    Ok(())
}
fn outpoint(display: &str, index: u32) -> Result<OutPoint> {
    require(fixed_hex::<32>(display)? != [0; 32], "schema", "outpoint")?;
    Ok(OutPoint {
        hash: display.parse::<Hash>().map_err(|_| Failure {
            stage: "schema",
            reason: "outpoint",
        })?,
        index,
    })
}
fn outpoint_fields(outpoint: &OutPoint) -> Outpoint {
    Outpoint {
        txid_display_hex: outpoint.hash.to_string(),
        index: outpoint.index,
        wire_hex: hex::encode(
            outpoint
                .zcash_serialize_to_vec()
                .expect("outpoint serializes"),
        ),
    }
}
fn record(value: &Record) -> Result<NativeRecord> {
    require(value.signer_index < 15, "schema", "signer_index")?;
    Ok(NativeRecord {
        index: value.signer_index,
        public_key: fixed_hex(&value.public_key_hex)?,
        signature: bounded_hex(&value.signature_hex, 7856)?
            .into_boxed_slice()
            .try_into()
            .map_err(|_| Failure {
                stage: "schema",
                reason: "signature_length",
            })?,
    })
}
fn record_fields(value: &NativeRecord) -> Record {
    Record {
        signer_index: value.index,
        public_key_hex: hex::encode(value.public_key),
        signature_hex: hex::encode(value.signature.as_ref()),
    }
}
struct Prepared {
    tx: Transaction,
    previous: Arc<Vec<ChainOutput>>,
    policies: Vec<Policy>,
    keys: Vec<Vec<[u8; 32]>>,
}
fn prepare(recipe: &Recipe) -> Result<Prepared> {
    identity(
        &recipe.case_id,
        recipe.transaction_version,
        recipe.inputs.len(),
        recipe.outputs.len(),
    )?;
    network(&recipe.network)?;
    require(recipe.lock_time < 500_000_000, "schema", "lock_time")?;
    value_sum(recipe.inputs.iter().map(|i| i.value_zat))?;
    let mut policies = Vec::new();
    let mut keys = Vec::new();
    let mut spends = Vec::new();
    let mut seen = HashSet::new();
    for input in &recipe.inputs {
        let n = input.public_keys_hex.len();
        require(
            (1..=15).contains(&n)
                && input.threshold > 0
                && usize::from(input.threshold) <= n
                && input.signer_indices.len() == usize::from(input.threshold),
            "schema",
            "policy",
        )?;
        let mut public = input
            .public_keys_hex
            .iter()
            .map(|k| fixed_hex::<32>(k))
            .collect::<Result<Vec<_>>>()?;
        public.sort_by_key(key_commitment);
        let policy = Policy::new(input.threshold, public.iter().map(key_commitment).collect())
            .map_err(|_| Failure {
                stage: "schema",
                reason: "policy",
            })?;
        require(
            input.signer_indices.iter().all(|&i| usize::from(i) < n)
                && input.signer_indices.windows(2).all(|p| p[0] < p[1]),
            "schema",
            "signer_indices",
        )?;
        let outpoint = outpoint(&input.outpoint.txid_display_hex, input.outpoint.index)?;
        require(seen.insert(outpoint), "schema", "duplicate_outpoint")?;
        spends.push(Spend {
            outpoint,
            sequence: input.sequence,
            previous_output: chain_output(
                input.value_zat,
                policy.lock_script().as_raw_bytes().to_vec(),
            )?,
        });
        policies.push(policy);
        keys.push(public);
    }
    let outputs = recipe
        .outputs
        .iter()
        .map(|o| match o {
            RecipeOutput::Policy(p) => chain_output(
                p.value_zat,
                policies
                    .get(p.input_policy_index)
                    .ok_or(Failure {
                        stage: "schema",
                        reason: "output_policy_index",
                    })?
                    .lock_script()
                    .as_raw_bytes()
                    .to_vec(),
            ),
            RecipeOutput::Script(s) => {
                chain_output(s.value_zat, bounded_hex(&s.script_hex, 10_000)?)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    value_sum(outputs.iter().map(|o| u64::from(o.value)))?;
    let (tx, previous) = TransactionRecipe {
        version: recipe.transaction_version,
        network_upgrade: NetworkUpgrade::Nu7,
        lock_time: LockTime::Height(Height(recipe.lock_time)),
        expiry_height: Height(recipe.expiry_height),
        spends,
        outputs,
    }
    .build();
    Ok(Prepared {
        tx,
        previous,
        policies,
        keys,
    })
}
fn input_fields(recipe: &Recipe, prepared: &Prepared) -> Result<Vec<Input>> {
    let context = TransactionContext::new(
        &prepared.tx,
        network(&recipe.network)?,
        NetworkUpgrade::Nu7,
        prepared.previous.clone(),
    )
    .map_err(|_| Failure {
        stage: "generation",
        reason: "context",
    })?;
    recipe
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let message = context.message(i).map_err(|_| Failure {
                stage: "generation",
                reason: "message",
            })?;
            Ok(Input {
                input_index: i,
                outpoint: outpoint_fields(&outpoint(
                    &input.outpoint.txid_display_hex,
                    input.outpoint.index,
                )?),
                sequence: input.sequence,
                spent_output: SpentOutput {
                    value_zat: input.value_zat,
                    script_hex: hex::encode(prepared.previous[i].lock_script.as_raw_bytes()),
                },
                descriptor_hex: hex::encode(prepared.policies[i].descriptor()),
                sighash_all_digest_hex: hex::encode(&message[69..]),
                message_hex: hex::encode(message),
                context_hex: String::new(),
                records: vec![],
            })
        })
        .collect()
}
fn output_fields(tx: &Transaction) -> Vec<Output> {
    tx.outputs()
        .iter()
        .enumerate()
        .map(|(i, o)| Output {
            output_index: i,
            value_zat: u64::from(o.value),
            script_hex: hex::encode(o.lock_script.as_raw_bytes()),
        })
        .collect()
}
fn outcome(error: Option<(&str, Rejection, Option<usize>)>, checks: Option<usize>) -> Outcome {
    let accepted = error.is_none();
    let over = accepted && checks.is_some_and(|n| n > 16);
    Outcome {
        native_authorization: if accepted { "accept" } else { "reject" }.into(),
        native_rejection: error.map(|(stage, e, index)| NativeRejection {
            stage: stage.into(),
            reason: e.name().into(),
            input_index: index,
        }),
        signature_checks: checks,
        functional_profile: FunctionalProfile {
            transaction_limit: 16,
            block_limit: 64,
            result: if !accepted {
                "not_evaluated"
            } else if over {
                "reject"
            } else {
                "accept"
            }
            .into(),
            stage: over.then(|| "transaction_budget".into()),
        },
    }
}
fn validate_expected(value: &Outcome, input_count: usize) -> Result<()> {
    let profile = &value.functional_profile;
    require(
        profile.transaction_limit == 16 && profile.block_limit == 64,
        "schema",
        "functional_profile",
    )?;
    require(
        value.signature_checks.is_none_or(|n| n <= 480),
        "schema",
        "signature_checks",
    )?;
    match (&*value.native_authorization, &value.native_rejection) {
        ("accept", None) => require(
            value.signature_checks.is_some()
                && ((profile.result == "accept" && profile.stage.is_none())
                    || (profile.result == "reject"
                        && profile.stage.as_deref() == Some("transaction_budget"))),
            "schema",
            "expected",
        )?,
        ("reject", Some(rejection)) => {
            require(
                profile.result == "not_evaluated" && profile.stage.is_none(),
                "schema",
                "expected",
            )?;
            let valid = match rejection.stage.as_str() {
                "context" => {
                    rejection.input_index.is_none()
                        && value.signature_checks.is_none()
                        && [
                            "transaction_version",
                            "backend_unavailable",
                            "consensus_branch",
                            "input_context",
                            "sighash",
                        ]
                        .contains(&rejection.reason.as_str())
                }
                "authorization" => {
                    rejection.input_index.is_some_and(|i| i < input_count)
                        && value.signature_checks.is_none()
                        && [
                            "input_context",
                            "output_template",
                            "authorization_size",
                            "encoding",
                            "unsupported_policy",
                            "threshold",
                            "key_order",
                            "output_commitment",
                            "signature_count",
                            "signer_index",
                            "key_commitment",
                            "verification_budget",
                        ]
                        .contains(&rejection.reason.as_str())
                }
                "signature" => {
                    rejection.input_index.is_some_and(|i| i < input_count)
                        && value.signature_checks.is_some()
                        && rejection.reason == "signature"
                }
                _ => false,
            };
            require(valid, "schema", "native_rejection")?;
        }
        _ => return fail("schema", "expected"),
    }
    Ok(())
}
fn validate_artifact(artifact: &Artifact) -> Result<Vec<u8>> {
    envelope(
        artifact.schema_version,
        &artifact.contract,
        artifact.public_fixture,
    )?;
    identity(
        &artifact.case_id,
        artifact.transaction_version,
        artifact.inputs.len(),
        artifact.outputs.len(),
    )?;
    network(&artifact.network)?;
    producer(&artifact.producer)?;
    require(
        artifact.context_provenance == "synthetic-public-fixture",
        "schema",
        "context_provenance",
    )?;
    validate_expected(&artifact.expected, artifact.inputs.len())?;
    fixed_hex::<32>(&artifact.artifact_sha256)?;
    fixed_hex::<32>(&artifact.transaction_sha256)?;
    let bytes = bounded_hex(&artifact.transaction_hex, MAX_TX)?;
    value_sum(artifact.inputs.iter().map(|i| i.spent_output.value_zat))?;
    value_sum(artifact.outputs.iter().map(|o| o.value_zat))?;
    for input in &artifact.inputs {
        require(u32::try_from(input.input_index).is_ok(), "schema", "fields")?;
        fixed_hex::<32>(&input.outpoint.txid_display_hex)?;
        fixed_hex::<36>(&input.outpoint.wire_hex)?;
        bounded_hex(&input.spent_output.script_hex, 10_000)?;
        bounded_hex(&input.descriptor_hex, 484)?;
        fixed_hex::<32>(&input.sighash_all_digest_hex)?;
        fixed_hex::<101>(&input.message_hex)?;
        require(
            input.context_hex.is_empty() && input.records.len() <= 15,
            "schema",
            "input_fields",
        )?;
        for entry in &input.records {
            record(entry)?;
        }
    }
    for output in &artifact.outputs {
        require(
            u32::try_from(output.output_index).is_ok(),
            "schema",
            "fields",
        )?;
        bounded_hex(&output.script_hex, 10_000)?;
    }
    Ok(bytes)
}
fn decode_transaction(bytes: &[u8]) -> Result<Transaction> {
    let mut cursor = Cursor::new(bytes);
    let tx = Transaction::zcash_deserialize(&mut cursor).map_err(|_| Failure {
        stage: "correspondence",
        reason: "transaction_encoding",
    })?;
    require(
        cursor.position() == u64::try_from(bytes.len()).expect("bounded bytes fit u64"),
        "correspondence",
        "trailing_transaction_bytes",
    )?;
    require(
        tx.zcash_serialize_to_vec().map_err(|_| Failure {
            stage: "correspondence",
            reason: "transaction_encoding",
        })? == bytes,
        "correspondence",
        "transaction_encoding",
    )?;
    Ok(tx)
}
fn check(artifact: &Artifact) -> Result<Outcome> {
    let bytes = validate_artifact(artifact)?;
    require(
        strict::hash(&bytes) == artifact.transaction_sha256,
        "integrity",
        "transaction_hash",
    )?;
    require(
        strict::artifact_hash(&encode(artifact)).map_err(|_| Failure {
            stage: "schema",
            reason: "artifact_object",
        })? == artifact.artifact_sha256,
        "integrity",
        "artifact_hash",
    )?;
    let tx = decode_transaction(&bytes)?;
    require(
        tx.version() == u32::from(artifact.transaction_version)
            && tx.inputs().len() == artifact.inputs.len()
            && tx.outputs().len() == artifact.outputs.len(),
        "correspondence",
        "transaction_shape",
    )?;
    require(
        !tx.has_sapling_shielded_data()
            && !tx.has_orchard_shielded_data()
            && !tx.has_ironwood_shielded_data(),
        "correspondence",
        "shielded_data",
    )?;
    let branch = tx
        .network_upgrade()
        .and_then(|n| n.branch_id())
        .map(u32::from);
    require(
        branch == Some(artifact.consensus_branch_id),
        "correspondence",
        "consensus_branch",
    )?;
    let mut seen = HashSet::new();
    let mut previous = Vec::new();
    for (i, (raw, input)) in tx.inputs().iter().zip(&artifact.inputs).enumerate() {
        let ChainInput::PrevOut {
            outpoint: raw_outpoint,
            unlock_script,
            sequence,
        } = raw
        else {
            return fail("correspondence", "coinbase");
        };
        require(
            unlock_script.as_raw_bytes().len() <= 131_072,
            "correspondence",
            "authorization_size",
        )?;
        let expected = outpoint_fields(raw_outpoint);
        require(
            input.input_index == i
                && input.sequence == *sequence
                && input.outpoint.txid_display_hex == expected.txid_display_hex
                && input.outpoint.index == expected.index
                && input.outpoint.wire_hex == expected.wire_hex,
            "correspondence",
            "input_wire",
        )?;
        require(
            seen.insert(*raw_outpoint),
            "correspondence",
            "duplicate_outpoint",
        )?;
        previous.push(chain_output(
            input.spent_output.value_zat,
            bounded_hex(&input.spent_output.script_hex, 10_000)?,
        )?);
    }
    for (i, (raw, output)) in tx.outputs().iter().zip(&artifact.outputs).enumerate() {
        require(
            output.output_index == i
                && output.value_zat == u64::from(raw.value)
                && bounded_hex(&output.script_hex, 10_000)? == raw.lock_script.as_raw_bytes(),
            "correspondence",
            "output_wire",
        )?;
    }
    let previous = Arc::new(previous);
    let context = TransactionContext::new(
        &tx,
        network(&artifact.network)?,
        NetworkUpgrade::Nu7,
        previous.clone(),
    );
    let mut context_error = context.as_ref().err().copied();
    if let Ok(context) = &context {
        for (i, input) in artifact.inputs.iter().enumerate() {
            match context.message(i) {
                Ok(message) => require(
                    input.message_hex == hex::encode(message)
                        && input.sighash_all_digest_hex == hex::encode(&message[69..]),
                    "correspondence",
                    "message_digest",
                )?,
                Err(error) => {
                    context_error.get_or_insert(error);
                }
            }
        }
    }
    let mut authorizations = Vec::new();
    let mut first_error = None;
    for i in 0..artifact.inputs.len() {
        if let Err(error) = input_authorization(&tx, &previous, i) {
            if first_error.is_none() {
                first_error = Some(("authorization", error, Some(i)));
            }
        }
        let ChainInput::PrevOut { unlock_script, .. } = &tx.inputs()[i] else {
            unreachable!("wire correspondence already rejected coinbase inputs")
        };
        // Binding failures do not make canonically decoded wire fields unavailable.
        authorizations.push(Authorization::decode(unlock_script.as_raw_bytes()).ok());
    }
    // Every decodable authorization must match metadata, including when context
    // derivation or another input fails. These fields do not require a digest.
    for (authorization, input) in authorizations.iter().zip(&artifact.inputs) {
        if let Some(authorization) = authorization {
            require(
                input.descriptor_hex == hex::encode(authorization.policy.descriptor())
                    && input.records
                        == authorization
                            .records
                            .iter()
                            .map(record_fields)
                            .collect::<Vec<_>>(),
                "correspondence",
                "authorization_fields",
            )?;
        }
    }
    if let Some(error) = context_error {
        return Ok(outcome(Some(("context", error, None)), None));
    }
    if first_error.is_some() {
        return Ok(outcome(first_error, None));
    }
    let context = context.expect("context errors returned after correspondence checks");
    let checks = authorizations
        .iter()
        .flatten()
        .map(|a| a.records.len())
        .sum();
    for i in 0..artifact.inputs.len() {
        if let Err(error) = context.verify_input(i) {
            return Ok(outcome(Some(("signature", error, Some(i))), Some(checks)));
        }
    }
    Ok(outcome(None, Some(checks)))
}
fn execute(request: Request) -> Result<(&'static str, Value)> {
    match request {
        Request::Prepare {
            schema_version,
            contract,
            public_fixture,
            recipe,
        } => {
            envelope(schema_version, &contract, public_fixture)?;
            let prepared = prepare(&recipe)?;
            let inputs = input_fields(&recipe, &prepared)?;
            let inputs = inputs.into_iter().enumerate().map(|(i, input)| {
                let mut value = encode(input); let object = value.as_object_mut().expect("input object"); object.remove("records");
                object.insert("signers".into(), json!(recipe.inputs[i].signer_indices.iter().map(|&index| json!({"signer_index":index,"public_key_hex":hex::encode(prepared.keys[i][usize::from(index)])})).collect::<Vec<_>>())); value
            }).collect::<Vec<_>>();
            Ok((
                "prepare",
                json!({"case_id":recipe.case_id,"network":recipe.network,"transaction_version":recipe.transaction_version,"consensus_branch_id":NU7,"unsigned_transaction_hex":hex::encode(prepared.tx.zcash_serialize_to_vec().map_err(|_| Failure { stage:"generation",reason:"serialization" })?),"inputs":inputs,"outputs":output_fields(&prepared.tx)}),
            ))
        }
        Request::Assemble {
            schema_version,
            contract,
            public_fixture,
            recipe,
            records,
            producer: identity,
        } => {
            envelope(schema_version, &contract, public_fixture)?;
            producer(&identity)?;
            let mut prepared = prepare(&recipe)?;
            require(
                records.len() == recipe.inputs.len(),
                "schema",
                "record_arrays",
            )?;
            let mut inputs = input_fields(&recipe, &prepared)?;
            for (i, (entries, recipe_input)) in records.iter().zip(&recipe.inputs).enumerate() {
                require(
                    entries.iter().map(|r| r.signer_index).collect::<Vec<_>>()
                        == recipe_input.signer_indices,
                    "schema",
                    "signer_indices",
                )?;
                let context = InputSigningContext::new(
                    &prepared.tx,
                    network(&recipe.network)?,
                    NetworkUpgrade::Nu7,
                    prepared.previous.clone(),
                    i,
                    &prepared.policies[i],
                )
                .map_err(|_| Failure {
                    stage: "generation",
                    reason: "context",
                })?;
                let authorization = context
                    .authorization(entries.iter().map(record).collect::<Result<Vec<_>>>()?)
                    .map_err(|_| Failure {
                        stage: "generation",
                        reason: "authorization",
                    })?;
                install(&mut prepared.tx, i, Script::new(&authorization.encode()));
                inputs[i].records = entries.clone();
            }
            let bytes = prepared.tx.zcash_serialize_to_vec().map_err(|_| Failure {
                stage: "generation",
                reason: "serialization",
            })?;
            require(bytes.len() <= MAX_TX, "generation", "transaction_size")?;
            let checks = records.iter().map(Vec::len).sum();
            let mut artifact = Artifact {
                schema_version: 1,
                contract: CONTRACT.into(),
                public_fixture: true,
                case_id: recipe.case_id,
                context_provenance: "synthetic-public-fixture".into(),
                producer: *identity,
                network: recipe.network,
                transaction_version: recipe.transaction_version,
                consensus_branch_id: NU7,
                transaction_hex: hex::encode(&bytes),
                transaction_sha256: strict::hash(&bytes),
                inputs,
                outputs: output_fields(&prepared.tx),
                expected: outcome(None, Some(checks)),
                artifact_sha256: String::new(),
            };
            artifact.artifact_sha256 =
                strict::artifact_hash(&encode(&artifact)).expect("artifact object");
            require(
                check(&artifact)? == artifact.expected,
                "generation",
                "native_recheck",
            )?;
            Ok(("assemble", encode(artifact)))
        }
        Request::Check {
            schema_version,
            contract,
            public_fixture,
            artifact,
        } => {
            envelope(schema_version, &contract, public_fixture)?;
            let observed = check(&artifact)?;
            Ok((
                "check",
                json!({"expectation_match":observed == artifact.expected,"observed":observed}),
            ))
        }
    }
}
fn handle(bytes: &[u8]) -> Value {
    let mut operation = "unknown".to_string();
    let result = strict::parse(bytes)
        .map_err(|reason| Failure {
            stage: if reason == "encoded_size" {
                "transport"
            } else {
                "schema"
            },
            reason,
        })
        .and_then(|value| {
            if let Some(op) = value.get("op").and_then(Value::as_str) {
                if ["prepare", "assemble", "check"].contains(&op) {
                    operation = op.into();
                }
            }
            let request = serde_json::from_value(value).map_err(|_| Failure {
                stage: "schema",
                reason: "fields",
            })?;
            execute(request)
        });
    match result {
        Ok((op, result)) => {
            json!({"schema_version":1,"contract":CONTRACT,"public_fixture":true,"op":op,"ok":true,"result":result})
        }
        Err(error) => {
            json!({"schema_version":1,"contract":CONTRACT,"public_fixture":true,"op":operation,"ok":false,"error":{"stage":error.stage,"reason":error.reason}})
        }
    }
}
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(u64::try_from(strict::MAX_BYTES + 1)?)
        .read_to_end(&mut bytes)?;
    let mut output = serde_json::to_vec(&handle(&bytes))?;
    if output.len() >= strict::MAX_BYTES {
        output = serde_json::to_vec(
            &json!({"schema_version":1,"contract":CONTRACT,"public_fixture":true,"op":"unknown","ok":false,"error":{"stage":"transport","reason":"response_size"}}),
        )?;
    }
    let mut stdout = io::stdout().lock();
    stdout.write_all(&output)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Value {
        json!({"schema_version":1,"contract":CONTRACT,"public_fixture":true,"op":"prepare","recipe":{"case_id":"v5-unit","network":"Regtest","transaction_version":5,"lock_time":5,"expiry_height":140,"inputs":[{"outpoint":{"txid_display_hex":hex::encode((0u8..32).collect::<Vec<_>>()),"index":1},"sequence":4294967294u32,"value_zat":100000,"threshold":1,"public_keys_hex":["11".repeat(32)],"signer_indices":[0]}],"outputs":[{"value_zat":20000,"input_policy_index":0},{"value_zat":30000,"script_hex":"51"}]}})
    }
    fn run(value: Value) -> Value {
        handle(&serde_json::to_vec(&value).unwrap())
    }
    #[test]
    fn prepares_ordered_messages_and_rejects_ambiguous_inputs() {
        let valid = request();
        let response = run(valid.clone());
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(
            response["result"]["inputs"][0]["message_hex"]
                .as_str()
                .unwrap()
                .len(),
            202
        );
        let mut expected_wire: Vec<_> = (0u8..32).rev().collect();
        expected_wire.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            response["result"]["inputs"][0]["outpoint"]["wire_hex"],
            hex::encode(expected_wire)
        );
        for (field, value) in [
            ("lock_time", json!(500000000)),
            ("network", json!("regtest")),
            ("transaction_version", json!(4)),
            ("secret_key", json!("forbidden")),
        ] {
            let mut invalid = valid.clone();
            invalid["recipe"][field] = value;
            assert_eq!(run(invalid)["ok"], false, "{field}");
        }
        let mut invalid = valid.clone();
        invalid["recipe"]["outputs"][0]["script_hex"] = json!("51");
        assert_eq!(run(invalid)["ok"], false);
        let mut invalid = valid.clone();
        let duplicate = invalid["recipe"]["inputs"][0].clone();
        invalid["recipe"]["inputs"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert_eq!(run(invalid)["ok"], false);
        let mut invalid = valid.clone();
        invalid["recipe"]["inputs"][0]["public_keys_hex"] =
            json!(["11".repeat(32), "11".repeat(32)]);
        assert_eq!(run(invalid)["ok"], false);
        let mut invalid = valid;
        invalid["recipe"]["inputs"][0]["signer_indices"] = json!([14]);
        assert_eq!(run(invalid)["ok"], false);
    }
    #[test]
    fn prepare_rejects_null_hashes_before_deriving_messages() {
        for index in [1, u32::MAX] {
            let mut value = request();
            value["recipe"]["inputs"][0]["outpoint"]["index"] = json!(index);
            assert_eq!(run(value.clone())["ok"], true);
            value["recipe"]["inputs"][0]["outpoint"]["txid_display_hex"] = json!("00".repeat(32));
            assert_eq!(
                run(value)["error"],
                json!({"stage":"schema","reason":"outpoint"})
            );
        }
    }
    #[test]
    fn fail_closed_assembly_and_exact_consumption() {
        let mut value = request();
        value["op"] = json!("assemble");
        value["records"] = json!([[{"signer_index":0,"public_key_hex":"11".repeat(32),"signature_hex":"00".repeat(7856)}]]);
        value["producer"] = json!({"zakura_revision":"9b175e9d3d46a6aa4cfb5552517c3d828852ecbc","algorithm_revision":"b392fe82d2d9770142477a576a758a233888bc0a","blake3_version":"1.8.5","host_source_inventory_sha256":"00".repeat(32),"host_lock_sha256":"00".repeat(32),"host_binary_sha256":"00".repeat(32),"signer_source_inventory_sha256":"00".repeat(32),"signer_lock_sha256":"00".repeat(32),"signer_binary_sha256":"00".repeat(32)});
        let response = run(value);
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["stage"], "generation");
        let prepared = run(request());
        let bytes = hex::decode(
            prepared["result"]["unsigned_transaction_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert!(decode_transaction(&bytes).is_ok());
        let mut bytes = bytes;
        bytes.push(0);
        assert_eq!(
            decode_transaction(&bytes).err().unwrap().reason,
            "trailing_transaction_bytes"
        );
    }
    #[test]
    fn canonical_del_matches_python_and_budget_is_not_native_rejection() {
        assert_eq!(
            strict::canonical(&json!({"\u{7f}":"\u{7f}"})),
            br#"{"\u007f":"\u007f"}"#
        );
        assert_eq!(outcome(None, Some(16)).functional_profile.result, "accept");
        let over = outcome(None, Some(17));
        assert_eq!(over.native_authorization, "accept");
        assert_eq!(over.functional_profile.result, "reject");
        let invalid = outcome(Some(("signature", Rejection::Signature, Some(0))), Some(17));
        assert_eq!(invalid.functional_profile.result, "not_evaluated");
    }
    #[test]
    fn nullable_fields_must_be_present() {
        let accepted = encode(outcome(None, Some(1)));
        assert!(serde_json::from_value::<Outcome>(accepted.clone()).is_ok());
        for field in ["native_rejection", "signature_checks"] {
            let mut value = accepted.clone();
            value.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Outcome>(value).is_err(), "{field}");
        }
        let mut value = accepted;
        value["functional_profile"]
            .as_object_mut()
            .unwrap()
            .remove("stage");
        assert!(serde_json::from_value::<Outcome>(value).is_err());
        let mut rejected = encode(outcome(
            Some(("context", Rejection::ConsensusBranch, None)),
            None,
        ));
        assert!(serde_json::from_value::<Outcome>(rejected.clone()).is_ok());
        rejected["native_rejection"]
            .as_object_mut()
            .unwrap()
            .remove("input_index");
        assert!(serde_json::from_value::<Outcome>(rejected).is_err());
    }
    fn binding_rejected_artifact(input_count: usize) -> Artifact {
        let mut value = request();
        let first_input = value["recipe"]["inputs"][0].clone();
        for index in 1..input_count {
            let mut input = first_input.clone();
            input["outpoint"]["index"] = json!(index + 1);
            value["recipe"]["inputs"]
                .as_array_mut()
                .unwrap()
                .push(input);
        }
        let Request::Prepare { recipe, .. } = serde_json::from_value(value).unwrap() else {
            unreachable!()
        };
        let mut prepared = prepare(&recipe).unwrap();
        let entry = Record {
            signer_index: 0,
            public_key_hex: "11".repeat(32),
            signature_hex: "00".repeat(7856),
        };
        for index in 0..input_count {
            let authorization = Authorization {
                policy: prepared.policies[index].clone(),
                records: vec![record(&entry).unwrap()],
            };
            install(
                &mut prepared.tx,
                index,
                Script::new(&authorization.encode()),
            );
        }
        Arc::make_mut(&mut prepared.previous)[0].lock_script = Script::new(&[0x51]);
        let mut inputs = input_fields(&recipe, &prepared).unwrap();
        for input in &mut inputs {
            input.records = vec![entry.clone()];
        }
        let bytes = prepared.tx.zcash_serialize_to_vec().unwrap();
        let producer: Producer = serde_json::from_value(json!({"zakura_revision":"9b175e9d3d46a6aa4cfb5552517c3d828852ecbc","algorithm_revision":"b392fe82d2d9770142477a576a758a233888bc0a","blake3_version":"1.8.5","host_source_inventory_sha256":"00".repeat(32),"host_lock_sha256":"00".repeat(32),"host_binary_sha256":"00".repeat(32),"signer_source_inventory_sha256":"00".repeat(32),"signer_lock_sha256":"00".repeat(32),"signer_binary_sha256":"00".repeat(32)})).unwrap();
        let mut artifact = Artifact {
            schema_version: 1,
            contract: CONTRACT.into(),
            public_fixture: true,
            case_id: recipe.case_id,
            context_provenance: "synthetic-public-fixture".into(),
            producer,
            network: recipe.network,
            transaction_version: 5,
            consensus_branch_id: NU7,
            transaction_hex: hex::encode(&bytes),
            transaction_sha256: strict::hash(&bytes),
            inputs,
            outputs: output_fields(&prepared.tx),
            expected: outcome(
                Some(("authorization", Rejection::OutputTemplate, Some(0))),
                None,
            ),
            artifact_sha256: String::new(),
        };
        artifact.artifact_sha256 = strict::artifact_hash(&encode(&artifact)).unwrap();
        artifact
    }
    #[test]
    fn binding_rejection_does_not_hide_decodable_metadata_mismatch() {
        let artifact = binding_rejected_artifact(1);
        assert_eq!(check(&artifact).unwrap(), artifact.expected);
        for mutate_descriptor in [true, false] {
            let mut altered = artifact.clone();
            if mutate_descriptor {
                altered.inputs[0].descriptor_hex = "00".into();
            } else {
                altered.inputs[0].records[0].signature_hex = "01".repeat(7856);
            }
            altered.artifact_sha256 = strict::artifact_hash(&encode(&altered)).unwrap();
            let failure = check(&altered).unwrap_err();
            assert_eq!(
                (failure.stage, failure.reason),
                ("correspondence", "authorization_fields")
            );
        }
    }
    #[test]
    fn context_rejection_still_checks_every_decodable_authorization() {
        let mut artifact = binding_rejected_artifact(2);
        let mut bytes = hex::decode(&artifact.transaction_hex).unwrap();
        bytes[8..12].copy_from_slice(&0xc2d6_d0b4u32.to_le_bytes());
        artifact.transaction_hex = hex::encode(&bytes);
        artifact.transaction_sha256 = strict::hash(&bytes);
        artifact.consensus_branch_id = 0xc2d6_d0b4;
        artifact.expected = outcome(Some(("context", Rejection::ConsensusBranch, None)), None);
        artifact.artifact_sha256 = strict::artifact_hash(&encode(&artifact)).unwrap();
        // Context rejection retains precedence over the first input's binding
        // failure, and unavailable messages need not match the changed branch.
        assert_eq!(check(&artifact).unwrap(), artifact.expected);
        for input_index in 0..artifact.inputs.len() {
            for mutate_descriptor in [true, false] {
                let mut altered = artifact.clone();
                if mutate_descriptor {
                    altered.inputs[input_index].descriptor_hex = "00".into();
                } else {
                    altered.inputs[input_index].records[0].signature_hex = "01".repeat(7856);
                }
                altered.artifact_sha256 = strict::artifact_hash(&encode(&altered)).unwrap();
                let failure = check(&altered).unwrap_err();
                assert_eq!(
                    (failure.stage, failure.reason),
                    ("correspondence", "authorization_fields")
                );
            }
        }
        // An undecodable first input cannot hide the second input's metadata.
        let mut tx = decode_transaction(&bytes).unwrap();
        install(&mut tx, 0, Script::new(&[]));
        let bytes = tx.zcash_serialize_to_vec().unwrap();
        artifact.transaction_hex = hex::encode(&bytes);
        artifact.transaction_sha256 = strict::hash(&bytes);
        artifact.artifact_sha256 = strict::artifact_hash(&encode(&artifact)).unwrap();
        assert_eq!(check(&artifact).unwrap(), artifact.expected);
        artifact.inputs[1].records[0].signature_hex = "01".repeat(7856);
        artifact.artifact_sha256 = strict::artifact_hash(&encode(&artifact)).unwrap();
        let failure = check(&artifact).unwrap_err();
        assert_eq!(
            (failure.stage, failure.reason),
            ("correspondence", "authorization_fields")
        );
    }
    #[test]
    fn metadata_indices_distinguish_width_from_wire_correspondence() {
        let artifact = encode(binding_rejected_artifact(1));
        for (array, field, reason) in [
            ("inputs", "input_index", "input_wire"),
            ("outputs", "output_index", "output_wire"),
        ] {
            for index in [1, u64::from(u32::MAX), u64::from(u32::MAX) + 1] {
                let mut altered = artifact.clone();
                altered[array][0][field] = json!(index);
                altered["artifact_sha256"] = json!(strict::artifact_hash(&altered).unwrap());
                let response = run(json!({"schema_version":1,"contract":CONTRACT,
                    "public_fixture":true,"op":"check","artifact":altered}));
                let (stage, reason) = if index > u64::from(u32::MAX) {
                    ("schema", "fields")
                } else {
                    ("correspondence", reason)
                };
                assert_eq!(response["error"], json!({"stage":stage,"reason":reason}));
            }
        }
    }
}
