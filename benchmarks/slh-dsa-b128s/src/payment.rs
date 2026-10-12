//! Offline product wallet lifecycle measurements. The synthetic node adapter is
//! adapted from product wallet tests; the foreground/evidence split follows
//! research `experiments/hash-four-payments/common/src/payment.rs` at
//! 53a6e4bd1c11d90349fd3d989507f0e1a4995112 (MIT OR Apache-2.0).
//! Production approval, enrollment, signing and journal APIs remain unchanged.

use std::{
    fs::{self, OpenOptions},
    io::{self, Cursor, Write},
    path::Path,
    sync::Arc,
    time::Instant,
};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use zakura_chain::{
    parameters::NetworkUpgrade,
    serialization::{ZcashDeserialize, ZcashSerialize},
    transaction::{zip317, Transaction},
    transparent::{Input, Output, Script},
};
use zakura_pq_slh_dsa_b_exp::{Authorization, TransactionContext};
use zakura_pq_tx_context::NetworkDomain;
use zakura_pq_wallet::{
    payment::{Partial, PaymentState, Proposal, Review},
    WatchStore,
};

use crate::{
    classical::ClassicalPayment,
    config::{Algorithm, PaymentConfig},
    measurement::{observe, process_peak, Observation},
    payment_fixture::{self, Inventory, Session},
    write_record,
};

const CACHED_INVENTORY: &str = "prepared outside foreground; not measured for cached mode";

/// Stage timers are optional so correctness execution never takes a performance
/// or OS resource measurement. No timing is manufactured for untimed operations.
struct Stages {
    enabled: bool,
    metrics: Map<String, Value>,
}

impl Stages {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            metrics: Map::new(),
        }
    }

    fn run<T>(
        &mut self,
        name: &str,
        operation: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let start = self.enabled.then(Instant::now);
        let result = operation();
        if let Some(start) = start {
            let elapsed =
                u64::try_from(start.elapsed().as_nanos()).map_err(|_| "stage timer overflow")?;
            self.metrics.insert(name.into(), elapsed.into());
        }
        result
    }
}

fn error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub fn metadata() -> Value {
    json!({
        "contract": "tpq-wallet-payment-v1",
        "algorithms": ["slh-dsa-b128s", "ecdsa-secp256k1"],
        "versions": ["v5", "v6"], "policies": ["single", "multisig"],
        "input_counts": [1, 2, 5], "inventory_modes": ["cached", "generated"],
        "max_samples": crate::config::MAX_PAYMENT_SAMPLES,
        "max_warmup": crate::config::MAX_PAYMENT_WARMUP,
        "scope": "offline synthetic payment implementation, no live node, consensus validation, relay, mining, propagation or authenticated funding",
        "slh_boundary": "foreground wraps optional fresh enrolled inventory, fresh WatchStore setup and scan, prepare_payment, threshold sign_payment calls, assemble_payment, and full TransactionContext input verification",
        "durability_boundary": "production wallet stages include their mandatory journal writes and file/directory syncs; persistence is not separately attributable from those APIs",
        "classical_boundary": "matched transparent P2SH transaction assembly, secp256k1 signing and script-aware verification; no SLH wallet lifecycle or durability comparison",
        "inventory_boundary": "cached means public enrolled inventory prepared outside foreground; both modes derive secret SigningKey afresh during actual Wallet signing; no CPU/OS cache flush",
        "generated_inventory_boundary": "Wallet creation, all participant receive/change public key derivations, policy enrollment, recipient creation and verified encrypted backup publication",
        "correctness_boundary": "check-payment executes one untimed fixture without Instant/getrusage/RSS snapshots, writes public evidence and checks reopen/negative controls; independent checker is separate",
        "artifact_boundary": "canonical signed/unsigned transaction, ordered fixture previous outputs and derived messages; no secrets or backup files; artifact encoding, negative controls, durable reopen checks and output excluded from foreground",
        "matched_workload": "each input 10000000 zat; recipient inputs*10000000-5000000 zat; each algorithm uses current 400-zat marginal fee and exact serialized actions; change therefore differs",
        "ephemeral_state": "fresh private temporary WatchStores each attempt, empty prior history; this is not long-lived journal growth or cold disk-cache behavior",
    })
}

pub fn cases() -> Vec<Value> {
    let mut cases = Vec::new();
    for algorithm in [Algorithm::Slh, Algorithm::Classical] {
        for version in [5, 6] {
            for multisig in [false, true] {
                for inputs in [1, 2, 5] {
                    for generated in [false, true] {
                        let config = PaymentConfig {
                            algorithm,
                            version,
                            multisig,
                            inputs,
                            generated,
                            samples: 1,
                            warmup: 0,
                            artifact_directory: "unused".into(),
                        };
                        cases.push(json!({ "case_id": config.case_id(), "phase": "wallet", "algorithm": algorithm.name(), "human_execution_required": true }));
                    }
                }
            }
        }
    }
    cases
}

enum Cached {
    Slh(Inventory),
    Classical(ClassicalPayment),
    None,
}

impl Cached {
    fn prepare(config: &PaymentConfig, path: &Path) -> Result<Self, String> {
        if config.generated {
            return Ok(Self::None);
        }
        match config.algorithm {
            Algorithm::Slh => Inventory::generate(config.multisig, path)
                .map(Self::Slh)
                .map_err(error),
            Algorithm::Classical => {
                ClassicalPayment::new(config.version, config.inputs, config.multisig, 0)
                    .map(Self::Classical)
            }
        }
    }
}

struct SlhCompleted {
    session: Session,
    // Keep generated keys alive until after the foreground boundary.
    _generated: Option<Inventory>,
    proposal: Proposal,
    review: Review,
    signed: Vec<u8>,
    persisted_partials: Vec<Vec<Partial>>,
}

struct ClassicalCompleted {
    _generated: Option<ClassicalPayment>,
    transaction: Transaction,
    signed: Vec<u8>,
}

enum Completed {
    Slh(Box<SlhCompleted>),
    Classical(Box<ClassicalCompleted>),
}

impl Completed {
    fn signed(&self) -> &[u8] {
        match self {
            Self::Slh(result) => &result.signed,
            Self::Classical(result) => &result.signed,
        }
    }

    fn finish(
        self,
        config: &PaymentConfig,
        cached: &Cached,
        directory: &Path,
    ) -> Result<Value, String> {
        match self {
            Self::Classical(result) => {
                let control = match (&result._generated, cached) {
                    (Some(control), _) | (None, Cached::Classical(control)) => control,
                    _ => {
                        return Err("classical inventory missing during evidence publication".into())
                    }
                };
                let mut artifact = control.evidence(&result.transaction)?;
                artifact["inventory"] = config.inventory().into();
                Ok(artifact)
            }
            Self::Slh(result) => {
                let SlhCompleted {
                    session,
                    proposal,
                    review,
                    signed,
                    persisted_partials,
                    ..
                } = *result;
                // Closing and reopening proves the wallet can recover the actual
                // signed bytes/partials, without counting readback as signing cost.
                drop(session);
                for (index, expected) in persisted_partials.into_iter().enumerate() {
                    let store = WatchStore::open(
                        &directory.join(format!("watch-{index}")),
                        &payment_fixture::profile(),
                    )
                    .map_err(error)?;
                    let records = store.payments().map_err(error)?;
                    if records.len() != 1
                        || records[0].partials != expected
                        || records[0].proposal != proposal
                    {
                        return Err("durable wallet partials did not survive reopen".into());
                    }
                    if index == 0
                        && (records[0].state != PaymentState::Signed
                            || records[0].signed_transaction_hex.as_deref()
                                != Some(hex::encode(&signed).as_str()))
                    {
                        return Err("durable signed transaction did not survive reopen".into());
                    }
                }
                let transaction: Transaction = decode(&signed)?;
                let previous = Arc::new(
                    proposal
                        .inputs
                        .iter()
                        .map(|input| decode_hex::<Output>(&input.spent_output_hex))
                        .collect::<Result<Vec<_>, _>>()?,
                );
                let context = TransactionContext::new(
                    &transaction,
                    NetworkDomain::Regtest,
                    NetworkUpgrade::Nu7,
                    previous,
                )
                .map_err(error)?;
                let messages = (0..config.inputs).map(|input_index| Ok(json!({"input_index":input_index,"message_hex":hex::encode(context.message(input_index).map_err(error)?)}))).collect::<Result<Vec<_>, String>>()?;
                let artifact = json!({
                    "schema_version": 1, "algorithm": config.algorithm.name(), "version": config.version,
                    "policy": config.policy(), "input_count": config.inputs, "inventory": config.inventory(),
                    "offline_fixture": true, "trusted_utxos": false, "node_acceptance": false,
                    "transaction_hex": hex::encode(&signed), "unsigned_transaction_hex": proposal.transaction_hex,
                    "previous_outputs_hex": proposal.inputs.iter().map(|input| input.spent_output_hex.clone()).collect::<Vec<_>>(),
                    "messages": messages,
                    "wallet": {"review":review, "proposal":proposal, "state_scope":"fresh-disposable-WatchStore-each-attempt", "durable_signed_bytes_reopened":true,"partials_reopened":true},
                });
                negative_controls(&artifact)?;
                Ok(artifact)
            }
        }
    }
}

fn slh(
    config: &PaymentConfig,
    cached: &Cached,
    directory: &Path,
    stages: &mut Stages,
) -> Result<Completed, String> {
    let generated = if config.generated {
        Some(stages.run("payment_inventory_ns", || {
            Inventory::generate(config.multisig, directory).map_err(error)
        })?)
    } else {
        None
    };
    let inventory = match (&generated, cached) {
        (Some(inventory), _) | (None, Cached::Slh(inventory)) => inventory,
        _ => return Err("SLH inventory missing".into()),
    };
    let intent = inventory
        .intent(config.version, config.inputs)
        .map_err(error)?;
    let mut session = stages.run("payment_wallet_setup_ns", || {
        Session::new(inventory, config.inputs, directory).map_err(error)
    })?;
    let (proposal, review) = stages.run("payment_prepare_persist_ns", || {
        session.stores[0]
            .prepare_payment(&inventory.wallets[0], &mut session.source, &intent)
            .map_err(error)
    })?;
    if proposal.inputs.len() != config.inputs
        || review.checks as usize != config.inputs * if config.multisig { 2 } else { 1 }
    {
        return Err("wallet selected a different input/policy workload".into());
    }
    let mut persisted_partials = Vec::new();
    let partials = stages.run("payment_sign_persist_ns", || {
        let mut partials = Vec::new();
        for (index, store) in session.stores.iter_mut().enumerate() {
            let signed = store
                .sign_payment(
                    &inventory.wallets[index],
                    &mut session.source,
                    &proposal,
                    &intent,
                    review.proposal_id,
                )
                .map_err(error)?;
            persisted_partials.push(signed.clone());
            partials.extend(signed);
        }
        Ok(partials)
    })?;
    let signed = stages.run("payment_assemble_persist_ns", || {
        session.stores[0]
            .assemble_payment(
                &inventory.wallets[0],
                &mut session.source,
                &proposal,
                &intent,
                &partials,
            )
            .map_err(error)
    })?;
    let transaction: Transaction = decode(&signed)?;
    let previous = Arc::new(
        proposal
            .inputs
            .iter()
            .map(|input| decode_hex::<Output>(&input.spent_output_hex))
            .collect::<Result<Vec<_>, _>>()?,
    );
    stages.run("payment_verify_ns", || {
        verify(&transaction, previous.clone())
    })?;
    if signed.len() != review.final_bytes
        || u64::from(zip317::conventional_actions(&transaction)) * zip317::MARGINAL_FEE
            != review.fee
    {
        return Err("wallet byte/fee estimate differs from the signed transaction".into());
    }
    Ok(Completed::Slh(Box::new(SlhCompleted {
        session,
        _generated: generated,
        proposal,
        review,
        signed,
        persisted_partials,
    })))
}

fn classical(
    config: &PaymentConfig,
    cached: &Cached,
    attempt: u32,
    stages: &mut Stages,
) -> Result<Completed, String> {
    let generated = if config.generated {
        Some(stages.run("payment_inventory_ns", || {
            ClassicalPayment::new(config.version, config.inputs, config.multisig, attempt + 1)
        })?)
    } else {
        None
    };
    let control = match (&generated, cached) {
        (Some(control), _) | (None, Cached::Classical(control)) => control,
        _ => return Err("classical inventory missing".into()),
    };
    let mut transaction = stages.run("payment_assembly_ns", || control.assemble())?;
    stages.run("payment_sign_ns", || control.sign(&mut transaction))?;
    stages.run("payment_verify_ns", || control.verify(&transaction))?;
    let signed = transaction.zcash_serialize_to_vec().map_err(error)?;
    Ok(Completed::Classical(Box::new(ClassicalCompleted {
        _generated: generated,
        transaction,
        signed,
    })))
}

fn perform(
    config: &PaymentConfig,
    cached: &Cached,
    directory: &Path,
    attempt: u32,
    stages: &mut Stages,
) -> Result<Completed, String> {
    match config.algorithm {
        Algorithm::Slh => slh(config, cached, directory, stages),
        Algorithm::Classical => classical(config, cached, attempt, stages),
    }
}

fn inventory_timing(config: &PaymentConfig) -> &'static str {
    if !config.generated {
        CACHED_INVENTORY
    } else if config.algorithm == Algorithm::Slh {
        "wallet creation, key derivation, policy enrollment and verified backup publication inside foreground"
    } else {
        "disposable classical key creation inside foreground"
    }
}

fn artifact_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(error)?;
    if !metadata.is_dir() || fs::read_dir(path).map_err(error)?.next().is_some() {
        return Err("artifact directory must be an existing empty directory, not a symlink".into());
    }
    Ok(())
}

fn publish(path: &Path, artifact: &Value) -> Result<(String, String), String> {
    let bytes = serde_json::to_vec(artifact).map_err(error)?;
    if bytes.len() > 2_000_000 {
        return Err("public payment evidence exceeded 2 MB".into());
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(error)?;
    file.write_all(&bytes).map_err(error)?;
    file.sync_all().map_err(error)?;
    Ok((
        blake3::hash(&bytes).to_hex().to_string(),
        hex::encode(Sha256::digest(&bytes)),
    ))
}

pub fn measure(config: PaymentConfig) -> Result<(), String> {
    artifact_directory(&config.artifact_directory)?;
    let cached_directory = tempfile::tempdir().map_err(error)?;
    let cached = Cached::prepare(&config, cached_directory.path())?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut failed = false;
    for attempt in 0..config.warmup + config.samples {
        let directory = tempfile::tempdir().map_err(error)?;
        let mut stages = Stages::new(true);
        let (completed, mut observation) = observe("payment_total_ns", || {
            perform(&config, &cached, directory.path(), attempt, &mut stages)
        });
        observation.metrics.extend(stages.metrics);
        let name = format!("attempt-{attempt:06}.json");
        let mut details = json!({"fixture_index":attempt,"public_fixture":true,"offline_fixture":true,"trusted_utxos":false,"node_acceptance":false,"inventory_timing":inventory_timing(&config),"measurement_scope":if config.algorithm==Algorithm::Slh {"offline-wallet-with-durable-journal"} else {"classical-transaction-control-no-wallet-journal"}});
        let result = completed.and_then(|completed| {
            observation
                .metrics
                .insert("transaction_bytes".into(), completed.signed().len().into());
            observation
                .metrics
                .insert("input_count".into(), config.inputs.into());
            observation.metrics.insert(
                "signature_count".into(),
                (config.inputs * if config.multisig { 2 } else { 1 }).into(),
            );
            let artifact = completed.finish(&config, &cached, directory.path())?;
            let (blake3, sha256) = publish(&config.artifact_directory.join(&name), &artifact)?;
            details["artifact_path"] = name.into();
            details["artifact_blake3"] = blake3.into();
            details["artifact_sha256"] = sha256.into();
            Ok(())
        });
        let outcome = match result {
            Ok(()) => "success",
            Err(error) => {
                failed = true;
                details["error"] = error.into();
                "error"
            }
        };
        write_record(
            &mut output,
            &record(&config, attempt, "wallet", outcome, observation, details),
        )?;
        if failed {
            break;
        }
    }
    write_record(
        &mut output,
        &record(
            &config,
            config.warmup,
            "process",
            if failed { "error" } else { "success" },
            process_peak(),
            json!({"scope":"one process-lifetime peak through final snapshot; includes setup, warmups, attempts, artifact output and untimed checks; excludes final-record allocation and later teardown","samples":config.samples,"warmup_attempts":config.warmup}),
        ),
    )?;
    if failed {
        return Err("payment attempt failed; partial evidence retained".into());
    }
    Ok(())
}

pub fn check(config: PaymentConfig) -> Result<(), String> {
    artifact_directory(&config.artifact_directory)?;
    let cached_directory = tempfile::tempdir().map_err(error)?;
    let cached = Cached::prepare(&config, cached_directory.path())?;
    let directory = tempfile::tempdir().map_err(error)?;
    let mut stages = Stages::new(false);
    let completed = perform(&config, &cached, directory.path(), 0, &mut stages)?;
    let artifact = completed.finish(&config, &cached, directory.path())?;
    let (blake3, sha256) = publish(
        &config.artifact_directory.join("attempt-000000.json"),
        &artifact,
    )?;
    if !stages.metrics.is_empty() {
        return Err("untimed correctness unexpectedly collected measurements".into());
    }
    println!(
        "{}",
        json!({"case_id":config.case_id(),"correctness":"product-checks-passed","independent_preflight":"required separately","performance_measured":false,"artifact_path":"attempt-000000.json","artifact_blake3":blake3,"artifact_sha256":sha256})
    );
    Ok(())
}

fn record(
    config: &PaymentConfig,
    attempt: u32,
    phase: &str,
    outcome: &str,
    observation: Observation,
    details: Value,
) -> Value {
    json!({"case_id":config.case_id(),"phase":phase,"cache_mode":config.inventory(),"warmup":phase!="process"&&attempt<config.warmup,"outcome":outcome,"metrics":observation.metrics,"unavailable":observation.unavailable,"censored":[],"details":details})
}

fn decode<T: ZcashDeserialize>(bytes: &[u8]) -> Result<T, String> {
    let mut cursor = Cursor::new(bytes);
    let value = T::zcash_deserialize(&mut cursor).map_err(error)?;
    if cursor.position() != bytes.len() as u64 {
        return Err("trailing serialized bytes".into());
    }
    Ok(value)
}

fn decode_hex<T: ZcashDeserialize>(encoded: &str) -> Result<T, String> {
    decode(&hex::decode(encoded).map_err(error)?)
}

fn verify(transaction: &Transaction, previous: Arc<Vec<Output>>) -> Result<(), String> {
    let context = TransactionContext::new(
        transaction,
        NetworkDomain::Regtest,
        NetworkUpgrade::Nu7,
        previous,
    )
    .map_err(error)?;
    for index in 0..transaction.inputs().len() {
        context.verify_input(index).map_err(error)?;
    }
    Ok(())
}

fn inputs_mut(transaction: &mut Transaction) -> Result<&mut Vec<Input>, String> {
    match transaction {
        Transaction::V5 { inputs, .. } | Transaction::V6 { inputs, .. } => Ok(inputs),
        _ => Err("unsupported transaction version".into()),
    }
}

/// These product-side negative controls complement (and never replace) the
/// external independent digest/encoding/primitive checker.
fn negative_controls(artifact: &Value) -> Result<(), String> {
    let transaction: Transaction = decode_hex(
        artifact["transaction_hex"]
            .as_str()
            .ok_or("missing transaction")?,
    )?;
    let previous = Arc::new(
        artifact["previous_outputs_hex"]
            .as_array()
            .ok_or("missing previous outputs")?
            .iter()
            .map(|value| decode_hex::<Output>(value.as_str().ok_or("missing output bytes")?))
            .collect::<Result<Vec<_>, String>>()?,
    );
    let mut changed_previous = previous.as_ref().clone();
    changed_previous[0].value = (u64::from(changed_previous[0].value) + 1)
        .try_into()
        .map_err(error)?;
    if verify(&transaction, Arc::new(changed_previous)).is_ok() {
        return Err("changed fixture prevout value was accepted".into());
    }
    let mut changed = transaction.clone();
    let Input::PrevOut { unlock_script, .. } = &mut inputs_mut(&mut changed)?[0] else {
        return Err("coinbase in payment".into());
    };
    let mut authorization = Authorization::decode(unlock_script.as_raw_bytes()).map_err(error)?;
    authorization.records[0].signature[7855] ^= 1;
    *unlock_script = Script::new(&authorization.encode());
    if verify(&changed, previous.clone()).is_ok() {
        return Err("corrupt signature was accepted".into());
    }
    let mut changed = transaction.clone();
    let Input::PrevOut { unlock_script, .. } = &mut inputs_mut(&mut changed)?[0] else {
        return Err("coinbase in payment".into());
    };
    let mut bytes = unlock_script.as_raw_bytes().to_vec();
    bytes.push(0);
    *unlock_script = Script::new(&bytes);
    if verify(&changed, previous).is_ok() {
        return Err("noncanonical authorization was accepted".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untimed_stage_execution_never_inserts_metrics() {
        let mut stages = Stages::new(false);
        assert_eq!(stages.run("payment_sign_ns", || Ok(17)), Ok(17));
        assert!(stages.metrics.is_empty());
    }

    #[test]
    fn catalog_covers_both_algorithms_and_all_requested_shapes() {
        let cases = cases();
        let unique = cases
            .iter()
            .map(|case| case["case_id"].as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(cases.len(), 48);
        assert_eq!(unique.len(), 48);
    }

    #[test]
    fn artifact_publication_refuses_overwrite_and_nonempty_directory() {
        let directory = tempfile::tempdir().unwrap();
        artifact_directory(directory.path()).unwrap();
        let path = directory.path().join("attempt-000000.json");
        publish(&path, &json!({"offline_fixture":true})).unwrap();
        assert!(publish(&path, &json!({"replacement":true})).is_err());
        assert!(artifact_directory(directory.path()).is_err());
    }
}
