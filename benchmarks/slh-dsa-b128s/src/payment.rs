//! Offline product wallet lifecycle measurements. The synthetic node adapter is
//! adapted from product wallet tests; the foreground/evidence split follows
//! research `experiments/hash-four-payments/common/src/payment.rs` at
//! 53a6e4bd1c11d90349fd3d989507f0e1a4995112 (MIT OR Apache-2.0).
//! Production approval, enrollment, signing and journal APIs remain unchanged.

use std::{
    fs::{self, OpenOptions},
    io::{self, Cursor, Write},
    ops::Range,
    path::{Path, PathBuf},
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
    payment_fixture::{self, Inventory, OfflineSource, Session},
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
        "slh_boundary": "foreground wraps optional fresh enrolled inventory, fresh WatchStore setup and scan, prepare_payment, threshold sign_payment calls, assemble_payment, and full TransactionContext input verification; generated inventory requires synthetic source preparation inside total after keys exist",
        "fixture_boundary": "synthetic source responses are prepared outside wallet setup; cached SLH preparation is also outside total/CPU, but generated SLH preparation remains inside total/CPU after key generation; lookups use prepared hashes and bytes",
        "durability_boundary": "production wallet stages include their mandatory journal writes and file/directory syncs; persistence is not separately attributable from those APIs",
        "classical_boundary": "matched transparent P2SH transaction assembly, secp256k1 signing and script-aware verification; no SLH wallet lifecycle or durability comparison",
        "inventory_boundary": "cached means public enrolled inventory prepared outside foreground; both modes derive secret SigningKey afresh during actual Wallet signing; no CPU/OS cache flush",
        "generated_inventory_boundary": "Wallet creation, all participant receive/change public key derivations, policy enrollment, recipient creation and verified encrypted backup publication",
        "correctness_boundary": "check-payment executes one untimed fixture without Instant/getrusage/RSS snapshots, writes public evidence and checks reopen/negative controls; independent checker is separate",
        "artifact_boundary": "canonical signed/unsigned transaction, ordered fixture previous outputs and derived messages; no secrets or backup files; artifact encoding, negative controls, durable reopen checks and output excluded from foreground",
        "matched_workload": "each input 10000000 zat; recipient inputs*10000000-5000000 zat; each algorithm uses current 400-zat marginal fee and exact serialized actions; change therefore differs",
        "ephemeral_state": "fresh private temporary WatchStores each attempt, empty prior history; this is not long-lived journal growth or cold disk-cache behavior",
        "storage_boundary": "private stores and disposable backups are created only beneath the explicit wallet-storage-root; registered runs bind that directory and its declared storage profile; TMPDIR is ignored",
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
                            wallet_storage_root: "unused".into(),
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
    transaction: Transaction,
    persisted_partials: RetainedPartials,
}

/// Own each returned partial once, while retaining signer boundaries for the
/// untimed durable readback. Moving partials does not copy their signature text.
#[derive(Default)]
struct RetainedPartials {
    records: Vec<Partial>,
    signers: Vec<Range<usize>>,
}

impl RetainedPartials {
    fn push_signer(&mut self, partials: Vec<Partial>) {
        let start = self.records.len();
        self.records.extend(partials);
        self.signers.push(start..self.records.len());
    }
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
                    transaction,
                    persisted_partials,
                    ..
                } = *result;
                // Closing and reopening proves the wallet can recover the actual
                // signed bytes/partials, without counting readback as signing cost.
                drop(session);
                for (index, range) in persisted_partials.signers.iter().enumerate() {
                    let expected = &persisted_partials.records[range.clone()];
                    let store = WatchStore::open(
                        &directory.join(format!("watch-{index}")),
                        &payment_fixture::profile(),
                    )
                    .map_err(error)?;
                    let records = store.payments().map_err(error)?;
                    if records.len() != 1
                        || records[0].partials.as_slice() != expected
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
    prepared_source: Option<OfflineSource>,
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
    let source = if config.generated {
        // Fresh funding scripts depend on the just-generated inventory. This
        // fixture preparation remains inside the enclosing total, but not the
        // wallet-setup stage. Cached cases prepare it before the total starts.
        OfflineSource::new(&inventory.wallets[0], config.inputs).map_err(error)?
    } else {
        prepared_source.ok_or("cached SLH source was not prepared outside timing")?
    };
    let mut session = stages.run("payment_wallet_setup_ns", || {
        Session::new(inventory, source, directory).map_err(error)
    })?;
    let (proposal, review) = stages.run("payment_prepare_persist_ns", || {
        session.stores[0]
            .prepare_payment(&inventory.wallets[0], &mut session.source, &intent)
            .map_err(error)
    })?;
    if proposal.inputs.len() != config.inputs
        || usize::try_from(review.checks).map_err(error)?
            != config.inputs * if config.multisig { 2 } else { 1 }
    {
        return Err("wallet selected a different input/policy workload".into());
    }
    let partials = stages.run("payment_sign_persist_ns", || {
        let mut partials = RetainedPartials::default();
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
            partials.push_signer(signed);
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
                &partials.records,
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
        transaction,
        persisted_partials: partials,
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
    prepared_source: Option<OfflineSource>,
    stages: &mut Stages,
) -> Result<Completed, String> {
    match config.algorithm {
        Algorithm::Slh => slh(config, cached, directory, prepared_source, stages),
        Algorithm::Classical => classical(config, cached, attempt, stages),
    }
}

fn prepare_cached_source(
    config: &PaymentConfig,
    cached: &Cached,
) -> Result<Option<OfflineSource>, String> {
    match cached {
        Cached::Slh(inventory) => OfflineSource::new(&inventory.wallets[0], config.inputs)
            .map(Some)
            .map_err(error),
        _ => Ok(None),
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

fn wallet_storage_root(config: &PaymentConfig) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(&config.wallet_storage_root).map_err(error)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("wallet storage root must be an existing directory, not a symlink".into());
    }
    let root = config.wallet_storage_root.canonicalize().map_err(error)?;
    let artifacts = config.artifact_directory.canonicalize().map_err(error)?;
    if root.starts_with(artifacts) {
        return Err("private wallet storage must be outside public artifacts".into());
    }
    Ok(root)
}

fn wallet_directory(root: &Path) -> Result<tempfile::TempDir, String> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("tpq-wallet-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    builder.tempdir_in(root).map_err(error)
}

pub fn measure(config: PaymentConfig) -> Result<(), String> {
    artifact_directory(&config.artifact_directory)?;
    let storage = wallet_storage_root(&config)?;
    let cached_directory = wallet_directory(&storage)?;
    let cached = Cached::prepare(&config, cached_directory.path())?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut failed = false;
    for attempt in 0..config.warmup + config.samples {
        let directory = wallet_directory(&storage)?;
        let prepared_source = prepare_cached_source(&config, &cached)?;
        let mut stages = Stages::new(true);
        let (completed, mut observation) = observe("payment_total_ns", || {
            perform(
                &config,
                &cached,
                directory.path(),
                attempt,
                prepared_source,
                &mut stages,
            )
        });
        observation.metrics.extend(stages.metrics);
        let name = format!("attempt-{attempt:06}.json");
        let mut details = json!({"fixture_index":attempt,"public_fixture":true,"offline_fixture":true,"trusted_utxos":false,"node_acceptance":false,"inventory_timing":inventory_timing(&config),"synthetic_source_preparation_inside_total":config.algorithm==Algorithm::Slh && config.generated,"measurement_scope":if config.algorithm==Algorithm::Slh {"offline-wallet-with-durable-journal"} else {"classical-transaction-control-no-wallet-journal"}});
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
    let storage = wallet_storage_root(&config)?;
    let cached_directory = wallet_directory(&storage)?;
    let cached = Cached::prepare(&config, cached_directory.path())?;
    let directory = wallet_directory(&storage)?;
    let prepared_source = prepare_cached_source(&config, &cached)?;
    let mut stages = Stages::new(false);
    let completed = perform(
        &config,
        &cached,
        directory.path(),
        0,
        prepared_source,
        &mut stages,
    )?;
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
    if cursor.position() != u64::try_from(bytes.len()).map_err(error)? {
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
    let Input::PrevOut { unlock_script, .. } = &mut changed.inputs_mut()[0] else {
        return Err("coinbase in payment".into());
    };
    let mut authorization = Authorization::decode(unlock_script.as_raw_bytes()).map_err(error)?;
    authorization.records[0].signature[7855] ^= 1;
    *unlock_script = Script::new(&authorization.encode());
    if verify(&changed, previous.clone()).is_ok() {
        return Err("corrupt signature was accepted".into());
    }
    let mut changed = transaction.clone();
    let Input::PrevOut { unlock_script, .. } = &mut changed.inputs_mut()[0] else {
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
    fn signer_groups_retain_signature_ownership_without_copying() {
        let partial = |input_index, signer_index| Partial {
            format: "test".into(),
            input_index,
            proposal_id: zakura_pq_wallet::Hex([0x42; 32]),
            public_key_hex: "ab".repeat(32),
            signature_hex: "cd".repeat(7856),
            signer_index,
        };
        let first = vec![partial(0, 0), partial(1, 0)];
        let second = vec![partial(0, 1), partial(1, 1)];
        let pointers = first
            .iter()
            .chain(&second)
            .map(|partial| partial.signature_hex.as_ptr())
            .collect::<Vec<_>>();
        let mut retained = RetainedPartials::default();
        retained.push_signer(first);
        retained.push_signer(second);
        assert_eq!(retained.signers, [0..2, 2..4]);
        for (partial, pointer) in retained.records.iter().zip(pointers) {
            assert_eq!(partial.signature_hex.as_ptr(), pointer);
        }
        assert_eq!(
            retained.records[retained.signers[0].clone()][1].input_index,
            1
        );
        assert_eq!(
            retained.records[retained.signers[1].clone()][0].signer_index,
            1
        );
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

    #[test]
    fn wallet_storage_is_explicit_private_and_outside_public_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let public = directory.path().join("public");
        let storage = directory.path().join("storage");
        fs::create_dir(&public).unwrap();
        fs::create_dir(&storage).unwrap();
        let mut config = PaymentConfig {
            algorithm: Algorithm::Slh,
            version: 5,
            multisig: false,
            inputs: 1,
            generated: false,
            samples: 1,
            warmup: 0,
            artifact_directory: public.clone(),
            wallet_storage_root: storage.clone(),
        };
        let root = wallet_storage_root(&config).unwrap();
        let private = wallet_directory(&root).unwrap();
        assert_eq!(private.path().parent(), Some(root.as_path()));
        assert_eq!(fs::read_dir(&public).unwrap().count(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(private.path()).unwrap().permissions().mode() & 0o777,
                0o700
            );
            let alias = directory.path().join("storage-alias");
            std::os::unix::fs::symlink(&storage, &alias).unwrap();
            config.wallet_storage_root = alias;
            assert!(wallet_storage_root(&config).is_err());
        }
        config.wallet_storage_root = public.clone();
        assert!(wallet_storage_root(&config).is_err());
        config.wallet_storage_root = public.join("nested");
        fs::create_dir(&config.wallet_storage_root).unwrap();
        assert!(wallet_storage_root(&config).is_err());
        config.wallet_storage_root = directory.path().join("missing");
        assert!(wallet_storage_root(&config).is_err());
        fs::write(&config.wallet_storage_root, b"not a directory").unwrap();
        assert!(wallet_storage_root(&config).is_err());
    }
}
