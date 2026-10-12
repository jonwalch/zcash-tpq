//! Explicit human-run primitive measurements using the actual product APIs.
//! No transaction, secret seed, signature, or entropy bytes are emitted.

mod config;
mod fixture;
mod measurement;

use std::{
    hint::black_box,
    io::{self, Write},
    process::ExitCode,
};

use config::{CacheMode, Case, Command, Config};
use fixture::SignatureFixture;
use measurement::{observe, process_peak, Observation};
use serde_json::{json, Value};
use zakura_pq_slh_dsa_b_sign::{SigningKey, MESSAGE_BYTES, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use zakura_pq_slh_dsa_b_verify::{verify, VerifyError};

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tpq-bench: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<(), String> {
    match config::parse(std::env::args().skip(1))? {
        Command::Help => println!("{}", config::HELP),
        Command::List => println!(
            "{}",
            json!({"cases": Case::ALL.map(|case| json!({
                "case": case.name(), "case_id": case.id(), "phase": "primitive",
                "timing_metric": case.timing_metric(), "human_execution_required": true,
            }))})
        ),
        Command::Metadata => println!("{}", metadata()),
        Command::Measure(config) => measure(config)?,
    }
    Ok(())
}

fn metadata() -> Value {
    json!({
        "producer": "tpq-bench", "producer_version": env!("CARGO_PKG_VERSION"),
        "contract": "slh-dsa-b-128s-exp-v1", "blake3_version": "1.8.5",
        "target_os": std::env::consts::OS, "target_arch": std::env::consts::ARCH,
        "debug_assertions": cfg!(debug_assertions), "human_execution_required": true,
        "max_samples": config::MAX_SAMPLES, "max_warmup": config::MAX_WARMUP,
        "cache_modes": ["repeated-input", "varied-input"],
        "public_key_bytes": PUBLIC_KEY_BYTES, "signature_bytes": SIGNATURE_BYTES,
        "message_bytes": MESSAGE_BYTES, "context_bytes": 0,
        "keygen_boundary": "SigningKey::from_seed: complete public root; seed derivation excluded; key drop excluded",
        "sign_boundary": "SigningKey::sign: OS entropy, signing, mandatory local verification, and signature release",
        "verify_boundary": "verify: external Pure interface with empty context; fixture preparation excluded",
        "rss_boundary": "primitive endpoint resident sizes; one final process_peak_rss_bytes snapshot includes setup, warmups, attempts, and prior output, but excludes final-record allocation and later teardown",
        "cpu_boundary": "getrusage process user+system delta; includes timer boundary overhead; ratio is CPU/wall, not host utilization",
        "preflight": "untimed valid and same-length last-byte-corrupted signature checks",
        "fixture_security": "synthetic public seeds; never use benchmark keys for funds",
        "cache_boundary": "input reuse only; no processor or OS cache flush; varied verification signs a fresh fixture before each timer",
    })
}

fn measure(config: Config) -> Result<(), String> {
    // All cases validate the actual signing/verifying flow outside observation
    // windows. Keygen/sign costs here remain visible in process-lifetime RSS.
    let key = SigningKey::from_seed(fixture::seed(0));
    let mut repeated = SignatureFixture::prepare(&key, 0)?;
    if config.case == Case::VerifyInvalid {
        repeated.corrupt();
    }

    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut errors = false;
    // The independently bounded arguments make this sum at most 11,000.
    for attempt in 0..config.warmup + config.samples {
        let index = config.cache_mode.input_index(attempt);
        let (mut observation, outcome, mut details) = match config.case {
            Case::Keygen => {
                let seed = fixture::seed(index);
                let (generated, observation) = observe(config.case.timing_metric(), || {
                    SigningKey::from_seed(black_box(seed))
                });
                let details = json!({"public_key_blake3": hash(generated.public_key())});
                (observation, "success", details)
            }
            Case::Sign => {
                let message = fixture::message(index);
                let (signature, observation) = observe(config.case.timing_metric(), || {
                    black_box(&key).sign(black_box(&message))
                });
                let mut details = json!({
                    "public_key_blake3": hash(key.public_key()),
                    "message_blake3": hash(&message), "signing_randomness": "fresh-os-entropy",
                    "mandatory_local_verification": true,
                });
                let outcome = match signature {
                    Ok(signature) => {
                        details["signature_blake3"] = hash(&*signature).into();
                        if verify(key.public_key(), &*signature, &message, &[]).is_ok() {
                            "success"
                        } else {
                            details["error"] = "untimed post-sign verification failed".into();
                            "error"
                        }
                    }
                    Err(error) => {
                        details["error"] = error.to_string().into();
                        "error"
                    }
                };
                (observation, outcome, details)
            }
            Case::Verify | Case::VerifyInvalid => {
                let varied;
                let fixture = if config.cache_mode == CacheMode::VariedInput {
                    let mut prepared = SignatureFixture::prepare(&key, index)?;
                    if config.case == Case::VerifyInvalid {
                        prepared.corrupt();
                    }
                    varied = prepared;
                    &varied
                } else {
                    &repeated
                };
                let (verified, observation) = observe(config.case.timing_metric(), || {
                    verify(
                        black_box(key.public_key()),
                        black_box(&*fixture.signature),
                        black_box(&fixture.message),
                        black_box(&[]),
                    )
                });
                let mut details = json!({
                    "public_key_blake3": hash(key.public_key()),
                    "message_blake3": hash(&fixture.message),
                    "signature_blake3": hash(&*fixture.signature),
                    "mutation": if config.case == Case::VerifyInvalid { "last-byte-xor-1" } else { "none" },
                });
                let outcome = match (config.case, verified) {
                    (Case::Verify, Ok(())) => "success",
                    (Case::VerifyInvalid, Err(VerifyError::InvalidSignature)) => {
                        "expected_rejection"
                    }
                    (_, result) => {
                        details["error"] =
                            format!("unexpected verification result: {result:?}").into();
                        "error"
                    }
                };
                (observation, outcome, details)
            }
        };
        observation
            .metrics
            .insert("public_key_bytes".into(), PUBLIC_KEY_BYTES.into());
        if config.case != Case::Keygen {
            observation
                .metrics
                .insert("message_bytes".into(), MESSAGE_BYTES.into());
            if config.case == Case::Sign && outcome == "error" {
                observation
                    .metrics
                    .insert("signature_bytes".into(), Value::Null);
                observation.unavailable.insert(
                    "signature_bytes".into(),
                    "signing attempt did not produce a valid released signature".into(),
                );
            } else {
                observation
                    .metrics
                    .insert("signature_bytes".into(), SIGNATURE_BYTES.into());
            }
        }
        details["fixture_index"] = index.into();
        details["public_fixture"] = true.into();
        let record = record(config, attempt, observation, outcome, details);
        write_record(&mut output, &record)?;
        errors |= outcome == "error";
    }
    let final_record = process_record(config, process_peak(), errors);
    write_record(&mut output, &final_record)?;
    if errors {
        return Err("one or more attempts failed; error records were emitted".into());
    }
    Ok(())
}

fn write_record(output: &mut impl Write, record: &Value) -> Result<(), String> {
    serde_json::to_writer(&mut *output, record).map_err(|error| error.to_string())?;
    output.write_all(b"\n").map_err(|error| error.to_string())?;
    output.flush().map_err(|error| error.to_string())
}

fn hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn record(
    config: Config,
    attempt: u32,
    observation: Observation,
    outcome: &str,
    details: Value,
) -> Value {
    json!({
        "case_id": config.case.id(), "phase": "primitive", "cache_mode": config.cache_mode.name(),
        "warmup": attempt < config.warmup, "outcome": outcome,
        "metrics": observation.metrics, "unavailable": observation.unavailable,
        "censored": [], "details": details,
    })
}

fn process_record(config: Config, observation: Observation, errors: bool) -> Value {
    json!({
        "case_id": config.case.id(), "phase": "process", "cache_mode": config.cache_mode.name(),
        "warmup": false, "outcome": if errors { "error" } else { "success" },
        "metrics": observation.metrics, "unavailable": observation.unavailable,
        "censored": [], "details": {
            "scope": "one process-lifetime peak through the final snapshot; includes setup, warmups, attempts, and prior output; excludes final-record allocation and later teardown",
            "samples": config.samples, "warmup_attempts": config.warmup,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;

    #[test]
    fn metadata_and_case_list_do_not_need_fixtures() {
        let metadata = metadata();
        assert_eq!(metadata["message_bytes"], 101);
        assert_eq!(metadata["public_key_bytes"], 32);
        assert_eq!(metadata["signature_bytes"], 7856);
        assert_eq!(metadata["blake3_version"], "1.8.5");
        assert!(metadata["human_execution_required"].as_bool().unwrap());
        assert_eq!(Case::ALL.len(), 4);
        assert_eq!(Case::Sign.timing_metric(), "sign_release_ns");
    }

    #[test]
    fn raw_records_preserve_warmups_unavailable_and_expected_rejections() {
        let config = Config {
            case: Case::VerifyInvalid,
            samples: 2,
            warmup: 1,
            cache_mode: CacheMode::RepeatedInput,
        };
        let observation = Observation {
            metrics: Map::from_iter([("process_cpu_ns".into(), Value::Null)]),
            unavailable: Map::from_iter([("process_cpu_ns".into(), "unavailable in test".into())]),
        };
        let raw = record(
            config,
            0,
            observation,
            "expected_rejection",
            json!({"public_fixture": true}),
        );
        assert_eq!(raw["case_id"], "primitive.verify-invalid");
        assert_eq!(raw["phase"], "primitive");
        assert_eq!(raw["warmup"], true);
        assert_eq!(raw["outcome"], "expected_rejection");
        assert!(raw["metrics"]["process_cpu_ns"].is_null());
        assert_eq!(raw["unavailable"]["process_cpu_ns"], "unavailable in test");
        assert_eq!(raw["censored"], json!([]));
        assert!(
            raw.get("schema_version").is_none(),
            "the parent assigns run identity and schema"
        );
    }

    #[test]
    fn lifetime_peak_has_one_separate_final_process_record() {
        let config = Config {
            case: Case::VerifyInvalid,
            samples: 2,
            warmup: 1,
            cache_mode: CacheMode::RepeatedInput,
        };
        let observation = Observation {
            metrics: Map::from_iter([("process_peak_rss_bytes".into(), 12_288.into())]),
            unavailable: Map::new(),
        };
        let raw = process_record(config, observation, false);
        assert_eq!(raw["case_id"], "primitive.verify-invalid");
        assert_eq!(raw["phase"], "process");
        assert_eq!(raw["warmup"], false);
        assert_eq!(raw["outcome"], "success");
        assert_eq!(raw["metrics"].as_object().unwrap().len(), 1);
        assert_eq!(raw["metrics"]["process_peak_rss_bytes"], 12_288);
        assert_eq!(raw["details"]["samples"], 2);
        assert_eq!(raw["details"]["warmup_attempts"], 1);

        let unavailable = Observation {
            metrics: Map::from_iter([("process_peak_rss_bytes".into(), Value::Null)]),
            unavailable: Map::from_iter([(
                "process_peak_rss_bytes".into(),
                "OS query failed".into(),
            )]),
        };
        let failed = process_record(config, unavailable, true);
        assert_eq!(failed["outcome"], "error");
        assert!(failed["metrics"]["process_peak_rss_bytes"].is_null());
        assert_eq!(
            failed["unavailable"]["process_peak_rss_bytes"],
            "OS query failed"
        );
    }
}
