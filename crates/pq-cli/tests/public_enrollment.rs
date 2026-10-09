//! Nonterminal public command comparisons against independent retained answers.
#![cfg(all(unix, feature = "experimental-slh-dsa-b128s"))]

use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn corpus() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../../tests/slh-dsa-b128s/wallet/interfaces/vectors.json"
    ))
    .unwrap()
}

fn write_private(path: &Path, raw: &str) {
    fs::write(path, raw).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn run(directory: &Path, case: &Value, keys: &[Value]) -> std::process::Output {
    write_private(
        &directory.join("profile.json"),
        corpus()["profile_json"].as_str().unwrap(),
    );
    write_private(
        &directory.join("previous.json"),
        case["previous_json"].as_str().unwrap(),
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_pq-wallet"));
    command
        .current_dir(directory)
        .args([
            "enroll-prepare",
            "profile.json",
            "previous.json",
            if case["role"] == 0 {
                "receive"
            } else {
                "change"
            },
            &case["threshold"].as_u64().unwrap().to_string(),
            "candidate.json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (index, key) in keys.iter().enumerate() {
        let path = format!("key-{index}.json");
        write_private(&directory.join(&path), key["json"].as_str().unwrap());
        command.args([&path, key["fingerprint"].as_str().unwrap()]);
    }
    // Reuse the polling/kill pattern of zakura-test's
    // TestChild::wait_with_output_or_timeout without a new framework dependency.
    // These public responses fit in the pipes. A regressed child that fills a
    // pipe cannot block this polling thread; it is killed before output drains.
    let mut child = command.spawn().unwrap();
    let started = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if started.elapsed() >= Duration::from_secs(10) {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "public enrollment command timed out: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn public_enrollment_command_matches_independent_cumulative_inventory_answers() {
    for case in corpus()["enrollments"].as_array().unwrap() {
        let directory = tempfile::tempdir().unwrap();
        let output = run(directory.path(), case, case["keys"].as_array().unwrap());
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(directory.path().join("candidate.json")).unwrap(),
            case["inventory_json"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            json!({
                "fingerprint": case["inventory_fingerprint"],
                "inventory": serde_json::from_str::<Value>(case["inventory_json"].as_str().unwrap()).unwrap(),
                "threshold": case["threshold"],
            })
        );
        // Repeating the command cannot replace a covering candidate file.
        let retry = run(directory.path(), case, case["keys"].as_array().unwrap());
        assert!(!retry.status.success());
        assert_eq!(
            fs::read(directory.path().join("candidate.json")).unwrap(),
            case["inventory_json"].as_str().unwrap().as_bytes()
        );
    }
}

#[test]
fn public_enrollment_rejects_transport_and_pairing_mutations_without_output() {
    let corpus = corpus();
    let case = &corpus["enrollments"][0];
    for mutation in [
        "fingerprint",
        "newline",
        "duplicate",
        "unknown",
        "oversize",
        "suite",
        "key",
    ] {
        let mut keys = case["keys"].as_array().unwrap().clone();
        let raw = keys[0]["json"].as_str().unwrap().to_string();
        match mutation {
            "fingerprint" => keys[0]["fingerprint"] = "00".repeat(32).into(),
            "newline" => keys[0]["json"] = format!("{raw}\n").into(),
            "duplicate" => {
                keys[0]["json"] = raw
                    .replace("\"suite\":247", "\"suite\":247,\"suite\":247")
                    .into()
            }
            "unknown" => keys[0]["json"] = format!("{},\"zzz\":0}}", &raw[..raw.len() - 1]).into(),
            "oversize" => keys[0]["json"] = " ".repeat(4097).into(),
            "suite" => keys[0]["json"] = raw.replace("\"suite\":247", "\"suite\":1").into(),
            "key" => {
                let mut value: Value = serde_json::from_str(&raw).unwrap();
                value["public_key_hex"] = "ab".repeat(32).into();
                keys[0]["json"] = serde_json::to_string(&value).unwrap().into();
            }
            _ => unreachable!(),
        }
        let directory = tempfile::tempdir().unwrap();
        let output = run(directory.path(), case, &keys);
        assert!(!output.status.success(), "{mutation}");
        assert!(
            !directory.path().join("candidate.json").exists(),
            "{mutation}"
        );
        assert!(output.stdout.is_empty(), "{mutation}");
        if matches!(mutation, "fingerprint" | "key") {
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("public key pairing fingerprint mismatch"),
                "{mutation}"
            );
        }
    }
}

#[test]
fn independently_paired_keys_cannot_be_reused_in_the_wrong_enrollment_context() {
    let corpus = corpus();
    let base = &corpus["enrollments"][0];
    for mutation in ["role", "missing-local", "duplicate", "next-index"] {
        let mut case = base.clone();
        let mut keys = case["keys"].as_array().unwrap().clone();
        match mutation {
            "role" => case["role"] = 1.into(),
            // Keys are reverse ordered; local key is last.
            "missing-local" => {
                keys.pop();
            }
            "duplicate" => {
                keys[1] = keys[0].clone();
            }
            "next-index" => {
                case["previous_json"] = corpus["enrollments"][2]["previous_json"].clone();
            }
            _ => unreachable!(),
        }
        let directory = tempfile::tempdir().unwrap();
        let output = run(directory.path(), &case, &keys);
        assert!(!output.status.success(), "{mutation}");
        assert!(
            !directory.path().join("candidate.json").exists(),
            "{mutation}"
        );
        assert!(output.stdout.is_empty(), "{mutation}");
        let error = String::from_utf8_lossy(&output.stderr);
        let expected = match mutation {
            "role" | "duplicate" => "cosigner profile, role, suite or participant mismatch",
            "missing-local" => "policy must contain the local wallet",
            "next-index" => "local key must use the next cumulative inventory index",
            _ => unreachable!(),
        };
        assert!(error.contains(expected), "{mutation}: {error}");
    }
}
