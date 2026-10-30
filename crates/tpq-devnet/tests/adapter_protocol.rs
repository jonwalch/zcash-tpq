#![cfg(feature = "adapter")]
use serde_json::{json, Value};
use zakura_tpq_devnet::adapter::{self, Pin};

#[test]
fn describe_is_strict_bound_and_never_reads_seed_bytes() {
    let request = json!({"protocol":adapter::PROTOCOL,"operation":"describe","requestId":"00000000-0000-4000-8000-000000000000","adapterSelectionSha256":"ab".repeat(32),"input":{"adapterId":adapter::ADAPTER_ID,"adapterVersion":adapter::VERSION,"preparedInputSchema":adapter::SCHEMA}});
    let bytes = serde_json::to_vec(&request).unwrap();
    let response = adapter::respond(&bytes, || panic!("describe must not read seeds")).unwrap();
    let response: Value = serde_json::from_slice(&response).unwrap();
    for name in [
        "protocol",
        "operation",
        "requestId",
        "adapterSelectionSha256",
    ] {
        assert_eq!(request[name], response[name]);
    }
    assert!(response.get("context").is_none());
    assert_eq!(
        response["result"]["operations"],
        json!(["describe", "compile", "render"])
    );
    for (field, value) in [
        ("requestId", json!("stale")),
        ("adapterSelectionSha256", json!("XX".repeat(32))),
        ("operation", json!("execute")),
    ] {
        let mut bad = request.clone();
        bad[field] = value;
        assert!(
            adapter::respond(&serde_json::to_vec(&bad).unwrap(), || panic!(
                "bad request must not read seeds"
            ))
            .is_err()
        );
    }
    let mut bad = request;
    bad["input"]["unknown"] = true.into();
    assert!(
        adapter::respond(&serde_json::to_vec(&bad).unwrap(), || panic!(
            "unknown fields must not read seeds"
        ))
        .is_err()
    );
}

#[test]
fn nested_duplicate_unknown_array_and_float_contracts_are_rejected() {
    for raw in [
        r#"[1,"ab"]"#,
        r#"{"bytes":1,"bytes":2,"sha256":"ab"}"#,
        r#"{"bytes":1.0,"sha256":"ab"}"#,
        r#"{"bytes":1,"sha256":"ab","privateKey":"x"}"#,
    ] {
        assert!(adapter::parse::<Pin>(raw.as_bytes()).is_err(), "{raw}");
    }
    let bytes=br#"{"protocol":"x","protocol":"y","operation":"describe","requestId":"x","adapterSelectionSha256":"x","input":{}}"#;
    assert!(adapter::respond(bytes, || panic!("duplicate envelope must not read seeds")).is_err());
}

#[test]
fn importer_refuses_invalid_public_sources_without_executing_or_creating_output() {
    use std::{fs, process::Command};
    let directory = tempfile::tempdir().unwrap();
    let chain = directory.path().join("chain.json");
    let profile = directory.path().join("wallet-profile.json");
    let host = directory.path().join("host-adapter");
    let output = directory.path().join("export");
    let marker = directory.path().join("executed");
    fs::write(&chain, b"{}").unwrap();
    fs::write(&profile, b"{}").unwrap();
    fs::write(&host, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    let host_pin = Pin::of(&fs::read(&host).unwrap());
    let status = Command::new(env!("CARGO_BIN_EXE_zdn-tpq-import"))
        .arg(&chain)
        .arg(&profile)
        .arg(&host)
        .arg(host_pin.sha256)
        .arg("01".repeat(32))
        .arg("02".repeat(20))
        .arg(&output)
        .output()
        .unwrap();
    assert!(!status.status.success());
    assert!(status.stdout.is_empty());
    assert!(!output.exists());
    assert!(!marker.exists());
    // Inputs are never reflected in fixed diagnostics, including parser errors.
    assert!(!String::from_utf8_lossy(&status.stderr).contains(&chain.display().to_string()));
}
