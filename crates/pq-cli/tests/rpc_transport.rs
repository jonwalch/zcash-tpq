//! Offline CLI transport selection and identity checks, without wallet secrets.
#![cfg(all(unix, feature = "experimental-slh-dsa-b128s"))]

use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zakura_pq_wallet::{Hex, Manifest, WatchMode, WatchStore};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pq-wallet"));
    command.stdin(Stdio::null());
    command
}

#[test]
fn help_and_mutual_exclusion_apply_before_any_command() {
    let help = command().arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    for text in [
        "--trusted-local-gateway",
        "mutually exclusive",
        "numeric",
        "never falls back",
    ] {
        assert!(help.contains(text));
    }
    for args in [
        vec!["--rpc-cookie", "missing-cookie", "--trusted-local-gateway"],
        vec!["--trusted-local-gateway", "--rpc-cookie", "missing-cookie"],
        vec![
            "--json",
            "--trusted-local-gateway",
            "--rpc-cookie",
            "missing-cookie",
        ],
    ] {
        // Even --help must refuse contradictory global transport selection.
        let output = command().args(args).arg("--help").output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("mutually exclusive"));
    }
    assert!(command()
        .args(["--trusted-local-gateway", "--help"])
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn custom_testnet_needs_explicit_mode_and_gateway_still_rejects_missing_identity() {
    let temp = tempfile::tempdir().unwrap();
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
    ))
    .unwrap();
    let mut manifest =
        Manifest::from_json(corpus["inventory_json"].as_str().unwrap().as_bytes()).unwrap();
    manifest.profile.network = 1;
    manifest.profile.chain_fingerprint = Some(Hex([7; 32]));
    manifest.derivation_version = 2;
    manifest.format = "ZcashTransparentPQ/inventory/v2".into();
    let profile = temp.path().join("profile.json");
    std::fs::write(&profile, serde_json::to_vec(&manifest.profile).unwrap()).unwrap();
    let watch = temp.path().join("watch");
    drop(
        WatchStore::create(
            &watch,
            &manifest.to_json().unwrap(),
            manifest.fingerprint().unwrap(),
            &manifest.profile,
            WatchMode::Monitor,
        )
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let socket = listener.local_addr().unwrap().to_string();
    let invoke = |options: &[&str], endpoint: &str| {
        command()
            .args(options)
            .arg("sync")
            .arg(&profile)
            .arg(&watch)
            .arg(endpoint)
            .arg("1")
            .output()
            .unwrap()
    };
    let default = invoke(&[], &socket);
    assert!(!default.status.success());
    assert!(String::from_utf8(default.stderr)
        .unwrap()
        .contains("custom Testnet requires"));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    for endpoint in [
        "127.0.0.1:0",
        "192.0.2.1:8232",
        "localhost:8232",
        "http://127.0.0.1:8232",
    ] {
        assert!(!invoke(&["--trusted-local-gateway"], endpoint)
            .status
            .success());
    }
    // Missing cookie is not a request to select the gateway.
    assert!(!invoke(&["--rpc-cookie", "missing-cookie"], &socket)
        .status
        .success());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "gateway request not received");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() < 16_384);
        }
        let header = String::from_utf8(header).unwrap();
        assert!(!header.to_ascii_lowercase().contains("authorization:"));
        let length: usize = header
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["method"],
            "getblockchaininfo"
        );
        // A custom Testnet cannot accept legacy Regtest's missing diagnostics.
        let body = serde_json::to_vec(&json!({"id":1,"result":{
            "chain":"test", "blocks":0, "bestblockhash":"00".repeat(32),
            "consensus":{"nextblock":"00000000"},
            "upgrades":{"77190ad9":{"activationheight":105}}
        }}))
        .unwrap();
        write!(
            stream,
            "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
        listener
    });
    let output = invoke(&["--trusted-local-gateway"], &socket);
    assert!(!output.status.success());
    assert!(!String::from_utf8(output.stderr)
        .unwrap()
        .contains("requires --rpc-cookie"));
    let listener = server.join().unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
