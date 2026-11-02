//! Fake-loopback transport only. No nodes, proofs, generated chains or cloud.
#![cfg(all(unix, feature = "wallet"))]

use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::Command,
    time::{Duration, Instant},
};
use zakura_tpq_devnet::{
    rpc::{HttpRpc, Rpc},
    storage,
};

const SMALL: usize = 2 * 1024 * 1024;
const LARGE: usize = 40_100_000;

fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "missing transport request");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("{error}"),
        }
    }
}

fn request(stream: &mut TcpStream) -> (String, Value) {
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
    let length: usize = header
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .unwrap()
        .parse()
        .unwrap();
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    (header, serde_json::from_slice(&body).unwrap())
}

fn reply(stream: &mut TcpStream, body: Value) {
    let body = serde_json::to_vec(&body).unwrap();
    write!(
        stream,
        "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(&body).unwrap();
}

#[test]
fn gateway_sends_no_authorization_and_large_hex_can_cross_small_body_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut rpc = HttpRpc::trusted_local_gateway(listener.local_addr().unwrap()).unwrap();
    let transaction = "0123456789abcdef".repeat(SMALL / 16 + 1);
    let expected_transaction = transaction.clone();
    let server = std::thread::spawn(move || {
        for method in ["getblock", "getrawtransaction", "sendrawtransaction"] {
            let mut stream = accept(&listener);
            let (header, body) = request(&mut stream);
            assert!(!header.to_ascii_lowercase().contains("authorization:"));
            assert_eq!(body["id"], 1);
            assert_eq!(body["method"], method);
            if method == "sendrawtransaction" {
                assert_eq!(body["params"], json!([expected_transaction]));
                reply(&mut stream, json!({"id":1,"result":"txid"}));
            } else {
                assert_eq!(body["params"], json!(["hash", 0]));
                reply(&mut stream, json!({"id":1,"result":"0".repeat(SMALL + 2)}));
            }
        }
    });
    for method in ["getblock", "getrawtransaction"] {
        assert_eq!(
            rpc.call(method, json!(["hash", 0]))
                .unwrap()
                .as_str()
                .unwrap()
                .len(),
            SMALL + 2
        );
    }
    assert_eq!(
        rpc.call("sendrawtransaction", json!([transaction]))
            .unwrap(),
        "txid"
    );
    server.join().unwrap();
}

#[test]
fn result_presence_null_and_errors_preserve_response_validation_order() {
    for (body, expected) in [
        (json!({"id":1,"result":null}), Ok(Value::Null)),
        (
            json!({"id":1,"result":{"items":[1,"text",null]},"error":null}),
            Ok(json!({"items":[1,"text",null]})),
        ),
        (json!({"id":1}), Err("missing RPC result")),
        (json!({"id":1,"error":null}), Err("missing RPC result")),
        (
            json!({"id":2}),
            Err("RPC returned error or wrong response id"),
        ),
        (
            json!({"id":2,"result":null}),
            Err("RPC returned error or wrong response id"),
        ),
        (
            json!({"result":null}),
            Err("RPC returned error or wrong response id"),
        ),
        (
            json!({"id":1,"error":{"code":-5}}),
            Err("RPC returned error or wrong response id"),
        ),
        (
            json!({"id":1,"result":null,"error":{"code":-5}}),
            Err("RPC returned error or wrong response id"),
        ),
        (
            json!({"id":1,"result":{"items":[1]},"error":{"code":-1}}),
            Err("RPC returned error or wrong response id"),
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut rpc = HttpRpc::trusted_local_gateway(listener.local_addr().unwrap()).unwrap();
        let server = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            request(&mut stream);
            reply(&mut stream, body);
        });
        match expected {
            Ok(result) => assert_eq!(rpc.call("gettxout", json!([])).unwrap(), result),
            Err(message) => assert_eq!(
                rpc.call("gettxout", json!([])).unwrap_err().to_string(),
                message
            ),
        }
        server.join().unwrap();
    }
}

#[test]
fn private_cookie_rotation_and_invalid_auth_never_fall_back() {
    let temp = tempfile::tempdir().unwrap();
    let private = temp.path().join("private");
    storage::create_private_dir(&private).unwrap();
    let cookie = private.join("cookie");
    storage::write_new(&cookie, b"u:a").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut rpc = HttpRpc::new(address, &cookie).unwrap();
    let server = std::thread::spawn(move || {
        for expected in ["dTph", "dTpi"] {
            let mut stream = accept(&listener);
            let (header, _) = request(&mut stream);
            assert!(header.contains(&format!("Authorization: Basic {expected}\r\n")));
            reply(&mut stream, json!({"id":1,"result":true}));
        }
        listener
    });
    rpc.call("getblockchaininfo", json!([])).unwrap();
    let replacement = private.join("replacement");
    storage::write_new(&replacement, b"u:b").unwrap();
    std::fs::rename(&replacement, &cookie).unwrap();
    rpc.call("getblockchaininfo", json!([])).unwrap();
    let listener = server.join().unwrap();
    listener.set_nonblocking(true).unwrap();
    for invalid in [b"invalid".as_slice(), b"u:a\r\nInjected: yes", b""] {
        std::fs::write(&cookie, invalid).unwrap();
        assert!(rpc.call("getblockchaininfo", json!([])).is_err());
        assert!(HttpRpc::new(address, &cookie).is_err());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    std::fs::remove_file(&cookie).unwrap();
    assert!(rpc.call("getblockchaininfo", json!([])).is_err());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn server_auth_failure_and_wrong_id_never_retry() {
    for response in [
        "HTTP/1.0 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.0 200 OK\r\nContent-Length: 22\r\n\r\n{\"id\":2,\"result\":true}",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let private = temp.path().join("private");
        storage::create_private_dir(&private).unwrap();
        let cookie = private.join("cookie");
        storage::write_new(&cookie, b"u:a").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut rpc = HttpRpc::new(listener.local_addr().unwrap(), &cookie).unwrap();
        let server = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            let (header, _) = request(&mut stream);
            assert!(header.contains("Authorization: Basic dTph\r\n"));
            stream.write_all(response.as_bytes()).unwrap();
            listener
        });
        assert!(rpc.call("getblockchaininfo", json!([])).is_err());
        let listener = server.join().unwrap();
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn endpoints_and_admin_methods_fail_before_connecting() {
    for address in ["192.0.2.1:8232", "0.0.0.0:8232", "127.0.0.1:0", "[::1]:0"] {
        let address = address.parse().unwrap();
        assert!(HttpRpc::trusted_local_gateway(address).is_err());
        assert!(HttpRpc::new(address, std::path::Path::new("missing-cookie")).is_err());
    }
    assert!(HttpRpc::trusted_local_gateway("[::1]:8232".parse().unwrap()).is_ok());
    for address in [
        "localhost:8232",
        "http://127.0.0.1:8232",
        "127.0.0.1:8232/path",
    ] {
        assert!(address.parse::<SocketAddr>().is_err());
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut rpc = HttpRpc::trusted_local_gateway(listener.local_addr().unwrap()).unwrap();
    for method in ["submitblock", "stop", "getblocktemplate", "unknown"] {
        assert!(rpc
            .call(method, json!([]))
            .unwrap_err()
            .to_string()
            .contains("direct authenticated"));
    }
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn response_budgets_are_method_and_verbosity_specific() {
    let cases = [
        ("getblock", json!(["hash", 0]), LARGE),
        ("getrawtransaction", json!(["hash", 0]), LARGE),
        ("getblock", json!(["hash", 1]), SMALL),
        ("getblock", json!(["hash", 2]), SMALL),
        ("getrawtransaction", json!(["hash", 1]), SMALL),
        ("getrawtransaction", json!(["hash", false]), SMALL),
        ("getblock", json!(["hash"]), SMALL),
        ("getblock", json!(["hash", 0, null]), SMALL),
        ("getblock", json!(["hash", "0"]), SMALL),
        ("getblockchaininfo", json!([]), SMALL),
        ("sendrawtransaction", json!(["00"]), SMALL),
    ];
    for (method, params, limit) in cases {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut rpc = HttpRpc::trusted_local_gateway(listener.local_addr().unwrap()).unwrap();
        let server = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            request(&mut stream);
            write!(
                stream,
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n",
                limit + 1
            )
            .unwrap();
        });
        assert!(rpc
            .call(method, params)
            .unwrap_err()
            .to_string()
            .contains("response exceeds bound"));
        server.join().unwrap();
    }
}

#[test]
fn oversized_requests_refuse_without_network_effects() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut rpc = HttpRpc::trusted_local_gateway(listener.local_addr().unwrap()).unwrap();
    for (method, params) in [
        ("sendrawtransaction", json!(["0".repeat(LARGE)])),
        ("sendrawtransaction", json!(["0".repeat(SMALL), 0])),
        ("getblockchaininfo", json!(["0".repeat(SMALL)])),
    ] {
        assert!(rpc
            .call(method, params)
            .unwrap_err()
            .to_string()
            .contains("request too large"));
    }
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn cli_help_and_conflicting_modes_refuse_before_files_or_network() {
    let binary = env!("CARGO_BIN_EXE_tpq-devnet");
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("--trusted-local-gateway"));
    assert!(help.contains("mutually exclusive"));
    assert!(help.contains("Bootstrap requires direct"));
    for args in [
        vec![
            "bootstrap",
            "missing-chain",
            "127.0.0.1:1",
            "--trusted-local-gateway",
            "--producers-stopped",
        ],
        vec![
            "fund-submit",
            "missing-chain",
            "127.0.0.1:1",
            "missing-cookie",
            "--trusted-local-gateway",
            "review",
            "hash",
        ],
        vec![
            "fund-submit",
            "missing-chain",
            "127.0.0.1:1",
            "--trusted-local-gateway",
            "missing-cookie",
            "review",
            "hash",
        ],
    ] {
        let output = Command::new(binary).args(args).output().unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("replaces COOKIE") || error.contains("usage:"));
        assert!(!error.contains("No such file"));
    }
    for socket in [
        "127.0.0.1:0",
        "192.0.2.1:8232",
        "localhost:8232",
        "http://127.0.0.1:8232",
    ] {
        let output = Command::new(binary)
            .args([
                "fund-submit",
                "missing-chain",
                socket,
                "--trusted-local-gateway",
                "review",
                "hash",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!String::from_utf8(output.stderr)
            .unwrap()
            .contains("No such file"));
    }
}
