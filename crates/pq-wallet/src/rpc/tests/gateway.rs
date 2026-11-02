//! Offline loopback-only transport checks, not live-node qualification.
use super::super::*;
use std::net::TcpListener;

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
        assert!(header.len() < MAX_HEADER);
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

#[test]
fn explicit_gateway_omits_auth_and_keeps_exact_response_id() {
    for id in [1, 2] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let rpc = LocalRpc::trusted_local_gateway(listener.local_addr().unwrap()).unwrap();
        let server = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            let (headers, body) = request(&mut stream);
            assert!(!headers.to_ascii_lowercase().contains("authorization:"));
            assert_eq!(
                body,
                json!({"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[0]})
            );
            write!(
                stream,
                "HTTP/1.0 200 OK\r\n\r\n{{\"id\":{id},\"result\":\"ok\"}}"
            )
            .unwrap();
        });
        assert_eq!(rpc.call("getblockhash", json!([0])).is_ok(), id == 1);
        server.join().unwrap();
    }
    for address in ["192.0.2.1:8232", "0.0.0.0:8232", "127.0.0.1:0", "[::1]:0"] {
        assert!(LocalRpc::trusted_local_gateway(address.parse().unwrap()).is_err());
    }
    assert!(LocalRpc::trusted_local_gateway("[::1]:8232".parse().unwrap()).is_ok());
    for address in [
        "localhost:8232",
        "http://127.0.0.1:8232",
        "127.0.0.1:8232/path",
    ] {
        assert!(address.parse::<SocketAddr>().is_err());
    }
}

#[cfg(unix)]
#[test]
fn invalid_cookie_never_connects_and_server_auth_failure_never_retries() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let cookie = dir.path().join("cookie");
    std::fs::write(&cookie, b"not-a-cookie").unwrap();
    std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let rpc = LocalRpc::with_cookie(listener.local_addr().unwrap(), &cookie).unwrap();
    assert!(matches!(
        rpc.call("getblockhash", json!([0])),
        Err(Error::Authentication)
    ));
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    listener.set_nonblocking(false).unwrap();
    std::fs::write(&cookie, b"u:a").unwrap();
    let server = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        let (headers, _) = request(&mut stream);
        assert!(headers.contains("Authorization: Basic dTph\r\n"));
        stream
            .write_all(b"HTTP/1.0 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        drop(stream);
        listener
    });
    assert!(rpc.call("getblockhash", json!([0])).is_err());
    let listener = server.join().unwrap();
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn large_hex_class_is_exact_and_verbose_and_unknown_stay_small() {
    assert_eq!(MAX_RESPONSE, 40_100_000);
    for method in ["getblock", "getrawtransaction"] {
        assert_eq!(
            body_limits(method, &json!(["hash", 0])),
            (SMALL_BODY, MAX_RESPONSE)
        );
        for params in [
            json!(["hash"]),
            json!(["hash", 1]),
            json!(["hash", 2]),
            json!(["hash", false]),
            json!(["hash", "0"]),
            json!(["hash", 0, null]),
            json!({"verbosity":0}),
            json!([42, 0]),
        ] {
            assert_eq!(body_limits(method, &params), (SMALL_BODY, SMALL_BODY));
        }
    }
    assert_eq!(
        body_limits("sendrawtransaction", &json!(["00"])),
        (MAX_RESPONSE, SMALL_BODY)
    );
    for method in ["getblockchaininfo", "gettxout", "unknown", "submitblock"] {
        assert_eq!(
            body_limits(method, &json!(["hash", 0])),
            (SMALL_BODY, SMALL_BODY)
        );
    }
    for params in [json!([]), json!(["00", 0]), json!([0])] {
        assert_eq!(
            body_limits("sendrawtransaction", &params),
            (SMALL_BODY, SMALL_BODY)
        );
    }
    let prefix = b"HTTP/1.0 200 OK\r\n\r\n";
    let mut response = prefix.to_vec();
    let body = serde_json::to_vec(&json!({"id":1,"result":""})).unwrap();
    let overhead = body.len();
    let body =
        serde_json::to_vec(&json!({"id":1,"result":"0".repeat(SMALL_BODY - overhead)})).unwrap();
    assert_eq!(body.len(), SMALL_BODY);
    response.extend_from_slice(&body);
    assert!(parse_response_limited(&response, false, SMALL_BODY).is_ok());
    response.push(b' ');
    assert!(matches!(
        parse_response_limited(&response, false, SMALL_BODY),
        Err(Error::Limits)
    ));
    assert!(parse_response_limited(&response, false, MAX_RESPONSE).is_ok());
}

#[test]
fn gateway_large_raw_block_works_but_metadata_and_request_overages_refuse() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let rpc = LocalRpc::trusted_local_gateway(listener.local_addr().unwrap()).unwrap();
    let server = std::thread::spawn(move || {
        for method in ["getblock", "getblockchaininfo"] {
            let mut stream = accept(&listener);
            let (headers, body) = request(&mut stream);
            assert!(!headers.contains("Authorization:"));
            assert_eq!(body["method"], method);
            let body =
                serde_json::to_vec(&json!({"id":1,"result":"0".repeat(SMALL_BODY + 1)})).unwrap();
            write!(
                stream,
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            // The bounded client may close before an oversized metadata body finishes.
            let _ = stream.write_all(&body);
        }
        listener
    });
    assert!(rpc.call("getblock", json!(["hash", 0])).is_ok());
    assert!(matches!(
        rpc.call("getblockchaininfo", json!([])),
        Err(Error::Limits)
    ));
    let listener = server.join().unwrap();
    assert!(matches!(
        rpc.call("unknown", json!(["0".repeat(SMALL_BODY)])),
        Err(Error::Limits)
    ));
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
