//! Scripted loopback transport, with no node or live chain.
use super::*;
use crate::{
    payment::PaymentSource,
    watch::tests::{transaction, Chain},
    Outpoint,
};
use std::{net::TcpListener, thread};
use zakura_chain::{
    serialization::{BytesInDisplayOrder, ZcashSerialize},
    transparent::{OutPoint, Output, Script},
};

struct Step {
    method: &'static str,
    params: Value,
    envelope: Value,
}
fn reply(method: &'static str, params: Value, result: Value) -> Step {
    Step {
        method,
        params,
        envelope: json!({"id":1,"result":result}),
    }
}
fn scripted<T>(steps: Vec<Step>, call: impl FnOnce(&mut LocalRpc) -> T) -> T {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for step in steps {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "missing RPC request: {}",
                            step.method
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("mock accept: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let (end, length) = loop {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < MAX_HEADER);
                if request.ends_with(b"\r\n\r\n") {
                    let header = std::str::from_utf8(&request).unwrap();
                    assert!(header.starts_with("POST / HTTP/1.0\r\n"));
                    let length: usize = header
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    assert!(length <= 2 * crate::payment::MAX_TRANSACTION + 256);
                    break (request.len(), length);
                }
            };
            request.resize(end + length, 0);
            stream.read_exact(&mut request[end..]).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&request[end..]).unwrap(),
                json!({"jsonrpc":"2.0","id":1,"method":step.method,"params":step.params})
            );
            let body = serde_json::to_vec(&step.envelope).unwrap();
            write!(
                stream,
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    let result = call(&mut LocalRpc::new(address).unwrap());
    server.join().unwrap();
    result
}

fn fixture(version: u8) -> (Chain, Outpoint, Vec<u8>) {
    let tx = transaction(
        version,
        7,
        vec![OutPoint {
            hash: [0x33; 32].into(),
            index: 0,
        }],
        vec![Output {
            value: 123_456_789u64.try_into().unwrap(),
            lock_script: Script::new(&[0x51]),
        }],
    );
    let point = Outpoint {
        txid: Hex(tx.hash().bytes_in_display_order()),
        index: 0,
    };
    let raw = tx.zcash_serialize_to_vec().unwrap();
    let mut chain = Chain::new();
    chain.push(vec![tx], None);
    (chain, point, raw)
}
fn block_steps(chain: &Chain) -> Vec<Step> {
    let block = &chain.blocks[1];
    let hash = hex::encode(block.hash().bytes_in_display_order());
    vec![
        reply("getblockhash", json!([1]), json!(hash)),
        reply(
            "getblock",
            json!([hash, 0]),
            json!(hex::encode(block.zcash_serialize_to_vec().unwrap())),
        ),
    ]
}
fn resolve_steps(chain: &mut Chain, point: Outpoint, result: Value) -> Vec<Step> {
    let context = chain.context().unwrap();
    vec![
        reply(
            "getblockchaininfo",
            json!([]),
            json!({"chain":"test","consensus":{"nextblock":"77190ad9"},"upgrades":{"77190ad9":{"activationheight":2}},"blocks":context.tip.height,"bestblockhash":hex::encode(context.tip.hash.0)}),
        ),
        reply(
            "gettxout",
            json!([hex::encode(point.txid.0), point.index, true]),
            result,
        ),
    ]
}
fn assert_error<T: std::fmt::Debug>(result: Result<T, Error>, expected: Error) {
    assert_eq!(
        std::mem::discriminant(&result.unwrap_err()),
        std::mem::discriminant(&expected)
    );
}

#[test]
fn resolve_uses_exact_block_amount_and_checks_unspent_metadata() {
    for version in [5, 6] {
        let (mut chain, point, _) = fixture(version);
        let tip = chain.context().unwrap().tip;
        // The floating-point amount deliberately disagrees with the canonical block.
        let valid = json!({"confirmations":1,"bestblock":hex::encode(tip.hash.0),"coinbase":false,"scriptPubKey":{"hex":"51"},"value":9.99});
        let mut steps = resolve_steps(&mut chain, point, valid.clone());
        steps.extend(block_steps(&chain));
        let resolved = scripted(steps, |rpc| rpc.resolve(point)).unwrap().unwrap();
        assert_eq!(
            resolved.output,
            chain.blocks[1].transactions[1].outputs()[0]
        );
        assert_eq!(resolved.height, 1);
        assert_eq!(resolved.tip, tip);
        assert!(!resolved.coinbase);
        for missing in [Value::Null, json!({"confirmations":0})] {
            assert!(
                scripted(resolve_steps(&mut chain, point, missing), |rpc| rpc
                    .resolve(point))
                .unwrap()
                .is_none()
            );
        }
        for (field, value, expected, reads_block) in [
            (
                "bestblock",
                json!(hex::encode([9; 32])),
                Error::ChainChanged,
                false,
            ),
            ("confirmations", json!(3), Error::ChainChanged, false),
            (
                "confirmations",
                json!("1"),
                Error::HistoryUnavailable,
                false,
            ),
            ("coinbase", json!(true), Error::InputContext, true),
            (
                "scriptPubKey",
                json!({"hex":"52"}),
                Error::InputContext,
                true,
            ),
        ] {
            let mut bad = valid.clone();
            bad[field] = value;
            let mut steps = resolve_steps(&mut chain, point, bad);
            if reads_block {
                steps.extend(block_steps(&chain));
            }
            assert_error(scripted(steps, |rpc| rpc.resolve(point)), expected);
        }
        let mut steps = resolve_steps(&mut chain, point, valid);
        steps.push(reply(
            "getblockhash",
            json!([1]),
            json!(hex::encode([9; 32])),
        ));
        steps.push(reply(
            "getblock",
            json!([hex::encode([9; 32]), 0]),
            json!(hex::encode(
                chain.blocks[1].zcash_serialize_to_vec().unwrap()
            )),
        ));
        assert_error(
            scripted(steps, |rpc| rpc.resolve(point)),
            Error::ChainChanged,
        );
    }
}

#[test]
fn transaction_lookup_binds_raw_bytes_id_and_confirmation() {
    for version in [5, 6] {
        let (chain, point, raw) = fixture(version);
        let params = json!([hex::encode(point.txid.0), 1]);
        let valid = json!({"hex":hex::encode(&raw),"height":1});
        let mut steps = vec![reply("getrawtransaction", params.clone(), valid.clone())];
        steps.extend(block_steps(&chain));
        let located = scripted(steps, |rpc| rpc.transaction(point.txid))
            .unwrap()
            .unwrap();
        assert_eq!(located.bytes, raw);
        assert_eq!(
            located.block,
            Some(Checkpoint {
                height: 1,
                hash: Hex(chain.blocks[1].hash().bytes_in_display_order())
            })
        );
        let mempool = json!({"hex":hex::encode(&raw),"confirmations":0});
        assert!(scripted(
            vec![reply("getrawtransaction", params.clone(), mempool)],
            |rpc| rpc.transaction(point.txid)
        )
        .unwrap()
        .unwrap()
        .block
        .is_none());
        for missing in [Value::Null, json!({"hex":hex::encode(&raw),"height":-1})] {
            assert!(scripted(
                vec![reply("getrawtransaction", params.clone(), missing)],
                |rpc| rpc.transaction(point.txid)
            )
            .unwrap()
            .is_none());
        }
        let mut missing = reply("getrawtransaction", params.clone(), Value::Null);
        missing.envelope["error"] = json!({"code":-5});
        assert!(scripted(vec![missing], |rpc| rpc.transaction(point.txid))
            .unwrap()
            .is_none());
        for (bad, expected) in [
            (json!({}), Error::HistoryUnavailable),
            (json!({"hex":"gg"}), Error::HistoryUnavailable),
            (json!({"hex":"00"}), Error::HistoryUnavailable),
            (
                json!({"hex":format!("{}00", hex::encode(&raw))}),
                Error::InputContext,
            ),
            (
                json!({"hex":hex::encode(&raw),"confirmations":1}),
                Error::HistoryUnavailable,
            ),
        ] {
            assert_error(
                scripted(
                    vec![reply("getrawtransaction", params.clone(), bad)],
                    |rpc| rpc.transaction(point.txid),
                ),
                expected,
            );
        }
        let wrong = Hex([9; 32]);
        assert_error(
            scripted(
                vec![reply(
                    "getrawtransaction",
                    json!([hex::encode(wrong.0), 1]),
                    valid,
                )],
                |rpc| rpc.transaction(wrong),
            ),
            Error::InputContext,
        );
        let mut absent = Chain::new();
        absent.push(vec![], None);
        let mut steps = vec![reply(
            "getrawtransaction",
            params,
            json!({"hex":hex::encode(&raw),"height":1}),
        )];
        steps.extend(block_steps(&absent));
        assert_error(
            scripted(steps, |rpc| rpc.transaction(point.txid)),
            Error::ChainChanged,
        );
    }
}

#[test]
fn submission_sends_exact_bytes_and_surfaces_server_failures() {
    let (_, point, raw) = fixture(6);
    let params = json!([hex::encode(&raw)]);
    assert_eq!(
        scripted(
            vec![reply(
                "sendrawtransaction",
                params.clone(),
                json!(hex::encode(point.txid.0))
            )],
            |rpc| rpc.submit(&raw)
        )
        .unwrap(),
        point.txid
    );
    for result in [Value::Null, json!("bad"), json!({})] {
        assert_error(
            scripted(
                vec![reply("sendrawtransaction", params.clone(), result)],
                |rpc| rpc.submit(&raw),
            ),
            Error::HistoryUnavailable,
        );
    }
    let mut failure = reply("sendrawtransaction", params, Value::Null);
    failure.envelope["error"] = json!({"code":-26,"message":"rejected"});
    assert_error(
        scripted(vec![failure], |rpc| rpc.submit(&raw)),
        Error::HistoryUnavailable,
    );
    assert_error(
        scripted(vec![], |rpc| {
            rpc.submit(&vec![0; crate::payment::MAX_TRANSACTION + 1])
        }),
        Error::Limits,
    );
}

#[test]
fn slh_large_transaction_transport_preserves_exact_bytes_and_independent_caps() {
    let txid = Hex([0x77; 32]);
    // Public byte patterns exercise transport only; they are not valid signatures.
    for size in [119_041, crate::payment::MAX_TRANSACTION] {
        let raw = vec![0x42; size];
        assert_eq!(
            scripted(
                vec![reply(
                    "sendrawtransaction",
                    json!([hex::encode(&raw)]),
                    json!(hex::encode(txid.0))
                )],
                |rpc| rpc.submit(&raw)
            )
            .unwrap(),
            txid
        );
    }
    let too_large = "00".repeat(crate::payment::MAX_TRANSACTION + 1);
    assert_error(
        scripted(
            vec![reply(
                "getrawtransaction",
                json!([hex::encode(txid.0), 1]),
                json!({"hex":too_large,"confirmations":0}),
            )],
            |rpc| rpc.transaction(txid),
        ),
        Error::Limits,
    );
    let mut oversized_body = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
    oversized_body.resize(oversized_body.len() + MAX_RESPONSE + 1, b' ');
    assert_error(parse_response(&oversized_body), Error::Limits);
    let mut oversized_header = b"HTTP/1.0 200 OK\r\nX-Test: ".to_vec();
    oversized_header.resize(MAX_HEADER + 1, b'a');
    oversized_header.extend_from_slice(b"\r\n\r\n{\"id\":1,\"result\":1}");
    assert_error(parse_response(&oversized_header), Error::Limits);
    for endpoint in [
        "0.0.0.0:8232",
        "127.0.0.1:0",
        "[::]:8232",
        "[2001:db8::1]:8232",
    ] {
        assert!(LocalRpc::new(endpoint.parse().unwrap()).is_err());
    }
}
