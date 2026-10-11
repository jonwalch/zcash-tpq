//! Reused synthetic discovery over actual pinned RPC shapes; no live node.
use super::*;
use crate::{
    watch::tests::{create, output, transaction, Chain},
    WatchMode,
};
use std::sync::Arc;
#[test]
fn local_rpc_scans_raw_blocks_using_actual_pinned_rpc_shapes() {
    use std::{
        io::{BufRead, BufReader},
        net::TcpListener,
        sync::atomic::{AtomicBool, Ordering},
        thread,
        time::Duration,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
    ))
    .unwrap();
    let mut manifest =
        crate::Manifest::from_json(corpus["inventory_json"].as_str().unwrap().as_bytes()).unwrap();
    manifest.profile = crate::watch::tests::profile();
    manifest.birthday_height = 0;
    manifest.validate().unwrap();
    let mut chain = Chain::new();
    chain.push(
        vec![transaction(
            6,
            3,
            vec![zakura_chain::transparent::OutPoint {
                hash: [0x33; 32].into(),
                index: 0,
            }],
            vec![output(&manifest.entries[0], 25)],
        )],
        None,
    );
    let context = chain.context().unwrap();
    // Check HTTP framing and actual RPC shapes, without assuming request counts.
    let server = thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            // macOS accepts can inherit the listener's nonblocking mode.
            // Read complete HTTP frames using the timeout below.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, "POST / HTTP/1.0\r\n");
            let mut length = 0;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(n) = line.strip_prefix("Content-Length: ") {
                    length = n.trim().parse::<usize>().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let request: Value = serde_json::from_slice(&body).unwrap();
            let result = match request["method"].as_str().unwrap() {
                "getblockchaininfo" => {
                    json!({"chain":"test", "blocks":context.tip.height,"bestblockhash":hex::encode(context.tip.hash.0),
                    "consensus":{"nextblock":"77190ad9"},"upgrades":{"77190ad9":{"activationheight":2,"status":"pending"}}})
                }
                "getblockhash" => json!(hex::encode(
                    chain
                        .block_hash(request["params"][0].as_u64().unwrap() as u32)
                        .unwrap()
                        .0
                )),
                "getblock" => {
                    let raw = hex::decode(request["params"][0].as_str().unwrap()).unwrap();
                    assert_eq!(request["params"][1], 0);
                    json!(hex::encode(
                        chain.block_bytes(Hex(raw.try_into().unwrap())).unwrap()
                    ))
                }
                _ => panic!("unexpected RPC"),
            };
            let response =
                serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":1,"result":result})).unwrap();
            write!(
                stream,
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                response.len()
            )
            .unwrap();
            stream.write_all(&response).unwrap();
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let mut store = create(&temp.path().join("watch"), &manifest, WatchMode::Monitor);
    let result = store.sync(&mut crate::rpc::LocalRpc::new(address).unwrap(), 10);
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    let status = result.unwrap();
    assert_eq!(status.confirmed_zatoshis, Some(25));
    assert!(status.complete_at_checkpoint);
}
