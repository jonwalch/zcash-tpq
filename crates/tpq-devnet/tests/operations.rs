//! Public-interface tests with an authenticated node double, never a live node.
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpListener,
};
use zakura_chain::{
    parameters::NetworkUpgrade,
    serialization::{ZcashDeserialize, ZcashSerialize},
    transaction::{HashType, Transaction},
    transparent::Input,
};
use zakura_tpq_devnet::{
    bootstrap, funding, prepare,
    rpc::{HttpRpc, Rpc},
    storage, Chain, Result,
};

struct Node {
    chain: Chain,
    tip: Option<u32>,
    wrong_fingerprint: bool,
    wrong_genesis: bool,
    conflicting: bool,
    lose_block_reply: bool,
    lose_tx_reply: bool,
    submitted_blocks: usize,
    sent: Vec<String>,
    known: bool,
    spent: bool,
}

impl Node {
    fn new(chain: Chain) -> Self {
        Self {
            chain,
            tip: None,
            wrong_fingerprint: false,
            wrong_genesis: false,
            conflicting: false,
            lose_block_reply: false,
            lose_tx_reply: false,
            submitted_blocks: 0,
            sent: vec![],
            known: false,
            spent: false,
        }
    }
    fn hash(&self, height: u32) -> String {
        if let Some(block) = self
            .chain
            .validate()
            .unwrap()
            .get(usize::try_from(height).unwrap())
        {
            block.hash().to_string()
        } else {
            "11".repeat(32)
        }
    }
}

impl Rpc for Node {
    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        match method {
            "getblockchaininfo" => Ok(
                json!({"blocks":self.tip.unwrap_or(0),"bestblockhash":self.tip.map(|h|self.hash(h)),
                "experimental_slh_dsa_b128s":{"chain_fingerprint":if self.wrong_fingerprint {"00".repeat(32)} else {self.chain.chain_fingerprint.clone()},
                "genesis_hash":if self.wrong_genesis {"00".repeat(32)} else {self.chain.rules.genesis_hash.clone()},"runtime_supported":true,"tip_height":self.tip}}),
            ),
            "getblockhash" => {
                let height = u32::try_from(params[0].as_u64().unwrap())?;
                Ok(json!(if self.conflicting && height == 0 {
                    "00".repeat(32)
                } else {
                    self.hash(height)
                }))
            }
            "submitblock" => {
                let height = self.tip.map_or(0, |h| h + 1);
                assert_eq!(params[0], self.chain.blocks[usize::try_from(height)?]);
                self.tip = Some(height);
                self.submitted_blocks += 1;
                if self.lose_block_reply {
                    self.lose_block_reply = false;
                    Err("lost reply".into())
                } else {
                    Ok(Value::Null)
                }
            }
            "getblock" => {
                let blocks = self.chain.validate()?;
                let index = blocks
                    .iter()
                    .position(|b| json!(b.hash().to_string()) == params[0])
                    .unwrap();
                Ok(json!(self.chain.blocks[index]))
            }
            "gettxout" => {
                if self.spent {
                    return Ok(Value::Null);
                }
                let blocks = self.chain.validate()?;
                let parent = &blocks[1].transactions[0];
                assert_eq!(params[0], parent.hash().to_string());
                assert_eq!(params[1], 0);
                Ok(
                    json!({"bestblock":self.hash(self.tip.unwrap()),"confirmations":self.tip.unwrap(),"coinbase":true,"value":10.0,
                    "scriptPubKey":{"hex":hex::encode(parent.outputs()[0].lock_script.as_raw_bytes())}}),
                )
            }
            "getrawtransaction" => {
                if self.known {
                    Ok(json!(self.sent.last().unwrap()))
                } else {
                    Err("not known (or lost response)".into())
                }
            }
            "sendrawtransaction" => {
                self.sent.push(params[0].as_str().unwrap().to_owned());
                if self.lose_tx_reply {
                    return Err("lost submission reply".into());
                }
                self.known = true;
                // Tests use lost responses and reconcile known exact bytes instead.
                Err("lost reply after acceptance".into())
            }
            _ => panic!("unexpected RPC {method}"),
        }
    }
}

fn prepared() -> (tempfile::TempDir, Chain) {
    let dir = tempfile::tempdir().unwrap();
    let chain = prepare(
        &dir.path().join("public"),
        &dir.path().join("private"),
        "ToolTests".into(),
    )
    .unwrap();
    (dir, chain)
}

fn receiver(chain: &Chain) -> String {
    zakura_pq_wallet::Receiver::for_profile(
        zakura_pq_wallet::Suite::SlhDsaB128sExpV1,
        zakura_pq_wallet::Hex([9; 32]),
        &chain.wallet_profile().unwrap(),
    )
    .unwrap()
    .encode()
}

#[test]
fn prepare_saves_exact_public_rules_and_separate_create_new_private_key() {
    let (dir, chain) = prepared();
    let loaded = Chain::load(&dir.path().join("public/chain.json")).unwrap();
    assert_eq!(chain.blocks, loaded.blocks);
    assert_eq!(chain.chain_fingerprint, loaded.chain_fingerprint);
    assert_eq!(chain.validate().unwrap().len(), 102);
    let public =
        storage::read_bounded(&dir.path().join("public/chain.json"), 16 * 1024 * 1024).unwrap();
    let private: Value = serde_json::from_slice(
        &storage::read_private(&dir.path().join("private/funder.json"), 4096).unwrap(),
    )
    .unwrap();
    assert!(!String::from_utf8(public)
        .unwrap()
        .contains(private["secret_key_hex"].as_str().unwrap()));
    assert!(prepare(
        &dir.path().join("public"),
        &dir.path().join("private"),
        "ToolTests".into()
    )
    .is_err());
    assert!(storage::write_new(&dir.path().join("private/funder.json"), b"overwrite").is_err());
    let profile = zakura_pq_wallet::Profile::from_json(
        &std::fs::read(dir.path().join("public/wallet-profile.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(profile, chain.wallet_profile().unwrap());
    #[derive(serde::Deserialize)]
    struct Config {
        network: zakura_network::Config,
    }
    let config: Config = toml::from_str(
        &std::fs::read_to_string(dir.path().join("public/node-network.toml")).unwrap(),
    )
    .unwrap();
    config
        .network
        .validate_experimental_slh_dsa_b128s_peers()
        .unwrap();
    assert_eq!(
        config
            .network
            .network
            .experimental_slh_dsa_b128s_chain_fingerprint()
            .map(hex::encode),
        Some(chain.chain_fingerprint.clone())
    );
    let config: Config =
        serde_json::from_slice(&std::fs::read(dir.path().join("public/network.json")).unwrap())
            .unwrap();
    assert_eq!(
        config.network.network.genesis_hash().to_string(),
        chain.rules.genesis_hash
    );
}

#[test]
fn bootstrap_reconciles_lost_reply_and_reuses_prefix() {
    let (_dir, chain) = prepared();
    let mut node = Node::new(chain.clone());
    node.lose_block_reply = true;
    assert!(bootstrap::bootstrap(&mut node, &chain, false).is_err());
    bootstrap::bootstrap(&mut node, &chain, true).unwrap();
    assert_eq!(node.submitted_blocks, chain.blocks.len());
    bootstrap::bootstrap(&mut node, &chain, true).unwrap();
    assert_eq!(node.submitted_blocks, chain.blocks.len());
}

#[test]
fn bootstrap_rejects_wrong_identity_conflicts_and_checkpoint_expansion() {
    let (_dir, chain) = prepared();
    let mut node = Node::new(chain.clone());
    node.wrong_fingerprint = true;
    assert!(bootstrap::bootstrap(&mut node, &chain, true).is_err());
    node.wrong_fingerprint = false;
    node.wrong_genesis = true;
    assert!(bootstrap::bootstrap(&mut node, &chain, true).is_err());
    node.wrong_genesis = false;
    node.tip = Some(1);
    node.conflicting = true;
    assert!(bootstrap::bootstrap(&mut node, &chain, true).is_err());
    node.conflicting = false;
    node.tip = Some(102);
    assert!(bootstrap::bootstrap(&mut node, &chain, true).is_err());
    assert_eq!(node.submitted_blocks, 0);
    let mut bad = chain.clone();
    bad.rules.genesis_hash = "00".repeat(32);
    assert!(bad.validate().is_err());
    let mut bad = chain.clone();
    bad.blocks[0] = chain.blocks[1].clone();
    assert!(bad.validate().is_err());
    let mut bad = chain.clone();
    bad.rules.target_difficulty_limit = "00".repeat(32);
    assert!(bad.validate().is_err());
    let mut bad = chain;
    bad.chain_fingerprint = "00".repeat(32);
    assert!(bad.validate().is_err());
}

#[test]
fn funding_saves_before_submit_and_retries_only_saved_bytes() {
    let (dir, chain) = prepared();
    let mut node = Node::new(chain.clone());
    node.tip = Some(102);
    let path = dir.path().join("private/review.json");
    let destination = receiver(&chain);
    let review = funding::draft(
        &mut node,
        &chain,
        &dir.path().join("private/funder.json"),
        &path,
        &destination,
        100_000_000,
        10_000,
    )
    .unwrap();
    assert_eq!(review.change_zat, 899_990_000);
    assert_eq!(
        review.destination_script_hex,
        hex::encode([vec![0x53, 0x20], vec![9; 32], vec![0xc0]].concat())
    );
    assert!(node.sent.is_empty());
    // Check the exported real-key authorization directly, without calling the
    // tool's signature-check helper. Mutation must invalidate the signature.
    let bytes = hex::decode(&review.transaction_hex).unwrap();
    let mut tx = Transaction::zcash_deserialize(bytes.as_slice()).unwrap();
    let Input::PrevOut { unlock_script, .. } = &tx.inputs()[0] else {
        panic!("expected P2PKH prevout");
    };
    let script = unlock_script.as_raw_bytes();
    let length = usize::from(script[0]);
    assert_eq!(script[length], 1);
    let signature = secp256k1::ecdsa::Signature::from_der(&script[1..length]).unwrap();
    let public = secp256k1::PublicKey::from_slice(&script[length + 2..]).unwrap();
    let previous = chain.validate().unwrap()[1].transactions[0]
        .outputs()
        .to_vec();
    let digest = |tx: &Transaction| {
        tx.sighasher(NetworkUpgrade::Nu7, std::sync::Arc::new(previous.clone()))
            .unwrap()
            .sighash(
                HashType::ALL,
                Some((0, previous[0].lock_script.as_raw_bytes().to_vec())),
            )
            .0
    };
    secp256k1::ecdsa::verify(
        &signature,
        secp256k1::Message::from_digest(digest(&tx)),
        &public,
    )
    .unwrap();
    if let Transaction::V5 { outputs, .. } = &mut tx {
        outputs[0].value = 100_000_001u64.try_into().unwrap();
    }
    assert!(secp256k1::ecdsa::verify(
        &signature,
        secp256k1::Message::from_digest(digest(&tx)),
        &public
    )
    .is_err());
    assert_eq!(
        funding::Review::load(&path).unwrap().transaction_hex,
        review.transaction_hex
    );
    assert!(funding::submit(&mut node, &chain, &review, &"00".repeat(32)).is_err());
    assert!(node.sent.is_empty());
    node.lose_tx_reply = true;
    assert!(funding::submit(&mut node, &chain, &review, &review.transaction_sha256).is_err());
    node.lose_tx_reply = false;
    funding::submit(&mut node, &chain, &review, &review.transaction_sha256).unwrap();
    assert_eq!(
        node.sent,
        vec![
            review.transaction_hex.clone(),
            review.transaction_hex.clone()
        ]
    );
    funding::submit(&mut node, &chain, &review, &review.transaction_sha256).unwrap();
    assert_eq!(node.sent.len(), 2);
    let mut changed = review.clone();
    changed.change_zat += 1;
    assert!(funding::submit(&mut node, &chain, &changed, &review.transaction_sha256).is_err());
    let mut changed = review.clone();
    changed.transaction_hex.push_str("00");
    assert!(funding::submit(&mut node, &chain, &changed, &review.transaction_sha256).is_err());
    node.known = false;
    node.spent = true;
    assert!(funding::submit(&mut node, &chain, &review, &review.transaction_sha256).is_err());
    assert_eq!(node.sent.len(), 2);
    assert_ne!(
        hex::encode(tx.zcash_serialize_to_vec().unwrap()),
        review.transaction_hex
    );
}

#[test]
fn funding_rejects_foreign_keys_immaturity_and_bad_payment_arithmetic() {
    let (dir, chain) = prepared();
    let (other_dir, _) = prepared();
    let mut other: Value = serde_json::from_slice(
        &storage::read_private(&other_dir.path().join("private/funder.json"), 4096).unwrap(),
    )
    .unwrap();
    other["chain_fingerprint"] = json!(chain.chain_fingerprint);
    let wrong = dir.path().join("private/wrong-owner.json");
    storage::write_new(&wrong, &serde_json::to_vec(&other).unwrap()).unwrap();
    let mut node = Node::new(chain.clone());
    node.tip = Some(102);
    let review = dir.path().join("private/rejected.json");
    let key = dir.path().join("private/funder.json");
    let destination = receiver(&chain);
    assert!(funding::draft(
        &mut node,
        &chain,
        &wrong,
        &review,
        &destination,
        100_000_000,
        10_000
    )
    .unwrap_err()
    .to_string()
    .contains("owner"));
    node.tip = Some(99);
    assert!(funding::draft(
        &mut node,
        &chain,
        &key,
        &review,
        &destination,
        100_000_000,
        10_000
    )
    .is_err());
    node.tip = Some(102);
    for (amount, fee) in [
        (u64::MAX, 10_000),
        (999_990_000, 10_000),
        (100_000_000, 9_999),
        (2402, 10_000),
    ] {
        assert!(
            funding::draft(&mut node, &chain, &key, &review, &destination, amount, fee).is_err()
        );
    }
    assert!(!review.exists());
    assert!(node.sent.is_empty());
}

#[test]
fn funding_rejects_other_chain_regtest_and_raw_script_receivers() {
    let (dir, chain) = prepared();
    let (_, other) = prepared();
    let mut node = Node::new(chain.clone());
    node.tip = Some(102);
    let review = dir.path().join("private/rejected.json");
    let regtest = zakura_pq_wallet::Receiver::new(
        zakura_pq_wallet::Suite::SlhDsaB128sExpV1,
        zakura_pq_wallet::Hex([9; 32]),
    )
    .encode();
    for destination in [receiver(&other), regtest, hex::encode([0; 35])] {
        assert!(funding::draft(
            &mut node,
            &chain,
            &dir.path().join("private/funder.json"),
            &review,
            &destination,
            100_000_000,
            10_000
        )
        .is_err());
        assert!(!review.exists());
    }
    assert!(node.sent.is_empty());
}

#[test]
fn bounded_authenticated_loopback_http() {
    for oversized in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("private");
        storage::create_private_dir(&private).unwrap();
        let cookie = private.join("cookie");
        storage::write_new(&cookie, b"test:password").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16 * 1024);
            }
            let headers = String::from_utf8(request).unwrap();
            assert!(headers.contains("Authorization: Basic dGVzdDpwYXNzd29yZA==\r\n"));
            let length: usize = headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            let mut body = vec![0; length];
            socket.read_exact(&mut body).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap()["method"],
                "getblockchaininfo"
            );
            if oversized {
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n")
                    .unwrap();
            } else {
                let body = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .unwrap();
                socket.write_all(body).unwrap();
            }
        });
        let mut rpc = HttpRpc::new(address, &cookie).unwrap();
        let result = rpc.call("getblockchaininfo", json!([]));
        if oversized {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), json!({"ok":true}));
        }
        server.join().unwrap();
        assert!(HttpRpc::new("192.0.2.1:8232".parse().unwrap(), &cookie).is_err());
    }
}
