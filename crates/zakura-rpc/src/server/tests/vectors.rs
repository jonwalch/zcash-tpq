//! Fixed test vectors for the RPC server.

// These tests call functions which can take unit arguments if some features aren't enabled.
#![allow(clippy::unit_arg)]

use crate::tests::test_rpc::TestRpcImpl;
use std::net::{Ipv4Addr, SocketAddrV4};

use tokio::sync::watch;
use tower::buffer::Buffer;

use zakura_chain::{
    chain_sync_status::MockSyncStatus, chain_tip::NoChainTip, parameters::Network::*,
};
use zakura_network::address_book_peers::MockAddressBookPeers;
use zakura_node_services::{mempool, BoxError};
use zakura_test::mock_service::MockService;

use super::super::*;

use config::rpc::Config;

/// Test that the JSON-RPC server spawns.
#[tokio::test]
async fn rpc_server_spawn_test() {
    rpc_server_spawn().await
}

/// Test if the RPC server will spawn on a randomly generated port.
#[tracing::instrument]
async fn rpc_server_spawn() {
    let _init_guard = zakura_test::init();

    let conf = Config {
        listen_addr: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into()),
        admin_listen_addr: None,
        indexer_listen_addr: None,
        indexer_tls: None,
        parallel_cpu_threads: 0,
        debug_force_finished_sync: false,
        cookie_dir: Default::default(),
        cookie_file_name: ".cookie".to_string(),
        enable_cookie_auth: false,
        max_response_body_size: Default::default(),
        tls: None,
    };

    let mut mempool: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();
    let state: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();
    let mut read_state: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();
    let mut block_verifier_router: MockService<_, _, _, BoxError> =
        MockService::build().for_unit_tests();

    info!("spawning RPC server...");

    let (_tx, rx) = watch::channel(None);
    let (rpc_impl, _) = TestRpcImpl::new_for_tests(
        Mainnet,
        Default::default(),
        false,
        "RPC test",
        "RPC test",
        Buffer::new(mempool.clone(), 1),
        Buffer::new(state.clone(), 1),
        Buffer::new(read_state.clone(), 1),
        Buffer::new(block_verifier_router.clone(), 1),
        MockSyncStatus::default(),
        NoChainTip,
        MockAddressBookPeers::default(),
        rx,
        None,
    );

    RpcServer::start(rpc_impl, conf)
        .await
        .expect("RPC server should start");

    info!("spawned RPC server, checking services...");

    tokio::join!(
        mempool.expect_no_requests(),
        read_state.expect_no_requests(),
        block_verifier_router.expect_no_requests(),
    );
}

/// Test startup and task shutdown on an OS-assigned port without large payloads.
#[tokio::test]
async fn rpc_server_spawn_unallocated_port_and_shuts_down() {
    rpc_spawn_unallocated_port(false).await
}

/// Full block-sized requests and verbose transaction responses fit the default limits.
#[tokio::test]
async fn rpc_server_accepts_twenty_mb_requests_and_verbose_responses() {
    rpc_spawn_unallocated_port(true).await
}

/// Test RPC startup and task shutdown, optionally exercising full-size payloads.
#[tracing::instrument]
async fn rpc_spawn_unallocated_port(probe_large_payloads: bool) {
    let _init_guard = zakura_test::init();

    let port = zakura_test::net::random_unallocated_port();
    #[allow(unknown_lints)]
    #[allow(clippy::bool_to_int_with_if)]
    let conf = Config {
        listen_addr: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()),
        admin_listen_addr: None,
        indexer_listen_addr: None,
        indexer_tls: None,
        parallel_cpu_threads: 0,
        debug_force_finished_sync: false,
        cookie_dir: Default::default(),
        cookie_file_name: ".cookie".to_string(),
        enable_cookie_auth: false,
        max_response_body_size: Config::default().max_response_body_size,
        tls: None,
    };

    let mut mempool: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();
    let mut state: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();
    let mut read_state: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();
    let mut block_verifier_router: MockService<_, _, _, BoxError> =
        MockService::build().for_unit_tests();

    info!("spawning RPC server...");

    let (_tx, rx) = watch::channel(None);
    let (rpc_impl, _) = TestRpcImpl::new_for_tests(
        Mainnet,
        Default::default(),
        false,
        "RPC test",
        "RPC test",
        Buffer::new(mempool.clone(), 1),
        Buffer::new(state.clone(), 1),
        Buffer::new(read_state.clone(), 1),
        Buffer::new(block_verifier_router.clone(), 1),
        MockSyncStatus::default(),
        NoChainTip,
        MockAddressBookPeers::default(),
        rx,
        None,
    );

    let (address, rpc) = RpcServer::start_inner(
        rpc_impl,
        conf,
        RpcSurface::Restricted,
        OPENED_RPC_ENDPOINT_MSG,
    )
    .await
    .expect("server should start");

    info!("spawned RPC server, checking services...");

    tokio::join!(
        mempool.expect_no_requests(),
        state.expect_no_requests(),
        read_state.expect_no_requests(),
        block_verifier_router.expect_no_requests(),
    );

    if probe_large_payloads {
        crate::indexer::server::install_tls_crypto_provider();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let response = client
            .post(format!("http://{address}"))
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "block_size_probe",
                    "params": ["00".repeat(20_000_000)],
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        // Method-not-found proves the request passed both HTTP byte limits.
        assert_eq!(response["error"]["code"], -32601);

        let mut block = zakura_chain::block::tests::generate::block_with_size(20_000_000);
        let transaction = Arc::make_mut(&mut block.transactions[0]);
        let mut script = transaction.outputs()[0].lock_script.as_raw_bytes().to_vec();
        // One data push produces large hex/asm fields without millions of opcode objects.
        let payload_len = u32::try_from(script.len() - 5).unwrap();
        script[0] = 0x4e; // OP_PUSHDATA4
        script[1..5].copy_from_slice(&payload_len.to_le_bytes());
        transaction.outputs_mut()[0].lock_script = zakura_chain::transparent::Script::new(&script);
        let transaction: zakura_chain::transaction::UnminedTx =
            block.transactions[0].clone().into();
        let txid = transaction.id().mined_id();
        let transaction_size = transaction.size();

        let request = async {
            client
                .post(format!("http://{address}"))
                .header("content-type", "application/json")
                .body(
                    serde_json::json!({
                        "jsonrpc": "2.0", "id": 2, "method": "getrawtransaction",
                        "params": [txid.to_string(), 1],
                    })
                    .to_string(),
                )
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        };
        let respond = async {
            mempool
                .expect_request(mempool::Request::TransactionsByMinedId([txid].into()))
                .await
                .respond(mempool::Response::Transactions(vec![transaction]));
        };
        let (response, ()) = tokio::join!(request, respond);
        assert!(
            response.len() > 50 * 1024 * 1024,
            "response exceeds the old cap"
        );
        // Borrow the raw hex and skip unused verbose fields while parsing, rather
        // than allocating another full copy of this large response as a JSON tree.
        #[derive(serde::Deserialize)]
        struct TransactionResult<'a> {
            size: usize,
            hex: &'a str,
        }
        #[derive(serde::Deserialize)]
        struct TransactionResponse<'a> {
            #[serde(borrow)]
            result: TransactionResult<'a>,
        }
        let response: TransactionResponse<'_> = serde_json::from_str(&response).unwrap();
        assert_eq!(response.result.size, transaction_size);
        assert_eq!(response.result.hex.len(), 2 * transaction_size);
    }
    rpc.abort();
    assert!(rpc.await.unwrap_err().is_cancelled());
}

/// Test if the RPC server will panic correctly when there is a port conflict.
#[tokio::test]
async fn rpc_server_spawn_port_conflict() {
    let _init_guard = zakura_test::init();

    let port = zakura_test::net::random_known_port();
    let conf = Config {
        listen_addr: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()),
        admin_listen_addr: None,
        indexer_listen_addr: None,
        indexer_tls: None,
        debug_force_finished_sync: false,
        parallel_cpu_threads: 0,
        cookie_dir: Default::default(),
        cookie_file_name: ".cookie".to_string(),
        enable_cookie_auth: false,
        max_response_body_size: Default::default(),
        tls: None,
    };

    let mut mempool: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();
    let mut state: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();
    let mut read_state: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();
    let mut block_verifier_router: MockService<_, _, _, BoxError> =
        MockService::build().for_unit_tests();

    let (_tx, rx) = watch::channel(None);
    let (rpc_impl, _) = TestRpcImpl::new_for_tests(
        Mainnet,
        Default::default(),
        false,
        "RPC test",
        "RPC test",
        Buffer::new(mempool.clone(), 1),
        Buffer::new(state.clone(), 1),
        Buffer::new(read_state.clone(), 1),
        Buffer::new(block_verifier_router.clone(), 1),
        MockSyncStatus::default(),
        NoChainTip,
        MockAddressBookPeers::default(),
        rx.clone(),
        None,
    );

    RpcServer::start(rpc_impl.clone(), conf.clone())
        .await
        .expect("RPC server should start");

    RpcServer::start(rpc_impl, conf)
        .await
        .expect_err("RPC server should not start");

    tokio::join!(
        mempool.expect_no_requests(),
        state.expect_no_requests(),
        read_state.expect_no_requests(),
        block_verifier_router.expect_no_requests(),
    );
}
