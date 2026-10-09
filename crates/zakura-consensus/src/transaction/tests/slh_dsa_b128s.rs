//! Bounded consensus controls using retained public synthetic SLH fixtures.
//! The production service resolves outputs through mock trusted chain/mempool services.
//! No signing, live node, proof generation or performance workload is used.

use super::*;
use crate::transaction::{
    pq::SlhDsaB128sTransactionBudget, slh_dsa_b128s::verify_experimental_slh_dsa_b128s_inputs,
    AsyncChecks, Response, SlhDsaB128sBlockBudget,
};
use serde_json::Value;
use zakura_chain::parameters::testnet::{ExperimentalSlhDsaB128sLimits, RegtestParameters};
use zakura_pq_slh_dsa_b_exp::{Authorization, Rejection};
use zakura_pq_test_support::install;
use zakura_pq_tx_context::NetworkDomain;

const SLH_HEIGHT: Height = Height(110);

fn network(transaction: u32, block: u32) -> Network {
    Network::new_regtest(RegtestParameters {
        activation_heights: ConfiguredActivationHeights {
            nu6_3: Some(1),
            nu7: Some(105),
            ..Default::default()
        },
        experimental_slh_dsa_b128s_activation_height: Some(SLH_HEIGHT),
        experimental_slh_dsa_b128s_limits: Some(
            ExperimentalSlhDsaB128sLimits::new(transaction, block).unwrap(),
        ),
        ..Default::default()
    })
}

#[derive(Clone)]
struct Fixture {
    transaction: Transaction,
    previous: Arc<Vec<transparent::Output>>,
}

fn fixture(version: u8, case: &str) -> Fixture {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/slh-dsa-b128s/fixtures/data")
        .join(format!("v{version}-{case}.json"));
    let json: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(json["contract"], "slh-dsa-b-128s-exp-v1");
    assert_eq!(json["context_provenance"], "synthetic-public-fixture");
    let bytes = hex::decode(json["transaction_hex"].as_str().unwrap()).unwrap();
    let transaction = Transaction::zcash_deserialize(bytes.as_slice()).unwrap();
    let previous = Arc::new(
        json["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|input| {
                let spent = &input["spent_output"];
                transparent::Output {
                    value: spent["value_zat"].as_u64().unwrap().try_into().unwrap(),
                    lock_script: transparent::Script::new(
                        &hex::decode(spent["script_hex"].as_str().unwrap()).unwrap(),
                    ),
                }
            })
            .collect(),
    );
    Fixture {
        transaction,
        previous,
    }
}

impl Fixture {
    fn utxos(&self) -> HashMap<transparent::OutPoint, transparent::OrderedUtxo> {
        self.transaction
            .inputs()
            .iter()
            .zip(self.previous.iter())
            .map(|(input, output)| {
                (
                    input.outpoint().unwrap(),
                    transparent::OrderedUtxo::new(output.clone(), Height(1), 1),
                )
            })
            .collect()
    }
    fn block_request(&self, budget: Option<SlhDsaB128sBlockBudget>) -> Request {
        Request::Block {
            transaction_hash: self.transaction.hash(),
            transaction: Arc::new(self.transaction.clone()),
            known_outpoint_hashes: Arc::new(HashSet::new()),
            known_utxos: Arc::new(self.utxos()),
            height: SLH_HEIGHT,
            time: DateTime::<Utc>::MAX_UTC,
            slh_dsa_b128s_budget: budget,
        }
    }
}

fn rejected(input_index: usize, rejection: Rejection) -> TransactionError {
    TransactionError::ExperimentalSlhDsaB128s {
        input_index,
        reason: rejection.to_string(),
    }
}

fn corrupt_signature(transaction: &mut Transaction, index: usize) {
    let transparent::Input::PrevOut { unlock_script, .. } = &transaction.inputs()[index] else {
        unreachable!()
    };
    let mut authorization = Authorization::decode(unlock_script.as_raw_bytes()).unwrap();
    authorization.records[0].signature[100] ^= 1;
    install(
        transaction,
        index,
        transparent::Script::new(&authorization.encode()),
    );
}

fn worker(
    fixture: &Fixture,
    limits: ExperimentalSlhDsaB128sLimits,
    budget: SlhDsaB128sBlockBudget,
) -> Result<u32, TransactionError> {
    verify_experimental_slh_dsa_b128s_inputs(
        &fixture.transaction,
        NetworkDomain::Regtest,
        NetworkUpgrade::Nu7,
        fixture.previous.clone(),
        &(0..fixture.transaction.inputs().len()).collect::<Vec<_>>(),
        SlhDsaB128sTransactionBudget::new(limits, Some(budget)),
    )
}

#[test]
fn slh_worker_real_signatures_and_exact_transaction_block_boundaries() {
    let limits = ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap();
    for version in [5, 6] {
        let exact = fixture(version, "16checks");
        let budget = SlhDsaB128sBlockBudget::new(limits);
        for remaining in [48, 32, 16, 0] {
            assert_eq!(worker(&exact, limits, budget.clone()), Ok(16));
            assert_eq!(budget.remaining(), remaining);
        }
        assert_eq!(
            worker(&fixture(version, "1of1"), limits, budget.clone()),
            Err(TransactionError::ExperimentalSlhDsaB128sBlockBudget { limit: 64 })
        );
        assert_eq!(budget.remaining(), 0);
        let retry = SlhDsaB128sBlockBudget::new(limits);
        assert_eq!(worker(&exact, limits, retry.clone()), Ok(16));
        assert_eq!(retry.remaining(), 48);
        let budget = SlhDsaB128sBlockBudget::new(limits);
        assert_eq!(
            worker(&fixture(version, "17checks"), limits, budget.clone()),
            Err(TransactionError::ExperimentalSlhDsaB128sTransactionBudget { limit: 16 })
        );
        assert_eq!(
            budget.remaining(),
            49,
            "first threshold reserves 15; second cannot reserve 2"
        );
    }
}

#[test]
fn slh_worker_n1_verifies_reserved_prefix_before_later_structural_or_budget_failure() {
    let limits = ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap();
    for version in [5, 6] {
        let mut invalid = fixture(version, "16checks");
        install(&mut invalid.transaction, 1, transparent::Script::new(&[]));
        let budget = SlhDsaB128sBlockBudget::new(limits);
        assert_eq!(
            worker(&invalid, limits, budget.clone()),
            Err(rejected(1, Rejection::Encoding))
        );
        assert_eq!(budget.remaining(), 49);
        corrupt_signature(&mut invalid.transaction, 0);
        let budget = SlhDsaB128sBlockBudget::new(limits);
        assert_eq!(
            worker(&invalid, limits, budget.clone()),
            Err(rejected(0, Rejection::Signature))
        );
        assert_eq!(budget.remaining(), 49);
        let mut invalid = fixture(version, "17checks");
        corrupt_signature(&mut invalid.transaction, 0);
        let budget = SlhDsaB128sBlockBudget::new(limits);
        assert_eq!(
            worker(&invalid, limits, budget.clone()),
            Err(rejected(0, Rejection::Signature))
        );
        assert_eq!(budget.remaining(), 49);
    }
}

#[tokio::test]
async fn slh_trusted_block_dispatch_uses_real_worker_and_preserves_fresh_attempts() {
    let network = network(16, 64);
    for version in [5, 6] {
        for case in ["1of1", "1of15-index14", "16checks"] {
            let fixture = fixture(version, case);
            let budget =
                SlhDsaB128sBlockBudget::new(network.experimental_slh_dsa_b128s_limits().unwrap());
            let state = service_fn(|_| async { unreachable!("known UTXOs cover every input") });
            let result = timeout(
                test_timeout(),
                Verifier::new_for_tests(&network, state)
                    .oneshot(fixture.block_request(Some(budget.clone()))),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(result.tx_id(), fixture.transaction.unmined_id());
            assert_eq!(budget.remaining(), if case == "16checks" { 48 } else { 63 });
            let mut bad = fixture.clone();
            corrupt_signature(&mut bad.transaction, 0);
            assert_eq!(fixture.transaction.hash(), bad.transaction.hash());
            let state = service_fn(|_| async { unreachable!("known UTXOs cover every input") });
            let result = timeout(
                test_timeout(),
                Verifier::new_for_tests(&network, state)
                    .oneshot(bad.block_request(Some(budget.clone()))),
            )
            .await
            .unwrap();
            assert_eq!(result, Err(rejected(0, Rejection::Signature)));
        }
    }
}

#[tokio::test]
async fn slh_dispatch_rejects_mixed_inputs_before_any_budget_or_authorization_work() {
    let network = network(16, 64);
    for version in [5, 6] {
        let mut mixed = fixture(version, "16checks");
        Arc::make_mut(&mut mixed.previous)[1].lock_script = transparent::Script::new(&[0x51]);
        // The first input is also structurally invalid: whole-transaction classification wins.
        install(&mut mixed.transaction, 0, transparent::Script::new(&[]));
        assert_eq!(
            check::mempool_standard_input_scripts_with_slh_dsa_b128s(
                &mixed.transaction,
                &mixed.previous,
                true
            ),
            Err(TransactionError::ExperimentalSlhDsaB128sMixedInputs)
        );
        let budget =
            SlhDsaB128sBlockBudget::new(network.experimental_slh_dsa_b128s_limits().unwrap());
        let state = service_fn(|_| async { unreachable!("known UTXOs cover every input") });
        let result = timeout(
            test_timeout(),
            Verifier::new_for_tests(&network, state)
                .oneshot(mixed.block_request(Some(budget.clone()))),
        )
        .await
        .unwrap();
        assert_eq!(
            result,
            Err(TransactionError::ExperimentalSlhDsaB128sMixedInputs)
        );
        assert_eq!(budget.remaining(), 64);
    }
}

async fn mempool_result(
    network: &Network,
    height: Height,
    fixture: Fixture,
    state_fails: bool,
) -> Result<Response, TransactionError> {
    let transaction = fixture.transaction.clone();
    let utxos = fixture.utxos();
    let state = service_fn(move |request| {
        let response = match request {
            zakura_state::Request::UnspentBestChainUtxo(point) => {
                Ok(zakura_state::Response::UnspentBestChainUtxo(
                    utxos.get(&point).map(|utxo| utxo.utxo.clone()),
                ))
            }
            zakura_state::Request::CheckBestChainTipNullifiersAndAnchors(_) if state_fails => {
                Err("state check failed".into())
            }
            zakura_state::Request::CheckBestChainTipNullifiersAndAnchors(_) => {
                Ok(zakura_state::Response::ValidBestChainTipNullifiersAndAnchors)
            }
            request => panic!("unexpected request {request:?}"),
        };
        std::future::ready(response)
    });
    timeout(
        test_timeout(),
        Verifier::new_for_tests(network, state).oneshot(Request::Mempool {
            transaction: transaction.into(),
            height,
        }),
    )
    .await
    .unwrap()
}

fn funding(version: u8) -> Fixture {
    let mut fixture = fixture(version, "1of1");
    let (input, _, utxos) =
        mock_transparent_transfer(Height(1), true, 0, 100_000.try_into().unwrap());
    fixture.previous = Arc::new(vec![utxos[&input.outpoint().unwrap()].utxo.output.clone()]);
    fixture.transaction.inputs_mut()[0] = input;
    fixture
}

#[tokio::test]
async fn slh_mempool_publishes_bound_counts_only_after_complete_success_including_zero_funding() {
    let network = network(16, 64);
    for version in [5, 6] {
        for (fixture, expected) in [(fixture(version, "1of1"), 1), (funding(version), 0)] {
            let Response::Mempool { transaction, .. } =
                mempool_result(&network, SLH_HEIGHT, fixture.clone(), false)
                    .await
                    .unwrap()
            else {
                unreachable!()
            };
            assert_eq!(
                transaction.verified_slh_dsa_b128s_checks(&network, SLH_HEIGHT),
                Ok(expected)
            );
            assert_eq!(
                transaction.verified_slh_dsa_b128s_checks(&network, Height(111)),
                Ok(expected)
            );
            assert!(transaction
                .verified_slh_dsa_b128s_checks(&network, Height(109))
                .is_err());
            assert!(transaction.slh_dsa_b128s_verification.is_some());
            assert_eq!(transaction.spent_outputs, fixture.previous);
            assert!(mempool_result(&network, SLH_HEIGHT, fixture, true)
                .await
                .is_err());
        }
        let mut corrupt = fixture(version, "1of1");
        corrupt_signature(&mut corrupt.transaction, 0);
        assert_eq!(
            mempool_result(&network, SLH_HEIGHT, corrupt, false).await,
            Err(rejected(0, Rejection::Signature))
        );
        // Structural count wins over invalid crypto, before any worker starts.
        let mut over = fixture(version, "17checks");
        corrupt_signature(&mut over.transaction, 0);
        assert_eq!(
            mempool_result(&network, SLH_HEIGHT, over, false).await,
            Err(TransactionError::ExperimentalSlhDsaB128sTransactionBudget { limit: 16 })
        );
    }
}

#[tokio::test]
async fn slh_accounting_waits_for_other_checks_and_never_refunds_cancelled_work() {
    let limits = ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap();
    for outcome in ["success", "failure", "cancel"] {
        let fixture = fixture(6, "1of1");
        let budget = SlhDsaB128sBlockBudget::new(limits);
        let worker_budget = budget.clone();
        let (finished, worker_finished) = tokio::sync::oneshot::channel();
        let mut checks = AsyncChecks::new();
        checks.push_slh_dsa_b128s(async move {
            let result = crate::primitives::spawn_fifo_and_convert(move || {
                worker(&fixture, limits, worker_budget)
            })
            .await;
            finished.send(()).unwrap();
            result
        });
        let (release, waiting) = tokio::sync::oneshot::channel::<Result<(), BoxError>>();
        let mut other = AsyncChecks::new();
        other.push(async move { waiting.await? });
        let handle = tokio::spawn(checks.and(other).check(None));
        timeout(test_timeout(), worker_finished)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(budget.remaining(), 63);
        assert!(!handle.is_finished());
        match outcome {
            "success" => {
                release.send(Ok(())).unwrap();
                assert_eq!(
                    timeout(test_timeout(), handle)
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap()
                        .slh_dsa_b128s,
                    1
                );
            }
            "failure" => {
                release
                    .send(Err("late shielded/state check failure".into()))
                    .unwrap();
                assert!(timeout(test_timeout(), handle)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err());
            }
            _ => {
                handle.abort();
                assert!(timeout(test_timeout(), handle)
                    .await
                    .unwrap()
                    .unwrap_err()
                    .is_cancelled());
                assert!(release.send(Ok(())).is_err());
            }
        }
        assert_eq!(budget.remaining(), 63);
    }
}

#[test]
fn slh_budget_error_wrappers_preserve_attempt_scope_and_peer_scores() {
    use zakura_header_chain::{BodyVerificationClass, TransientBodyFailureKind};
    let block_budget = TransactionError::ExperimentalSlhDsaB128sBlockBudget { limit: 64 };
    let transaction_budget =
        TransactionError::ExperimentalSlhDsaB128sTransactionBudget { limit: 16 };
    assert_eq!(block_budget.mempool_misbehavior_score(), 0);
    assert_eq!(
        block_budget.body_verification_class(),
        BodyVerificationClass::Retryable(TransientBodyFailureKind::VerifierUnavailable)
    );
    assert_eq!(transaction_budget.mempool_misbehavior_score(), 100);
    for error in [
        block_budget,
        transaction_budget,
        rejected(0, Rejection::Signature),
        TransactionError::ExperimentalSlhDsaB128sMixedInputs,
    ] {
        assert_eq!(TransactionError::from(BoxError::from(error.clone())), error);
        let wrapper = crate::block::VerifyBlockError::Transaction(error.clone());
        assert_eq!(
            wrapper.body_verification_class(),
            error.body_verification_class()
        );
        let router = crate::RouterError::from(wrapper);
        assert_eq!(
            router.body_verification_class(),
            error.body_verification_class()
        );
        assert_eq!(
            router.misbehavior_score(),
            error.mempool_misbehavior_score()
        );
    }
    let block = crate::error::BlockError::TooManyExperimentalSlhDsaB128sChecks {
        height: SLH_HEIGHT,
        hash: zakura_chain::block::Hash([1; 32]),
        limit: 64,
    };
    assert_eq!(block.misbehavior_score(), 100);
    assert!(matches!(
        crate::block::VerifyBlockError::from(block).body_verification_class(),
        BodyVerificationClass::ConsensusInvalid(_)
    ));
}

#[cfg(feature = "slh-test-observer")]
#[test]
fn slh_real_primitive_entry_and_structural_zero_entry_controls() {
    use std::sync::Mutex;
    use zakura_pq_slh_dsa_b_exp::test_observer::{self, Event};
    let limits = ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap();
    for malformed in [false, true] {
        let mut fixture = fixture(5, "1of1");
        if malformed {
            install(&mut fixture.transaction, 0, transparent::Script::new(&[]));
        }
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = events.clone();
        let budget = SlhDsaB128sBlockBudget::new(limits);
        let result = test_observer::observe(
            Arc::new(move |event| observed.lock().unwrap().push(event)),
            || worker(&fixture, limits, budget.clone()),
        );
        let events = events.lock().unwrap();
        if malformed {
            assert_eq!(result, Err(rejected(0, Rejection::Encoding)));
            assert!(events.is_empty());
            assert_eq!(budget.remaining(), 64);
        } else {
            assert_eq!(result, Ok(1));
            assert_eq!(
                events.as_slice(),
                &[
                    Event::Reserved { checks: 1 },
                    Event::CryptoStarted,
                    Event::CryptoFinished { valid: true }
                ]
            );
        }
    }
}

#[tokio::test]
async fn slh_coinbase_dispatch_has_no_spent_output_or_budget_requirement() {
    type State =
        tower::util::BoxCloneService<zakura_state::Request, zakura_state::Response, BoxError>;
    type Mempool = tower::util::BoxCloneService<mempool::Request, mempool::Response, BoxError>;
    let network = network(16, 64);
    let genesis =
        Block::zcash_deserialize(&zakura_test::vectors::BLOCK_MAINNET_GENESIS_BYTES[..]).unwrap();
    let mut request = fixture(5, "1of1").block_request(None);
    let Request::Block {
        transaction,
        known_utxos,
        ..
    } = &mut request
    else {
        unreachable!()
    };
    *Arc::make_mut(transaction).inputs_mut() = vec![genesis.transactions[0].inputs()[0].clone()];
    *known_utxos = Arc::new(HashMap::new());
    let cached = Arc::new(
        zakura_script::CachedFfiTransaction::new(
            transaction.clone(),
            Arc::new(vec![]),
            NetworkUpgrade::Nu7,
        )
        .unwrap(),
    );
    assert!(transaction.is_coinbase());
    let checks = Verifier::<State, Mempool>::verify_transparent_inputs_and_outputs(
        &request,
        &network,
        crate::script::Verifier,
        cached,
    )
    .unwrap();
    assert_eq!(checks.check(None).await.unwrap().slh_dsa_b128s, 0);
}

#[cfg(feature = "slh-test-observer")]
#[tokio::test]
async fn slh_cancelled_inflight_worker_keeps_reservation_and_discards_result() {
    use std::sync::Mutex;
    use zakura_pq_slh_dsa_b_exp::test_observer::{self, Event};
    let limits = ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap();
    let budget = SlhDsaB128sBlockBudget::new(limits);
    let worker_budget = budget.clone();
    let fixture = fixture(5, "1of1");
    let (entered, started) = tokio::sync::oneshot::channel();
    let entered = Mutex::new(Some(entered));
    let (release, released) = std::sync::mpsc::channel();
    let released = Mutex::new(released);
    let (finished, completed) = tokio::sync::oneshot::channel();
    let finished = Mutex::new(Some(finished));
    let mut checks = AsyncChecks::new();
    checks.push_slh_dsa_b128s(crate::primitives::spawn_fifo_and_convert(move || {
        test_observer::observe(
            Arc::new(move |event| match event {
                Event::CryptoStarted => {
                    entered.lock().unwrap().take().unwrap().send(()).unwrap();
                    released
                        .lock()
                        .unwrap()
                        .recv_timeout(test_timeout())
                        .unwrap();
                }
                Event::CryptoFinished { valid } => {
                    assert!(valid);
                    finished.lock().unwrap().take().unwrap().send(()).unwrap();
                }
                Event::Reserved { .. } => {}
            }),
            || worker(&fixture, limits, worker_budget),
        )
    }));
    let handle = tokio::spawn(checks.check(None));
    timeout(test_timeout(), started).await.unwrap().unwrap();
    assert_eq!(budget.remaining(), 63);
    handle.abort();
    assert!(timeout(test_timeout(), handle)
        .await
        .unwrap()
        .unwrap_err()
        .is_cancelled());
    release.send(()).unwrap();
    timeout(test_timeout(), completed).await.unwrap().unwrap();
    assert_eq!(budget.remaining(), 63);
    assert_eq!(SlhDsaB128sBlockBudget::new(limits).remaining(), 64);
}

#[test]
fn slh_exact_recognition_ignores_created_outputs_and_native_looking_witnesses() {
    use crate::transaction::slh_dsa_b128s::input_indexes;
    let signed = fixture(5, "1of1");
    assert_eq!(
        input_indexes(&signed.transaction, &signed.previous, true).unwrap(),
        [0]
    );
    assert!(input_indexes(&signed.transaction, &signed.previous, false)
        .unwrap()
        .is_empty());
    let mut ordinary = funding(5);
    // A native-looking witness cannot select the verifier for a classical spent output.
    let transparent::Input::PrevOut { unlock_script, .. } = &signed.transaction.inputs()[0] else {
        unreachable!()
    };
    install(&mut ordinary.transaction, 0, unlock_script.clone());
    assert!(ordinary
        .transaction
        .outputs()
        .iter()
        .all(check::is_slh_dsa_b128s_output));
    assert!(
        input_indexes(&ordinary.transaction, &ordinary.previous, true)
            .unwrap()
            .is_empty()
    );
    let script = signed.previous[0].lock_script.as_raw_bytes();
    for alternate in [
        [&[0x23][..], script].concat(),
        [&[0x51][..], &script[1..]].concat(),
        [&[0x52][..], &script[1..]].concat(),
        [script, &[0x00][..]].concat(),
        script[..34].to_vec(),
    ] {
        let mut output = signed.previous[0].clone();
        output.lock_script = transparent::Script::new(&alternate);
        assert!(!check::is_slh_dsa_b128s_output(&output));
        assert!(input_indexes(&signed.transaction, &[output], true)
            .unwrap()
            .is_empty());
    }
}

#[tokio::test]
async fn slh_relay_structural_precheck_precedes_worker_n1_ordering() {
    let network = network(16, 64);
    for version in [5, 6] {
        let mut invalid = fixture(version, "16checks");
        corrupt_signature(&mut invalid.transaction, 0);
        install(&mut invalid.transaction, 1, transparent::Script::new(&[]));
        // Relay policy rejects the later malformed authorization before scheduling
        // the worker. The paired worker test deliberately returns input0/signature.
        assert_eq!(
            mempool_result(&network, SLH_HEIGHT, invalid, false).await,
            Err(TransactionError::NonStandardInputs)
        );
    }
}
