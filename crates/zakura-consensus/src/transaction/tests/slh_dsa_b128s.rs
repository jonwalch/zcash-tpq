//! Bounded consensus controls using retained public synthetic SLH fixtures.
//! The production service resolves outputs through mock trusted chain/mempool services.
//! No signing, live node, proof generation or performance workload is used.
//! Tests that need the verifier use its feature. The other tests run in the default build.

mod devnet;
mod policy;

use super::*;
#[cfg(feature = "experimental-slh-dsa-b128s")]
use crate::transaction::{
    pq::SlhDsaB128sTransactionBudget, slh_dsa_b128s::verify_experimental_slh_dsa_b128s_inputs,
    AsyncChecks,
};
use crate::transaction::{Response, SlhDsaB128sBlockBudget};
use serde_json::Value;
use zakura_chain::parameters::testnet::{ExperimentalSlhDsaB128sLimits, RegtestParameters};
#[cfg(feature = "experimental-slh-dsa-b128s")]
use zakura_pq_slh_dsa_b_exp::{Authorization, Rejection};
use zakura_pq_test_support::install;
#[cfg(feature = "experimental-slh-dsa-b128s")]
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

#[cfg(feature = "experimental-slh-dsa-b128s")]
fn rejected(input_index: usize, rejection: Rejection) -> TransactionError {
    TransactionError::ExperimentalSlhDsaB128s {
        input_index,
        reason: rejection.to_string(),
    }
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
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

#[cfg(feature = "experimental-slh-dsa-b128s")]
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

#[cfg(feature = "experimental-slh-dsa-b128s")]
#[test]
fn slh_worker_local_context_failures_preserve_budgets_and_retry() {
    use zakura_header_chain::{BodyVerificationClass, TransientBodyFailureKind};

    let limits = ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap();
    for version in [5, 6] {
        let fixture = fixture(version, "1of1");
        for (previous, indexes) in [
            (Arc::new(vec![]), vec![0]),
            (Arc::new(vec![fixture.previous[0].clone(); 2]), vec![0]),
            (fixture.previous.clone(), vec![1]),
        ] {
            let budget = SlhDsaB128sBlockBudget::new(limits);
            let error = verify_experimental_slh_dsa_b128s_inputs(
                &fixture.transaction,
                NetworkDomain::Regtest,
                NetworkUpgrade::Nu7,
                previous,
                &indexes,
                SlhDsaB128sTransactionBudget::new(limits, Some(budget.clone())),
            )
            .unwrap_err();
            assert_eq!(error, TransactionError::ExperimentalSlhDsaB128sInputContext);
            assert_eq!(
                error.body_verification_class(),
                BodyVerificationClass::Retryable(TransientBodyFailureKind::MissingContext)
            );
            assert_eq!(error.mempool_misbehavior_score(), 0);
            assert_eq!(budget.remaining(), 64);
        }
    }
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
#[test]
fn slh_worker_invalid_transaction_context_and_encoding_remain_consensus_invalid() {
    use zakura_header_chain::BodyVerificationClass;

    let limits = ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap();
    let genesis =
        Block::zcash_deserialize(&zakura_test::vectors::BLOCK_MAINNET_GENESIS_BYTES[..]).unwrap();
    for version in [5, 6] {
        for (case, reason) in [
            ("version", "transaction_version"),
            ("branch", "consensus_branch"),
            ("coinbase", "input_context"),
            ("empty", "input_context"),
            ("encoding", "encoding"),
        ] {
            let mut fixture = fixture(version, "1of1");
            let mut upgrade = NetworkUpgrade::Nu7;
            match case {
                "version" => upgrade = NetworkUpgrade::Genesis,
                "branch" => upgrade = NetworkUpgrade::Nu6_3,
                "coinbase" => {
                    fixture.transaction.inputs_mut()[0] =
                        genesis.transactions[0].inputs()[0].clone();
                }
                "empty" => {
                    fixture.transaction.inputs_mut().clear();
                    fixture.previous = Arc::new(vec![]);
                }
                "encoding" => {
                    install(&mut fixture.transaction, 0, transparent::Script::new(&[]));
                }
                _ => unreachable!(),
            }
            let budget = SlhDsaB128sBlockBudget::new(limits);
            let error = verify_experimental_slh_dsa_b128s_inputs(
                &fixture.transaction,
                NetworkDomain::Regtest,
                upgrade,
                fixture.previous,
                &[0],
                SlhDsaB128sTransactionBudget::new(limits, Some(budget.clone())),
            )
            .unwrap_err();
            let expected = if case == "encoding" {
                rejected(0, Rejection::Encoding)
            } else {
                TransactionError::ExperimentalSlhDsaB128sContext {
                    reason: reason.to_owned(),
                }
            };
            assert_eq!(error, expected, "v{version}/{case}");
            assert!(matches!(
                error.body_verification_class(),
                BodyVerificationClass::ConsensusInvalid(_)
            ));
            assert_eq!(error.mempool_misbehavior_score(), 100);
            assert_eq!(budget.remaining(), 64);
        }
    }
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
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

#[cfg(feature = "experimental-slh-dsa-b128s")]
#[test]
fn slh_worker_requires_every_signer_of_every_input() {
    let limits = ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap();
    for version in [5, 6] {
        for (case, expected_counts) in [("15of15", &[15][..]), ("16checks", &[15, 1][..])] {
            let fixture = fixture(version, case);
            assert_eq!(fixture.transaction.inputs().len(), expected_counts.len());
            let total = expected_counts.iter().sum::<u32>();
            let budget = SlhDsaB128sBlockBudget::new(limits);
            assert_eq!(worker(&fixture, limits, budget.clone()), Ok(total));
            assert_eq!(budget.remaining(), 64 - total);
            for (input_index, count) in expected_counts.iter().enumerate() {
                let transparent::Input::PrevOut { unlock_script, .. } =
                    &fixture.transaction.inputs()[input_index]
                else {
                    panic!("public fixture spends transparent outputs")
                };
                let authorization = Authorization::decode(unlock_script.as_raw_bytes()).unwrap();
                assert_eq!(
                    authorization.records.len(),
                    usize::try_from(*count).unwrap()
                );
                for record_index in 0..authorization.records.len() {
                    let mut changed = fixture.clone();
                    let mut authorization = authorization.clone();
                    authorization.records[record_index].signature[100] ^= 1;
                    install(
                        &mut changed.transaction,
                        input_index,
                        transparent::Script::new(&authorization.encode()),
                    );
                    let budget = SlhDsaB128sBlockBudget::new(limits);
                    assert_eq!(
                        worker(&changed, limits, budget.clone()),
                        Err(rejected(input_index, Rejection::Signature)),
                        "v{version}-{case}, input {input_index}, signer {record_index}"
                    );
                    // Canonical inputs reserve all checks before parallel crypto.
                    // A bad signature does not refund the attempt's allowance.
                    assert_eq!(budget.remaining(), 64 - total);
                }
            }
        }
    }
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
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

#[cfg(feature = "experimental-slh-dsa-b128s")]
#[tokio::test]
async fn slh_trusted_block_dispatch_uses_real_worker_and_preserves_fresh_attempts() {
    let network = network(16, 64);
    for version in [5, 6] {
        for case in ["1of1", "1of15-index14", "16checks"] {
            let checks = if case == "16checks" { 16 } else { 1 };
            let fixture = fixture(version, case);
            let budget =
                SlhDsaB128sBlockBudget::new(network.experimental_slh_dsa_b128s_limits().unwrap());
            let state = service_fn(|_| async { unreachable!("known UTXOs cover every input") });
            // One verifier serves both requests, so any reuse keyed by txid would show here.
            let mut verifier = Verifier::new_for_tests(&network, state);
            let result = timeout(
                test_timeout(),
                verifier
                    .ready()
                    .await
                    .unwrap()
                    .call(fixture.block_request(Some(budget.clone()))),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(result.tx_id(), fixture.transaction.unmined_id());
            assert_eq!(budget.remaining(), 64 - checks);
            let mut bad = fixture.clone();
            corrupt_signature(&mut bad.transaction, 0);
            assert_eq!(fixture.transaction.hash(), bad.transaction.hash());
            let result = timeout(
                test_timeout(),
                verifier
                    .ready()
                    .await
                    .unwrap()
                    .call(bad.block_request(Some(budget.clone()))),
            )
            .await
            .unwrap();
            assert_eq!(result, Err(rejected(0, Rejection::Signature)));
            // The failed attempt reserved its own checks and did not refund them.
            assert_eq!(budget.remaining(), 64 - 2 * checks);
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

/// A build without the verifier rejects active SLH spends in blocks and relay.
#[cfg(not(feature = "experimental-slh-dsa-b128s"))]
#[tokio::test]
async fn slh_spends_fail_closed_without_the_compiled_verifier() {
    let network = network(16, 64);
    let unavailable = || TransactionError::ExperimentalSlhDsaB128sBackendUnavailable;
    for version in [5, 6] {
        let fixture = fixture(version, "1of1");
        let budget =
            SlhDsaB128sBlockBudget::new(network.experimental_slh_dsa_b128s_limits().unwrap());
        let state = service_fn(|_| async { unreachable!("known UTXOs cover every input") });
        let result = timeout(
            test_timeout(),
            Verifier::new_for_tests(&network, state)
                .oneshot(fixture.block_request(Some(budget.clone()))),
        )
        .await
        .unwrap();
        assert_eq!(result, Err(unavailable()));
        assert_eq!(budget.remaining(), 64);
        assert_eq!(
            mempool_result(&network, SLH_HEIGHT, fixture, false).await,
            Err(unavailable())
        );
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
    classical_funding(version, true)
}

/// SLH funding from one standard P2SH input whose script passes or fails.
fn classical_funding(version: u8, script_should_succeed: bool) -> Fixture {
    let mut fixture = fixture(version, "1of1");
    let (input, _, utxos) = mock_transparent_transfer(
        Height(1),
        script_should_succeed,
        0,
        100_000.try_into().unwrap(),
    );
    fixture.previous = Arc::new(vec![utxos[&input.outpoint().unwrap()].utxo.output.clone()]);
    fixture.transaction.inputs_mut()[0] = input;
    fixture
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
#[tokio::test]
async fn slh_mempool_publishes_bound_counts_only_after_complete_success_including_zero_funding() {
    // A structural count equal to the transaction limit passes the relay precheck.
    let exact = network(1, 64);
    let network = network(16, 64);
    for version in [5, 6] {
        for (rules, fixture, expected) in [
            (&network, fixture(version, "1of1"), 1),
            (&network, funding(version), 0),
            (&exact, fixture(version, "1of1"), 1),
        ] {
            let Response::Mempool { transaction, .. } =
                mempool_result(rules, SLH_HEIGHT, fixture.clone(), false)
                    .await
                    .unwrap()
            else {
                unreachable!()
            };
            assert_eq!(
                transaction.verified_slh_dsa_b128s_checks(rules, SLH_HEIGHT),
                Ok(expected)
            );
            assert_eq!(
                transaction.verified_slh_dsa_b128s_checks(rules, Height(111)),
                Ok(expected)
            );
            assert!(transaction
                .verified_slh_dsa_b128s_checks(rules, Height(109))
                .is_err());
            assert!(transaction.slh_dsa_b128s_verification.is_some());
            assert_eq!(transaction.spent_outputs, fixture.previous);
            // The late state check fails after every other check succeeded.
            assert!(matches!(
                mempool_result(rules, SLH_HEIGHT, fixture, true).await,
                Err(TransactionError::InternalDowncastError(error))
                    if error.contains("state check failed")
            ));
        }
        assert_eq!(
            mempool_result(&exact, SLH_HEIGHT, fixture(version, "2of3"), false).await,
            Err(TransactionError::ExperimentalSlhDsaB128sTransactionBudget { limit: 1 })
        );
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

#[cfg(feature = "experimental-slh-dsa-b128s")]
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

#[cfg(feature = "experimental-slh-dsa-b128s")]
#[tokio::test]
async fn slh_accounting_drains_held_work_after_an_early_error() {
    let limits = ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap();
    let budget = SlhDsaB128sBlockBudget::new(limits);
    let worker_budget = budget.clone();
    let fixture = fixture(6, "1of1");
    let (failed, failure_seen) = tokio::sync::oneshot::channel();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let mut checks = AsyncChecks::new();
    checks.push(async move {
        failed.send(()).unwrap();
        Err(TransactionError::CoinbasePosition.into())
    });
    checks.push_slh_dsa_b128s(async move {
        entered.send(()).unwrap();
        waiting.await?;
        crate::primitives::spawn_fifo_and_convert(move || worker(&fixture, limits, worker_budget))
            .await
    });
    let handle = tokio::spawn(checks.check(None));
    timeout(test_timeout(), failure_seen)
        .await
        .unwrap()
        .unwrap();
    timeout(test_timeout(), started).await.unwrap().unwrap();
    assert!(!handle.is_finished());
    assert_eq!(budget.remaining(), 64);

    release.send(()).unwrap();
    let error = timeout(test_timeout(), handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(
        TransactionError::from(error),
        TransactionError::CoinbasePosition
    );
    assert_eq!(budget.remaining(), 63);
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
        TransactionError::ExperimentalSlhDsaB128s {
            input_index: 0,
            reason: "signature".to_owned(),
        },
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
        [&script[..34], &[0xc1][..]].concat(),
        [&[0x53, 0x21][..], &script[2..]].concat(),
    ] {
        let mut output = signed.previous[0].clone();
        output.lock_script = transparent::Script::new(&alternate);
        assert!(!check::is_slh_dsa_b128s_output(&output));
        assert!(input_indexes(&signed.transaction, &[output], true)
            .unwrap()
            .is_empty());
    }
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
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

#[cfg(feature = "slh-test-observer")]
#[test]
fn slh_diagnostics_match_actual_primitive_entries_and_authorization_identity() {
    use crate::transaction::slh_dsa_b128s::verify_observed_inputs_for_test;
    use std::sync::Mutex;
    use zakura_pq_slh_dsa_b_exp::test_observer::{self, Event};
    let limits = ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap();
    for version in [5, 6] {
        for case in ["1of1", "1of15-index14", "16checks"] {
            for condition in ["valid", "bad-signature", "bad-encoding", "budget"] {
                let mut fixture = fixture(version, case);
                let original = fixture.transaction.txid_and_auth_digest();
                match condition {
                    "bad-signature" => corrupt_signature(&mut fixture.transaction, 0),
                    "bad-encoding" => {
                        install(&mut fixture.transaction, 0, transparent::Script::new(&[]))
                    }
                    _ => {}
                }
                let expected_identity = fixture.transaction.txid_and_auth_digest();
                if condition == "bad-signature" {
                    assert_eq!(original.0, expected_identity.0);
                    assert_ne!(original.1, expected_identity.1);
                }
                let native = Arc::new(Mutex::new(Vec::new()));
                let native_events = native.clone();
                let lines = Arc::new(Mutex::new(Vec::new()));
                let captured = lines.clone();
                let budget = SlhDsaB128sBlockBudget::new(limits);
                if condition == "budget" {
                    SlhDsaB128sTransactionBudget::new(limits, Some(budget.clone()))
                        .reserve(16)
                        .unwrap();
                    for _ in 0..3 {
                        SlhDsaB128sTransactionBudget::new(limits, Some(budget.clone()))
                            .reserve(16)
                            .unwrap();
                    }
                }
                let result = test_observer::observe(
                    Arc::new(move |event| native_events.lock().unwrap().push(event)),
                    || {
                        verify_observed_inputs_for_test(
                            &fixture.transaction,
                            NetworkDomain::Regtest,
                            NetworkUpgrade::Nu7,
                            fixture.previous.clone(),
                            &(0..fixture.previous.len()).collect::<Vec<_>>(),
                            SlhDsaB128sTransactionBudget::new(limits, Some(budget.clone())),
                            Arc::new(move |line| captured.lock().unwrap().push(line)),
                        )
                    },
                );
                let expected = match condition {
                    "valid" => Ok(if case == "16checks" { 16 } else { 1 }),
                    "bad-signature" => Err(rejected(0, Rejection::Signature)),
                    "bad-encoding" => Err(rejected(0, Rejection::Encoding)),
                    _ => Err(TransactionError::ExperimentalSlhDsaB128sBlockBudget { limit: 64 }),
                };
                assert_eq!(result, expected, "{version} {case} {condition}");
                let native = native.lock().unwrap();
                let started = native
                    .iter()
                    .filter(|event| **event == Event::CryptoStarted)
                    .count();
                let finished = native
                    .iter()
                    .filter(|event| matches!(event, Event::CryptoFinished { .. }))
                    .count();
                let lines = lines.lock().unwrap();
                assert_eq!(lines.len(), started);
                assert_eq!(started, finished);
                if matches!(condition, "bad-encoding" | "budget") {
                    assert_eq!(started, 0);
                } else {
                    assert!(started > 0);
                    let mut sequences = Vec::new();
                    for line in lines.iter() {
                        assert!(line.starts_with(
                            "slh_primitive_v1 token=0123456789abcdef0123456789abcdef "
                        ));
                        assert!(line.contains(&format!(
                            "txid={} auth_digest={}",
                            expected_identity.0,
                            expected_identity.1.unwrap()
                        )));
                        assert!(
                            line.ends_with("backend=portable-rust contract=slh-dsa-b-128s-exp-v1")
                        );
                        let sequence = line
                            .split_whitespace()
                            .find_map(|field| field.strip_prefix("seq="))
                            .unwrap()
                            .parse::<usize>()
                            .unwrap();
                        sequences.push(sequence);
                        if case == "1of15-index14" {
                            assert!(
                                line.contains("input=0 check=0 "),
                                "ordinal is not policy signer index14"
                            );
                        }
                    }
                    sequences.sort_unstable();
                    assert_eq!(sequences, (1..=started).collect::<Vec<_>>());
                }
            }
        }
    }
}
