//! Custom Testnet controls use separately produced Testnet-domain signatures.

use super::*;

fn devnet(transaction: u32, block: u32, genesis_tag: u8) -> Network {
    zakura_chain::parameters::testnet::Parameters::build()
        .with_network_name("SlhDevnet")
        .unwrap()
        .with_network_magic(zakura_chain::parameters::Magic([0x53, 0x4c, 0x48, 0x31]))
        .unwrap()
        .with_genesis_hash(zakura_chain::block::Hash([genesis_tag; 32]))
        .unwrap()
        .with_activation_heights(ConfiguredActivationHeights {
            nu6_3: Some(1),
            nu7: Some(105),
            ..Default::default()
        })
        .unwrap()
        .clear_funding_streams()
        .with_lockbox_disbursements(vec![])
        .clear_checkpoints()
        .unwrap()
        .with_experimental_slh_dsa_b128s(
            SLH_HEIGHT,
            ExperimentalSlhDsaB128sLimits::new(transaction, block).unwrap(),
        )
        .unwrap()
        .to_network()
        .unwrap()
}

fn devnet_fixture(version: u8) -> Fixture {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/slh-dsa-b128s/fixtures/devnet")
        .join(format!("v{version}-testnet-1of1.json"));
    let json: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(json["contract"], "slh-dsa-b-128s-exp-v1");
    assert_eq!(json["context_provenance"], "synthetic-public-fixture");
    assert_eq!(json["network"], "Testnet");
    assert_eq!(json["transaction_version"], version);
    let bytes = hex::decode(json["transaction_hex"].as_str().unwrap()).unwrap();
    Fixture {
        transaction: Transaction::zcash_deserialize(bytes.as_slice()).unwrap(),
        previous: Arc::new(
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
        ),
    }
}

async fn block_result(
    network: &Network,
    height: Height,
    fixture: &Fixture,
    budget: SlhDsaB128sBlockBudget,
) -> Result<Response, TransactionError> {
    let mut request = fixture.block_request(Some(budget));
    let Request::Block { height: at, .. } = &mut request else {
        unreachable!()
    };
    *at = height;
    let state = service_fn(|_| async { unreachable!("known UTXOs cover every input") });
    timeout(
        test_timeout(),
        Verifier::new_for_tests(network, state).oneshot(request),
    )
    .await
    .unwrap()
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
#[tokio::test]
async fn slh_devnet_block_dispatch_accepts_testnet_signatures_and_rejects_wrong_domains() {
    let net = devnet(1, 1, 42);
    let limits = net.experimental_slh_dsa_b128s_limits().unwrap();
    for version in [5, 6] {
        let fixture = devnet_fixture(version);
        let budget = SlhDsaB128sBlockBudget::new(limits);
        let accepted = block_result(&net, SLH_HEIGHT, &fixture, budget.clone())
            .await
            .unwrap();
        assert_eq!(accepted.tx_id(), fixture.transaction.unmined_id());
        assert_eq!(budget.remaining(), 0);
        assert_eq!(
            block_result(&net, SLH_HEIGHT, &fixture, budget.clone()).await,
            Err(TransactionError::ExperimentalSlhDsaB128sBlockBudget { limit: 1 })
        );
        assert_eq!(budget.remaining(), 0);
        assert!(
            block_result(&net, SLH_HEIGHT, &funding(version), budget.clone())
                .await
                .is_ok()
        );
        assert_eq!(
            budget.remaining(),
            0,
            "classical funding reserves no SLH checks"
        );

        let mut corrupt = fixture.clone();
        corrupt_signature(&mut corrupt.transaction, 0);
        for (rules, invalid) in [
            (net.clone(), corrupt),
            (net.clone(), super::fixture(version, "1of1")),
            (super::network(1, 1), fixture.clone()),
        ] {
            let budget = SlhDsaB128sBlockBudget::new(limits);
            assert_eq!(
                block_result(&rules, SLH_HEIGHT, &invalid, budget.clone()).await,
                Err(rejected(0, Rejection::Signature))
            );
            assert_eq!(
                budget.remaining(),
                0,
                "failed signatures do not refund reservations"
            );
            assert_eq!(
                mempool_result(&rules, SLH_HEIGHT, invalid, false).await,
                Err(rejected(0, Rejection::Signature))
            );
        }
        // A fresh block attempt receives a new allowance.
        assert!(block_result(
            &net,
            SLH_HEIGHT,
            &fixture,
            SlhDsaB128sBlockBudget::new(limits)
        )
        .await
        .is_ok());
    }
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
#[tokio::test]
async fn slh_devnet_mempool_binds_counts_to_custom_rules_and_trusted_outputs() {
    let net = devnet(1, 64, 42);
    let other_chain = devnet(1, 64, 43);
    let other_limits = devnet(2, 64, 42);
    for version in [5, 6] {
        for (fixture, expected) in [(devnet_fixture(version), 1), (funding(version), 0)] {
            let Response::Mempool { transaction, .. } =
                mempool_result(&net, SLH_HEIGHT, fixture.clone(), false)
                    .await
                    .unwrap()
            else {
                unreachable!()
            };
            assert_eq!(
                transaction.verified_slh_dsa_b128s_checks(&net, SLH_HEIGHT),
                Ok(expected)
            );
            assert_eq!(
                transaction.verified_slh_dsa_b128s_checks(&net, Height(111)),
                Ok(expected)
            );
            assert_eq!(transaction.spent_outputs, fixture.previous);
            for rules in [&other_chain, &other_limits, &super::network(1, 64)] {
                assert!(transaction
                    .verified_slh_dsa_b128s_checks(rules, SLH_HEIGHT)
                    .is_err());
            }
            assert!(transaction
                .verified_slh_dsa_b128s_checks(&net, Height(109))
                .is_err());
            assert!(matches!(
                mempool_result(&net, SLH_HEIGHT, fixture, true).await,
                Err(TransactionError::InternalDowncastError(error)) if error.contains("state check failed")
            ));
        }
    }
}

#[tokio::test]
async fn slh_devnet_preserves_activation_and_classical_funding_rules() {
    let net = devnet(16, 64, 42);
    let limits = net.experimental_slh_dsa_b128s_limits().unwrap();
    for version in [5, 6] {
        let signed = devnet_fixture(version);
        assert!(crate::transaction::slh_dsa_b128s::input_indexes(
            &signed.transaction,
            &signed.previous,
            net.is_experimental_slh_dsa_b128s_active(Height(109))
        )
        .unwrap()
        .is_empty());
        let budget = SlhDsaB128sBlockBudget::new(limits);
        assert!(block_result(&net, Height(109), &signed, budget.clone())
            .await
            .is_err());
        assert_eq!(
            budget.remaining(),
            64,
            "inactive spends do not enter the SLH worker"
        );
        assert_eq!(
            mempool_result(&net, Height(109), signed, false).await,
            Err(TransactionError::NonStandardSlhDsaB128sOutput { output_index: 0 })
        );
        assert!(
            block_result(&net, Height(109), &funding(version), budget.clone())
                .await
                .is_ok()
        );
        assert_eq!(budget.remaining(), 64);
        assert_eq!(
            mempool_result(&net, Height(109), funding(version), false).await,
            Err(TransactionError::NonStandardSlhDsaB128sOutput { output_index: 0 })
        );
        let Response::Mempool { transaction, .. } =
            mempool_result(&net, SLH_HEIGHT, funding(version), false)
                .await
                .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(
            transaction.verified_slh_dsa_b128s_checks(&net, SLH_HEIGHT),
            Ok(0)
        );
        assert_eq!(
            mempool_result(&net, SLH_HEIGHT, classical_funding(version, false), false).await,
            Err(TransactionError::Script(
                zakura_script::Error::ScriptInvalid
            ))
        );
    }
}

#[cfg(not(feature = "experimental-slh-dsa-b128s"))]
#[tokio::test]
async fn slh_devnet_spends_fail_closed_without_compiled_verifier() {
    let net = devnet(16, 64, 42);
    for version in [5, 6] {
        let fixture = devnet_fixture(version);
        let budget = SlhDsaB128sBlockBudget::new(net.experimental_slh_dsa_b128s_limits().unwrap());
        assert_eq!(
            block_result(&net, SLH_HEIGHT, &fixture, budget.clone()).await,
            Err(TransactionError::ExperimentalSlhDsaB128sBackendUnavailable)
        );
        assert_eq!(budget.remaining(), 64);
        assert_eq!(
            mempool_result(&net, SLH_HEIGHT, fixture, false).await,
            Err(TransactionError::ExperimentalSlhDsaB128sBackendUnavailable)
        );
    }
}
