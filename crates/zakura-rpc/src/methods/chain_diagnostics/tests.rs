use super::*;
use serde_json::{json, Value};
use zakura_chain::{
    block::Height,
    parameters::{
        testnet::{
            ConfiguredActivationHeights, ConfiguredCheckpoints, ConfiguredFundingStreamRecipient,
            ConfiguredFundingStreams, ConfiguredLockboxDisbursement, Parameters, ParametersBuilder,
        },
        Magic,
    },
    serialization::ZcashDeserializeInto,
    work::difficulty::{ExpandedDifficulty, U256},
};

fn custom_builder() -> ParametersBuilder {
    Parameters::build()
        .with_network_name("diagnostic_fixture")
        .unwrap()
        .with_network_magic(Magic([1, 2, 3, 4]))
        .unwrap()
        .with_genesis_hash("11".repeat(32))
        .unwrap()
        .with_activation_heights(ConfiguredActivationHeights {
            before_overwinter: Some(1),
            overwinter: Some(1),
            sapling: Some(1),
            blossom: Some(1),
            heartwood: Some(1),
            canopy: Some(1),
            nu5: Some(1),
            nu6: Some(1),
            nu6_1: Some(1),
            nu6_2: Some(1),
            nu6_3: Some(1),
            ..Default::default()
        })
        .unwrap()
        .clear_funding_streams()
        .with_lockbox_disbursements(vec![])
        .clear_checkpoints()
        .unwrap()
        .with_slow_start_interval(Height(0))
        .with_halving_interval(840_000)
        .unwrap()
        .with_target_difficulty_limit(ExpandedDifficulty::from((U256::one() << 255) - 1))
        .unwrap()
        .with_disable_pow(true)
        .with_max_block_time_start_height(Height(7))
        .with_temporary_orchard_disabling_soft_fork_height(Height(1))
}

fn report(builder: ParametersBuilder) -> Value {
    serde_json::to_value(chain_rules(&builder.to_network().unwrap()).unwrap()).unwrap()
}

#[test]
fn parsed_effective_rules_have_an_independent_complete_expected_report() {
    assert_eq!(
        report(custom_builder()),
        json!({
            "apiVersion": "zakura-chain-rules/v1",
            "ruleset": "zakura-configured-testnet/v1",
            "networkKind": "custom-testnet",
            "rules": {
                "networkMagic": "01020304",
                "genesisHash": "11".repeat(32),
                "checkpoints": [{"height": 0, "hash": "11".repeat(32)}],
                // The node builder replaces same-height activations, rather than
                // retaining or echoing all eleven requested declarations.
                "activationHeights": [{"height": 0, "upgrade": "Genesis"}, {"height": 1, "upgrade": "NU6.3"}],
                "subsidy": {
                    "slowStartInterval": 0,
                    "slowStartShift": 0,
                    "preBlossomHalvingInterval": 840000,
                    "postBlossomHalvingInterval": 1680000,
                    "fundingStreams": [],
                    "lockboxDisbursements": [],
                    "initialNsmValueBalance": null,
                    "allowUnshieldedCoinbaseSpends": false
                },
                "difficulty": {
                    "targetDifficultyLimitCompact": "207fffff",
                    "proofOfWork": "disabled",
                    "maxBlockTimeStartHeight": 7
                },
                "temporaryOrchardDisablingHeight": 1,
                "experimental": {"pq": null, "sqisign": null}
            }
        })
    );
}

#[test]
fn reports_effective_mutations_and_preserves_absent_versus_zero_seed() {
    let changed = report(
        custom_builder()
            .with_initial_nsm_value_balance(0u64.try_into().unwrap())
            .with_slow_start_interval(Height(20))
            .with_halving_interval(240)
            .unwrap()
            .with_disable_pow(false)
            .with_unshielded_coinbase_spends(true)
            .disable_temporary_orchard_disabling_soft_fork()
            .with_network_magic(Magic([4, 3, 2, 1]))
            .unwrap()
            .with_checkpoints(ConfiguredCheckpoints::HeightsAndHashes(vec![
                (Height(0), "11".repeat(32).parse().unwrap()),
                (Height(5), "22".repeat(32).parse().unwrap()),
            ]))
            .unwrap(),
    );
    assert_eq!(changed["rules"]["networkMagic"], "04030201");
    assert_eq!(
        changed["rules"]["checkpoints"][1],
        json!({"height":5,"hash":"22".repeat(32)})
    );
    assert_eq!(changed["rules"]["subsidy"]["initialNsmValueBalance"], 0);
    assert_eq!(changed["rules"]["subsidy"]["slowStartInterval"], 20);
    assert_eq!(changed["rules"]["subsidy"]["slowStartShift"], 10);
    assert_eq!(
        changed["rules"]["subsidy"]["preBlossomHalvingInterval"],
        240
    );
    assert_eq!(
        changed["rules"]["subsidy"]["postBlossomHalvingInterval"],
        480
    );
    assert_eq!(
        changed["rules"]["subsidy"]["allowUnshieldedCoinbaseSpends"],
        true
    );
    assert_eq!(changed["rules"]["difficulty"]["proofOfWork"], "equihash");
    assert!(changed["rules"]["temporaryOrchardDisablingHeight"].is_null());
}

#[test]
fn canonical_funding_recipients_and_lockbox_multiplicity_survive_projection() {
    let address = |byte| {
        Address::PayToScriptHash {
            network_kind: NetworkKind::Testnet,
            script_hash: [byte; 20],
        }
        .to_string()
    };
    let output = |byte, amount: u64| ConfiguredLockboxDisbursement {
        address: address(byte),
        amount: amount.try_into().unwrap(),
    };
    let value = report(
        custom_builder()
            .with_funding_streams(vec![ConfiguredFundingStreams {
                height_range: Some(Height(1)..Height(2)),
                recipients: Some(vec![
                    ConfiguredFundingStreamRecipient {
                        receiver: FundingStreamReceiver::MajorGrants,
                        numerator: 8,
                        addresses: Some(vec![address(3)]),
                    },
                    ConfiguredFundingStreamRecipient {
                        receiver: FundingStreamReceiver::Ecc,
                        numerator: 7,
                        addresses: Some(vec![address(2)]),
                    },
                ]),
            }])
            .with_lockbox_disbursements(vec![output(3, 3), output(2, 2), output(2, 2)]),
    );
    assert_eq!(
        value["rules"]["subsidy"]["fundingStreams"],
        json!([{
            "startHeight":1,"endHeight":2,"recipients":[
                {"receiver":"ecc","numerator":7,"scriptHashes":["02".repeat(20)]},
                {"receiver":"major-grants","numerator":8,"scriptHashes":["03".repeat(20)]}
            ]
        }])
    );
    assert_eq!(
        value["rules"]["subsidy"]["lockboxDisbursements"],
        json!([
            {"scriptHash":"02".repeat(20),"amount":2},
            {"scriptHash":"02".repeat(20),"amount":2},
            {"scriptHash":"03".repeat(20),"amount":3}
        ])
    );
}

#[test]
fn public_and_regtest_networks_and_artificial_consensus_overrides_fail_closed() {
    for network in [
        Network::Mainnet,
        Network::new_default_testnet(),
        Network::new_regtest(Default::default()),
    ] {
        assert!(chain_rules(&network)
            .unwrap_err()
            .message()
            .contains("configured Testnet"));
    }
    let network = custom_builder()
        .with_test_nsm_reissuance_height(Height(50))
        .to_network()
        .unwrap();
    assert!(chain_rules(&network)
        .unwrap_err()
        .message()
        .contains("artificial NSM"));
    for address in [
        Address::PayToPublicKeyHash {
            network_kind: NetworkKind::Testnet,
            pub_key_hash: [1; 20],
        },
        Address::PayToScriptHash {
            network_kind: NetworkKind::Mainnet,
            script_hash: [1; 20],
        },
    ] {
        assert!(script_identity(&address).is_err());
    }
}

#[test]
fn exact_mainnet_fixture_identity_uses_node_decoder_without_claiming_consensus() {
    let bytes = zakura_test::vectors::BLOCK_MAINNET_GENESIS_BYTES.as_slice();
    let inspected =
        serde_json::to_value(inspect_chain_block(&hex::encode(bytes)).unwrap()).unwrap();
    assert_eq!(
        inspected,
        json!({
            "apiVersion":"zakura-block-inspection/v1",
            "height":0,
            "hash":"00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08",
            "previousHash":"00".repeat(32),
            "bytesLength": 1692
        })
    );
}

#[test]
fn raw_block_inspection_rejects_invalid_trailing_oversized_and_unknown_height() {
    let bytes = zakura_test::vectors::BLOCK_MAINNET_GENESIS_BYTES.as_slice();
    for raw in [
        String::new(),
        "0".into(),
        "gg".into(),
        "00".into(),
        "00".repeat(usize::try_from(MAX_BLOCK_BYTES).unwrap() + 1),
        format!("{}00", hex::encode(bytes)),
    ] {
        assert!(inspect_chain_block(&raw).is_err());
    }
    let mut no_coinbase: Block = bytes.zcash_deserialize_into().unwrap();
    no_coinbase.transactions.clear();
    let encoded = no_coinbase.zcash_serialize_to_vec().unwrap();
    assert!(inspect_chain_block(&hex::encode(encoded))
        .unwrap_err()
        .message()
        .contains("coinbase height"));
    // Non-minimal CompactSize for the single transaction must not pass even if
    // the low-level decoder ever starts accepting it.
    let block: Block = bytes.zcash_deserialize_into().unwrap();
    let header = block.header.zcash_serialize_to_vec().unwrap();
    assert_eq!(bytes[header.len()], 1);
    let mut noncanonical = bytes[..header.len()].to_vec();
    noncanonical.extend([0xfd, 1, 0]);
    noncanonical.extend_from_slice(&bytes[header.len() + 1..]);
    assert!(inspect_chain_block(&hex::encode(noncanonical)).is_err());
}

#[test]
fn slh_rules_are_versioned_and_report_actual_build_support() {
    use zakura_chain::{
        local_genesis::{generate_local_testnet_with_slh_dsa_b128s, LocalTestnetGenesisOptions},
        parameters::testnet::ExperimentalSlhDsaB128sLimits,
    };
    let network = generate_local_testnet_with_slh_dsa_b128s(
        Vec::new(),
        LocalTestnetGenesisOptions {
            latest_network_upgrade: NetworkUpgrade::Nu7,
            ..Default::default()
        },
        ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap(),
    )
    .unwrap()
    .network;
    let report = chain_rules(&network).unwrap();
    assert_eq!(report.api_version, "zakura-chain-rules/slh-dsa-b128s/v2");
    assert_eq!(report.ruleset, "zakura-configured-testnet/slh-dsa-b128s/v2");
    let slh = report.rules.experimental.slh_dsa_b128s.unwrap();
    let identity = zakura_consensus::experimental_slh_dsa_b128s_verifier_identity();
    assert_eq!(slh.contract, "slh-dsa-b-128s-exp-v1");
    assert_eq!(slh.verifier_compiled, identity.verifier_compiled);
    assert_eq!(slh.runtime_supported, identity.runtime_supported);
    #[cfg(not(feature = "experimental-slh-dsa-b128s"))]
    assert!(
        !slh.runtime_supported,
        "a wrong-feature build must not report readiness"
    );
    assert_eq!(
        slh.chain_fingerprint,
        hex::encode(
            network
                .experimental_slh_dsa_b128s_chain_fingerprint()
                .unwrap()
        )
    );
    assert_eq!(slh.activation_height, 2);
    assert_eq!(slh.max_checks_per_transaction, 16);
    assert_eq!(slh.max_checks_per_block, 64);
    assert_eq!(slh.max_block_bytes, 20_000_000);
}
