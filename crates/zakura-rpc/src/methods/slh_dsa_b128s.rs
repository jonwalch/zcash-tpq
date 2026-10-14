//! Effective experimental SLH rules for launchers and RPC clients.

use getset::{CopyGetters, Getters};
use zakura_chain::{
    block::{self, Height},
    parameters::Network,
};

/// The configured SLH rules and their status at one observed chain tip.
///
/// Rule activation does not establish synchronization, mempool readiness, or
/// permission to trust this chain. A launcher must check those separately.
#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Getters, CopyGetters,
)]
pub struct ExperimentalSlhDsaB128sInfo {
    /// Version of this diagnostic response.
    #[getset(get_copy = "pub")]
    schema_version: u8,
    /// The experimental signing contract, from the compiled verifier identity.
    #[getset(get = "pub")]
    contract: String,
    /// Whether this build contains the SLH verifier.
    #[getset(get_copy = "pub")]
    verifier_compiled: bool,
    /// Whether this build supports the complete SLH runtime.
    #[getset(get_copy = "pub")]
    runtime_supported: bool,
    /// Configured genesis hash, in the usual RPC display order.
    #[serde(with = "hex")]
    #[getset(get_copy = "pub")]
    genesis_hash: block::Hash,
    /// Lowercase hexadecimal rule fingerprint for custom testnets; absent on Regtest.
    #[getset(get = "pub")]
    chain_fingerprint: Option<String>,
    /// First block height governed by these SLH rules.
    #[getset(get_copy = "pub")]
    activation_height: Height,
    /// Maximum SLH signature checks reserved by one transaction.
    #[getset(get_copy = "pub")]
    max_checks_per_transaction: u32,
    /// Maximum SLH signature checks reserved by one block.
    #[getset(get_copy = "pub")]
    max_checks_per_block: u32,
    /// Observed chain tip, or null when chain state is unavailable.
    #[getset(get_copy = "pub")]
    tip_height: Option<Height>,
    /// Candidate height for mempool and mining rules; null without a usable tip.
    #[getset(get_copy = "pub")]
    next_block_height: Option<Height>,
    /// Whether SLH rules govern the candidate height; null without a usable tip.
    #[getset(get_copy = "pub")]
    active_for_next_block: Option<bool>,
}

impl ExperimentalSlhDsaB128sInfo {
    /// Describe a configured SLH network without starting services or doing cryptography.
    ///
    /// Returns `None` when SLH is not configured. `tip_height` must come from the
    /// node's observed chain state; pass `None` before bootstrap or when state
    /// cannot provide a tip. It must not be a configured or estimated height.
    pub fn for_network(network: &Network, tip_height: Option<Height>) -> Option<Self> {
        let activation_height = network.experimental_slh_dsa_b128s_activation_height()?;
        let limits = network
            .experimental_slh_dsa_b128s_limits()
            .expect("validated SLH activation always has signature-check limits");
        let identity = zakura_consensus::experimental_slh_dsa_b128s_verifier_identity();
        let next_block_height = tip_height.and_then(|height| height.next().ok());

        Some(Self {
            schema_version: 1,
            contract: identity.contract.to_owned(),
            verifier_compiled: identity.verifier_compiled,
            runtime_supported: identity.runtime_supported,
            genesis_hash: network.genesis_hash(),
            chain_fingerprint: network
                .experimental_slh_dsa_b128s_chain_fingerprint()
                .map(hex::encode),
            activation_height,
            max_checks_per_transaction: limits.transaction(),
            max_checks_per_block: limits.block(),
            tip_height,
            next_block_height,
            active_for_next_block: next_block_height
                .map(|height| network.is_experimental_slh_dsa_b128s_active(height)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_chain::{
        local_genesis::{generate_local_testnet_with_slh_dsa_b128s, LocalTestnetGenesisOptions},
        parameters::{
            testnet::{
                ConfiguredActivationHeights, ExperimentalSlhDsaB128sLimits, RegtestParameters,
            },
            NetworkUpgrade,
        },
    };

    fn slh_devnet() -> Network {
        generate_local_testnet_with_slh_dsa_b128s(
            Vec::new(),
            LocalTestnetGenesisOptions {
                latest_network_upgrade: NetworkUpgrade::Nu7,
                ..Default::default()
            },
            ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap(),
        )
        .expect("NU7 custom testnet supports an SLH activation")
        .network
    }

    #[test]
    fn slh_info_omits_unconfigured_networks() {
        for network in [
            Network::Mainnet,
            Network::new_default_testnet(),
            Network::new_regtest(Default::default()),
        ] {
            assert_eq!(
                ExperimentalSlhDsaB128sInfo::for_network(&network, Some(Height(100))),
                None
            );
        }
    }

    #[test]
    fn slh_info_reports_rules_without_claiming_tip_readiness() {
        let network = slh_devnet();
        let info = ExperimentalSlhDsaB128sInfo::for_network(&network, None).unwrap();
        let identity = zakura_consensus::experimental_slh_dsa_b128s_verifier_identity();
        assert_eq!(info.contract(), identity.contract);
        assert_eq!(info.verifier_compiled(), identity.verifier_compiled);
        assert_eq!(info.runtime_supported(), identity.runtime_supported);
        assert_eq!(info.genesis_hash(), network.genesis_hash());
        assert_eq!(
            info.chain_fingerprint(),
            &network
                .experimental_slh_dsa_b128s_chain_fingerprint()
                .map(hex::encode)
        );
        assert!(info.chain_fingerprint().is_some());
        assert_eq!(info.activation_height(), Height(2));
        assert_eq!(info.max_checks_per_transaction(), 16);
        assert_eq!(info.max_checks_per_block(), 64);
        assert_eq!(info.tip_height(), None);
        assert_eq!(info.next_block_height(), None);
        assert_eq!(info.active_for_next_block(), None);
        let json = serde_json::to_value(&info).unwrap();
        assert!(json["active_for_next_block"].is_null());
        assert_eq!(
            serde_json::from_value::<ExperimentalSlhDsaB128sInfo>(json).unwrap(),
            info
        );
    }

    #[test]
    fn slh_info_uses_candidate_height_and_handles_rollback_and_exhaustion() {
        let network = slh_devnet();
        for (height, next, active) in [
            (Height(0), Some(Height(1)), Some(false)),
            (Height(1), Some(Height(2)), Some(true)),
            (Height(2), Some(Height(3)), Some(true)),
            (Height(0), Some(Height(1)), Some(false)),
            (Height::MAX, None, None),
        ] {
            let info = ExperimentalSlhDsaB128sInfo::for_network(&network, Some(height)).unwrap();
            assert_eq!(info.tip_height(), Some(height));
            assert_eq!(info.next_block_height(), next);
            assert_eq!(info.active_for_next_block(), active);
        }
    }

    #[test]
    fn slh_info_retains_regtest_rules_without_custom_fingerprint() {
        let network = Network::new_regtest(RegtestParameters {
            activation_heights: ConfiguredActivationHeights {
                nu6_3: Some(1),
                nu7: Some(5),
                ..Default::default()
            },
            experimental_slh_dsa_b128s_activation_height: Some(Height(10)),
            experimental_slh_dsa_b128s_limits: Some(
                ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap(),
            ),
            ..Default::default()
        });
        let info = ExperimentalSlhDsaB128sInfo::for_network(&network, Some(Height(9))).unwrap();
        assert_eq!(info.activation_height(), Height(10));
        assert_eq!(info.active_for_next_block(), Some(true));
        assert_eq!(info.chain_fingerprint(), &None);
    }

    #[tokio::test]
    async fn slh_info_rpc_uses_observed_tip_and_preserves_unavailable_state() {
        use crate::methods::{RpcImpl, RpcServer};
        use zakura_chain::{chain_sync_status::MockSyncStatus, chain_tip::NoChainTip};
        use zakura_network::address_book_peers::MockAddressBookPeers;
        use zakura_state::{ReadRequest, ReadResponse};
        use zakura_test::mock_service::MockService;

        let network = slh_devnet();
        for observed_tip in [None, Some(Height(0)), Some(Height(1))] {
            let read_state = tower::service_fn(move |request| async move {
                let response = match request {
                    ReadRequest::UsageInfo => ReadResponse::UsageInfo(0),
                    ReadRequest::PruningInfo => ReadResponse::PruningInfo {
                        pruned: false,
                        prune_height: None,
                    },
                    ReadRequest::TipPoolValues => {
                        let Some(tip_height) = observed_tip else {
                            return Err("chain tip unavailable".into());
                        };
                        ReadResponse::TipPoolValues {
                            tip_height,
                            tip_hash: block::Hash([42; 32]),
                            value_balance: Default::default(),
                        }
                    }
                    ReadRequest::HeaderChainSnapshot => ReadResponse::HeaderChainSnapshot(None),
                    ReadRequest::ChainInfo => return Err("chain info unavailable".into()),
                    _ => panic!("unexpected RPC state request: {request:?}"),
                };
                Ok::<_, zakura_node_services::BoxError>(response)
            });
            let (_log_tx, log_rx) = tokio::sync::watch::channel(None);
            let (rpc, queue) = RpcImpl::new(
                network.clone(),
                Default::default(),
                false,
                "0.0.1",
                "SLH RPC unit test",
                MockService::build().for_unit_tests(),
                MockService::build().for_unit_tests(),
                read_state,
                MockService::build().for_unit_tests(),
                MockSyncStatus::default(),
                NoChainTip,
                MockAddressBookPeers::default(),
                log_rx,
                None,
            );
            let response =
                tokio::time::timeout(std::time::Duration::from_secs(1), rpc.get_blockchain_info())
                    .await
                    .expect("mock state responds without external waits")
                    .expect("getblockchaininfo retains its unavailable-state fallback");
            queue.abort();
            let info = response.experimental_slh_dsa_b128s().as_ref().unwrap();
            assert_eq!(info.tip_height(), observed_tip);
            assert_eq!(
                info.active_for_next_block(),
                observed_tip.map(|height| height == Height(1))
            );
        }
    }
}
