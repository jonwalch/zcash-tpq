//! Node-owned identities for configured Testnet startup.
//!
//! These diagnostics read parsed consensus parameters or decode block bytes. They
//! do not accept claimed fingerprints, submit blocks, or certify consensus validity.

use std::io::Cursor;

use jsonrpsee::core::RpcResult;
use jsonrpsee_types::ErrorObjectOwned;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zakura_chain::{
    block::{Block, MAX_BLOCK_BYTES},
    parameters::{subsidy::FundingStreamReceiver, Network, NetworkKind, NetworkUpgrade},
    serialization::{ZcashDeserialize, ZcashSerialize},
    transparent::Address,
};

use crate::server::error::{LegacyCode, MapError, OkOrError};

/// Effective configured-Testnet rule report, independent of a config file or manifest.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetChainRulesResponse {
    /// Version of this diagnostic schema.
    pub api_version: String,
    /// Versioned fixed protocol semantics for the configurable rules below.
    pub ruleset: String,
    /// This schema currently supports only `custom-testnet`.
    pub network_kind: String,
    /// Effective values from the node's parsed network parameters.
    pub rules: ChainRules,
}

/// Configurable consensus rules; no deployment names or claimed fingerprints.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChainRules {
    /// Network magic bytes in wire order, as lowercase hex.
    pub network_magic: String,
    /// Configured genesis hash, in display order.
    pub genesis_hash: String,
    /// Checkpoints in ascending height order, including genesis.
    pub checkpoints: Vec<RuleCheckpoint>,
    /// Actual activation map, including Genesis; equal-height entries are collapsed.
    pub activation_heights: Vec<RuleActivation>,
    /// Effective subsidy, funding, lockbox, and NSM settings.
    pub subsidy: RuleSubsidy,
    /// Effective difficulty and proof-of-work policy.
    pub difficulty: RuleDifficulty,
    /// Temporary Orchard disabling height, or no disabling rule.
    pub temporary_orchard_disabling_height: Option<u32>,
    /// Disabled experiments, or explicitly versioned SLH diagnostics.
    pub experimental: RuleExperiments,
}

/// A height and checkpoint hash in display order.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleCheckpoint {
    /// Checkpoint height.
    pub height: u32,
    /// Block hash in display order.
    pub hash: String,
}

/// One entry in the effective network upgrade map.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleActivation {
    /// Activation height.
    pub height: u32,
    /// Versioned upgrade spelling, such as `Genesis` or `NU6.3`.
    pub upgrade: String,
}

/// Effective configurable subsidy rules.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleSubsidy {
    /// Number of slow-start blocks.
    pub slow_start_interval: u32,
    /// Effective slow-start shift.
    pub slow_start_shift: u32,
    /// Halving interval before Blossom.
    pub pre_blossom_halving_interval: u64,
    /// Halving interval from Blossom onwards.
    pub post_blossom_halving_interval: u64,
    /// Funding periods, in ascending range order.
    pub funding_streams: Vec<RuleFundingStream>,
    /// Expected outputs, sorted by script hash and amount; duplicates are preserved.
    pub lockbox_disbursements: Vec<RuleLockboxOutput>,
    /// Explicit NSM seed override, or `None` to derive it from state.
    pub initial_nsm_value_balance: Option<u64>,
    /// Whether transparent outputs may spend coinbase outputs.
    pub allow_unshielded_coinbase_spends: bool,
}

/// One resolved funding period, with an exclusive end height.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleFundingStream {
    /// Inclusive start height.
    pub start_height: u32,
    /// Exclusive end height.
    pub end_height: u32,
    /// Recipients sorted by their receiver string.
    pub recipients: Vec<RuleFundingRecipient>,
}

/// Funding recipient and ordered address-period script identities.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleFundingRecipient {
    /// One of `ecc`, `zcash-foundation`, `major-grants`, or `deferred`.
    pub receiver: String,
    /// Funding share numerator under the versioned protocol denominator.
    pub numerator: u64,
    /// P2SH script hashes in address-period order, in lowercase hex.
    pub script_hashes: Vec<String>,
}

/// One expected lockbox output.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleLockboxOutput {
    /// P2SH script hash in lowercase hex.
    pub script_hash: String,
    /// Amount in zatoshis.
    pub amount: u64,
}

/// Effective difficulty policy.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleDifficulty {
    /// Canonical compact target, as eight lowercase display-order hex digits.
    pub target_difficulty_limit_compact: String,
    /// `disabled` or `equihash`.
    pub proof_of_work: String,
    /// Activation of the MTP-plus-90-minutes rule.
    pub max_block_time_start_height: u32,
}

/// Disabled experiments are explicit rather than silently omitted.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleExperiments {
    /// This schema version accepts only `null`.
    pub pq: Option<()>,
    /// This schema version accepts only `null`.
    pub sqisign: Option<()>,
    /// SLH diagnostics are present only in the SLH-specific v2 projection.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub slh_dsa_b128s: Option<RuleSlhDsaB128s>,
}

/// Configured SLH rules and compiled support, independent of chain-tip state.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleSlhDsaB128s {
    /// Signing contract reported by the compiled verifier.
    pub contract: String,
    /// Whether the verifier is compiled in.
    pub verifier_compiled: bool,
    /// Whether all node runtime paths support SLH.
    pub runtime_supported: bool,
    /// Native consensus fingerprint, not a supplied manifest digest.
    pub chain_fingerprint: String,
    /// First SLH-governed block height.
    pub activation_height: u32,
    /// Per-transaction check limit.
    pub max_checks_per_transaction: u32,
    /// Per-block check limit.
    pub max_checks_per_block: u32,
    /// Fork-wide encoded block limit, in bytes.
    pub max_block_bytes: u64,
}

/// Structural identity of exact encoded bytes, not evidence of consensus acceptance.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectChainBlockResponse {
    /// Version of this diagnostic schema.
    pub api_version: String,
    /// Height recognized by the node's coinbase input decoder.
    pub height: u32,
    /// Header hash in display order.
    pub hash: String,
    /// Parent header hash in display order.
    pub previous_hash: String,
    /// Exact byte length of the canonical input.
    pub bytes_length: u64,
}

fn unsupported(message: &str) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(LegacyCode::InvalidParameter.into(), message, None::<()>)
}

fn script_identity(address: &Address) -> RpcResult<String> {
    match address {
        Address::PayToScriptHash {
            network_kind: NetworkKind::Testnet,
            script_hash,
        } => Ok(hex::encode(script_hash)),
        _ => Err(unsupported(
            "chain rules v1 requires Testnet P2SH funding and lockbox addresses",
        )),
    }
}

fn upgrade_name(upgrade: NetworkUpgrade) -> RpcResult<&'static str> {
    Ok(match upgrade {
        NetworkUpgrade::Genesis => "Genesis",
        NetworkUpgrade::BeforeOverwinter => "BeforeOverwinter",
        NetworkUpgrade::Overwinter => "Overwinter",
        NetworkUpgrade::Sapling => "Sapling",
        NetworkUpgrade::Blossom => "Blossom",
        NetworkUpgrade::Heartwood => "Heartwood",
        NetworkUpgrade::Canopy => "Canopy",
        NetworkUpgrade::Nu5 => "NU5",
        NetworkUpgrade::Nu6 => "NU6",
        NetworkUpgrade::Nu6_1 => "NU6.1",
        NetworkUpgrade::Nu6_2 => "NU6.2",
        NetworkUpgrade::Nu6_3 => "NU6.3",
        NetworkUpgrade::Nu7 => "NU7",
        #[cfg(zcash_unstable = "zfuture")]
        NetworkUpgrade::ZFuture => {
            return Err(unsupported("chain rules v1 does not support ZFuture"))
        }
    })
}

/// Projects only the parsed running network. A caller cannot supply claimed rules.
pub(super) fn chain_rules(network: &Network) -> RpcResult<GetChainRulesResponse> {
    let Network::Testnet(params) = network else {
        return Err(unsupported("chain rules v1 requires a configured Testnet"));
    };
    if params.is_default_testnet() || params.is_regtest() {
        return Err(unsupported("chain rules v1 requires a configured Testnet"));
    }
    let slh = super::ExperimentalSlhDsaB128sInfo::for_network(network, None)
        .map(|info| -> RpcResult<RuleSlhDsaB128s> {
            Ok(RuleSlhDsaB128s {
                contract: info.contract().clone(),
                verifier_compiled: info.verifier_compiled(),
                runtime_supported: info.runtime_supported(),
                chain_fingerprint: info.chain_fingerprint().clone().ok_or_else(|| {
                    unsupported("custom SLH Testnet requires a native chain fingerprint")
                })?,
                activation_height: info.activation_height().0,
                max_checks_per_transaction: info.max_checks_per_transaction(),
                max_checks_per_block: info.max_checks_per_block(),
                max_block_bytes: MAX_BLOCK_BYTES,
            })
        })
        .transpose()?;
    #[cfg(any(test, feature = "proptest-impl"))]
    if params.test_nsm_reissuance_height().is_some() {
        return Err(unsupported(
            "chain rules v1 does not support artificial NSM reissuance",
        ));
    }

    let mut funding_streams = params
        .funding_streams()
        .iter()
        .map(|stream| {
            let mut recipients = stream
                .recipients()
                .iter()
                .map(|(receiver, recipient)| {
                    Ok(RuleFundingRecipient {
                        receiver: match receiver {
                            FundingStreamReceiver::Ecc => "ecc",
                            FundingStreamReceiver::ZcashFoundation => "zcash-foundation",
                            FundingStreamReceiver::MajorGrants => "major-grants",
                            FundingStreamReceiver::Deferred => "deferred",
                        }
                        .into(),
                        numerator: recipient.numerator(),
                        script_hashes: recipient
                            .addresses()
                            .iter()
                            .map(script_identity)
                            .collect::<RpcResult<_>>()?,
                    })
                })
                .collect::<RpcResult<Vec<_>>>()?;
            recipients.sort_by(|a, b| a.receiver.cmp(&b.receiver));
            Ok(RuleFundingStream {
                start_height: stream.height_range().start.0,
                end_height: stream.height_range().end.0,
                recipients,
            })
        })
        .collect::<RpcResult<Vec<_>>>()?;
    funding_streams.sort_by_key(|stream| (stream.start_height, stream.end_height));
    let mut lockbox_disbursements = params
        .lockbox_disbursements()
        .into_iter()
        .map(|(address, amount)| {
            Ok(RuleLockboxOutput {
                script_hash: script_identity(&address)?,
                amount: u64::from(amount),
            })
        })
        .collect::<RpcResult<Vec<_>>>()?;
    lockbox_disbursements
        .sort_by(|a, b| (&a.script_hash, a.amount).cmp(&(&b.script_hash, b.amount)));

    Ok(GetChainRulesResponse {
        api_version: if slh.is_some() {
            "zakura-chain-rules/slh-dsa-b128s/v2"
        } else {
            "zakura-chain-rules/v1"
        }
        .into(),
        ruleset: if slh.is_some() {
            "zakura-configured-testnet/slh-dsa-b128s/v2"
        } else {
            "zakura-configured-testnet/v1"
        }
        .into(),
        network_kind: "custom-testnet".into(),
        rules: ChainRules {
            network_magic: hex::encode(params.network_magic().0),
            genesis_hash: params.genesis_hash().to_string(),
            checkpoints: params
                .checkpoints()
                .iter()
                .map(|(height, hash)| RuleCheckpoint {
                    height: height.0,
                    hash: hash.to_string(),
                })
                .collect(),
            activation_heights: params
                .activation_heights()
                .iter()
                .map(|(height, upgrade)| {
                    Ok(RuleActivation {
                        height: height.0,
                        upgrade: upgrade_name(*upgrade)?.into(),
                    })
                })
                .collect::<RpcResult<_>>()?,
            subsidy: RuleSubsidy {
                slow_start_interval: params.slow_start_interval().0,
                slow_start_shift: params.slow_start_shift().0,
                pre_blossom_halving_interval: u64::try_from(params.pre_blossom_halving_interval())
                    .map_error(LegacyCode::InvalidParameter)?,
                post_blossom_halving_interval: u64::try_from(
                    params.post_blossom_halving_interval(),
                )
                .map_error(LegacyCode::InvalidParameter)?,
                funding_streams,
                lockbox_disbursements,
                initial_nsm_value_balance: params
                    .configured_initial_nsm_value_balance()
                    .map(u64::from),
                allow_unshielded_coinbase_spends: params.should_allow_unshielded_coinbase_spends(),
            },
            difficulty: RuleDifficulty {
                target_difficulty_limit_compact: params
                    .target_difficulty_limit()
                    .to_compact()
                    .to_string(),
                proof_of_work: if params.disable_pow() {
                    "disabled"
                } else {
                    "equihash"
                }
                .into(),
                max_block_time_start_height: params.max_block_time_start_height().0,
            },
            temporary_orchard_disabling_height: params
                .temporary_orchard_disabling_soft_fork_height()
                .map(|height| height.0),
            experimental: RuleExperiments {
                pq: None,
                sqisign: None,
                slh_dsa_b128s: slh,
            },
        },
    })
}

/// Decodes an exact canonical block under protocol limits without touching state.
pub(super) fn inspect_chain_block(block_hex: &str) -> RpcResult<InspectChainBlockResponse> {
    let hex_length = u64::try_from(block_hex.len()).map_error(LegacyCode::InvalidParameter)?;
    if hex_length == 0 || hex_length % 2 != 0 || hex_length > MAX_BLOCK_BYTES * 2 {
        return Err(unsupported(
            "block hex must encode 1..=MAX_BLOCK_BYTES complete bytes",
        ));
    }
    let bytes = hex::decode(block_hex).map_error(LegacyCode::Deserialization)?;
    let mut cursor = Cursor::new(&bytes);
    let block = Block::zcash_deserialize(&mut cursor).map_error(LegacyCode::Deserialization)?;
    if cursor.position() != hex_length / 2 {
        return Err(unsupported("block contains trailing bytes"));
    }
    let encoded = block
        .zcash_serialize_to_vec()
        .map_error(LegacyCode::Deserialization)?;
    if encoded != bytes {
        return Err(unsupported("block encoding is not canonical"));
    }
    let height = block.coinbase_height().ok_or_error(
        LegacyCode::Deserialization,
        "block has no recognized coinbase height",
    )?;
    Ok(InspectChainBlockResponse {
        api_version: "zakura-block-inspection/v1".into(),
        height: height.0,
        hash: block.hash().to_string(),
        previous_hash: block.header.previous_block_hash.to_string(),
        bytes_length: hex_length / 2,
    })
}

#[cfg(test)]
mod tests;
