//! Bounded, opt-in devnet preparation and operations, outside the node graph.
#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod funding;
pub mod rpc;
pub mod storage;

use hex::FromHex;
use serde::{Deserialize, Serialize};
use std::{io::Cursor, path::Path};
use zakura_chain::{
    block::{Block, Height},
    local_genesis::{
        generate_local_testnet_with_slh_dsa_b128s_funding, LocalTestnetGenesisOptions,
    },
    parameters::{
        testnet::{
            ConfiguredActivationHeights, ConfiguredCheckpoints, ConfiguredLockboxDisbursement,
            ExperimentalSlhDsaB128sLimits, Parameters,
        },
        Magic, Network, NetworkUpgrade,
    },
    serialization::{ZcashDeserialize, ZcashSerialize},
};

pub type Result<T> = std::result::Result<T, zakura_chain::BoxError>;
pub const MAX_FILE: u64 = 16 * 1024 * 1024;
pub const MAX_SEED_BLOCKS: usize = 256;

pub(crate) fn require(ok: bool, reason: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(reason.into())
    }
}

/// Public chain rules, also the exact custom-network object in node config.
/// This bounded recipe is not a general network configuration importer.
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    pub network_name: String,
    pub network_magic: [u8; 4],
    pub genesis_hash: String,
    pub target_difficulty_limit: String,
    pub disable_pow: bool,
    pub slow_start_interval: u32,
    pub max_block_time_start_height: u32,
    pub should_allow_unshielded_coinbase_spends: bool,
    pub activation_heights: ConfiguredActivationHeights,
    pub pre_blossom_halving_interval: u32,
    pub funding_streams: Vec<serde_json::Value>,
    pub lockbox_disbursements: Vec<ConfiguredLockboxDisbursement>,
    pub checkpoints: ConfiguredCheckpoints,
    pub experimental_slh_dsa_b128s_activation_height: u32,
    pub experimental_slh_dsa_b128s_max_checks_per_transaction: u32,
    pub experimental_slh_dsa_b128s_max_checks_per_block: u32,
}

impl Rules {
    pub fn network(&self) -> Result<Network> {
        require(
            self.funding_streams.is_empty()
                && self.slow_start_interval == 0
                && self.pre_blossom_halving_interval == 144
                && self.should_allow_unshielded_coinbase_spends,
            "not the supported transparent devnet funding recipe",
        )?;
        require(
            matches!(&self.checkpoints, ConfiguredCheckpoints::HeightsAndHashes(items) if (2..=MAX_SEED_BLOCKS).contains(&items.len()))
                && self.lockbox_disbursements.len() == 1,
            "only bounded inline seed checkpoints and one lockbox marker are supported",
        )?;
        let difficulty_bytes = <[u8; 32]>::from_hex(&self.target_difficulty_limit)?;
        require(
            difficulty_bytes.iter().any(|byte| *byte != 0),
            "zero difficulty is invalid",
        )?;
        let marker = &self.lockbox_disbursements[0];
        require(
            marker.amount.is_zero()
                && marker
                    .address
                    .parse::<zakura_chain::transparent::Address>()?
                    == zakura_chain::transparent::Address::from_script_hash(
                        zakura_chain::parameters::NetworkKind::Testnet,
                        [0; 20],
                    ),
            "unsupported lockbox marker",
        )?;
        Ok(Parameters::build()
            .with_network_name(&self.network_name)?
            .with_network_magic(Magic(self.network_magic))?
            .with_genesis_hash(&self.genesis_hash)?
            .with_target_difficulty_limit(
                zakura_chain::work::difficulty::ExpandedDifficulty::from_hex(
                    &self.target_difficulty_limit,
                )?,
            )?
            .with_disable_pow(self.disable_pow)
            .with_unshielded_coinbase_spends(true)
            .with_slow_start_interval(Height(0))
            .with_max_block_time_start_height(Height(self.max_block_time_start_height))
            .with_activation_heights(self.activation_heights)?
            .with_halving_interval(144)?
            .with_funding_streams(vec![])
            .with_lockbox_disbursements(self.lockbox_disbursements.clone())
            .with_checkpoints(self.checkpoints.clone())?
            .with_experimental_slh_dsa_b128s(
                Height(self.experimental_slh_dsa_b128s_activation_height),
                ExperimentalSlhDsaB128sLimits::new(
                    self.experimental_slh_dsa_b128s_max_checks_per_transaction,
                    self.experimental_slh_dsa_b128s_max_checks_per_block,
                )?,
            )?
            .to_network()?)
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    pub schema: u8,
    pub chain_fingerprint: String,
    pub rules: Rules,
    /// Exact canonical seed bytes, never regenerated on restart.
    pub blocks: Vec<String>,
}

impl Chain {
    /// Wallet transport identity derived from the validated native chain rules.
    pub fn wallet_profile(&self) -> Result<zakura_pq_wallet::Profile> {
        self.validate()?;
        let profile = zakura_pq_wallet::Profile {
            chain_fingerprint: Some(zakura_pq_wallet::Hex(
                hex::decode(&self.chain_fingerprint)?
                    .try_into()
                    .map_err(|_| "fingerprint length")?,
            )),
            genesis_hash: zakura_pq_wallet::Hex(
                hex::decode(&self.rules.genesis_hash)?
                    .try_into()
                    .map_err(|_| "genesis hash length")?,
            ),
            max_block_pq_checks: self.rules.experimental_slh_dsa_b128s_max_checks_per_block,
            max_tx_pq_checks: self
                .rules
                .experimental_slh_dsa_b128s_max_checks_per_transaction,
            network: 1,
            nu7_activation_height: self.rules.activation_heights.nu7.ok_or("missing NU7")?,
            nu7_branch_id: "77190ad9".into(),
            pq_activation_height: self.rules.experimental_slh_dsa_b128s_activation_height,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Decode and bind all saved blocks to the native rules and checkpoints.
    pub fn validate(&self) -> Result<Vec<Block>> {
        require(
            self.schema == 1 && (2..=MAX_SEED_BLOCKS).contains(&self.blocks.len()),
            "invalid saved seed range",
        )?;
        let network = self.rules.network()?;
        require(
            network
                .experimental_slh_dsa_b128s_chain_fingerprint()
                .map(hex::encode)
                .as_deref()
                == Some(self.chain_fingerprint.as_str()),
            "saved chain fingerprint mismatch",
        )?;
        let blocks = self
            .blocks
            .iter()
            .map(|hex| decode_block(hex))
            .collect::<Result<Vec<_>>>()?;
        let tip = Height(u32::try_from(blocks.len() - 1)?);
        require(
            network.checkpoint_list().max_height() == tip
                && NetworkUpgrade::Nu7.activation_height(&network) == Some(tip.next()?)
                && network.experimental_slh_dsa_b128s_activation_height()
                    == Some(tip.next()?.next()?),
            "seed range must end immediately before NU7 and SLH",
        )?;
        for (index, block) in blocks.iter().enumerate() {
            let height = Height(u32::try_from(index)?);
            require(
                block.coinbase_height() == Some(height),
                "wrong saved block height",
            )?;
            let merkle: zakura_chain::block::merkle::Root =
                block.transactions.iter().cloned().collect();
            require(
                block.header.merkle_root == merkle,
                "saved transaction merkle root mismatch",
            )?;
            require(
                network.checkpoint_list().hash(height) == Some(block.hash()),
                "saved block not an exact checkpoint",
            )?;
            if index == 0 {
                require(
                    block.hash() == network.genesis_hash()
                        && block.header.previous_block_hash == zakura_chain::block::Hash([0; 32]),
                    "wrong genesis",
                )?;
            } else {
                require(
                    block.header.previous_block_hash == blocks[index - 1].hash(),
                    "saved parent mismatch",
                )?;
            }
        }
        Ok(blocks)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let chain: Self = serde_json::from_slice(&storage::read_bounded(path, MAX_FILE)?)?;
        chain.validate()?;
        Ok(chain)
    }
}

pub(crate) fn decode_block(encoded: &str) -> Result<Block> {
    require(
        encoded.len() <= 2 * 1024 * 1024,
        "seed block exceeds tool bound",
    )?;
    let bytes = hex::decode(encoded)?;
    let mut cursor = Cursor::new(&bytes);
    let block = Block::zcash_deserialize(&mut cursor)?;
    require(
        cursor.position() == u64::try_from(bytes.len())?,
        "trailing block bytes",
    )?;
    require(
        block.zcash_serialize_to_vec()? == bytes,
        "noncanonical block",
    )?;
    Ok(block)
}

/// Generate one private local cohort. PoW is explicitly disabled in this recipe.
/// A separate create-new private directory holds the classical key, not a PQ root.
pub fn prepare(public_dir: &Path, private_dir: &Path, name: String) -> Result<Chain> {
    storage::create_private_dir(private_dir)?;
    std::fs::create_dir(public_dir)?;
    let public_path = public_dir.canonicalize()?;
    let private_path = private_dir.canonicalize()?;
    require(
        !private_path.starts_with(&public_path) && !public_path.starts_with(&private_path),
        "public and private directories must be separate, not nested",
    )?;
    let generated = generate_local_testnet_with_slh_dsa_b128s_funding(
        vec!["funder".into()],
        LocalTestnetGenesisOptions {
            network_name: name,
            latest_network_upgrade: NetworkUpgrade::Nu7,
            disable_pow: true,
            maturity_padding_blocks: 100,
            ..Default::default()
        },
        ExperimentalSlhDsaB128sLimits::new(16, 64)?,
    )?;
    let params = generated
        .network
        .parameters()
        .ok_or("expected custom network")?;
    let chain = Chain {
        schema: 1,
        chain_fingerprint: hex::encode(
            generated
                .network
                .experimental_slh_dsa_b128s_chain_fingerprint()
                .ok_or("missing fingerprint")?,
        ),
        rules: Rules {
            network_name: params.network_name().into(),
            network_magic: params.network_magic().0,
            genesis_hash: params.genesis_hash().to_string(),
            target_difficulty_limit: params.target_difficulty_limit().to_string(),
            disable_pow: params.disable_pow(),
            slow_start_interval: 0,
            max_block_time_start_height: params.max_block_time_start_height().0,
            should_allow_unshielded_coinbase_spends: true,
            activation_heights: params.activation_heights().into(),
            pre_blossom_halving_interval: 144,
            funding_streams: vec![],
            lockbox_disbursements: params
                .lockbox_disbursements()
                .into_iter()
                .map(Into::into)
                .collect(),
            checkpoints: ConfiguredCheckpoints::HeightsAndHashes(generated.checkpoints),
            experimental_slh_dsa_b128s_activation_height: params
                .experimental_slh_dsa_b128s_activation_height()
                .ok_or("missing SLH")?
                .0,
            experimental_slh_dsa_b128s_max_checks_per_transaction: 16,
            experimental_slh_dsa_b128s_max_checks_per_block: 64,
        },
        blocks: generated
            .blocks
            .iter()
            .map(|block| block.zcash_serialize_to_vec().map(hex::encode))
            .collect::<std::result::Result<_, _>>()?,
    };
    chain.validate()?;
    let private = serde_json::json!({"schema":1,"chain_fingerprint":chain.chain_fingerprint,
        "secret_key_hex":generated.funded_keys[0].secret_key_hex});
    storage::write_new(
        &private_dir.join("funder.json"),
        &serde_json::to_vec_pretty(&private)?,
    )?;
    storage::write_new(
        &public_dir.join("chain.json"),
        &serde_json::to_vec_pretty(&chain)?,
    )?;
    // The wallet's typed field order and compact serializer are canonical.
    let profile_bytes = serde_json::to_vec(&chain.wallet_profile()?)?;
    zakura_pq_wallet::Profile::from_json(&profile_bytes)?;
    storage::write_new(&public_dir.join("wallet-profile.json"), &profile_bytes)?;
    storage::write_new(
        &public_dir.join("network.json"),
        &serde_json::to_vec_pretty(&serde_json::json!({
            "network": {"network":chain.rules,"p2p_stack":"zakura","initial_testnet_peers":[],"zakura":{"bootstrap_peers":[]}}
        }))?,
    )?;
    #[derive(Serialize)]
    struct NativePeers {
        bootstrap_peers: Vec<String>,
    }
    #[derive(Serialize)]
    struct NodeNetwork<'a> {
        network: &'a Rules,
        p2p_stack: &'static str,
        initial_testnet_peers: Vec<String>,
        zakura: NativePeers,
    }
    #[derive(Serialize)]
    struct NodeConfig<'a> {
        network: NodeNetwork<'a>,
    }
    let config = NodeConfig {
        network: NodeNetwork {
            network: &chain.rules,
            p2p_stack: "zakura",
            initial_testnet_peers: vec![],
            zakura: NativePeers {
                bootstrap_peers: vec![],
            },
        },
    };
    storage::write_new(
        &public_dir.join("node-network.toml"),
        toml::to_string_pretty(&config)?.as_bytes(),
    )?;
    Ok(chain)
}
