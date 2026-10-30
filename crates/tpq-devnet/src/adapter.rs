//! Signing-free ZDN public-input compiler. This module does not start a node,
//! access RPC, hold wallet keys or authenticate a publisher. Core supplies trust.
use crate::{require, Chain, Result, Rules};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zakura_chain::{
    chain_diagnostics::{self, SlhSupport, SLH_CONTRACT},
    serialization::ZcashSerialize,
};

pub const PROTOCOL: &str = "zdn-public-chain-adapter/v1";
pub const SCHEMA: &str = "zdn-external-public/v1";
pub const ADAPTER_ID: &str = "zdn-tpq";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAX_JSON: usize = 4 * 1024 * 1024;
pub const MAX_BUNDLE: u64 = 128 * 1024 * 1024;

macro_rules! wire {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Serialize, Deserialize)]
        #[serde(rename_all="camelCase",deny_unknown_fields)]
        pub struct $name { $(pub $field: $ty),* }
    };
}
wire!(Pin {
    bytes: u64,
    sha256: String
});
impl Pin {
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            // Supported Rust targets have at most 64-bit slice lengths.
            bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        }
    }
    fn check(&self, bytes: &[u8]) -> Result<()> {
        let actual = Self::of(bytes);
        require(
            self.bytes == actual.bytes && self.sha256 == actual.sha256,
            "public slot pin mismatch",
        )
    }
}
wire!(Descriptor {
    schema: String,
    native_name: String,
    native_fingerprint: String
});
wire!(CompileInput {
    descriptor: Descriptor,
    native_rules_json: String,
    wallet_profile_json: String,
    seed_bundle: Pin
});
wire!(SeedBlock {
    height: u32,
    hash: String,
    pin: Pin
});
wire!(Upgrade {
    name: String,
    branch_id: String,
    activation_height: u32
});
wire!(Compiled { schema: String, native_name: String, native_fingerprint: String, expected_rules: Value, upgrades: Vec<Upgrade>, seed_blocks: Vec<SeedBlock>, cargo_features: Vec<String>, required_capabilities: Vec<String>, transport_class: String });
wire!(Peer {
    node_id: String,
    endpoint: String
});
wire!(RenderOptions { deployment_id: String, node_id: String, role: String, image_digest: String, state_dir: String, identity_dir: String, cookie_dir: String, rpc_listen: String, native_listen: String, expected_node_id: String, peers: Vec<Peer>, reward_address: Option<String> });
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderInput {
    pub public: CompileInput,
    pub compiled_sha256: String,
    pub options: RenderOptions,
    #[serde(default, skip_serializing_if = "is_false")]
    pub identity_only: bool,
}
fn is_false(value: &bool) -> bool {
    !*value
}
wire!(Rendered {
    config_toml: String
});
wire!(Context { public_descriptor_sha256: String, input_sha256: String, seed_bundle_sha256: String, compiled_result_sha256: Option<String> });

/// Pure import of exactly the two named public preparation files. Callers must
/// never recursively copy the preparation directory or accept private funder data.
/// Returns the compiled result from this same fresh validation operation.
pub fn import_public(
    chain_json: &[u8],
    wallet_profile_json: &[u8],
) -> Result<(CompileInput, Vec<u8>, Compiled)> {
    require(
        u64::try_from(chain_json.len())? <= crate::MAX_FILE
            && wallet_profile_json.len() <= 2 * 1024 * 1024,
        "public file exceeds bound",
    )?;
    let chain: Chain = parse(chain_json)?;
    let blocks = chain.validate()?;
    chain.compare_wallet_profile(zakura_pq_wallet::Profile::from_json(wallet_profile_json)?)?;
    let mut bundle = Vec::new();
    for block in &blocks {
        let bytes = block.zcash_serialize_to_vec()?;
        require(
            bytes.len() <= 2_000_000,
            "large saved blocks are not supported",
        )?;
        bundle.extend_from_slice(&u32::try_from(bytes.len())?.to_le_bytes());
        bundle.extend_from_slice(&bytes);
    }
    let input = CompileInput {
        descriptor: Descriptor {
            schema: SCHEMA.into(),
            native_name: chain.rules.network_name.clone(),
            native_fingerprint: chain.chain_fingerprint.clone(),
        },
        native_rules_json: serde_json::to_string(&chain.rules)?,
        wallet_profile_json: std::str::from_utf8(wallet_profile_json)?.into(),
        seed_bundle: Pin::of(&bundle),
    };
    check_public_input(&input)?;
    let compiled = compile_validated(chain, &blocks, block_bytes(&bundle)?)?;
    Ok((input, bundle, compiled))
}

fn block_bytes(mut bundle: &[u8]) -> Result<Vec<&[u8]>> {
    require(
        u64::try_from(bundle.len())? <= MAX_BUNDLE,
        "seed bundle exceeds bound",
    )?;
    let mut blocks = vec![];
    while !bundle.is_empty() {
        require(
            bundle.len() >= 4 && blocks.len() < crate::MAX_SEED_BLOCKS,
            "invalid raw bundle",
        )?;
        let n = usize::try_from(u32::from_le_bytes(bundle[..4].try_into()?))?;
        bundle = &bundle[4..];
        require(
            n > 0 && n <= 2_000_000 && n <= bundle.len(),
            "invalid saved block size",
        )?;
        blocks.push(&bundle[..n]);
        bundle = &bundle[n..];
    }
    require(blocks.len() >= 2, "seed range is empty")?;
    Ok(blocks)
}

fn check_public_input(input: &CompileInput) -> Result<()> {
    require(
        input.descriptor.schema == SCHEMA
            && input.native_rules_json.len() <= 2 * 1024 * 1024
            && input.wallet_profile_json.len() <= 2 * 1024 * 1024,
        "unsupported public schema or size",
    )
}

/// Actually decode the raw bytes whose digest is claimed, then reuse native
/// chain/checkpoint/profile validation and the same projection as getchainrules.
pub fn compile(input: &CompileInput, bundle: &[u8]) -> Result<Compiled> {
    check_public_input(input)?;
    input.seed_bundle.check(bundle)?;
    let raw = block_bytes(bundle)?;
    let rules: Rules = parse(input.native_rules_json.as_bytes())?;
    require(
        rules.network_name == input.descriptor.native_name,
        "native name mismatch",
    )?;
    let chain = Chain {
        schema: 1,
        chain_fingerprint: input.descriptor.native_fingerprint.clone(),
        rules,
        blocks: raw.iter().map(hex::encode).collect(),
    };
    let blocks = chain.validate()?;
    chain.compare_wallet_profile(zakura_pq_wallet::Profile::from_json(
        input.wallet_profile_json.as_bytes(),
    )?)?;
    compile_validated(chain, &blocks, raw)
}

// Both callers freshly validate the immutable chain and profile before projecting.
fn compile_validated(
    chain: Chain,
    blocks: &[zakura_chain::block::Block],
    raw: Vec<&[u8]>,
) -> Result<Compiled> {
    let network = chain.rules.network()?;
    // These are requirements on the future running node, NOT observations of
    // this signing-free compiler. Runtime RPC must match the complete report.
    let report = chain_diagnostics::chain_rules(
        &network,
        SlhSupport {
            contract: SLH_CONTRACT,
            verifier_compiled: true,
            runtime_supported: true,
        },
    )?;
    // getblockchaininfo includes implicit upgrades at shared heights, unlike
    // getchainrules' collapsed effective schedule. Preserve both projections.
    let upgrades = network
        .full_activation_list()
        .into_iter()
        .map(|(height, upgrade)| {
            Ok(Upgrade {
                name: serde_json::to_value(upgrade)?
                    .as_str()
                    .ok_or("invalid upgrade name")?
                    .into(),
                branch_id: upgrade
                    .branch_id()
                    .map(|id| format!("{id}"))
                    .unwrap_or_else(|| "00000000".into()),
                activation_height: height.0,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let seed_blocks = blocks
        .iter()
        .zip(raw)
        .enumerate()
        .map(|(height, (block, bytes))| {
            Ok(SeedBlock {
                height: u32::try_from(height)?,
                hash: block.hash().to_string(),
                pin: Pin::of(bytes),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Compiled {
        schema: SCHEMA.into(),
        native_name: chain.rules.network_name,
        native_fingerprint: chain.chain_fingerprint,
        expected_rules: serde_json::to_value(report)?,
        upgrades,
        seed_blocks,
        cargo_features: vec![
            "default-release-binaries".into(),
            "experimental-slh-dsa-b128s".into(),
        ],
        required_capabilities: vec![
            "native-managed-identity-v1".into(),
            "slh-dsa-b128s-v2".into(),
        ],
        transport_class: "large-hex-v1".into(),
    })
}

pub fn render(input: &RenderInput, bundle: &[u8]) -> Result<Rendered> {
    let compiled = compile(&input.public, bundle)?;
    require(
        Pin::of(&serde_json::to_vec(&compiled)?).sha256 == input.compiled_sha256,
        "compiled bytes mismatch",
    )?;
    let o = &input.options;
    require(
        !input.identity_only
            || (o.role == "follower"
                && o.reward_address.is_none()
                && o.peers.is_empty()
                && o.expected_node_id.is_empty()),
        "identity-only rendering must not select a runtime",
    )?;
    require(
        o.peers.len() <= 128
            && matches!(o.role.as_str(), "producer" | "follower")
            && (o.role == "producer") == o.reward_address.is_some(),
        "invalid role/peers",
    )?;
    let rules: Rules = parse(input.public.native_rules_json.as_bytes())?;
    if let Some(address) = &o.reward_address {
        let address: zakura_chain::transparent::Address = address.parse()?;
        require(
            address.network_kind() == zakura_chain::parameters::NetworkKind::Testnet,
            "reward address must be Testnet",
        )?;
    }
    let mut peers: Vec<_> = o
        .peers
        .iter()
        .map(|p| format!("{}@{}", p.node_id, p.endpoint))
        .collect();
    peers.sort();
    let mut config = serde_json::json!({
        "network":{"network":rules,"p2p_stack":"zakura","listen_addr":o.native_listen,"identity_dir":o.identity_dir,"initial_mainnet_peers":[],"initial_testnet_peers":[],"cache_dir":false,
            "zakura":{"listen_addr":o.native_listen,"bootstrap_peers":peers,"nat_traversal":false,"expected_node_id":o.expected_node_id}},
        "state":{"cache_dir":o.state_dir,"ephemeral":false,"should_backup_non_finalized_state":true,"delete_old_database":false,"storage_mode":"archive"},
        "consensus":{"checkpoint_sync":true,"vct_fast_sync":false},"mempool":{"debug_enable_at_height":0},
        "rpc":{"listen_addr":o.rpc_listen,"cookie_dir":o.cookie_dir,"cookie_file_name":".cookie","enable_cookie_auth":true,"debug_force_finished_sync":false},
        "mining":{"internal_miner":false,"optimistic_block_inventory":false},
        "tracing":{"use_color":false,"force_use_color":false,"use_journald":false},"zcashd_compat":{"enabled":false}
    });
    if input.identity_only {
        config["network"]["zakura"]
            .as_object_mut()
            .expect("constructed table")
            .remove("expected_node_id");
    }
    if let Some(address) = &o.reward_address {
        config["mining"]["miner_address"] = address.clone().into();
    }
    fn no_nulls(v: &mut Value) {
        match v {
            Value::Object(m) => {
                m.retain(|_, v| !v.is_null());
                for v in m.values_mut() {
                    no_nulls(v);
                }
            }
            Value::Array(a) => {
                for v in a {
                    no_nulls(v);
                }
            }
            _ => {}
        }
    }
    no_nulls(&mut config);
    Ok(Rendered {
        config_toml: toml::to_string_pretty(&config)?,
    })
}

/// Strict tree validation precedes typed parsing, including nested JSON slots.
pub fn parse<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    use serde::de::{self, MapAccess, SeqAccess, Visitor};
    struct Checked(Value);
    struct Check;
    impl<'de> Visitor<'de> for Check {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("integer JSON with unique fields")
        }
        fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
            Ok(v.into())
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Value, E> {
            Ok(v.into())
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
            Ok(v.into())
        }
        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
            Ok(v.into())
        }
        fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
            Ok(v.into())
        }
        fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
            let mut v = vec![];
            while let Some(x) = a.next_element::<Checked>()? {
                v.push(x.0);
            }
            Ok(Value::Array(v))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
            let mut v = serde_json::Map::new();
            while let Some(k) = a.next_key::<String>()? {
                if v.contains_key(&k) {
                    return Err(de::Error::custom("duplicate field"));
                }
                v.insert(k, a.next_value::<Checked>()?.0);
            }
            Ok(Value::Object(v))
        }
    }
    impl<'de> Deserialize<'de> for Checked {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            d.deserialize_any(Check).map(Self)
        }
    }
    require(
        u64::try_from(bytes.len())? <= crate::MAX_FILE,
        "JSON exceeds bound",
    )?;
    let raw = serde_json::from_slice::<Checked>(bytes)?.0;
    let typed: T = serde_json::from_slice(bytes)?;
    fn shape(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::Object(a), Value::Object(b)) => {
                a.iter().all(|(k, v)| b.get(k).is_some_and(|b| shape(v, b)))
            }
            (Value::Array(a), Value::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(a, b)| shape(a, b))
            }
            (Value::Object(_), _)
            | (_, Value::Object(_))
            | (Value::Array(_), _)
            | (_, Value::Array(_)) => false,
            _ => true,
        }
    }
    require(
        shape(&raw, &serde_json::to_value(&typed)?),
        "positional object is forbidden",
    )?;
    Ok(typed)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    protocol: String,
    operation: String,
    request_id: String,
    adapter_selection_sha256: String,
    context: Option<Context>,
    input: Box<serde_json::value::RawValue>,
}

/// One bounded protocol exchange. File access is fixed to the staged raw slot.
pub fn respond(bytes: &[u8], bundle: impl FnOnce() -> Result<Vec<u8>>) -> Result<Vec<u8>> {
    require(bytes.len() <= MAX_JSON, "request exceeds bound")?;
    let request: Request = parse(bytes)?;
    fn hash(s: &str) -> bool {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    require(
        request.protocol == PROTOCOL
            && hash(&request.adapter_selection_sha256)
            && request.request_id.len() == 36
            && request.request_id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            }),
        "invalid request binding",
    )?;
    let result = match request.operation.as_str() {
        "describe" => {
            wire!(Describe {
                adapter_id: String,
                adapter_version: String,
                prepared_input_schema: String
            });
            let input: Describe = parse(request.input.get().as_bytes())?;
            require(
                request.context.is_none()
                    && input.adapter_id == ADAPTER_ID
                    && input.adapter_version == VERSION
                    && input.prepared_input_schema == SCHEMA,
                "incompatible adapter",
            )?;
            serde_json::to_string(
                &serde_json::json!({"adapterId":ADAPTER_ID,"adapterVersion":VERSION,"preparedInputSchema":SCHEMA,"runtimeFamily":"zakura-custom-testnet","operations":["describe","compile","render"]}),
            )?
        }
        "compile" => {
            let input: CompileInput = parse(request.input.get().as_bytes())?;
            check_context(
                &request,
                &input,
                &input.descriptor,
                &input.seed_bundle,
                None,
            )?;
            serde_json::to_string(&compile(&input, &bundle()?)?)?
        }
        "render" => {
            let input: RenderInput = parse(request.input.get().as_bytes())?;
            check_context(
                &request,
                &input,
                &input.public.descriptor,
                &input.public.seed_bundle,
                Some(&input.compiled_sha256),
            )?;
            serde_json::to_string(&render(&input, &bundle()?)?)?
        }
        _ => return Err("unsupported operation".into()),
    };
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Response<'a> {
        protocol: &'a str,
        operation: &'a str,
        request_id: &'a str,
        adapter_selection_sha256: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: &'a Option<Context>,
        result: Box<serde_json::value::RawValue>,
    }
    let output = serde_json::to_vec(&Response {
        protocol: PROTOCOL,
        operation: &request.operation,
        request_id: &request.request_id,
        adapter_selection_sha256: &request.adapter_selection_sha256,
        context: &request.context,
        result: serde_json::value::RawValue::from_string(result)?,
    })?;
    require(output.len() <= MAX_JSON, "output exceeds bound")?;
    Ok(output)
}
fn check_context<T: Serialize>(
    request: &Request,
    input: &T,
    descriptor: &Descriptor,
    bundle: &Pin,
    compiled: Option<&str>,
) -> Result<()> {
    let context = request.context.as_ref().ok_or("context required")?;
    require(
        context.public_descriptor_sha256 == Pin::of(&serde_json::to_vec(descriptor)?).sha256
            && context.input_sha256 == Pin::of(&serde_json::to_vec(input)?).sha256
            && context.seed_bundle_sha256 == bundle.sha256
            && context.compiled_result_sha256.as_deref() == compiled,
        "context mismatch",
    )
}

#[cfg(all(test, feature = "wallet"))]
mod tests {
    use super::*;
    #[test]
    fn public_import_compile_and_native_render_reuse_the_real_validators() {
        let root = tempfile::tempdir().unwrap();
        let public = root.path().join("public");
        let private = root.path().join("private");
        crate::prepare(&public, &private, "AdapterFixture".into()).unwrap();
        let chain = std::fs::read(public.join("chain.json")).unwrap();
        let profile = std::fs::read(public.join("wallet-profile.json")).unwrap();
        let (input, bundle, compiled) = import_public(&chain, &profile).unwrap();
        let compiled_bytes = serde_json::to_vec(&compiled).unwrap();
        assert_eq!(
            compiled_bytes,
            serde_json::to_vec(&compile(&input, &bundle).unwrap()).unwrap()
        );
        // Literal RPC expectations, not the diagnostic's collapsed schedule.
        let rpc_upgrades: Vec<_> = compiled
            .upgrades
            .iter()
            .filter(|u| u.branch_id != "00000000")
            .map(|u| (u.name.as_str(), u.branch_id.as_str(), u.activation_height))
            .collect();
        assert_eq!(
            rpc_upgrades,
            vec![
                ("Overwinter", "5ba81b19", 102),
                ("Sapling", "76b809bb", 102),
                ("Blossom", "2bb40e60", 102),
                ("Heartwood", "f5b9230b", 102),
                ("Canopy", "e9ff75a6", 102),
                ("NU5", "c2d6d0b4", 102),
                ("NU6", "c8e71055", 102),
                ("NU6.1", "4dec4df0", 102),
                ("NU6.2", "5437f330", 102),
                ("NU6.3", "37a5165b", 102),
                ("NU7", "77190ad9", 102),
            ]
        );
        for mutation in ["schema", "fingerprint", "block"] {
            let mut changed: Chain = parse(&chain).unwrap();
            match mutation {
                "schema" => changed.schema = 2,
                "fingerprint" => changed.chain_fingerprint = "00".repeat(32),
                "block" => changed.blocks[1].push_str("00"),
                _ => unreachable!(),
            }
            assert!(import_public(&serde_json::to_vec(&changed).unwrap(), &profile).is_err());
        }
        let mut mismatched_profile = zakura_pq_wallet::Profile::from_json(&profile).unwrap();
        mismatched_profile.max_block_pq_checks += 1;
        let mismatched_profile = serde_json::to_vec(&mismatched_profile).unwrap();
        for rejected_profile in [mismatched_profile, [profile.as_slice(), b" "].concat()] {
            assert!(import_public(&chain, &rejected_profile).is_err());
            let mut changed = input.clone();
            changed.wallet_profile_json = String::from_utf8(rejected_profile).unwrap();
            assert!(compile(&changed, &bundle).is_err());
        }
        assert_eq!(compiled.seed_blocks.len(), 102);
        assert_eq!(
            compiled.expected_rules["apiVersion"],
            "zakura-chain-rules/slh-dsa-b128s/v2"
        );
        assert_eq!(
            compiled.expected_rules["rules"]["experimental"]["slhDsaB128s"]["verifierCompiled"],
            true
        );
        assert_eq!(
            compiled.expected_rules["rules"]["experimental"]["slhDsaB128s"]["runtimeSupported"],
            true
        );
        let render_input = RenderInput {
            public: input.clone(),
            compiled_sha256: Pin::of(&compiled_bytes).sha256,
            identity_only: false,
            options: RenderOptions {
                deployment_id: "00000000-0000-4000-8000-000000000000".into(),
                node_id: "node-1".into(),
                role: "follower".into(),
                image_digest: format!("sha256:{}", "ab".repeat(32)),
                state_dir: "/tmp/state".into(),
                identity_dir: "/tmp/identity".into(),
                cookie_dir: "/tmp/rpc".into(),
                rpc_listen: "127.0.0.1:18232".into(),
                native_listen: "0.0.0.0:18233".into(),
                // RFC 8032 test-vector public key, not arbitrary hex bytes.
                expected_node_id:
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into(),
                peers: vec![],
                reward_address: None,
            },
        };
        let rendered = render(&render_input, &bundle).unwrap();
        let config: toml::Value = toml::from_str(&rendered.config_toml).unwrap();
        let network: zakura_network::Config = config["network"].clone().try_into().unwrap();
        assert_eq!(
            network
                .network
                .experimental_slh_dsa_b128s_chain_fingerprint()
                .map(hex::encode)
                .unwrap(),
            input.descriptor.native_fingerprint
        );
        let mut bad = input.clone();
        bad.descriptor.native_name = "Other".into();
        assert!(compile(&bad, &bundle).is_err());
        let mut tampered = bundle.clone();
        tampered[4] ^= 1;
        assert!(compile(&input, &tampered).is_err());
        // Rehashing malformed bytes must not turn integrity into native decoding.
        bad = input.clone();
        bad.seed_bundle = Pin::of(&tampered);
        assert!(compile(&bad, &tampered).is_err());
        bad = input.clone();
        bad.wallet_profile_json = bad.wallet_profile_json.replace("77190ad9", "00000000");
        assert!(compile(&bad, &bundle).is_err());
        let mut bad_render = render_input;
        bad_render.compiled_sha256 = "00".repeat(32);
        assert!(render(&bad_render, &bundle).is_err());
    }
}
