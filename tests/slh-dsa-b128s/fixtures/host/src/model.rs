//! Exact public-only version 1 transport schema.

use serde::{Deserialize, Deserializer, Serialize};

fn required_option<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub enum Request {
    #[serde(rename = "classical-info")]
    ClassicalInfo {
        schema_version: u64,
        contract: String,
        public_fixture: bool,
        kind: String,
    },
    #[serde(rename = "classical-spend")]
    ClassicalSpend {
        schema_version: u64,
        contract: String,
        public_fixture: bool,
        recipe: ClassicalRecipe,
    },
    Prepare {
        schema_version: u64,
        contract: String,
        public_fixture: bool,
        recipe: Recipe,
    },
    Assemble {
        schema_version: u64,
        contract: String,
        public_fixture: bool,
        recipe: Recipe,
        records: Vec<Vec<Record>>,
        producer: Box<Producer>,
    },
    Check {
        schema_version: u64,
        contract: String,
        public_fixture: bool,
        artifact: Box<Artifact>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassicalRecipe {
    pub kind: String,
    pub transaction_version: u8,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub parent_hex: String,
    pub output_index: u32,
    pub outputs: Vec<ScriptOutput>,
    pub fee_zat: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub case_id: String,
    pub network: String,
    pub transaction_version: u8,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub inputs: Vec<RecipeInput>,
    pub outputs: Vec<RecipeOutput>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeInput {
    pub outpoint: RecipeOutpoint,
    pub sequence: u32,
    pub value_zat: u64,
    pub threshold: u8,
    pub public_keys_hex: Vec<String>,
    pub signer_indices: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeOutpoint {
    pub txid_display_hex: String,
    pub index: u32,
}
#[derive(Deserialize)]
#[serde(untagged)]
pub enum RecipeOutput {
    Policy(PolicyOutput),
    Script(ScriptOutput),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyOutput {
    pub value_zat: u64,
    pub input_policy_index: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptOutput {
    pub value_zat: u64,
    pub script_hex: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Producer {
    pub zakura_revision: String,
    pub algorithm_revision: String,
    pub blake3_version: String,
    pub host_source_inventory_sha256: String,
    pub host_lock_sha256: String,
    pub host_binary_sha256: String,
    pub signer_source_inventory_sha256: String,
    pub signer_lock_sha256: String,
    pub signer_binary_sha256: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub schema_version: u64,
    pub contract: String,
    pub public_fixture: bool,
    pub case_id: String,
    pub context_provenance: String,
    pub producer: Producer,
    pub network: String,
    pub transaction_version: u8,
    pub consensus_branch_id: u32,
    pub transaction_hex: String,
    pub transaction_sha256: String,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub expected: Outcome,
    pub artifact_sha256: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub input_index: usize,
    pub outpoint: Outpoint,
    pub sequence: u32,
    pub spent_output: SpentOutput,
    pub descriptor_hex: String,
    pub sighash_all_digest_hex: String,
    pub message_hex: String,
    pub context_hex: String,
    pub records: Vec<Record>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Outpoint {
    pub txid_display_hex: String,
    pub index: u32,
    pub wire_hex: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpentOutput {
    pub value_zat: u64,
    pub script_hex: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub signer_index: u8,
    pub public_key_hex: String,
    pub signature_hex: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    pub output_index: usize,
    pub value_zat: u64,
    pub script_hex: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub native_authorization: String,
    #[serde(deserialize_with = "required_option")]
    pub native_rejection: Option<NativeRejection>,
    #[serde(deserialize_with = "required_option")]
    pub signature_checks: Option<usize>,
    pub functional_profile: FunctionalProfile,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRejection {
    pub stage: String,
    pub reason: String,
    #[serde(deserialize_with = "required_option")]
    pub input_index: Option<usize>,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionalProfile {
    pub transaction_limit: u64,
    pub block_limit: u64,
    pub result: String,
    #[serde(deserialize_with = "required_option")]
    pub stage: Option<String>,
}
