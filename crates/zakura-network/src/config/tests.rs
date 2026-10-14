//! Tests for zakura-network configs.

#![allow(clippy::unwrap_in_result)]

mod vectors;

pub(crate) const CUSTOM_SLH_FIELDS: &str = "experimental_slh_dsa_b128s_activation_height = 110, experimental_slh_dsa_b128s_max_checks_per_transaction = 16, experimental_slh_dsa_b128s_max_checks_per_block = 64";

pub(crate) fn custom_slh_config(fields: &str) -> String {
    let genesis = zakura_chain::block::Hash([42; 32]);
    let fields = if fields.is_empty() {
        String::new()
    } else {
        format!(", {fields}")
    };
    format!(
        "initial_testnet_peers = []\nnetwork = {{ network_name = 'SlhDevnet', network_magic = [83, 76, 72, 49], genesis_hash = '{genesis}', activation_heights = {{ 'NU6.3' = 1, NU7 = 105 }}, funding_streams = [], lockbox_disbursements = [], checkpoints = false{fields} }}\n[zakura]\nbootstrap_peers = []"
    )
}
