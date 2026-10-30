//! Ensure/show a managed native identity without starting network or state services.

use std::path::PathBuf;

use clap::Parser;
use eyre::Result;

use crate::config::ZakuradConfig;

/// Ensure the configured network's durable private key and print only public identity.
#[derive(Debug, Parser)]
pub struct NativeIdentityCmd {
    /// Absolute owner-only identity directory, outside chain/cache snapshots.
    #[clap(long)]
    identity_dir: PathBuf,
}

impl NativeIdentityCmd {
    #[allow(clippy::print_stdout)]
    pub(crate) fn run(&self, config: &ZakuradConfig) -> Result<()> {
        let mut network = config.network.clone();
        network.identity_dir = self.identity_dir.clone();
        let node_id = network
            .ensure_managed_zakura_identity()
            .inspect_err(|error| {
                tracing::error!("Failed to ensure managed native identity: {error}")
            })?;
        println!(
            "{}",
            serde_json::json!({
                "schema": "zakura-native-identity/v1",
                "nodeId": node_id.to_string(),
                "chainFingerprint": network.network
                    .experimental_slh_dsa_b128s_chain_fingerprint().map(hex::encode),
            })
        );
        Ok(())
    }
}
