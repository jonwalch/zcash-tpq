//! RPC error boundary around the shared native pure diagnostics.

use crate::server::{
    error::{LegacyCode, MapError, OkOrError},
    jsonrpc::{ErrorObject, RpcResult},
};
use std::io::Cursor;
pub use zakura_chain::chain_diagnostics::{GetChainRulesResponse, InspectChainBlockResponse};
use zakura_chain::{
    block::{Block, MAX_BLOCK_BYTES},
    chain_diagnostics as native,
    parameters::Network,
    serialization::{ZcashDeserialize, ZcashSerialize},
};

pub(super) fn chain_rules(network: &Network) -> RpcResult<GetChainRulesResponse> {
    let identity = zakura_consensus::experimental_slh_dsa_b128s_verifier_identity();
    native::chain_rules(
        network,
        native::SlhSupport {
            contract: identity.contract,
            verifier_compiled: identity.verifier_compiled,
            runtime_supported: identity.runtime_supported,
        },
    )
    .map_error(LegacyCode::InvalidParameter)
}

pub(super) fn inspect_chain_block(block_hex: &str) -> RpcResult<InspectChainBlockResponse> {
    let unsupported = |message| ErrorObject::new(LegacyCode::InvalidParameter, message);
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
