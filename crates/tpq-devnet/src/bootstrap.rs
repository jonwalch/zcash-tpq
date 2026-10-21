//! Checkpoint-only loading through the node verifier; never writes a database.
use crate::{require, rpc::Rpc, Chain, Result};
use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tip {
    pub height: Option<u32>,
    pub hash: Option<String>,
}

/// Validate configured identity even before genesis exists in state.
pub fn observe(rpc: &mut impl Rpc, chain: &Chain) -> Result<Tip> {
    let info = rpc.call("getblockchaininfo", json!([]))?;
    let slh = &info["experimental_slh_dsa_b128s"];
    require(
        slh["chain_fingerprint"].as_str() == Some(chain.chain_fingerprint.as_str())
            && slh["genesis_hash"].as_str() == Some(chain.rules.genesis_hash.as_str())
            && slh["runtime_supported"] == true,
        "node configured genesis/fingerprint/runtime mismatch",
    )?;
    match slh.get("tip_height").ok_or("missing observed tip height")? {
        Value::Null => Ok(Tip {
            height: None,
            hash: None,
        }),
        height => {
            let height = u32::try_from(height.as_u64().ok_or("invalid tip height")?)?;
            require(
                info["blocks"].as_u64() == Some(u64::from(height)),
                "node tip height observations disagree",
            )?;
            let hash = info["bestblockhash"]
                .as_str()
                .ok_or("missing best hash")?
                .to_owned();
            require(
                rpc.call("getblockhash", json!([height]))? == hash,
                "node best hash observations disagree",
            )?;
            Ok(Tip {
                height: Some(height),
                hash: Some(hash),
            })
        }
    }
}

pub fn stable(rpc: &mut impl Rpc, chain: &Chain) -> Result<Tip> {
    let tip = observe(rpc, chain)?;
    require(
        observe(rpc, chain)? == tip,
        "producer/peer activity changed the tip",
    )?;
    Ok(tip)
}

/// Caller must stop all block producers and inbound sync first. Restartable:
/// reconcile every accepted prefix, including a lost submitblock reply.
pub fn bootstrap(rpc: &mut impl Rpc, chain: &Chain, producers_stopped: bool) -> Result<()> {
    require(
        producers_stopped,
        "explicit stopped-producers precondition required",
    )?;
    let blocks = chain.validate()?;
    let mut tip = stable(rpc, chain)?;
    if let Some(height) = tip.height {
        require(
            usize::try_from(height)? < blocks.len(),
            "bootstrap refuses a tip beyond saved checkpoint range",
        )?;
        for index in 0..=height {
            require(
                rpc.call("getblockhash", json!([index]))?
                    == blocks[usize::try_from(index)?].hash().to_string(),
                "bootstrap conflicts with existing best chain",
            )?;
        }
    }
    for (index, block) in blocks.iter().enumerate() {
        let height = u32::try_from(index)?;
        if tip.height.is_some_and(|tip| height <= tip) {
            continue;
        }
        require(
            observe(rpc, chain)? == tip,
            "tip changed before seed submission",
        )?;
        let result = rpc.call("submitblock", json!([chain.blocks[index]]));
        // An error can be a lost reply after commit. Never blindly submit again.
        let after = stable(rpc, chain)?;
        let expected = Tip {
            height: Some(height),
            hash: Some(block.hash().to_string()),
        };
        if after != expected {
            return Err(if after == tip && result.is_err() {
                "seed outcome unresolved or rejected; restart bootstrap to reconcile"
            } else {
                "seed not on expected best chain; stop and inspect"
            }
            .into());
        }
        let actual = rpc.call("getblock", json!([block.hash().to_string(), 0]))?;
        require(
            actual.as_str() == Some(chain.blocks[index].as_str()),
            "node returned different saved block bytes",
        )?;
        tip = after;
    }
    require(
        stable(rpc, chain)? == tip,
        "tip changed at bootstrap completion",
    )?;
    Ok(())
}
