use crate::{manifest::bounded, Error, Hex, Manifest};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
};
use zakura_chain::{
    block::{merkle, Block, MAX_BLOCK_BYTES},
    serialization::{BytesInDisplayOrder, ZcashDeserialize},
    transparent::{Input, MIN_TRANSPARENT_COINBASE_MATURITY},
};

pub(crate) const MAX_COINS: usize = 10_000;
const MAX_UNDO_BLOCKS: usize = 128;
const MAX_UNDO_CHANGES: usize = 20_000;

/// Hashes are in RPC display order, unlike internal consensus serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// RPC display-order block hash.
    pub hash: Hex<32>,
    /// Block height.
    pub height: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The trusted node context independently matched to the approved profile.
pub struct NodeContext {
    /// Trusted node network label.
    pub chain: String,
    /// Candidate-block consensus branch identifier.
    pub next_branch_id: Hex<4>,
    /// Trusted node NU7 activation height.
    pub nu7_activation_height: u32,
    /// Observed trusted node tip.
    pub tip: Checkpoint,
}
impl NodeContext {
    pub(crate) fn validate(&self, manifest: &Manifest) -> Result<(), Error> {
        let next = self
            .tip
            .height
            .checked_add(1)
            .ok_or(Error::UnsupportedContext)?;
        // This Zakura pin reports Regtest through its BIP70 "test" alias. The
        // scanner also MUST match getblockhash(0) to the approved profile; this
        // label alone cannot distinguish Testnet from a private Regtest chain.
        if !matches!(self.chain.as_str(), "test" | "regtest")
            || self.nu7_activation_height != manifest.profile.nu7_activation_height
            || (next >= self.nu7_activation_height)
                != (self.next_branch_id == Hex([0x77, 0x19, 0x0a, 0xd9]))
        {
            return Err(Error::UnsupportedContext);
        }
        Ok(())
    }
}

/// A trusted, fully validating node connection, not a light-client proof source.
/// Missing/pruned blocks MUST be errors. PQ configuration is independently
/// approved by the operator because the existing RPC does not advertise it.
pub trait ChainSource {
    /// Read the trusted node tip and upgrade context.
    fn context(&mut self) -> Result<NodeContext, Error>;
    /// Read the trusted main-chain block hash at the requested height.
    fn block_hash(&mut self, height: u32) -> Result<Hex<32>, Error>;
    /// Read a complete block; unavailable or pruned history is an error.
    fn block_bytes(&mut self, hash: Hex<32>) -> Result<Vec<u8>, Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// A transparent outpoint using RPC display-order transaction bytes.
pub struct Outpoint {
    /// Unsigned output or derivation index.
    pub index: u32,
    /// RPC display-order transaction hash.
    pub txid: Hex<32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One cached transparent receipt belonging to the covered inventory.
pub struct Coin {
    /// Whether this output comes from a coinbase transaction.
    pub coinbase: bool,
    /// Block height.
    pub height: u32,
    /// Unsigned output or derivation index.
    pub index: u32,
    /// The confirmed transparent output reference.
    pub outpoint: Outpoint,
    /// Public derivation role, receive zero or change one.
    pub role: u8,
    /// Output amount in zatoshis.
    pub value: u64,
}
impl Coin {
    /// Whether the cached height meets transparent coinbase maturity.
    pub fn mature_at(&self, candidate_height: u32) -> bool {
        candidate_height > self.height
            && (!self.coinbase
                || candidate_height
                    .checked_sub(self.height)
                    .is_some_and(|n| n >= MIN_TRANSPARENT_COINBASE_MATURITY))
    }
    fn validate(&self, manifest: &Manifest, checkpoint: Option<Checkpoint>) -> Result<(), Error> {
        let end = match self.role {
            0 => manifest.receive_end,
            1 => manifest.change_end,
            _ => return Err(Error::Encoding),
        };
        if u64::from(self.index) >= end
            || checkpoint.is_none_or(|p| self.height > p.height)
            || self.height < manifest.birthday_height
            || zakura_chain::amount::Amount::<zakura_chain::amount::NonNegative>::try_from(
                self.value,
            )
            .is_err()
        {
            return Err(Error::Encoding);
        }
        Ok(())
    }
}

/// Cached confirmed data, never an assertion of current node unspentness.
/// A failed/interrupted scan cannot return a complete or spendable balance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScanStatus {
    /// Last fully applied block, if any.
    pub checkpoint: Option<Checkpoint>,
    /// Whether required history is complete at the cached checkpoint.
    pub complete_at_checkpoint: bool,
    /// Cached confirmed amount only when history is complete.
    pub confirmed_zatoshis: Option<u64>,
    /// Cached immature amount only when history is complete.
    pub immature_coinbase_zatoshis: Option<u64>,
    /// Observed amount even if required history is incomplete.
    pub observed_zatoshis: u64,
    /// Approved SLH gate status when the cached scan is complete.
    pub pq_active_for_next_block: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    before: Option<Coin>,
    outpoint: Outpoint,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Undo {
    #[serde(deserialize_with = "changes")]
    changes: Vec<Change>,
    checkpoint: Checkpoint,
    previous: Option<Checkpoint>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scan {
    /// Last fully applied block, if any.
    pub checkpoint: Option<Checkpoint>,
    #[serde(deserialize_with = "coins")]
    /// Coins.
    pub coins: Vec<Coin>,
    /// Complete.
    pub complete: bool,
    /// Context.
    pub context: Option<NodeContext>,
    #[serde(deserialize_with = "undos")]
    undo: Vec<Undo>,
}
fn coins<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Coin>, D::Error> {
    bounded::<D, Coin, MAX_COINS>(d)
}
fn undos<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Undo>, D::Error> {
    bounded::<D, Undo, MAX_UNDO_BLOCKS>(d)
}
fn changes<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Change>, D::Error> {
    bounded::<D, Change, MAX_UNDO_CHANGES>(d)
}

impl Scan {
    pub fn validate(&self, manifest: &Manifest) -> Result<(), Error> {
        if self.coins.len() > MAX_COINS
            || self.undo.len() > MAX_UNDO_BLOCKS
            || self.undo.iter().map(|u| u.changes.len()).sum::<usize>() > MAX_UNDO_CHANGES
            || self
                .coins
                .windows(2)
                .any(|w| w[0].outpoint >= w[1].outpoint)
        {
            return Err(Error::Limits);
        }
        if let Some(context) = &self.context {
            context.validate(manifest)?;
        }
        if self.complete
            && self
                .context
                .as_ref()
                .is_none_or(|c| Some(c.tip) != self.checkpoint)
        {
            return Err(Error::Encoding);
        }
        if self
            .checkpoint
            .is_some_and(|p| p.height.saturating_add(1) < manifest.birthday_height)
            || self
                .undo
                .last()
                .is_some_and(|u| Some(u.checkpoint) != self.checkpoint)
        {
            return Err(Error::Encoding);
        }
        for coin in &self.coins {
            coin.validate(manifest, self.checkpoint)?;
        }
        for (i, undo) in self.undo.iter().enumerate() {
            if undo.previous.map_or(0, |p| u64::from(p.height) + 1)
                != u64::from(undo.checkpoint.height)
                || (i > 0 && undo.previous != Some(self.undo[i - 1].checkpoint))
                || undo
                    .changes
                    .windows(2)
                    .any(|w| w[0].outpoint >= w[1].outpoint)
            {
                return Err(Error::Encoding);
            }
            for change in &undo.changes {
                if let Some(coin) = &change.before {
                    coin.validate(manifest, undo.previous)?;
                    if coin.outpoint != change.outpoint {
                        return Err(Error::Encoding);
                    }
                }
            }
        }
        self.status(manifest)?;
        Ok(())
    }

    pub fn status(&self, manifest: &Manifest) -> Result<ScanStatus, Error> {
        let mut confirmed = 0u64;
        let mut immature = 0u64;
        let next = self.checkpoint.and_then(|p| p.height.checked_add(1));
        for coin in &self.coins {
            confirmed = confirmed.checked_add(coin.value).ok_or(Error::Limits)?;
            if coin.coinbase && next.is_none_or(|h| !coin.mature_at(h)) {
                immature = immature.checked_add(coin.value).ok_or(Error::Limits)?;
            }
        }
        Ok(ScanStatus {
            checkpoint: self.checkpoint,
            complete_at_checkpoint: self.complete,
            confirmed_zatoshis: self.complete.then_some(confirmed),
            immature_coinbase_zatoshis: self.complete.then_some(immature),
            observed_zatoshis: confirmed,
            pq_active_for_next_block: if self.complete {
                Some(next.is_some_and(|h| h >= manifest.profile.pq_activation_height))
            } else {
                None
            },
        })
    }

    /// Undo retained wallet effects. A deeper fork resets discovery, preserving
    /// inventory and issuance in the enclosing store; rescan starts at birthday.
    pub fn rollback(&mut self) {
        let Some(undo) = self.undo.pop() else {
            *self = Self::default();
            return;
        };
        let mut coins: BTreeMap<_, _> = self.coins.drain(..).map(|c| (c.outpoint, c)).collect();
        for change in undo.changes {
            if let Some(coin) = change.before {
                coins.insert(change.outpoint, coin);
            } else {
                coins.remove(&change.outpoint);
            }
        }
        self.coins = coins.into_values().collect();
        self.checkpoint = undo.previous;
        self.complete = false;
        self.context = None;
    }

    pub fn apply(
        &mut self,
        manifest: &Manifest,
        point: Checkpoint,
        bytes: &[u8],
    ) -> Result<u64, Error> {
        if bytes.len() as u64 > MAX_BLOCK_BYTES {
            return Err(Error::Limits);
        }
        let mut reader = Cursor::new(bytes);
        let block = Block::zcash_deserialize(&mut reader).map_err(|_| Error::ChainChanged)?;
        if reader.position() != bytes.len() as u64
            || Hex(block.hash().bytes_in_display_order()) != point.hash
            || block.coinbase_height().map(|h| h.0) != Some(point.height)
            || self.checkpoint.map_or(0, |p| u64::from(p.height) + 1) != u64::from(point.height)
            || Hex(block.header.previous_block_hash.bytes_in_display_order())
                != self.checkpoint.map_or(Hex([0; 32]), |p| p.hash)
            || block.transactions.is_empty()
            || block
                .transactions
                .iter()
                .map(|tx| tx.hash())
                .collect::<merkle::Root>()
                != block.header.merkle_root
            || block.transactions.iter().skip(1).any(|tx| tx.is_coinbase())
        {
            return Err(Error::ChainChanged);
        }
        let scripts: BTreeMap<_, _> = manifest
            .entries
            .iter()
            .map(|entry| {
                Ok((
                    entry.receiver()?.script(),
                    (entry.role, entry.local(manifest.wallet_id)?.1.index),
                ))
            })
            .collect::<Result<_, Error>>()?;
        let mut coins: BTreeMap<_, _> = self
            .coins
            .iter()
            .cloned()
            .map(|c| (c.outpoint, c))
            .collect();
        let mut before = BTreeMap::new();
        let mut txids = BTreeSet::new();
        let mut observed_change_end = 0;
        for tx in &block.transactions {
            let txid = Hex(tx.hash().bytes_in_display_order());
            if !txids.insert(txid) {
                return Err(Error::ChainChanged);
            }
            for input in tx.inputs() {
                if let Input::PrevOut { outpoint, .. } = input {
                    let point = Outpoint {
                        index: outpoint.index,
                        txid: Hex(outpoint.hash.bytes_in_display_order()),
                    };
                    if let Some(coin) = coins.remove(&point) {
                        before.entry(point).or_insert(Some(coin));
                    }
                }
            }
            for (index, output) in tx.outputs().iter().enumerate() {
                let Ok(script) = <[u8; 35]>::try_from(output.lock_script.as_raw_bytes()) else {
                    continue;
                };
                if let Some(&(role, local_index)) = scripts.get(&script) {
                    if role == 1 {
                        observed_change_end = observed_change_end.max(u64::from(local_index) + 1);
                    }
                    let outpoint = Outpoint {
                        index: u32::try_from(index).map_err(|_| Error::Limits)?,
                        txid,
                    };
                    if coins.contains_key(&outpoint) {
                        return Err(Error::ChainChanged);
                    }
                    before.entry(outpoint).or_insert(None);
                    coins.insert(
                        outpoint,
                        Coin {
                            coinbase: tx.is_coinbase(),
                            height: point.height,
                            index: local_index,
                            outpoint,
                            role,
                            value: output.value.into(),
                        },
                    );
                    if coins.len() > MAX_COINS {
                        return Err(Error::Limits);
                    }
                }
            }
        }
        if before.len() > MAX_UNDO_CHANGES {
            return Err(Error::Limits);
        }
        self.undo.push(Undo {
            changes: before
                .into_iter()
                .map(|(outpoint, before)| Change { before, outpoint })
                .collect(),
            checkpoint: point,
            previous: self.checkpoint,
        });
        while self.undo.len() > MAX_UNDO_BLOCKS
            || self.undo.iter().map(|u| u.changes.len()).sum::<usize>() > MAX_UNDO_CHANGES
        {
            self.undo.remove(0);
        }
        self.coins = coins.into_values().collect();
        self.checkpoint = Some(point);
        self.complete = false;
        self.context = None;
        Ok(observed_change_end)
    }
}
