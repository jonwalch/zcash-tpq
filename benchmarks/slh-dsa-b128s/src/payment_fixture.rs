//! Offline wallet fixture adapter, derived from `pq-wallet/src/{watch,payment}/tests.rs`.
//! These headers and funding transactions are deliberately NOT consensus-valid.
//! The adapter supplies disposable responses at the wallet's trusted-node interface;
//! it must never be used with real keys, funding, or a network connection.

use std::{collections::BTreeMap, path::Path, sync::Arc};

use zakura_chain::{
    block::{genesis::regtest_genesis_block, Block, Height},
    parameters::NetworkUpgrade,
    serialization::{BytesInDisplayOrder, ZcashSerialize},
    transaction::{self, LockTime, Transaction},
    transparent::{Input, OutPoint, Output, Script},
};
use zakura_pq_slh_dsa_b_exp::{codec::key_commitment, Policy};
use zakura_pq_wallet::{
    payment::{Intent, LocatedTransaction, PaymentSource, Remainder, ResolvedInput},
    ChainSource, Checkpoint, Entry, Error, Hex, KeyPath, NodeContext, Origin, Outpoint, Profile,
    Role, Wallet, WatchMode, WatchStore,
};

pub const INPUT_VALUE: u64 = 10_000_000;
pub const TIP_HEIGHT: u32 = 110;
const FUNDING_HEIGHT: u32 = TIP_HEIGHT - 1;
// Only ephemeral OS-random disposable roots are encrypted by this public password.
// Encrypted backups remain in private temporary directories and are never artifacts.
const DISPOSABLE_PASSWORD: &[u8] = b"tpq-bench-disposable-offline-wallet-not-for-funds";

pub fn profile() -> Profile {
    Profile {
        genesis_hash: Hex(regtest_genesis_block().hash().bytes_in_display_order()),
        max_block_pq_checks: 64,
        max_tx_pq_checks: 16,
        network: 2,
        nu7_activation_height: 2,
        nu7_branch_id: "77190ad9".into(),
        pq_activation_height: 4,
    }
}

pub struct Inventory {
    pub wallets: Vec<Wallet>,
    pub recipient: Wallet,
}

impl Inventory {
    /// Generate, derive, enroll and durably back up one receive and change policy
    /// per participant. Secret key material is recomputed by operational signing.
    pub fn generate(multisig: bool, directory: &Path) -> Result<Self, Error> {
        let count = if multisig { 3 } else { 1 };
        let mut wallets = (0..count)
            .map(|_| Wallet::create(profile(), FUNDING_HEIGHT))
            .collect::<Result<Vec<_>, _>>()?;
        let mut entries = Vec::new();
        for role in [Role::Receive, Role::Change] {
            let mut participants = wallets
                .iter()
                .map(|wallet| {
                    (
                        key_commitment(&wallet.public_key(KeyPath { role, index: 0 })),
                        Origin {
                            account: 0,
                            index: 0,
                            wallet_id: wallet.manifest().wallet_id,
                        },
                    )
                })
                .collect::<Vec<_>>();
            participants.sort_by_key(|(commitment, _)| *commitment);
            let policy = Policy::new(
                if multisig { 2 } else { 1 },
                participants.iter().map(|(key, _)| *key).collect(),
            )?;
            entries.push(Entry {
                origins: participants.into_iter().map(|(_, origin)| origin).collect(),
                policy_hex: hex::encode(policy.descriptor()),
                role: role as u8, // Role has only its repr(u8) receive/change values.
            });
        }
        for (index, wallet) in wallets.iter_mut().enumerate() {
            let mut candidate = wallet.manifest().clone();
            candidate.revision = 1;
            candidate.entries = entries.clone();
            candidate.receive_end = 1;
            candidate.change_end = 1;
            wallet.enroll_backup(
                candidate.clone(),
                candidate.fingerprint()?,
                &directory.join(format!("participant-{index}.tpq")),
                DISPOSABLE_PASSWORD,
            )?;
        }
        let mut recipient = Wallet::create(profile(), FUNDING_HEIGHT)?;
        recipient.extend_single_backup(
            1,
            0,
            &directory.join("recipient.tpq"),
            DISPOSABLE_PASSWORD,
        )?;
        Ok(Self { wallets, recipient })
    }

    pub fn intent(&self, version: u8, inputs: usize) -> Result<Intent, Error> {
        let amount = INPUT_VALUE
            .checked_mul(u64::try_from(inputs).map_err(|_| Error::Limits)?)
            .and_then(|total| total.checked_sub(INPUT_VALUE / 2))
            .ok_or(Error::Funds)?;
        Ok(Intent {
            amount,
            max_fee: 5_000_000,
            receiver: self.recipient.manifest().entries[0].receiver()?.encode(),
            receiver_activation_height: None,
            remainder: Remainder::Reject,
            version: Some(version),
        })
    }
}

pub struct Session {
    pub stores: Vec<WatchStore>,
    pub source: OfflineSource,
}

impl Session {
    pub fn new(
        inventory: &Inventory,
        mut source: OfflineSource,
        directory: &Path,
    ) -> Result<Self, Error> {
        // Only threshold participants are needed for signing. All three public
        // participants were generated and included in the 2-of-3 policy above.
        let threshold = if inventory.wallets.len() == 1 { 1 } else { 2 };
        let mut stores = Vec::new();
        for (index, wallet) in inventory.wallets.iter().take(threshold).enumerate() {
            let manifest = wallet.manifest();
            let mut store = WatchStore::create(
                &directory.join(format!("watch-{index}")),
                &manifest.to_json()?,
                manifest.fingerprint()?,
                &profile(),
                WatchMode::Allocator,
            )?;
            if !store.sync(&mut source, 3)?.complete_at_checkpoint {
                return Err(Error::HistoryUnavailable);
            }
            stores.push(store);
        }
        Ok(Self { stores, source })
    }
}

pub struct OfflineSource {
    blocks: Vec<(Hex<32>, Vec<u8>)>,
    block_indexes: BTreeMap<Hex<32>, usize>,
    funding: Arc<Transaction>,
    funding_hash: Hex<32>,
    funding_bytes: Vec<u8>,
}

impl OfflineSource {
    /// Prepare the synthetic node's responses before observing wallet work.
    pub fn new(wallet: &Wallet, input_count: usize) -> Result<Self, Error> {
        Self::with_script(
            wallet.manifest().entries[0].policy()?.lock_script(),
            input_count,
        )
    }

    fn with_script(lock_script: Script, input_count: usize) -> Result<Self, Error> {
        if ![1, 2, 5].contains(&input_count) {
            return Err(Error::Limits);
        }
        let output = Output {
            value: INPUT_VALUE.try_into().map_err(|_| Error::Funds)?,
            lock_script,
        };
        let funding = Arc::new(Transaction::V6 {
            network_upgrade: NetworkUpgrade::Nu7,
            lock_time: LockTime::unlocked(),
            expiry_height: Height(1000),
            inputs: vec![Input::PrevOut {
                outpoint: OutPoint {
                    hash: transaction::Hash([0x33; 32]),
                    index: 0,
                },
                unlock_script: Script::new(&[]),
                sequence: u32::MAX,
            }],
            outputs: vec![output; input_count],
            sapling_shielded_data: None,
            orchard_shielded_data: None,
            ironwood_shielded_data: None,
        });
        let mut blocks = vec![(*regtest_genesis_block()).clone()];
        for height in 1..=TIP_HEIGHT {
            let mut transactions = vec![Arc::new(Transaction::V1 {
                inputs: vec![Input::Coinbase {
                    height: Height(height),
                    data: vec![0x42],
                    sequence: u32::MAX,
                }],
                outputs: vec![Output {
                    value: 1u64.try_into().map_err(|_| Error::Funds)?,
                    lock_script: Script::new(&[0x51]),
                }],
                lock_time: LockTime::unlocked(),
            })];
            if height == FUNDING_HEIGHT {
                transactions.push(funding.clone());
            }
            let previous = blocks.last().ok_or(Error::HistoryUnavailable)?;
            let mut header = *previous.header;
            header.previous_block_hash = previous.hash();
            header.merkle_root = transactions
                .iter()
                .map(|transaction| transaction.hash())
                .collect();
            blocks.push(Block {
                header: Arc::new(header),
                transactions,
            });
        }
        let blocks = blocks
            .into_iter()
            .map(|block| {
                Ok((
                    Hex(block.hash().bytes_in_display_order()),
                    block
                        .zcash_serialize_to_vec()
                        .map_err(|_| Error::Encoding)?,
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let block_indexes = blocks
            .iter()
            .enumerate()
            .map(|(index, (hash, _))| (*hash, index))
            .collect::<BTreeMap<_, _>>();
        if block_indexes.len() != blocks.len() {
            return Err(Error::Encoding);
        }
        Ok(Self {
            blocks,
            block_indexes,
            funding_hash: Hex(funding.hash().bytes_in_display_order()),
            funding_bytes: funding
                .zcash_serialize_to_vec()
                .map_err(|_| Error::Encoding)?,
            funding,
        })
    }
}

impl ChainSource for OfflineSource {
    fn context(&mut self) -> Result<NodeContext, Error> {
        Ok(NodeContext {
            chain: "regtest".into(),
            next_branch_id: Hex([0x77, 0x19, 0x0a, 0xd9]),
            nu7_activation_height: 2,
            tip: Checkpoint {
                height: TIP_HEIGHT,
                hash: self.block_hash(TIP_HEIGHT)?,
            },
        })
    }

    fn block_hash(&mut self, height: u32) -> Result<Hex<32>, Error> {
        self.blocks
            .get(usize::try_from(height).map_err(|_| Error::Limits)?)
            .map(|(hash, _)| *hash)
            .ok_or(Error::HistoryUnavailable)
    }

    fn block_bytes(&mut self, hash: Hex<32>) -> Result<Vec<u8>, Error> {
        let index = self
            .block_indexes
            .get(&hash)
            .ok_or(Error::HistoryUnavailable)?;
        Ok(self.blocks[*index].1.clone())
    }
}

impl PaymentSource for OfflineSource {
    fn resolve(&mut self, point: Outpoint) -> Result<Option<ResolvedInput>, Error> {
        let tip = self.context()?.tip;
        if point.txid != self.funding_hash {
            return Ok(None);
        }
        Ok(self
            .funding
            .outputs()
            .get(usize::try_from(point.index).map_err(|_| Error::Limits)?)
            .map(|output| ResolvedInput {
                output: output.clone(),
                height: FUNDING_HEIGHT,
                coinbase: false,
                tip,
            }))
    }

    fn transaction(&mut self, txid: Hex<32>) -> Result<Option<LocatedTransaction>, Error> {
        if txid != self.funding_hash {
            return Ok(None);
        }
        Ok(Some(LocatedTransaction {
            bytes: self.funding_bytes.clone(),
            block: Some(Checkpoint {
                height: FUNDING_HEIGHT,
                hash: self.block_hash(FUNDING_HEIGHT)?,
            }),
        }))
    }

    fn submit(&mut self, _transaction: &[u8]) -> Result<Hex<32>, Error> {
        // A benchmark must not manufacture a submission/acceptance receipt.
        Err(Error::UnsupportedContext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_chain::serialization::ZcashDeserialize;

    #[test]
    fn prepared_responses_preserve_chain_links_and_funding() {
        let script = Policy::new(1, vec![[0x42; 32]]).unwrap().lock_script();
        let mut source = OfflineSource::with_script(script.clone(), 5).unwrap();
        let mut previous = None;
        for height in 0..=TIP_HEIGHT {
            let hash = source.block_hash(height).unwrap();
            let bytes = source.block_bytes(hash).unwrap();
            let block = Block::zcash_deserialize(bytes.as_slice()).unwrap();
            assert_eq!(Hex(block.hash().bytes_in_display_order()), hash);
            assert_eq!(block.zcash_serialize_to_vec().unwrap(), bytes);
            if let Some(previous) = previous {
                assert_eq!(block.header.previous_block_hash, previous);
                let merkle_root = block
                    .transactions
                    .iter()
                    .map(|tx| tx.hash())
                    .collect::<zakura_chain::block::merkle::Root>();
                assert_eq!(block.header.merkle_root, merkle_root);
            }
            if height == FUNDING_HEIGHT {
                assert_eq!(block.transactions.len(), 2);
                assert_eq!(block.transactions[1], source.funding);
            }
            previous = Some(block.hash());
        }
        let funding_hash = source.funding_hash;
        let located = source.transaction(funding_hash).unwrap().unwrap();
        assert_eq!(
            located.bytes,
            source.funding.zcash_serialize_to_vec().unwrap()
        );
        assert_eq!(located.block.unwrap().height, FUNDING_HEIGHT);
        for index in 0..5 {
            let resolved = source
                .resolve(Outpoint {
                    txid: funding_hash,
                    index,
                })
                .unwrap()
                .unwrap();
            assert_eq!(resolved.output.lock_script, script);
            assert_eq!(u64::from(resolved.output.value), INPUT_VALUE);
            assert_eq!(resolved.height, FUNDING_HEIGHT);
            assert_eq!(resolved.tip, source.context().unwrap().tip);
            assert!(!resolved.coinbase);
        }
    }

    #[test]
    fn prepared_lookups_reject_missing_items_and_return_owned_bytes() {
        let mut source = OfflineSource::with_script(Script::new(&[0x51]), 1).unwrap();
        assert!(source.block_hash(TIP_HEIGHT + 1).is_err());
        assert!(source.block_hash(u32::MAX).is_err());
        assert!(source.block_bytes(Hex([0xff; 32])).is_err());
        assert!(source.transaction(Hex([0xff; 32])).unwrap().is_none());
        assert!(source
            .resolve(Outpoint {
                txid: source.funding_hash,
                index: u32::MAX
            })
            .unwrap()
            .is_none());
        let hash = source.block_hash(FUNDING_HEIGHT).unwrap();
        let original = source.block_bytes(hash).unwrap();
        let mut response = source.block_bytes(hash).unwrap();
        response[0] ^= 1;
        assert_eq!(source.block_bytes(hash).unwrap(), original);
        assert!(OfflineSource::with_script(Script::new(&[]), 0).is_err());
        assert!(OfflineSource::with_script(Script::new(&[]), 6).is_err());
    }
}
