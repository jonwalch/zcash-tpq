//! Offline wallet fixture adapter, derived from `pq-wallet/src/{watch,payment}/tests.rs`.
//! These headers and funding transactions are deliberately NOT consensus-valid.
//! The adapter supplies disposable responses at the wallet's trusted-node interface;
//! it must never be used with real keys, funding, or a network connection.

use std::{path::Path, sync::Arc};

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
    pub fn new(inventory: &Inventory, inputs: usize, directory: &Path) -> Result<Self, Error> {
        let mut source = OfflineSource::new(&inventory.wallets[0], inputs)?;
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
    blocks: Vec<Block>,
    funding: Arc<Transaction>,
}

impl OfflineSource {
    fn new(wallet: &Wallet, input_count: usize) -> Result<Self, Error> {
        let output = Output {
            value: INPUT_VALUE.try_into().map_err(|_| Error::Funds)?,
            lock_script: wallet.manifest().entries[0].policy()?.lock_script(),
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
        let mut source = Self {
            blocks: vec![(*regtest_genesis_block()).clone()],
            funding,
        };
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
                transactions.push(source.funding.clone());
            }
            let previous = source.blocks.last().ok_or(Error::HistoryUnavailable)?;
            let mut header = *previous.header;
            header.previous_block_hash = previous.hash();
            header.merkle_root = transactions
                .iter()
                .map(|transaction| transaction.hash())
                .collect();
            source.blocks.push(Block {
                header: Arc::new(header),
                transactions,
            });
        }
        Ok(source)
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
            .get(height as usize)
            .map(|block| Hex(block.hash().bytes_in_display_order()))
            .ok_or(Error::HistoryUnavailable)
    }

    fn block_bytes(&mut self, hash: Hex<32>) -> Result<Vec<u8>, Error> {
        self.blocks
            .iter()
            .find(|block| Hex(block.hash().bytes_in_display_order()) == hash)
            .ok_or(Error::HistoryUnavailable)?
            .zcash_serialize_to_vec()
            .map_err(|_| Error::Encoding)
    }
}

impl PaymentSource for OfflineSource {
    fn resolve(&mut self, point: Outpoint) -> Result<Option<ResolvedInput>, Error> {
        let tip = self.context()?.tip;
        if point.txid != Hex(self.funding.hash().bytes_in_display_order()) {
            return Ok(None);
        }
        Ok(self
            .funding
            .outputs()
            .get(point.index as usize)
            .map(|output| ResolvedInput {
                output: output.clone(),
                height: FUNDING_HEIGHT,
                coinbase: false,
                tip,
            }))
    }

    fn transaction(&mut self, txid: Hex<32>) -> Result<Option<LocatedTransaction>, Error> {
        if txid != Hex(self.funding.hash().bytes_in_display_order()) {
            return Ok(None);
        }
        Ok(Some(LocatedTransaction {
            bytes: self
                .funding
                .zcash_serialize_to_vec()
                .map_err(|_| Error::Encoding)?,
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
