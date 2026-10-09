//! Synthetic trusted-node responses test wallet bookkeeping, not node acceptance
//! or validity of proofs/authorizations. Real wallet payment recovery is change 5.
mod enrollment;

use super::*;
use crate::{Entry, KeyPath, NodeContext, Origin, Role, Wallet};
use serde_json::{json, Value};
use std::{collections::BTreeSet, sync::Arc};
use zakura_chain::{
    block::{genesis::regtest_genesis_block, Block, Height},
    parameters::NetworkUpgrade,
    serialization::{BytesInDisplayOrder, ZcashSerialize},
    transaction::{self, LockTime, Transaction},
    transparent::{Input, OutPoint, Output, Script},
};
use zakura_pq_slh_dsa_b_exp::Policy;

pub(crate) fn profile() -> Profile {
    Profile {
        genesis_hash: Hex(regtest_genesis_block().hash().bytes_in_display_order()),
        max_block_pq_checks: 42,
        max_tx_pq_checks: 15,
        network: 2,
        nu7_activation_height: 2,
        nu7_branch_id: "77190ad9".into(),
        pq_activation_height: 4,
    }
}
fn inventory(receive: u32, change: u32) -> Manifest {
    let wallet = Wallet::create(profile(), 0).unwrap();
    let mut manifest = wallet.manifest().clone();
    for (role, end) in [(Role::Receive, receive), (Role::Change, change)] {
        for index in 0..end {
            let key = wallet.key(KeyPath { role, index });
            manifest.entries.push(Entry {
                origins: vec![Origin {
                    account: 0,
                    index,
                    wallet_id: manifest.wallet_id,
                }],
                policy_hex: hex::encode(
                    Policy::new(
                        1,
                        vec![zakura_pq_slh_dsa_b_exp::codec::key_commitment(
                            key.public_key(),
                        )],
                    )
                    .unwrap()
                    .descriptor(),
                ),
                role: role as u8,
            });
        }
    }
    manifest.receive_end = receive.into();
    manifest.change_end = change.into();
    manifest.validate().unwrap();
    manifest
}
pub(crate) fn create(path: &Path, manifest: &Manifest, mode: WatchMode) -> WatchStore {
    WatchStore::create(
        path,
        &manifest.to_json().unwrap(),
        manifest.fingerprint().unwrap(),
        &manifest.profile,
        mode,
    )
    .unwrap()
}
pub(crate) fn output(entry: &Entry, value: u64) -> Output {
    Output {
        value: value.try_into().unwrap(),
        lock_script: entry.suite_policy().unwrap().lock_script(),
    }
}
pub(crate) fn transaction(
    version: u8,
    nonce: u32,
    inputs: Vec<OutPoint>,
    outputs: Vec<Output>,
) -> Arc<Transaction> {
    let inputs = inputs
        .into_iter()
        .map(|outpoint| Input::PrevOut {
            outpoint,
            unlock_script: Script::new(&[]),
            sequence: u32::MAX,
        })
        .collect();
    let transaction = if version == 5 {
        Transaction::V5 {
            network_upgrade: NetworkUpgrade::Nu7,
            lock_time: LockTime::unlocked(),
            expiry_height: Height(nonce + 1000),
            inputs,
            outputs,
            sapling_shielded_data: None,
            orchard_shielded_data: None,
        }
    } else {
        Transaction::V6 {
            network_upgrade: NetworkUpgrade::Nu7,
            lock_time: LockTime::unlocked(),
            expiry_height: Height(nonce + 1000),
            inputs,
            outputs,
            sapling_shielded_data: None,
            orchard_shielded_data: None,
            ironwood_shielded_data: None,
        }
    };
    Arc::new(transaction)
}
fn prev(tx: &Transaction, index: u32) -> OutPoint {
    OutPoint {
        hash: tx.hash(),
        index,
    }
}
fn external() -> Vec<OutPoint> {
    vec![OutPoint {
        hash: transaction::Hash([0x33; 32]),
        index: 0,
    }]
}

#[derive(Clone)]
pub(crate) struct Chain {
    pub(crate) blocks: Vec<Block>,
    missing: BTreeSet<u32>,
}
impl Chain {
    pub(crate) fn new() -> Self {
        Self {
            blocks: vec![(*regtest_genesis_block()).clone()],
            missing: BTreeSet::new(),
        }
    }
    pub(crate) fn push(&mut self, transactions: Vec<Arc<Transaction>>, reward: Option<Output>) {
        let height = self.blocks.len() as u32;
        let coinbase = Arc::new(Transaction::V1 {
            inputs: vec![Input::Coinbase {
                height: Height(height),
                data: vec![0x42],
                sequence: u32::MAX,
            }],
            outputs: vec![reward.unwrap_or(Output {
                value: 1u64.try_into().unwrap(),
                lock_script: Script::new(&[0x51]),
            })],
            lock_time: LockTime::unlocked(),
        });
        let transactions: Vec<_> = std::iter::once(coinbase).chain(transactions).collect();
        let mut header = *self.blocks.last().unwrap().header;
        header.previous_block_hash = self.blocks.last().unwrap().hash();
        header.merkle_root = transactions.iter().map(|tx| tx.hash()).collect();
        self.blocks.push(Block {
            header: Arc::new(header),
            transactions,
        });
    }
}
// Invalid synthetic blocks must panic, not simulate unavailable trusted history.
#[allow(clippy::unwrap_in_result)]
impl ChainSource for Chain {
    fn context(&mut self) -> Result<NodeContext, Error> {
        let height = self.blocks.len() as u32 - 1;
        Ok(NodeContext {
            chain: "test".into(),
            next_branch_id: if height + 1 >= 2 {
                Hex([0x77, 0x19, 0x0a, 0xd9])
            } else {
                Hex([0; 4])
            },
            nu7_activation_height: 2,
            tip: Checkpoint {
                height,
                hash: self.block_hash(height)?,
            },
        })
    }
    fn block_hash(&mut self, height: u32) -> Result<Hex<32>, Error> {
        self.blocks
            .get(height as usize)
            .map(|b| Hex(b.hash().bytes_in_display_order()))
            .ok_or(Error::HistoryUnavailable)
    }
    fn block_bytes(&mut self, hash: Hex<32>) -> Result<Vec<u8>, Error> {
        let (height, block) = self
            .blocks
            .iter()
            .enumerate()
            .find(|(_, b)| Hex(b.hash().bytes_in_display_order()) == hash)
            .ok_or(Error::HistoryUnavailable)?;
        if self.missing.contains(&(height as u32)) {
            return Err(Error::HistoryUnavailable);
        }
        Ok(block
            .zcash_serialize_to_vec()
            .expect("synthetic blocks have serializable fields"))
    }
}

#[test]
fn receiver_runtime_matches_all_public_answers_and_rejects_unsupported_senders() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
    ))
    .unwrap();
    for row in corpus["policies"].as_array().unwrap() {
        let text = row["receiver"].as_str().unwrap();
        let receiver = Receiver::parse(text).unwrap();
        assert_eq!(receiver.encode(), text);
        assert_eq!(hex::encode(receiver.script()), row["script_hex"]);
        assert!(text.parse::<zakura_chain::transparent::Address>().is_err());
    }
    let good = corpus["policies"][0]["receiver"].as_str().unwrap();
    for bad in [
        good.to_uppercase(),
        format!("{good}q"),
        good.replacen("tpqreg", "tpqtest", 1),
        good[..good.len() - 1].to_owned(),
    ] {
        assert!(Receiver::parse(&bad).is_err());
    }
    for suite in [0, 1, 0xf3, 0xf6, 0xf8] {
        let mut payload = [0; 35];
        payload[..3].copy_from_slice(&[1, 2, suite]);
        let unsupported =
            bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse("tpqreg").unwrap(), &payload)
                .unwrap();
        assert!(matches!(
            Receiver::parse(&unsupported),
            Err(Error::UnsupportedFormat)
        ));
    }
}

#[test]
fn extension_and_multisig_enrollment_publish_a_verified_backup_before_installation() {
    let _serial = crate::tests::BACKUPS.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let old = temp.path().join("old.tpq");
    let next = temp.path().join("next.tpq");
    let quorum = temp.path().join("quorum.tpq");
    let password = b"public-discovery-test-password";
    let mut wallet = Wallet::create(profile(), 0).unwrap();
    wallet.save_backup(&old, password).unwrap();
    let saved = fs::read(&old).unwrap();
    let initial = wallet.manifest().clone();
    assert!(wallet.extend_single_backup(2, 1, &old, password).is_err());
    assert_eq!(wallet.manifest(), &initial);
    wallet.extend_single_backup(2, 1, &next, password).unwrap();
    assert_eq!(wallet.manifest().revision, 1);
    assert_eq!(
        Wallet::load_backup(&next, password, &profile())
            .unwrap()
            .manifest(),
        wallet.manifest()
    );
    assert!(matches!(
        wallet.extend_single_backup(4096, 0, &quorum, password),
        Err(Error::Limits)
    ));
    assert!(!quorum.exists());
    let exported = temp.path().join("inventory.json");
    export_inventory(wallet.manifest(), &exported).unwrap();
    let public = read_inventory(&exported).unwrap();
    assert_eq!(Manifest::from_json(&public).unwrap(), *wallet.manifest());
    assert!(!String::from_utf8(public).unwrap().contains("root_hex"));
    assert!(export_inventory(wallet.manifest(), &exported).is_err());

    let mut candidate = wallet.manifest().clone();
    let local_key = wallet.key(KeyPath {
        role: Role::Receive,
        index: 2,
    });
    let mut participants = vec![
        (
            zakura_pq_slh_dsa_b_exp::codec::key_commitment(local_key.public_key()),
            Origin {
                account: 0,
                index: 2,
                wallet_id: candidate.wallet_id,
            },
        ),
        (
            zakura_pq_slh_dsa_b_exp::codec::key_commitment(
                zakura_pq_slh_dsa_b_sign::SigningKey::from_seed(zeroize::Zeroizing::new([33; 48]))
                    .public_key(),
            ),
            Origin {
                account: 0,
                index: 7,
                wallet_id: Hex([1; 16]),
            },
        ),
        (
            zakura_pq_slh_dsa_b_exp::codec::key_commitment(
                zakura_pq_slh_dsa_b_sign::SigningKey::from_seed(zeroize::Zeroizing::new([44; 48]))
                    .public_key(),
            ),
            Origin {
                account: 0,
                index: 9,
                wallet_id: Hex([2; 16]),
            },
        ),
    ];
    participants.sort_by_key(|(commitment, _)| *commitment);
    let policy = Policy::new(
        2,
        participants
            .iter()
            .map(|(commitment, _)| *commitment)
            .collect(),
    )
    .unwrap();
    candidate.entries.insert(
        2,
        Entry {
            origins: participants.into_iter().map(|(_, origin)| origin).collect(),
            policy_hex: hex::encode(policy.descriptor()),
            role: 0,
        },
    );
    candidate.receive_end += 1;
    candidate.revision += 1;
    assert!(matches!(
        wallet.enroll_backup(candidate.clone(), Hex([0; 32]), &quorum, password),
        Err(Error::Pairing)
    ));
    let mut wrong = candidate.clone();
    wrong.entries[2]
        .origins
        .iter_mut()
        .find(|origin| origin.wallet_id == wrong.wallet_id)
        .unwrap()
        .index = 1;
    assert!(wallet
        .enroll_backup(wrong, candidate.fingerprint().unwrap(), &quorum, password)
        .is_err());
    // Complete schema and local derivation ownership must both hold. Replacing a
    // whole new policy with a self-consistent but foreign key still fails.
    let mut wrong = candidate.clone();
    let foreign = Policy::new(
        1,
        vec![zakura_pq_slh_dsa_b_exp::codec::key_commitment(
            zakura_pq_slh_dsa_b_sign::SigningKey::from_seed(zeroize::Zeroizing::new([55; 48]))
                .public_key(),
        )],
    )
    .unwrap();
    wrong.entries[2] = Entry {
        origins: vec![Origin {
            account: 0,
            index: 2,
            wallet_id: wrong.wallet_id,
        }],
        policy_hex: hex::encode(foreign.descriptor()),
        role: 0,
    };
    assert!(matches!(
        wallet.enroll_backup(
            wrong.clone(),
            wrong.fingerprint().unwrap(),
            &quorum,
            password
        ),
        Err(Error::Policy)
    ));
    assert!(!quorum.exists());
    wallet
        .enroll_backup(
            candidate.clone(),
            candidate.fingerprint().unwrap(),
            &quorum,
            password,
        )
        .unwrap();
    assert_eq!(wallet.manifest(), &candidate);
    assert_eq!(fs::read(&old).unwrap(), saved);
    let mut chain = Chain::new();
    chain.push(
        vec![transaction(
            6,
            1,
            external(),
            vec![
                output(&candidate.entries[2], 42),
                output(&candidate.entries[3], 9),
            ],
        )],
        None,
    );
    let mut watcher = create(
        &temp.path().join("quorum-watch"),
        &candidate,
        WatchMode::Monitor,
    );
    assert_eq!(
        watcher.sync(&mut chain, 10).unwrap().confirmed_zatoshis,
        Some(51)
    );
}

#[test]
fn reorg_during_block_download_does_not_install_the_disconnected_effects() {
    struct Race {
        chain: Chain,
        replacement: Option<Chain>,
    }
    impl ChainSource for Race {
        fn context(&mut self) -> Result<NodeContext, Error> {
            self.chain.context()
        }
        fn block_hash(&mut self, height: u32) -> Result<Hex<32>, Error> {
            self.chain.block_hash(height)
        }
        fn block_bytes(&mut self, hash: Hex<32>) -> Result<Vec<u8>, Error> {
            let bytes = self.chain.block_bytes(hash)?;
            if hash == self.chain.block_hash(2)? {
                if let Some(replacement) = self.replacement.take() {
                    self.chain = replacement;
                }
            }
            Ok(bytes)
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let manifest = inventory(1, 1);
    let funding = transaction(5, 1, external(), vec![output(&manifest.entries[0], 100)]);
    let mut chain = Chain::new();
    chain.push(vec![funding.clone()], None);
    let mut replacement = chain.clone();
    chain.push(
        vec![transaction(
            6,
            2,
            vec![prev(&funding, 0)],
            vec![output(&manifest.entries[1], 50)],
        )],
        None,
    );
    replacement.push(
        vec![transaction(
            6,
            3,
            vec![prev(&funding, 0)],
            vec![output(&manifest.entries[1], 75)],
        )],
        None,
    );
    let mut source = Race {
        chain,
        replacement: Some(replacement),
    };
    let mut store = create(&path, &manifest, WatchMode::Monitor);
    assert!(matches!(
        store.sync(&mut source, 10),
        Err(Error::ChainChanged)
    ));
    let partial = store.status().unwrap();
    assert_eq!(partial.checkpoint.unwrap().height, 1);
    assert_eq!(partial.confirmed_zatoshis, None);
    assert_eq!(partial.observed_zatoshis, 100);
    assert!(!partial.complete_at_checkpoint);
    drop(store);
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    assert_eq!(
        store.sync(&mut source, 10).unwrap().confirmed_zatoshis,
        Some(75)
    );
}

#[test]
fn receiver_reservations_survive_restart_and_exclude_change_or_parallel_allocators() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let manifest = inventory(2, 1);
    let mut store = create(&path, &manifest, WatchMode::Allocator);
    assert!(matches!(
        WatchStore::open(&path, &profile()),
        Err(Error::Locked)
    ));
    let first = store.receive().unwrap();
    assert_eq!(first, manifest.entries[0].receiver().unwrap());
    drop(store);
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    assert_eq!(
        store.receive().unwrap(),
        manifest.entries[1].receiver().unwrap()
    );
    assert!(matches!(store.receive(), Err(Error::Exhausted)));
    assert_eq!(store.receive_next(), 2);
    let mut monitor = create(&temp.path().join("monitor"), &manifest, WatchMode::Monitor);
    assert!(matches!(monitor.receive(), Err(Error::MonitorOnly)));
    for file in [
        path.clone(),
        path.join("state.json"),
        path.join("allocator.lock"),
    ] {
        assert_eq!(fs::metadata(file).unwrap().permissions().mode() & 0o077, 0);
    }
    let bytes = fs::read(path.join("state.json")).unwrap();
    assert!(!bytes.windows(8).any(|w| w == b"root_hex"));
}

#[test]
fn pairing_schema_and_cumulative_imports_preserve_issuance_and_retire_old_allocator() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let all = inventory(2, 1);
    let mut initial = all.clone();
    initial.receive_end = 1;
    initial.entries.remove(1);
    assert!(matches!(
        WatchStore::create(
            &path,
            &initial.to_json().unwrap(),
            Hex([0; 32]),
            &profile(),
            WatchMode::Allocator
        ),
        Err(Error::Pairing)
    ));
    assert!(!path.exists());
    let mut value = serde_json::to_value(&initial).unwrap();
    value["root_hex"] = json!("00".repeat(32));
    assert!(Manifest::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut store = create(&path, &initial, WatchMode::Allocator);
    store.receive().unwrap();
    let mut extended = all.clone();
    extended.revision += 1;
    store
        .import(
            &extended.to_json().unwrap(),
            extended.fingerprint().unwrap(),
        )
        .unwrap();
    assert_eq!(store.receive_next(), 1);
    assert_eq!(
        store.receive().unwrap(),
        extended.entries[1].receiver().unwrap()
    );
    let unchanged = fs::read(path.join("state.json")).unwrap();
    assert!(store
        .import(&initial.to_json().unwrap(), initial.fingerprint().unwrap())
        .is_err());
    assert_eq!(fs::read(path.join("state.json")).unwrap(), unchanged);
    store
        .import(
            &extended.to_json().unwrap(),
            extended.fingerprint().unwrap(),
        )
        .unwrap();
    assert_eq!(store.receive_next(), 2);
    let mut rotated = extended.clone();
    rotated.revision += 1;
    rotated.allocator_id.0[0] ^= 1;
    assert!(store
        .import(&rotated.to_json().unwrap(), rotated.fingerprint().unwrap())
        .is_err());
    rotated.retired_receive_end = rotated.receive_end;
    rotated.retired_change_end = rotated.change_end;
    store
        .import(&rotated.to_json().unwrap(), rotated.fingerprint().unwrap())
        .unwrap();
    assert_eq!(store.mode(), WatchMode::Monitor);
    assert_eq!(store.manifest().entries, extended.entries);
    assert!(matches!(store.receive(), Err(Error::MonitorOnly)));
}

#[test]
fn failed_reservation_never_returns_a_receiver_and_requires_reopening() {
    let manifest = inventory(2, 0);
    for stage in [
        StateStage::FileSync,
        StateStage::Publish,
        StateStage::DirectorySync,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("watch");
        let mut store = create(&path, &manifest, WatchMode::Allocator);
        assert!(matches!(
            store.receive_with_hook(|at| if at == stage {
                Err(Error::Storage(std::io::Error::other(
                    "injected persistence failure",
                )))
            } else {
                Ok(())
            }),
            Err(Error::Storage(_))
        ));
        assert!(matches!(store.receive(), Err(Error::ReopenRequired)));
        assert!(matches!(store.status(), Err(Error::ReopenRequired)));
        drop(store);
        let mut store = WatchStore::open(&path, &profile()).unwrap();
        let expected = if stage == StateStage::DirectorySync {
            1
        } else {
            0
        };
        assert_eq!(store.receive_next(), expected);
        assert_eq!(
            store.receive().unwrap(),
            manifest.entries[expected as usize].receiver().unwrap()
        );
    }
}

#[test]
fn exact_script_scanning_covers_unused_gaps_change_pre_activation_and_spends() {
    for version in [5, 6] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("watch");
        let manifest = inventory(129, 1);
        let mut store = create(&path, &manifest, WatchMode::Monitor);
        let late = &manifest.entries[128];
        let change = &manifest.entries[129];
        let mut lookalike = late.receiver().unwrap().script().to_vec();
        lookalike.push(0);
        let funding = transaction(
            version,
            1,
            external(),
            vec![
                output(late, 60),
                output(change, 30),
                Output {
                    value: 999u64.try_into().unwrap(),
                    lock_script: Script::new(&lookalike),
                },
            ],
        );
        let mut chain = Chain::new();
        chain.push(vec![funding.clone()], Some(output(late, 5)));
        let status = store.sync(&mut chain, 10).unwrap();
        assert_eq!(status.confirmed_zatoshis, Some(95));
        assert_eq!(status.immature_coinbase_zatoshis, Some(5));
        assert_eq!(status.pq_active_for_next_block, Some(false));
        assert!(status.complete_at_checkpoint);
        assert_eq!(store.receive_next(), 0);
        // A watcher and a signer's monitor reconstruct the same public inventory.
        let mut other = create(&temp.path().join("other"), &manifest, WatchMode::Monitor);
        assert_eq!(other.sync(&mut chain, 10).unwrap(), status);
        let spend = transaction(
            version,
            2,
            vec![prev(&funding, 0)],
            vec![output(change, 40)],
        );
        let same_block_spend =
            transaction(version, 3, vec![prev(&spend, 0)], vec![output(late, 35)]);
        chain.push(vec![spend, same_block_spend], None);
        chain.push(vec![], None);
        let status = store.sync(&mut chain, 10).unwrap();
        assert_eq!(status.confirmed_zatoshis, Some(70));
        assert_eq!(status.pq_active_for_next_block, Some(true));
        assert_eq!(store.coins().len(), 3);
        assert!(!store
            .coins()
            .iter()
            .find(|c| c.coinbase)
            .unwrap()
            .mature_at(100));
        assert!(store
            .coins()
            .iter()
            .find(|c| c.coinbase)
            .unwrap()
            .mature_at(101));
    }
}

#[test]
fn forks_restore_spent_outputs_and_rollback_to_inactive_then_reenter() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let manifest = inventory(2, 1);
    let receive = &manifest.entries[0];
    let change = &manifest.entries[2];
    let funding = transaction(5, 1, external(), vec![output(receive, 100)]);
    let mut chain = Chain::new();
    chain.push(vec![funding.clone()], None);
    chain.push(vec![], None);
    let ancestor = chain.clone();
    chain.push(vec![], None);
    let spend = transaction(6, 2, vec![prev(&funding, 0)], vec![output(change, 75)]);
    chain.push(vec![spend], None);
    let mut store = create(&path, &manifest, WatchMode::Allocator);
    store.receive().unwrap();
    assert_eq!(
        store.sync(&mut chain, 10).unwrap().confirmed_zatoshis,
        Some(75)
    );
    drop(store);
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    chain = ancestor.clone();
    let status = store.sync(&mut chain, 10).unwrap();
    assert_eq!(status.confirmed_zatoshis, Some(100));
    assert_eq!(status.pq_active_for_next_block, Some(false));
    assert_eq!(store.receive_next(), 1);
    let alternate = transaction(5, 3, vec![prev(&funding, 0)], vec![output(change, 65)]);
    chain.push(vec![], None);
    chain.push(vec![alternate], None);
    let status = store.sync(&mut chain, 10).unwrap();
    assert_eq!(status.confirmed_zatoshis, Some(65));
    assert_eq!(status.pq_active_for_next_block, Some(true));
    let mut fresh = create(&temp.path().join("fresh"), &manifest, WatchMode::Monitor);
    assert_eq!(fresh.sync(&mut chain, 10).unwrap(), status);
    assert_eq!(fresh.coins(), store.coins());
}

#[test]
fn interrupted_scans_and_missing_history_remain_incomplete_across_restart() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let manifest = inventory(1, 0);
    let mut chain = Chain::new();
    chain.push(
        vec![transaction(
            5,
            1,
            external(),
            vec![output(&manifest.entries[0], 100)],
        )],
        None,
    );
    chain.push(vec![], None);
    chain.push(vec![], None);
    let mut store = create(&path, &manifest, WatchMode::Monitor);
    let status = store.sync(&mut chain, 2).unwrap();
    assert_eq!(status.checkpoint.unwrap().height, 1);
    assert!(!status.complete_at_checkpoint);
    drop(store);
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    chain.missing.insert(2);
    assert!(matches!(
        store.sync(&mut chain, 10),
        Err(Error::HistoryUnavailable)
    ));
    assert_eq!(store.status().unwrap().confirmed_zatoshis, None);
    assert_eq!(store.status().unwrap().observed_zatoshis, 100);
    assert!(!store.status().unwrap().complete_at_checkpoint);
    chain.missing.clear();
    assert!(store.sync(&mut chain, 10).unwrap().complete_at_checkpoint);
    chain.push(vec![], None);
    chain.missing.insert(4);
    assert!(matches!(
        store.sync(&mut chain, 10),
        Err(Error::HistoryUnavailable)
    ));
    assert!(!store.status().unwrap().complete_at_checkpoint);
}

#[test]
fn earlier_birthdays_and_new_ranges_rescan_old_receipts_without_resetting_cursor() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let full = inventory(2, 1);
    let mut early = full.clone();
    early.receive_end = 1;
    early.entries.remove(1);
    early.birthday_height = 2;
    let mut chain = Chain::new();
    chain.push(
        vec![transaction(
            5,
            1,
            external(),
            vec![
                output(&full.entries[0], 10),
                output(&full.entries[1], 20),
                output(&full.entries[2], 30),
            ],
        )],
        None,
    );
    chain.push(vec![], None);
    let mut store = create(&path, &early, WatchMode::Allocator);
    store.receive().unwrap();
    assert_eq!(
        store.sync(&mut chain, 10).unwrap().confirmed_zatoshis,
        Some(0)
    );
    let mut revised = full.clone();
    revised.revision += 1;
    store
        .import(&revised.to_json().unwrap(), revised.fingerprint().unwrap())
        .unwrap();
    assert_eq!(store.receive_next(), 1);
    assert!(!store.status().unwrap().complete_at_checkpoint);
    assert_eq!(
        store.sync(&mut chain, 10).unwrap().confirmed_zatoshis,
        Some(60)
    );
    assert_eq!(
        store.receive().unwrap(),
        full.entries[1].receiver().unwrap()
    );
}

#[test]
fn deep_forks_rescan_birthday_and_keep_retired_receiver_history() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut manifest = inventory(1, 0);
    manifest.retired_receive_end = 1;
    let mut chain = Chain::new();
    chain.push(
        vec![transaction(
            5,
            1,
            external(),
            vec![output(&manifest.entries[0], 10)],
        )],
        None,
    );
    for _ in 0..129 {
        chain.push(vec![], None);
    }
    let mut store = create(&path, &manifest, WatchMode::Allocator);
    assert_eq!(
        store.sync(&mut chain, 200).unwrap().confirmed_zatoshis,
        Some(10)
    );
    assert!(matches!(store.receive(), Err(Error::Exhausted)));
    chain.blocks.truncate(1);
    chain.push(
        vec![transaction(
            6,
            2,
            external(),
            vec![output(&manifest.entries[0], 25)],
        )],
        None,
    );
    assert_eq!(
        store.sync(&mut chain, 200).unwrap().confirmed_zatoshis,
        Some(25)
    );
    assert_eq!(store.receive_next(), 1);
}

#[test]
fn mismatched_node_context_and_block_data_do_not_advance_a_scan() {
    struct Bad(Chain, u8);
    impl ChainSource for Bad {
        fn context(&mut self) -> Result<NodeContext, Error> {
            let mut context = self.0.context()?;
            if self.1 == 0 {
                context.chain = "main".into();
            }
            if self.1 == 1 {
                context.nu7_activation_height += 1;
            }
            if self.1 == 2 {
                context.next_branch_id = Hex([0xff; 4]);
            }
            Ok(context)
        }
        fn block_hash(&mut self, height: u32) -> Result<Hex<32>, Error> {
            if self.1 == 3 && height == 0 {
                return Ok(Hex([0; 32]));
            }
            self.0.block_hash(height)
        }
        fn block_bytes(&mut self, hash: Hex<32>) -> Result<Vec<u8>, Error> {
            let mut bytes = self.0.block_bytes(hash)?;
            if self.1 == 4 {
                bytes.push(0);
            }
            if self.1 == 5 {
                bytes[100] ^= 1;
            }
            Ok(bytes)
        }
    }
    let manifest = inventory(1, 0);
    let mut chain = Chain::new();
    chain.push(vec![], None);
    for mode in 0..6 {
        let temp = tempfile::tempdir().unwrap();
        let mut store = create(&temp.path().join("watch"), &manifest, WatchMode::Monitor);
        assert!(store.sync(&mut Bad(chain.clone(), mode), 10).is_err());
        assert!(!store.status().unwrap().complete_at_checkpoint);
        assert_eq!(store.status().unwrap().checkpoint, None);
    }
}
