//! Enrollment binds externally authenticated approval; it does not authenticate
//! a coordinator or attest that other participants approved the same policy.
use super::profile;
use crate::{
    export_inventory, Entry, Error, Hex, KeyPath, Manifest, Origin, Receiver, Role, Wallet,
    WatchMode, WatchStore,
};
use std::{collections::BTreeSet, fs, path::PathBuf};
use zakura_pq_slh_dsa_b_exp::{codec::key_commitment, Policy};

const PASSWORD: &[u8] = b"public-enrollment-test-password";

struct SavedWallet {
    wallet: Wallet,
    directory: tempfile::TempDir,
    before: Manifest,
    backup: Vec<u8>,
    inventory: Vec<u8>,
}

impl SavedWallet {
    fn new(prefix: u32) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut wallet = Wallet::create(profile(), prefix).unwrap();
        // Different prior inventories and derivation coordinates are legitimate.
        // Install even this prefix through the real backup-before-enrollment API.
        wallet
            .extend_single_backup(prefix, prefix, &directory.path().join("old.tpq"), PASSWORD)
            .unwrap();
        export_inventory(wallet.manifest(), &directory.path().join("inventory.json")).unwrap();
        Self {
            before: wallet.manifest().clone(),
            backup: fs::read(directory.path().join("old.tpq")).unwrap(),
            inventory: fs::read(directory.path().join("inventory.json")).unwrap(),
            wallet,
            directory,
        }
    }

    fn destination(&self) -> PathBuf {
        self.directory.path().join("enrolled.tpq")
    }

    fn unchanged(&self) {
        assert_eq!(self.wallet.manifest(), &self.before);
        assert_eq!(self.wallet.manifest().to_json().unwrap(), self.inventory);
        assert_eq!(
            self.wallet.manifest().fingerprint().unwrap(),
            self.before.fingerprint().unwrap()
        );
        assert_eq!(
            fs::read(self.directory.path().join("old.tpq")).unwrap(),
            self.backup
        );
        assert_eq!(
            fs::read(self.directory.path().join("inventory.json")).unwrap(),
            self.inventory
        );
        let names: BTreeSet<_> = fs::read_dir(self.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["inventory.json".into(), "old.tpq".into()].into());
    }

    fn reject(&mut self, candidate: Manifest, approved: Hex<32>, local_failure: bool, case: &str) {
        // These attacks are canonical, cumulative updates. Their rejection must
        // come from approval/ownership, not a malformed descriptor or stale range.
        let candidate = Manifest::from_json(&candidate.to_json().unwrap()).unwrap();
        self.before.check_update(&candidate).unwrap();
        assert_eq!(candidate.revision, self.before.revision + 1);
        let result = self
            .wallet
            .enroll_backup(candidate, approved, &self.destination(), PASSWORD);
        assert!(
            if local_failure {
                matches!(result, Err(Error::Policy))
            } else {
                matches!(result, Err(Error::Pairing))
            },
            "enrollment rejection: {case}: {result:?}"
        );
        self.unchanged();
    }
}

// Records come from each participant's own public-key API. Keep origins paired
// with their commitments when sorting; enrollment order is not signer order.
fn entry(role: Role, threshold: u8, mut records: Vec<([u8; 32], Origin)>) -> Entry {
    records.sort_by_key(|(commitment, _)| *commitment);
    let policy = Policy::new(threshold, records.iter().map(|(key, _)| *key).collect()).unwrap();
    Entry {
        role: role as u8,
        policy_hex: hex::encode(policy.descriptor()),
        origins: records.into_iter().map(|(_, origin)| origin).collect(),
    }
}

fn records(entry: &Entry) -> Vec<([u8; 32], Origin)> {
    entry
        .policy()
        .unwrap()
        .commitments()
        .iter()
        .copied()
        .zip(entry.origins.clone())
        .collect()
}

fn path(manifest: &Manifest, role: Role) -> KeyPath {
    KeyPath {
        role,
        index: u32::try_from(if role == Role::Receive {
            manifest.receive_end
        } else {
            manifest.change_end
        })
        .unwrap(),
    }
}

fn candidate(wallet: &Wallet, shared: &[Entry; 2]) -> Manifest {
    let mut candidate = wallet.manifest().clone();
    candidate
        .entries
        .insert(candidate.receive_end.try_into().unwrap(), shared[0].clone());
    candidate.entries.push(shared[1].clone());
    candidate.receive_end += 1;
    candidate.change_end += 1;
    candidate.revision += 1;
    candidate.validate().unwrap();
    candidate
}

fn shared_entry(manifest: &mut Manifest, role: Role) -> &mut Entry {
    let index = if role == Role::Receive {
        usize::try_from(manifest.receive_end - 1).unwrap()
    } else {
        manifest.entries.len() - 1
    };
    &mut manifest.entries[index]
}

fn locally_owned(wallet: &Wallet, entry: &Entry) {
    let (slot, origin) = entry.local(wallet.manifest().wallet_id).unwrap();
    let role = if entry.role == 0 {
        Role::Receive
    } else {
        Role::Change
    };
    assert_eq!(
        entry.policy().unwrap().commitments()[slot],
        key_commitment(&wallet.public_key(KeyPath {
            role,
            index: origin.index
        }))
    );
}

fn substitute(entry: &Entry, local: Hex<16>, replacements: &[[u8; 32]]) -> Entry {
    let mut records = records(entry);
    for ((key, _), replacement) in records
        .iter_mut()
        .filter(|(_, origin)| origin.wallet_id != local)
        .zip(replacements)
    {
        *key = *replacement;
    }
    self::entry(
        if entry.role == 0 {
            Role::Receive
        } else {
            Role::Change
        },
        2,
        records,
    )
}

#[test]
fn multisig_enrollment_binds_independent_approval_and_preserves_rejected_state() {
    let _serial = crate::tests::BACKUPS.lock().unwrap();
    let mut wallets = [
        SavedWallet::new(1),
        SavedWallet::new(2),
        SavedWallet::new(3),
    ];
    let shared = [Role::Receive, Role::Change].map(|role| {
        entry(
            role,
            2,
            wallets
                .iter()
                .map(|saved| {
                    let path = path(saved.wallet.manifest(), role);
                    (
                        key_commitment(&saved.wallet.public_key(path)),
                        Origin {
                            account: 0,
                            index: path.index,
                            wallet_id: saved.before.wallet_id,
                        },
                    )
                })
                .collect(),
        )
    });
    let candidates = wallets
        .each_ref()
        .map(|saved| candidate(&saved.wallet, &shared));
    // These represent independently authenticated approval of each wallet's
    // complete inventory. Freeze them before constructing coordinator messages.
    let approved = candidates
        .each_ref()
        .map(|candidate| candidate.fingerprint().unwrap());
    assert_eq!(approved.into_iter().collect::<BTreeSet<_>>().len(), 3);
    for candidate in &candidates {
        assert_eq!(candidate.profile, profile());
        assert_eq!((candidate.suite, candidate.derivation_version), (1, 1));
    }
    for (saved, candidate) in wallets.iter().zip(&candidates) {
        for (role, expected) in [Role::Receive, Role::Change].into_iter().zip(&shared) {
            let mut view = candidate.clone();
            let actual = shared_entry(&mut view, role);
            assert_eq!(actual, expected); // Includes role and the ordered origin-to-key map.
            assert_eq!(actual.policy().unwrap().threshold(), 2);
            locally_owned(&saved.wallet, actual);
            assert_eq!(actual.receiver().unwrap(), expected.receiver().unwrap());
            assert_eq!(
                actual.receiver().unwrap().script().as_slice(),
                actual.policy().unwrap().lock_script().as_raw_bytes()
            );
        }
    }

    let attacker_keys = [71, 72].map(|seed| {
        zakura_pq_slh_dsa_b_exp::codec::key_commitment(
            zakura_pq_slh_dsa_b_sign::SigningKey::from_seed(zeroize::Zeroizing::new([seed; 48]))
                .public_key(),
        )
    });
    for (i, saved) in wallets.iter_mut().enumerate() {
        for (role, agreed) in [Role::Receive, Role::Change].into_iter().zip(&shared) {
            let local = saved.before.wallet_id;
            let remote: Vec<_> = agreed
                .origins
                .iter()
                .enumerate()
                .filter_map(|(slot, origin)| (origin.wallet_id != local).then_some(slot))
                .collect();
            let mut index = agreed.clone();
            index.origins[remote[0]].index += 10;
            let mut identity = agreed.clone();
            identity.origins[remote[0]].wallet_id = Hex([99; 16]);
            let mut swapped = agreed.clone();
            swapped.origins.swap(remote[0], remote[1]);
            let downgrade = entry(
                role,
                1,
                records(agreed)
                    .into_iter()
                    .filter(|(_, origin)| origin.wallet_id == local)
                    .collect(),
            );
            for (case, altered, same_receiver) in [
                (
                    "replace_one_remote_key",
                    substitute(agreed, local, &attacker_keys[..1]),
                    false,
                ),
                (
                    "replace_both_remote_keys",
                    substitute(agreed, local, &attacker_keys),
                    false,
                ),
                ("downgrade_to_local_one_of_one", downgrade, false),
                ("remote_origin_index", index, true),
                ("remote_origin_identity", identity, true),
                ("swap_remote_origins", swapped, true),
            ] {
                locally_owned(&saved.wallet, &altered);
                assert_ne!(&altered, agreed);
                assert_eq!(
                    altered.receiver().unwrap() == agreed.receiver().unwrap(),
                    same_receiver
                );
                let mut proposed = candidates[i].clone();
                *shared_entry(&mut proposed, role) = altered;
                assert_ne!(proposed.fingerprint().unwrap(), approved[i]);
                saved.reject(proposed, approved[i], false, case);
            }
        }
    }

    // Equivocation: each participant sees its own correct key alongside the
    // coordinator's two keys. Comparing full inventory hashes would also reject
    // the honest fixture; compare the shared policy/receiver instead.
    let inconsistent = wallets
        .each_ref()
        .map(|saved| substitute(&shared[0], saved.before.wallet_id, &attacker_keys));
    assert_eq!(
        inconsistent
            .each_ref()
            .map(|entry| entry.policy_hex.clone())
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    for (i, saved) in wallets.iter_mut().enumerate() {
        locally_owned(&saved.wallet, &inconsistent[i]);
        assert_ne!(
            inconsistent[i].receiver().unwrap(),
            shared[0].receiver().unwrap()
        );
        let mut proposed = candidates[i].clone();
        *shared_entry(&mut proposed, Role::Receive) = inconsistent[i].clone();
        saved.reject(
            proposed,
            approved[i],
            false,
            "inconsistent_participant_view",
        );
    }

    // Even a supplied matching approval cannot authorize a foreign key as this
    // wallet's own key. Keep the schema/origin coordinate correct to isolate it.
    let mut proposed = candidates[0].clone();
    let mut replaced = records(&shared[0]);
    replaced
        .iter_mut()
        .find(|(_, origin)| origin.wallet_id == proposed.wallet_id)
        .unwrap()
        .0 = attacker_keys[0];
    *shared_entry(&mut proposed, Role::Receive) = entry(Role::Receive, 2, replaced);
    let wrong_approval = proposed.fingerprint().unwrap();
    wallets[0].reject(
        proposed,
        wrong_approval,
        true,
        "foreign_local_key_with_matching_approval",
    );

    // Every wallet remains usable after the attacks. The same destination that
    // remained absent on rejection now holds a real, reloadable encrypted backup.
    for (i, saved) in wallets.iter_mut().enumerate() {
        saved
            .wallet
            .enroll_backup(
                candidates[i].clone(),
                approved[i],
                &saved.destination(),
                PASSWORD,
            )
            .unwrap();
        assert_eq!(saved.wallet.manifest(), &candidates[i]);
        let restored = Wallet::load_backup(&saved.destination(), PASSWORD, &profile()).unwrap();
        assert_eq!(restored.manifest(), &candidates[i]);
        assert_eq!(
            fs::read(saved.directory.path().join("old.tpq")).unwrap(),
            saved.backup
        );
        assert_eq!(
            fs::read(saved.directory.path().join("inventory.json")).unwrap(),
            saved.inventory
        );
        let mut watch = WatchStore::create(
            &saved.directory.path().join("watch"),
            &restored.manifest().to_json().unwrap(),
            approved[i],
            &profile(),
            WatchMode::Allocator,
        )
        .unwrap();
        for _ in 0..saved.before.receive_end {
            watch.receive().unwrap();
        }
        assert_eq!(watch.receive().unwrap(), shared[0].receiver().unwrap());
    }
}

#[test]
fn multisig_enrollment_coordinator_supplied_hash_is_not_authentication() {
    let _serial = crate::tests::BACKUPS.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut wallet = Wallet::create(profile(), 0).unwrap();
    let owned = key_commitment(&wallet.public_key(KeyPath {
        role: Role::Receive,
        index: 0,
    }));
    let policy = entry(
        Role::Receive,
        2,
        vec![
            (
                owned,
                Origin {
                    account: 0,
                    index: 0,
                    wallet_id: wallet.manifest().wallet_id,
                },
            ),
            (
                zakura_pq_slh_dsa_b_exp::codec::key_commitment(
                    zakura_pq_slh_dsa_b_sign::SigningKey::from_seed(zeroize::Zeroizing::new(
                        [81; 48],
                    ))
                    .public_key(),
                ),
                Origin {
                    account: 0,
                    index: 4,
                    wallet_id: Hex([81; 16]),
                },
            ),
            (
                zakura_pq_slh_dsa_b_exp::codec::key_commitment(
                    zakura_pq_slh_dsa_b_sign::SigningKey::from_seed(zeroize::Zeroizing::new(
                        [82; 48],
                    ))
                    .public_key(),
                ),
                Origin {
                    account: 0,
                    index: 7,
                    wallet_id: Hex([82; 16]),
                },
            ),
        ],
    );
    locally_owned(&wallet, &policy);
    let mut candidate = wallet.manifest().clone();
    candidate.entries.push(policy.clone());
    candidate.receive_end = 1;
    candidate.revision = 1;
    // Deliberately cross the documented trust boundary: the coordinator supplies
    // both the inventory and its "approval". There is no cosigner handshake in
    // enroll_backup, so a locally owned, otherwise valid inventory is accepted.
    let supplied_hash = candidate.fingerprint().unwrap();
    wallet
        .enroll_backup(
            candidate,
            supplied_hash,
            &directory.path().join("self-approved.tpq"),
            PASSWORD,
        )
        .unwrap();
    let restored = Wallet::load_backup(
        &directory.path().join("self-approved.tpq"),
        PASSWORD,
        &profile(),
    )
    .unwrap();
    assert_eq!(restored.manifest(), wallet.manifest());
    let issued = restored.manifest().entries[0].receiver().unwrap();
    assert_eq!(issued, policy.receiver().unwrap());

    // A valid alternative receiver can be detected by an external comparison,
    // but its advertised text is not an argument to enroll_backup. This is not
    // evidence of an automatic receiver-agreement check in that API.
    let other = entry(
        Role::Receive,
        1,
        vec![(
            owned,
            Origin {
                account: 0,
                index: 0,
                wallet_id: wallet.manifest().wallet_id,
            },
        )],
    )
    .receiver()
    .unwrap();
    assert_eq!(Receiver::parse(&other.encode()).unwrap(), other);
    assert_ne!(issued, other);
    assert_ne!(issued.script(), other.script());
}
