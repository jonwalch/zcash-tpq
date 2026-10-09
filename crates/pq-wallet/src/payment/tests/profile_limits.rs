//! Local profile guards; synthetic chain responses never change node consensus.
use super::*;
use crate::{InputSigningContext, Profile};

fn limited(tx: u32, block: u32) -> Profile {
    Profile {
        max_tx_pq_checks: tx,
        max_block_pq_checks: block,
        ..profile()
    }
}
fn limited_owners(n: usize, tx: u32, block: u32) -> Vec<Wallet> {
    let mut owners = wallets(n, 1, 1);
    for owner in &mut owners {
        owner.manifest.profile = limited(tx, block);
        owner.manifest.validate().unwrap();
    }
    owners
}

#[test]
fn normal_profile_is_explicit_and_cannot_reopen_small_profile_inventory() {
    let wallet = limited_owners(1, 100, 500).remove(0);
    let raw = wallet.plaintext().unwrap();
    Wallet::from_plaintext(&raw, &limited(100, 500)).unwrap();
    assert!(Wallet::from_plaintext(&raw, &limited(15, 42)).is_err());
    let old = limited_owners(1, 15, 42).remove(0);
    let raw = old.plaintext().unwrap();
    Wallet::from_plaintext(&raw, &limited(15, 42)).unwrap();
    assert!(Wallet::from_plaintext(&raw, &limited(100, 500)).is_err());
}
fn is_policy_limit<T>(result: Result<T, Error>, tx: u32, block: u32) {
    assert!(
        matches!(result, Err(Error::PolicyLimit { required: 2, transaction, block: found }) if transaction == tx && found == block)
    );
}
fn empty_inventory(wallet: &mut Wallet) -> crate::Manifest {
    let mut candidate = wallet.manifest.clone();
    candidate.revision += 1;
    wallet.manifest.entries.clear();
    wallet.manifest.receive_end = 0;
    wallet.manifest.change_end = 0;
    candidate
}

#[test]
fn enrollment_rejects_new_incompatible_entries_without_hiding_old_inventory() {
    for (tx, block) in [(1, 1), (1, 2)] {
        for role in [Role::Receive, Role::Change] {
            let mut owners = limited_owners(3, tx, block);
            let wallet = &mut owners[0];
            let original = wallet.manifest.to_json().unwrap();
            // Existing inventory and recovery plaintext remain decodable even
            // when its policies cannot be newly issued under this profile.
            let restored =
                Wallet::from_plaintext(&wallet.plaintext().unwrap(), &limited(tx, block)).unwrap();
            assert_eq!(restored.manifest().to_json().unwrap(), original);
            let mut candidate = empty_inventory(wallet);
            candidate.entries.retain(|e| e.role == role as u8);
            match role {
                Role::Receive => candidate.change_end = 0,
                Role::Change => candidate.receive_end = 0,
            }
            let before = wallet.manifest.clone();
            let temp = tempfile::tempdir().unwrap();
            let target = temp.path().join("rejected.tpq");
            is_policy_limit(
                wallet.enroll_backup(
                    candidate.clone(),
                    candidate.fingerprint().unwrap(),
                    &target,
                    b"public-profile-test",
                ),
                tx,
                block,
            );
            assert!(!target.exists());
            assert_eq!(wallet.manifest(), &before);
        }
    }
    let mut owners = limited_owners(3, 1, 1);
    let wallet = &mut owners[0];
    let mut candidate = wallet.manifest.clone();
    candidate.revision += 1;
    candidate.retired_receive_end = candidate.receive_end;
    candidate.retired_change_end = candidate.change_end;
    let temp = tempfile::tempdir().unwrap();
    // A metadata-only recovery update gets as far as backup password checking;
    // the new-entry guard must not retroactively reject the old descriptors.
    assert!(matches!(
        wallet.enroll_backup(
            candidate.clone(),
            candidate.fingerprint().unwrap(),
            &temp.path().join("recovery.tpq"),
            b""
        ),
        Err(Error::Password)
    ));
}

#[test]
fn small_positive_profiles_allow_backed_up_single_and_multisig_enrollment() {
    let _serial = crate::tests::BACKUPS.lock().unwrap();
    let password = b"public-small-profile-test";
    for n in [1, 3] {
        let limit = if n == 1 { 1 } else { 2 };
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("enrolled.tpq");
        let mut owners = limited_owners(n, limit, limit);
        let wallet = &mut owners[0];
        let candidate = empty_inventory(wallet);
        if n == 1 {
            wallet.extend_single_backup(1, 1, &path, password).unwrap();
        } else {
            wallet
                .enroll_backup(
                    candidate.clone(),
                    candidate.fingerprint().unwrap(),
                    &path,
                    password,
                )
                .unwrap();
        }
        let reopened = Wallet::load_backup(&path, password, &limited(limit, limit)).unwrap();
        assert_eq!(reopened.manifest(), wallet.manifest());
        assert_eq!(reopened.manifest().receive_end, 1);
        assert_eq!(reopened.manifest().change_end, 1);
    }
    assert!(matches!(
        limited(2, 1).validate(),
        Err(Error::UnsupportedContext)
    ));
}

#[test]
fn receive_and_change_issuance_respect_limits_without_losing_legacy_discovery() {
    let owners = limited_owners(3, 1, 1);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let before = fs::read(path.join("state.json")).unwrap();
    is_policy_limit(store.receive(), 1, 1);
    let entry = wallet.manifest.entries[0].clone();
    let input = InputRecord {
        spent_output_hex: hex::encode(output(&entry, 2_000_000).zcash_serialize_to_vec().unwrap()),
        entry,
    };
    is_policy_limit(store.eligible_change(&[input]), 1, 1);
    assert_eq!(store.receive_next(), 0);
    assert_eq!(store.state.payments.change_next, 0);
    assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
    let mut source = Source::funded(wallet, &[2_000_000]);
    store.sync(&mut source, 100).unwrap();
    assert_eq!(store.coins().len(), 1);
    assert_eq!(store.status().unwrap().confirmed_zatoshis, Some(2_000_000));
    is_policy_limit(store.prepare_payment(wallet, &mut source, &intent(6)), 1, 1);
    assert!(store.payments().unwrap().is_empty());
    let bytes = wallet.manifest().to_json().unwrap();
    store
        .import(&bytes, wallet.manifest().fingerprint().unwrap())
        .unwrap();
    drop(store);
    let store = WatchStore::open(&path, &limited(1, 1)).unwrap();
    assert_eq!(store.coins().len(), 1);
    assert!(store.payments().unwrap().is_empty());
    assert_eq!(store.receive_next(), 0);
    assert_eq!(store.state.payments.change_next, 0);
}

#[test]
fn each_signer_rejects_an_incompatible_policy_before_reserving_or_signing() {
    for version in [5, 6] {
        let mut owners = wallets(3, 1, 1);
        let temp = tempfile::tempdir().unwrap();
        let mut source = Source::funded(&owners[0], &[2_000_000]);
        let mut coordinator = create(
            &temp.path().join("coordinator"),
            owners[0].manifest(),
            WatchMode::Allocator,
        );
        let approved = intent(version);
        let (mut proposal, _) = coordinator
            .prepare_payment(&owners[0], &mut source, &approved)
            .unwrap();
        proposal.profile = limited(1, 1);
        for owner in &mut owners {
            owner.manifest.profile = limited(1, 1);
        }
        for (i, owner) in owners.iter().enumerate() {
            let path = temp.path().join(format!("signer-{i}"));
            let mut signer = create(&path, owner.manifest(), WatchMode::Allocator);
            is_policy_limit(
                signer.review_payment(owner, &mut source, &proposal, &approved),
                1,
                1,
            );
            is_policy_limit(
                signer.sign_payment_with_rng(
                    owner,
                    &mut source,
                    &proposal,
                    &approved,
                    proposal.id().unwrap(),
                    &mut FailingRng,
                ),
                1,
                1,
            );
            assert!(signer.payments().unwrap().is_empty());
            assert_eq!(signer.state.payments.change_next, 0);
            let tx = proposal.transaction().unwrap();
            let previous = source
                .resolve(proposal.points().unwrap()[0])
                .unwrap()
                .unwrap()
                .output;
            let policy = proposal.inputs[0].entry.policy().unwrap();
            let context = InputSigningContext::new(
                &tx,
                zakura_pq::NetworkDomain::Regtest,
                zakura_chain::parameters::NetworkUpgrade::Nu7,
                Arc::new(vec![previous]),
                0,
                &policy,
            )
            .unwrap();
            is_policy_limit(
                owner.sign_partial_with_rng(
                    &context,
                    KeyPath {
                        role: Role::Receive,
                        index: 0,
                    },
                    &mut FailingRng,
                ),
                1,
                1,
            );
        }
    }
}

#[test]
fn small_profile_payments_work_and_multi_input_budget_still_applies() {
    for n in [1, 3] {
        let limit = if n == 1 { 1 } else { 2 };
        let owners = limited_owners(n, limit, limit);
        for version in [5, 6] {
            let temp = tempfile::tempdir().unwrap();
            let wallet = &owners[0];
            let mut source = Source::funded(wallet, &[2_000_000]);
            let mut store = create(
                &temp.path().join("coordinator"),
                wallet.manifest(),
                WatchMode::Allocator,
            );
            assert_eq!(
                store.receive().unwrap(),
                wallet.manifest.entries[0].receiver().unwrap()
            );
            let approved = intent(version);
            let (proposal, summary) = store
                .prepare_payment(wallet, &mut source, &approved)
                .unwrap();
            assert_eq!(summary.checks, limit);
            let id = proposal.id().unwrap();
            let mut partials = store
                .sign_payment(wallet, &mut source, &proposal, &approved, id)
                .unwrap();
            if n == 3 {
                let mut cosigner = create(
                    &temp.path().join("cosigner"),
                    owners[1].manifest(),
                    WatchMode::Allocator,
                );
                partials.extend(
                    cosigner
                        .sign_payment(&owners[1], &mut source, &proposal, &approved, id)
                        .unwrap(),
                );
            }
            assert!(!store
                .assemble_payment(wallet, &mut source, &proposal, &approved, &partials)
                .unwrap()
                .is_empty());
        }
    }
    let mut owners = wallets(1, 1, 1);
    let temp = tempfile::tempdir().unwrap();
    let mut source = Source::funded(&owners[0], &[400_000, 400_000]);
    let mut coordinator = create(
        &temp.path().join("coordinator"),
        owners[0].manifest(),
        WatchMode::Allocator,
    );
    let mut approved = intent(6);
    approved.remainder = Remainder::Keep;
    let (mut proposal, summary) = coordinator
        .prepare_payment(&owners[0], &mut source, &approved)
        .unwrap();
    assert_eq!(summary.checks, 2);
    proposal.profile = limited(1, 1);
    owners[0].manifest.profile = limited(1, 1);
    let mut signer = create(
        &temp.path().join("signer"),
        owners[0].manifest(),
        WatchMode::Allocator,
    );
    assert!(matches!(
        signer.sign_payment_with_rng(
            &owners[0],
            &mut source,
            &proposal,
            &approved,
            proposal.id().unwrap(),
            &mut FailingRng
        ),
        Err(Error::Limits)
    ));
    assert!(signer.payments().unwrap().is_empty());
    assert_eq!(signer.state.payments.change_next, 0);
}
