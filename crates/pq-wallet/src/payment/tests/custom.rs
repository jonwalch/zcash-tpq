//! Synthetic public wallet workflows; these do not qualify live node acceptance.
use super::*;
use crate::{Profile, Receiver};

fn custom_profile() -> Profile {
    Profile {
        network: 1,
        chain_fingerprint: Some(Hex([0x31; 32])),
        ..profile()
    }
}

#[test]
fn custom_chain_payments_recovery_and_context_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let approved = custom_profile();
    let mut wallet = Wallet::create(approved.clone(), 0).unwrap();
    wallet
        .extend_single_backup(1, 2, &temp.path().join("backup"), b"public-test-password")
        .unwrap();
    let manifest = wallet.manifest();
    assert_eq!(manifest.derivation_version, 2);
    assert_eq!(manifest.format, "ZcashTransparentPQ/inventory/v2");
    let mut old_transport = manifest.clone();
    old_transport.format = "ZcashTransparentPQ/inventory/v1".into();
    old_transport.derivation_version = 1;
    assert!(old_transport.to_json().is_err());
    let receiver = manifest.entries[0].receiver_for(&approved).unwrap();
    assert!(receiver.encode().starts_with("tpqtest1"));
    assert_eq!(receiver.encode().len(), 122);
    assert_eq!(Receiver::parse(&receiver.encode()).unwrap(), receiver);
    assert!(receiver.check_profile(&profile()).is_err());
    let wrong = Profile {
        chain_fingerprint: Some(Hex([0x32; 32])),
        ..approved.clone()
    };
    assert!(receiver.check_profile(&wrong).is_err());
    assert!(manifest.entries[0]
        .receiver()
        .unwrap()
        .check_profile(&approved)
        .is_err());
    let restored = Wallet::load_backup(
        &temp.path().join("backup"),
        b"public-test-password",
        &approved,
    )
    .unwrap();
    assert_eq!(restored.manifest(), manifest);
    assert!(
        Wallet::load_backup(&temp.path().join("backup"), b"public-test-password", &wrong).is_err()
    );
    let recovered = crate::recovery::restore_inventory(
        &temp.path().join("backup"),
        b"public-test-password",
        &approved,
        manifest.fingerprint().unwrap(),
        &temp.path().join("recovered"),
    )
    .unwrap();
    assert_eq!(recovered.watch.mode(), WatchMode::Monitor);
    assert_eq!(
        recovered.wallet.public_key(KeyPath {
            role: Role::Receive,
            index: 0
        }),
        wallet.public_key(KeyPath {
            role: Role::Receive,
            index: 0
        })
    );
    assert!(crate::recovery::restore_inventory(
        &temp.path().join("backup"),
        b"public-test-password",
        &wrong,
        manifest.fingerprint().unwrap(),
        &temp.path().join("wrong-recovery"),
    )
    .is_err());
    let mut store = create(&temp.path().join("watch"), manifest, WatchMode::Allocator);
    assert_eq!(store.receive().unwrap(), receiver);
    let mut source = Source::funded(&wallet, &[2_000_000]);
    let intent = Intent {
        amount: 500_000,
        max_fee: 1_000_000,
        receiver: receiver.encode(),
        receiver_activation_height: None,
        remainder: Remainder::Reject,
        version: Some(6),
    };
    for mutation in 0..6 {
        let mut bad = source.context().unwrap();
        match mutation {
            0 => bad.slh.as_mut().unwrap().chain_fingerprint = Some(Hex([0x32; 32])),
            1 => bad.slh.as_mut().unwrap().activation_height += 1,
            2 => bad.slh.as_mut().unwrap().max_tx_pq_checks += 1,
            3 => bad.slh.as_mut().unwrap().max_block_pq_checks += 1,
            4 => bad.nu7_activation_height += 1,
            _ => bad.slh = None,
        }
        assert!(bad.validate(manifest).is_err());
        if mutation != 4 {
            let original = source.slh.clone();
            source.slh = bad.slh;
            assert!(store.sync(&mut source, 100).is_err());
            source.slh = original;
        }
    }
    for version in [5, 6] {
        let mut store = create(
            &temp.path().join(format!("pay-{version}")),
            manifest,
            WatchMode::Allocator,
        );
        let mut source = Source::funded(&wallet, &[2_000_000]);
        let intent = Intent {
            version: Some(version),
            ..intent.clone()
        };
        let (proposal, review) = store
            .prepare_payment(&wallet, &mut source, &intent)
            .unwrap();
        assert_eq!(proposal.format, "ZcashTransparentPQ/proposal/v2");
        let mut old_proposal = proposal.clone();
        old_proposal.format = "ZcashTransparentPQ/proposal/v1".into();
        assert!(old_proposal.to_json().is_err());
        let partials = store
            .sign_payment(&wallet, &mut source, &proposal, &intent, review.proposal_id)
            .unwrap();
        let bytes = store
            .assemble_payment(&wallet, &mut source, &proposal, &intent, &partials)
            .unwrap();
        let tx = proposal::decode_transaction(&bytes).unwrap();
        let previous: Arc<Vec<zakura_chain::transparent::Output>> = Arc::new(
            proposal
                .inputs
                .iter()
                .map(|i| proposal::decode_output(&i.spent_output_hex).unwrap())
                .collect(),
        );
        crate::suite::verify_inputs(
            &tx,
            previous.clone(),
            &[crate::Suite::SlhDsaB128sExpV1],
            approved.network_domain(),
        )
        .unwrap();
        assert!(crate::suite::verify_inputs(
            &tx,
            previous,
            &[crate::Suite::SlhDsaB128sExpV1],
            profile().network_domain()
        )
        .is_err());
        assert_eq!(
            store
                .submit_payment(&wallet, &mut source, review.proposal_id)
                .unwrap(),
            txid(&tx)
        );
        assert_eq!(source.sent, [bytes.clone()]);
        if version == 6 {
            let snapshot = temp.path().join("snapshot");
            store
                .save_operational_snapshot(
                    &temp.path().join("backup"),
                    b"public-test-password",
                    &snapshot,
                )
                .unwrap();
            let mut recovered = crate::recovery::restore_operational_snapshot(
                &snapshot,
                b"public-test-password",
                &approved,
                crate::recovery::SnapshotTrust::Unknown,
                &temp.path().join("snapshot-restored"),
            )
            .unwrap();
            let record = recovered
                .watch
                .payment_record(review.proposal_id)
                .unwrap()
                .unwrap();
            assert_eq!(
                record.signed_transaction_hex.as_deref(),
                Some(hex::encode(&bytes).as_str())
            );
        }
    }
}
