//! Resume pre-update approvals using synthetic trusted history and both disk formats.
use super::*;

fn with_fee(proposal: &Proposal, fee: u64) -> Proposal {
    let mut proposal = proposal.clone();
    let mut tx = proposal.transaction().unwrap();
    let (Transaction::V5 { outputs, .. } | Transaction::V6 { outputs, .. }) = &mut tx else {
        unreachable!()
    };
    // These fixtures spend 2,000,000 and pay 500,000. Keep their old fee
    // independent of the production estimator and its current marginal rate.
    outputs[1].value = (1_500_000 - fee).try_into().unwrap();
    proposal.transaction_hex = hex::encode(tx.zcash_serialize_to_vec().unwrap());
    proposal
}

fn retain(store: &mut WatchStore, proposal: &Proposal, intent: &Intent, journal: bool) {
    // Recreate the approval written before the fee update, without asking the
    // current fee policy to approve a new high-fee proposal.
    let mut candidate = store.state.clone();
    candidate.payments.change_next = 1;
    candidate.payments.records.push(PaymentRecord {
        intent: intent.clone(),
        partials: vec![],
        proposal: proposal.clone(),
        signed_transaction_hex: None,
        state: PaymentState::Prepared,
    });
    store.commit(candidate).unwrap();
    if journal {
        store.migrate_payment_journal().unwrap();
    }
}

pub(super) fn resume_legacy_approvals(owners: &[Wallet], current_fee: u64, legacy_fee: u64) {
    let signer_count = if owners.len() == 1 { 1 } else { 2 };
    for version in [5, 6] {
        for journal in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let paths: Vec<_> = (0..signer_count)
                .map(|i| temp.path().join(format!("signer-{i}")))
                .collect();
            let mut stores: Vec<_> = paths
                .iter()
                .zip(owners)
                .map(|(path, wallet)| create(path, wallet.manifest(), WatchMode::Allocator))
                .collect();
            let mut source = Source::funded(&owners[0], &[2_000_000, 800_000]);
            let mut approved = intent(version);
            if crate::Receiver::parse(&approved.receiver).unwrap().suite() != owners[0].suite() {
                approved.receiver_activation_height = Some(profile().pq_activation_height);
            }
            if journal {
                approved.remainder = Remainder::Keep;
            }
            let (new, summary) = stores[0]
                .preview_payment(&owners[0], &mut source, &approved)
                .unwrap();
            assert_eq!(summary.fee, current_fee);
            let old = with_fee(&new, legacy_fee);
            let old_id = old.id().unwrap();
            for store in &mut stores {
                retain(store, &old, &approved, journal);
            }
            drop(stores);
            let mut stores: Vec<_> = paths
                .iter()
                .zip(owners)
                .map(|(path, wallet)| WatchStore::open(path, &wallet.manifest().profile).unwrap())
                .collect();
            let mut partials = Vec::new();
            for (store, wallet) in stores.iter_mut().zip(owners) {
                let summary = store
                    .review_payment(wallet, &mut source, &old, &approved)
                    .unwrap();
                assert_eq!(summary.fee, legacy_fee);
                assert_eq!(summary.conventional_fee, current_fee);
                partials.extend(
                    store
                        .sign_payment(wallet, &mut source, &old, &approved, old_id)
                        .unwrap(),
                );
            }
            // A saved partial survives restart; each cosigner keeps its intent.
            drop(stores);
            let mut stores: Vec<_> = paths
                .iter()
                .zip(owners)
                .map(|(path, wallet)| WatchStore::open(path, &wallet.manifest().profile).unwrap())
                .collect();
            let signed = stores[0]
                .assemble_payment(&owners[0], &mut source, &old, &approved, &partials)
                .unwrap();
            let next = stores[0]
                .preview_payment(&owners[0], &mut source, &approved)
                .unwrap()
                .1;
            assert_eq!(next.input_value, 800_000, "old inputs remain reserved");
            assert_eq!(next.fee, current_fee, "new payments keep the lower rate");

            source.mine();
            let (refreshed, summary) = stores[0]
                .preview_payment_refresh(&owners[0], &mut source, old_id)
                .unwrap();
            let new_id = refreshed.id().unwrap();
            assert_ne!(new_id, old_id);
            assert_eq!(summary.fee, legacy_fee);
            assert_eq!(refreshed.transaction_hex, old.transaction_hex);
            assert_eq!(refreshed.expiry().unwrap(), old.expiry().unwrap());
            let mut retried = Vec::new();
            for (i, (store, wallet)) in stores.iter_mut().zip(owners).enumerate() {
                assert_eq!(
                    store
                        .review_payment_refresh(wallet, &mut source, old_id, &refreshed)
                        .unwrap()
                        .fee,
                    legacy_fee
                );
                store
                    .approve_payment_refresh(wallet, &mut source, old_id, &refreshed, new_id)
                    .unwrap();
                assert_eq!(store.payments().unwrap()[0].intent, approved);
                let saved = store
                    .sign_payment(wallet, &mut source, &refreshed, &approved, new_id)
                    .unwrap();
                let mut expected = partials[i].clone();
                expected.proposal_id = new_id;
                assert_eq!(saved, [expected], "reuse the original signature bytes");
                retried.extend(saved);
            }
            assert_eq!(
                stores[0]
                    .assemble_payment(&owners[0], &mut source, &refreshed, &approved, &retried)
                    .unwrap(),
                signed
            );
            drop(stores);

            let wallet = &owners[0];
            let mut store = WatchStore::open(&paths[0], &wallet.manifest().profile).unwrap();
            source.journal = Some(paths[0].join("state.json"));
            source.fail_submit = true;
            assert!(matches!(
                store.submit_payment(wallet, &mut source, new_id),
                Err(Error::SubmissionUnknown)
            ));
            drop(store);
            let mut store = WatchStore::open(&paths[0], &wallet.manifest().profile).unwrap();
            source.fail_submit = false;
            store.submit_payment(wallet, &mut source, new_id).unwrap();
            assert_eq!(source.sent, [signed.clone(), signed]);
            source.mine();
            assert_eq!(
                store.reconcile_payments(&mut source).unwrap(),
                [PaymentState::Confirmed]
            );
        }
    }
}

#[test]
fn slh_legacy_approvals_resume_across_fee_upgrade() {
    resume_legacy_approvals(&wallets(1, 1, 2), 21_600, 270_000);
    resume_legacy_approvals(&wallets(3, 1, 2), 42_800, 535_000);
}

#[test]
fn legacy_fee_requires_exact_local_approval_and_still_checks_trusted_inputs() {
    let owners = wallets(1, 1, 2);
    let wallet = &owners[0];
    for journal in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("store");
        let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
        let mut source = Source::funded(wallet, &[2_000_000]);
        let approved = intent(6);
        let (new, _) = store
            .preview_payment(wallet, &mut source, &approved)
            .unwrap();
        let old = with_fee(&new, 270_000);
        let id = old.id().unwrap();
        assert!(matches!(
            store.review_payment(wallet, &mut source, &old, &approved),
            Err(Error::Fee)
        ));
        assert!(matches!(
            store.sign_payment(wallet, &mut source, &old, &approved, id),
            Err(Error::Fee)
        ));
        assert!(store.payments().unwrap().is_empty());
        retain(&mut store, &old, &approved, journal);
        let mut changed = approved.clone();
        changed.remainder = Remainder::Fee;
        assert!(matches!(
            store.review_payment(wallet, &mut source, &old, &changed),
            Err(Error::ProposalMismatch)
        ));
        // A different retained intent that still rejects overpayment gets
        // ordinary fee validation. It cannot inherit the legacy fee and reach
        // the later intent comparison.
        changed = approved.clone();
        changed.max_fee -= 1;
        assert!(matches!(
            store.review_payment(wallet, &mut source, &old, &changed),
            Err(Error::Fee)
        ));
        source.corrupt_value = true;
        assert!(matches!(
            store.sign_payment(wallet, &mut source, &old, &approved, id),
            Err(Error::InputContext)
        ));
        source.corrupt_value = false;
        source.mine();
        let (refreshed, _) = store
            .preview_payment_refresh(wallet, &mut source, id)
            .unwrap();
        assert!(
            matches!(
                store.review_payment(wallet, &mut source, &refreshed, &approved),
                Err(Error::Fee)
            ),
            "changed tip needs the explicit refresh approval"
        );
        let altered = with_fee(&refreshed, 270_001);
        assert!(matches!(
            store.approve_payment_refresh(wallet, &mut source, id, &altered, altered.id().unwrap()),
            Err(Error::ProposalMismatch)
        ));
        assert!(store.payments().unwrap()[0].partials.is_empty());
        for _ in 0..EXPIRY_BLOCKS {
            source.mine();
        }
        assert!(matches!(
            store.sign_payment(wallet, &mut source, &old, &approved, id),
            Err(Error::Expired)
        ));
    }
}

#[test]
fn retained_approval_does_not_waive_fee_ceiling_or_allow_arbitrary_overpayment() {
    let owners = wallets(1, 1, 1);
    let wallet = &owners[0];
    for journal in [false, true] {
        for (fee, ceiling) in [
            (270_001, 1_000_000),
            (270_000, 269_999),
            (21_599, 1_000_000),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let mut store = create(
                &temp.path().join("store"),
                wallet.manifest(),
                WatchMode::Allocator,
            );
            let mut source = Source::funded(wallet, &[2_000_000]);
            let mut approved = intent(6);
            approved.max_fee = ceiling;
            let (new, _) = store
                .preview_payment(wallet, &mut source, &approved)
                .unwrap();
            let old = with_fee(&new, fee);
            retain(&mut store, &old, &approved, journal);
            assert!(matches!(
                store.sign_payment(wallet, &mut source, &old, &approved, old.id().unwrap()),
                Err(Error::Fee)
            ));
            assert!(store.payments().unwrap()[0].partials.is_empty());
        }
    }
}
