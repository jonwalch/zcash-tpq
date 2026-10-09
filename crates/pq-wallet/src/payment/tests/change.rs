use super::*;
use std::path::Path;

fn state(store: &WatchStore, path: &Path) -> Vec<u8> {
    let bytes = fs::read(path.join("state.json")).unwrap();
    assert_eq!(
        serde_json::to_value(&store.state).unwrap(),
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
    );
    bytes
}

fn advancement(review: &Review) -> &ChangeAdvancement {
    review
        .local_change
        .as_ref()
        .unwrap()
        .advancement
        .as_ref()
        .unwrap()
}

fn change_to(proposal: &Proposal, entry: &Entry) -> Proposal {
    let mut changed = proposal.clone();
    changed.outputs[1].entry = Some(entry.clone());
    changed.outputs[1].receiver = entry.receiver().unwrap().encode();
    let mut tx = proposal.transaction().unwrap();
    match &mut tx {
        Transaction::V5 { outputs, .. } | Transaction::V6 { outputs, .. } => {
            outputs[1].lock_script = entry.policy().unwrap().lock_script();
        }
        _ => unreachable!(),
    }
    changed.transaction_hex = hex::encode(tx.zcash_serialize_to_vec().unwrap());
    changed
}

#[test]
fn last_change_entry_cannot_silently_retire_unused_inventory() {
    for version in [5, 6] {
        for count in [1, 3] {
            let owners = wallets(count, 1, 4);
            let wallet = &owners[0];
            let temp = tempfile::tempdir().unwrap();
            let mut coordinator = create(
                &temp.path().join("coordinator"),
                wallet.manifest(),
                WatchMode::Allocator,
            );
            let path = temp.path().join("signer");
            let mut signer = create(&path, wallet.manifest(), WatchMode::Allocator);
            let mut source = Source::funded(wallet, &[2_000_000]);
            let approved = intent(version);
            let (proposal, _) = coordinator
                .prepare_payment(wallet, &mut source, &approved)
                .unwrap();
            let changed = change_to(&proposal, wallet.manifest.entries.last().unwrap());
            signer.sync(&mut source, 10).unwrap();
            let before = state(&signer, &path);
            let summary = signer
                .review_payment(wallet, &mut source, &changed, &approved)
                .unwrap();
            let jump = advancement(&summary);
            assert_eq!(
                (
                    jump.first_eligible_index,
                    jump.skipped_start,
                    jump.skipped_end
                ),
                (0, 0, 3)
            );
            assert_eq!(summary.local_change.as_ref().unwrap().local_index, 3);
            assert!(matches!(
                signer.sign_payment_with_rng(
                    wallet,
                    &mut source,
                    &changed,
                    &approved,
                    changed.id().unwrap(),
                    &mut FailingRng
                ),
                Err(Error::ChangeApprovalRequired)
            ));
            assert!(matches!(
                signer.assemble_payment(wallet, &mut source, &changed, &approved, &[]),
                Err(Error::ChangeApprovalRequired)
            ));
            assert!(matches!(
                signer.approve_payment_change(
                    wallet,
                    &mut source,
                    &changed,
                    &approved,
                    summary.proposal_id
                ),
                Err(Error::ProposalMismatch)
            ));
            assert_eq!(state(&signer, &path), before);
            drop(signer);
            let signer = WatchStore::open(&path, &profile()).unwrap();
            assert_eq!(state(&signer, &path), before);
            assert_eq!(signer.state.payments.change_next, 0);
            assert!(signer.payments().unwrap().is_empty());
        }
    }
}

#[test]
fn advancement_approval_binds_proposal_intent_inventory_and_cursor() {
    for version in [5, 6] {
        let mut owners = wallets(1, 1, 5);
        let wallet = &mut owners[0];
        let temp = tempfile::tempdir().unwrap();
        let mut coordinator = create(
            &temp.path().join("coordinator"),
            wallet.manifest(),
            WatchMode::Allocator,
        );
        let path = temp.path().join("signer");
        let mut signer = create(&path, wallet.manifest(), WatchMode::Allocator);
        let mut source = Source::funded(wallet, &[2_000_000, 2_000_000]);
        let approved = intent(version);
        let (first, _) = coordinator
            .prepare_payment(wallet, &mut source, &approved)
            .unwrap();
        let (second, _) = coordinator
            .prepare_payment(wallet, &mut source, &approved)
            .unwrap();
        let jumped = change_to(&second, wallet.manifest.entries.last().unwrap());
        let initial = signer
            .review_payment(wallet, &mut source, &jumped, &approved)
            .unwrap();
        let token = advancement(&initial).approval_id;
        let before = state(&signer, &path);
        let different = change_to(&jumped, &wallet.manifest.entries[4]);
        assert!(matches!(
            signer.approve_payment_change(wallet, &mut source, &different, &approved, token),
            Err(Error::ProposalMismatch)
        ));
        let mut different_intent = approved.clone();
        different_intent.max_fee += 1;
        assert!(matches!(
            signer.approve_payment_change(wallet, &mut source, &jumped, &different_intent, token),
            Err(Error::ProposalMismatch)
        ));
        assert_eq!(state(&signer, &path), before);

        // An independently reserved payment moves the cursor without consuming
        // the jumped proposal's input. The old approval still must fail.
        signer
            .sign_payment(wallet, &mut source, &first, &approved, first.id().unwrap())
            .unwrap();
        let before = state(&signer, &path);
        assert!(matches!(
            signer.approve_payment_change(wallet, &mut source, &jumped, &approved, token),
            Err(Error::ProposalMismatch)
        ));
        assert_eq!(state(&signer, &path), before);
        let updated = signer
            .review_payment(wallet, &mut source, &jumped, &approved)
            .unwrap();
        let token = advancement(&updated).approval_id;
        assert_eq!(advancement(&updated).skipped_start, 1);

        // An authenticated inventory revision invalidates the token even when
        // its covered entries and cursor are unchanged.
        wallet.manifest.revision += 1;
        signer
            .import(
                &wallet.manifest.to_json().unwrap(),
                wallet.manifest.fingerprint().unwrap(),
            )
            .unwrap();
        let before = state(&signer, &path);
        assert!(matches!(
            signer.approve_payment_change(wallet, &mut source, &jumped, &approved, token),
            Err(Error::ProposalMismatch)
        ));
        assert_eq!(state(&signer, &path), before);
        let updated = signer
            .review_payment(wallet, &mut source, &jumped, &approved)
            .unwrap();
        let token = advancement(&updated).approval_id;
        signer
            .approve_payment_change(wallet, &mut source, &jumped, &approved, token)
            .unwrap();
        assert_eq!(signer.state.payments.change_next, 5);
        assert!(signer.payments().unwrap()[1].partials.is_empty());
        assert!(signer.payments().unwrap()[1]
            .signed_transaction_hex
            .is_none());
        let before = state(&signer, &path);
        assert!(matches!(
            signer.approve_payment_change(wallet, &mut source, &jumped, &approved, token),
            Err(Error::ProposalMismatch)
        ));
        assert_eq!(state(&signer, &path), before);
        drop(signer);
        let mut signer = WatchStore::open(&path, &profile()).unwrap();
        assert_eq!(state(&signer, &path), before);
        assert!(signer
            .review_payment(wallet, &mut source, &jumped, &approved)
            .unwrap()
            .local_change
            .unwrap()
            .advancement
            .is_none());
        signer
            .sign_payment(
                wallet,
                &mut source,
                &jumped,
                &approved,
                jumped.id().unwrap(),
            )
            .unwrap();
    }
}

#[test]
fn concurrent_input_reservation_cannot_be_overridden_by_change_approval() {
    let owners = wallets(1, 1, 4);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("signer");
    let mut signer = create(&path, wallet.manifest(), WatchMode::Allocator);
    let mut source = Source::funded(wallet, &[2_000_000]);
    let approved = intent(6);
    let (proposal, _) = signer
        .preview_payment(wallet, &mut source, &approved)
        .unwrap();
    let jumped = change_to(&proposal, wallet.manifest.entries.last().unwrap());
    let summary = signer
        .review_payment(wallet, &mut source, &jumped, &approved)
        .unwrap();
    signer
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    let before = state(&signer, &path);
    assert!(matches!(
        signer.approve_payment_change(
            wallet,
            &mut source,
            &jumped,
            &approved,
            advancement(&summary).approval_id
        ),
        Err(Error::Reserved)
    ));
    assert_eq!(state(&signer, &path), before);
    assert!(signer.payments().unwrap()[0].partials.is_empty());
}

// The shared policies are enrolled at different local indices. No signer's
// local ordering or approval ID can be inferred from another signer's review.
fn reordered_cosigners() -> Vec<Wallet> {
    let mut owners = wallets(3, 1, 0);
    let coordinates = [[0, 1, 0], [1, 0, 2], [2, 2, 1]];
    let mut entries = Vec::new();
    for indices in coordinates {
        let mut keys: Vec<_> = owners
            .iter()
            .zip(indices)
            .map(|(owner, index)| {
                (
                    owner
                        .key(KeyPath {
                            role: Role::Change,
                            index,
                        })
                        .commitment(),
                    Origin {
                        account: 0,
                        index,
                        wallet_id: owner.manifest().wallet_id,
                    },
                )
            })
            .collect();
        keys.sort_by_key(|(commitment, _)| *commitment);
        entries.push(Entry {
            origins: keys.iter().map(|(_, origin)| origin.clone()).collect(),
            policy_hex: hex::encode(
                Policy::new(2, keys.iter().map(|(commitment, _)| *commitment).collect())
                    .unwrap()
                    .encode(),
            ),
            role: 1,
        });
    }
    for owner in &mut owners {
        let mut local = entries.clone();
        local.sort_by_key(|entry| entry.local(owner.manifest.wallet_id).unwrap().1.index);
        owner.manifest.entries.extend(local);
        owner.manifest.change_end = 3;
        owner.manifest.validate().unwrap();
    }
    owners
}

#[test]
fn cosigners_approve_their_own_index_and_cursor_differences() {
    for version in [5, 6] {
        let owners = reordered_cosigners();
        let temp = tempfile::tempdir().unwrap();
        let paths: Vec<_> = (0..3)
            .map(|i| temp.path().join(format!("signer-{i}")))
            .collect();
        let mut stores: Vec<_> = owners
            .iter()
            .zip(&paths)
            .map(|(owner, path)| create(path, owner.manifest(), WatchMode::Allocator))
            .collect();
        let mut source = Source::funded(&owners[0], &[2_000_000, 2_000_000]);
        let approved = intent(version);
        let (first, _) = stores[0]
            .prepare_payment(&owners[0], &mut source, &approved)
            .unwrap();
        let review = stores[1]
            .review_payment(&owners[1], &mut source, &first, &approved)
            .unwrap();
        assert_eq!(review.local_change.as_ref().unwrap().local_index, 1);
        let other_token = advancement(&review).approval_id;
        let before = state(&stores[1], &paths[1]);
        assert!(matches!(
            stores[1].sign_payment_with_rng(
                &owners[1],
                &mut source,
                &first,
                &approved,
                first.id().unwrap(),
                &mut FailingRng
            ),
            Err(Error::ChangeApprovalRequired)
        ));
        assert_eq!(state(&stores[1], &paths[1]), before);
        stores[1]
            .approve_payment_change(&owners[1], &mut source, &first, &approved, other_token)
            .unwrap();
        let mut partials = stores[0]
            .sign_payment(
                &owners[0],
                &mut source,
                &first,
                &approved,
                first.id().unwrap(),
            )
            .unwrap();
        partials.extend(
            stores[1]
                .sign_payment(
                    &owners[1],
                    &mut source,
                    &first,
                    &approved,
                    first.id().unwrap(),
                )
                .unwrap(),
        );
        stores[0]
            .assemble_payment(&owners[0], &mut source, &first, &approved, &partials)
            .unwrap();
        assert_eq!(
            (
                stores[0].state.payments.change_next,
                stores[1].state.payments.change_next,
                stores[2].state.payments.change_next
            ),
            (1, 2, 0)
        );

        let (second, _) = stores[0]
            .prepare_payment(&owners[0], &mut source, &approved)
            .unwrap();
        // Signer 1 already retired this policy as part of its explicit jump.
        assert!(matches!(
            stores[1].review_payment(&owners[1], &mut source, &second, &approved),
            Err(Error::Reserved)
        ));
        let review = stores[2]
            .review_payment(&owners[2], &mut source, &second, &approved)
            .unwrap();
        assert_eq!(review.local_change.as_ref().unwrap().local_index, 2);
        let before = state(&stores[2], &paths[2]);
        assert!(matches!(
            stores[2].approve_payment_change(
                &owners[2],
                &mut source,
                &second,
                &approved,
                other_token
            ),
            Err(Error::ProposalMismatch)
        ));
        assert_eq!(state(&stores[2], &paths[2]), before);
        stores[2]
            .approve_payment_change(
                &owners[2],
                &mut source,
                &second,
                &approved,
                advancement(&review).approval_id,
            )
            .unwrap();
        let mut partials = stores[0]
            .sign_payment(
                &owners[0],
                &mut source,
                &second,
                &approved,
                second.id().unwrap(),
            )
            .unwrap();
        partials.extend(
            stores[2]
                .sign_payment(
                    &owners[2],
                    &mut source,
                    &second,
                    &approved,
                    second.id().unwrap(),
                )
                .unwrap(),
        );
        stores[0]
            .assemble_payment(&owners[0], &mut source, &second, &approved, &partials)
            .unwrap();
    }
}

#[test]
fn interleaved_ownership_requires_review_before_preparation_retires_other_groups() {
    for version in [5, 6] {
        let mut owners = wallets(1, 1, 3);
        let wallet = &mut owners[0];
        // The first change policy is a valid 2-of-3 enrollment; funding belongs
        // to the single signer group whose earliest usable change is index 1.
        let peers = wallets(1, 0, 0);
        let third = wallets(1, 0, 0);
        wallet.manifest.entries[1] =
            counterexamples::change_entry(&[wallet, &peers[0], &third[0]], 0);
        wallet.manifest.validate().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("signer");
        let mut signer = create(&path, wallet.manifest(), WatchMode::Allocator);
        let mut source = Source::funded(wallet, &[2_000_000]);
        let approved = intent(version);
        signer.sync(&mut source, 10).unwrap();
        let before = state(&signer, &path);
        assert!(matches!(
            signer.prepare_payment(wallet, &mut source, &approved),
            Err(Error::ChangeApprovalRequired)
        ));
        assert_eq!(state(&signer, &path), before);
        let (proposal, summary) = signer
            .preview_payment(wallet, &mut source, &approved)
            .unwrap();
        assert_eq!(state(&signer, &path), before);
        assert_eq!(
            (
                advancement(&summary).first_eligible_index,
                advancement(&summary).skipped_start,
                advancement(&summary).skipped_end
            ),
            (1, 0, 1)
        );
        assert_eq!(
            proposal.outputs[1].entry,
            Some(wallet.manifest.entries[2].clone())
        );
        signer
            .approve_payment_change(
                wallet,
                &mut source,
                &proposal,
                &approved,
                advancement(&summary).approval_id,
            )
            .unwrap();
        assert_eq!(signer.state.payments.change_next, 2);
        let partials = signer
            .sign_payment(
                wallet,
                &mut source,
                &proposal,
                &approved,
                proposal.id().unwrap(),
            )
            .unwrap();
        signer
            .assemble_payment(wallet, &mut source, &proposal, &approved, &partials)
            .unwrap();
    }
}

#[test]
fn approved_jump_survives_restart_observed_use_rollback_and_tip_refresh() {
    for version in [5, 6] {
        for count in [1, 3] {
            let owners = wallets(count, 1, 5);
            let temp = tempfile::tempdir().unwrap();
            let signer_count = if count == 1 { 1 } else { 2 };
            let paths: Vec<_> = (0..signer_count)
                .map(|i| temp.path().join(format!("signer-{i}")))
                .collect();
            let mut stores: Vec<_> = owners
                .iter()
                .zip(&paths)
                .map(|(owner, path)| create(path, owner.manifest(), WatchMode::Allocator))
                .collect();
            let mut source = Source::funded(&owners[0], &[2_000_000, 2_000_000]);
            source.mine();
            let approved = intent(version);
            let (proposal, _) = stores[0]
                .preview_payment(&owners[0], &mut source, &approved)
                .unwrap();
            let proposal = change_to(&proposal, &owners[0].manifest.entries[3]);
            let id = proposal.id().unwrap();
            let mut first_token = None;
            let mut partials = Vec::new();
            for i in 0..signer_count {
                let summary = stores[i]
                    .review_payment(&owners[i], &mut source, &proposal, &approved)
                    .unwrap();
                let token = advancement(&summary).approval_id;
                if let Some(foreign) = first_token {
                    // Same proposal, intent, indices and cursor: only the local
                    // inventory identity differs between these cosigners.
                    assert_ne!(token, foreign);
                    let before = state(&stores[i], &paths[i]);
                    assert!(matches!(
                        stores[i].approve_payment_change(
                            &owners[i],
                            &mut source,
                            &proposal,
                            &approved,
                            foreign
                        ),
                        Err(Error::ProposalMismatch)
                    ));
                    assert_eq!(state(&stores[i], &paths[i]), before);
                } else {
                    first_token = Some(token);
                }
                stores[i]
                    .approve_payment_change(&owners[i], &mut source, &proposal, &approved, token)
                    .unwrap();
                assert_eq!(stores[i].state.payments.change_next, 3);
                partials.extend(
                    stores[i]
                        .sign_payment(&owners[i], &mut source, &proposal, &approved, id)
                        .unwrap(),
                );
            }
            let signed = stores[0]
                .assemble_payment(&owners[0], &mut source, &proposal, &approved, &partials)
                .unwrap();
            let saved: Vec<_> = stores
                .iter()
                .map(|store| serde_json::to_value(store.payments().unwrap()).unwrap())
                .collect();
            drop(stores);
            let mut stores: Vec<_> = paths
                .iter()
                .map(|path| WatchStore::open(path, &profile()).unwrap())
                .collect();
            for (store, saved) in stores.iter().zip(&saved) {
                assert_eq!(
                    serde_json::to_value(store.payments().unwrap()).unwrap(),
                    *saved
                );
            }

            // Chain observation retires index 3 independently. Its rollback
            // must not restore that inventory or revoke the existing jump.
            source.chain.push(
                vec![transaction(
                    6,
                    77,
                    vec![],
                    vec![output(&owners[0].manifest.entries[4], DUST)],
                )],
                None,
            );
            for store in &mut stores {
                store.sync(&mut source, 10).unwrap();
                assert_eq!(store.state.payments.change_next, 4);
            }
            source.chain.blocks.pop();
            replace_tip(&mut source);
            let (refreshed, summary) = stores[0]
                .preview_payment_refresh(&owners[0], &mut source, id)
                .unwrap();
            assert!(summary.local_change.as_ref().unwrap().advancement.is_none());
            let mut retries = Vec::new();
            for i in 0..signer_count {
                stores[i]
                    .approve_payment_refresh(
                        &owners[i],
                        &mut source,
                        id,
                        &refreshed,
                        summary.proposal_id,
                    )
                    .unwrap();
                assert_eq!(stores[i].state.payments.change_next, 4);
                retries.extend(
                    stores[i]
                        .sign_payment_with_rng(
                            &owners[i],
                            &mut source,
                            &refreshed,
                            &approved,
                            summary.proposal_id,
                            &mut FailingRng,
                        )
                        .unwrap(),
                );
                // A refresh of the existing capability cannot switch change.
                let different = change_to(&refreshed, &owners[0].manifest.entries[5]);
                let before = state(&stores[i], &paths[i]);
                assert!(matches!(
                    stores[i].approve_payment_refresh(
                        &owners[i],
                        &mut source,
                        summary.proposal_id,
                        &different,
                        different.id().unwrap()
                    ),
                    Err(Error::ProposalMismatch)
                ));
                assert_eq!(state(&stores[i], &paths[i]), before);
            }
            for (old, retried) in partials.iter().zip(&retries) {
                let mut expected = old.clone();
                expected.proposal_id = summary.proposal_id;
                assert_eq!(expected, *retried);
            }
            assert_eq!(
                stores[0]
                    .assemble_payment(&owners[0], &mut source, &refreshed, &approved, &retries)
                    .unwrap(),
                signed
            );
            let (next, next_review) = stores[0]
                .prepare_payment(&owners[0], &mut source, &approved)
                .unwrap();
            assert_ne!(next.points().unwrap(), proposal.points().unwrap());
            assert_eq!(next_review.local_change.as_ref().unwrap().local_index, 4);
            assert!(next_review.local_change.unwrap().advancement.is_none());
            assert_eq!(stores[0].state.payments.change_next, 5);
            assert!(source.sent.is_empty());
            state(&stores[0], &paths[0]);
        }
    }
}

#[test]
fn retired_inventory_cannot_be_reopened_by_an_old_change_approval() {
    let mut owners = wallets(1, 1, 4);
    let wallet = &mut owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("signer");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let mut source = Source::funded(wallet, &[2_000_000]);
    let approved = intent(6);
    let (proposal, _) = store
        .preview_payment(wallet, &mut source, &approved)
        .unwrap();
    let jumped = change_to(&proposal, wallet.manifest.entries.last().unwrap());
    let summary = store
        .review_payment(wallet, &mut source, &jumped, &approved)
        .unwrap();
    // Import a monotonic retirement under the same allocator. Replacement
    // allocator restoration and monitor-only behavior have separate controls.
    wallet.manifest.retired_change_end = 4;
    wallet.manifest.revision += 1;
    store
        .import(
            &wallet.manifest.to_json().unwrap(),
            wallet.manifest.fingerprint().unwrap(),
        )
        .unwrap();
    drop(store);
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    let before = state(&store, &path);
    assert!(matches!(
        store.approve_payment_change(
            wallet,
            &mut source,
            &jumped,
            &approved,
            advancement(&summary).approval_id
        ),
        Err(Error::Reserved)
    ));
    assert!(matches!(
        store.prepare_payment(wallet, &mut source, &approved),
        Err(Error::Exhausted)
    ));
    assert_eq!(state(&store, &path), before);
    // No-change payments still work with every change entry retired.
    let mut exact = approved;
    exact.amount = 2_000_000 - 10_400;
    let (_, summary) = store.prepare_payment(wallet, &mut source, &exact).unwrap();
    assert!(summary.local_change.is_none());
    assert_eq!(store.state.payments.change_next, 4);
}
