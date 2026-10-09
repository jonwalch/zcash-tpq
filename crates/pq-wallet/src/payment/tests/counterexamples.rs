//! Coordinator mutations must fail at signing even with a matching proposal ID.
//! Synthetic node histories isolate wallet approval from consensus validation.
use super::*;

fn outputs_mut(tx: &mut Transaction) -> &mut Vec<zakura_chain::transparent::Output> {
    match tx {
        Transaction::V5 { outputs, .. } | Transaction::V6 { outputs, .. } => outputs,
        _ => unreachable!("wallet fixtures use v5/v6"),
    }
}

#[test]
fn signing_independently_rejects_coherent_recipient_amount_and_fee_changes() {
    for version in [5, 6] {
        for participants in [1, 3] {
            let wallets = wallets(participants, 1, 1);
            let wallet = &wallets[0];
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("store");
            let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
            let mut source = Source::funded(wallet, &[2_000_000]);
            let mut approved = intent(version);
            approved.max_fee = 300_000;
            // Permit donations so the fee attack fails solely on the ceiling.
            approved.remainder = Remainder::Fee;
            let (proposal, review) = store
                .prepare_payment(wallet, &mut source, &approved)
                .unwrap();
            let before = fs::read(path.join("state.json")).unwrap();

            for case in ["recipient", "amount", "fee"] {
                let mut changed = proposal.clone();
                let mut tx = proposal.transaction().unwrap();
                let mut authorized = approved.clone();
                match case {
                    "recipient" => {
                        let entry = &wallet.manifest.entries[0];
                        authorized.receiver = entry.receiver().unwrap().encode();
                        changed.outputs[0].receiver = authorized.receiver.clone();
                        outputs_mut(&mut tx)[0].lock_script = entry.policy().unwrap().lock_script();
                    }
                    "amount" => {
                        authorized.amount += 1;
                        outputs_mut(&mut tx)[0].value = authorized.amount.try_into().unwrap();
                        outputs_mut(&mut tx)[1].value =
                            (review.change_value - 1).try_into().unwrap();
                    }
                    "fee" => {
                        authorized.max_fee += 1;
                        outputs_mut(&mut tx)[1].value =
                            (review.input_value - approved.amount - authorized.max_fee)
                                .try_into()
                                .unwrap();
                    }
                    _ => unreachable!(),
                }
                changed.transaction_hex = hex::encode(tx.zcash_serialize_to_vec().unwrap());
                // Canonical metadata agrees with the changed effects. The same
                // proposal passes contextual review with explicitly changed intent.
                let changed = Proposal::from_json(&changed.to_json().unwrap()).unwrap();
                review::check(wallet.manifest(), &mut source, &changed, &authorized, false)
                    .unwrap();
                let id = changed.id().unwrap();
                assert_ne!(id, review.proposal_id);
                let error = store
                    .sign_payment_with_rng(
                        wallet,
                        &mut source,
                        &changed,
                        &approved,
                        id,
                        &mut FailingRng,
                    )
                    .unwrap_err();
                assert!(
                    matches!((case, &error), ("fee", Error::Fee))
                        || matches!(
                            (case, &error),
                            ("recipient" | "amount", Error::ProposalMismatch)
                        ),
                    "v{version}, {participants} participants, {case}: {error:?}"
                );
                assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
            }
            // An honest request still signs after the attacks. Assembly checks
            // the full threshold with the other surviving signer where needed.
            let mut partials = store
                .sign_payment(
                    wallet,
                    &mut source,
                    &proposal,
                    &approved,
                    review.proposal_id,
                )
                .unwrap();
            if participants == 3 {
                let mut other = create(
                    &temp.path().join("cosigner"),
                    wallets[1].manifest(),
                    WatchMode::Allocator,
                );
                partials.extend(
                    other
                        .sign_payment(
                            &wallets[1],
                            &mut source,
                            &proposal,
                            &approved,
                            review.proposal_id,
                        )
                        .unwrap(),
                );
            }
            store
                .assemble_payment(wallet, &mut source, &proposal, &approved, &partials)
                .unwrap();
        }
    }
}

pub(super) fn change_entry(wallets: &[&Wallet], index: u32) -> Entry {
    let mut keys: Vec<_> = wallets
        .iter()
        .map(|w| {
            (
                w.key(KeyPath {
                    role: Role::Change,
                    index,
                })
                .commitment(),
                Origin {
                    account: 0,
                    index,
                    wallet_id: w.manifest.wallet_id,
                },
            )
        })
        .collect();
    keys.sort_by_key(|(commitment, _)| *commitment);
    Entry {
        origins: keys.iter().map(|(_, origin)| origin.clone()).collect(),
        policy_hex: hex::encode(
            Policy::new(
                if wallets.len() == 1 { 1 } else { 2 },
                keys.iter().map(|(c, _)| *c).collect(),
            )
            .unwrap()
            .encode(),
        ),
        role: Role::Change as u8,
    }
}

#[test]
fn signing_rejects_enrolled_change_with_weaker_or_different_ownership() {
    for version in [5, 6] {
        let mut wallets = wallets(3, 1, 3);
        let foreign = Wallet::create(profile(), 0).unwrap();
        wallets[0].manifest.entries[2] = change_entry(&[&wallets[0]], 1);
        wallets[0].manifest.entries[3] = change_entry(&[&wallets[0], &wallets[1], &foreign], 2);
        let wallet = &wallets[0];
        wallet.manifest.validate().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("store");
        let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
        let mut source = Source::funded(wallet, &[2_000_000]);
        let approved = intent(version);
        let (proposal, review) = store
            .prepare_payment(wallet, &mut source, &approved)
            .unwrap();
        let before = fs::read(path.join("state.json")).unwrap();
        for entry in &wallet.manifest.entries[2..] {
            let mut changed = proposal.clone();
            let mut tx = proposal.transaction().unwrap();
            outputs_mut(&mut tx)[1].lock_script = entry.policy().unwrap().lock_script();
            changed.outputs[1].entry = Some(entry.clone());
            changed.outputs[1].receiver = entry.receiver().unwrap().encode();
            changed.transaction_hex = hex::encode(tx.zcash_serialize_to_vec().unwrap());
            let changed = Proposal::from_json(&changed.to_json().unwrap()).unwrap();
            // Both policies are enrolled and contain the correct local key.
            // Only their threshold/participant group differs from the inputs.
            review::enrolled(wallet.manifest(), entry).unwrap();
            let error = store
                .sign_payment_with_rng(
                    wallet,
                    &mut source,
                    &changed,
                    &approved,
                    changed.id().unwrap(),
                    &mut FailingRng,
                )
                .unwrap_err();
            assert!(matches!(error, Error::Policy), "{error:?}");
            assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
        }
        let mut partials = store
            .sign_payment(
                wallet,
                &mut source,
                &proposal,
                &approved,
                review.proposal_id,
            )
            .unwrap();
        let mut other = create(
            &temp.path().join("cosigner"),
            wallets[1].manifest(),
            WatchMode::Allocator,
        );
        partials.extend(
            other
                .sign_payment(
                    &wallets[1],
                    &mut source,
                    &proposal,
                    &approved,
                    review.proposal_id,
                )
                .unwrap(),
        );
        store
            .assemble_payment(wallet, &mut source, &proposal, &approved, &partials)
            .unwrap();
    }
}

#[test]
fn recovered_cosigners_reject_retired_change_and_keep_the_original_threshold() {
    for version in [5, 6] {
        let mut wallets = wallets(3, 1, 1);
        let temp = tempfile::tempdir().unwrap();
        let mut original = create(
            &temp.path().join("original"),
            wallets[0].manifest(),
            WatchMode::Allocator,
        );
        let mut source = Source::funded(&wallets[0], &[2_000_000]);
        let approved = intent(version);
        let (old, old_review) = original
            .prepare_payment(&wallets[0], &mut source, &approved)
            .unwrap();
        // No authorization was released and no node input has been spent.
        // Start at authenticated plaintext (backup decryption has separate
        // controls). Restore only the two survivors; the third root is dropped.
        drop(original);
        wallets.truncate(2);
        let restored: Vec<_> = wallets
            .into_iter()
            .map(|wallet| {
                let mut restored =
                    Wallet::from_plaintext(&wallet.plaintext().unwrap(), &profile()).unwrap();
                restored.retire_for_restore().unwrap();
                assert_eq!(restored.manifest.entries, wallet.manifest.entries);
                restored
            })
            .collect();
        let mut stores = Vec::new();
        for (i, wallet) in restored.iter().enumerate() {
            let path = temp.path().join(format!("restored-{i}"));
            let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
            store.sync(&mut source, 10).unwrap();
            // Inputs, signatures-to-be, fees and ancestry are all still valid;
            // the recovered allocation state alone rules out the old change.
            review::check(wallet.manifest(), &mut source, &old, &approved, false).unwrap();
            let before = fs::read(path.join("state.json")).unwrap();
            assert!(matches!(
                store.sign_payment_with_rng(
                    wallet,
                    &mut source,
                    &old,
                    &approved,
                    old_review.proposal_id,
                    &mut FailingRng,
                ),
                Err(Error::Reserved)
            ));
            assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
            stores.push(store);
        }
        let mut exact = approved;
        exact.amount = old_review.input_value - old_review.conventional_fee;
        let (proposal, review) = stores[0]
            .prepare_payment(&restored[0], &mut source, &exact)
            .unwrap();
        assert_eq!(proposal.outputs.len(), 1);
        assert_eq!(review.change_value, 0);
        assert_eq!(review.checks, 2);
        let mut partials = Vec::new();
        for (wallet, store) in restored.iter().zip(&mut stores) {
            partials.extend(
                store
                    .sign_payment(wallet, &mut source, &proposal, &exact, review.proposal_id)
                    .unwrap(),
            );
        }
        assert_eq!(partials.len(), 2);
        assert_ne!(partials[0].signer_index, partials[1].signer_index);
        assert!(matches!(
            stores[0].assemble_payment(
                &restored[0],
                &mut source,
                &proposal,
                &exact,
                &partials[..1]
            ),
            Err(Error::ProposalMismatch)
        ));
        stores[0]
            .assemble_payment(&restored[0], &mut source, &proposal, &exact, &partials)
            .unwrap();
    }
}
