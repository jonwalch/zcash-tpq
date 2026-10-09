//! Compare actual product serialization with independent frozen W0 answers.
use super::*;
use zakura_chain::transparent::{Output, Script};

#[test]
fn all_120_policy_shapes_have_exact_sizes_and_current_fees() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
    ))
    .unwrap();
    for row in corpus["policies"].as_array().unwrap() {
        let entry = Entry {
            origins: (0..row["participants"].as_u64().unwrap())
                .map(|i| Origin {
                    account: 0,
                    index: 0,
                    // The independent corpus has at most fifteen participants.
                    wallet_id: Hex([u8::try_from(i + 1).unwrap(); 16]),
                })
                .collect(),
            policy_hex: row["policy_hex"].as_str().unwrap().into(),
            role: 0,
        };
        let authorization = row["authorization_bytes"].as_u64().unwrap() as usize;
        assert_eq!(
            entry.suite_policy().unwrap().authorization_size(),
            authorization
        );
        for version in [5, 6] {
            let input = Input::PrevOut {
                outpoint: OutPoint {
                    hash: zakura_chain::transaction::Hash([1; 32]),
                    index: 0,
                },
                unlock_script: Script::new(&[]),
                sequence: u32::MAX,
            };
            let output = Output {
                value: 1_000_000u64.try_into().unwrap(),
                lock_script: entry.suite_policy().unwrap().lock_script(),
            };
            let tx = review::transaction(version, vec![input.clone()], vec![output.clone(); 2], 20)
                .unwrap();
            let (bytes, fee) = review::estimate(&tx, &[&entry]).unwrap();
            let input_bytes = 40 + if authorization <= 65_535 { 3 } else { 5 } + authorization;
            assert_eq!(bytes, input_bytes + if version == 5 { 113 } else { 114 });
            assert_eq!(fee, (input_bytes as u64).div_ceil(150) * 400);
            if row["threshold"] == 15 && row["participants"] == 15 {
                assert_eq!(bytes, if version == 5 { 119_040 } else { 119_041 });
                let oversized =
                    review::transaction(version, vec![input; 3], vec![output; 2], 20).unwrap();
                assert!(matches!(
                    review::estimate(&oversized, &[&entry; 3]),
                    Err(Error::Limits)
                ));
            }
        }
    }
    let raw = corpus["partial_json"].as_str().unwrap().as_bytes();
    assert_eq!(raw.len(), 16_001);
    assert_eq!(Partial::from_json(raw).unwrap().to_json().unwrap(), raw);
    for slot in [15, u8::MAX] {
        let mut partial = Partial::from_json(raw).unwrap();
        partial.signer_index = slot;
        assert!(matches!(partial.to_json(), Err(Error::ProposalMismatch)));
    }
}

#[test]
fn recipient_dust_floor_is_2403_independent_of_signature_cost() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
    ))
    .unwrap();
    let receiver = corpus["policies"][0]["receiver"].as_str().unwrap();
    for amount in [2_402, 2_403, 2_404] {
        let intent = Intent {
            amount,
            max_fee: 100_000,
            receiver: receiver.into(),
            receiver_activation_height: None,
            remainder: Remainder::Keep,
            version: Some(6),
        };
        assert_eq!(intent.to_json().is_ok(), amount >= 2_403);
    }
}

#[test]
fn trusted_payment_review_accepts_all_120_enrolled_shapes_for_both_versions() {
    let mut owners = wallets(1, 1, 1);
    let wallet = &mut owners[0];
    let own = [
        wallet
            .key_commitment(KeyPath {
                role: Role::Receive,
                index: 0,
            })
            .unwrap(),
        wallet
            .key_commitment(KeyPath {
                role: Role::Change,
                index: 0,
            })
            .unwrap(),
    ];
    let recipient = intent(6).receiver;
    let temporary = tempfile::tempdir().unwrap();
    for n in 1..=15u8 {
        for m in 1..=n {
            wallet.manifest.entries = (0..2u8)
                .map(|role| {
                    let mut commitments = vec![(
                        own[usize::from(role)],
                        Origin {
                            account: 0,
                            index: 0,
                            wallet_id: wallet.manifest.wallet_id,
                        },
                    )];
                    for participant in 1..n {
                        let mut wallet_id = wallet.manifest.wallet_id;
                        wallet_id.0[0] ^= participant;
                        let mut commitment = [participant; 32];
                        commitment[31] = role;
                        commitments.push((
                            commitment,
                            Origin {
                                account: 0,
                                index: 0,
                                wallet_id,
                            },
                        ));
                    }
                    commitments.sort_by_key(|(commitment, _)| *commitment);
                    Entry {
                        origins: commitments
                            .iter()
                            .map(|(_, origin)| origin.clone())
                            .collect(),
                        policy_hex: hex::encode(
                            Policy::new(m, commitments.iter().map(|(key, _)| *key).collect())
                                .unwrap()
                                .descriptor(),
                        ),
                        role,
                    }
                })
                .collect();
            wallet.manifest.validate().unwrap();
            for version in [5, 6] {
                let mut store = create(
                    &temporary.path().join(format!("{m}-{n}-{version}")),
                    wallet.manifest(),
                    WatchMode::Allocator,
                );
                let mut source = Source::funded(wallet, &[2_000_000]);
                let approved = Intent {
                    amount: 500_000,
                    max_fee: 1_000_000,
                    receiver: recipient.clone(),
                    receiver_activation_height: None,
                    remainder: Remainder::Keep,
                    version: Some(version),
                };
                let (proposal, reviewed) = store
                    .prepare_payment(wallet, &mut source, &approved)
                    .unwrap();
                assert_eq!(reviewed.checks, u32::from(m));
                assert_eq!(
                    reviewed,
                    store
                        .review_payment(wallet, &mut source, &proposal, &approved)
                        .unwrap()
                );
                assert!(reviewed.final_bytes <= MAX_TRANSACTION);
                assert_eq!(proposal.inputs[0].entry.origins.len(), usize::from(n));
                assert_eq!(
                    proposal.outputs[1].entry.as_ref().unwrap().origins.len(),
                    usize::from(n)
                );
            }
        }
    }
}

#[test]
fn real_fifteen_of_fifteen_authorization_survives_journal_reopen() {
    let mut owners = wallets(15, 1, 1);
    let mut entries = owners[0].manifest.entries.clone();
    for entry in &mut entries {
        let commitments = entry.policy().unwrap().commitments().to_vec();
        entry.policy_hex = hex::encode(Policy::new(15, commitments).unwrap().descriptor());
    }
    for owner in &mut owners {
        owner.manifest.entries = entries.clone();
        owner.manifest.validate().unwrap();
    }
    let temporary = tempfile::tempdir().unwrap();
    let paths: Vec<_> = (0..15)
        .map(|i| temporary.path().join(i.to_string()))
        .collect();
    let mut stores: Vec<_> = owners
        .iter()
        .zip(&paths)
        .map(|(wallet, path)| create(path, wallet.manifest(), WatchMode::Allocator))
        .collect();
    let mut source = Source::funded(&owners[0], &[2_000_000]);
    let approved = intent(6);
    let (proposal, summary) = stores[0]
        .prepare_payment(&owners[0], &mut source, &approved)
        .unwrap();
    assert_eq!(summary.checks, 15);
    assert_eq!(summary.final_bytes, 119_041);
    stores[0].migrate_payment_journal().unwrap();
    let mut partials = Vec::new();
    for (store, owner) in stores.iter_mut().zip(&owners) {
        partials.extend(
            store
                .sign_payment(
                    owner,
                    &mut source,
                    &proposal,
                    &approved,
                    summary.proposal_id,
                )
                .unwrap(),
        );
    }
    assert_eq!(partials.len(), 15);
    assert!(partials.iter().any(|partial| partial.signer_index == 14));
    let signed = stores[0]
        .assemble_payment(&owners[0], &mut source, &proposal, &approved, &partials)
        .unwrap();
    assert_eq!(signed.len(), 119_041);
    let transaction = proposal::decode_transaction(&signed).unwrap();
    let Input::PrevOut { unlock_script, .. } = &transaction.inputs()[0] else {
        unreachable!()
    };
    assert_eq!(unlock_script.as_raw_bytes().len(), 118_882);
    let local = stores[0].payments().unwrap()[0].partials.clone();
    assert_eq!(local.len(), 1);
    drop(stores.remove(0));
    let mut store = WatchStore::open(&paths[0], &profile()).unwrap();
    assert_eq!(store.payments().unwrap()[0].partials, local);
    assert_eq!(
        store.payments().unwrap()[0].signed_transaction_hex,
        Some(hex::encode(&signed))
    );
    assert!(
        store
            .journal_snapshot()
            .unwrap()
            .metadata()
            .reachable_objects
            > 0
    );
    assert_eq!(
        store
            .sign_payment(
                &owners[0],
                &mut source,
                &proposal,
                &approved,
                summary.proposal_id
            )
            .unwrap(),
        local
    );
}
