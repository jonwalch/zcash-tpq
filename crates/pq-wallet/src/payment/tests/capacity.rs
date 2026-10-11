//! Wallet bounds with synthetic trusted history and real PQ authorization.
//! One full-capacity fixture; no live nodes, profiling or retained artifacts.
use super::*;
use crate::{scan::MAX_COINS, Manifest};
use serde_json::Value;
use std::path::Path;

const USABLE: u64 = 2_000_000;
const PASSWORD: &[u8] = b"public-capacity-test-password";

fn state(store: &WatchStore, path: &Path) -> Value {
    let memory = serde_json::to_value(&store.state).unwrap();
    let durable: Value =
        serde_json::from_slice(&fs::read(path.join("state.json")).unwrap()).unwrap();
    assert_eq!(memory, durable);
    memory
}

fn reopen(store: WatchStore, path: &Path, expected: &Value) -> WatchStore {
    assert_eq!(&state(&store, path), expected);
    drop(store);
    let store = WatchStore::open(path, &profile()).unwrap();
    assert_eq!(&state(&store, path), expected);
    store
}

fn exhausted(
    store: &mut WatchStore,
    wallet: &Wallet,
    source: &mut Source,
    approved: &Intent,
    path: &Path,
) {
    let before = state(store, path);
    assert!(matches!(
        store.prepare_payment(wallet, source, approved),
        Err(Error::Exhausted)
    ));
    assert_eq!(state(store, path), before);
    assert!(source.sent.is_empty());
}

fn authorize(
    owners: &[Wallet],
    stores: &mut [WatchStore],
    source: &mut Source,
    proposal: &Proposal,
    approved: &Intent,
    summary: &Review,
) -> Vec<u8> {
    let mut partials = Vec::new();
    for (owner, store) in owners.iter().zip(stores.iter_mut()) {
        assert_eq!(
            store
                .review_payment(owner, source, proposal, approved)
                .unwrap(),
            *summary
        );
        partials.extend(
            store
                .sign_payment(owner, source, proposal, approved, summary.proposal_id)
                .unwrap(),
        );
    }
    assert_eq!(partials.len(), summary.checks as usize);
    if owners.len() == 2 {
        assert!(matches!(
            stores[0].assemble_payment(&owners[0], source, proposal, approved, &partials[..1]),
            Err(Error::ProposalMismatch)
        ));
    }
    let signed = stores[0]
        .assemble_payment(&owners[0], source, proposal, approved, &partials)
        .unwrap();
    assert_eq!(signed.len(), summary.final_bytes);
    signed
}

#[test]
fn coin_capacity_preserves_authorization_and_recovers_only_after_history_fits() {
    let _serial = crate::tests::BACKUPS.lock().unwrap();
    let owners = wallets(1, 1, 2);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let backup = temp.path().join("original.tpq");
    wallet.save_backup(&backup, PASSWORD).unwrap();
    let backup_bytes = fs::read(&backup).unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    store.receive().unwrap();

    // Repeat one covered script, not thousands of derived keys. There is only
    // one economical input; the tiny receipts stay in the inventory.
    let mut values = vec![DUST; MAX_COINS - 1];
    *values.last_mut().unwrap() = USABLE;
    let mut source = Source::funded(wallet, &values);
    source.journal = Some(path.join("state.json"));
    assert!(store.sync(&mut source, 10).unwrap().complete_at_checkpoint);
    assert_eq!(store.coins().len(), MAX_COINS - 1);
    let funding = source.chain.blocks[3].transactions[1].clone();
    let tiny = proposal::point(OutPoint {
        hash: funding.hash(),
        index: 0,
    });
    let usable = store
        .coins()
        .iter()
        .find(|c| c.value == USABLE)
        .unwrap()
        .outpoint;
    source.chain.push(
        vec![transaction(
            6,
            1,
            vec![],
            vec![output(&wallet.manifest.entries[0], DUST)],
        )],
        None,
    );
    assert!(store.sync(&mut source, 10).unwrap().complete_at_checkpoint);
    assert_eq!(store.coins().len(), MAX_COINS);

    let approved = intent(6);
    let (proposal, summary) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    assert_eq!(proposal.points().unwrap(), [usable]);
    assert_eq!(summary.fee, 21_600);
    let signed = authorize(
        &owners,
        std::slice::from_mut(&mut store),
        &mut source,
        &proposal,
        &approved,
        &summary,
    );
    assert_eq!(store.state.payments.change_next, 1);
    let before = state(&store, &path);
    let checkpoint = store.status().unwrap().checkpoint;
    let mut incomplete = before.clone();
    incomplete["scan"]["complete"] = false.into();
    incomplete["scan"]["context"] = Value::Null;

    // The rejected block would remove an old coin, add another at the limit,
    // and consume the final change coordinate before its last output overflows.
    // None of those earlier effects may escape a failed block application.
    source.chain.push(
        vec![transaction(
            6,
            2,
            vec![OutPoint {
                hash: funding.hash(),
                index: 0,
            }],
            vec![
                output(&wallet.manifest.entries[2], DUST),
                output(&wallet.manifest.entries[0], DUST),
            ],
        )],
        None,
    );
    assert!(
        source
            .chain
            .blocks
            .last()
            .unwrap()
            .zcash_serialize_to_vec()
            .unwrap()
            .len()
            < zakura_chain::block::MAX_BLOCK_BYTES as usize
    );
    assert!(fs::metadata(path.join("state.json")).unwrap().len() < 32 * 1024 * 1024);
    assert!(matches!(store.sync(&mut source, 10), Err(Error::Limits)));
    assert_eq!(state(&store, &path), incomplete);
    let status = store.status().unwrap();
    assert_eq!(status.checkpoint, checkpoint);
    assert!(!status.complete_at_checkpoint);
    assert_eq!(status.confirmed_zatoshis, None);
    assert_eq!(status.immature_coinbase_zatoshis, None);
    assert_eq!(status.pq_active_for_next_block, None);
    assert!(status.observed_zatoshis > 0);
    store = reopen(store, &path, &incomplete);
    assert!(matches!(
        store.prepare_payment(wallet, &mut source, &approved),
        Err(Error::Limits)
    ));
    assert!(matches!(
        store.sign_payment_with_rng(
            wallet,
            &mut source,
            &proposal,
            &approved,
            summary.proposal_id,
            &mut FailingRng
        ),
        Err(Error::Limits)
    ));
    assert!(matches!(
        store.submit_payment(wallet, &mut source, summary.proposal_id),
        Err(Error::Limits)
    ));
    store = reopen(store, &path, &incomplete);
    assert!(source.sent.is_empty());
    assert_eq!(fs::read(&backup).unwrap(), backup_bytes);

    // Restore authentic encrypted inventory, but create only a monitor: the
    // original journal still owns an outstanding signed capability. Restoring
    // inventory does not recover that journal or solve overflowing history.
    let mut restored = Wallet::load_backup(&backup, PASSWORD, &profile()).unwrap();
    restored.retire_for_restore().unwrap();
    let recovered_path = temp.path().join("restored-monitor");
    let mut recovered = create(&recovered_path, restored.manifest(), WatchMode::Monitor);
    assert!(matches!(
        recovered.sync(&mut source, 10),
        Err(Error::Limits)
    ));
    assert_eq!(recovered.coins(), store.coins());
    assert_eq!(recovered.status().unwrap().checkpoint, checkpoint);
    assert!(!recovered.status().unwrap().complete_at_checkpoint);
    let recovered_state = state(&recovered, &recovered_path);
    drop(reopen(recovered, &recovered_path, &recovered_state));

    source.chain.blocks.pop();
    source.mine(); // A replacement block removes the overflow, not tracked coins.
    assert!(store.sync(&mut source, 10).unwrap().complete_at_checkpoint);
    assert_eq!(store.coins().len(), MAX_COINS);
    assert!(store.coins().iter().any(|c| c.outpoint == tiny));
    assert_eq!(store.state.payments.change_next, 1);
    let (refreshed, review) = store
        .preview_payment_refresh(wallet, &mut source, summary.proposal_id)
        .unwrap();
    store
        .approve_payment_refresh(
            wallet,
            &mut source,
            summary.proposal_id,
            &refreshed,
            review.proposal_id,
        )
        .unwrap();
    let partials = store
        .sign_payment_with_rng(
            wallet,
            &mut source,
            &refreshed,
            &approved,
            review.proposal_id,
            &mut FailingRng,
        )
        .unwrap();
    assert_eq!(
        store
            .assemble_payment(wallet, &mut source, &refreshed, &approved, &partials)
            .unwrap(),
        signed
    );
    store
        .submit_payment(wallet, &mut source, review.proposal_id)
        .unwrap();
    assert_eq!(source.sent, [signed]);
    source.mine();
    assert_eq!(
        store.reconcile_payments(&mut source).unwrap(),
        [PaymentState::Confirmed]
    );
    assert!(store.sync(&mut source, 10).unwrap().complete_at_checkpoint);
    assert_eq!(store.coins().len(), MAX_COINS);
    assert!(!store.coins().iter().any(|c| c.outpoint == usable));
    assert!(store.coins().iter().any(|c| c.outpoint == tiny));
    assert_eq!(fs::read(&backup).unwrap(), backup_bytes);
}

#[test]
fn last_change_receipts_exhaust_normal_and_restored_wallets_after_reorg() {
    for version in [5, 6] {
        for n in [1, 3] {
            for restored in [false, true] {
                let mut owners = wallets(n, 1, 2);
                owners.truncate(2); // A 2-of-3 payment has only the surviving pair.
                if restored {
                    owners = owners
                        .into_iter()
                        .map(|wallet| {
                            let mut recovered =
                                Wallet::from_plaintext(&wallet.plaintext().unwrap(), &profile())
                                    .unwrap();
                            recovered.retire_for_restore().unwrap();
                            recovered
                        })
                        .collect();
                }
                let wallet = &owners[0];
                let inventory = wallet.plaintext().unwrap();
                let temp = tempfile::tempdir().unwrap();
                let path = temp.path().join("watch");
                let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
                let mut source = Source::funded(wallet, &[USABLE]);
                let approved = intent(version);
                source.chain.push(
                    vec![transaction(
                        version,
                        9,
                        vec![],
                        vec![output(&wallet.manifest.entries[2], DUST)],
                    )],
                    None,
                );
                assert!(store.sync(&mut source, 10).unwrap().complete_at_checkpoint);
                assert_eq!(store.state.payments.change_next, 2);
                assert_eq!(store.coins().len(), 2);
                exhausted(&mut store, wallet, &mut source, &approved, &path);
                let before = state(&store, &path);
                store = reopen(store, &path, &before);

                source.chain.blocks.pop();
                assert!(store.sync(&mut source, 10).unwrap().complete_at_checkpoint);
                assert_eq!(store.coins().len(), 1);
                assert_eq!(store.state.payments.change_next, 2);
                exhausted(&mut store, wallet, &mut source, &approved, &path);
                let before = state(&store, &path);
                store = reopen(store, &path, &before);
                assert_eq!(wallet.plaintext().unwrap(), inventory);

                let fee = if n == 1 { 21_600 } else { 42_800 };
                let mut exact = approved;
                exact.amount = USABLE - fee; // Independently approve an exact payment.
                let (proposal, summary) =
                    store.prepare_payment(wallet, &mut source, &exact).unwrap();
                assert_eq!(proposal.outputs.len(), 1);
                assert_eq!((summary.change_value, summary.fee), (0, fee));
                assert_eq!(summary.checks, if n == 1 { 1 } else { 2 });
                let mut stores = vec![store];
                for (i, owner) in owners.iter().enumerate().skip(1) {
                    stores.push(create(
                        &temp.path().join(i.to_string()),
                        owner.manifest(),
                        WatchMode::Allocator,
                    ));
                }
                let signed = authorize(
                    &owners,
                    &mut stores,
                    &mut source,
                    &proposal,
                    &exact,
                    &summary,
                );
                stores[0]
                    .submit_payment(wallet, &mut source, summary.proposal_id)
                    .unwrap();
                assert_eq!(source.sent, [signed]);
                source.mine();
                assert_eq!(
                    stores[0].reconcile_payments(&mut source).unwrap(),
                    [PaymentState::Confirmed]
                );
                let status = stores[0].sync(&mut source, 10).unwrap();
                assert_eq!(status.confirmed_zatoshis, Some(0));
                assert!(stores[0].coins().is_empty());
                assert_eq!(stores[0].state.payments.change_next, 2);
            }
        }
    }
}

#[test]
fn exhausted_change_requires_successfully_backed_up_extension() {
    let _serial = crate::tests::BACKUPS.lock().unwrap();
    for n in [1, 3] {
        let mut owners = wallets(n, 1, 1);
        if n == 1 {
            // A restored single signer can derive fresh change. For multisig,
            // all three owners supply and back up the new public coordinates.
            owners[0].retire_for_restore().unwrap();
        }
        let temp = tempfile::tempdir().unwrap();
        let backups: Vec<_> = owners
            .iter()
            .enumerate()
            .map(|(i, owner)| {
                let path = temp.path().join(format!("old-{i}.tpq"));
                owner.save_backup(&path, PASSWORD).unwrap();
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        let path = temp.path().join("watch");
        let mut store = create(&path, owners[0].manifest(), WatchMode::Allocator);
        if n == 3 {
            store.receive().unwrap();
        }
        let mut source = Source::funded(&owners[0], &[USABLE]);
        source.chain.push(
            vec![transaction(
                6,
                9,
                vec![],
                vec![output(&owners[0].manifest.entries[1], DUST)],
            )],
            None,
        );
        assert!(store.sync(&mut source, 10).unwrap().complete_at_checkpoint);
        let approved = intent(6);
        exhausted(&mut store, &owners[0], &mut source, &approved, &path);
        let before = state(&store, &path);
        let old = owners[0].plaintext().unwrap();
        let entry = counterexamples::change_entry(&owners.iter().collect::<Vec<_>>(), 1);
        let candidates: Vec<Manifest> = owners
            .iter()
            .map(|owner| {
                let mut manifest = owner.manifest().clone();
                manifest.entries.push(entry.clone());
                manifest.change_end += 1;
                manifest.revision += 1;
                manifest.validate().unwrap();
                manifest
            })
            .collect();
        let approved_fingerprints: Vec<_> = candidates
            .iter()
            .map(|m| m.fingerprint().unwrap())
            .collect();

        // Real no-clobber failure through the extension/enrollment API. Detailed
        // write/sync/rename failure stages remain covered by the backup tests.
        let failed = if n == 1 {
            owners[0].extend_single_backup(0, 1, &backups[0].0, PASSWORD)
        } else {
            owners[0].enroll_backup(
                candidates[0].clone(),
                approved_fingerprints[0],
                &backups[0].0,
                PASSWORD,
            )
        };
        assert!(
            matches!(failed, Err(Error::Storage(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
        );
        assert_eq!(owners[0].plaintext().unwrap(), old);
        assert_eq!(state(&store, &path), before);
        store = reopen(store, &path, &before);
        exhausted(&mut store, &owners[0], &mut source, &approved, &path);

        for (i, owner) in owners.iter_mut().enumerate() {
            let next = temp.path().join(format!("new-{i}.tpq"));
            if n == 1 {
                owner.extend_single_backup(0, 1, &next, PASSWORD).unwrap();
            } else {
                owner
                    .enroll_backup(
                        candidates[i].clone(),
                        approved_fingerprints[i],
                        &next,
                        PASSWORD,
                    )
                    .unwrap();
            }
            assert_eq!(owner.manifest(), &candidates[i]);
            assert_eq!(
                Wallet::load_backup(&next, PASSWORD, &profile())
                    .unwrap()
                    .manifest(),
                owner.manifest()
            );
            assert_eq!(fs::read(&backups[i].0).unwrap(), backups[i].1);
        }
        store
            .import(
                &owners[0].manifest().to_json().unwrap(),
                approved_fingerprints[0],
            )
            .unwrap();
        assert!(!store.status().unwrap().complete_at_checkpoint);
        assert_eq!(store.receive_next(), 1);
        assert_eq!(store.state.payments.change_next, 1);
        assert!(store.sync(&mut source, 10).unwrap().complete_at_checkpoint);
        let (proposal, summary) = store
            .prepare_payment(&owners[0], &mut source, &approved)
            .unwrap();
        assert_eq!(proposal.outputs[1].entry.as_ref(), Some(&entry));
        assert_eq!(summary.fee, if n == 1 { 21_600 } else { 42_800 });
        assert_eq!(summary.change_value, USABLE - approved.amount - summary.fee);
        let before = state(&store, &path);
        store = reopen(store, &path, &before);
        owners.truncate(2);
        let mut stores = vec![store];
        for (i, owner) in owners.iter().enumerate().skip(1) {
            stores.push(create(
                &temp.path().join(i.to_string()),
                owner.manifest(),
                WatchMode::Allocator,
            ));
        }
        let signed = authorize(
            &owners,
            &mut stores,
            &mut source,
            &proposal,
            &approved,
            &summary,
        );
        stores[0]
            .submit_payment(&owners[0], &mut source, summary.proposal_id)
            .unwrap();
        assert_eq!(source.sent, [signed]);
        source.mine();
        assert!(
            stores[0]
                .sync(&mut source, 10)
                .unwrap()
                .complete_at_checkpoint
        );
        assert!(stores[0]
            .coins()
            .iter()
            .any(|c| c.role == 1 && c.index == 1 && c.value == summary.change_value));
        assert_eq!(stores[0].state.payments.change_next, 2);
        for (path, bytes) in backups {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
}
