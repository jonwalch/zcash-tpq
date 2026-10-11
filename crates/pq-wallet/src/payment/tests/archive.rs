//! Bounded synthetic chain and filesystem regressions; no live node or profiling.
use super::*;
use crate::{
    journal::{ReadBudget, Stage},
    watch::StateStage,
};
use serde_json::{json, Value};
use std::path::Path;

fn parse<T: serde::de::DeserializeOwned>(value: &Value) -> T {
    serde_json::from_slice(&serde_json::to_vec(value).unwrap()).unwrap()
}

pub(super) fn durable_records(path: &Path) -> Vec<Value> {
    let state: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    if let Some(records) = state["payments"]["records"].as_array() {
        return records.clone();
    }
    let manifest = parse(&state["manifest"]);
    let journal_id = parse(&state["payments"]["journal"]["journal_id"]);
    state["payments"]["active"]
        .as_array()
        .unwrap()
        .iter()
        .map(|active| {
            let hash = active["capability"].as_str().unwrap();
            let bytes =
                fs::read(path.parent().unwrap().join("journal/objects").join(hash)).unwrap();
            use sha2::{Digest, Sha256};
            let mut digest = Sha256::new();
            digest.update(b"ZcashTransparentPQ/wallet-journal-object/v1\0");
            digest.update(&bytes);
            assert_eq!(hex::encode(digest.finalize()), hash);
            let cap = crate::journal::Capability::decode(
                &bytes,
                journal_id,
                &manifest,
                state["payments"]["change_next"].as_u64().unwrap(),
            )
            .unwrap();
            assert_eq!(
                serde_json::to_value(cap.lineage_id).unwrap(),
                active["lineage_id"]
            );
            serde_json::to_value(
                cap.record(serde_json::from_value(active["state"].clone()).unwrap()),
            )
            .unwrap()
        })
        .collect()
}
fn disk(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path.join("state.json")).unwrap()).unwrap()
}
fn snapshot(path: &Path) -> Value {
    let mut value = disk(path)["payments"].clone();
    value["journal"]
        .as_object_mut()
        .unwrap()
        .remove("generation");
    value
}
pub(super) fn exact(wallet: &Wallet, version: u8) -> (Intent, u64) {
    let approved = intent(version);
    let tx = review::transaction(
        version,
        vec![Input::PrevOut {
            outpoint: OutPoint {
                hash: zakura_chain::transaction::Hash([1; 32]),
                index: 0,
            },
            unlock_script: zakura_chain::transparent::Script::new(&[]),
            sequence: u32::MAX,
        }],
        vec![zakura_chain::transparent::Output {
            value: approved.amount.try_into().unwrap(),
            lock_script: zakura_chain::transparent::Script::new(
                &crate::Receiver::parse(&approved.receiver).unwrap().script(),
            ),
        }],
        23,
    )
    .unwrap();
    let fee = review::estimate(&tx, &[&wallet.manifest.entries[0]])
        .unwrap()
        .1;
    let value = approved.amount + fee;
    (approved, value)
}
fn budget() -> ReadBudget {
    ReadBudget::new(4096).unwrap()
}
fn recovery_copy(path: &Path, original: &[u8]) -> bool {
    fs::read_dir(path).unwrap().filter_map(Result::ok).any(|p| {
        p.file_name().to_string_lossy().starts_with("state-pre-v3-")
            && fs::read(p.path()).unwrap() == original
    })
}
fn reopen(store: WatchStore, path: &Path) -> WatchStore {
    drop(store);
    WatchStore::open(path, &profile()).unwrap()
}

#[test]
fn forty_completed_payments_per_version_and_threshold_cross_capacity_and_resume() {
    for version in [5, 6] {
        for participants in [1, 3] {
            let owners = wallets(participants, 1, 0);
            let wallet = &owners[0];
            let temp = tempfile::tempdir().unwrap();
            let paths: Vec<_> = (0..participants)
                .map(|i| temp.path().join(format!("watch-{i}")))
                .collect();
            let mut stores: Vec<_> = owners
                .iter()
                .zip(&paths)
                .map(|(w, p)| create(p, w.manifest(), WatchMode::Allocator))
                .collect();
            let (approved, value) = exact(wallet, version);
            let mut source = Source::funded(wallet, &[value; 40]);
            source.journal = Some(paths[0].join("state.json"));
            let mut saved = Vec::new();
            for i in 0..40 {
                let (proposal, summary) = stores[0]
                    .prepare_payment(wallet, &mut source, &approved)
                    .unwrap();
                let mut partials = stores[0]
                    .sign_payment(
                        wallet,
                        &mut source,
                        &proposal,
                        &approved,
                        summary.proposal_id,
                    )
                    .unwrap();
                if participants > 1 {
                    partials.extend(
                        stores[1]
                            .sign_payment(
                                &owners[1],
                                &mut source,
                                &proposal,
                                &approved,
                                summary.proposal_id,
                            )
                            .unwrap(),
                    );
                }
                let signed = stores[0]
                    .assemble_payment(wallet, &mut source, &proposal, &approved, &partials)
                    .unwrap();
                stores[0]
                    .submit_payment(wallet, &mut source, summary.proposal_id)
                    .unwrap();
                source.mine();
                saved.push((
                    proposal,
                    signed,
                    stores[0]
                        .payments()
                        .unwrap()
                        .last()
                        .unwrap()
                        .partials
                        .clone(),
                ));
                assert_eq!(stores[0].payments().unwrap().len(), (i + 1).min(32));
                if i == 32 || i == 39 {
                    let store = stores.remove(0);
                    stores.insert(0, reopen(store, &paths[0]));
                }
            }
            let (proposal, signed, partials) = saved
                .into_iter()
                .find(|(proposal, _, _)| {
                    !stores[0]
                        .payments()
                        .unwrap()
                        .iter()
                        .any(|record| record.proposal == *proposal)
                })
                .unwrap();
            let id = proposal.id().unwrap();
            let found = stores[0]
                .resolve_payment(id, &mut budget())
                .unwrap()
                .unwrap();
            assert_eq!(found.location, crate::journal::Location::Archived);
            assert_eq!(
                found.capability.signed_transaction_hex,
                Some(hex::encode(&signed))
            );
            assert_eq!(found.capability.partials, partials);
            assert_eq!(
                disk(&paths[0])["payments"]["journal"]["lineages"]["count"],
                40
            );
            assert_eq!(
                disk(&paths[0])["payments"]["journal"]["reservations"]["count"],
                40
            );
            assert_eq!(disk(&paths[0])["payments"]["journal"]["next_event"], 8);
            stores[0].resume_payment(wallet, &mut source, id).unwrap();
            let resumed = stores[0]
                .payments()
                .unwrap()
                .iter()
                .find(|r| r.proposal.id().unwrap() == id)
                .unwrap();
            assert_eq!(resumed.partials, partials);
            assert_eq!(resumed.signed_transaction_hex, Some(hex::encode(signed)));
            assert_eq!(resumed.state, PaymentState::Confirmed);
            stores[0].archive_payment(wallet, &mut source, id).unwrap();
            assert_eq!(disk(&paths[0])["payments"]["journal"]["next_event"], 10);
            assert_eq!(
                disk(&paths[0])["payments"]["journal"]["reservations"]["count"],
                40
            );
        }
    }
}

#[test]
fn full_active_book_rejects_new_reservation_but_allows_review() {
    let owners = wallets(1, 1, 0);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let (approved, value) = exact(wallet, 6);
    let mut source = Source::funded(wallet, &[value; 33]);
    for _ in 0..32 {
        store
            .prepare_payment(wallet, &mut source, &approved)
            .unwrap();
    }
    let original = fs::read(path.join("state.json")).unwrap();
    store.migrate_payment_journal().unwrap();
    assert_eq!(store.payments().unwrap().len(), 32);
    assert!(fs::read_dir(&path)
        .unwrap()
        .filter_map(Result::ok)
        .any(
            |p| p.file_name().to_string_lossy().starts_with("state-pre-v3-")
                && fs::read(p.path()).unwrap() == original
        ));
    let before = snapshot(&path);
    let (proposal, _) = store
        .preview_payment(wallet, &mut source, &approved)
        .unwrap();
    store
        .review_payment(wallet, &mut source, &proposal, &approved)
        .unwrap();
    assert!(matches!(
        store.prepare_payment(wallet, &mut source, &approved),
        Err(Error::ActivePaymentLimit)
    ));
    assert!(matches!(
        store.sign_payment_with_rng(
            wallet,
            &mut source,
            &proposal,
            &approved,
            proposal.id().unwrap(),
            &mut FailingRng
        ),
        Err(Error::ActivePaymentLimit)
    ));
    assert_eq!(snapshot(&path), before);
    assert!(source.sent.is_empty());
    let store = reopen(store, &path);
    assert_eq!(store.payments().unwrap().len(), 32);
}

#[test]
fn archived_expiry_reorg_revives_both_lineages_beyond_scan_undo() {
    let owners = wallets(1, 1, 2);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let mut source = Source::funded(wallet, &[2_000_000]);
    let approved = intent(6);
    let (old, _) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    let partials = store
        .sign_payment(wallet, &mut source, &old, &approved, old.id().unwrap())
        .unwrap();
    let signed = store
        .assemble_payment(wallet, &mut source, &old, &approved, &partials)
        .unwrap();
    while source.chain.blocks.len() < 25 {
        source.mine();
    }
    store
        .archive_payment(wallet, &mut source, old.id().unwrap())
        .unwrap();
    assert!(store.payments().unwrap().is_empty());
    let (new, _) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    let point = old.points().unwrap()[0];
    assert_eq!(new.points().unwrap(), old.points().unwrap());
    let reservations = disk(&path)["payments"]["journal"]["reservations"].clone();
    while source.chain.blocks.len() < 155 {
        source.mine();
    }
    store.sync(&mut source, 1000).unwrap();
    store = reopen(store, &path);
    source.chain.blocks.truncate(4);
    store.sync(&mut source, 1000).unwrap();
    assert_eq!(
        disk(&path)["payments"]["journal"]["reservations"],
        reservations
    );
    assert_eq!(store.state.payments.change_next, 2);
    assert!(store
        .journal_reserved(point, 4, Some(old.id().unwrap()), &mut budget())
        .unwrap());
    assert!(store
        .journal_reserved(point, 4, Some(new.id().unwrap()), &mut budget())
        .unwrap());
    assert!(!store
        .journal_reserved(point, 45, None, &mut budget())
        .unwrap());
    assert!(matches!(
        store.prepare_payment(wallet, &mut source, &approved),
        Err(Error::Funds)
    ));
    assert!(matches!(
        store.sign_payment_with_rng(
            wallet,
            &mut source,
            &old,
            &approved,
            old.id().unwrap(),
            &mut FailingRng
        ),
        Err(Error::ArchivedPayment)
    ));
    store
        .resume_payment(wallet, &mut source, old.id().unwrap())
        .unwrap();
    let record = store
        .payments()
        .unwrap()
        .iter()
        .find(|r| r.proposal == old)
        .unwrap();
    assert_eq!(record.partials, partials);
    assert_eq!(record.signed_transaction_hex, Some(hex::encode(signed)));
    assert!(matches!(
        store.sign_payment_with_rng(
            wallet,
            &mut source,
            &old,
            &approved,
            old.id().unwrap(),
            &mut FailingRng
        ),
        Err(Error::Reserved)
    ));
    assert_eq!(
        disk(&path)["payments"]["journal"]["reservations"],
        reservations
    );
}

#[test]
fn refresh_aliases_preserve_bytes_and_reject_silent_old_id_mutation() {
    let owners = wallets(3, 1, 1);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let mut source = Source::funded(wallet, &[2_000_000]);
    let approved = intent(6);
    let (old, _) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    let partials = store
        .sign_payment(wallet, &mut source, &old, &approved, old.id().unwrap())
        .unwrap();
    store.migrate_payment_journal().unwrap();
    source.mine();
    let (new, summary) = store
        .preview_payment_refresh(wallet, &mut source, old.id().unwrap())
        .unwrap();
    store
        .approve_payment_refresh(
            wallet,
            &mut source,
            old.id().unwrap(),
            &new,
            summary.proposal_id,
        )
        .unwrap();
    assert!(
        matches!(store.sign_payment_with_rng(wallet, &mut source, &old, &approved, old.id().unwrap(), &mut FailingRng), Err(Error::SupersededPayment { current }) if current == new.id().unwrap())
    );
    assert_eq!(
        store
            .resolve_payment(old.id().unwrap(), &mut budget())
            .unwrap()
            .unwrap()
            .capability
            .partials,
        partials
    );
    let mut rerouted = partials.clone();
    for p in &mut rerouted {
        p.proposal_id = new.id().unwrap();
    }
    assert_eq!(
        store
            .sign_payment_with_rng(
                wallet,
                &mut source,
                &new,
                &approved,
                new.id().unwrap(),
                &mut FailingRng
            )
            .unwrap(),
        rerouted
    );
    // Explicitly refreshing back to a previously approved ID in the same
    // lineage is permitted; there is still exactly one reservation per input.
    store
        .approve_payment_refresh(
            wallet,
            &mut source,
            new.id().unwrap(),
            &old,
            old.id().unwrap(),
        )
        .unwrap();
    assert_eq!(store.payments().unwrap()[0].partials, partials);
    assert_eq!(
        disk(&path)["payments"]["journal"]["reservations"]["count"],
        1
    );
    let mut bad = store.state.clone();
    bad.payments.records[0].partials.clear();
    assert!(matches!(store.commit(bad), Err(Error::JournalCorrupt)));
    assert!(matches!(store.payments(), Err(Error::ReopenRequired)));
    let store = reopen(store, &path);
    assert_eq!(store.payments().unwrap()[0].partials, partials);
}

#[test]
fn migration_faults_keep_exact_legacy_copy_and_reopen_old_or_complete_new_root() {
    let owners = wallets(1, 1, 1);
    let wallet = &owners[0];
    let stages = [
        StateStage::Journal(Stage::CreateJournal),
        StateStage::Journal(Stage::CreateObjects),
        StateStage::Journal(Stage::ObjectWrite),
        StateStage::Journal(Stage::ObjectVerify),
        StateStage::Journal(Stage::ObjectSync),
        StateStage::Journal(Stage::ObjectPublish),
        StateStage::Journal(Stage::ObjectsSync),
        StateStage::Journal(Stage::JournalSync),
        StateStage::Journal(Stage::WatchSync),
        StateStage::Journal(Stage::RecoveryWrite),
        StateStage::Journal(Stage::RecoveryVerify),
        StateStage::Journal(Stage::RecoverySync),
        StateStage::Journal(Stage::RecoveryPublish),
        StateStage::Journal(Stage::RecoveryDirectorySync),
        StateStage::FileWrite,
        StateStage::FileSync,
        StateStage::Publish,
        StateStage::DirectorySync,
    ];
    for fail_at in stages {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("watch");
        let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
        let mut source = Source::funded(wallet, &[2_000_000]);
        let approved = intent(6);
        let (proposal, _) = store
            .prepare_payment(wallet, &mut source, &approved)
            .unwrap();
        let saved = store
            .sign_payment(
                wallet,
                &mut source,
                &proposal,
                &approved,
                proposal.id().unwrap(),
            )
            .unwrap();
        let old = fs::read(path.join("state.json")).unwrap();
        let mut reached = false;
        assert!(matches!(
            store.migrate_journal_with_hook(|stage| {
                if stage == fail_at {
                    reached = true;
                    Err(Error::Storage(std::io::Error::other(
                        "injected migration failure",
                    )))
                } else {
                    Ok(())
                }
            }),
            Err(Error::Storage(_))
        ));
        assert!(reached, "{fail_at:?}");
        assert!(matches!(store.payments(), Err(Error::ReopenRequired)));
        if fail_at != StateStage::DirectorySync {
            assert_eq!(fs::read(path.join("state.json")).unwrap(), old);
        }
        store = reopen(store, &path);
        store.migrate_payment_journal().unwrap();
        assert_eq!(store.payments().unwrap()[0].partials, saved);
        assert!(fs::read_dir(&path)
            .unwrap()
            .filter_map(Result::ok)
            .any(
                |p| p.file_name().to_string_lossy().starts_with("state-pre-v3-")
                    && fs::read(p.path()).unwrap() == old
            ));
        assert_eq!(
            durable_records(&path.join("state.json"))[0]["partials"],
            serde_json::to_value(saved).unwrap()
        );
    }
}

#[test]
fn v1_empty_migration_and_v3_corruption_never_fall_back_to_recovery_copy() {
    let owners = wallets(1, 1, 1);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    store.receive().unwrap();
    let mut old = disk(&path);
    old["format"] = json!("ZcashTransparentPQ/watch-state/v1");
    old.as_object_mut().unwrap().remove("payments");
    drop(store);
    let original = serde_json::to_vec(&old).unwrap();
    fs::write(path.join("state.json"), &original).unwrap();
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    store.migrate_payment_journal().unwrap();
    assert_eq!(store.receive_next(), 1);
    assert!(!store.status().unwrap().complete_at_checkpoint);
    // The exact v1 copy exists, so the rejections below cannot fall back to it.
    assert!(recovery_copy(&path, &original));
    let mut root = disk(&path);
    drop(store);
    root["payments"]["journal"]["lineages"] = json!({"count":1,"hash":"00".repeat(32),"level":0,"max":"00".repeat(32),"min":"00".repeat(32)});
    fs::write(path.join("state.json"), serde_json::to_vec(&root).unwrap()).unwrap();
    assert!(matches!(
        WatchStore::open(&path, &profile()),
        Err(Error::JournalCorrupt)
    ));
    root["format"] = json!("ZcashTransparentPQ/watch-state/v99");
    fs::write(path.join("state.json"), serde_json::to_vec(&root).unwrap()).unwrap();
    assert!(matches!(
        WatchStore::open(&path, &profile()),
        Err(Error::UnsupportedFormat)
    ));
}

#[test]
fn native_reservation_queries_match_retained_book_with_ties_exclusions_and_archival() {
    let owners = wallets(1, 1, 0);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let (approved, value) = exact(wallet, 6);
    let mut source = Source::funded(wallet, &[value]);
    let (proposal, _) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    // A legacy fixture may retain competing historical capabilities, including
    // tied expiries. The reference below scans records independently of keys.
    let mut old = store.state.clone();
    old.payments.records.clear();
    for (i, expiry) in [23, 25, 25].into_iter().enumerate() {
        let mut proposal = super::expiry::with_expiry(&proposal, expiry);
        proposal.tip.hash = Hex([i as u8 + 90; 32]);
        old.payments.records.push(PaymentRecord {
            proposal,
            intent: approved.clone(),
            partials: vec![],
            signed_transaction_hex: None,
            state: PaymentState::Prepared,
        });
    }
    store.commit(old.clone()).unwrap();
    store.migrate_payment_journal().unwrap();
    let point = proposal.points().unwrap()[0];
    let ids: Vec<_> = old
        .payments
        .records
        .iter()
        .map(|r| r.proposal.id().unwrap())
        .collect();
    while source.chain.blocks.len() < 27 {
        source.mine();
    }
    for placement in 0..=3 {
        for height in [1, 23, 24, 25, 26, u32::MAX] {
            for except in [None, Some(ids[0]), Some(ids[1]), Some(ids[2])] {
                let expected = old.payments.records.iter().any(|r| {
                    Some(r.proposal.id().unwrap()) != except
                        && r.proposal.expiry().unwrap() >= height
                        && r.proposal.points().unwrap().contains(&point)
                });
                assert_eq!(
                    store
                        .journal_reserved(point, height, except, &mut budget())
                        .unwrap(),
                    expected
                );
            }
        }
        if placement < 3 {
            store
                .archive_payment(wallet, &mut source, ids[placement])
                .unwrap();
        }
    }
    store = reopen(store, &path);
    let before = fs::read(path.join("state.json")).unwrap();
    let mut none = ReadBudget::new(0).unwrap();
    assert!(matches!(
        store.journal_reserved(point, 4, None, &mut none),
        Err(Error::JournalLookupLimit)
    ));
    assert_eq!(none.reads, 0);
    assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
    assert!(store
        .journal_reserved(point, 4, None, &mut budget())
        .unwrap());
    let reference = disk(&path)["payments"]["journal"]["reservations"]["hash"]
        .as_str()
        .unwrap()
        .to_owned();
    fs::remove_file(path.join("journal/objects").join(reference)).unwrap();
    assert!(matches!(
        store.journal_reserved(point, 4, None, &mut budget()),
        Err(Error::Storage(_))
    ));
    assert!(matches!(store.payments(), Err(Error::ReopenRequired)));
    drop(store);
    assert!(matches!(
        WatchStore::open(&path, &profile()),
        Err(Error::Storage(_))
    ));
}

#[test]
fn archived_confirmed_authorization_blocks_after_reorg_and_resumes_exact_submission_retry() {
    let owners = wallets(1, 1, 2);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let mut source = Source::funded(wallet, &[2_000_000, 1_900_000]);
    let approved = intent(6);
    let (proposal, _) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    let id = proposal.id().unwrap();
    let partials = store
        .sign_payment(wallet, &mut source, &proposal, &approved, id)
        .unwrap();
    let signed = store
        .assemble_payment(wallet, &mut source, &proposal, &approved, &partials)
        .unwrap();
    store.submit_payment(wallet, &mut source, id).unwrap();
    source.mine();
    store.archive_payment(wallet, &mut source, id).unwrap();
    source.journal = Some(path.join("state.json"));
    store = reopen(store, &path);
    source.chain.blocks.truncate(4);
    assert!(matches!(
        store.submit_payment(wallet, &mut source, id),
        Err(Error::ArchivedPayment)
    ));
    assert!(matches!(
        store.assemble_payment(wallet, &mut source, &proposal, &approved, &partials),
        Err(Error::ArchivedPayment)
    ));
    assert!(matches!(
        store.preview_payment_refresh(wallet, &mut source, id),
        Err(Error::ArchivedPayment)
    ));
    // Read-only review recognizes the saved change reservation without resume.
    store
        .review_payment(wallet, &mut source, &proposal, &approved)
        .unwrap();
    let (unrelated, _) = store
        .preview_payment(wallet, &mut source, &approved)
        .unwrap();
    assert_ne!(unrelated.points().unwrap(), proposal.points().unwrap());
    assert!(store
        .journal_reserved(proposal.points().unwrap()[0], 4, None, &mut budget())
        .unwrap());
    store.resume_payment(wallet, &mut source, id).unwrap();
    assert_eq!(
        store
            .sign_payment_with_rng(
                wallet,
                &mut source,
                &proposal,
                &approved,
                id,
                &mut FailingRng
            )
            .unwrap(),
        partials
    );
    source.fail_submit = true;
    assert!(matches!(
        store.submit_payment(wallet, &mut source, id),
        Err(Error::SubmissionUnknown)
    ));
    store = reopen(store, &path);
    source.fail_submit = false;
    store.submit_payment(wallet, &mut source, id).unwrap();
    assert_eq!(
        source.sent[source.sent.len() - 2..],
        [signed.clone(), signed]
    );
}

#[test]
fn archive_root_failures_leave_the_old_active_record_or_complete_archive() {
    let owners = wallets(1, 1, 1);
    let wallet = &owners[0];
    for fail_at in [
        StateStage::Journal(Stage::ObjectWrite),
        StateStage::Journal(Stage::ObjectSync),
        StateStage::Journal(Stage::ObjectPublish),
        StateStage::Journal(Stage::ObjectsSync),
        StateStage::FileWrite,
        StateStage::FileSync,
        StateStage::Publish,
        StateStage::DirectorySync,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("watch");
        let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
        let mut source = Source::funded(wallet, &[2_000_000]);
        let approved = intent(6);
        let (proposal, _) = store
            .prepare_payment(wallet, &mut source, &approved)
            .unwrap();
        let id = proposal.id().unwrap();
        let partials = store
            .sign_payment(wallet, &mut source, &proposal, &approved, id)
            .unwrap();
        store.migrate_payment_journal().unwrap();
        while source.chain.blocks.len() < 25 {
            source.mine();
        }
        let (mut candidate, _) = store.observe_payments(&mut source).unwrap();
        WatchStore::archive_candidate(&mut candidate, 0).unwrap();
        let before = fs::read(path.join("state.json")).unwrap();
        let mut reached = false;
        assert!(matches!(
            store.commit_with_hook(candidate, |stage| {
                if stage == fail_at {
                    reached = true;
                    Err(Error::Storage(std::io::Error::other(
                        "injected archive failure",
                    )))
                } else {
                    Ok(())
                }
            }),
            Err(Error::Storage(_))
        ));
        assert!(reached);
        assert!(matches!(store.payments(), Err(Error::ReopenRequired)));
        if fail_at != StateStage::DirectorySync {
            assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
        }
        store = reopen(store, &path);
        let found = store.resolve_payment(id, &mut budget()).unwrap().unwrap();
        assert_eq!(found.capability.partials, partials);
        assert_eq!(
            found.location,
            if fail_at == StateStage::DirectorySync {
                crate::journal::Location::Archived
            } else {
                crate::journal::Location::Active
            }
        );
        assert!(store
            .journal_reserved(proposal.points().unwrap()[0], 4, None, &mut budget())
            .unwrap());
        if fail_at != StateStage::DirectorySync {
            store.archive_payment(wallet, &mut source, id).unwrap();
        }
        store.resume_payment(wallet, &mut source, id).unwrap();
        assert_eq!(store.payments().unwrap()[0].partials, partials);
    }
}

#[test]
fn v3_import_retains_reservations_and_monitor_cannot_archive_or_resume() {
    let mut owners = wallets(1, 1, 1);
    let wallet = &mut owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let mut source = Source::funded(wallet, &[2_000_000]);
    let approved = intent(6);
    let (proposal, _) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    store.migrate_payment_journal().unwrap();
    let roots = disk(&path)["payments"]["journal"].clone();
    // Preserve enrolled policies and permanently retire the old allocator's
    // issuance range before importing a new allocator identity.
    wallet.manifest.allocator_id = Hex([99; 16]);
    wallet.manifest.retired_receive_end = wallet.manifest.receive_end;
    wallet.manifest.retired_change_end = wallet.manifest.change_end;
    wallet.manifest.revision += 1;
    store
        .import(
            &wallet.manifest().to_json().unwrap(),
            wallet.manifest().fingerprint().unwrap(),
        )
        .unwrap();
    assert_eq!(store.mode(), WatchMode::Monitor);
    for kind in [
        "aliases",
        "lineages",
        "reservations",
        "history",
        "journal_id",
    ] {
        assert_eq!(disk(&path)["payments"]["journal"][kind], roots[kind]);
    }
    assert!(matches!(
        store.archive_payment(wallet, &mut source, proposal.id().unwrap()),
        Err(Error::MonitorOnly)
    ));
    assert!(matches!(
        store.resume_payment(wallet, &mut source, proposal.id().unwrap()),
        Err(Error::MonitorOnly)
    ));
    store = reopen(store, &path);
    assert!(store
        .journal_reserved(proposal.points().unwrap()[0], 4, None, &mut budget())
        .unwrap());
}

#[test]
fn v3_rejects_a_mixed_reservation_root_even_when_aggregate_counts_fit() {
    let owners = wallets(1, 1, 0);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let (approved, value) = exact(wallet, 6);
    let mut source = Source::funded(wallet, &[value, value, value]);
    let (first, _) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    // Build a structurally valid legacy two-input record so the stale root's
    // count can still satisfy the aggregate lower bound after a new lineage.
    let mut old = store.state.clone();
    let mut tx = first.transaction().unwrap();
    let mut extra = tx.inputs()[0].clone();
    if let Input::PrevOut { outpoint, .. } = &mut extra {
        outpoint.index = 1;
    }
    review::inputs_mut(&mut tx).unwrap().push(extra);
    let record = &mut old.payments.records[0];
    record.proposal.transaction_hex = hex::encode(tx.zcash_serialize_to_vec().unwrap());
    record
        .proposal
        .inputs
        .push(record.proposal.inputs[0].clone());
    store.commit(old).unwrap();
    store.migrate_payment_journal().unwrap();
    let stale = disk(&path)["payments"]["journal"]["reservations"].clone();
    store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    let mut root = disk(&path);
    assert_eq!(root["payments"]["journal"]["lineages"]["count"], 2);
    assert_eq!(stale["count"], 2);
    drop(store);
    root["payments"]["journal"]["reservations"] = stale;
    fs::write(path.join("state.json"), serde_json::to_vec(&root).unwrap()).unwrap();
    assert!(matches!(
        WatchStore::open(&path, &profile()),
        Err(Error::JournalCorrupt)
    ));
}

#[test]
fn v1_recovery_copy_failures_cannot_publish_v3_and_matching_retry_resyncs() {
    let owners = wallets(1, 1, 0);
    let wallet = &owners[0];
    for failed in [
        Stage::RecoveryWrite,
        Stage::RecoveryVerify,
        Stage::RecoverySync,
        Stage::RecoveryPublish,
        Stage::RecoveryDirectorySync,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("watch");
        let store = create(&path, wallet.manifest(), WatchMode::Allocator);
        let mut legacy = disk(&path);
        legacy["format"] = json!("ZcashTransparentPQ/watch-state/v1");
        legacy.as_object_mut().unwrap().remove("payments");
        drop(store);
        let bytes = serde_json::to_vec(&legacy).unwrap();
        fs::write(path.join("state.json"), &bytes).unwrap();
        let mut store = WatchStore::open(&path, &profile()).unwrap();
        assert!(matches!(
            store.migrate_journal_with_hook(|stage| if stage == StateStage::Journal(failed) {
                Err(Error::Storage(std::io::Error::other(
                    "injected recovery copy failure",
                )))
            } else {
                Ok(())
            }),
            Err(Error::Storage(_))
        ));
        assert_eq!(fs::read(path.join("state.json")).unwrap(), bytes);
        assert!(matches!(store.payments(), Err(Error::ReopenRequired)));
        // Only a failed final directory sync leaves a published copy.
        let published = failed == Stage::RecoveryDirectorySync;
        assert_eq!(recovery_copy(&path, &bytes), published);
        store = reopen(store, &path);
        let mut stages = Vec::new();
        store
            .migrate_journal_with_hook(|stage| {
                stages.push(stage);
                Ok(())
            })
            .unwrap();
        let at = |stage| stages.iter().position(|s| *s == stage).unwrap();
        assert!(
            at(StateStage::Journal(Stage::RecoverySync))
                < at(StateStage::Journal(Stage::RecoveryDirectorySync))
        );
        assert!(at(StateStage::Journal(Stage::RecoveryDirectorySync)) < at(StateStage::Publish));
        // A matching published copy is verified and synced, never rewritten.
        for stage in [Stage::RecoveryWrite, Stage::RecoveryPublish] {
            assert_eq!(
                stages.contains(&StateStage::Journal(stage)),
                !published,
                "{failed:?} {stage:?}"
            );
        }
        assert!(stages.contains(&StateStage::Journal(Stage::RecoveryVerify)));
        assert!(recovery_copy(&path, &bytes));
    }
}

#[test]
fn selection_and_final_review_share_one_lookup_budget_without_changing_state() {
    let owners = wallets(1, 1, 0);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let (approved, value) = exact(wallet, 6);
    let mut source = Source::funded(wallet, &[value, value]);
    store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    store.migrate_payment_journal().unwrap();
    let before = snapshot(&path);
    let mut unlimited = budget();
    let expected = store
        .preview_with_budget(wallet, &mut source, &approved, &mut unlimited)
        .unwrap();
    assert!(unlimited.reads > 1);
    let mut short = ReadBudget::new(unlimited.reads - 1).unwrap();
    assert!(matches!(
        store.preview_with_budget(wallet, &mut source, &approved, &mut short),
        Err(Error::JournalLookupLimit)
    ));
    assert_eq!(short.reads, unlimited.reads - 1);
    assert_eq!(snapshot(&path), before);
    let mut exact = ReadBudget::new(unlimited.reads).unwrap();
    assert_eq!(
        store
            .preview_with_budget(wallet, &mut source, &approved, &mut exact)
            .unwrap(),
        expected
    );
    assert_eq!(exact.reads, unlimited.reads);
    assert_eq!(snapshot(&path), before);
}

#[test]
fn automatic_archival_uses_lineage_order_not_active_insertion_order() {
    let owners = wallets(1, 1, 0);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let (approved, value) = exact(wallet, 6);
    let mut source = Source::funded(wallet, &[value; 33]);
    let (proposal, _) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    let mut legacy = store.state.clone();
    legacy.payments.records.clear();
    for index in 0..32 {
        let mut proposal = proposal.clone();
        let mut tx = proposal.transaction().unwrap();
        if let Input::PrevOut { outpoint, .. } = &mut review::inputs_mut(&mut tx).unwrap()[0] {
            outpoint.index = index;
        }
        proposal.transaction_hex = hex::encode(tx.zcash_serialize_to_vec().unwrap());
        legacy.payments.records.push(PaymentRecord {
            intent: approved.clone(),
            proposal,
            partials: vec![],
            signed_transaction_hex: None,
            state: PaymentState::Prepared,
        });
    }
    legacy
        .payments
        .records
        .sort_by_cached_key(|record| std::cmp::Reverse(record.proposal.id().unwrap()));
    // Put the earliest lineage in the middle, so neither first-in nor
    // last-in archival selects it.
    legacy.payments.records.swap(16, 31);
    let earliest = legacy.payments.records[16].proposal.id().unwrap();
    let first = legacy.payments.records[0].proposal.id().unwrap();
    let last = legacy.payments.records[31].proposal.id().unwrap();
    assert!(earliest < first && earliest < last);
    store.commit(legacy).unwrap();
    while source.chain.blocks.len() < 25 {
        source.mine();
    }
    store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    assert_eq!(
        store
            .resolve_payment(earliest, &mut budget())
            .unwrap()
            .unwrap()
            .location,
        crate::journal::Location::Archived
    );
    for active in [first, last] {
        assert_eq!(
            store
                .resolve_payment(active, &mut budget())
                .unwrap()
                .unwrap()
                .location,
            crate::journal::Location::Active
        );
    }
}
