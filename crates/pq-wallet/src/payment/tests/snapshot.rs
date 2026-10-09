//! Bounded snapshot regressions use existing files and synthetic trusted state.
use super::*;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[test]
fn snapshot_validates_predecessors_and_preserves_retained_orphans() {
    let owners = wallets(1, 1, 1);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let mut source = Source::funded(wallet, &[2_000_000]);
    let approved = intent(6);
    let (proposal, review) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    store.migrate_payment_journal().unwrap();
    let partials = store
        .sign_payment(
            wallet,
            &mut source,
            &proposal,
            &approved,
            review.proposal_id,
        )
        .unwrap();
    store
        .assemble_payment(wallet, &mut source, &proposal, &approved, &partials)
        .unwrap();
    let before = fs::read(path.join("state.json")).unwrap();
    let first = store.journal_snapshot().unwrap().metadata().clone();
    let orphan = path.join("journal/objects/.object-retained");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&orphan)
        .unwrap();
    fs::write(&orphan, b"legitimate retained temporary bytes").unwrap();
    let next = store.journal_snapshot().unwrap().metadata().clone();
    assert_eq!(first.root_fingerprint, next.root_fingerprint);
    assert_eq!(first.reachable_objects, next.reachable_objects);
    assert_eq!(next.retained_objects, first.retained_objects + 1);
    assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
    let state: serde_json::Value = serde_json::from_slice(&before).unwrap();
    let current = state["payments"]["active"][0]["capability"]
        .as_str()
        .unwrap();
    let cap: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("journal/objects").join(current)).unwrap())
            .unwrap();
    let previous = cap["previous"].as_str().unwrap();
    let missing = path.join("journal/objects").join(previous);
    fs::remove_file(missing).unwrap();
    drop(store);
    // The bounded ordinary open reads the latest capability, while snapshot
    // validation additionally traverses its retained predecessor authority.
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    assert!(store.journal_snapshot().is_err());
    assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
}

#[test]
fn snapshot_rejects_archived_lineage_without_its_history_event() {
    let owners = wallets(1, 1, 1);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let mut source = Source::funded(wallet, &[2_000_000]);
    let (proposal, _) = store
        .prepare_payment(wallet, &mut source, &intent(6))
        .unwrap();
    while source.chain.context().unwrap().tip.height <= proposal.expiry().unwrap() {
        source.mine();
    }
    store
        .archive_payment(wallet, &mut source, proposal.id().unwrap())
        .unwrap();
    assert!(store.journal_snapshot().is_ok());
    drop(store);
    let state_file = path.join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    assert!(state["payments"]["journal"]["history"].is_object());
    state["payments"]["journal"]["history"] = serde_json::Value::Null;
    state["payments"]["journal"]["next_event"] = 0.into();
    fs::write(&state_file, serde_json::to_vec(&state).unwrap()).unwrap();
    fs::set_permissions(&state_file, fs::Permissions::from_mode(0o600)).unwrap();
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    assert!(matches!(
        store.journal_snapshot(),
        Err(Error::JournalCorrupt)
    ));
}

#[test]
fn snapshot_keeps_failed_first_migration_orphans_under_existing_quota() {
    use crate::watch::StateStage;
    let owners = wallets(1, 1, 1);
    let wallet = &owners[0];
    for failure in [
        StateStage::Journal(crate::journal::Stage::CreateObjects),
        StateStage::FileWrite,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("watch");
        let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
        let mut source = Source::funded(wallet, &[2_000_000]);
        store
            .prepare_payment(wallet, &mut source, &intent(6))
            .unwrap();
        let before = fs::read(path.join("state.json")).unwrap();
        let result = store.migrate_journal_with_hook(|stage| {
            if stage == failure {
                Err(Error::Storage(std::io::Error::other(
                    "migration checkpoint",
                )))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
        drop(store);
        let mut store = WatchStore::open(&path, &profile()).unwrap();
        let metadata = store.journal_snapshot().unwrap().metadata().clone();
        assert_eq!(metadata.journal_id, None);
        assert_eq!(metadata.generation, None);
        assert_eq!(metadata.reachable_objects, 0);
        let objects = path.join("journal/objects");
        if objects.exists() {
            assert!(metadata.retained_objects > 0);
            assert!(metadata.retained_bytes > 0);
            let entry = fs::read_dir(objects)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            fs::set_permissions(entry, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                store.journal_snapshot(),
                Err(Error::JournalCorrupt)
            ));
        } else {
            assert_eq!((metadata.retained_objects, metadata.retained_bytes), (0, 0));
        }
    }
}

#[test]
fn snapshot_rejects_dropped_historical_proposal_alias() {
    use crate::journal::{
        Batch, Entry as IndexEntry, Journal, Key, Kind, Limits, ReadBudget, Snapshot, Value,
    };
    let owners = wallets(1, 1, 1);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let mut source = Source::funded(wallet, &[2_000_000]);
    let (old, _) = store
        .prepare_payment(wallet, &mut source, &intent(6))
        .unwrap();
    let old_id = old.id().unwrap();
    store.migrate_payment_journal().unwrap();
    source.mine();
    let (new, _) = store
        .preview_payment_refresh(wallet, &mut source, old_id)
        .unwrap();
    let new_id = new.id().unwrap();
    assert_ne!(old_id, new_id);
    store
        .approve_payment_refresh(wallet, &mut source, old_id, &new, new_id)
        .unwrap();
    assert!(store.journal_snapshot().is_ok());
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("state.json")).unwrap()).unwrap();
    let journal_id =
        serde_json::from_value(state["payments"]["journal"]["journal_id"].clone()).unwrap();
    let current_hash =
        serde_json::from_value(state["payments"]["active"][0]["capability"].clone()).unwrap();
    let root = Snapshot {
        journal_id,
        generation: state["payments"]["journal"]["generation"].as_u64().unwrap(),
        kind: Kind::Aliases,
        root: None,
    };
    let mut journal = Journal::resume(&mut store, journal_id, Limits::default()).unwrap();
    let cap = journal
        .capability(current_hash, wallet.manifest(), 1)
        .unwrap();
    let mut batch = Batch::new(journal_id);
    let forged = journal
        .insert(
            &mut batch,
            &root,
            IndexEntry {
                key: Key::id(new_id),
                value: Value::Alias {
                    capability: current_hash,
                    lineage_id: cap.lineage_id,
                    revision: cap.revision,
                },
            },
            &mut ReadBudget::new(4096).unwrap(),
        )
        .unwrap();
    journal.publish(&batch, |_| Ok(())).unwrap();
    drop(journal);
    drop(store);
    state["payments"]["journal"]["aliases"] = serde_json::to_value(forged.root).unwrap();
    fs::write(path.join("state.json"), serde_json::to_vec(&state).unwrap()).unwrap();
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    assert!(matches!(
        store.journal_snapshot(),
        Err(Error::JournalCorrupt)
    ));
}
