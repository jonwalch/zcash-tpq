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
