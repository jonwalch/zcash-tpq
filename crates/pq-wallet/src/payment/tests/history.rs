//! Bounded filesystem/synthetic-chain history tests; no live node execution.
use super::*;
use crate::{PaymentLocation, PaymentObservation};
use std::path::Path;

fn disk(path: &Path) -> Vec<u8> {
    fs::read(path.join("state.json")).unwrap()
}
fn reopen(store: WatchStore, path: &Path) -> WatchStore {
    drop(store);
    WatchStore::open(path, &profile()).unwrap()
}
fn expire(source: &mut Source) {
    while source.chain.blocks.len() < 25 {
        source.mine();
    }
}
fn corrupt_cursor(cursor: &str, key: &str, value: serde_json::Value) -> String {
    let mut parsed: serde_json::Value =
        serde_json::from_slice(&hex::decode(cursor).unwrap()).unwrap();
    parsed[key] = value;
    hex::encode(serde_json::to_vec(&parsed).unwrap())
}

#[test]
fn history_pages_are_dated_repeatable_and_bound_to_the_exact_snapshot() {
    let owners = wallets(1, 1, 0);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let (approved, value) = archive::exact(wallet, 6);
    let mut source = Source::funded(wallet, &[value]);
    let (proposal, _) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    let id = proposal.id().unwrap();
    let before = disk(&path);
    assert!(store.payment_history(16, None).unwrap().entries.is_empty());
    assert_eq!(disk(&path), before); // Read-only lookup does not migrate v2.
    expire(&mut source);
    // Each archival happens at a new tip, so every row has its own date.
    let mut tips = Vec::new();
    for event in 0..18 {
        source.mine();
        store.archive_payment(wallet, &mut source, id).unwrap();
        tips.push(source.context().unwrap().tip);
        if event != 17 {
            store.resume_payment(wallet, &mut source, id).unwrap();
        }
    }
    let before = disk(&path);
    let page = store.payment_history(16, None).unwrap();
    assert_eq!(page.entries.len(), 16);
    for (sequence, row) in page.entries.iter().enumerate() {
        assert_eq!(row.sequence, sequence as u64);
        assert_eq!(row.proposal_id, id);
        assert_eq!(row.lineage_id, id);
        assert_eq!(row.state, PaymentState::Expired);
        assert_eq!(row.checkpoint, tips[sequence]);
        assert_eq!(row.amount, approved.amount);
    }
    let cursor = page.next_cursor.unwrap();
    store = reopen(store, &path);
    let tail = store.payment_history(16, Some(&cursor)).unwrap();
    assert_eq!(
        tail.entries.iter().map(|r| r.sequence).collect::<Vec<_>>(),
        [16, 17]
    );
    assert_eq!(
        tail.entries
            .iter()
            .map(|r| r.checkpoint)
            .collect::<Vec<_>>(),
        tips[16..]
    );
    assert!(tail.next_cursor.is_none());
    let mut cursor_small = None;
    let mut sequences = Vec::new();
    loop {
        let page = store.payment_history(1, cursor_small.as_deref()).unwrap();
        sequences.extend(page.entries.iter().map(|r| r.sequence));
        cursor_small = page.next_cursor;
        if cursor_small.is_none() {
            break;
        }
    }
    assert_eq!(sequences, (0..18).collect::<Vec<_>>());
    assert_eq!(disk(&path), before);
    for limit in [0, 17, usize::MAX] {
        assert!(matches!(
            store.payment_history(limit, None),
            Err(Error::Limits)
        ));
    }
    for bad in [
        String::new(),
        cursor.to_uppercase(),
        "aa".into(),
        corrupt_cursor(&cursor, "format", serde_json::json!("other")),
        corrupt_cursor(&cursor, "next_sequence", serde_json::json!(19)),
        corrupt_cursor(&cursor, "extra", serde_json::json!(1)),
    ] {
        assert!(matches!(
            store.payment_history(16, Some(&bad)),
            Err(Error::Encoding)
        ));
    }
    assert!(matches!(
        store.payment_history(16, Some(&"a".repeat(1025))),
        Err(Error::Limits)
    ));
    assert_eq!(store.payment_history(16, Some(&cursor)).unwrap(), tail);
    let other_path = temp.path().join("other");
    let mut other = create(&other_path, wallet.manifest(), WatchMode::Allocator);
    assert!(matches!(
        other.payment_history(16, Some(&cursor)),
        Err(Error::StaleJournalCursor)
    ));
    other.migrate_payment_journal().unwrap();
    assert!(matches!(
        other.payment_history(16, Some(&cursor)),
        Err(Error::StaleJournalCursor)
    ));
    assert!(other.payments().is_ok());
    store.resume_payment(wallet, &mut source, id).unwrap();
    assert!(matches!(
        store.payment_history(16, Some(&cursor)),
        Err(Error::StaleJournalCursor)
    ));
    assert!(store.payment_history(16, None).is_ok());
    assert!(store.payments().is_ok());
}

#[test]
fn saved_alias_exports_preserve_authorization_and_partial_failures_leave_store_usable() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let owners = wallets(1, 1, 0);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let (approved, value) = archive::exact(wallet, 6);
    let mut source = Source::funded(wallet, &[value]);
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
    let legacy = store.payment_record(id).unwrap().unwrap();
    assert_eq!(legacy.proposal, proposal);
    assert_eq!(legacy.partials, partials);
    assert_eq!(legacy.signed_transaction_hex, Some(hex::encode(&signed)));
    assert_eq!(legacy.lineage_id, None);
    assert_eq!(
        legacy.observation,
        Some(PaymentObservation {
            checkpoint: None,
            state: PaymentState::Signed
        })
    );
    let before = disk(&path);
    store
        .export_payment_history(id, &temp.path().join("legacy-export"))
        .unwrap();
    assert_eq!(disk(&path), before);
    assert_eq!(store.payment_record(Hex([0; 32])).unwrap(), None);
    store.migrate_payment_journal().unwrap();
    source.mine();
    let (new, _) = store
        .preview_payment_refresh(wallet, &mut source, id)
        .unwrap();
    let current = new.id().unwrap();
    store
        .approve_payment_refresh(wallet, &mut source, id, &new, current)
        .unwrap();
    let old = store.payment_record(id).unwrap().unwrap();
    assert_eq!(old.proposal, proposal);
    assert_eq!(old.partials, partials);
    assert_eq!(old.current_proposal_id, current);
    assert_eq!(old.location, PaymentLocation::Active);
    assert_eq!(old.observation, None);
    expire(&mut source);
    store.archive_payment(wallet, &mut source, current).unwrap();
    store = reopen(store, &path);
    let old = store.payment_record(id).unwrap().unwrap();
    assert_eq!(old.location, PaymentLocation::Archived);
    assert_eq!(old.observation, None);
    assert_eq!(old.proposal, proposal);
    assert_eq!(old.partials, partials);
    let latest = store.payment_record(current).unwrap().unwrap();
    assert_eq!(latest.proposal, new);
    assert_eq!(latest.signed_transaction_hex, old.signed_transaction_hex);
    let before = disk(&path);
    let out = temp.path().join("export");
    store.export_payment_history(id, &out).unwrap();
    assert_eq!(
        fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for entry in fs::read_dir(&out).unwrap() {
        assert_eq!(
            entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        fs::read(out.join("proposal.json")).unwrap(),
        proposal.to_json().unwrap()
    );
    assert_eq!(
        fs::read(out.join("signed-transaction.hex")).unwrap(),
        hex::encode(&signed).as_bytes()
    );
    for partial in &partials {
        let name = format!(
            "input-{:04}-signer-{:02}.json",
            partial.input_index, partial.signer_index
        );
        assert_eq!(
            fs::read(out.join(name)).unwrap(),
            partial.to_json().unwrap()
        );
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("payment.json")).unwrap()).unwrap();
    assert_eq!(metadata, serde_json::to_value(&old).unwrap());
    assert!(out.join("complete.json").is_file());
    assert!(matches!(
        store.export_payment_history(id, &out),
        Err(Error::Storage(_))
    ));
    // A destination symlink is never followed, even when its target is absent.
    let target = temp.path().join("symlink-target");
    let link = temp.path().join("symlink");
    symlink(&target, &link).unwrap();
    assert!(matches!(
        store.export_payment_history(id, &link),
        Err(Error::Storage(_))
    ));
    assert!(!target.exists());
    // A symlinked parent outside the store passes the alias check but is
    // refused when opened without following it.
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let parent_link = temp.path().join("parent-link");
    symlink(&outside, &parent_link).unwrap();
    assert!(matches!(
        store.export_payment_history(id, &parent_link.join("export")),
        Err(Error::Storage(_))
    ));
    assert!(!outside.join("export").exists());
    for parent in [&path, &path.join("journal/objects")] {
        let inside = parent.join("export");
        assert!(matches!(
            store.export_payment_history(id, &inside),
            Err(Error::Encoding)
        ));
        assert!(!inside.exists());
    }
    let alias_parent = temp.path().join("source-alias");
    symlink(&path, &alias_parent).unwrap();
    let inside = alias_parent.join("journal/objects/export");
    assert!(matches!(
        store.export_payment_history(id, &inside),
        Err(Error::Encoding)
    ));
    assert!(!inside.exists());
    let failed = temp.path().join("failed-export");
    assert!(matches!(
        store.export_payment_with_hook(id, &failed, |path| {
            if path.file_name().unwrap() == "proposal.json" {
                Err(Error::Storage(std::io::Error::other(
                    "injected export failure",
                )))
            } else {
                Ok(())
            }
        }),
        Err(Error::Storage(_))
    ));
    assert!(failed.join("payment.json").is_file());
    assert!(!failed.join("complete.json").exists());
    let unknown = temp.path().join("unknown");
    assert!(matches!(
        store.export_payment_history(Hex([0; 32]), &unknown),
        Err(Error::ProposalMismatch)
    ));
    assert!(!unknown.exists());
    assert_eq!(disk(&path), before);
    assert_eq!(store.payment_record(id).unwrap().unwrap(), old);
    assert!(store.payments().is_ok());
}

#[test]
fn monitor_history_reads_do_not_resume_or_release_reservations() {
    let owners = wallets(1, 1, 0);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let (approved, value) = archive::exact(wallet, 6);
    let mut source = Source::funded(wallet, &[value]);
    let (proposal, _) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    let id = proposal.id().unwrap();
    expire(&mut source);
    store.archive_payment(wallet, &mut source, id).unwrap();
    let mut candidate = store.state.clone();
    candidate.mode = WatchMode::Monitor;
    store.commit(candidate).unwrap();
    store = reopen(store, &path);
    let before = disk(&path);
    assert_eq!(store.payment_history(16, None).unwrap().entries.len(), 1);
    assert_eq!(
        store.payment_record(id).unwrap().unwrap().location,
        PaymentLocation::Archived
    );
    store
        .export_payment_history(id, &temp.path().join("monitor-export"))
        .unwrap();
    assert!(matches!(
        store.resume_payment(wallet, &mut source, id),
        Err(Error::MonitorOnly)
    ));
    assert!(matches!(
        store.archive_payment(wallet, &mut source, id),
        Err(Error::MonitorOnly)
    ));
    assert!(store
        .journal_reserved(
            proposal.points().unwrap()[0],
            4,
            None,
            &mut crate::journal::ReadBudget::new(4096).unwrap()
        )
        .unwrap());
    assert_eq!(disk(&path), before);
}

#[test]
fn history_read_fails_closed_on_missing_or_corrupt_capabilities() {
    let owners = wallets(1, 1, 0);
    let wallet = &owners[0];
    for missing in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("watch");
        let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
        let (approved, value) = archive::exact(wallet, 6);
        let mut source = Source::funded(wallet, &[value]);
        let (proposal, _) = store
            .prepare_payment(wallet, &mut source, &approved)
            .unwrap();
        let id = proposal.id().unwrap();
        expire(&mut source);
        store.archive_payment(wallet, &mut source, id).unwrap();
        let capability = store
            .payment_record(id)
            .unwrap()
            .unwrap()
            .capability
            .unwrap();
        let object = path.join("journal/objects").join(hex::encode(capability.0));
        if missing {
            fs::remove_file(&object).unwrap();
        } else {
            fs::write(&object, b"{}").unwrap();
        }
        let before = disk(&path);
        let result = store.payment_history(16, None);
        if missing {
            assert!(matches!(result, Err(Error::Storage(_))));
        } else {
            assert!(matches!(result, Err(Error::JournalCorrupt)));
        }
        assert!(matches!(
            store.payment_record(id),
            Err(Error::ReopenRequired)
        ));
        assert!(matches!(store.payments(), Err(Error::ReopenRequired)));
        assert_eq!(disk(&path), before);
    }
}

#[test]
fn history_rejects_a_rehashed_but_mixed_alias_reference() {
    use crate::journal::{Batch, Entry, Journal, Key, Kind, Limits, ReadBudget, Snapshot, Value};
    let owners = wallets(1, 1, 0);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watch");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let (approved, value) = archive::exact(wallet, 6);
    let mut source = Source::funded(wallet, &[value]);
    let (proposal, _) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    let id = proposal.id().unwrap();
    expire(&mut source);
    store.archive_payment(wallet, &mut source, id).unwrap();
    let mut disk: serde_json::Value = serde_json::from_slice(&disk(&path)).unwrap();
    let descriptor = &disk["payments"]["journal"];
    let journal_id =
        serde_json::from_slice(&serde_json::to_vec(&descriptor["journal_id"]).unwrap()).unwrap();
    let snapshot = Snapshot {
        generation: descriptor["generation"].as_u64().unwrap(),
        journal_id,
        kind: Kind::Aliases,
        root: serde_json::from_slice(&serde_json::to_vec(&descriptor["aliases"]).unwrap()).unwrap(),
    };
    let mut batch = Batch::new(journal_id);
    let mut journal = Journal::open(&mut store, journal_id, Limits::default()).unwrap();
    let mut budget = ReadBudget::new(4096).unwrap();
    let mut value = journal
        .get(&snapshot, &Key::id(id), &mut budget)
        .unwrap()
        .unwrap();
    if let Value::Alias { capability, .. } = &mut value {
        *capability = Hex([91; 32]);
    } else {
        panic!("expected alias");
    }
    let changed = journal
        .insert(
            &mut batch,
            &snapshot,
            Entry {
                key: Key::id(id),
                value,
            },
            &mut budget,
        )
        .unwrap();
    journal.publish(&batch, |_| Ok(())).unwrap();
    drop(journal);
    drop(store);
    disk["payments"]["journal"]["aliases"] = serde_json::to_value(changed.root).unwrap();
    fs::write(path.join("state.json"), serde_json::to_vec(&disk).unwrap()).unwrap();
    // The immutable page hash, counts, keys and schema all remain valid.
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    assert!(matches!(
        store.payment_history(16, None),
        Err(Error::JournalCorrupt)
    ));
    assert!(matches!(store.payments(), Err(Error::ReopenRequired)));
}
