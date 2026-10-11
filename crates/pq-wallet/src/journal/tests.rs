use super::*;
use crate::{
    canonical,
    watch::tests::{create, profile},
    Manifest, Outpoint, WatchMode, WatchStore,
};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};

const ID: Hex<16> = Hex([7; 16]);
fn fixture() -> (tempfile::TempDir, WatchStore) {
    let temp = tempfile::tempdir().unwrap();
    let manifest = Manifest::empty(profile(), 0, Hex([1; 16]), Hex([2; 16]));
    let watch = create(&temp.path().join("watch"), &manifest, WatchMode::Allocator);
    (temp, watch)
}
fn id(n: u64) -> Hex<32> {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    Hex(bytes)
}
fn alias(n: u64, revision: u64) -> Entry {
    Entry {
        key: Key::id(id(n)),
        value: Value::Alias {
            capability: id(n + 1000),
            lineage_id: id(n),
            revision,
        },
    }
}
fn budget() -> ReadBudget {
    ReadBudget::new(4096).unwrap()
}
fn populated(journal: &mut Journal<'_>, n: u64) -> Snapshot {
    let mut batch = Batch::new(ID);
    let mut snapshot = Snapshot::empty(ID, Kind::Aliases);
    for i in 0..n {
        snapshot = journal
            .insert(&mut batch, &snapshot, alias(i * 2 + 2, 0), &mut budget())
            .unwrap();
    }
    journal.publish(&batch, |_| Ok(())).unwrap();
    snapshot
}
fn object_path(temp: &tempfile::TempDir, hash: Hash) -> std::path::PathBuf {
    temp.path()
        .join("watch/journal/objects")
        .join(hex::encode(hash.0))
}
fn reopen(temp: &tempfile::TempDir) -> WatchStore {
    WatchStore::open(&temp.path().join("watch"), &profile()).unwrap()
}
fn injected() -> Error {
    Error::Storage(std::io::Error::other("injected journal failure"))
}

#[test]
fn immutable_tree_matches_ordered_map_through_splits_updates_and_reopen() {
    let (temp, mut watch) = fixture();
    let original = fs::read(temp.path().join("watch/state.json")).unwrap();
    let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
    let empty = Snapshot::empty(ID, Kind::Aliases);
    assert!(journal
        .get(&empty, &Key::id(id(1)), &mut budget())
        .unwrap()
        .is_none());
    let mut snapshot = empty;
    let mut expected = BTreeMap::new();
    let mut batch = Batch::new(ID);
    for i in 0..257 {
        let n = (i * 137) % 257;
        let entry = alias(2 * n + 2, n);
        expected.insert(entry.key.clone(), entry.value.clone());
        snapshot = journal
            .insert(&mut batch, &snapshot, entry, &mut budget())
            .unwrap();
    }
    assert!(snapshot.root.as_ref().unwrap().level >= 2);
    assert_eq!(snapshot.root.as_ref().unwrap().count, 257);
    journal.publish(&batch, |_| Ok(())).unwrap();
    let old = snapshot.clone();
    let mut updates = Batch::new(ID);
    for n in (0..257).step_by(7) {
        let entry = alias(2 * n + 2, 9000 + n);
        expected.insert(entry.key.clone(), entry.value.clone());
        snapshot = journal
            .insert(&mut updates, &snapshot, entry, &mut budget())
            .unwrap();
    }
    journal.publish(&updates, |_| Ok(())).unwrap();
    assert_eq!(
        journal.get(&old, &Key::id(id(2)), &mut budget()).unwrap(),
        Some(alias(2, 0).value)
    );
    drop(journal);
    drop(watch);
    let mut watch = reopen(&temp);
    let mut journal = Journal::open(&mut watch, ID, Limits::default()).unwrap();
    for n in 0..516 {
        assert_eq!(
            journal
                .get(&snapshot, &Key::id(id(n)), &mut budget())
                .unwrap(),
            expected.get(&Key::id(id(n))).cloned()
        );
    }
    let mut cursor = None;
    let mut actual = BTreeMap::new();
    loop {
        let (page, next) = journal
            .page(&snapshot, None, cursor.as_ref(), 13, &mut budget())
            .unwrap();
        for entry in page {
            assert!(actual.insert(entry.key, entry.value).is_none());
        }
        cursor = next;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(actual, expected);
    assert_eq!(
        fs::read(temp.path().join("watch/state.json")).unwrap(),
        original
    );
    let (page, _) = journal
        .page(&old, Some(&Key::id(id(200))), None, 1, &mut budget())
        .unwrap();
    assert_eq!(page, vec![alias(200, 99)]);
}

#[test]
fn cursors_pin_kind_root_journal_and_generation() {
    let (_temp, mut watch) = fixture();
    let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
    let snapshot = populated(&mut journal, 24);
    let (_, cursor) = journal
        .page(&snapshot, None, None, 8, &mut budget())
        .unwrap();
    let cursor = cursor.unwrap();
    let (page, _) = journal
        .page(&snapshot, None, Some(&cursor), 1, &mut budget())
        .unwrap();
    assert_eq!(page[0].key, Key::id(id(18)));
    for changed in [
        Snapshot {
            generation: 1,
            ..snapshot.clone()
        },
        Snapshot {
            root: None,
            ..snapshot.clone()
        },
        Snapshot {
            kind: Kind::History,
            ..snapshot.clone()
        },
    ] {
        assert!(matches!(
            journal.page(&changed, None, Some(&cursor), 8, &mut budget()),
            Err(Error::StaleCursor)
        ));
    }
    assert!(matches!(
        journal.page(&snapshot, None, None, 17, &mut budget()),
        Err(Error::Limit)
    ));
    let alien = Snapshot {
        journal_id: Hex([8; 16]),
        ..snapshot
    };
    assert!(matches!(
        journal.page(&alien, None, Some(&cursor), 8, &mut budget()),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        journal.get(&alien, &Key::id(id(2)), &mut budget()),
        Err(Error::ReopenRequired)
    ));
}

#[test]
fn exact_read_limits_cache_scope_and_failed_io_charging() {
    let (temp, mut watch) = fixture();
    let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
    let snapshot = populated(&mut journal, 17);
    let key = Key::id(id(2));
    let mut zero = ReadBudget::new(0).unwrap();
    assert!(matches!(
        journal.get(&snapshot, &key, &mut zero),
        Err(Error::LookupLimit)
    ));
    assert_eq!(zero.reads, 0);
    let mut one = ReadBudget::new(1).unwrap();
    assert!(matches!(
        journal.get(&snapshot, &key, &mut one),
        Err(Error::LookupLimit)
    ));
    assert_eq!(one.reads, 1);
    let mut leaf = ReadBudget::new(1).unwrap();
    assert!(journal.get(&snapshot, &key, &mut leaf).unwrap().is_some());
    assert_eq!(leaf.reads, 1);
    assert!(journal.get(&snapshot, &key, &mut zero).unwrap().is_some());
    let changed = Snapshot {
        generation: 1,
        ..snapshot.clone()
    };
    assert!(matches!(
        journal.get(&changed, &key, &mut zero),
        Err(Error::LookupLimit)
    ));
    fs::remove_file(object_path(&temp, snapshot.root.as_ref().unwrap().hash)).unwrap();
    let mut failure = ReadBudget::new(1).unwrap();
    assert!(matches!(
        journal.get(&changed, &key, &mut failure),
        Err(Error::Storage(_))
    ));
    assert_eq!(failure.reads, 1);
    assert!(matches!(
        journal.get(&changed, &key, &mut budget()),
        Err(Error::ReopenRequired)
    ));
    drop(journal);
    assert!(matches!(watch.status(), Err(crate::Error::ReopenRequired)));
}

#[test]
fn missing_successor_is_an_error_not_end_of_range() {
    let (temp, mut watch) = fixture();
    let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
    let snapshot = populated(&mut journal, 17);
    let root = snapshot.root.as_ref().unwrap();
    let parent = Page::decode(
        &fs::read(object_path(&temp, root.hash)).unwrap(),
        ID,
        Kind::Aliases,
    )
    .unwrap();
    fs::remove_file(object_path(&temp, parent.children[1].hash)).unwrap();
    let mut reads = budget();
    assert!(matches!(
        journal.page(&snapshot, Some(&Key::id(id(16))), None, 2, &mut reads),
        Err(Error::Storage(_))
    ));
    assert_eq!(reads.reads, 3);
}

#[test]
fn corrupt_missing_oversize_and_unsafe_objects_poison_the_handle() {
    for case in [
        "missing",
        "changed",
        "truncated",
        "oversize",
        "permissions",
        "symlink",
        "directory",
    ] {
        let (temp, mut watch) = fixture();
        let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
        let snapshot = populated(&mut journal, 1);
        let path = object_path(&temp, snapshot.root.as_ref().unwrap().hash);
        match case {
            "missing" => fs::remove_file(&path).unwrap(),
            "changed" => {
                let mut bytes = fs::read(&path).unwrap();
                bytes[1] ^= 1;
                fs::write(&path, bytes).unwrap();
            }
            "truncated" => {
                let mut bytes = fs::read(&path).unwrap();
                bytes.pop();
                fs::write(&path, bytes).unwrap();
            }
            "oversize" => fs::write(&path, vec![b' '; PAGE_BYTES + 1]).unwrap(),
            "permissions" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "symlink" => {
                // The target holds the exact valid private object, so only the
                // no-follow open can reject it.
                let copy = temp.path().join("copy");
                fs::copy(&path, &copy).unwrap();
                fs::set_permissions(&copy, fs::Permissions::from_mode(0o600)).unwrap();
                fs::remove_file(&path).unwrap();
                symlink(&copy, &path).unwrap();
            }
            "directory" => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            _ => unreachable!(),
        }
        let result = journal.get(&snapshot, &Key::id(id(2)), &mut budget());
        assert!(
            if case == "symlink" {
                matches!(result, Err(Error::Storage(_)))
            } else {
                matches!(result, Err(Error::Corrupt | Error::Storage(_)))
            },
            "{case}"
        );
        assert!(
            matches!(
                journal.get(&snapshot, &Key::id(id(2)), &mut budget()),
                Err(Error::ReopenRequired)
            ),
            "{case}"
        );
    }
}

#[test]
fn malformed_pages_and_false_reference_metadata_reject() {
    let good = Page::leaf(ID, Kind::Aliases, vec![alias(2, 0), alias(4, 0)]);
    let bytes = good.encode().unwrap();
    assert_eq!(Page::decode(&bytes.bytes, ID, Kind::Aliases).unwrap(), good);
    for case in [
        "duplicate",
        "unsorted",
        "key",
        "kind",
        "format",
        "level",
        "empty",
        "too_many",
    ] {
        let mut page = good.clone();
        match case {
            "duplicate" => page.records[1] = page.records[0].clone(),
            "unsorted" => page.records.reverse(),
            "key" => page.records[0].key.0 = "00".into(),
            "kind" => page.kind = Kind::Reservations,
            "format" => page.format.push('x'),
            "level" => page.level = 1,
            "empty" => page.records.clear(),
            "too_many" => page.records = (0..17).map(|n| alias(n, 0)).collect(),
            _ => unreachable!(),
        }
        let bytes = canonical::encode(&page, PAGE_BYTES).unwrap();
        assert!(
            matches!(Page::decode(&bytes, ID, Kind::Aliases), Err(Error::Corrupt)),
            "{case}"
        );
    }
    let mut value: serde_json::Value = serde_json::from_slice(&bytes.bytes).unwrap();
    value["unexpected"] = true.into();
    assert!(matches!(
        Page::decode(&serde_json::to_vec(&value).unwrap(), ID, Kind::Aliases),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        Page::decode(&bytes.bytes, Hex([8; 16]), Kind::Aliases),
        Err(Error::Corrupt)
    ));
    // Lineage and alias keys have the same length: a self-consistent page of
    // another kind fails only the expected-kind check.
    let lineages = Page::leaf(
        ID,
        Kind::Lineages,
        vec![Entry {
            key: Key::id(id(2)),
            value: Value::Lineage {
                capability: id(1),
                location: Location::Active,
                proposal_id: id(2),
                revision: 0,
            },
        }],
    );
    let encoded = lineages.encode().unwrap();
    assert_eq!(
        Page::decode(&encoded.bytes, ID, Kind::Lineages).unwrap(),
        lineages
    );
    assert!(matches!(
        Page::decode(&encoded.bytes, ID, Kind::Aliases),
        Err(Error::Corrupt)
    ));
    for case in ["count", "min", "max", "level", "nonroot"] {
        let (_temp, mut watch) = fixture();
        let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
        let snapshot = populated(&mut journal, 2);
        let mut reference = snapshot.root.unwrap();
        match case {
            "count" => reference.count += 1,
            "min" => reference.min = Key::id(id(1)),
            "max" => reference.max = Key::id(id(9)),
            "level" => reference.level = 1,
            "nonroot" => (),
            _ => unreachable!(),
        }
        assert!(
            matches!(
                journal.load_page(
                    &reference,
                    Kind::Aliases,
                    case != "nonroot",
                    None,
                    &mut budget()
                ),
                Err(Error::Corrupt)
            ),
            "{case}"
        );
    }
}

#[test]
fn publication_faults_preserve_the_root_poison_and_recover() {
    for fail_at in [
        Stage::ObjectWrite,
        Stage::ObjectVerify,
        Stage::ObjectSync,
        Stage::ObjectPublish,
        Stage::ObjectsSync,
    ] {
        let (temp, mut watch) = fixture();
        let before = fs::read(temp.path().join("watch/state.json")).unwrap();
        let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
        let mut batch = Batch::new(ID);
        let snapshot = journal
            .insert(
                &mut batch,
                &Snapshot::empty(ID, Kind::Aliases),
                alias(2, 0),
                &mut budget(),
            )
            .unwrap();
        assert!(journal
            .publish(&batch, |stage| if stage == fail_at {
                Err(injected())
            } else {
                Ok(())
            })
            .is_err());
        assert!(matches!(
            journal.publish(&batch, |_| Ok(())),
            Err(Error::ReopenRequired)
        ));
        assert_eq!(
            fs::read(temp.path().join("watch/state.json")).unwrap(),
            before
        );
        drop(journal);
        drop(watch);
        let mut watch = reopen(&temp);
        let mut journal = Journal::open(&mut watch, ID, Limits::default()).unwrap();
        journal.publish(&batch, |_| Ok(())).unwrap();
        assert_eq!(
            journal
                .get(&snapshot, &Key::id(id(2)), &mut budget())
                .unwrap(),
            Some(alias(2, 0).value)
        );
    }
}

#[test]
fn creation_sync_failures_leave_v2_reopenable() {
    for fail_at in [
        Stage::CreateJournal,
        Stage::CreateObjects,
        Stage::ObjectsSync,
        Stage::JournalSync,
        Stage::WatchSync,
    ] {
        let (temp, mut watch) = fixture();
        let before = fs::read(temp.path().join("watch/state.json")).unwrap();
        assert!(Journal::create(&mut watch, ID, Limits::default(), |stage| {
            if stage == fail_at {
                Err(injected())
            } else {
                Ok(())
            }
        })
        .is_err());
        assert!(matches!(watch.status(), Err(crate::Error::ReopenRequired)));
        assert_eq!(
            fs::read(temp.path().join("watch/state.json")).unwrap(),
            before
        );
        drop(watch);
        let mut watch = reopen(&temp);
        Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
    }
}

#[test]
fn quota_counts_peak_names_orphans_and_reopen_inventory() {
    let (temp, mut watch) = fixture();
    let page = Page::leaf(ID, Kind::Aliases, vec![alias(2, 0)]);
    let size = page.encode().unwrap().bytes.len() as u64;
    let limits = Limits {
        bytes: size * 2,
        objects: 2,
        ..Limits::default()
    };
    let mut journal = Journal::create(&mut watch, ID, limits, |_| Ok(())).unwrap();
    let mut batch = Batch::new(ID);
    batch.page(&page, limits).unwrap();
    journal.limits.bytes -= 1;
    assert!(matches!(
        journal.publish(&batch, |_| panic!("preflight must precede writes")),
        Err(Error::Quota)
    ));
    journal.limits.bytes += 1;
    journal.limits.objects = 1;
    assert!(matches!(
        journal.publish(&batch, |_| panic!("preflight must precede writes")),
        Err(Error::ObjectLimit)
    ));
    journal.limits.objects = 2;
    journal.publish(&batch, |_| Ok(())).unwrap();
    assert_eq!(journal.used_bytes, size);
    assert_eq!(journal.used_objects, 1);
    journal.publish(&batch, |_| Ok(())).unwrap();
    assert_eq!(journal.used_objects, 1);
    drop(journal);
    let orphan = temp.path().join("watch/journal/objects/.object-abandoned");
    fs::write(&orphan, [0; 11]).unwrap();
    fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();
    let journal = Journal::open(&mut watch, ID, limits).unwrap();
    assert_eq!((journal.used_bytes, journal.used_objects), (size + 11, 2));
    drop(journal);
    assert!(matches!(
        Journal::open(
            &mut watch,
            ID,
            Limits {
                bytes: size + 10,
                ..limits
            }
        ),
        Err(Error::Quota)
    ));
}

#[test]
fn commit_and_depth_limits_invalidate_the_entire_batch() {
    for case in ["bytes", "objects", "depth"] {
        let (_temp, mut watch) = fixture();
        let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
        match case {
            "bytes" => journal.limits.commit_bytes = 1,
            "objects" => journal.limits.commit_objects = 1,
            "depth" => journal.limits.depth = 1,
            _ => unreachable!(),
        }
        let mut batch = Batch::new(ID);
        let mut snapshot = Snapshot::empty(ID, Kind::Aliases);
        let mut failed = false;
        for n in 0..17 {
            match journal.insert(&mut batch, &snapshot, alias(n, 0), &mut budget()) {
                Ok(updated) => snapshot = updated,
                Err(Error::Limit) => {
                    failed = true;
                    break;
                }
                Err(error) => panic!("{case}: {error}"),
            }
        }
        assert!(failed, "{case}");
        assert!(matches!(
            journal.publish(&batch, |_| Ok(())),
            Err(Error::InvalidBatch)
        ));
        assert_eq!(journal.used_objects, 0);
    }
}

#[test]
fn reservation_key_order_matches_outpoint_then_descending_expiry() {
    let point = Outpoint {
        txid: id(9),
        index: 255,
    };
    let mut keys = vec![
        Key::reservation(point, 1, id(1)),
        Key::reservation(point, u32::MAX, id(1)),
        Key::reservation(point, 20, id(2)),
        Key::reservation(point, 20, id(1)),
    ];
    keys.sort();
    assert_eq!(
        keys,
        vec![
            Key::reservation(point, u32::MAX, id(1)),
            Key::reservation(point, 20, id(1)),
            Key::reservation(point, 20, id(2)),
            Key::reservation(point, 1, id(1))
        ]
    );
    assert!(
        keys[3]
            < Key::reservation(
                Outpoint {
                    index: 256,
                    ..point
                },
                u32::MAX,
                id(0)
            )
    );
    let (_temp, mut watch) = fixture();
    let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
    let mut snapshot = Snapshot::empty(ID, Kind::Reservations);
    let mut batch = Batch::new(ID);
    for key in &keys {
        snapshot = journal
            .insert(
                &mut batch,
                &snapshot,
                Entry {
                    key: key.clone(),
                    value: Value::Reservation,
                },
                &mut budget(),
            )
            .unwrap();
    }
    journal.publish(&batch, |_| Ok(())).unwrap();
    let (page, _) = journal
        .page(
            &snapshot,
            Some(&Key::reservation(point, u32::MAX, id(0))),
            None,
            2,
            &mut budget(),
        )
        .unwrap();
    assert_eq!(
        page.iter().map(|e| e.key.clone()).collect::<Vec<_>>(),
        keys[..2]
    );
}

#[test]
fn recovery_copy_sync_sequence_and_failures_preserve_legacy_bytes() {
    for fail_at in [
        None,
        Some(Stage::RecoveryWrite),
        Some(Stage::RecoveryVerify),
        Some(Stage::RecoverySync),
        Some(Stage::RecoveryPublish),
        Some(Stage::RecoveryDirectorySync),
    ] {
        let (temp, mut watch) = fixture();
        let before = fs::read(temp.path().join("watch/state.json")).unwrap();
        let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
        let mut stages = vec![];
        let result = journal.save_legacy(|stage| {
            stages.push(stage);
            if Some(stage) == fail_at {
                Err(injected())
            } else {
                Ok(())
            }
        });
        assert_eq!(result.is_err(), fail_at.is_some());
        if fail_at.is_none() {
            assert_eq!(
                stages,
                vec![
                    Stage::RecoveryWrite,
                    Stage::RecoveryVerify,
                    Stage::RecoverySync,
                    Stage::RecoveryPublish,
                    Stage::RecoveryDirectorySync
                ]
            );
        } else {
            assert!(matches!(
                journal.save_legacy(|_| Ok(())),
                Err(Error::ReopenRequired)
            ));
        }
        assert_eq!(
            fs::read(temp.path().join("watch/state.json")).unwrap(),
            before
        );
        drop(journal);
        drop(watch);
        let mut watch = reopen(&temp);
        let mut journal = Journal::open(&mut watch, ID, Limits::default()).unwrap();
        let saved = journal.save_legacy(|_| Ok(())).unwrap();
        assert_eq!(fs::read(&saved).unwrap(), before);
        let mut retry = vec![];
        assert_eq!(
            journal
                .save_legacy(|stage| {
                    retry.push(stage);
                    Ok(())
                })
                .unwrap(),
            saved
        );
        assert_eq!(
            retry,
            vec![
                Stage::RecoveryVerify,
                Stage::RecoverySync,
                Stage::RecoveryDirectorySync
            ]
        );
        fs::write(&saved, b"truncated").unwrap();
        assert!(matches!(
            journal.save_legacy(|_| Ok(())),
            Err(Error::Corrupt)
        ));
        assert_eq!(
            fs::read(temp.path().join("watch/state.json")).unwrap(),
            before
        );
    }
}

#[test]
fn opening_missing_or_unsafe_journal_directories_never_recreates_them() {
    for case in ["missing", "symlink", "permissions"] {
        let (temp, mut watch) = fixture();
        if case != "missing" {
            Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
            let path = temp.path().join("watch/journal/objects");
            if case == "symlink" {
                // An empty private target would pass every other check.
                let elsewhere = temp.path().join("elsewhere");
                fs::create_dir(&elsewhere).unwrap();
                fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o700)).unwrap();
                fs::remove_dir(&path).unwrap();
                symlink(&elsewhere, &path).unwrap();
            } else {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let result = Journal::open(&mut watch, ID, Limits::default());
        assert!(
            match case {
                "missing" => matches!(
                    &result,
                    Err(Error::Storage(error)) if error.kind() == std::io::ErrorKind::NotFound
                ),
                "symlink" => matches!(result, Err(Error::Storage(_))),
                _ => matches!(result, Err(Error::Corrupt)),
            },
            "{case}"
        );
        if case == "missing" {
            assert!(!temp.path().join("watch/journal").exists());
        }
    }
}

#[test]
fn all_page_kinds_fit_at_maximum_fanout_and_hashes_are_domain_separated() {
    use crate::{payment::PaymentState, Checkpoint};
    use sha2::{Digest, Sha256};
    let point = Outpoint {
        txid: Hex([0xfe; 32]),
        index: u32::MAX,
    };
    for kind in [
        Kind::Lineages,
        Kind::Aliases,
        Kind::Reservations,
        Kind::History,
    ] {
        let records: Vec<_> = (0..16)
            .map(|n| match kind {
                Kind::Aliases => alias(n, u64::MAX),
                Kind::Lineages => Entry {
                    key: Key::id(id(n)),
                    value: Value::Lineage {
                        capability: Hex([0xff; 32]),
                        location: object::Location::Archived,
                        proposal_id: Hex([0xff; 32]),
                        revision: u64::MAX,
                    },
                },
                Kind::Reservations => Entry {
                    key: Key::reservation(point, u32::MAX, id(n)),
                    value: Value::Reservation,
                },
                Kind::History => Entry {
                    key: Key::sequence(n),
                    value: Value::History {
                        capability: Hex([0xff; 32]),
                        checkpoint: Checkpoint {
                            height: u32::MAX,
                            hash: Hex([0xff; 32]),
                        },
                        lineage_id: Hex([0xff; 32]),
                        proposal_id: Hex([0xff; 32]),
                        state: PaymentState::Conflicted,
                    },
                },
            })
            .collect();
        let page = Page::leaf(ID, kind, records);
        let encoded = page.encode().unwrap();
        assert!(encoded.bytes.len() <= PAGE_BYTES);
        assert_eq!(Page::decode(&encoded.bytes, ID, kind).unwrap(), page);
        let mut reference = Sha256::new();
        reference.update(b"ZcashTransparentPQ/wallet-journal-object/v1\0");
        reference.update(&encoded.bytes);
        assert_eq!(encoded.hash, Hex(reference.finalize().into()));
        assert_ne!(
            encoded.hash.0,
            <[u8; 32]>::from(Sha256::digest(&encoded.bytes))
        );
    }
    let children = (0..16)
        .map(|n| {
            Page::leaf(
                ID,
                Kind::Reservations,
                (0..16)
                    .map(|i| Entry {
                        key: Key::reservation(point, u32::MAX, id(n * 16 + i)),
                        value: Value::Reservation,
                    })
                    .collect(),
            )
            .reference()
            .unwrap()
        })
        .collect();
    let branch = Page::branch(ID, Kind::Reservations, 1, children);
    assert!(branch.encode().unwrap().bytes.len() <= PAGE_BYTES);
    let mut overlap = branch.clone();
    overlap.children[1] = overlap.children[0].clone();
    assert!(matches!(overlap.encode(), Err(Error::Corrupt)));
    let mut wrong_level = branch;
    wrong_level.children[0].level = 1;
    assert!(matches!(wrong_level.encode(), Err(Error::Corrupt)));
}

#[test]
fn corrupted_child_bounds_counts_and_journal_identity_cannot_prove_absence() {
    for case in ["min", "max", "count", "journal"] {
        let (temp, mut watch) = fixture();
        let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
        let mut snapshot = populated(&mut journal, 17);
        let mut parent = Page::decode(
            &fs::read(object_path(&temp, snapshot.root.as_ref().unwrap().hash)).unwrap(),
            ID,
            Kind::Aliases,
        )
        .unwrap();
        match case {
            "min" => parent.children[0].min = Key::id(id(1)),
            "max" => parent.children[0].max = Key::id(id(17)),
            "count" => parent.children[0].count -= 1,
            "journal" => parent.journal_id = Hex([8; 16]),
            _ => unreachable!(),
        }
        let object = parent.encode().unwrap();
        let path = object_path(&temp, object.hash);
        fs::write(&path, &object.bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        snapshot.root = Some(parent.reference().unwrap());
        assert!(
            matches!(
                journal.get(&snapshot, &Key::id(id(15)), &mut budget()),
                Err(Error::Corrupt)
            ),
            "{case}"
        );
    }
}

#[test]
fn page_cache_is_bounded_and_eviction_charges_another_read() {
    let (_temp, mut watch) = fixture();
    let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
    let mut batch = Batch::new(ID);
    let references: Vec<_> = (0..=CACHE_PAGES)
        .map(|n| {
            batch
                .page(
                    &Page::leaf(ID, Kind::Aliases, vec![alias(n as u64, 0)]),
                    Limits::default(),
                )
                .unwrap()
        })
        .collect();
    journal.publish(&batch, |_| Ok(())).unwrap();
    let mut reads = budget();
    for reference in &references {
        journal
            .load_page(reference, Kind::Aliases, true, None, &mut reads)
            .unwrap();
    }
    assert_eq!(journal.cache.len(), CACHE_PAGES);
    assert_eq!(reads.reads, CACHE_PAGES as u32 + 1);
    journal
        .load_page(&references[0], Kind::Aliases, true, None, &mut reads)
        .unwrap();
    assert_eq!(reads.reads, CACHE_PAGES as u32 + 2);
    assert_eq!(journal.cache.len(), CACHE_PAGES);
}

#[test]
fn budget_failure_during_an_edit_cannot_publish_an_earlier_partial_batch() {
    let (_temp, mut watch) = fixture();
    let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
    let snapshot = populated(&mut journal, 24);
    let count = journal.used_objects;
    let mut batch = Batch::new(ID);
    let updated = journal
        .insert(&mut batch, &snapshot, alias(2, 1), &mut budget())
        .unwrap();
    assert!(!batch.objects.is_empty());
    assert!(matches!(
        journal.insert(
            &mut batch,
            &updated,
            alias(48, 1),
            &mut ReadBudget::new(0).unwrap()
        ),
        Err(Error::LookupLimit)
    ));
    assert!(matches!(
        journal.publish(&batch, |_| Ok(())),
        Err(Error::InvalidBatch)
    ));
    assert_eq!(journal.used_objects, count);
    assert_eq!(
        journal
            .get(&snapshot, &Key::id(id(2)), &mut budget())
            .unwrap(),
        Some(alias(2, 0).value)
    );
}

#[test]
fn publication_rejects_existing_wrong_bytes_and_poisoning_is_not_error_type_dependent() {
    for case in ["existing", "limit_hook"] {
        let (temp, mut watch) = fixture();
        let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
        let mut batch = Batch::new(ID);
        let reference = batch
            .page(
                &Page::leaf(ID, Kind::Aliases, vec![alias(2, 0)]),
                Limits::default(),
            )
            .unwrap();
        if case == "existing" {
            let path = object_path(&temp, reference.hash);
            fs::write(&path, b"wrong").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(matches!(
                journal.publish(&batch, |_| Ok(())),
                Err(Error::Corrupt)
            ));
            assert_eq!(fs::read(path).unwrap(), b"wrong");
        } else {
            assert!(matches!(
                journal.publish(&batch, |stage| if stage == Stage::ObjectsSync {
                    Err(Error::Limit)
                } else {
                    Ok(())
                }),
                Err(Error::Limit)
            ));
        }
        assert!(matches!(
            journal.publish(&batch, |_| Ok(())),
            Err(Error::ReopenRequired)
        ));
    }
}

#[test]
fn legacy_v1_copy_and_existing_copy_safety_checks() {
    for case in ["v1", "symlink", "permissions", "directory"] {
        let (temp, watch) = fixture();
        let root = temp.path().join("watch/state.json");
        drop(watch);
        if case == "v1" {
            let mut state: serde_json::Value =
                serde_json::from_slice(&fs::read(&root).unwrap()).unwrap();
            state["format"] = "ZcashTransparentPQ/watch-state/v1".into();
            state.as_object_mut().unwrap().remove("payments");
            fs::write(&root, serde_json::to_vec(&state).unwrap()).unwrap();
        }
        let before = fs::read(&root).unwrap();
        let mut watch = reopen(&temp);
        let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
        let saved = journal.save_legacy(|_| Ok(())).unwrap();
        assert_eq!(fs::read(&saved).unwrap(), before);
        if case != "v1" {
            match case {
                "symlink" => {
                    fs::remove_file(&saved).unwrap();
                    symlink(&root, &saved).unwrap();
                }
                "permissions" => {
                    fs::set_permissions(&saved, fs::Permissions::from_mode(0o644)).unwrap()
                }
                "directory" => {
                    fs::remove_file(&saved).unwrap();
                    fs::create_dir(&saved).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(matches!(
                journal.save_legacy(|_| Ok(())),
                Err(Error::Corrupt | Error::Storage(_))
            ));
        }
        assert_eq!(fs::read(root).unwrap(), before);
    }
}

#[test]
fn capabilities_preserve_public_fixture_proposals_partials_and_signed_bytes() {
    use crate::payment::{Intent, Partial, PaymentRecord, PaymentState, Proposal, Remainder};
    use zakura_chain::{
        serialization::ZcashSerialize, transaction::Transaction, transparent::Input,
    };
    use zakura_pq_slh_dsa_b_exp::{Authorization, Record};
    // Independent public format fixtures. Signatures here are structural bytes,
    // not cryptographic claims: journal readers preserve authority verbatim.
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
    ))
    .unwrap();
    let manifest =
        Manifest::from_json(corpus["inventory_json"].as_str().unwrap().as_bytes()).unwrap();
    for row in corpus["proposals"].as_array().unwrap() {
        let proposal =
            Proposal::from_json(row["proposal_json"].as_str().unwrap().as_bytes()).unwrap();
        let mut partial: Partial =
            serde_json::from_str(corpus["partial_json"].as_str().unwrap()).unwrap();
        partial.input_index = 0;
        partial.signer_index = 0;
        partial.proposal_id = proposal.id().unwrap();
        let record = Record {
            index: 0,
            public_key: hex::decode(&partial.public_key_hex)
                .unwrap()
                .try_into()
                .unwrap(),
            signature: hex::decode(&partial.signature_hex)
                .unwrap()
                .into_boxed_slice()
                .try_into()
                .unwrap(),
        };
        let local = vec![partial];
        let mut signed = proposal.transaction().unwrap();
        let inputs = match &mut signed {
            Transaction::V5 { inputs, .. } | Transaction::V6 { inputs, .. } => inputs,
            _ => unreachable!(),
        };
        let Input::PrevOut { unlock_script, .. } = &mut inputs[0] else {
            unreachable!()
        };
        *unlock_script = zakura_chain::transparent::Script::new(
            &Authorization {
                policy: proposal.inputs[0].entry.policy().unwrap(),
                records: vec![record],
            }
            .encode(),
        );
        let signed_hex = hex::encode(signed.zcash_serialize_to_vec().unwrap());
        let record = PaymentRecord {
            intent: Intent {
                amount: 20_000,
                max_fee: 100_000,
                receiver: proposal.outputs[0].receiver.clone(),
                receiver_activation_height: None,
                remainder: Remainder::Keep,
                version: Some(signed.version() as u8),
            },
            partials: local,
            proposal,
            signed_transaction_hex: Some(signed_hex),
            state: PaymentState::Signed,
        };
        let capability = Capability::initial(ID, &record).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let mut watch = create(&temp.path().join("watch"), &manifest, WatchMode::Allocator);
        let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
        let mut batch = Batch::new(ID);
        let hash = batch
            .capability(
                &capability,
                &manifest,
                manifest.change_end,
                Limits::default(),
            )
            .unwrap();
        journal.publish(&batch, |_| Ok(())).unwrap();
        let loaded = journal
            .capability(hash, &manifest, manifest.change_end)
            .unwrap();
        assert_eq!(loaded.proposal, record.proposal);
        assert_eq!(loaded.partials, record.partials);
        assert_eq!(loaded.signed_transaction_hex, record.signed_transaction_hex);
        assert_eq!(loaded.intent, record.intent);
        let mut retry = Batch::new(ID);
        assert_eq!(
            retry
                .capability(&loaded, &manifest, manifest.change_end, Limits::default())
                .unwrap(),
            hash
        );
        journal.publish(&retry, |_| Ok(())).unwrap();
        assert_eq!(journal.used_objects, 1);
        for case in [
            "revision", "lineage", "journal", "change", "partial", "signed",
        ] {
            let mut changed = capability.clone();
            let mut change_next = manifest.change_end;
            match case {
                "revision" => changed.revision = 1,
                "lineage" => changed.lineage_id.0[0] ^= 1,
                "journal" => changed.journal_id = Hex([8; 16]),
                "change" => change_next = 0,
                "partial" => {
                    // Keep the saved partial's valid input index; change only its proposal.
                    let mut p = capability.partials[0].clone();
                    p.proposal_id = id(0);
                    changed.partials = vec![p];
                }
                "signed" => changed.signed_transaction_hex = Some("00".into()),
                _ => unreachable!(),
            }
            let mut bad = Batch::new(ID);
            assert!(
                matches!(
                    bad.capability(&changed, &manifest, change_next, Limits::default()),
                    Err(Error::Corrupt)
                ),
                "{case}"
            );
            assert!(matches!(
                journal.publish(&bad, |_| Ok(())),
                Err(Error::InvalidBatch)
            ));
        }
    }
}

#[test]
fn complete_snapshot_traversal_checks_unvisited_descendant_pages() {
    let (temp, mut watch) = fixture();
    let mut journal = Journal::create(&mut watch, ID, Limits::default(), |_| Ok(())).unwrap();
    let snapshot = populated(&mut journal, 257);
    let mut reachable = std::collections::BTreeSet::new();
    journal
        .validate_snapshot_pages(&snapshot, &mut reachable)
        .unwrap();
    assert!(reachable.len() > 16);
    let page = journal
        .load_page(
            snapshot.root.as_ref().unwrap(),
            Kind::Aliases,
            true,
            None,
            &mut budget(),
        )
        .unwrap();
    let missing = page.children.last().unwrap().hash;
    fs::remove_file(object_path(&temp, missing)).unwrap();
    drop(journal);
    let mut journal = Journal::open(&mut watch, ID, Limits::default()).unwrap();
    assert!(journal
        .get(
            &snapshot,
            &snapshot.root.as_ref().unwrap().min,
            &mut budget()
        )
        .unwrap()
        .is_some());
    assert!(journal
        .validate_snapshot_pages(&snapshot, &mut std::collections::BTreeSet::new())
        .is_err());
}
