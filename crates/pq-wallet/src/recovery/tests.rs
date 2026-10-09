use super::*;
use crate::{tests::BACKUPS, watch::tests::profile};
use std::os::unix::fs::{symlink, PermissionsExt};

const PASSWORD: &[u8] = b"public recovery unit-test password";

fn wallet() -> Wallet {
    Wallet::create(profile(), 0).unwrap()
}
fn store(path: &Path, wallet: &Wallet) -> WatchStore {
    WatchStore::create(
        path,
        &wallet.manifest().to_json().unwrap(),
        wallet.manifest().fingerprint().unwrap(),
        &profile(),
        WatchMode::Allocator,
    )
    .unwrap()
}
fn failed() -> Error {
    Error::Storage(std::io::Error::other(
        "injected recovery publication failure",
    ))
}

#[test]
fn encrypted_inventory_restore_retires_ranges_and_stays_monitor_only() {
    let _serial = BACKUPS.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let backup = directory.path().join("original.tpq");
    let mut wallet = wallet();
    wallet
        .extend_single_backup(1, 1, &backup, PASSWORD)
        .unwrap();
    let original = wallet.manifest().clone();
    let destination = directory.path().join("restored");
    let mut restored = restore_inventory(
        &backup,
        PASSWORD,
        &profile(),
        original.fingerprint().unwrap(),
        &destination,
    )
    .unwrap();
    assert_eq!(restored.authority, SnapshotTrust::Unknown);
    assert_eq!(restored.watch.mode(), WatchMode::Monitor);
    assert_eq!(restored.wallet.manifest().entries, original.entries);
    assert_eq!(restored.wallet.manifest().retired_receive_end, 1);
    assert_eq!(restored.wallet.manifest().retired_change_end, 1);
    assert_ne!(
        restored.wallet.manifest().allocator_id,
        original.allocator_id
    );
    assert!(!restored.watch.status().unwrap().complete_at_checkpoint);
    assert!(matches!(restored.watch.receive(), Err(Error::MonitorOnly)));
    assert_eq!(
        fs::read(destination.join("backup-original.tpq")).unwrap(),
        fs::read(&backup).unwrap()
    );
    assert_eq!(
        Wallet::load_backup(
            &destination.join("backup-restored.tpq"),
            PASSWORD,
            &profile()
        )
        .unwrap()
        .manifest(),
        restored.wallet.manifest()
    );
    drop(restored);
    assert_eq!(
        WatchStore::open(&destination.join("watch"), &profile())
            .unwrap()
            .mode(),
        WatchMode::Monitor
    );
    assert!(restore_inventory(
        &backup,
        PASSWORD,
        &profile(),
        Hex([9; 32]),
        &directory.path().join("wrong")
    )
    .is_err());
    assert!(!directory.path().join("wrong").exists());
}

#[test]
fn operational_snapshot_restores_from_only_documented_artifacts_and_requires_trust() {
    let _serial = BACKUPS.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let backup = directory.path().join("key.tpq");
    let wallet = wallet();
    wallet.save_backup(&backup, PASSWORD).unwrap();
    let original = directory.path().join("working");
    let mut watch = store(&original, &wallet);
    watch.migrate_payment_journal().unwrap();
    // Legitimate unreferenced retained files consume the existing journal quota
    // and must survive a whole-store recovery rather than being discarded.
    write_private(
        &original.join("journal/objects/.journal-retained"),
        b"orphan bytes",
    )
    .unwrap();
    // Non-authoritative root copies have no journal quota and are outside the
    // documented artifact set. They must neither block capture nor be removed.
    write_private(
        &original.join("state-pre-v3-public.json"),
        b"retained old copy",
    )
    .unwrap();
    write_private(
        &original.join(".watch-retained"),
        b"retained root temporary",
    )
    .unwrap();
    let snapshot = directory.path().join("snapshot");
    let receipt = watch
        .save_operational_snapshot(&backup, PASSWORD, &snapshot)
        .unwrap();
    assert!(receipt.generation().is_some());
    assert!(original.join("state-pre-v3-public.json").exists());
    assert!(original.join(".watch-retained").exists());
    assert!(!snapshot.join("watch/state-pre-v3-public.json").exists());
    assert!(!snapshot.join("watch/.watch-retained").exists());
    let trusted = SnapshotTrust::KnownAuthority {
        trusted_receipt: receipt.fingerprint().unwrap(),
    };
    drop(watch);
    fs::remove_dir_all(&original).unwrap();
    fs::remove_file(&backup).unwrap();
    let restored = restore_operational_snapshot(
        &snapshot,
        PASSWORD,
        &profile(),
        trusted,
        &directory.path().join("known"),
    )
    .unwrap();
    assert_eq!(restored.authority, trusted);
    assert_eq!(restored.watch.mode(), WatchMode::Allocator);
    assert!(!restored.watch.status().unwrap().complete_at_checkpoint);
    assert_eq!(
        fs::read(
            directory
                .path()
                .join("known/watch/journal/objects/.journal-retained")
        )
        .unwrap(),
        b"orphan bytes"
    );
    assert_ne!(
        restored.wallet.manifest().allocator_id,
        wallet.manifest().allocator_id
    );
    let mut restored = restore_operational_snapshot(
        &snapshot,
        PASSWORD,
        &profile(),
        SnapshotTrust::Unknown,
        &directory.path().join("unknown"),
    )
    .unwrap();
    assert_eq!(restored.watch.mode(), WatchMode::Monitor);
    let mut chain = crate::watch::tests::Chain::new();
    restored.watch.sync(&mut chain, 10).unwrap();
    assert_eq!(restored.watch.mode(), WatchMode::Monitor);
    assert!(matches!(restored.watch.receive(), Err(Error::MonitorOnly)));
    drop(restored);
    assert_eq!(
        WatchStore::open(&directory.path().join("unknown/watch"), &profile())
            .unwrap()
            .mode(),
        WatchMode::Monitor
    );
    let wrong = SnapshotTrust::KnownAuthority {
        trusted_receipt: Hex([0; 32]),
    };
    assert!(matches!(
        restore_operational_snapshot(
            &snapshot,
            PASSWORD,
            &profile(),
            wrong,
            &directory.path().join("wrong")
        ),
        Err(Error::Pairing)
    ));
    assert!(!directory.path().join("wrong").exists());
}

#[test]
fn snapshot_rejects_changed_backup_state_unsafe_files_and_wrong_profile() {
    let _serial = BACKUPS.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let backup = directory.path().join("key.tpq");
    let wallet = wallet();
    wallet.save_backup(&backup, PASSWORD).unwrap();
    let mut watch = store(&directory.path().join("working"), &wallet);
    let snapshot = directory.path().join("snapshot");
    let receipt = watch
        .save_operational_snapshot(&backup, PASSWORD, &snapshot)
        .unwrap();
    let trust = SnapshotTrust::KnownAuthority {
        trusted_receipt: receipt.fingerprint().unwrap(),
    };
    let mut wrong_profile = profile();
    wrong_profile.genesis_hash.0[0] ^= 1;
    assert!(matches!(
        restore_operational_snapshot(
            &snapshot,
            PASSWORD,
            &wrong_profile,
            trust,
            &directory.path().join("wrong-profile")
        ),
        Err(Error::UnsupportedContext)
    ));
    let state = snapshot.join("watch/state.json");
    let saved = fs::read(&state).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    value["mode"] = "monitor".into();
    fs::write(&state, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(restore_operational_snapshot(
        &snapshot,
        PASSWORD,
        &profile(),
        trust,
        &directory.path().join("changed")
    )
    .is_err());
    fs::write(&state, saved).unwrap();
    let saved = fs::read(snapshot.join("backup.tpq")).unwrap();
    let mut damaged = saved.clone();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(snapshot.join("backup.tpq"), damaged).unwrap();
    assert!(matches!(
        restore_operational_snapshot(
            &snapshot,
            PASSWORD,
            &profile(),
            trust,
            &directory.path().join("corrupt")
        ),
        Err(Error::Authentication)
    ));
    fs::write(snapshot.join("backup.tpq"), saved).unwrap();
    let real_state = snapshot.join("watch/state-real.json");
    fs::rename(&state, &real_state).unwrap();
    symlink(&real_state, &state).unwrap();
    assert!(restore_operational_snapshot(
        &snapshot,
        PASSWORD,
        &profile(),
        trust,
        &directory.path().join("unsafe")
    )
    .is_err());
    assert!(!directory.path().join("unsafe").exists());
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".tpq-restore-")));
}

#[test]
fn directory_publication_is_atomic_private_and_never_clobbers_racing_destinations() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("published");
    let stage = staging(&destination).unwrap();
    write_private(&stage.path().join("complete"), b"complete").unwrap();
    assert!(publish(stage, &destination, &mut |point| {
        if point == RecoveryStage::Publish {
            fs::create_dir(&destination).unwrap();
            fs::write(destination.join("existing"), b"keep").unwrap();
        }
        Ok(())
    })
    .is_err());
    assert_eq!(fs::read(destination.join("existing")).unwrap(), b"keep");
    assert!(!destination.join("complete").exists());
    assert!(staging(&destination).is_err());
    for failure in [RecoveryStage::Publish, RecoveryStage::DirectorySync] {
        let target = directory.path().join(format!("failure-{failure:?}"));
        let stage = staging(&target).unwrap();
        write_private(&stage.path().join("complete"), b"complete").unwrap();
        assert!(publish(stage, &target, &mut |point| if point == failure {
            Err(failed())
        } else {
            Ok(())
        })
        .is_err());
        assert_eq!(target.exists(), failure == RecoveryStage::DirectorySync);
        if target.exists() {
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(target.join("complete"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".tpq-restore-")));
}

#[test]
fn every_local_root_is_checked_and_retirement_is_monotonic() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
    ))
    .unwrap();
    let original = corpus["recovery_json"].as_str().unwrap();
    let mut wallet = Wallet::from_plaintext(
        original.as_bytes(),
        &Profile::from_json(
            &serde_json::to_vec(
                &serde_json::from_str::<serde_json::Value>(original).unwrap()["manifest"]
                    ["profile"],
            )
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let profile = wallet.manifest().profile.clone();
    let value: serde_json::Value = serde_json::from_str(original).unwrap();
    for index in 0..wallet.manifest().entries.len() {
        let mut bad = value.clone();
        let mut descriptor = hex::decode(
            bad["manifest"]["entries"][index]["policy_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        descriptor[4] ^= 0x80;
        bad["manifest"]["entries"][index]["policy_hex"] = hex::encode(descriptor).into();
        assert!(matches!(
            Wallet::from_plaintext(&serde_json::to_vec(&bad).unwrap(), &profile),
            Err(Error::Policy)
        ));
    }
    let original = wallet.manifest().clone();
    wallet.retire_for_restore().unwrap();
    original.check_update(wallet.manifest()).unwrap();
    assert_eq!(wallet.manifest().entries, original.entries);
    assert_eq!(wallet.manifest().retired_receive_end, original.receive_end);
    assert_eq!(wallet.manifest().retired_change_end, original.change_end);
    let mut rollback = wallet.manifest().clone();
    rollback.revision += 1;
    rollback.retired_receive_end = 0;
    assert!(matches!(
        wallet.manifest().check_update(&rollback),
        Err(Error::RecoveryIncomplete)
    ));
}

#[test]
fn interrupted_v2_migration_directories_and_orphans_survive_capture_and_restore() {
    let _serial = BACKUPS.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let wallet = wallet();
    let backup = directory.path().join("key.tpq");
    wallet.save_backup(&backup, PASSWORD).unwrap();
    for with_objects in [false, true] {
        let original = directory.path().join(format!("working-{with_objects}"));
        let mut watch = store(&original, &wallet);
        create_directory(&original.join("journal")).unwrap();
        if with_objects {
            create_directory(&original.join("journal/objects")).unwrap();
            write_private(
                &original.join("journal/objects/.object-retained"),
                b"old incomplete migration",
            )
            .unwrap();
        }
        let snapshot = directory.path().join(format!("snapshot-{with_objects}"));
        let receipt = watch
            .save_operational_snapshot(&backup, PASSWORD, &snapshot)
            .unwrap();
        assert_eq!(receipt.generation(), None);
        drop(watch);
        fs::remove_dir_all(&original).unwrap();
        let destination = directory.path().join(format!("restored-{with_objects}"));
        let restored = restore_operational_snapshot(
            &snapshot,
            PASSWORD,
            &profile(),
            SnapshotTrust::Unknown,
            &destination,
        )
        .unwrap();
        assert_eq!(restored.watch.mode(), WatchMode::Monitor);
        assert!(destination.join("watch/journal").is_dir());
        assert_eq!(
            destination.join("watch/journal/objects").exists(),
            with_objects
        );
        if with_objects {
            assert_eq!(
                fs::read(destination.join("watch/journal/objects/.object-retained")).unwrap(),
                b"old incomplete migration"
            );
        }
    }
}
