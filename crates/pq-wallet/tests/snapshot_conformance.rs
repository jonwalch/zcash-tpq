//! Independent receipt identities and companion bytes, without a node or terminal.
#![cfg(all(unix, feature = "experimental-slh-dsa-b128s"))]

use serde_json::Value;
use std::{fs, os::unix::fs::PermissionsExt};
use zakura_pq_wallet::{recovery::SnapshotReceipt, Error, Manifest, WatchMode, WatchStore};

fn corpus() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../../tests/slh-dsa-b128s/wallet/interfaces/vectors.json"
    ))
    .unwrap()
}

#[test]
fn snapshot_receipt_encoding_and_every_identity_component_match_independent_answers() {
    let corpus = corpus();
    let snapshot = &corpus["snapshot"];
    let raw = snapshot["receipt_json"].as_str().unwrap().as_bytes();
    let receipt = SnapshotReceipt::from_json(raw).unwrap();
    assert_eq!(receipt.to_json().unwrap(), raw);
    assert_eq!(
        hex::encode(receipt.fingerprint().unwrap().0),
        snapshot["fingerprint"]
    );
    assert_eq!(receipt.generation(), None);
    for changed in snapshot["valid_identity_mutations"].as_array().unwrap() {
        let raw = changed["json"].as_str().unwrap().as_bytes();
        let candidate = SnapshotReceipt::from_json(raw).unwrap();
        assert_eq!(candidate.to_json().unwrap(), raw);
        assert_eq!(
            hex::encode(candidate.fingerprint().unwrap().0),
            changed["fingerprint"],
            "{}",
            changed["field"]
        );
        assert_ne!(
            candidate.fingerprint().unwrap(),
            receipt.fingerprint().unwrap(),
            "{}",
            changed["field"]
        );
        if changed["field"] == "journal identity boundary (syntax only)" {
            assert_eq!(candidate.generation(), Some(u64::MAX));
        }
    }
}

#[test]
fn snapshot_receipt_rejects_independent_schema_and_canonical_mutations() {
    let cases = corpus()["snapshot"]["invalid_receipts"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(cases.len(), 9);
    for case in cases {
        let reason = case["reason"].as_str().unwrap();
        let result = SnapshotReceipt::from_json(case["json"].as_str().unwrap().as_bytes());
        let matched = match reason {
            "byte limit" => matches!(result, Err(Error::Limits)),
            "suite" => matches!(result, Err(Error::UnsupportedFormat)),
            "profile.network" => matches!(result, Err(Error::UnsupportedContext)),
            "receive_next" | "journal.generation" | "journal.journal_id" => {
                matches!(result, Err(Error::RecoveryIncomplete))
            }
            "trailing newline" | "duplicate field" | "unknown field" => {
                matches!(result, Err(Error::Encoding))
            }
            _ => panic!("unexpected invalid receipt case: {reason}"),
        };
        assert!(matched, "{reason}: {:?}", result.err());
    }
}

#[test]
fn captured_v2_snapshot_matches_independent_state_backup_and_retained_object_answers() {
    let corpus = corpus();
    let answer = &corpus["snapshot"];
    let formats: Value = serde_json::from_slice(include_bytes!(
        "../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
    ))
    .unwrap();
    let inventory = formats["inventory_json"].as_str().unwrap().as_bytes();
    let manifest = Manifest::from_json(inventory).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let watch_path = directory.path().join("watch");
    let mut watch = WatchStore::create(
        &watch_path,
        inventory,
        manifest.fingerprint().unwrap(),
        &manifest.profile,
        WatchMode::Allocator,
    )
    .unwrap();
    watch.receive().unwrap();
    assert_eq!(
        fs::read(watch_path.join("state.json")).unwrap(),
        answer["state_json"].as_str().unwrap().as_bytes()
    );
    fs::create_dir(watch_path.join("journal")).unwrap();
    fs::create_dir(watch_path.join("journal/objects")).unwrap();
    for path in ["journal", "journal/objects"] {
        fs::set_permissions(watch_path.join(path), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let retained = hex::decode(answer["retained_object_hex"].as_str().unwrap()).unwrap();
    let retained_path = "journal/objects/.object-retained";
    fs::write(watch_path.join(retained_path), &retained).unwrap();
    fs::set_permissions(
        watch_path.join(retained_path),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let backup = directory.path().join("backup.tpq");
    let encrypted = hex::decode(formats["backup"]["file_hex"].as_str().unwrap()).unwrap();
    fs::write(&backup, &encrypted).unwrap();
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o600)).unwrap();
    let password = hex::decode(formats["backup"]["password_utf8_hex"].as_str().unwrap()).unwrap();
    let destination = directory.path().join("snapshot");
    let receipt = watch
        .save_operational_snapshot(&backup, &password, &destination)
        .unwrap();
    assert_eq!(
        receipt.to_json().unwrap(),
        answer["receipt_json"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        hex::encode(receipt.fingerprint().unwrap().0),
        answer["fingerprint"]
    );
    for (path, expected) in [
        (
            "receipt.json",
            answer["receipt_json"].as_str().unwrap().as_bytes(),
        ),
        (
            "watch/state.json",
            answer["state_json"].as_str().unwrap().as_bytes(),
        ),
        ("backup.tpq", encrypted.as_slice()),
        (
            "watch/journal/objects/.object-retained",
            retained.as_slice(),
        ),
    ] {
        assert_eq!(
            fs::read(destination.join(path)).unwrap(),
            expected,
            "{path}"
        );
    }
}
