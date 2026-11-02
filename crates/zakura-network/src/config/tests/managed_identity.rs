//! Managed identity is durable and fail-closed through the public config API.

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use crate::config::{Config, ZakuraNodeSecretKey, ZakuraSecretKeyError};
use zakura_quic::NodeSecretKey;

fn setup() -> (tempfile::TempDir, Config, PathBuf) {
    let parent = tempfile::tempdir().unwrap();
    let mut config: Config =
        toml::from_str(&super::custom_slh_config(super::CUSTOM_SLH_FIELDS)).unwrap();
    config.identity_dir = parent.path().join("identities");
    let path = super::super::zakura_secret_key_file_path(&config.identity_dir, &config.network);
    (parent, config, path)
}

#[test]
fn managed_identity_survives_restart_and_never_replaces_pinned_or_corrupt_keys() {
    let (_parent, mut config, path) = setup();
    let id = config.ensure_managed_zakura_identity().unwrap();
    assert_eq!(
        fs::metadata(&config.identity_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let original = fs::read(&path).unwrap();
    assert_eq!(config.ensure_managed_zakura_identity().unwrap(), id);
    config.zakura.expected_node_id = Some(id);
    let serialized = toml::to_string(&config).unwrap();
    let mut restored: Config = toml::from_str(&serialized).unwrap();
    assert_eq!(restored.zakura_secret_key().unwrap().public(), id);
    restored.zakura.expected_node_id = Some(NodeSecretKey::from_bytes(&[43; 32]).public());
    assert!(matches!(
        restored.zakura_secret_key(),
        Err(ZakuraSecretKeyError::ManagedMismatch)
    ));
    assert!(fs::read(&path).unwrap() == original);

    config.zakura_node_secret_key = Some(
        serde_json::from_value::<ZakuraNodeSecretKey>(serde_json::json!("2a".repeat(32))).unwrap(),
    );
    assert!(matches!(
        config.ensure_managed_zakura_identity(),
        Err(ZakuraSecretKeyError::ManagedOverride)
    ));
    config.zakura_node_secret_key = None;
    fs::write(&path, b"invalid-key").unwrap();
    assert!(config.zakura_secret_key().is_err());
    assert!(config.ensure_managed_zakura_identity().is_err());
    assert!(fs::read(&path).unwrap() == b"invalid-key");
    fs::remove_file(&path).unwrap();
    assert!(config.ensure_managed_zakura_identity().is_err());
    assert!(!path.exists());
}

#[test]
fn managed_identity_refuses_unsafe_files_and_unwritable_storage() {
    use std::os::unix::fs::symlink;
    for mode in [0o755, 0o500] {
        let (_parent, config, path) = setup();
        fs::create_dir(&config.identity_dir).unwrap();
        fs::set_permissions(&config.identity_dir, fs::Permissions::from_mode(mode)).unwrap();
        assert!(config.ensure_managed_zakura_identity().is_err());
        assert!(!path.exists());
    }
    for kind in [
        "corrupt", "oversize", "public", "symlink", "hardlink", "fifo",
    ] {
        let (parent, config, path) = setup();
        config.ensure_managed_zakura_identity().unwrap();
        match kind {
            "corrupt" => fs::write(&path, b"not-a-key").unwrap(),
            "oversize" => fs::write(&path, vec![b'0'; 129]).unwrap(),
            "public" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "symlink" => {
                let outside = parent.path().join("outside");
                fs::rename(&path, &outside).unwrap();
                symlink(outside, &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, parent.path().join("alias")).unwrap(),
            "fifo" => {
                fs::remove_file(&path).unwrap();
                rustix::fs::mkfifoat(
                    rustix::fs::CWD,
                    &path,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(config.ensure_managed_zakura_identity().is_err(), "{kind}");
    }
    let (parent, mut config, _path) = setup();
    let target = parent.path().join("target");
    fs::create_dir(&target).unwrap();
    symlink(&target, &config.identity_dir).unwrap();
    assert!(config.ensure_managed_zakura_identity().is_err());
    assert!(fs::read_dir(target).unwrap().next().is_none());
    config.identity_dir = parent.path().join("missing-parent/identity");
    assert!(config.ensure_managed_zakura_identity().is_err());
    config.identity_dir = PathBuf::from("relative-identity");
    assert!(config.ensure_managed_zakura_identity().is_err());
}

#[test]
fn concurrent_managed_ensure_keeps_one_persisted_identity() {
    let (_parent, config, _path) = setup();
    let workers: Vec<_> = (0..3)
        .map(|_| {
            let config = config.clone();
            std::thread::spawn(move || config.ensure_managed_zakura_identity())
        })
        .collect();
    let id = config.ensure_managed_zakura_identity().unwrap();
    for worker in workers {
        assert_eq!(worker.join().unwrap().unwrap(), id);
    }
}
