//! Preserved encrypted-backup and durable-publication controls against the independent SLH corpus.
use super::*;
use crate::tests::BACKUPS;
use rand_core::{CryptoRng, RngCore};
use serde_json::{json, Value};
use std::num::NonZeroU32;

struct TestRng {
    next: u8,
    calls: usize,
    fail_at: Option<usize>,
}
impl TestRng {
    fn new() -> Self {
        Self {
            next: 0,
            calls: 0,
            fail_at: None,
        }
    }
    fn failing(call: usize) -> Self {
        Self {
            fail_at: Some(call),
            ..Self::new()
        }
    }
}
impl CryptoRng for TestRng {}
impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        panic!("must use fallible randomness")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("must use fallible randomness")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("must use fallible randomness")
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        let call = self.calls;
        self.calls += 1;
        if self.fail_at == Some(call) {
            bytes.fill(0x77); // Even a partially written failed request must abort.
            return Err(rand_core::Error::from(
                NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
            ));
        }
        for byte in bytes {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
        Ok(())
    }
}
fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
    ))
    .unwrap()
}
fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}
fn manifest() -> Manifest {
    Manifest::from_json(corpus()["inventory_json"].as_str().unwrap().as_bytes()).unwrap()
}
fn fixture_wallet() -> Wallet {
    Wallet::from_plaintext(
        corpus()["recovery_json"].as_str().unwrap().as_bytes(),
        &manifest().profile,
    )
    .unwrap()
}

#[test]
fn rust_backup_matches_python_ciphertext_and_authentication_controls() {
    let _serial = BACKUPS.lock().unwrap();
    let corpus = corpus();
    let answer = &corpus["backup"];
    let password = bytes(&answer["password_utf8_hex"]);
    let original = bytes(&answer["file_hex"]);
    let wallet = fixture_wallet();
    assert_eq!(
        wallet.plaintext().unwrap().as_slice(),
        corpus["recovery_json"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        backup::key(&password, &original[24..40])
            .unwrap()
            .as_slice(),
        bytes(&answer["key_hex"])
    );
    assert_eq!(
        wallet
            .encrypt_with_rng(&password, &mut TestRng::new())
            .unwrap(),
        original
    );
    let restored = Wallet::decrypt(&original, &password, &wallet.manifest.profile).unwrap();
    assert_eq!(wallet.manifest, restored.manifest);
    assert_eq!(*wallet.root, *restored.root);
    assert!(matches!(
        Wallet::decrypt(&original, b"wrong password", &wallet.manifest.profile),
        Err(Error::Authentication)
    ));
    let test_key: [u8; 32] = bytes(&answer["key_hex"]).try_into().unwrap();
    for offset in [24, 40, 56, original.len() - 1] {
        let mut bad = original.clone();
        bad[offset] ^= 1;
        assert!(matches!(
            backup::decrypt_with(&bad, &password, |_, _| Ok(Zeroizing::new(test_key))),
            Err(Error::Authentication)
        ));
    }
    let first = wallet.encrypt(&password).unwrap();
    let second = wallet.encrypt(&password).unwrap();
    assert_ne!(&first[24..40], &second[24..40]);
    assert_ne!(&first[40..52], &second[40..52]);
    assert_eq!(
        Wallet::decrypt(&second, &password, &wallet.manifest.profile)
            .unwrap()
            .manifest,
        wallet.manifest
    );
}

#[test]
fn header_and_entropy_failures_never_reach_the_kdf() {
    let corpus = corpus();
    let blob = bytes(&corpus["backup"]["file_hex"]);
    let forbidden = |_: &[u8], _: &[u8]| -> Result<Zeroizing<[u8; 32]>, Error> {
        panic!("invalid header reached KDF")
    };
    for offset in [0, 8, 9, 10, 11, 12, 16, 20, 52] {
        let mut bad = blob.clone();
        bad[offset] ^= 1;
        assert!(backup::decrypt_with(&bad, b"password", forbidden).is_err());
    }
    for bad in [
        blob[..55].to_vec(),
        blob[..blob.len() - 1].to_vec(),
        [blob.clone(), vec![0]].concat(),
    ] {
        assert!(backup::decrypt_with(&bad, b"password", forbidden).is_err());
    }
    for password in [vec![], vec![b'x'; 1025], vec![0xff]] {
        assert!(matches!(
            backup::decrypt_with(&blob, &password, forbidden),
            Err(Error::Password)
        ));
    }
    let wallet = fixture_wallet();
    for call in 0..2 {
        assert!(matches!(
            wallet.encrypt_with_rng(b"public test password", &mut TestRng::failing(call)),
            Err(Error::Entropy)
        ));
    }
}

#[test]
fn recovery_schema_profile_and_owned_commitments_are_mandatory() {
    let corpus = corpus();
    let raw = corpus["recovery_json"].as_str().unwrap().as_bytes();
    let profile = manifest().profile;
    let mut wrong_profile = profile.clone();
    Wallet::from_plaintext(raw, &profile).unwrap();
    wrong_profile.genesis_hash.0[0] ^= 1;
    assert!(matches!(
        Wallet::from_plaintext(raw, &wrong_profile),
        Err(Error::UnsupportedContext)
    ));
    let original: Value = serde_json::from_slice(raw).unwrap();
    let mut bad = original.clone();
    bad["root_hex"] = "00".repeat(32).into();
    assert!(matches!(
        Wallet::from_plaintext(&serde_json::to_vec(&bad).unwrap(), &profile),
        Err(Error::Policy)
    ));
    for field in ["network", "max_tx_pq_checks", "nu7_activation_height"] {
        let mut bad = original.clone();
        bad["manifest"]["profile"][field] = 0.into();
        assert!(matches!(
            Wallet::from_plaintext(&serde_json::to_vec(&bad).unwrap(), &profile),
            Err(Error::UnsupportedContext)
        ));
    }
    let mut empty = original.clone();
    empty["manifest"]["receive_end"] = 0.into();
    empty["manifest"]["change_end"] = 0.into();
    empty["manifest"]["entries"] = json!([]);
    assert!(Wallet::from_plaintext(&serde_json::to_vec(&empty).unwrap(), &profile).is_ok());
    for value in [json!({}), json!(""), Value::Null, json!(0), json!(false)] {
        let mut bad = empty.clone();
        bad["manifest"]["entries"] = value;
        assert!(Wallet::from_plaintext(&serde_json::to_vec(&bad).unwrap(), &profile).is_err());
    }
    let mut bad = original.clone();
    bad["manifest"]["entries"][0]["origins"] = json!({});
    assert!(Wallet::from_plaintext(&serde_json::to_vec(&bad).unwrap(), &profile).is_err());
    let mut bad = original.clone();
    bad["root_hex"] = bad["root_hex"].as_str().unwrap().to_uppercase().into();
    assert!(Wallet::from_plaintext(&serde_json::to_vec(&bad).unwrap(), &profile).is_err());
    let mut bad = original.clone();
    bad["manifest"]["secret"] = "not allowed".into();
    assert!(Wallet::from_plaintext(&serde_json::to_vec(&bad).unwrap(), &profile).is_err());
    for bad in [
        String::from_utf8(raw.to_vec()).unwrap() + "\n",
        String::from_utf8(raw.to_vec())
            .unwrap()
            .replacen("{", "{\"format\":\"duplicate\",", 1),
    ] {
        assert!(Wallet::from_plaintext(bad.as_bytes(), &profile).is_err());
    }
    let too_many = [
        b"{\"allocator_id\":\"00000000000000000000000000000000\",\"entries\":".as_slice(),
        serde_json::to_vec(&vec![
            original["manifest"]["entries"][0].clone();
            MAX_ENTRIES + 1
        ])
        .unwrap()
        .as_slice(),
        b"}",
    ]
    .concat();
    assert!(Manifest::from_json(&too_many).is_err());
}

#[test]
fn authenticated_plaintext_still_requires_the_complete_recovery_schema() {
    use chacha20poly1305::{
        aead::{AeadInPlace, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    let _serial = BACKUPS.lock().unwrap();
    let corpus = corpus();
    let original = bytes(&corpus["backup"]["file_hex"]);
    let password = bytes(&corpus["backup"]["password_utf8_hex"]);
    let key: [u8; 32] = bytes(&corpus["backup"]["key_hex"]).try_into().unwrap();
    let profile = manifest().profile;
    for case in 0..2u8 {
        let mut value: Value =
            serde_json::from_str(corpus["recovery_json"].as_str().unwrap()).unwrap();
        if case == 0 {
            value["manifest"]["receive_end"] = 0.into();
            value["manifest"]["change_end"] = 0.into();
            value["manifest"]["entries"] = json!({});
        } else {
            value["root_hex"] = "00".repeat(32).into();
        }
        let mut plaintext = serde_json::to_vec(&value).unwrap();
        let mut header = original[..56].to_vec();
        // Distinct public test nonces, separate from the corpus known answer.
        header[40..52].fill(0x80 + case);
        header[52..56].copy_from_slice(&u32::try_from(plaintext.len() + 16).unwrap().to_le_bytes());
        let tag = ChaCha20Poly1305::new((&key).into())
            .encrypt_in_place_detached(Nonce::from_slice(&header[40..52]), &header, &mut plaintext)
            .unwrap();
        let blob = [header, plaintext, tag.to_vec()].concat();
        let result = Wallet::decrypt(&blob, &password, &profile);
        assert!(if case == 0 {
            matches!(result, Err(Error::Encoding))
        } else {
            matches!(result, Err(Error::Policy))
        });
    }
}

#[cfg(unix)]
#[test]
fn backup_publication_is_private_noclobber_and_preserves_previous_generation_on_failures() {
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };
    let _serial = BACKUPS.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let wallet = Wallet::create_with_rng(manifest().profile, 0, &mut TestRng::new()).unwrap();
    let password = b"public storage test password";
    let old = directory.path().join("old.tpq");
    wallet.save_backup(&old, password).unwrap();
    let saved = fs::read(&old).unwrap();
    assert_eq!(
        fs::metadata(&old).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        Wallet::load_backup(&old, password, &wallet.manifest.profile)
            .unwrap()
            .manifest,
        wallet.manifest
    );
    assert!(wallet.save_backup(&old, password).is_err());
    let link = directory.path().join("link");
    symlink(&old, &link).unwrap();
    assert!(Wallet::load_backup(&link, password, &wallet.manifest.profile).is_err());
    assert!(wallet.save_backup(&link, password).is_err());
    let parent_link = directory.path().join("parent-link");
    symlink(directory.path(), &parent_link).unwrap();
    assert!(wallet
        .save_backup(&parent_link.join("new.tpq"), password)
        .is_err());
    for (i, failure) in [
        storage::Stage::Write,
        storage::Stage::FileSync,
        storage::Stage::Verify,
        storage::Stage::Publish,
        storage::Stage::DirectorySync,
    ]
    .into_iter()
    .enumerate()
    {
        let new = directory.path().join(format!("failed-{i}.tpq"));
        let result = wallet.save_with_hook(&new, password, |stage| {
            if stage == failure {
                Err(Error::Storage(std::io::Error::other("injected failure")))
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(Error::Storage(_))));
        assert_eq!(fs::read(&old).unwrap(), saved);
        assert_eq!(new.exists(), failure == storage::Stage::DirectorySync);
    }
    let race = directory.path().join("race.tpq");
    assert!(wallet
        .save_with_hook(&race, password, |stage| {
            if stage == storage::Stage::Publish {
                fs::write(&race, b"existing generation").unwrap();
            }
            Ok(())
        })
        .is_err());
    assert_eq!(fs::read(&race).unwrap(), b"existing generation");
    assert!(fs::read_dir(directory.path()).unwrap().all(|item| !item
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".tpq-backup-")));
    fs::set_permissions(&old, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Wallet::load_backup(&old, password, &wallet.manifest.profile).is_err());
}
