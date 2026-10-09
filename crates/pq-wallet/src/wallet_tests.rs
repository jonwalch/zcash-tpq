//! Focused foundation controls; private fixtures do not establish durable enrollment.
use super::*;
use rand_core::{CryptoRng, RngCore};
use std::{num::NonZeroU32, sync::Arc};
use zakura_chain::{
    block::Height,
    parameters::NetworkUpgrade,
    transaction::{Hash, LockTime, Transaction},
    transparent::{Input, OutPoint, Output, Script},
};
use zakura_pq_tx_context::NetworkDomain;

struct TestRng {
    next: u8,
    calls: Vec<usize>,
    fail_at: Option<usize>,
}
impl TestRng {
    fn new() -> Self {
        Self {
            next: 0,
            calls: vec![],
            fail_at: None,
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
        let call = self.calls.len();
        self.calls.push(bytes.len());
        if self.fail_at == Some(call) {
            bytes.fill(0x77);
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

fn profile() -> Profile {
    Profile {
        genesis_hash: Hex([0x42; 32]),
        max_block_pq_checks: 64,
        max_tx_pq_checks: 16,
        network: 2,
        nu7_activation_height: 100,
        nu7_branch_id: "77190ad9".into(),
        pq_activation_height: 101,
    }
}

#[test]
fn creation_uses_three_fallible_requests_and_issues_no_receiver() {
    for fail_at in 0..3 {
        let mut rng = TestRng {
            fail_at: Some(fail_at),
            ..TestRng::new()
        };
        assert!(matches!(
            Wallet::create_with_rng(profile(), 12, &mut rng),
            Err(Error::Entropy)
        ));
        assert_eq!(rng.calls.len(), fail_at + 1);
    }
    let mut rng = TestRng::new();
    let wallet = Wallet::create_with_rng(profile(), 12, &mut rng).unwrap();
    assert_eq!(rng.calls, [32, 16, 16]);
    assert_eq!(&wallet.root[..], &(0..32).collect::<Vec<_>>());
    assert_eq!(
        &wallet.manifest.wallet_id.0[..],
        &(32..48).collect::<Vec<_>>()
    );
    assert_eq!(
        &wallet.manifest.allocator_id.0[..],
        &(48..64).collect::<Vec<_>>()
    );
    assert_eq!(wallet.manifest.birthday_height, 12);
    assert_eq!(wallet.suite(), Suite::SlhDsaB128sExpV1);
    assert!(wallet.manifest.entries.is_empty());
    let json = wallet.manifest.to_json().unwrap();
    assert_eq!(Manifest::from_json(&json).unwrap(), *wallet.manifest());
    let invalid = Profile {
        pq_activation_height: 100,
        ..profile()
    };
    let mut rng = TestRng::new();
    assert!(matches!(
        Wallet::create_with_rng(invalid, 0, &mut rng),
        Err(Error::UnsupportedContext)
    ));
    assert!(rng.calls.is_empty());
}

#[test]
fn manifest_accepts_all_shapes_but_never_alternate_suites_or_origins() {
    let local = Hex([1; 16]);
    for participants in 1..=15u8 {
        for threshold in 1..=participants {
            let policy = SuitePolicy::new(
                Suite::SlhDsaB128sExpV1,
                threshold,
                (1..=participants).map(|n| [n; 32]).collect(),
            )
            .unwrap();
            let entry = Entry {
                origins: (1..=participants)
                    .map(|n| Origin {
                        account: 0,
                        index: 0,
                        wallet_id: Hex([n; 16]),
                    })
                    .collect(),
                policy_hex: hex::encode(policy.encode()),
                role: 0,
            };
            let mut manifest = Manifest::empty(profile(), 0, local, Hex([9; 16]));
            manifest.entries.push(entry);
            manifest.receive_end = 1;
            let encoded = manifest.to_json().unwrap();
            assert_eq!(Manifest::from_json(&encoded).unwrap(), manifest);
            assert_eq!(manifest.entries[0].policy().unwrap().threshold(), threshold);
            let mut bad = manifest.clone();
            bad.suite = 1;
            assert!(matches!(bad.validate(), Err(Error::UnsupportedFormat)));
            let mut bad = manifest.clone();
            bad.entries[0].origins[0].account = 1;
            assert!(matches!(bad.validate(), Err(Error::Policy)));
            if participants > 1 {
                let mut bad = manifest.clone();
                bad.entries[0].origins[1].wallet_id = local;
                assert!(matches!(bad.validate(), Err(Error::Policy)));
            }
        }
    }
}

#[test]
fn canonical_reader_preserves_exact_encoding_and_independent_caps() {
    let manifest = Manifest::empty(profile(), 0, Hex([1; 16]), Hex([2; 16]));
    let encoded = manifest.to_json().unwrap();
    for changed in [
        [encoded.as_slice(), b"\n"].concat(),
        String::from_utf8(encoded.clone())
            .unwrap()
            .replacen("\"network\":2", "\"network\":2,\"network\":2", 1)
            .into_bytes(),
        String::from_utf8(encoded.clone())
            .unwrap()
            .replacen("\"network\":2", "\"network\":02", 1)
            .into_bytes(),
        String::from_utf8(encoded.clone())
            .unwrap()
            .replacen("\"network\":2", "\"network\":2,\"unknown\":0", 1)
            .into_bytes(),
    ] {
        assert!(Manifest::from_json(&changed).is_err());
    }
    assert!(matches!(
        canonical::encode(&manifest, encoded.len() - 1),
        Err(Error::Limits)
    ));
    assert!(matches!(
        canonical::decode::<Manifest>(&encoded, encoded.len() - 1),
        Err(Error::Limits)
    ));
    assert_eq!(
        canonical::encode(&manifest, encoded.len())
            .unwrap()
            .as_slice(),
        encoded
    );
}

fn transaction(policy: &SuitePolicy) -> (Transaction, Arc<Vec<Output>>) {
    let previous = Arc::new(vec![Output {
        value: 100_000.try_into().unwrap(),
        lock_script: policy.lock_script(),
    }]);
    let transaction = Transaction::V5 {
        network_upgrade: NetworkUpgrade::Nu7,
        lock_time: LockTime::Height(Height(0)),
        expiry_height: Height(140),
        inputs: vec![Input::PrevOut {
            outpoint: OutPoint {
                hash: Hash([1; 32]),
                index: 0,
            },
            unlock_script: Script::new(&[]),
            sequence: u32::MAX,
        }],
        outputs: vec![Output {
            value: 90_000.try_into().unwrap(),
            lock_script: policy.lock_script(),
        }],
        sapling_shielded_data: None,
        orchard_shielded_data: None,
    };
    (transaction, previous)
}

#[test]
fn operational_signing_requires_matching_enrolled_origin_profile_and_context() {
    let mut wallet = Wallet::create_with_rng(profile(), 0, &mut TestRng::new()).unwrap();
    let path = KeyPath {
        role: Role::Receive,
        index: 0,
    };
    let commitment = wallet.key_commitment(path).unwrap();
    // Fixed tiny commitments sort before this fixture's local commitment, so
    // exercise the maximum signer index without computing 14 unused secret keys.
    let mut commitments: Vec<_> = (0..14u8)
        .map(|n| {
            let mut c = [0; 32];
            c[31] = n;
            c
        })
        .collect();
    assert!(commitments.iter().all(|c| *c < commitment));
    commitments.push(commitment);
    let policy = SuitePolicy::new(wallet.suite(), 1, commitments).unwrap();
    let (mut tx, previous) = transaction(&policy);
    let signer = InputSigner::new(&tx, previous.clone(), 0, &policy).unwrap();
    assert!(matches!(
        wallet.sign_input(&signer, path),
        Err(Error::Policy)
    ));
    let mut origins: Vec<_> = (0..14u8)
        .map(|n| Origin {
            account: 0,
            index: 0,
            wallet_id: Hex([n; 16]),
        })
        .collect();
    origins.push(Origin {
        account: 0,
        index: 0,
        wallet_id: wallet.manifest.wallet_id,
    });
    wallet.manifest.entries.push(Entry {
        origins,
        policy_hex: hex::encode(policy.encode()),
        role: 0,
    });
    wallet.manifest.receive_end = 1;
    wallet.manifest.validate().unwrap();
    let wrong_path = KeyPath {
        role: Role::Change,
        index: 0,
    };
    assert!(matches!(
        wallet.sign_input(&signer, wrong_path),
        Err(Error::Policy)
    ));
    let non_regtest = InputSigningContext::new(
        &tx,
        NetworkDomain::Mainnet,
        NetworkUpgrade::Nu7,
        previous.clone(),
        0,
        match &policy {
            SuitePolicy::SlhDsaB128sExpV1(native) => native,
        },
    )
    .unwrap();
    assert!(matches!(
        wallet.sign_partial(&non_regtest, path),
        Err(Error::UnsupportedContext)
    ));
    let mut higher = match &policy {
        SuitePolicy::SlhDsaB128sExpV1(native) => native,
    }
    .descriptor();
    higher[2] = 2;
    let higher = SuitePolicy::decode(&higher).unwrap();
    assert!(matches!(
        wallet.signer_index(path, &higher),
        Err(Error::Policy)
    ));
    wallet.manifest.profile.max_tx_pq_checks = 0;
    assert!(matches!(
        wallet.sign_input(&signer, path),
        Err(Error::PolicyLimit { .. })
    ));
    wallet.manifest.profile.max_tx_pq_checks = 16;
    let partial = wallet.sign_input(&signer, path).unwrap();
    assert_eq!(partial.index(), 14);
    signer.verify_partial(&partial).unwrap();
    let script = signer.assemble(vec![partial]).unwrap();
    let Transaction::V5 { inputs, .. } = &mut tx else {
        unreachable!()
    };
    let Input::PrevOut { unlock_script, .. } = &mut inputs[0] else {
        unreachable!()
    };
    *unlock_script = script;
    suite::verify_inputs(&tx, previous.clone(), &[wallet.suite()]).unwrap();
    let mut changed = previous.as_ref().clone();
    changed[0].value = 100_001.try_into().unwrap();
    assert!(suite::verify_inputs(&tx, Arc::new(changed), &[wallet.suite()]).is_err());
}
