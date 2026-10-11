use std::{cell::Cell, sync::Arc};

use zakura_chain::{
    block::Height,
    parameters::NetworkUpgrade,
    serialization::ZcashSerialize,
    transaction::{Hash, LockTime, Transaction},
    transparent::{OutPoint, Output, Script},
};
use zakura_pq_slh_dsa_b_exp::{
    codec::key_commitment, contract::MESSAGE_SIZE, input_authorization, profile::SIGNATURE_SIZE,
    verify_signature, Authorization, InputSigningContext, Policy, Record, Rejection,
    SignatureCheck, TransactionContext,
};
use zakura_pq_test_support::{
    inputs_mut, install, outputs_mut, set_upgrade, Spend, TransactionRecipe,
};
use zakura_pq_tx_context::NetworkDomain;

fn authorization(m: u8, n: u8) -> Authorization {
    let mut keys: Vec<_> = (1..=n).map(|i| [i; 32]).collect();
    keys.sort_by_key(key_commitment);
    Authorization {
        policy: Policy::new(m, keys.iter().map(key_commitment).collect()).unwrap(),
        records: keys
            .into_iter()
            .enumerate()
            .take(usize::from(m))
            .map(|(index, public_key)| Record {
                index: u8::try_from(index).unwrap(),
                public_key,
                signature: vec![0; SIGNATURE_SIZE]
                    .into_boxed_slice()
                    .try_into()
                    .unwrap(),
            })
            .collect(),
    }
}

fn transaction(
    version: u8,
    authorization: &Authorization,
    count: u8,
) -> (Transaction, Arc<Vec<Output>>) {
    let (mut transaction, previous) = TransactionRecipe {
        version,
        network_upgrade: NetworkUpgrade::Nu7,
        lock_time: LockTime::Height(Height(5)),
        expiry_height: Height(140),
        spends: (0..count)
            .map(|index| Spend {
                outpoint: OutPoint {
                    hash: Hash([index + 1; 32]),
                    index: u32::from(index),
                },
                sequence: u32::MAX - 1,
                previous_output: Output {
                    value: 100_000.try_into().unwrap(),
                    lock_script: authorization.policy.lock_script(),
                },
            })
            .collect(),
        outputs: vec![
            Output {
                value: 20_000.try_into().unwrap(),
                lock_script: authorization.policy.lock_script(),
            },
            Output {
                value: 30_000.try_into().unwrap(),
                lock_script: authorization.policy.lock_script(),
            },
        ],
    }
    .build();
    for index in 0..usize::from(count) {
        install(
            &mut transaction,
            index,
            Script::new(&authorization.encode()),
        );
    }
    (transaction, previous)
}

fn context<'a>(tx: &'a Transaction, previous: Arc<Vec<Output>>) -> TransactionContext<'a> {
    TransactionContext::new(tx, NetworkDomain::Regtest, NetworkUpgrade::Nu7, previous).unwrap()
}

#[test]
fn v5_v6_message_layout_and_effect_context_binding() {
    for version in [5, 6] {
        let auth = authorization(1, 1);
        let (tx, previous) = transaction(version, &auth, 2);
        let first = context(&tx, previous.clone()).message(0).unwrap();
        let second = context(&tx, previous.clone()).message(1).unwrap();
        assert_eq!(first.len(), 101);
        assert_eq!(
            &first[..58],
            b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/message/v1\0"
        );
        assert_eq!(&first[58..65], &[0xf7, 2, version, 0xd9, 0x0a, 0x19, 0x77]);
        assert_eq!(&first[65..69], &[0, 0, 0, 0]);
        assert_eq!(&second[65..69], &[1, 0, 0, 0]);
        assert_ne!(first, second);
        for (network, byte) in [(NetworkDomain::Mainnet, 0), (NetworkDomain::Testnet, 1)] {
            let mut expected = first;
            expected[59] = byte;
            assert_eq!(
                TransactionContext::new(&tx, network, NetworkUpgrade::Nu7, previous.clone())
                    .unwrap()
                    .message(0)
                    .unwrap(),
                expected
            );
        }
        let mut changed = tx.clone();
        outputs_mut(&mut changed)[0].value = 20_001.try_into().unwrap();
        assert_ne!(
            context(&changed, previous.clone()).message(0).unwrap(),
            first
        );
        let mut changed_previous = previous.as_ref().clone();
        changed_previous[1].value = 100_001.try_into().unwrap();
        assert_ne!(
            context(&tx, Arc::new(changed_previous)).message(0).unwrap(),
            first
        );
        let mut changed_previous = previous.as_ref().clone();
        changed_previous[1].lock_script = Script::new(&[0x51]);
        assert_ne!(
            context(&tx, Arc::new(changed_previous)).message(0).unwrap(),
            first
        );
        let mut effects_equal = tx.clone();
        install(&mut effects_equal, 0, Script::new(&[]));
        assert_eq!(
            context(&effects_equal, previous.clone())
                .message(0)
                .unwrap(),
            first
        );
        assert_eq!(
            context(&tx, previous).message(2),
            Err(Rejection::InputContext)
        );
    }
}

#[test]
fn real_serialization_matches_the_maximum_payment_capacity() {
    for (version, expected) in [(5, 119_040), (6, 119_041)] {
        let (tx, _) = transaction(version, &authorization(15, 15), 1);
        assert_eq!(tx.zcash_serialize_to_vec().unwrap().len(), expected);
    }
}

#[test]
fn contexts_reject_mismatch_and_preserve_shared_output_allocation() {
    let (tx, previous) = transaction(5, &authorization(1, 1), 1);
    let before = Arc::strong_count(&previous);
    let ctx = context(&tx, previous.clone());
    assert!(
        Arc::strong_count(&previous) > before,
        "prepared context retains the supplied Arc"
    );
    drop(ctx);
    assert_eq!(Arc::strong_count(&previous), before);
    assert!(matches!(
        TransactionContext::new(
            &tx,
            NetworkDomain::Regtest,
            NetworkUpgrade::Nu7,
            Arc::new(vec![])
        ),
        Err(Rejection::InputContext)
    ));
    assert!(matches!(
        TransactionContext::new(
            &tx,
            NetworkDomain::Regtest,
            NetworkUpgrade::Nu6_3,
            previous.clone()
        ),
        Err(Rejection::ConsensusBranch)
    ));
    // v6 is never reviewed before NU6.3, so this holds in every feature build.
    // Refusal of reviewed historical pairs is tested in zakura-pq-tx-context.
    let (mut historical, _) = transaction(6, &authorization(1, 1), 1);
    set_upgrade(&mut historical, NetworkUpgrade::Nu6_2);
    assert!(matches!(
        TransactionContext::new(
            &historical,
            NetworkDomain::Regtest,
            NetworkUpgrade::Nu6_2,
            previous.clone()
        ),
        Err(Rejection::TransactionVersion)
    ));
    let mut empty = tx;
    inputs_mut(&mut empty).clear();
    assert!(matches!(
        TransactionContext::new(
            &empty,
            NetworkDomain::Regtest,
            NetworkUpgrade::Nu7,
            Arc::new(vec![])
        ),
        Err(Rejection::InputContext)
    ));
}

#[test]
fn all_structural_checks_precede_exactly_one_reservation() {
    let auth = authorization(2, 3);
    let (tx, previous) = transaction(5, &auth, 1);
    let calls = Cell::new(0);
    let ctx = context(&tx, previous.clone());
    let reserved = ctx
        .reserve_input(0, |checks| {
            calls.set(calls.get() + 1);
            assert_eq!(checks, 2);
            Ok(())
        })
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(reserved.input_index(), 0);
    assert_eq!(reserved.checks().len(), 2);
    // Structural reservation cannot turn these zero-filled signatures valid.
    assert_eq!(reserved.verify(), Err(Rejection::Signature));
    assert!(matches!(
        ctx.reserve_input(0, |_| Err(Rejection::VerificationBudget)),
        Err(Rejection::VerificationBudget)
    ));
    for rejection in [
        Rejection::OutputTemplate,
        Rejection::Encoding,
        Rejection::OutputCommitment,
        Rejection::KeyCommitment,
    ] {
        let mut changed_tx = tx.clone();
        let mut changed_previous = previous.as_ref().clone();
        match rejection {
            Rejection::OutputTemplate => changed_previous[0].lock_script = Script::new(&[0x51]),
            Rejection::Encoding => install(&mut changed_tx, 0, Script::new(&[0])),
            Rejection::OutputCommitment => {
                changed_previous[0].lock_script = authorization(1, 1).policy.lock_script()
            }
            Rejection::KeyCommitment => {
                let mut changed_auth = auth.clone();
                changed_auth.records[0].public_key[0] ^= 1;
                install(&mut changed_tx, 0, Script::new(&changed_auth.encode()));
            }
            _ => unreachable!(),
        }
        assert_eq!(
            input_authorization(&changed_tx, &changed_previous, 0),
            Err(rejection)
        );
        assert!(
            matches!(context(&changed_tx, Arc::new(changed_previous)).reserve_input(0, |_| panic!("invalid structure must not reserve")), Err(actual) if actual == rejection)
        );
    }
}

#[test]
fn signing_context_reuses_derived_message_and_rejects_bad_partials_before_assembly() {
    let auth = authorization(2, 3);
    let (tx, previous) = transaction(6, &auth, 1);
    let signing = InputSigningContext::new(
        &tx,
        NetworkDomain::Regtest,
        NetworkUpgrade::Nu7,
        previous.clone(),
        0,
        &auth.policy,
    )
    .unwrap();
    assert_eq!(signing.network(), NetworkDomain::Regtest);
    assert_eq!(signing.upgrade(), NetworkUpgrade::Nu7);
    assert_eq!(signing.input_index(), 0);
    assert_eq!(signing.policy(), &auth.policy);
    assert_eq!(
        signing.message(),
        &context(&tx, previous.clone()).message(0).unwrap()
    );
    assert_eq!(
        signing.verify_partial(&auth.records[0]),
        Err(Rejection::Signature)
    );
    assert_eq!(
        signing.authorization(vec![]),
        Err(Rejection::SignatureCount)
    );
    assert_eq!(
        signing.authorization(vec![auth.records[0].clone(); 2]),
        Err(Rejection::SignerIndex)
    );
    let mut wrong_index = auth.records[0].clone();
    wrong_index.index = 3;
    assert_eq!(
        signing.verify_partial(&wrong_index),
        Err(Rejection::SignerIndex)
    );
    let mut wrong_key = auth.records[0].clone();
    wrong_key.public_key[0] ^= 1;
    assert_eq!(
        signing.verify_partial(&wrong_key),
        Err(Rejection::KeyCommitment)
    );
    assert!(matches!(
        InputSigningContext::new(
            &tx,
            NetworkDomain::Regtest,
            NetworkUpgrade::Nu7,
            previous,
            0,
            &authorization(1, 1).policy
        ),
        Err(Rejection::OutputCommitment)
    ));
}

#[test]
fn boxed_checks_keep_signatures_out_of_inline_record_and_worker_storage() {
    assert!(std::mem::size_of::<Record>() < 128);
    assert!(std::mem::size_of::<SignatureCheck>() < 256);
    // The independent primitive accepts verifier KAT 0 with its empty message;
    // only the native 101-byte message bound can refuse it.
    let kats: serde_json::Value = serde_json::from_str(include_str!(
        "../../pq-slh-dsa-b-verify/tests/data/pure-kats.json"
    ))
    .unwrap();
    let kat = &kats["cases"][0];
    assert_eq!(
        (kat["message"].as_str(), kat["context"].as_str()),
        (Some(""), Some(""))
    );
    let public_key = hex::decode(kat["public_key"].as_str().unwrap()).unwrap();
    let signature = hex::decode(kat["signature"].as_str().unwrap()).unwrap();
    assert_eq!(
        zakura_pq_slh_dsa_b_verify::verify(&public_key, &signature, &[], &[]),
        Ok(())
    );
    assert!(
        !verify_signature(&public_key, &signature, &[]),
        "native 101-byte bound, not crypto"
    );
    for length in [0, 100, 102, 65_536, 65_537] {
        assert!(!verify_signature(
            &[0; 32],
            &[0; SIGNATURE_SIZE],
            &vec![0; length]
        ));
    }
    assert!(!verify_signature(
        &[0; 31],
        &[0; SIGNATURE_SIZE],
        &[0; MESSAGE_SIZE]
    ));
    assert!(!verify_signature(
        &[0; 32],
        &[0; SIGNATURE_SIZE - 1],
        &[0; MESSAGE_SIZE]
    ));
    assert!(!verify_signature(
        &[0; 32],
        &[0; SIGNATURE_SIZE],
        &[0; MESSAGE_SIZE]
    ));
}

#[cfg(feature = "test-observer")]
#[test]
fn observer_reports_reservation_before_real_crypto_across_worker_threads() {
    use std::sync::Mutex;
    use zakura_pq_slh_dsa_b_exp::test_observer::{observe, Event};
    let (tx, previous) = transaction(5, &authorization(1, 1), 1);
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let callback = Arc::new(move |event| sink.lock().unwrap().push(event));
    let ctx = context(&tx, previous);
    observe(callback, || {
        // Native message bounds fail before entering the primitive.
        assert!(!verify_signature(&[0; 32], &[0; SIGNATURE_SIZE], &[0; 100]));
        assert!(events.lock().unwrap().is_empty());
        assert!(matches!(
            ctx.reserve_input(0, |_| Err(Rejection::VerificationBudget)),
            Err(Rejection::VerificationBudget)
        ));
        assert!(events.lock().unwrap().is_empty());
        let reserved = ctx.reserve_input(0, |_| Ok(())).unwrap();
        assert_eq!(&*events.lock().unwrap(), &[Event::Reserved { checks: 1 }]);
        std::thread::scope(|scope| {
            assert_eq!(
                scope.spawn(|| reserved.verify()).join().unwrap(),
                Err(Rejection::Signature)
            );
        });
    });
    let expected = [
        Event::Reserved { checks: 1 },
        Event::CryptoStarted,
        Event::CryptoFinished { valid: false },
    ];
    assert_eq!(&*events.lock().unwrap(), &expected);
    // Returning from the scope restores the absent observer on this thread.
    let reserved = ctx.reserve_input(0, |_| Ok(())).unwrap();
    assert_eq!(reserved.verify(), Err(Rejection::Signature));
    assert_eq!(&*events.lock().unwrap(), &expected);
}

#[cfg(feature = "test-observer")]
#[test]
fn nested_observer_scopes_restore_the_prior_observer_on_return_and_unwind() {
    use std::sync::Mutex;
    use zakura_pq_slh_dsa_b_exp::test_observer::{observe, Event};
    let (tx, previous) = transaction(5, &authorization(1, 1), 1);
    let ctx = context(&tx, previous);
    let reserve = || {
        ctx.reserve_input(0, |_| Ok(())).unwrap();
    };
    let outer = Arc::new(Mutex::new(Vec::<Event>::new()));
    let inner = Arc::new(Mutex::new(Vec::<Event>::new()));
    let (outer_sink, inner_sink) = (outer.clone(), inner.clone());
    observe(
        Arc::new(move |event| outer_sink.lock().unwrap().push(event)),
        || {
            observe(
                Arc::new(move |event| inner_sink.lock().unwrap().push(event)),
                reserve,
            );
            reserve();
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                observe(Arc::new(|_: Event| {}), || {
                    panic!("unwind through a nested scope")
                })
            }));
            assert!(unwound.is_err());
            reserve();
        },
    );
    reserve();
    let one = [Event::Reserved { checks: 1 }];
    assert_eq!(&*inner.lock().unwrap(), &one);
    assert_eq!(&*outer.lock().unwrap(), &[one, one].concat());
}
