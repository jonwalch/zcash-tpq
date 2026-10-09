//! Storage repeats the same slh policy and checks verified rule context.

use super::super::*;
use zakura_chain::{
    parameters::{
        testnet::{ConfiguredActivationHeights, ExperimentalSlhDsaB128sLimits, RegtestParameters},
        NetworkUpgrade,
    },
    transaction::LockTime,
};

fn network() -> Network {
    Network::new_regtest(RegtestParameters {
        activation_heights: ConfiguredActivationHeights {
            nu6_3: Some(1),
            nu7: Some(105),
            ..Default::default()
        },
        experimental_slh_dsa_b128s_activation_height: Some(Height(110)),
        experimental_slh_dsa_b128s_limits: Some(
            ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap(),
        ),
        ..Default::default()
    })
}

// Only storage is tested here. Real ECDSA/SLH verification is covered by the
// transaction service and in-process mempool tests, not by this trusted-result fixture.
fn funding(value: i64) -> VerifiedUnminedTx {
    let mut slh = vec![0x53, 0x20];
    slh.extend([73; 32]);
    slh.push(0xc0);
    let tx = Transaction::V6 {
        network_upgrade: NetworkUpgrade::Nu7,
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        inputs: vec![zakura_chain::transparent::Input::PrevOut {
            outpoint: zakura_chain::transparent::OutPoint {
                hash: Hash([92; 32]),
                index: 0,
            },
            unlock_script: zakura_chain::transparent::Script::new(&[0x00, 0x00]),
            sequence: u32::MAX,
        }],
        outputs: vec![zakura_chain::transparent::Output {
            value: value.try_into().unwrap(),
            lock_script: zakura_chain::transparent::Script::new(&slh),
        }],
        sapling_shielded_data: None,
        orchard_shielded_data: None,
        ironwood_shielded_data: None,
    };
    let outputs = Arc::new(vec![zakura_chain::transparent::Output {
        value: 2_000_000.try_into().unwrap(),
        lock_script: policy::p2pkh_lock_script(&[3; 20]),
    }]);
    VerifiedUnminedTx::new(tx.into(), 1_000_000.try_into().unwrap(), 0, 0, outputs)
        .unwrap()
        .with_verified_slh_dsa_b128s(&network(), Height(110), 0)
        .unwrap()
}

#[test]
fn slh_funding_dust_context_and_unknown_height_are_checked() {
    let net = network();
    for (value, accepted) in [(2_402, false), (2_403, true), (2_404, true)] {
        let mut storage = Storage::with_network(&config::Config::default(), &net);
        assert_eq!(
            storage
                .insert(funding(value), Vec::new(), Some(Height(109)))
                .is_ok(),
            accepted
        );
    }
    let mut storage = Storage::with_network(&config::Config::default(), &net);
    assert_eq!(
        storage.insert(funding(10_000), Vec::new(), None),
        Err(MempoolError::NonStandardTransaction(
            NonStandardTransactionError::SlhDsaB128sVerificationContext
        ))
    );
    assert!(Storage::with_network(&config::Config::default(), &net)
        .insert(funding(10_000), Vec::new(), Some(Height(108)))
        .is_err());
    for corruption in 0..3 {
        let mut tx = funding(10_000);
        match corruption {
            0 => tx.slh_dsa_b128s_verification = None,
            1 => tx.spent_outputs = Arc::new(Vec::new()),
            _ => Arc::make_mut(&mut tx.spent_outputs)[0].value = 1.try_into().unwrap(),
        }
        assert!(Storage::with_network(&config::Config::default(), &net)
            .insert(tx, Vec::new(), Some(Height(109)))
            .is_err());
    }
    // Ordinary forward growth with the same rules preserves a verified entry.
    assert!(Storage::with_network(&config::Config::default(), &net)
        .insert(funding(10_000), Vec::new(), Some(Height(111)))
        .is_ok());
    assert!(Storage::new(&config::Config::default())
        .insert(funding(10_000), Vec::new(), Some(Height(111)))
        .is_err());
    let mut inactive = funding(10_000);
    inactive.slh_dsa_b128s_verification = None;
    assert_eq!(
        Storage::with_network(&config::Config::default(), &net).insert(
            inactive,
            vec![],
            Some(Height(108))
        ),
        Err(MempoolError::NonStandardTransaction(
            NonStandardTransactionError::ScriptPubKeyNonStandard
        ))
    );
}

#[test]
fn slh_funding_storage_requires_matching_success_metadata_and_finite_tip() {
    let net = network();
    let wrong_count = funding(10_000)
        .with_verified_slh_dsa_b128s(&net, Height(110), 1)
        .unwrap();
    let mut stale = funding(10_000);
    stale.spent_outputs = Arc::new(stale.spent_outputs.as_ref().clone());
    for tx in [wrong_count, stale] {
        let mut storage = Storage::with_network(&config::Config::default(), &net);
        assert_eq!(
            storage.insert(tx, vec![], Some(Height(109))),
            Err(MempoolError::NonStandardTransaction(
                NonStandardTransactionError::SlhDsaB128sVerificationContext
            ))
        );
        assert_eq!(storage.transaction_count(), 0);
    }
    assert_eq!(
        Storage::with_network(&config::Config::default(), &net).insert(
            funding(10_000),
            vec![],
            Some(Height::MAX)
        ),
        Err(MempoolError::NonStandardTransaction(
            NonStandardTransactionError::SlhDsaB128sVerificationContext
        ))
    );
    let mut unauthorized = funding(10_000);
    let mut tx = unauthorized.transaction.transaction().as_ref().clone();
    let transparent::Input::PrevOut { unlock_script, .. } = &mut tx.inputs_mut()[0] else {
        unreachable!()
    };
    *unlock_script = transparent::Script::new(&[]);
    unauthorized.transaction = tx.into();
    assert!(Storage::with_network(&config::Config::default(), &net)
        .insert(unauthorized, vec![], Some(Height(109)))
        .is_err());
}
