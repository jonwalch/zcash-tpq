//! Metadata-only fixtures; actual signature verification belongs to consensus tests.

use super::*;
use crate::{
    parameters::testnet::{
        ConfiguredActivationHeights, ExperimentalSlhDsaB128sLimits, RegtestParameters,
    },
    transaction::{Hash, LockTime, UnminedTx},
    transparent::{Input, OutPoint, Output, Script},
};

fn network(nu7: u32, activation: u32, tx_limit: u32, block_limit: u32) -> Network {
    Network::new_regtest(RegtestParameters {
        activation_heights: ConfiguredActivationHeights {
            nu6_3: Some(1),
            nu7: Some(nu7),
            ..Default::default()
        },
        experimental_slh_dsa_b128s_activation_height: Some(Height(activation)),
        experimental_slh_dsa_b128s_limits: Some(
            ExperimentalSlhDsaB128sLimits::new(tx_limit, block_limit).unwrap(),
        ),
        ..Default::default()
    })
}

fn fixture(version: u8, upgrade: NetworkUpgrade) -> VerifiedUnminedTx {
    let inputs = (0..2)
        .map(|index| Input::PrevOut {
            outpoint: OutPoint {
                hash: Hash([1; 32]),
                index,
            },
            unlock_script: Script::new(&[0]),
            sequence: u32::MAX,
        })
        .collect();
    let outputs = vec![Output {
        value: 10_000.try_into().unwrap(),
        lock_script: Script::new(&[0x51]),
    }];
    let tx = match version {
        5 => Transaction::V5 {
            network_upgrade: upgrade,
            lock_time: LockTime::unlocked(),
            expiry_height: Height(0),
            inputs,
            outputs,
            sapling_shielded_data: None,
            orchard_shielded_data: None,
        },
        6 => Transaction::V6 {
            network_upgrade: upgrade,
            lock_time: LockTime::unlocked(),
            expiry_height: Height(0),
            inputs,
            outputs,
            sapling_shielded_data: None,
            orchard_shielded_data: None,
            ironwood_shielded_data: None,
        },
        _ => unreachable!(),
    };
    let unmined = UnminedTx::from(tx);
    let fee = unmined.conventional_fee();
    let spent = Arc::new(vec![
        Output {
            value: 20_000.try_into().unwrap(),
            lock_script: Script::new(&[0x51]),
        },
        Output {
            value: 30_000.try_into().unwrap(),
            lock_script: Script::new(&[0x00]),
        },
    ]);
    VerifiedUnminedTx::new(unmined, fee, 0, 0, spent).unwrap()
}

#[test]
fn slh_accounting_requires_complete_active_context_and_explicit_count() {
    let net = network(5, 10, 15, 42);
    for version in [5, 6] {
        let tx = fixture(version, NetworkUpgrade::Nu7);
        assert_eq!(tx.verified_slh_dsa_b128s_checks(&net, Height(9)), Ok(0));
        assert_eq!(
            tx.verified_slh_dsa_b128s_checks(&net, Height(10)),
            Err(SlhDsaB128sVerificationError)
        );
        assert_eq!(
            tx.verified_slh_dsa_b128s_checks(&Network::Mainnet, Height(10)),
            Ok(0)
        );
        assert_eq!(
            tx.clone().with_verified_slh_dsa_b128s(&net, Height(9), 0),
            Err(SlhDsaB128sVerificationError)
        );
        assert_eq!(
            tx.clone().with_verified_slh_dsa_b128s(&net, Height(10), 16),
            Err(SlhDsaB128sVerificationError)
        );
        for count in [0, 1, 15] {
            let annotated = tx
                .clone()
                .with_verified_slh_dsa_b128s(&net, Height(10), count)
                .unwrap();
            assert_eq!(
                annotated.verified_slh_dsa_b128s_checks(&net, Height(10)),
                Ok(count)
            );
            assert_eq!(
                annotated.verified_slh_dsa_b128s_checks(&net, Height(11)),
                Ok(count)
            );
            assert_eq!(
                annotated.verified_slh_dsa_b128s_checks(&net, Height(9)),
                Err(SlhDsaB128sVerificationError)
            );
            assert_eq!(
                annotated.verified_slh_dsa_b128s_checks(&Network::Mainnet, Height(10)),
                Err(SlhDsaB128sVerificationError)
            );
            for changed in [
                network(5, 11, 15, 42),
                network(5, 10, 16, 42),
                network(5, 10, 15, 43),
            ] {
                assert_eq!(
                    annotated.verified_slh_dsa_b128s_checks(&changed, Height(11)),
                    Err(SlhDsaB128sVerificationError)
                );
            }
        }
        let mut missing_outputs = tx;
        missing_outputs.spent_outputs = Arc::new(vec![]);
        assert_eq!(
            missing_outputs.with_verified_slh_dsa_b128s(&net, Height(10), 0),
            Err(SlhDsaB128sVerificationError)
        );
    }
}

#[test]
fn slh_accounting_binds_full_authorization_and_exact_payload_allocations() {
    let net = network(5, 10, 15, 42);
    for version in [5, 6] {
        let original = fixture(version, NetworkUpgrade::Nu7)
            .with_verified_slh_dsa_b128s(&net, Height(10), 3)
            .unwrap();
        let mut copy = original.clone();
        copy.height = Some(Height(11));
        copy.time = Some(chrono::Utc::now());
        assert_eq!(copy.verified_slh_dsa_b128s_checks(&net, Height(11)), Ok(3));
        assert!(Arc::ptr_eq(&copy.spent_outputs, &original.spent_outputs));
        assert!(Arc::ptr_eq(
            copy.transaction.transaction(),
            original.transaction.transaction()
        ));

        let mut changed_tx = original.transaction.transaction().as_ref().clone();
        let Input::PrevOut { unlock_script, .. } = &mut changed_tx.inputs_mut()[0] else {
            unreachable!()
        };
        *unlock_script = Script::new(&[0x51]);
        copy.transaction = changed_tx.into();
        assert_eq!(
            copy.transaction.id().mined_id(),
            original.transaction.id().mined_id()
        );
        assert_ne!(copy.transaction.id(), original.transaction.id());
        assert_eq!(
            copy.verified_slh_dsa_b128s_checks(&net, Height(10)),
            Err(SlhDsaB128sVerificationError)
        );

        // Even identical bytes in a replacement allocation need fresh verification.
        copy.transaction = original.transaction.transaction().as_ref().clone().into();
        assert_eq!(copy.transaction.id(), original.transaction.id());
        assert_eq!(
            copy.verified_slh_dsa_b128s_checks(&net, Height(10)),
            Err(SlhDsaB128sVerificationError)
        );

        for change in 0..5 {
            let mut copy = original.clone();
            match change {
                0 => Arc::make_mut(&mut copy.spent_outputs)[0].value = 1.try_into().unwrap(),
                1 => Arc::make_mut(&mut copy.spent_outputs)[0].lock_script = Script::new(&[0x00]),
                2 => Arc::make_mut(&mut copy.spent_outputs).swap(0, 1),
                3 => copy.spent_outputs = Arc::new(copy.spent_outputs.as_ref().clone()),
                _ => copy.slh_dsa_b128s_verification = None,
            }
            assert_eq!(
                copy.verified_slh_dsa_b128s_checks(&net, Height(10)),
                Err(SlhDsaB128sVerificationError)
            );
        }
        assert_eq!(
            original.verified_slh_dsa_b128s_checks(&net, Height(10)),
            Ok(3)
        );
    }
}
