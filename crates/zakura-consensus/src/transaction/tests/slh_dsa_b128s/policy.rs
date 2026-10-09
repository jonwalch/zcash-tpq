//! Relay-only funding policy and existing classical authorization controls.

use super::*;

#[test]
fn slh_funding_policy_uses_exact_template_gate_and_existing_dust_rate() {
    assert_eq!(check::SLH_DSA_B128S_DUST_THRESHOLD, 2_403);
    assert_eq!(zip317::MARGINAL_FEE, 400);
    for version in [5, 6] {
        let minimum = fixture(version, "1of1");
        assert_eq!(
            minimum.transaction.inputs()[0].zcash_serialized_size(),
            7_973
        );
        assert_eq!(minimum.transaction.outputs()[0].zcash_serialized_size(), 44);
        for (case, actions, fee) in [
            ("1of1", 54, 21_600),
            ("15of15", 793, 317_200),
            ("16checks", 846, 338_400),
            ("17checks", 900, 360_000),
        ] {
            let tx = fixture(version, case).transaction;
            assert_eq!(zip317::conventional_actions(&tx), actions);
            assert_eq!(i64::from(zip317::conventional_fee(&tx)), fee);
        }
        for (value, accepted) in [(2_402, false), (2_403, true), (2_404, true)] {
            let mut tx = funding(version).transaction;
            tx.outputs_mut()[0].value = value.try_into().unwrap();
            let expected = if accepted {
                Ok(())
            } else {
                Err(TransactionError::NonStandardSlhDsaB128sDust { output_index: 0 })
            };
            assert_eq!(
                check::mempool_slh_dsa_b128s_output_policy(&tx, true),
                expected
            );
            assert_eq!(
                check::mempool_slh_dsa_b128s_output_policy(&tx, false),
                Err(TransactionError::NonStandardSlhDsaB128sOutput { output_index: 0 }),
            );
        }
        let mut ordinary = funding(version).transaction;
        for output in ordinary.outputs_mut() {
            // Near matches are left to the unchanged classical output policy.
            let mut script = output.lock_script.as_raw_bytes().to_vec();
            script.push(0);
            output.lock_script = transparent::Script::new(&script);
            output.value = 1.try_into().unwrap();
        }
        assert_eq!(
            check::mempool_slh_dsa_b128s_output_policy(&ordinary, false),
            Ok(())
        );
    }
}

#[tokio::test]
async fn slh_relay_funding_uses_candidate_height_and_requires_classical_authorization() {
    let net = network(16, 64);
    for version in [5, 6] {
        assert_eq!(
            mempool_result(&net, Height(109), funding(version), false).await,
            Err(TransactionError::NonStandardSlhDsaB128sOutput { output_index: 0 }),
        );
        assert!(mempool_result(&net, SLH_HEIGHT, funding(version), false)
            .await
            .is_ok());
        let mut dust = funding(version);
        dust.transaction.outputs_mut()[0].value = 2_402.try_into().unwrap();
        assert_eq!(
            mempool_result(&net, SLH_HEIGHT, dust, false).await,
            Err(TransactionError::NonStandardSlhDsaB128sDust { output_index: 0 }),
        );
        let mut unauthorized = funding(version);
        install(
            &mut unauthorized.transaction,
            0,
            transparent::Script::new(&[]),
        );
        assert!(mempool_result(&net, SLH_HEIGHT, unauthorized, false)
            .await
            .is_err());

        // Funding remains consensus-valid before activation: output policy is
        // intentionally absent from the block verifier path.
        let mut request = funding(version).block_request(None);
        let Request::Block { height, .. } = &mut request else {
            unreachable!()
        };
        *height = Height(109);
        let state = service_fn(|_| async { unreachable!("known UTXOs cover every input") });
        assert!(Verifier::new_for_tests(&net, state)
            .oneshot(request)
            .await
            .is_ok());
    }
}

#[test]
fn slh_funding_policy_errors_are_not_consensus_invalid_or_peer_penalties() {
    use zakura_header_chain::BodyVerificationClass;
    for error in [
        TransactionError::NonStandardSlhDsaB128sOutput { output_index: 0 },
        TransactionError::NonStandardSlhDsaB128sDust { output_index: 1 },
    ] {
        assert_eq!(error.mempool_misbehavior_score(), 0);
        assert!(matches!(
            error.body_verification_class(),
            BodyVerificationClass::Retryable(_)
        ));
    }
}

#[test]
fn slh_structural_counts_include_large_authorizations_and_bind_keys_and_ordered_outputs() {
    for version in [5, 6] {
        for (case, expected) in [("15of15", 15), ("16checks", 16), ("17checks", 17)] {
            let fixture = fixture(version, case);
            let transparent::Input::PrevOut { unlock_script, .. } =
                &fixture.transaction.inputs()[0]
            else {
                unreachable!()
            };
            assert!(unlock_script.as_raw_bytes().len() > 65_536);
            assert_eq!(
                check::mempool_standard_input_scripts_with_slh_dsa_b128s(
                    &fixture.transaction,
                    &fixture.previous,
                    true,
                ),
                Ok(expected)
            );
        }
        let mut fixture = fixture(version, "1of1");
        let transparent::Input::PrevOut { unlock_script, .. } = &fixture.transaction.inputs()[0]
        else {
            unreachable!()
        };
        let mut bytes = unlock_script.as_raw_bytes().to_vec();
        bytes[2] ^= 1; // Change the public key while retaining its indexed commitment.
        install(
            &mut fixture.transaction,
            0,
            transparent::Script::new(&bytes),
        );
        assert_eq!(
            check::mempool_standard_input_scripts_with_slh_dsa_b128s(
                &fixture.transaction,
                &fixture.previous,
                true,
            ),
            Err(TransactionError::NonStandardInputs)
        );
    }
}
