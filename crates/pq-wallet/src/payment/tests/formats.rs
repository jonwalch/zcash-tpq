//! Structurally valid public files must still pass actual wallet assembly.
use super::*;

#[test]
fn receiver_activation_intent_is_canonical_and_same_suite_uses_the_profile() {
    let owners = wallets(1, 1, 2);
    let wallet = &owners[0];
    let mut approved = intent(6);
    let original = approved.to_json().unwrap();
    assert!(!std::str::from_utf8(&original)
        .unwrap()
        .contains("receiver_activation_height"));
    assert_eq!(Intent::from_json(&original).unwrap(), approved);
    approved.receiver_activation_height = Some(profile().pq_activation_height);
    let encoded = approved.to_json().unwrap();
    assert_eq!(Intent::from_json(&encoded).unwrap(), approved);
    let text = std::str::from_utf8(&encoded).unwrap();
    for malformed in [
        text.replace(
            "\"receiver_activation_height\":4",
            "\"receiver_activation_height\":null",
        ),
        text.replace(
            "\"receiver_activation_height\":4",
            "\"receiver_activation_height\":4.0",
        ),
        text.replace(
            "\"receiver_activation_height\":4",
            "\"receiver_activation_height\":4294967296",
        ),
        text.replace(
            "\"receiver_activation_height\":4",
            "\"receiver_activation_height\":4,\"receiver_activation_height\":4",
        ),
    ] {
        assert!(matches!(
            Intent::from_json(malformed.as_bytes()),
            Err(Error::Encoding)
        ));
    }
    let temp = tempfile::tempdir().unwrap();
    let mut store = create(
        &temp.path().join("store"),
        wallet.manifest(),
        WatchMode::Allocator,
    );
    let mut source = Source::funded(wallet, &[2_000_000]);
    for height in [None, Some(4)] {
        approved.receiver_activation_height = height;
        store
            .preview_payment(wallet, &mut source, &approved)
            .unwrap();
    }
    // Caller metadata cannot replace the independently approved same-suite gate.
    for height in [1, 3, 5] {
        approved.receiver_activation_height = Some(height);
        assert!(matches!(
            store.prepare_payment(wallet, &mut source, &approved),
            Err(Error::ReceiverActivation)
        ));
    }
    assert!(store.payments().unwrap().is_empty());
}

#[test]
fn decoded_partials_still_require_proposal_input_signer_and_signature_agreement() {
    for version in [5, 6] {
        let owners = wallets(3, 1, 1);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("coordinator");
        let mut store = create(&path, owners[0].manifest(), WatchMode::Allocator);
        let mut other = create(
            &temp.path().join("cosigner"),
            owners[1].manifest(),
            WatchMode::Allocator,
        );
        let mut source = Source::funded(&owners[0], &[2_000_000]);
        let approved = intent(version);
        let (proposal, review) = store
            .prepare_payment(&owners[0], &mut source, &approved)
            .unwrap();
        let mut partials = store
            .sign_payment(
                &owners[0],
                &mut source,
                &proposal,
                &approved,
                review.proposal_id,
            )
            .unwrap();
        partials.extend(
            other
                .sign_payment(
                    &owners[1],
                    &mut source,
                    &proposal,
                    &approved,
                    review.proposal_id,
                )
                .unwrap(),
        );
        let before = fs::read(path.join("state.json")).unwrap();
        for case in ["proposal", "input", "signer", "signature"] {
            let mut bad = partials.clone();
            match case {
                "proposal" => bad[0].proposal_id.0[0] ^= 1,
                "input" => bad[0].input_index = 1, // In parser range, absent in this proposal.
                "signer" => bad[0].signer_index = (bad[0].signer_index + 1) % 3,
                "signature" => {
                    let replacement = if bad[0].signature_hex.starts_with("00") {
                        "01"
                    } else {
                        "00"
                    };
                    bad[0].signature_hex.replace_range(..2, replacement);
                }
                _ => unreachable!(),
            }
            let decoded: Vec<_> = bad
                .iter()
                .map(|p| Partial::from_json(&p.to_json().unwrap()).unwrap())
                .collect();
            assert_eq!(decoded, bad);
            let error = store
                .assemble_payment(&owners[0], &mut source, &proposal, &approved, &decoded)
                .unwrap_err();
            if matches!(case, "proposal" | "input") {
                assert!(
                    matches!(error, Error::ProposalMismatch),
                    "{case}: {error:?}"
                );
            } else {
                assert!(
                    matches!(error, Error::Authorization(_)),
                    "{case}: {error:?}"
                );
            }
            assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
            assert!(source.sent.is_empty());
        }
        drop(store);
        let mut store = WatchStore::open(&path, &profile()).unwrap();
        let decoded: Vec<_> = partials
            .iter()
            .map(|p| Partial::from_json(&p.to_json().unwrap()).unwrap())
            .collect();
        store
            .assemble_payment(&owners[0], &mut source, &proposal, &approved, &decoded)
            .unwrap();
    }
}
