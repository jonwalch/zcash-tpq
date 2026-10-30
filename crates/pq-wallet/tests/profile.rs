//! Public context decoding works without wallet keys or signing support.
#![cfg(feature = "public-profile")]

use serde_json::json;
use zakura_pq_wallet::{Error, Hex, Profile};

const CUSTOM: &str = r#"{"chain_fingerprint":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","genesis_hash":"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","max_block_pq_checks":64,"max_tx_pq_checks":16,"network":1,"nu7_activation_height":102,"nu7_branch_id":"77190ad9","pq_activation_height":103}"#;

#[test]
fn public_profile_preserves_chain_bytes_and_context_rules() {
    let profile = Profile::from_json(CUSTOM.as_bytes()).unwrap();
    assert_eq!(
        profile.chain_fingerprint,
        Some(Hex(std::array::from_fn(|i| u8::try_from(i).unwrap())))
    );
    assert_eq!(
        profile.genesis_hash,
        Hex(std::array::from_fn(|i| 32 + u8::try_from(i).unwrap()))
    );
    assert_eq!(profile.max_block_pq_checks, 64);
    assert_eq!(profile.max_tx_pq_checks, 16);
    assert_eq!(profile.nu7_activation_height, 102);
    assert_eq!(profile.pq_activation_height, 103);
    assert_eq!(profile.wallet_version(), 2);
    assert_eq!(serde_json::to_vec(&profile).unwrap(), CUSTOM.as_bytes());

    let mut regtest = serde_json::to_value(&profile).unwrap();
    regtest.as_object_mut().unwrap().remove("chain_fingerprint");
    regtest["network"] = json!(2);
    assert_eq!(
        Profile::from_json(&serde_json::to_vec(&regtest).unwrap())
            .unwrap()
            .wallet_version(),
        1
    );
    regtest["network"] = json!(1);
    assert!(matches!(
        Profile::from_json(&serde_json::to_vec(&regtest).unwrap()),
        Err(Error::UnsupportedContext)
    ));
    regtest["network"] = json!(2);
    regtest["chain_fingerprint"] = json!("00".repeat(32));
    assert!(matches!(
        Profile::from_json(&serde_json::to_vec(&regtest).unwrap()),
        Err(Error::UnsupportedContext)
    ));

    for (field, value) in [
        ("network", json!(0)),
        ("nu7_branch_id", json!("77190ad8")),
        ("pq_activation_height", json!(102)),
        ("max_tx_pq_checks", json!(0)),
        ("max_block_pq_checks", json!(15)),
    ] {
        let mut changed = serde_json::to_value(&profile).unwrap();
        changed[field] = value;
        assert!(
            matches!(
                Profile::from_json(&serde_json::to_vec(&changed).unwrap()),
                Err(Error::UnsupportedContext)
            ),
            "{field}"
        );
    }
}

#[test]
fn public_profile_rejects_alternate_encodings_and_bounds_before_decode() {
    for changed in [
        CUSTOM.replace("\"network\":1", "\"network\": 1"),
        CUSTOM.replace("\"network\":1", "\"network\":1,\"network\":1"),
        CUSTOM.replace("\"network\":1", "\"network\":1,\"unknown\":0"),
        CUSTOM.replace(
            "\"max_block_pq_checks\":64,\"max_tx_pq_checks\":16",
            "\"max_tx_pq_checks\":16,\"max_block_pq_checks\":64",
        ),
        CUSTOM.replace("0a0b", "0A0B"),
        CUSTOM.replace("\"network\":1", "\"network\":1.0"),
        CUSTOM.replace("\"77190ad9\"", "\"77190ad\\u0039\""),
        format!("{CUSTOM}\n"),
        format!("{CUSTOM}{{}}"),
        // serde's derived struct reader accepts arrays; canonical comparison must not.
        format!(
            "[{}]",
            CUSTOM
                .replace(['{', '}'], "")
                .split(',')
                .map(|field| field.split_once(':').unwrap().1)
                .collect::<Vec<_>>()
                .join(",")
        ),
    ] {
        assert_ne!(changed, CUSTOM);
        assert!(
            matches!(Profile::from_json(changed.as_bytes()), Err(Error::Encoding)),
            "{changed}"
        );
    }
    assert!(matches!(
        Profile::from_json(&vec![b' '; 4096]),
        Err(Error::Encoding)
    ));
    assert!(matches!(
        Profile::from_json(&vec![b' '; 4097]),
        Err(Error::Limits)
    ));
}
