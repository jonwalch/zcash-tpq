//! Stable identities for configured SLH devnets.
//!
//! Version 1 hashes the fields below in their written order. Integers use their
//! declared width and little-endian order; booleans and option tags use one byte.
//! Strings and collections start with a little-endian `u64` byte/item count.
//! Hashes use internal byte order, and the expanded PoW limit uses 32 big-endian
//! bytes. Upgrade, receiver, address, and network tags are explicit below.
//!
//! The input is the validated, normalized `Parameters`, not its config syntax.
//! Maps and unordered sets of disbursements have a fixed order. The cached NSM
//! crossing is excluded because its inputs are included. Changes to this format
//! require a new version and a review of state and backup namespaces.

use sha2::{Digest, Sha256};

use super::{FundingStreamReceiver, Height, NetworkKind, NetworkUpgrade, Parameters};
use crate::{serialization::BytesInDisplayOrder, transparent};

const DOMAIN: &[u8] = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/chain-identity/v1\0";
const CONTRACT: &[u8] = b"slh-dsa-b-128s-exp-v1";

/// Hashes every immutable configured consensus parameter for an SLH devnet.
pub(super) fn chain_fingerprint(params: &Parameters) -> [u8; 32] {
    // Exhaustive destructuring makes new parameters require an identity decision.
    let Parameters {
        network_name,
        network_magic,
        genesis_hash,
        activation_heights,
        experimental_slh_dsa_b128s_activation_height,
        experimental_slh_dsa_b128s_limits,
        slow_start_interval,
        slow_start_shift,
        funding_streams,
        target_difficulty_limit,
        disable_pow,
        max_block_time_start_height,
        should_allow_unshielded_coinbase_spends,
        pre_blossom_halving_interval,
        post_blossom_halving_interval,
        lockbox_disbursements,
        checkpoints,
        temporary_orchard_disabling_soft_fork_height,
        #[cfg(any(test, feature = "proptest-impl"))]
        test_nsm_reissuance_height,
        nsm_reissuance_crossing_height: _,
        initial_nsm_value_balance,
    } = params;
    #[cfg(not(any(test, feature = "proptest-impl")))]
    let test_nsm_reissuance_height = &None;

    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash_bytes(&mut hash, network_name.as_bytes());
    hash.update(network_magic.0);
    hash.update(genesis_hash.0);
    hash_len(&mut hash, activation_heights.len());
    for (height, upgrade) in activation_heights {
        hash.update(height.0.to_le_bytes());
        hash.update([upgrade_tag(*upgrade)]);
    }
    hash_bytes(&mut hash, CONTRACT);
    hash_height(&mut hash, *experimental_slh_dsa_b128s_activation_height);
    hash.update([u8::from(experimental_slh_dsa_b128s_limits.is_some())]);
    if let Some(limits) = experimental_slh_dsa_b128s_limits {
        hash.update(limits.transaction().to_le_bytes());
        hash.update(limits.block().to_le_bytes());
    }
    hash.update(slow_start_interval.0.to_le_bytes());
    hash.update(slow_start_shift.0.to_le_bytes());

    // Validated funding ranges do not overlap, so their config order is immaterial.
    let mut streams: Vec<_> = funding_streams.iter().collect();
    streams.sort_by_key(|stream| (stream.height_range().start, stream.height_range().end));
    hash_len(&mut hash, streams.len());
    for stream in streams {
        hash.update(stream.height_range().start.0.to_le_bytes());
        hash.update(stream.height_range().end.0.to_le_bytes());
        let mut recipients: Vec<_> = stream.recipients().iter().collect();
        recipients.sort_by_key(|(receiver, _)| receiver_tag(**receiver));
        hash_len(&mut hash, recipients.len());
        for (receiver, recipient) in recipients {
            hash.update([receiver_tag(*receiver)]);
            hash.update(recipient.numerator().to_le_bytes());
            hash_len(&mut hash, recipient.addresses().len());
            // Address order selects the recipient for each funding period.
            for address in recipient.addresses() {
                hash.update(address_bytes(*address));
            }
        }
    }

    hash.update(target_difficulty_limit.bytes_in_serialized_order());
    hash.update([u8::from(*disable_pow)]);
    hash.update(max_block_time_start_height.0.to_le_bytes());
    hash.update([u8::from(*should_allow_unshielded_coinbase_spends)]);
    hash.update(pre_blossom_halving_interval.to_le_bytes());
    hash.update(post_blossom_halving_interval.to_le_bytes());

    // Consensus matches these payments irrespective of output order. Preserve
    // duplicate payments but normalize parsed addresses and configuration order.
    let mut disbursements: Vec<_> = lockbox_disbursements
        .iter()
        .map(|(address, amount)| {
            (
                address_bytes(
                    address
                        .parse()
                        .expect("validated lockbox addresses deserialize"),
                ),
                amount.zatoshis(),
            )
        })
        .collect();
    disbursements.sort_unstable();
    hash_len(&mut hash, disbursements.len());
    for (address, amount) in disbursements {
        hash.update(address);
        hash.update(amount.to_le_bytes());
    }
    hash_len(&mut hash, checkpoints.len());
    for (height, block_hash) in checkpoints.iter() {
        hash.update(height.0.to_le_bytes());
        hash.update(block_hash.0);
    }
    hash_height(&mut hash, *temporary_orchard_disabling_soft_fork_height);
    // Runtime builds encode the same None as tests without a fixture override.
    hash_height(&mut hash, *test_nsm_reissuance_height);
    hash.update([u8::from(initial_nsm_value_balance.is_some())]);
    if let Some(amount) = initial_nsm_value_balance {
        hash.update(amount.to_bytes());
    }
    hash.finalize().into()
}

fn hash_len(hash: &mut Sha256, len: usize) {
    hash.update(
        u64::try_from(len)
            .expect("configuration lengths fit in u64")
            .to_le_bytes(),
    );
}

fn hash_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash_len(hash, bytes.len());
    hash.update(bytes);
}

fn hash_height(hash: &mut Sha256, height: Option<Height>) {
    hash.update([u8::from(height.is_some())]);
    if let Some(height) = height {
        hash.update(height.0.to_le_bytes());
    }
}

fn upgrade_tag(upgrade: NetworkUpgrade) -> u8 {
    match upgrade {
        NetworkUpgrade::Genesis => 0,
        NetworkUpgrade::BeforeOverwinter => 1,
        NetworkUpgrade::Overwinter => 2,
        NetworkUpgrade::Sapling => 3,
        NetworkUpgrade::Blossom => 4,
        NetworkUpgrade::Heartwood => 5,
        NetworkUpgrade::Canopy => 6,
        NetworkUpgrade::Nu5 => 7,
        NetworkUpgrade::Nu6 => 8,
        NetworkUpgrade::Nu6_1 => 9,
        NetworkUpgrade::Nu6_2 => 10,
        NetworkUpgrade::Nu6_3 => 11,
        NetworkUpgrade::Nu7 => 12,
        #[cfg(zcash_unstable = "zfuture")]
        NetworkUpgrade::ZFuture => 255,
    }
}

fn receiver_tag(receiver: FundingStreamReceiver) -> u8 {
    match receiver {
        FundingStreamReceiver::Ecc => 0,
        FundingStreamReceiver::ZcashFoundation => 1,
        FundingStreamReceiver::MajorGrants => 2,
        FundingStreamReceiver::Deferred => 3,
    }
}

fn address_bytes(address: transparent::Address) -> [u8; 22] {
    let (tag, network_kind, payload) = match address {
        transparent::Address::PayToScriptHash {
            network_kind,
            script_hash,
        } => (0, network_kind, script_hash),
        transparent::Address::PayToPublicKeyHash {
            network_kind,
            pub_key_hash,
        } => (1, network_kind, pub_key_hash),
        transparent::Address::Tex {
            network_kind,
            validating_key_hash,
        } => (2, network_kind, validating_key_hash),
    };
    let mut bytes = [0; 22];
    bytes[0] = tag;
    bytes[1] = match network_kind {
        NetworkKind::Mainnet => 0,
        NetworkKind::Testnet => 1,
        NetworkKind::Regtest => 2,
    };
    bytes[2..].copy_from_slice(&payload);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block,
        parameters::{
            testnet::{
                ConfiguredActivationHeights, ConfiguredCheckpoints,
                ConfiguredFundingStreamRecipient, ConfiguredFundingStreams,
                ConfiguredLockboxDisbursement, ExperimentalSlhDsaB128sLimits, ParametersBuilder,
            },
            Magic, Network,
        },
        work::difficulty::{ExpandedDifficulty, U256},
    };

    fn builder() -> ParametersBuilder {
        Parameters::build()
            .with_network_name("SlhDevnet")
            .unwrap()
            .with_network_magic(Magic([0x53, 0x4c, 0x48, 0x31]))
            .unwrap()
            .with_genesis_hash(block::Hash([42; 32]))
            .unwrap()
            .with_activation_heights(ConfiguredActivationHeights {
                nu6_3: Some(1),
                nu7: Some(5),
                ..Default::default()
            })
            .unwrap()
            .with_slow_start_interval(Height(0))
            .clear_funding_streams()
            .with_target_difficulty_limit(ExpandedDifficulty::from(U256::from(1)))
            .unwrap()
            .with_disable_pow(false)
            .with_max_block_time_start_height(Height(2))
            .with_unshielded_coinbase_spends(false)
            .with_halving_interval(144)
            .unwrap()
            .with_lockbox_disbursements(vec![])
            .clear_checkpoints()
            .unwrap()
            .disable_temporary_orchard_disabling_soft_fork()
            .with_experimental_slh_dsa_b128s(
                Height(10),
                ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap(),
            )
            .unwrap()
    }

    fn fingerprint(builder: ParametersBuilder) -> [u8; 32] {
        builder
            .to_network()
            .unwrap()
            .experimental_slh_dsa_b128s_chain_fingerprint()
            .unwrap()
    }

    fn address(payload: u8) -> String {
        transparent::Address::PayToScriptHash {
            network_kind: NetworkKind::Testnet,
            script_hash: [payload; 20],
        }
        .to_string()
    }

    fn stream(start: u32) -> ConfiguredFundingStreams {
        ConfiguredFundingStreams {
            height_range: Some(Height(start)..Height(start + 1)),
            recipients: Some(vec![
                ConfiguredFundingStreamRecipient {
                    receiver: FundingStreamReceiver::MajorGrants,
                    numerator: 8,
                    addresses: Some(vec![address(1)]),
                },
                ConfiguredFundingStreamRecipient {
                    receiver: FundingStreamReceiver::Deferred,
                    numerator: 12,
                    addresses: None,
                },
            ]),
        }
    }

    #[test]
    fn slh_chain_fingerprint_has_a_stable_v1_encoding() {
        // Independent Python hashlib/struct encoding of this 309-byte fixture.
        // The simple fixture fixes every configurable value, including the PoW
        // limit of 1, intervals of 144/288, and Genesis/NU6.3/NU7 at 0/1/5.
        assert_eq!(
            hex::encode(fingerprint(builder())),
            "556994bb63690a82e2b86c5dbfaeb03481bb1beb5e856ac9dd4d25eb08d5f8c4"
        );
        assert_eq!(fingerprint(builder()), fingerprint(builder()));

        for network in [
            Network::Mainnet,
            Network::new_default_testnet(),
            Network::new_regtest(Default::default()),
        ] {
            assert!(network
                .experimental_slh_dsa_b128s_chain_fingerprint()
                .is_none());
        }
    }

    #[test]
    fn slh_chain_fingerprint_changes_with_configured_consensus_rules() {
        let expected = fingerprint(builder());
        let mutations = [
            ("name", builder().with_network_name("SlhDevnet2").unwrap()),
            (
                "magic",
                builder()
                    .with_network_magic(Magic([0x53, 0x4c, 0x48, 0x32]))
                    .unwrap(),
            ),
            (
                "genesis",
                builder()
                    .with_genesis_hash(block::Hash([43; 32]))
                    .unwrap()
                    .clear_checkpoints()
                    .unwrap(),
            ),
            (
                "upgrade schedule",
                builder()
                    .with_activation_heights(ConfiguredActivationHeights {
                        nu6_3: Some(1),
                        nu7: Some(6),
                        ..Default::default()
                    })
                    .unwrap(),
            ),
            (
                "SLH activation",
                builder()
                    .with_experimental_slh_dsa_b128s(
                        Height(11),
                        ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap(),
                    )
                    .unwrap(),
            ),
            (
                "transaction limit",
                builder()
                    .with_experimental_slh_dsa_b128s(
                        Height(10),
                        ExperimentalSlhDsaB128sLimits::new(15, 64).unwrap(),
                    )
                    .unwrap(),
            ),
            (
                "block limit",
                builder()
                    .with_experimental_slh_dsa_b128s(
                        Height(10),
                        ExperimentalSlhDsaB128sLimits::new(16, 65).unwrap(),
                    )
                    .unwrap(),
            ),
            ("slow start", builder().with_slow_start_interval(Height(2))),
            ("funding", builder().with_funding_streams(vec![stream(6)])),
            (
                "difficulty limit",
                builder()
                    .with_target_difficulty_limit(ExpandedDifficulty::from(U256::from(2)))
                    .unwrap(),
            ),
            ("PoW mode", builder().with_disable_pow(true)),
            (
                "maximum time",
                builder().with_max_block_time_start_height(Height(3)),
            ),
            (
                "coinbase spends",
                builder().with_unshielded_coinbase_spends(true),
            ),
            (
                "halving interval",
                builder().with_halving_interval(288).unwrap(),
            ),
            (
                "lockbox",
                builder().with_lockbox_disbursements(vec![ConfiguredLockboxDisbursement {
                    address: address(1),
                    amount: 1.try_into().unwrap(),
                }]),
            ),
            (
                "checkpoints",
                builder()
                    .with_checkpoints(ConfiguredCheckpoints::HeightsAndHashes(vec![
                        (Height(0), block::Hash([42; 32])),
                        (Height(1), block::Hash([43; 32])),
                    ]))
                    .unwrap(),
            ),
            (
                "Orchard soft fork",
                builder().with_temporary_orchard_disabling_soft_fork_height(Height(3)),
            ),
            (
                "fixture NSM reissuance",
                builder().with_test_nsm_reissuance_height(Height(200)),
            ),
            (
                "explicit zero NSM seed",
                builder().with_initial_nsm_value_balance(0.try_into().unwrap()),
            ),
            (
                "explicit nonzero NSM seed",
                builder().with_initial_nsm_value_balance(1.try_into().unwrap()),
            ),
        ];
        let mut fingerprints = std::collections::HashSet::from([expected]);
        for (field, changed) in mutations {
            assert!(
                fingerprints.insert(fingerprint(changed)),
                "{field} must change the identity"
            );
        }
    }

    #[test]
    fn slh_chain_fingerprint_normalizes_order_and_ignores_derived_caches() {
        let disbursements = vec![
            ConfiguredLockboxDisbursement {
                address: address(1),
                amount: 1.try_into().unwrap(),
            },
            ConfiguredLockboxDisbursement {
                address: address(2),
                amount: 2.try_into().unwrap(),
            },
        ];
        let streams = vec![stream(6), stream(8)];
        let first = builder()
            .with_funding_streams(streams.clone())
            .with_lockbox_disbursements(disbursements.clone())
            .to_network()
            .unwrap();
        let mut reordered_streams = streams;
        reordered_streams.reverse();
        for stream in &mut reordered_streams {
            stream.recipients.as_mut().unwrap().reverse();
        }
        let mut reordered_disbursements = disbursements;
        reordered_disbursements.reverse();
        let second = builder()
            .with_funding_streams(reordered_streams)
            .with_lockbox_disbursements(reordered_disbursements)
            .to_network()
            .unwrap();
        assert_eq!(
            first.experimental_slh_dsa_b128s_chain_fingerprint(),
            second.experimental_slh_dsa_b128s_chain_fingerprint()
        );

        let params = first.parameters().unwrap();
        let expected = chain_fingerprint(&params);
        params
            .nsm_reissuance_crossing_height
            .get_or_init(|| Some(Height(200)));
        assert_eq!(chain_fingerprint(&params), expected);
    }

    #[test]
    fn slh_chain_fingerprint_binds_funding_lockbox_and_checkpoint_contents() {
        let baseline_stream = stream(6);
        let expected = fingerprint(builder().with_funding_streams(vec![baseline_stream.clone()]));
        let mut mutations = Vec::new();
        let mut changed = baseline_stream.clone();
        changed.height_range = Some(Height(7)..Height(8));
        mutations.push(changed);
        let mut changed = baseline_stream.clone();
        changed.recipients.as_mut().unwrap()[0].receiver = FundingStreamReceiver::Ecc;
        mutations.push(changed);
        let mut changed = baseline_stream.clone();
        changed.recipients.as_mut().unwrap()[0].numerator = 9;
        mutations.push(changed);
        let mut changed = baseline_stream.clone();
        changed.recipients.as_mut().unwrap()[0].addresses = Some(vec![address(2)]);
        mutations.push(changed);
        let mut changed = baseline_stream.clone();
        changed.recipients.as_mut().unwrap()[0].addresses = Some(vec![address(1), address(2)]);
        mutations.push(changed);
        let mut changed = baseline_stream;
        changed.recipients.as_mut().unwrap()[0].addresses = Some(vec![address(2), address(1)]);
        mutations.push(changed);
        let mut fingerprints = std::collections::HashSet::from([expected]);
        for changed in mutations {
            assert!(fingerprints.insert(fingerprint(builder().with_funding_streams(vec![changed]))));
        }

        let mut fingerprints = std::collections::HashSet::new();
        for (payload, amount) in [(1, 1), (2, 1), (1, 2)] {
            assert!(
                fingerprints.insert(fingerprint(builder().with_lockbox_disbursements(vec![
                    ConfiguredLockboxDisbursement {
                        address: address(payload),
                        amount: amount.try_into().unwrap(),
                    },
                ])))
            );
        }

        let mut fingerprints = std::collections::HashSet::new();
        for (height, payload) in [(1, 43), (2, 43), (1, 44)] {
            assert!(fingerprints.insert(fingerprint(
                builder()
                    .with_checkpoints(ConfiguredCheckpoints::HeightsAndHashes(vec![
                        (Height(0), block::Hash([42; 32])),
                        (Height(height), block::Hash([payload; 32])),
                    ]))
                    .unwrap()
            )));
        }
    }

    #[test]
    fn slh_chain_fingerprint_uses_the_normalized_upgrade_schedule() {
        let equivalent = builder()
            .with_activation_heights(ConfiguredActivationHeights {
                nu6_2: Some(1),
                nu6_3: Some(1),
                nu7: Some(5),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(fingerprint(builder()), fingerprint(equivalent));
    }
}
