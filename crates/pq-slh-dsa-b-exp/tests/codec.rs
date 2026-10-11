use zakura_chain::{
    serialization::ZcashSerialize,
    transaction::Hash,
    transparent::{Input, OutPoint, Script},
};
use zakura_pq_slh_dsa_b_exp::{
    codec::{authorization_size, key_commitment, push, MAX_AUTHORIZATION_SIZE},
    profile::{PUBLIC_KEY_SIZE, SIGNATURE_SIZE},
    template_commitment, Authorization, Policy, Record, Rejection,
};

const RECORD_BYTES: usize = 7_893;

fn policy(m: u8, n: u8) -> Policy {
    Policy::new(m, (0..n).map(|i| [i + 1; 32]).collect()).unwrap()
}

fn authorization(m: u8, n: u8) -> Authorization {
    Authorization {
        policy: policy(m, n),
        records: (0..m)
            .map(|index| Record {
                index,
                public_key: [index; PUBLIC_KEY_SIZE],
                signature: vec![index; SIGNATURE_SIZE]
                    .into_boxed_slice()
                    .try_into()
                    .unwrap(),
            })
            .collect(),
    }
}

fn with_descriptor(records: &[u8], descriptor: &[u8]) -> Vec<u8> {
    let mut bytes = records.to_vec();
    push(&mut bytes, descriptor);
    bytes
}

#[test]
fn all_120_policy_shapes_round_trip_and_match_record_boundaries() {
    let mut count = 0;
    for n in 1..=15 {
        for m in 1..=n {
            let original = authorization(m, n);
            let encoded = original.encode();
            let descriptor = 4 + 32 * usize::from(n);
            let prefix = match n {
                1..=2 => 1,
                3..=7 => 2,
                _ => 3,
            };
            assert_eq!(
                encoded.len(),
                usize::from(m) * RECORD_BYTES + prefix + descriptor
            );
            assert_eq!(encoded.len(), authorization_size(m.into(), n.into()));
            assert_eq!(Authorization::decode(&encoded), Ok(original));
            for index in 0..m {
                let at = usize::from(index) * RECORD_BYTES;
                assert_eq!(encoded[at], if index == 0 { 0 } else { 0x50 + index });
                assert_eq!(encoded[at + 1], 0x20);
                assert_eq!(&encoded[at + 34..at + 37], &[0x4d, 0xb0, 0x1e]);
            }
            count += 1;
        }
    }
    assert_eq!(count, 120);
    for (m, n, bytes) in [
        (1, 1, 7_930),
        (2, 3, 15_888),
        (8, 10, 63_471),
        (9, 10, 71_364),
        (10, 10, 79_257),
        (15, 15, 118_882),
    ] {
        assert_eq!(authorization(m, n).encode().len(), bytes);
    }
}

#[test]
fn maximum_input_uses_compact_size_five_and_signature_pushdata_two() {
    let authorization = authorization(15, 15);
    let script = authorization.encode();
    assert_eq!(&script[..2], &[0, 0x20]);
    assert_eq!(&script[34..37], &[0x4d, 0xb0, 0x1e]);
    assert_eq!(
        &script[15 * RECORD_BYTES..15 * RECORD_BYTES + 3],
        &[0x4d, 0xe4, 1]
    );
    let input = Input::PrevOut {
        outpoint: OutPoint {
            hash: Hash([1; 32]),
            index: 7,
        },
        unlock_script: Script::new(&script),
        sequence: u32::MAX,
    };
    let bytes = input.zcash_serialize_to_vec().unwrap();
    assert_eq!(bytes.len(), 118_927);
    assert_eq!(&bytes[36..41], &[0xfe, 0x62, 0xd0, 1, 0]);
    assert_eq!(&bytes[41..41 + script.len()], &script);
}

#[test]
fn index_fourteen_is_canonical_and_fifteen_is_rejected() {
    let mut authorization = authorization(1, 15);
    authorization.records[0].index = 14;
    let mut bytes = authorization.encode();
    assert_eq!(bytes[0], 0x5e);
    assert_eq!(Authorization::decode(&bytes), Ok(authorization));
    bytes[0] = 0x5f;
    assert_eq!(Authorization::decode(&bytes), Err(Rejection::Encoding));
    bytes[0] = 0x60;
    assert_eq!(Authorization::decode(&bytes), Err(Rejection::Encoding));
}

#[test]
fn caps_are_checked_before_records_and_sixteenth_record_before_its_body() {
    let maximum = authorization(15, 15).encode();
    let mut sixteenth = maximum[..15 * RECORD_BYTES].to_vec();
    // No key/signature follows this index. Count rejection must win first.
    sixteenth.push(0x5e);
    assert_eq!(
        Authorization::decode(&sixteenth),
        Err(Rejection::SignatureCount)
    );
    let mut at_guard = maximum;
    at_guard.resize(MAX_AUTHORIZATION_SIZE, 0);
    assert_eq!(at_guard.len(), 131_072);
    assert_eq!(Authorization::decode(&at_guard), Err(Rejection::Encoding));
    at_guard.push(0);
    assert_eq!(
        Authorization::decode(&at_guard),
        Err(Rejection::AuthorizationSize)
    );
    assert_eq!(
        Authorization::decode(&vec![0; 131_073]),
        Err(Rejection::AuthorizationSize)
    );
    // Count validation precedes even the missing commitment bytes.
    assert_eq!(Policy::decode(&[1, 0xf7, 1, 16]), Err(Rejection::Threshold));
    assert_eq!(Policy::new(1, vec![[0; 32]; 16]), Err(Rejection::Threshold));
}

#[test]
fn every_field_rejects_nonminimal_pushes_and_wrong_fixed_lengths() {
    let good = authorization(1, 1).encode();
    let signature = &good[37..37 + SIGNATURE_SIZE];
    let descriptor = &good[RECORD_BYTES + 1..];
    let variants = [
        // Key through PUSHDATA1 or PUSHDATA2 instead of direct 32.
        [&good[..1], &[0x4c, 32], &good[2..]].concat(),
        [&good[..1], &[0x4d, 32, 0], &good[2..]].concat(),
        // Key short or extended by one byte, each still minimally pushed.
        [&good[..1], &[31], &good[2..33], &good[34..]].concat(),
        [&good[..1], &[33], &good[2..34], &[0], &good[34..]].concat(),
        // PUSHDATA4 is not a permitted spelling for an individual signature.
        [&good[..34], &[0x4e, 0xb0, 0x1e, 0, 0], &good[37..]].concat(),
        // Signature short or extended; not a suffix-bearing signature format.
        [
            &good[..34],
            &[0x4d, 0xaf, 0x1e],
            &signature[..SIGNATURE_SIZE - 1],
            &good[RECORD_BYTES..],
        ]
        .concat(),
        [
            &good[..34],
            &[0x4d, 0xb1, 0x1e],
            signature,
            &[0],
            &good[RECORD_BYTES..],
        ]
        .concat(),
        // Single-byte pushes of 0 or 1 are not canonical signer index opcodes.
        [&[1, 0], &good[1..]].concat(),
        [&[1, 1], &good[1..]].concat(),
        // Descriptor through longer framing, plus a truncated descriptor.
        [&good[..RECORD_BYTES], &[0x4c, 36], descriptor].concat(),
        [&good[..RECORD_BYTES], &[0x4d, 36, 0], descriptor].concat(),
        good[..good.len() - 1].to_vec(),
        [good.as_slice(), &[0]].concat(),
    ];
    for bytes in variants {
        assert_eq!(Authorization::decode(&bytes), Err(Rejection::Encoding));
    }
}

#[test]
fn decoder_rejects_excess_records_with_valid_signer_indices() {
    for participants in 2..=15 {
        let complete = authorization(participants, participants).encode();
        let records = &complete[..usize::from(participants) * RECORD_BYTES];
        for threshold in 1..participants {
            // Keep canonical records with distinct, ordered, in-range indices.
            // Only their count differs from the descriptor's required threshold.
            let encoded = with_descriptor(records, &policy(threshold, participants).descriptor());
            assert_eq!(
                Authorization::decode(&encoded),
                Err(Rejection::SignatureCount),
                "{participants} records for a {threshold}-of-{participants} policy"
            );
        }
    }
}

#[test]
fn descriptors_and_signer_order_are_rejected_without_normalizing() {
    let good = authorization(2, 3).encode();
    let mut duplicate = good.clone();
    duplicate[RECORD_BYTES] = 0;
    assert_eq!(
        Authorization::decode(&duplicate),
        Err(Rejection::SignerIndex)
    );
    let mut descending = good.clone();
    descending[0] = 0x51;
    descending[RECORD_BYTES] = 0;
    assert_eq!(
        Authorization::decode(&descending),
        Err(Rejection::SignerIndex)
    );
    let mut outside = authorization(1, 1).encode();
    outside[0] = 0x51;
    assert_eq!(Authorization::decode(&outside), Err(Rejection::SignerIndex));
    assert_eq!(
        Authorization::decode(&good[RECORD_BYTES..]),
        Err(Rejection::SignatureCount)
    );
    let base = policy(2, 3).descriptor();
    for field in [0, 1] {
        let mut unsupported = base.clone();
        unsupported[field] ^= 1;
        assert_eq!(
            Policy::decode(&unsupported),
            Err(Rejection::UnsupportedPolicy)
        );
    }
    for (m, n) in [(0, 1), (2, 1), (1, 0), (1, 16), (16, 15)] {
        assert_eq!(Policy::decode(&[1, 0xf7, m, n]), Err(Rejection::Threshold));
    }
    let mut reversed = base.clone();
    reversed[4..].rotate_left(32);
    assert_eq!(Policy::decode(&reversed), Err(Rejection::KeyOrder));
    let mut duplicate = base.clone();
    duplicate[36..68].copy_from_slice(&base[4..36]);
    assert_eq!(Policy::decode(&duplicate), Err(Rejection::KeyOrder));
    assert_eq!(Policy::new(1, vec![[1; 32]; 2]), Err(Rejection::KeyOrder));
    assert_eq!(
        Policy::decode(&base[..base.len() - 1]),
        Err(Rejection::Encoding)
    );
    assert_eq!(
        Authorization::decode(&with_descriptor(&good[..2 * RECORD_BYTES], &reversed)),
        Err(Rejection::KeyOrder)
    );
}

#[test]
fn commitment_known_answers_and_exact_template_are_domain_separated() {
    // Expected bytes independently computed with Python's hashlib.sha256 from
    // the literal protocol domains, suite byte and bytes(range(32)) key.
    let public_key = std::array::from_fn(|i| u8::try_from(i).unwrap());
    let commitment = key_commitment(&public_key);
    assert_eq!(
        hex::encode(commitment),
        "d10df4666f5ee2ef8d7f848edb301bf2ee9d81b1ca9dd26febb7edaffca4efc1"
    );
    let policy = Policy::new(1, vec![commitment]).unwrap();
    assert_eq!(
        hex::encode(policy.commitment()),
        "75c3cde55e376d5f3e9b6f77d92c4f217bf5d0fdea0424e0a7f8e843ce26bba3"
    );
    let script = policy.lock_script();
    let good = script.as_raw_bytes();
    assert_eq!(
        (good.len(), good[0], good[1], good[34]),
        (35, 0x53, 0x20, 0xc0)
    );
    assert_eq!(template_commitment(good), Some(policy.commitment()));
    for opcode in [0x51, 0x52, 0x54] {
        let mut other = good.to_vec();
        other[0] = opcode;
        assert_eq!(template_commitment(&other), None);
    }
    for (index, value) in [(1, 0x4c), (34, 0xac)] {
        let mut other = good.to_vec();
        other[index] = value;
        assert_eq!(template_commitment(&other), None);
    }
    assert_eq!(template_commitment(&good[..34]), None);
    assert_eq!(template_commitment(&[good, &[0]].concat()), None);
}
