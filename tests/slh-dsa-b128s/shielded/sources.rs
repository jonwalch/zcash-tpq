//! Existing public shielded bundle encodings and field-level mutators.
//! Source pins and unmodified input hashes are recorded in sources.json.

use zakura_chain::{
    orchard, sapling,
    serialization::{ZcashDeserialize, ZcashSerialize},
    transaction::Transaction,
};

/// Pool bit for the Orchard bundle in [`actions_mut`].
pub const ORCHARD: u8 = 2;
/// Pool bit for the Ironwood bundle in [`actions_mut`].
pub const IRONWOOD: u8 = 4;

/// The public shielded source transactions, normalized to v6 at NU6.3.
pub fn source(pool: &str) -> Transaction {
    let hex = match pool {
        "sapling" => include_str!("data/sapling-source.hex"),
        "sapling_output" => include_str!("data/sapling-output-source.hex"),
        "orchard" => include_str!("data/orchard-source.hex"),
        "ironwood" => include_str!("data/ironwood-source.hex"),
        _ => unreachable!("no such source bundle"),
    }
    .split_whitespace()
    .collect::<String>();
    let mut bytes = hex::decode(hex).unwrap();
    bytes[4..8].copy_from_slice(&zakura_chain::parameters::TX_V6_VERSION_GROUP_ID.to_le_bytes());
    bytes[8..12].copy_from_slice(&0x37a5165b_u32.to_le_bytes());
    Transaction::zcash_deserialize(bytes.as_slice()).unwrap()
}

pub fn sapling_mut(tx: &mut Transaction) -> &mut sapling::ShieldedData<sapling::SharedAnchor> {
    match tx {
        Transaction::V5 {
            sapling_shielded_data,
            ..
        }
        | Transaction::V6 {
            sapling_shielded_data,
            ..
        } => sapling_shielded_data.as_mut().unwrap(),
        _ => unreachable!("shielded fixtures are v5 or v6"),
    }
}

/// The Orchard (`ORCHARD`) or Ironwood (`IRONWOOD`) bundle; v5 has only Orchard.
pub fn actions_mut(tx: &mut Transaction, pool: u8) -> &mut orchard::ShieldedData {
    match tx {
        Transaction::V5 {
            orchard_shielded_data,
            ..
        } => {
            assert_eq!(pool, ORCHARD, "v5 has no Ironwood pool");
            orchard_shielded_data.as_mut().unwrap()
        }
        Transaction::V6 {
            orchard_shielded_data,
            ironwood_shielded_data,
            ..
        } => match pool {
            ORCHARD => orchard_shielded_data.as_deref_mut().unwrap(),
            IRONWOOD => ironwood_shielded_data.as_mut().unwrap(),
            _ => unreachable!("no such action pool"),
        },
        _ => unreachable!("shielded fixtures are v5 or v6"),
    }
}

/// Re-encode `value` with one byte changed.
pub fn change_byte<T: ZcashSerialize + ZcashDeserialize>(value: &T, offset: usize, mask: u8) -> T {
    let mut bytes = value.zcash_serialize_to_vec().unwrap();
    bytes[offset] ^= mask;
    T::zcash_deserialize(bytes.as_slice()).unwrap()
}

/// Give a synthetic bundle its canonical proof length; only the length matters
/// for digest tests, which claim no valid zero-knowledge proofs.
pub fn resize_proof(bundle: &mut orchard::ShieldedData) {
    bundle.proof.0.resize(2720 + 2272 * bundle.actions.len(), 0);
    assert!(bundle.proof_size_is_canonical());
}
