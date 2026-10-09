//! Identifiers and the exact signed message of `slh-dsa-b-128s-exp-v1`.

/// The contract label recorded in vectors and evidence.
pub const CONTRACT: &str = "slh-dsa-b-128s-exp-v1";

use zakura_chain::transaction::Transaction;
use zakura_pq_tx_context::{Error, NetworkDomain, PreparedTransaction};

/// Descriptor layout version, identical in shape to native V1.
pub const FORMAT_VERSION: u8 = 0x01;
/// Experiment-local suite identifier; not an official consensus allocation.
pub const SUITE: u8 = 0xf7;
/// Output template opcode, `OP_3`, recognized without reading any scriptSig.
pub const TEMPLATE_VERSION: u8 = 0x53;
/// Key-commitment domain, ending in one NUL byte.
pub const KEY_DOMAIN: &[u8] = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/key/v1\0";
/// Policy-commitment domain, ending in one NUL byte.
pub const POLICY_DOMAIN: &[u8] = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/policy/v1\0";
/// Signed-message domain, ending in one NUL byte.
pub const MESSAGE_DOMAIN: &[u8] = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/message/v1\0";
/// Domain, suite, network, version, branch, input index and digest.
pub const MESSAGE_SIZE: usize = MESSAGE_DOMAIN.len() + 1 + 1 + 1 + 4 + 4 + 32;

/// Network byte shared with native V1: 00 Mainnet, 01 Testnet, 02 Regtest.
pub fn network_byte(network: NetworkDomain) -> u8 {
    match network {
        NetworkDomain::Mainnet => 0,
        NetworkDomain::Testnet => 1,
        NetworkDomain::Regtest => 2,
    }
}

/// The fixed-width message for one input of an already validated context.
///
/// Version, branch and input position are also committed by the digest or its
/// selected input; they are repeated so binding does not rely on node rules.
pub fn message(
    prepared: &PreparedTransaction<'_>,
    input_index: usize,
) -> Result<[u8; MESSAGE_SIZE], Error> {
    let digest = prepared.input_digest(input_index)?;
    let version = match prepared.transaction() {
        Transaction::V5 { .. } => 5,
        Transaction::V6 { .. } => 6,
        _ => return Err(Error::TransactionVersion),
    };
    let branch = digest
        .upgrade
        .branch_id()
        .ok_or(Error::BackendUnavailable)?;
    let index = u32::try_from(input_index).map_err(|_| Error::InputContext)?;
    let mut bytes = [0; MESSAGE_SIZE];
    let fields: [&[u8]; 7] = [
        MESSAGE_DOMAIN,
        &[SUITE],
        &[network_byte(digest.network)],
        &[version],
        &u32::from(branch).to_le_bytes(),
        &index.to_le_bytes(),
        &digest.digest,
    ];
    let mut at = 0;
    for field in fields {
        bytes[at..at + field.len()].copy_from_slice(field);
        at += field.len();
    }
    debug_assert_eq!(at, MESSAGE_SIZE);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_distinct_versioned_and_message_size_is_fixed() {
        for domain in [KEY_DOMAIN, POLICY_DOMAIN, MESSAGE_DOMAIN] {
            assert_eq!(domain.last(), Some(&0));
            assert_eq!(domain.iter().filter(|&&b| b == 0).count(), 1);
            assert!(domain.is_ascii());
            assert!(
                domain.ends_with(b"/v1\0"),
                "domains are frozen by the v1 contract"
            );
        }
        assert_ne!(KEY_DOMAIN, POLICY_DOMAIN);
        assert_ne!(POLICY_DOMAIN, MESSAGE_DOMAIN);
        // Other experimental suite/template bytes do not identify this contract.
        assert_ne!(SUITE, 0x01);
        assert_ne!(TEMPLATE_VERSION, 0x51);
        assert_eq!(MESSAGE_DOMAIN.len(), 58);
        assert_eq!(MESSAGE_SIZE, 101);
    }
}
