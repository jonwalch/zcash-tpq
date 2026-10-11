//! Reviewed transaction signing pairs. Extending this set requires a signing-contract review.

use zakura_chain::{parameters::NetworkUpgrade, transaction::Transaction};
use zcash_protocol::consensus::BranchId;

use crate::Error;

// Numeric IDs are deliberately independent of either backend's enum conversion.
// This table also classifies historical branch mismatches. Acceptance of a
// matching historical context is separately gated in validate, before hashing.
fn reviewed_branch(version: u32, upgrade: NetworkUpgrade) -> Result<(BranchId, u32), Error> {
    use NetworkUpgrade::{Nu5, Nu6, Nu6_1, Nu6_2, Nu6_3, Nu7};
    match (version, upgrade) {
        (5, Nu5) => Ok((BranchId::Nu5, 0xc2d6_d0b4)),
        (5, Nu6) => Ok((BranchId::Nu6, 0xc8e7_1055)),
        (5, Nu6_1) => Ok((BranchId::Nu6_1, 0x4dec_4df0)),
        (5, Nu6_2) => Ok((BranchId::Nu6_2, 0x5437_f330)),
        (5 | 6, Nu6_3) => Ok((BranchId::Nu6_3, 0x37a5_165b)),
        (5 | 6, Nu7) => Ok((BranchId::Nu7, 0x7719_0ad9)),
        _ => Err(Error::TransactionVersion),
    }
}

fn check_backend(expected: (BranchId, u32), native: Option<u32>) -> Result<(), Error> {
    let (branch, numeric) = expected;
    if native != Some(numeric)
        || u32::from(branch) != numeric
        || BranchId::try_from(numeric) != Ok(branch)
    {
        return Err(Error::BackendUnavailable);
    }
    Ok(())
}

pub(super) fn validate(transaction: &Transaction, upgrade: NetworkUpgrade) -> Result<(), Error> {
    let expected = reviewed_branch(transaction.version(), upgrade)?;
    if transaction.network_upgrade() != Some(upgrade) {
        return Err(Error::ConsensusBranch);
    }
    // Preserve branch-mismatch classification for the saved negative corpus,
    // but never prepare a matching historical context in ordinary builds.
    #[cfg(not(feature = "historical-test-vectors"))]
    if upgrade != NetworkUpgrade::Nu7 {
        return Err(Error::TransactionVersion);
    }
    check_backend(expected, upgrade.branch_id().map(u32::from))
}

#[cfg(test)]
mod tests {
    use zakura_chain::{block::Height, transaction::LockTime};

    use super::*;

    // Expectations are independent of the production match and enum ordering.
    const REVIEWED: [((u32, NetworkUpgrade), (BranchId, u32)); 8] = [
        ((5, NetworkUpgrade::Nu5), (BranchId::Nu5, 0xc2d6_d0b4)),
        ((5, NetworkUpgrade::Nu6), (BranchId::Nu6, 0xc8e7_1055)),
        ((5, NetworkUpgrade::Nu6_1), (BranchId::Nu6_1, 0x4dec_4df0)),
        ((5, NetworkUpgrade::Nu6_2), (BranchId::Nu6_2, 0x5437_f330)),
        ((5, NetworkUpgrade::Nu6_3), (BranchId::Nu6_3, 0x37a5_165b)),
        ((5, NetworkUpgrade::Nu7), (BranchId::Nu7, 0x7719_0ad9)),
        ((6, NetworkUpgrade::Nu6_3), (BranchId::Nu6_3, 0x37a5_165b)),
        ((6, NetworkUpgrade::Nu7), (BranchId::Nu7, 0x7719_0ad9)),
    ];

    fn transaction(version: u32, network_upgrade: NetworkUpgrade) -> Transaction {
        let (lock_time, expiry_height) = (LockTime::unlocked(), Height(0));
        let (inputs, outputs) = (Vec::new(), Vec::new());
        match version {
            5 => Transaction::V5 {
                network_upgrade,
                lock_time,
                expiry_height,
                inputs,
                outputs,
                sapling_shielded_data: None,
                orchard_shielded_data: None,
            },
            6 => Transaction::V6 {
                network_upgrade,
                lock_time,
                expiry_height,
                inputs,
                outputs,
                sapling_shielded_data: None,
                orchard_shielded_data: None,
                ironwood_shielded_data: None,
            },
            _ => unreachable!("reviewed pairs use v5 or v6"),
        }
    }

    /// Validate each reviewed pair with a matching and a mismatched embedded
    /// upgrade. NU7 is accepted in every build; `historical` classifies the
    /// other matching pairs. A mismatch is a branch error in every build.
    fn assert_validate(historical: fn(Result<(), Error>) -> bool) {
        for ((version, upgrade), _) in REVIEWED {
            let result = validate(&transaction(version, upgrade), upgrade);
            if upgrade == NetworkUpgrade::Nu7 {
                assert!(result.is_ok(), "v{version}, {upgrade:?}: {result:?}");
            } else {
                assert!(historical(result), "v{version}, {upgrade:?}");
            }
            let other = if upgrade == NetworkUpgrade::Nu7 {
                NetworkUpgrade::Nu6_3
            } else {
                NetworkUpgrade::Nu7
            };
            assert!(matches!(
                validate(&transaction(version, other), upgrade),
                Err(Error::ConsensusBranch)
            ));
        }
    }

    #[cfg(not(feature = "historical-test-vectors"))]
    #[test]
    fn matching_historical_pairs_are_refused_in_ordinary_builds() {
        assert_validate(|result| matches!(result, Err(Error::TransactionVersion)));
    }

    #[cfg(feature = "historical-test-vectors")]
    #[test]
    fn matching_historical_pairs_reach_the_backend_check_with_test_vectors() {
        assert_validate(|result| result.is_ok());
    }

    #[test]
    fn absent_unknown_and_disagreeing_backend_ids_are_typed_errors() {
        let nu7 = (BranchId::Nu7, 0x7719_0ad9);
        check_backend(nu7, Some(0x7719_0ad9)).unwrap();
        for native in [
            None,
            Some(0),
            Some(0x7719_0ad8),
            Some(0xffff_fffe),
            Some(0xffff_ffff),
            Some(0x37a5_165b),
        ] {
            assert!(matches!(
                check_backend(nu7, native),
                Err(Error::BackendUnavailable)
            ));
        }
        for numeric in [0x7719_0ad8, 0xffff_fffe, 0xffff_ffff, 0x37a5_165b] {
            assert!(matches!(
                check_backend((BranchId::Nu7, numeric), Some(numeric)),
                Err(Error::BackendUnavailable)
            ));
        }
    }

    #[test]
    fn only_explicit_pairs_are_reviewed_including_unknown_versions() {
        for version in (0..=7).chain([u32::MAX]) {
            for upgrade in NetworkUpgrade::iter() {
                let expected = REVIEWED
                    .iter()
                    .find(|(pair, _)| *pair == (version, upgrade))
                    .map(|(_, branch)| *branch);
                match (reviewed_branch(version, upgrade), expected) {
                    (Ok(actual), Some(expected)) => {
                        assert_eq!(actual, expected, "v{version}, {upgrade:?}");
                        // Cross-check the literal against zakura-chain's table.
                        check_backend(expected, upgrade.branch_id().map(u32::from)).unwrap();
                    }
                    (Err(Error::TransactionVersion), None) => {}
                    (result, _) => panic!("v{version}, {upgrade:?}: {result:?}"),
                }
            }
        }
    }
}
