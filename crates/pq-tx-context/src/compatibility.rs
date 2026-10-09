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
    use super::*;

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
        // Expectations are independent of the production match and enum ordering.
        let pairs = [
            (5, NetworkUpgrade::Nu5),
            (5, NetworkUpgrade::Nu6),
            (5, NetworkUpgrade::Nu6_1),
            (5, NetworkUpgrade::Nu6_2),
            (5, NetworkUpgrade::Nu6_3),
            (5, NetworkUpgrade::Nu7),
            (6, NetworkUpgrade::Nu6_3),
            (6, NetworkUpgrade::Nu7),
        ];
        for version in (0..=7).chain([u32::MAX]) {
            for upgrade in NetworkUpgrade::iter() {
                let result = reviewed_branch(version, upgrade);
                assert_eq!(
                    result.is_ok(),
                    pairs.contains(&(version, upgrade)),
                    "v{version}, {upgrade:?}"
                );
                if let Err(error) = result {
                    assert!(matches!(error, Error::TransactionVersion));
                }
            }
        }
    }
}
