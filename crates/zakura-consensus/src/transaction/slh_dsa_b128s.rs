//! Experimental SLH dispatch from exact trusted outputs and the configured gate.

#[cfg(feature = "experimental-slh-dsa-b128s")]
mod worker;
#[cfg(feature = "experimental-slh-dsa-b128s")]
pub(super) use worker::verify_experimental_slh_dsa_b128s_inputs;
#[cfg(all(test, feature = "slh-test-observer"))]
pub(in crate::transaction) use worker::verify_observed_inputs_for_test;

use crate::error::TransactionError;
use zakura_chain::{transaction::Transaction, transparent};

/// Exact frozen output recognition, independent of witnesses and activation.
pub(crate) fn is_output(output: &transparent::Output) -> bool {
    matches!(output.lock_script.as_raw_bytes(), [0x53, 0x20, .., 0xc0])
        && output.lock_script.as_raw_bytes().len() == 35
}

/// Classify all transparent inputs before scheduling any checks. The caller
/// authenticates `spent_outputs` and supplies them in transaction input order.
/// Outputs being created never influence this classification.
pub(crate) fn input_indexes(
    transaction: &Transaction,
    spent_outputs: &[transparent::Output],
    active: bool,
) -> Result<Vec<usize>, TransactionError> {
    if !active {
        return Ok(Vec::new());
    }
    if transaction.inputs().len() != spent_outputs.len() {
        return Err(TransactionError::ExperimentalSlhDsaB128sInputContext);
    }
    let indexes: Vec<_> = spent_outputs
        .iter()
        .enumerate()
        .filter_map(|(index, output)| is_output(output).then_some(index))
        .collect();
    if !indexes.is_empty() && indexes.len() != transaction.inputs().len() {
        return Err(TransactionError::ExperimentalSlhDsaB128sMixedInputs);
    }
    Ok(indexes)
}

/// Canonical structural count for relay prechecks; never successful accounting.
pub(crate) fn structural_checks(
    transaction: &Transaction,
    spent_outputs: &[transparent::Output],
    indexes: &[usize],
) -> Result<u32, TransactionError> {
    #[cfg(feature = "experimental-slh-dsa-b128s")]
    {
        indexes.iter().try_fold(0u32, |count, &index| {
            let authorization =
                zakura_pq_slh_dsa_b_exp::input_authorization(transaction, spent_outputs, index)
                    .map_err(|_| TransactionError::NonStandardInputs)?;
            count
                .checked_add(u32::from(authorization.policy.threshold()))
                .ok_or(TransactionError::NonStandardInputs)
        })
    }
    #[cfg(not(feature = "experimental-slh-dsa-b128s"))]
    {
        let _ = (transaction, spent_outputs, indexes);
        Err(TransactionError::ExperimentalSlhDsaB128sBackendUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::check;
    use zakura_chain::{block::Height, parameters::NetworkUpgrade, transaction::LockTime};

    fn transaction_and_output() -> (Transaction, transparent::Output) {
        let mut lock_script = vec![0x53, 0x20];
        lock_script.extend([0x11; 32]);
        lock_script.push(0xc0);
        let output = transparent::Output {
            value: 10_000.try_into().unwrap(),
            lock_script: transparent::Script::new(&lock_script),
        };
        let transaction = Transaction::V5 {
            network_upgrade: NetworkUpgrade::Nu7,
            inputs: vec![transparent::Input::PrevOut {
                outpoint: transparent::OutPoint {
                    hash: [0x22; 32].into(),
                    index: 0,
                },
                unlock_script: transparent::Script::new(&[]),
                sequence: u32::MAX,
            }],
            outputs: vec![output.clone()],
            lock_time: LockTime::unlocked(),
            expiry_height: Height(0),
            sapling_shielded_data: None,
            orchard_shielded_data: None,
        };
        (transaction, output)
    }

    #[test]
    fn slh_inactive_dispatch_preserves_classical_context_errors() {
        let (transaction, output) = transaction_and_output();
        for spent_outputs in [vec![], vec![output.clone(), output]] {
            assert_eq!(
                input_indexes(&transaction, &spent_outputs, false),
                Ok(vec![])
            );
            let classical = check::mempool_standard_input_scripts(&transaction, &spent_outputs);
            assert!(matches!(&classical, Err(TransactionError::Other(_))));
            assert_eq!(
                check::mempool_standard_input_scripts_with_slh_dsa_b128s(
                    &transaction,
                    &spent_outputs,
                    false,
                ),
                classical.map(|()| 0)
            );
        }
    }

    #[test]
    fn slh_active_dispatch_requires_matching_local_input_context() {
        let (transaction, output) = transaction_and_output();
        for spent_outputs in [vec![], vec![output.clone(), output]] {
            assert_eq!(
                input_indexes(&transaction, &spent_outputs, true),
                Err(TransactionError::ExperimentalSlhDsaB128sInputContext)
            );
            assert_eq!(
                check::mempool_standard_input_scripts_with_slh_dsa_b128s(
                    &transaction,
                    &spent_outputs,
                    true,
                ),
                Err(TransactionError::ExperimentalSlhDsaB128sInputContext)
            );
        }
    }

    #[cfg(not(feature = "experimental-slh-dsa-b128s"))]
    #[test]
    fn slh_disabled_backend_is_a_local_failure() {
        let (transaction, output) = transaction_and_output();
        assert_eq!(
            check::mempool_standard_input_scripts_with_slh_dsa_b128s(&transaction, &[output], true,),
            Err(TransactionError::ExperimentalSlhDsaB128sBackendUnavailable)
        );
    }
}
