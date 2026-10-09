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
    if transaction.inputs().len() != spent_outputs.len() {
        return Err(TransactionError::ExperimentalSlhDsaB128sContext {
            reason: "input_context".to_owned(),
        });
    }
    if !active {
        return Ok(Vec::new());
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
        Err(TransactionError::ExperimentalSlhDsaB128sContext {
            reason: "backend_unavailable".to_owned(),
        })
    }
}
