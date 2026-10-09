//! One SLH CPU task per transaction: ordered reservation, then ordered parallel checks.

use crate::{error::TransactionError, transaction::pq::SlhDsaB128sTransactionBudget};
use rayon::prelude::*;
use std::sync::Arc;
use zakura_chain::{parameters::NetworkUpgrade, transaction::Transaction, transparent};

/// Verifies the SLH authorization of each input in `input_indexes`.
///
/// The caller selects these inputs from the active gate and resolved UTXOs, and
/// supplies every spent output in input order. The signature-digest precomputation
/// is shared by all of them instead of being repeated for each input.
///
/// Inputs are validated and reserved in the supplied order, stopping at the first
/// failure. Every reserved signature check then runs on the current Rayon pool.
/// The first failing check in input and signer order wins, so the transaction gets
/// the same error as when each input is verified in turn. Checks after a known
/// failure may be skipped. Reservations are never refunded.
pub(in crate::transaction) fn verify_experimental_slh_dsa_b128s_inputs(
    transaction: &Transaction,
    network: zakura_pq_tx_context::NetworkDomain,
    upgrade: NetworkUpgrade,
    spent_outputs: Arc<Vec<transparent::Output>>,
    input_indexes: &[usize],
    mut budget: SlhDsaB128sTransactionBudget,
) -> Result<u32, TransactionError> {
    if input_indexes.is_empty() {
        return Ok(0);
    }
    let rejected = |input_index, error: zakura_pq_slh_dsa_b_exp::Rejection| {
        TransactionError::ExperimentalSlhDsaB128s {
            input_index,
            reason: error.to_string(),
        }
    };

    let context = zakura_pq_slh_dsa_b_exp::TransactionContext::new(
        transaction,
        network,
        upgrade,
        spent_outputs,
    )
    .map_err(|error| TransactionError::ExperimentalSlhDsaB128sContext {
        reason: error.to_string(),
    })?;
    let mut reserved = Vec::with_capacity(input_indexes.len());
    let mut stopped = None;
    for &input_index in input_indexes {
        let mut reservation_error = None;
        let input = context.reserve_input(input_index, |checks| {
            budget.reserve(checks).map_err(|error| {
                reservation_error = Some(error);
                zakura_pq_slh_dsa_b_exp::Rejection::VerificationBudget
            })
        });
        match input {
            Ok(input) => reserved.push(input),
            Err(error) => {
                stopped = Some(reservation_error.unwrap_or_else(|| rejected(input_index, error)));
                break;
            }
        }
    }

    // A signature failure in an earlier input takes precedence over a later
    // structural or allowance failure, matching sequential verification.
    let checks: Vec<_> = reserved
        .iter()
        .flat_map(|input| {
            let input_index = input.input_index();
            input.checks().iter().map(move |check| (input_index, check))
        })
        .collect();
    if let Some(error) = checks.par_iter().find_map_first(|(input_index, check)| {
        check
            .verify()
            .err()
            .map(|error| rejected(*input_index, error))
    }) {
        return Err(error);
    }
    stopped.map_or_else(|| Ok(budget.reserved()), Err)
}
