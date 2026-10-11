//! One SLH CPU task per transaction: ordered reservation, then ordered parallel checks.

use crate::{error::TransactionError, transaction::pq::SlhDsaB128sTransactionBudget};
use rayon::prelude::*;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};
use zakura_chain::{
    parameters::NetworkUpgrade,
    transaction::{AuthDigest, Hash, Transaction},
    transparent,
};

// Selectively adapted from the pinned research worker observation hook. This
// process-local diagnostic is disabled by default and never selects a backend.
const OBSERVATION_ENV: &str = "ZAKURA_SLH_PRIMITIVE_OBSERVE";

struct Observation {
    token: String,
    sequence: AtomicU64,
    #[cfg(test)]
    sink: Option<Arc<dyn Fn(String) + Send + Sync>>,
}

impl Observation {
    fn configured(network: zakura_pq_tx_context::NetworkDomain, token: &str) -> Option<Self> {
        (network == zakura_pq_tx_context::NetworkDomain::Regtest
            && token.len() == 32
            && token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        .then(|| Self {
            token: token.to_owned(),
            sequence: AtomicU64::new(0),
            #[cfg(test)]
            sink: None,
        })
    }

    fn entry(&self, txid: Hash, auth_digest: AuthDigest, input: usize, check: usize) {
        // Assignment order, not log-write order, defines the capture sequence.
        // Receipts reject missing/duplicate/wrapped sequences and count attempts
        // over an observed window, never attribute retries to one RPC request.
        let sequence = self
            .sequence
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let line = format!(
            "slh_primitive_v1 token={} pid={} seq={} txid={} auth_digest={} input={} check={} backend=portable-rust contract=slh-dsa-b-128s-exp-v1",
            self.token, std::process::id(), sequence, txid, auth_digest, input, check,
        );
        tracing::info!(target: "slh_primitive", "{line}");
        #[cfg(test)]
        if let Some(sink) = &self.sink {
            sink(line);
        }
    }
}

fn observation(network: zakura_pq_tx_context::NetworkDomain) -> Option<&'static Observation> {
    if network != zakura_pq_tx_context::NetworkDomain::Regtest {
        return None;
    }
    static OBSERVATION: OnceLock<Option<Observation>> = OnceLock::new();
    OBSERVATION
        .get_or_init(|| Observation::configured(network, &std::env::var(OBSERVATION_ENV).ok()?))
        .as_ref()
}

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
    budget: SlhDsaB128sTransactionBudget,
) -> Result<u32, TransactionError> {
    verify_inputs(
        transaction,
        network,
        upgrade,
        spent_outputs,
        input_indexes,
        budget,
        observation(network),
    )
}

fn verify_inputs(
    transaction: &Transaction,
    network: zakura_pq_tx_context::NetworkDomain,
    upgrade: NetworkUpgrade,
    spent_outputs: Arc<Vec<transparent::Output>>,
    input_indexes: &[usize],
    mut budget: SlhDsaB128sTransactionBudget,
    observation: Option<&Observation>,
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
    let identity = observation.map(|_| {
        let (txid, auth_digest) = transaction.txid_and_auth_digest();
        (
            txid,
            auth_digest.expect("the validated native context requires a v5/v6 transaction"),
        )
    });
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
            input
                .checks()
                .iter()
                .enumerate()
                .map(move |(ordinal, check)| (input_index, ordinal, check))
        })
        .collect();
    if let Some(error) = checks
        .par_iter()
        .find_map_first(|(input_index, ordinal, check)| {
            check
                .verify_with_observation(|| {
                    if let (Some(observation), Some((txid, auth_digest))) = (observation, identity)
                    {
                        observation.entry(txid, auth_digest, *input_index, *ordinal);
                    }
                })
                .err()
                .map(|error| rejected(*input_index, error))
        })
    {
        return Err(error);
    }
    stopped.map_or_else(|| Ok(budget.reserved()), Err)
}

#[cfg(all(test, feature = "slh-test-observer"))]
pub(in crate::transaction) fn verify_observed_inputs_for_test(
    transaction: &Transaction,
    network: zakura_pq_tx_context::NetworkDomain,
    upgrade: NetworkUpgrade,
    spent_outputs: Arc<Vec<transparent::Output>>,
    input_indexes: &[usize],
    budget: SlhDsaB128sTransactionBudget,
    sink: Arc<dyn Fn(String) + Send + Sync>,
) -> Result<u32, TransactionError> {
    let mut observation = Observation::configured(network, "0123456789abcdef0123456789abcdef");
    if let Some(observation) = &mut observation {
        observation.sink = Some(sink);
    }
    verify_inputs(
        transaction,
        network,
        upgrade,
        spent_outputs,
        input_indexes,
        budget,
        observation.as_ref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_pq_tx_context::NetworkDomain;

    #[test]
    fn slh_observation_requires_explicit_regtest_token() {
        let token = "0123456789abcdef0123456789abcdef";
        assert!(Observation::configured(NetworkDomain::Regtest, token).is_some());
        for network in [NetworkDomain::Mainnet, NetworkDomain::Testnet] {
            assert!(Observation::configured(network, token).is_none());
            assert!(observation(network).is_none());
        }
        for token in [
            "",
            "1",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdeg",
            "0123456789abcdef0123456789abcdef\n",
        ] {
            assert!(Observation::configured(NetworkDomain::Regtest, token).is_none());
        }
    }
}
