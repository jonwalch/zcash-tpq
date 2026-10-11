//! Public signing context and partial assembly without secret-key operations.

use std::sync::Arc;

use zakura_chain::{parameters::NetworkUpgrade, transaction::Transaction, transparent::Output};
use zakura_pq_tx_context::NetworkDomain;

use crate::{
    codec::{key_commitment, template_commitment},
    contract::MESSAGE_SIZE,
    verify_signature, Authorization, Policy, Record, Rejection, TransactionContext,
};

/// Public per-input context for independent signers and authorization assembly.
///
/// Construction binds the policy to the actual spent output. Transaction
/// effects must be finalized and separately approved, and the caller must
/// authenticate every supplied previous output. Secret-key signing stays in
/// the wallet signer crate, outside this crate and the node dependency graph.
pub struct InputSigningContext {
    network: NetworkDomain,
    upgrade: NetworkUpgrade,
    input_index: usize,
    policy: Policy,
    message: [u8; MESSAGE_SIZE],
}

impl InputSigningContext {
    /// Check the spent output against `policy` and derive the exact message.
    pub fn new(
        transaction: &Transaction,
        network: NetworkDomain,
        upgrade: NetworkUpgrade,
        previous_outputs: Arc<Vec<Output>>,
        input_index: usize,
        policy: &Policy,
    ) -> Result<Self, Rejection> {
        let spent = previous_outputs
            .get(input_index)
            .ok_or(Rejection::InputContext)?;
        if template_commitment(spent.lock_script.as_raw_bytes()) != Some(policy.commitment()) {
            return Err(Rejection::OutputCommitment);
        }
        let context = TransactionContext::new(transaction, network, upgrade, previous_outputs)?;
        Ok(Self {
            network,
            upgrade,
            input_index,
            policy: policy.clone(),
            message: context.message(input_index)?,
        })
    }

    /// The caller-authenticated network domain.
    pub fn network(&self) -> NetworkDomain {
        self.network
    }

    /// The caller-authenticated network upgrade.
    pub fn upgrade(&self) -> NetworkUpgrade {
        self.upgrade
    }

    /// The input position bound by the message.
    pub fn input_index(&self) -> usize {
        self.input_index
    }

    /// The policy committed by the spent output.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The 101-byte message to pass to the external Pure signing API once.
    pub fn message(&self) -> &[u8; MESSAGE_SIZE] {
        &self.message
    }

    /// Check a received partial's index, key commitment and real signature.
    pub fn verify_partial(&self, record: &Record) -> Result<(), Rejection> {
        let expected = self
            .policy
            .commitments()
            .get(usize::from(record.index))
            .ok_or(Rejection::SignerIndex)?;
        if key_commitment(&record.public_key) != *expected {
            return Err(Rejection::KeyCommitment);
        }
        if !verify_signature(&record.public_key, record.signature.as_ref(), &self.message) {
            return Err(Rejection::Signature);
        }
        Ok(())
    }

    /// Verify exactly the threshold number of partials and assemble in order.
    ///
    /// Sorting belongs to this assembly API. The wire decoder always rejects
    /// noncanonical ordering instead of normalizing received bytes.
    pub fn authorization(&self, mut records: Vec<Record>) -> Result<Authorization, Rejection> {
        if records.len() != usize::from(self.policy.threshold()) {
            return Err(Rejection::SignatureCount);
        }
        records.sort_by_key(|record| record.index);
        if records
            .windows(2)
            .any(|pair| pair[0].index >= pair[1].index)
        {
            return Err(Rejection::SignerIndex);
        }
        records
            .iter()
            .try_for_each(|record| self.verify_partial(record))?;
        Ok(Authorization {
            policy: self.policy.clone(),
            records,
        })
    }
}
