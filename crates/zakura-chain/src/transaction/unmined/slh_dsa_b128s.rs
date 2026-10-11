//! In-memory SLH verification accounting; never supplied or serialized by a peer.

use std::sync::Arc;

use crate::{
    block::Height,
    parameters::{Network, NetworkUpgrade},
    transparent,
};

use super::{Transaction, UnminedTxId, VerifiedUnminedTx};

#[cfg(test)]
mod tests;

/// Successful SLH accounting bound to the exact transaction, trusted outputs and
/// configured rules. The existing payload allocations are shared, not copied.
#[derive(Clone, PartialEq)]
pub struct SlhDsaB128sVerification {
    checks: u32,
    id: UnminedTxId,
    transaction: Arc<Transaction>,
    spent_outputs: Arc<Vec<transparent::Output>>,
    network: Network,
    upgrade: NetworkUpgrade,
}

impl std::fmt::Debug for SlhDsaB128sVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlhDsaB128sVerification")
            .field("checks", &self.checks)
            .field("upgrade", &self.upgrade)
            .finish_non_exhaustive()
    }
}

/// Verified SLH accounting is absent or incompatible with the payload or rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("missing or incompatible experimental SLH verification context")]
pub struct SlhDsaB128sVerificationError;

/// One experimental suite's activation gate and per-transaction limit.
struct SuiteRules {
    active: bool,
    transaction_limit: Option<u32>,
}

impl SuiteRules {
    fn slh_dsa_b128s(network: &Network, height: Height) -> Self {
        Self {
            active: network.is_experimental_slh_dsa_b128s_active(height),
            transaction_limit: network
                .experimental_slh_dsa_b128s_limits()
                .map(|l| l.transaction()),
        }
    }
}

impl VerifiedUnminedTx {
    /// Record accounting after all native, legacy, shielded and state checks
    /// succeed. Like [`Self::new`], this is a trusted verifier constructor, not
    /// a verification operation. `checks` must be the successful worker's count;
    /// a policy parse or a peer-supplied count is not sufficient evidence.
    pub fn with_verified_slh_dsa_b128s(
        mut self,
        network: &Network,
        height: Height,
        checks: u32,
    ) -> Result<Self, SlhDsaB128sVerificationError> {
        self.slh_dsa_b128s_verification = Some(Box::new(self.bind_verification(
            SuiteRules::slh_dsa_b128s(network, height),
            network,
            height,
            checks,
        )?));
        Ok(self)
    }

    /// Return a verified count only when the payload, UTXOs and rules still agree.
    /// Ordinary forward tips within the same rules era preserve this metadata.
    /// Fork/UTXO freshness remains the mempool's reset and tip-snapshot contract.
    /// When SLH is inactive, unannotated legacy entries have zero native cost;
    /// entries verified under active SLH rules must be reverified after rollback.
    pub fn verified_slh_dsa_b128s_checks(
        &self,
        network: &Network,
        height: Height,
    ) -> Result<u32, SlhDsaB128sVerificationError> {
        self.checked_verification(
            self.slh_dsa_b128s_verification.as_deref(),
            SuiteRules::slh_dsa_b128s(network, height),
            network,
            height,
        )
    }

    fn bind_verification(
        &self,
        rules: SuiteRules,
        network: &Network,
        height: Height,
        checks: u32,
    ) -> Result<SlhDsaB128sVerification, SlhDsaB128sVerificationError> {
        if !rules.active
            || checks
                > rules
                    .transaction_limit
                    .ok_or(SlhDsaB128sVerificationError)?
            || self.spent_outputs.len() != self.transaction.transaction().inputs().len()
        {
            return Err(SlhDsaB128sVerificationError);
        }
        Ok(SlhDsaB128sVerification {
            checks,
            id: self.transaction.id(),
            transaction: self.transaction.transaction().clone(),
            spent_outputs: self.spent_outputs.clone(),
            network: network.clone(),
            upgrade: NetworkUpgrade::current(network, height),
        })
    }

    fn checked_verification(
        &self,
        verified: Option<&SlhDsaB128sVerification>,
        rules: SuiteRules,
        network: &Network,
        height: Height,
    ) -> Result<u32, SlhDsaB128sVerificationError> {
        if !rules.active {
            return verified
                .is_none()
                .then_some(0)
                .ok_or(SlhDsaB128sVerificationError);
        }
        let verified = verified.ok_or(SlhDsaB128sVerificationError)?;
        if verified.network != *network
            || verified.upgrade != NetworkUpgrade::current(network, height)
            || verified.id != self.transaction.id()
            || !Arc::ptr_eq(&verified.transaction, self.transaction.transaction())
            || !Arc::ptr_eq(&verified.spent_outputs, &self.spent_outputs)
            || verified.checks
                > rules
                    .transaction_limit
                    .ok_or(SlhDsaB128sVerificationError)?
        {
            return Err(SlhDsaB128sVerificationError);
        }
        Ok(verified.checks)
    }
}
