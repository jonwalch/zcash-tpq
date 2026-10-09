//! Per-attempt experimental SLH signature accounting, independent of legacy sigops.
//! Atomic reservations are never refunded, including after failure or cancellation.

use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use zakura_chain::parameters::testnet::ExperimentalSlhDsaB128sLimits;

use crate::error::TransactionError;

/// One experimental signature suite's allowance units, limits and errors.
pub trait SignatureCheckSuite: 'static {
    /// The network's explicit transaction and block limits for this suite.
    type Limits: Copy;
    /// Maximum reserved checks in one transaction.
    fn transaction_limit(limits: Self::Limits) -> u32;
    /// Maximum reserved checks in one block.
    fn block_limit(limits: Self::Limits) -> u32;
    /// The consensus rejection for an exhausted transaction allowance.
    fn transaction_exhausted(limit: u32) -> TransactionError;
    /// The attempt-level error for an exhausted block allowance.
    fn block_exhausted(limit: u32) -> TransactionError;
}

/// Experimental SLH-DSA-B-128s (`slh-dsa-b-128s-exp-v1`) signature checks.
#[derive(Debug)]
pub enum SlhDsaB128sChecks {}

impl SignatureCheckSuite for SlhDsaB128sChecks {
    type Limits = ExperimentalSlhDsaB128sLimits;
    fn transaction_limit(limits: Self::Limits) -> u32 {
        limits.transaction()
    }
    fn block_limit(limits: Self::Limits) -> u32 {
        limits.block()
    }
    fn transaction_exhausted(limit: u32) -> TransactionError {
        TransactionError::ExperimentalSlhDsaB128sTransactionBudget { limit }
    }
    fn block_exhausted(limit: u32) -> TransactionError {
        TransactionError::ExperimentalSlhDsaB128sBlockBudget { limit }
    }
}

/// A shared allowance for one block verification attempt, for one suite.
///
/// Every transaction in the block must receive a clone of the same allowance.
/// Reservations are never refunded, including when validation fails or is cancelled.
/// Equality compares attempt identity, not the counter's changing value.
pub struct BlockCheckBudget<S: SignatureCheckSuite>(Arc<BlockBudgetInner>, PhantomData<S>);

/// The SLH-DSA-B-128s block allowance.
pub type SlhDsaB128sBlockBudget = BlockCheckBudget<SlhDsaB128sChecks>;

#[derive(Debug)]
struct BlockBudgetInner {
    limit: u32,
    remaining: AtomicU32,
}

impl<S: SignatureCheckSuite> Clone for BlockCheckBudget<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<S: SignatureCheckSuite> std::fmt::Debug for BlockCheckBudget<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BlockCheckBudget")
            .field(&std::any::type_name::<S>())
            .field(&self.0)
            .finish()
    }
}

impl<S: SignatureCheckSuite> PartialEq for BlockCheckBudget<S> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl<S: SignatureCheckSuite> Eq for BlockCheckBudget<S> {}

impl<S: SignatureCheckSuite> BlockCheckBudget<S> {
    /// Create a fresh attempt using the network's explicit block limit.
    pub fn new(limits: S::Limits) -> Self {
        let limit = S::block_limit(limits);
        Self(
            Arc::new(BlockBudgetInner {
                limit,
                remaining: AtomicU32::new(limit),
            }),
            PhantomData,
        )
    }

    pub(super) fn limit(&self) -> u32 {
        self.0.limit
    }

    fn reserve(&self, checks: u32) -> Result<(), TransactionError> {
        // This counter publishes no other data; atomicity alone prevents overspending.
        self.0
            .remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(checks)
            })
            .map(|_| ())
            .map_err(|_| S::block_exhausted(self.0.limit))
    }

    #[cfg(test)]
    pub(super) fn remaining(&self) -> u32 {
        self.0.remaining.load(Ordering::Relaxed)
    }
}

/// One transaction attempt's allowance for one suite, plus its block allowance.
pub(super) struct TransactionCheckBudget<S: SignatureCheckSuite> {
    limit: u32,
    remaining: u32,
    block: Option<BlockCheckBudget<S>>,
}

/// The SLH-DSA-B-128s transaction allowance.
#[cfg_attr(not(feature = "experimental-slh-dsa-b128s"), allow(dead_code))]
pub(super) type SlhDsaB128sTransactionBudget = TransactionCheckBudget<SlhDsaB128sChecks>;

impl<S: SignatureCheckSuite> TransactionCheckBudget<S> {
    pub(super) fn new(limits: S::Limits, block: Option<BlockCheckBudget<S>>) -> Self {
        let limit = S::transaction_limit(limits);
        Self {
            limit,
            remaining: limit,
            block,
        }
    }

    pub(super) fn reserve(&mut self, checks: usize) -> Result<(), TransactionError> {
        let checks = u32::try_from(checks).map_err(|_| S::transaction_exhausted(self.limit))?;
        let remaining = self
            .remaining
            .checked_sub(checks)
            .ok_or_else(|| S::transaction_exhausted(self.limit))?;
        if let Some(block) = &self.block {
            block.reserve(checks)?;
        }
        // The local counter has one owner. Commit it only after the shared reservation
        // succeeds, so either exhaustion leaves both allowances unchanged.
        self.remaining = remaining;
        Ok(())
    }

    /// Reservations made by this attempt. Failed crypto retains its reservations;
    /// only a fully successful worker may publish this as verified accounting.
    pub(super) fn reserved(&self) -> u32 {
        self.limit - self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slh_dsa_b128s_functional_profile_exact_boundaries() {
        let limits = ExperimentalSlhDsaB128sLimits::new(16, 64).unwrap();
        let block = SlhDsaB128sBlockBudget::new(limits);
        for transaction_index in 0..4 {
            let mut transaction = SlhDsaB128sTransactionBudget::new(limits, Some(block.clone()));
            transaction.reserve(15).unwrap();
            assert_eq!(transaction.reserved(), 15);
            assert_eq!(block.remaining(), 64 - 16 * transaction_index - 15);
            transaction.reserve(1).unwrap();
            assert_eq!(transaction.reserved(), 16);
            assert_eq!(
                transaction.reserve(1),
                Err(TransactionError::ExperimentalSlhDsaB128sTransactionBudget { limit: 16 })
            );
            assert_eq!(block.remaining(), 64 - 16 * (transaction_index + 1));
        }
        let mut next = SlhDsaB128sTransactionBudget::new(limits, Some(block.clone()));
        assert_eq!(
            next.reserve(1),
            Err(TransactionError::ExperimentalSlhDsaB128sBlockBudget { limit: 64 })
        );
        assert_eq!(next.reserved(), 0);
        assert_eq!(block.remaining(), 0);
        assert_eq!(SlhDsaB128sBlockBudget::new(limits).remaining(), 64);
    }

    #[test]
    fn slh_dsa_b128s_reservations_are_atomic_across_both_allowances() {
        let limits = ExperimentalSlhDsaB128sLimits::new(3, 5).unwrap();
        let block = SlhDsaB128sBlockBudget::new(limits);
        let mut first = SlhDsaB128sTransactionBudget::new(limits, Some(block.clone()));
        first.reserve(2).unwrap();
        assert_eq!(first.remaining, 1);
        assert_eq!(block.remaining(), 3);
        assert_eq!(
            first.reserve(2),
            Err(TransactionError::ExperimentalSlhDsaB128sTransactionBudget { limit: 3 })
        );
        assert_eq!(block.remaining(), 3);
        let mut second = SlhDsaB128sTransactionBudget::new(limits, Some(block.clone()));
        second.reserve(2).unwrap();
        assert_eq!(block.remaining(), 1);
        let mut third = SlhDsaB128sTransactionBudget::new(limits, Some(block.clone()));
        assert_eq!(
            third.reserve(2),
            Err(TransactionError::ExperimentalSlhDsaB128sBlockBudget { limit: 5 })
        );
        assert_eq!(third.remaining, 3);
        assert_eq!(block.remaining(), 1);
        third.reserve(1).unwrap();
        assert_eq!(block.remaining(), 0);
        drop(first);
        drop(second);
        drop(third);
        assert_eq!(block.remaining(), 0);
        assert_eq!(SlhDsaB128sBlockBudget::new(limits).remaining(), 5);
    }

    #[test]
    fn slh_dsa_b128s_concurrent_reservations_never_overspend() {
        let limits = ExperimentalSlhDsaB128sLimits::new(3, 17).unwrap();
        let block = SlhDsaB128sBlockBudget::new(limits);
        let successes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    let budget = block.clone();
                    scope.spawn(move || {
                        SlhDsaB128sTransactionBudget::new(limits, Some(budget))
                            .reserve(3)
                            .is_ok()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| usize::from(handle.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(successes, 5);
        assert_eq!(block.remaining(), 2);
    }
}
