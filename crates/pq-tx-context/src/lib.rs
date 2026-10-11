//! Prepared v5/v6 transaction digests, independent of an authorization method.
//!
//! Callers supply the trusted network, upgrade and every resolved previous
//! output in input order. Neither length checks nor shared ownership authenticate
//! that context. This crate does not parse authorizations, classify native PQ
//! outputs, select a signature suite, verify signatures or enforce budgets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;
use zakura_chain::{
    parameters::NetworkUpgrade,
    transaction::{HashType, SigHasher, Transaction},
    transparent::{Input, Output},
};

pub mod accounting;
mod compatibility;
mod error;
pub use error::Error;

/// Network context supplied by the caller; byte framing belongs to each method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkDomain {
    /// Mainnet.
    Mainnet,
    /// Public testnet.
    Testnet,
    /// Local regtest; does not distinguish different regtest chains.
    Regtest,
}

/// A `SIGHASH_ALL` digest and its explicit input/chain context.
///
/// This is not a complete application signing message or proof of UTXO origin.
/// The digest itself does not bind the network domain; methods must frame it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputDigest {
    /// The existing transaction authorization digest, in its original byte order.
    pub digest: [u8; 32],
    /// Caller-selected network, requiring method-specific domain separation.
    pub network: NetworkDomain,
    /// Reviewed upgrade, checked against the embedded transaction branch.
    pub upgrade: NetworkUpgrade,
    /// The transparent input whose digest was derived.
    pub input_index: usize,
}

/// One immutable transaction and its ordered, shared previous outputs.
///
/// The transaction borrow prevents mutation while precomputed hashes are in
/// use. The supplied `Arc` is retained, not cloned into a new output vector.
pub struct PreparedTransaction<'a> {
    transaction: &'a Transaction,
    previous_outputs: Arc<Vec<Output>>,
    network: NetworkDomain,
    upgrade: NetworkUpgrade,
    hasher: SigHasher,
}

impl<'a> PreparedTransaction<'a> {
    /// Check the reviewed version/branch/backend and context shape, then hash once.
    ///
    /// Preserves the original rejection order: compatibility before input shape.
    /// Every transparent input must be a non-coinbase input with one output;
    /// empty input sets are rejected. This does not validate outpoint provenance.
    pub fn new(
        transaction: &'a Transaction,
        network: NetworkDomain,
        upgrade: NetworkUpgrade,
        previous_outputs: Arc<Vec<Output>>,
    ) -> Result<Self, Error> {
        compatibility::validate(transaction, upgrade)?;
        if transaction.inputs().is_empty()
            || previous_outputs.len() != transaction.inputs().len()
            || transaction
                .inputs()
                .iter()
                .any(|input| matches!(input, Input::Coinbase { .. }))
        {
            return Err(Error::InputContext);
        }
        let hasher = transaction
            .sighasher(upgrade, previous_outputs.clone())
            .map_err(Error::Sighash)?;
        Ok(Self {
            transaction,
            previous_outputs,
            network,
            upgrade,
            hasher,
        })
    }

    /// The immutable transaction used for precomputation.
    pub fn transaction(&self) -> &'a Transaction {
        self.transaction
    }

    /// Borrow the original shared UTXO allocation, without copying scripts.
    pub fn previous_outputs(&self) -> &Arc<Vec<Output>> {
        &self.previous_outputs
    }

    /// Derive the existing `SIGHASH_ALL` digest for an in-range transparent input.
    pub fn input_digest(&self, input_index: usize) -> Result<InputDigest, Error> {
        if input_index >= self.transaction.inputs().len() {
            return Err(Error::InputContext);
        }
        let digest = self
            .hasher
            .sighash(HashType::ALL, Some((input_index, Vec::new())));
        Ok(InputDigest {
            digest: digest.0,
            network: self.network,
            upgrade: self.upgrade,
            input_index,
        })
    }
}
