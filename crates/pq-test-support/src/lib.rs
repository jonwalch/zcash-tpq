//! Unsigned transaction recipes for tests, examples and benchmarks only.
//!
//! Callers supply every transaction field and script. These helpers do not
//! generate keys, sign, calculate fees, resolve UTXOs or validate transactions.
//! Pairing an input with an output preserves fixture order; it does not prove
//! that the output belongs to the outpoint or is available in any chain state.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;

use zakura_chain::{
    block::Height,
    parameters::NetworkUpgrade,
    transaction::{LockTime, Transaction},
    transparent::{Input, OutPoint, Output, Script},
};

/// One unsigned input and its caller-supplied previous output.
#[derive(Clone, Debug)]
pub struct Spend {
    /// The outpoint the fixture claims to spend; not resolved by this crate.
    pub outpoint: OutPoint,
    /// Exact sequence number, including nonfinal sequences used by controls.
    pub sequence: u32,
    /// Value and locking script supplied by the adapter, without interpretation.
    pub previous_output: Output,
}

/// Explicit transparent-only v5/v6 fields, without implicit network or fee rules.
///
/// Adapters may attach shielded bundles or authorizations after construction.
/// Empty vectors, duplicate outpoints and invalid scripts are preserved so the
/// caller can exercise negative cases. This is not a consensus validator.
pub struct TransactionRecipe {
    /// Transaction format: 5 or 6. This does not select a consensus branch.
    pub version: u8,
    /// Embedded upgrade, supplied separately from the transaction format.
    pub network_upgrade: NetworkUpgrade,
    /// Exact transaction lock time.
    pub lock_time: LockTime,
    /// Exact transaction expiry height.
    pub expiry_height: Height,
    /// Inputs and previous outputs in their intended order; never sorted.
    pub spends: Vec<Spend>,
    /// Transaction outputs in their intended order, including change if any.
    pub outputs: Vec<Output>,
}

impl TransactionRecipe {
    /// Build empty input authorizations and move previous outputs into an `Arc`.
    ///
    /// # Panics
    ///
    /// Panics for formats other than v5/v6, which this fixture helper does not
    /// define. It does not check whether the selected upgrade supports the format.
    pub fn build(self) -> (Transaction, Arc<Vec<Output>>) {
        let Self {
            version,
            network_upgrade,
            lock_time,
            expiry_height,
            spends,
            outputs,
        } = self;
        let (inputs, previous) = spends
            .into_iter()
            .map(|spend| {
                (
                    Input::PrevOut {
                        outpoint: spend.outpoint,
                        unlock_script: Script::new(&[]),
                        sequence: spend.sequence,
                    },
                    spend.previous_output,
                )
            })
            .unzip();
        let transaction = match version {
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
            _ => panic!("fixture only defines v5 and v6"),
        };
        (transaction, Arc::new(previous))
    }
}

/// Set the embedded upgrade without asserting format/upgrade compatibility.
///
/// # Panics
/// Panics for transactions other than v5/v6.
pub fn set_upgrade(tx: &mut Transaction, upgrade: NetworkUpgrade) {
    match tx {
        Transaction::V5 {
            network_upgrade, ..
        }
        | Transaction::V6 {
            network_upgrade, ..
        } => {
            *network_upgrade = upgrade;
        }
        _ => panic!("fixture only defines v5 and v6"),
    }
}

/// Borrow transparent inputs for fixture mutation, without touching context.
///
/// # Panics
/// Panics for transactions other than v5/v6.
pub fn inputs_mut(tx: &mut Transaction) -> &mut Vec<Input> {
    match tx {
        Transaction::V5 { inputs, .. } | Transaction::V6 { inputs, .. } => inputs,
        _ => panic!("fixture only defines v5 and v6"),
    }
}

/// Borrow transparent outputs for fixture mutation.
///
/// # Panics
/// Panics for transactions other than v5/v6.
pub fn outputs_mut(tx: &mut Transaction) -> &mut Vec<Output> {
    match tx {
        Transaction::V5 { outputs, .. } | Transaction::V6 { outputs, .. } => outputs,
        _ => panic!("fixture only defines v5 and v6"),
    }
}

/// Install caller-supplied bytes, including deliberately invalid authorizations.
///
/// # Panics
/// Panics unless `index` identifies a previous-output input in a v5/v6 fixture.
pub fn install(tx: &mut Transaction, index: usize, script: Script) {
    let Input::PrevOut { unlock_script, .. } = &mut inputs_mut(tx)[index] else {
        panic!("fixture input is a prevout")
    };
    *unlock_script = script;
}
