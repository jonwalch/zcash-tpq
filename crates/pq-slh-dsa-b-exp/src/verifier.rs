//! Structural input binding and signature verification after reservation.

use std::sync::Arc;

use zakura_chain::{
    parameters::NetworkUpgrade,
    transaction::Transaction,
    transparent::{Input, Output},
};
use zakura_pq_tx_context::{NetworkDomain, PreparedTransaction};

use crate::{
    codec::{key_commitment, template_commitment, Authorization},
    contract::{self, MESSAGE_SIZE},
    profile::{PUBLIC_KEY_SIZE, SIGNATURE_SIZE},
};

pub use crate::Rejection;

/// Verify one 101-byte native message with the frozen empty context.
///
/// This is the real primitive, with its length bounds, and never a replacement
/// hook. Input authorization also requires structural binding and reservation.
pub fn verify_signature(public_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    verify_signature_observed(public_key, signature, message, || {})
}

fn verify_signature_observed(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    observe: impl FnOnce(),
) -> bool {
    if message.len() != MESSAGE_SIZE {
        return false;
    }
    #[cfg(feature = "test-observer")]
    crate::test_observer::emit(crate::test_observer::Event::CryptoStarted);
    observe();
    let valid = zakura_pq_slh_dsa_b_verify::verify(public_key, signature, message, &[]).is_ok();
    #[cfg(feature = "test-observer")]
    crate::test_observer::emit(crate::test_observer::Event::CryptoFinished { valid });
    valid
}

/// Bind an input's canonical authorization to the actual resolved spent output.
///
/// Checks the exact template, encoding, policy and every key commitment before
/// any primitive work. The caller must supply authenticated outputs in input
/// order; this function does not resolve outpoints or establish their provenance.
pub fn input_authorization(
    transaction: &Transaction,
    previous_outputs: &[Output],
    input_index: usize,
) -> Result<Authorization, Rejection> {
    let Some(Input::PrevOut { unlock_script, .. }) = transaction.inputs().get(input_index) else {
        return Err(Rejection::InputContext);
    };
    let spent = previous_outputs
        .get(input_index)
        .ok_or(Rejection::InputContext)?;
    let commitment =
        template_commitment(spent.lock_script.as_raw_bytes()).ok_or(Rejection::OutputTemplate)?;
    let authorization = Authorization::decode(unlock_script.as_raw_bytes())?;
    if authorization.policy.commitment() != commitment {
        return Err(Rejection::OutputCommitment);
    }
    let commitments = authorization.policy.commitments();
    if authorization
        .records
        .iter()
        .any(|record| key_commitment(&record.public_key) != commitments[usize::from(record.index)])
    {
        return Err(Rejection::KeyCommitment);
    }
    Ok(authorization)
}

/// One immutable prepared transaction and its ordered shared spent outputs.
pub struct TransactionContext<'tx> {
    prepared: PreparedTransaction<'tx>,
}

impl<'tx> TransactionContext<'tx> {
    /// Validate the version, upgrade and context shape and precompute once.
    pub fn new(
        transaction: &'tx Transaction,
        network: NetworkDomain,
        upgrade: NetworkUpgrade,
        previous_outputs: Arc<Vec<Output>>,
    ) -> Result<Self, Rejection> {
        Ok(Self {
            prepared: PreparedTransaction::new(transaction, network, upgrade, previous_outputs)?,
        })
    }

    /// The fixed 101-byte message for one in-range input.
    pub fn message(&self, input_index: usize) -> Result<[u8; MESSAGE_SIZE], Rejection> {
        Ok(contract::message(&self.prepared, input_index)?)
    }

    /// Bind an input and atomically reserve all its checks before cryptography.
    ///
    /// Calls `reserve` exactly once after structural binding and message
    /// derivation. An error must consume no caller budget; a successful
    /// reservation is never refunded on later signature failure. Signature
    /// allocations move into checks; reservation makes no second large copy.
    pub fn reserve_input(
        &self,
        input_index: usize,
        reserve: impl FnOnce(usize) -> Result<(), Rejection>,
    ) -> Result<ReservedInput, Rejection> {
        let authorization = input_authorization(
            self.prepared.transaction(),
            self.prepared.previous_outputs(),
            input_index,
        )?;
        let message = self.message(input_index)?;
        reserve(authorization.records.len())?;
        #[cfg(feature = "test-observer")]
        crate::test_observer::emit(crate::test_observer::Event::Reserved {
            checks: authorization.records.len(),
        });
        Ok(ReservedInput {
            input_index,
            checks: authorization
                .records
                .into_iter()
                .map(|record| SignatureCheck {
                    public_key: record.public_key,
                    signature: record.signature,
                    message,
                    #[cfg(feature = "test-observer")]
                    observer: crate::test_observer::current(),
                })
                .collect(),
        })
    }

    /// Verify one input in signer order without a caller budget.
    pub fn verify_input(&self, input_index: usize) -> Result<(), Rejection> {
        self.reserve_input(input_index, |_| Ok(()))?.verify()
    }
}

/// Structurally bound and reserved checks for one input, in signer order.
/// Reservation alone is not proof that signatures verify.
pub struct ReservedInput {
    input_index: usize,
    checks: Vec<SignatureCheck>,
}

impl ReservedInput {
    /// The transaction input associated with this reservation.
    pub fn input_index(&self) -> usize {
        self.input_index
    }

    /// The ordered checks, which may be verified on a caller's worker pool.
    pub fn checks(&self) -> &[SignatureCheck] {
        &self.checks
    }

    /// Verify checks in signer order, stopping at the first failure.
    pub fn verify(&self) -> Result<(), Rejection> {
        self.checks.iter().try_for_each(SignatureCheck::verify)
    }
}

/// One privately held key/signature/message after structural reservation.
pub struct SignatureCheck {
    public_key: [u8; PUBLIC_KEY_SIZE],
    signature: Box<[u8; SIGNATURE_SIZE]>,
    message: [u8; MESSAGE_SIZE],
    #[cfg(feature = "test-observer")]
    observer: Option<crate::test_observer::Callback>,
}

impl SignatureCheck {
    /// Run the real fixed-profile verifier with external Pure framing once.
    pub fn verify(&self) -> Result<(), Rejection> {
        self.verify_with_observation(|| {})
    }

    /// Observe entry to the real primitive after structural binding/reservation.
    ///
    /// The callback receives no key, signature or message and cannot replace the
    /// verifier or its result. It reports an attempt, never successful validation.
    /// Callers should keep diagnostic callbacks infallible and inexpensive.
    pub fn verify_with_observation(&self, observe: impl FnOnce()) -> Result<(), Rejection> {
        let verify = || {
            verify_signature_observed(
                &self.public_key,
                self.signature.as_ref(),
                &self.message,
                observe,
            )
            .then_some(())
            .ok_or(Rejection::Signature)
        };
        #[cfg(feature = "test-observer")]
        if let Some(observer) = &self.observer {
            return crate::test_observer::observe(observer.clone(), verify);
        }
        verify()
    }
}
