//! SLH-only suite dispatch for policies, partials and trusted input contexts.

use crate::Error;
use std::sync::Arc;
use zakura_chain::{
    parameters::NetworkUpgrade,
    transaction::Transaction,
    transparent::{Output, Script},
};
use zakura_pq_slh_dsa_b_exp as slh;
use zakura_pq_tx_context::NetworkDomain;

/// The single experimental wallet signature suite.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Suite {
    /// SLH-DSA-B-128s, suite byte `f7`, output template `53 20 <C> c0`.
    SlhDsaB128sExpV1,
}

impl Suite {
    /// Decode the exact suite byte; other suites are never converted.
    pub fn from_byte(byte: u8) -> Result<Self, Error> {
        match byte {
            0xf7 => Ok(Self::SlhDsaB128sExpV1),
            _ => Err(Error::UnsupportedFormat),
        }
    }

    /// The descriptor, receiver and key-derivation suite byte.
    pub fn byte(self) -> u8 {
        slh::contract::SUITE
    }

    /// The exact locking-template version opcode.
    pub(crate) fn template_version(self) -> u8 {
        slh::contract::TEMPLATE_VERSION
    }

    /// Canonical format identity for transferred partial signatures.
    pub(crate) fn partial_format(self) -> &'static str {
        "ZcashTransparentPQ/experimental/slh-dsa-b-128s/partial/v1"
    }

    /// Decode the exact partial identity; no legacy suite fallback.
    pub(crate) fn from_partial_format(format: &str) -> Result<Self, Error> {
        (format == Self::SlhDsaB128sExpV1.partial_format())
            .then_some(Self::SlhDsaB128sExpV1)
            .ok_or(Error::UnsupportedFormat)
    }

    /// The fixed public-key and signature byte lengths.
    pub(crate) fn key_and_signature_sizes(self) -> (usize, usize) {
        (slh::profile::PUBLIC_KEY_SIZE, slh::profile::SIGNATURE_SIZE)
    }
}

/// A strictly decoded policy, retaining the existing wallet suite abstraction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SuitePolicy {
    /// The canonical native SLH policy.
    SlhDsaB128sExpV1(slh::Policy),
}

impl SuitePolicy {
    /// Sort commitments and construct any of the 120 supported policy shapes.
    pub fn new(suite: Suite, threshold: u8, commitments: Vec<[u8; 32]>) -> Result<Self, Error> {
        match suite {
            Suite::SlhDsaB128sExpV1 => Ok(Self::SlhDsaB128sExpV1(
                slh::Policy::new(threshold, commitments).map_err(|_| Error::Policy)?,
            )),
        }
    }

    /// Strictly decode the native descriptor without normalization.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        Ok(Self::SlhDsaB128sExpV1(
            slh::Policy::decode(raw).map_err(|_| Error::Policy)?,
        ))
    }

    /// The suite of this policy or signer record.
    pub fn suite(&self) -> Suite {
        Suite::SlhDsaB128sExpV1
    }

    /// Required signature count.
    pub fn threshold(&self) -> u8 {
        self.policy().threshold()
    }

    /// Public key commitments in canonical policy order.
    pub fn key_commitments(&self) -> &[[u8; 32]] {
        self.policy().commitments()
    }

    /// The policy commitment carried by the output and receiver.
    pub fn commitment(&self) -> [u8; 32] {
        self.policy().commitment()
    }

    /// The exact 35-byte locking script.
    pub fn lock_script(&self) -> Script {
        self.policy().lock_script()
    }

    /// The canonical descriptor.
    pub fn encode(&self) -> Vec<u8> {
        self.policy().descriptor()
    }

    /// Exact canonical authorization bytes, including the descriptor push.
    pub fn authorization_size(&self) -> usize {
        slh::codec::authorization_size(usize::from(self.threshold()), self.key_commitments().len())
    }

    fn policy(&self) -> &slh::Policy {
        match self {
            Self::SlhDsaB128sExpV1(policy) => policy,
        }
    }
}

/// One partial, with the fixed 7,856-byte signature in its own heap allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SignerPartial {
    /// One canonical native SLH signer record.
    SlhDsaB128sExpV1(slh::Record),
}

impl SignerPartial {
    /// Decode exact-length transfer fields and a bounded signer index.
    pub fn from_parts(
        suite: Suite,
        index: u8,
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<Self, Error> {
        if usize::from(index) >= slh::codec::MAX_SIGNERS {
            return Err(Error::Encoding);
        }
        match suite {
            Suite::SlhDsaB128sExpV1 => {
                let public_key = public_key.try_into().map_err(|_| Error::Encoding)?;
                if signature.len() != slh::profile::SIGNATURE_SIZE {
                    return Err(Error::Encoding);
                }
                let signature = signature
                    .to_vec()
                    .into_boxed_slice()
                    .try_into()
                    .map_err(|_| Error::Encoding)?;
                Ok(Self::SlhDsaB128sExpV1(slh::Record {
                    index,
                    public_key,
                    signature,
                }))
            }
        }
    }

    /// The suite of this policy or signer record.
    pub fn suite(&self) -> Suite {
        Suite::SlhDsaB128sExpV1
    }

    /// The participant position within the enrolled sorted policy.
    pub fn index(&self) -> u8 {
        self.record().index
    }

    /// The fixed public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.record().public_key
    }

    /// The fixed signature bytes.
    pub fn signature(&self) -> &[u8] {
        self.record().signature.as_ref()
    }

    fn record(&self) -> &slh::Record {
        match self {
            Self::SlhDsaB128sExpV1(record) => record,
        }
    }
}

/// Verifier-only context reconstructed from effects and authenticated outputs.
/// This wrapper exposes no constructor accepting a precomputed digest/message.
pub(crate) enum InputSigner {
    /// The native public, verifier-only context.
    SlhDsaB128sExpV1(slh::InputSigningContext),
}

impl InputSigner {
    /// Reconstruct the message from effects and trusted ordered spent outputs.
    pub fn new(
        transaction: &Transaction,
        previous: Arc<Vec<Output>>,
        input_index: usize,
        policy: &SuitePolicy,
    ) -> Result<Self, Error> {
        Ok(Self::SlhDsaB128sExpV1(slh::InputSigningContext::new(
            transaction,
            NetworkDomain::Regtest,
            NetworkUpgrade::Nu7,
            previous,
            input_index,
            policy.policy(),
        )?))
    }

    /// Check a partial against the bound slot, key and exact message.
    pub fn verify_partial(&self, partial: &SignerPartial) -> Result<(), Error> {
        match self {
            Self::SlhDsaB128sExpV1(context) => Ok(context.verify_partial(partial.record())?),
        }
    }

    /// Verify exactly the threshold count and canonically order valid partials.
    pub fn assemble(&self, partials: Vec<SignerPartial>) -> Result<Script, Error> {
        let records = partials
            .into_iter()
            .map(|partial| match partial {
                SignerPartial::SlhDsaB128sExpV1(record) => record,
            })
            .collect();
        match self {
            Self::SlhDsaB128sExpV1(context) => {
                Ok(Script::new(&context.authorization(records)?.encode()))
            }
        }
    }
}

/// Verify every input. A shortened suite list must never skip authorization.
pub(crate) fn verify_inputs(
    transaction: &Transaction,
    previous: Arc<Vec<Output>>,
    suites: &[Suite],
) -> Result<(), Error> {
    if suites.len() != transaction.inputs().len() {
        return Err(Error::InputContext);
    }
    let context = slh::TransactionContext::new(
        transaction,
        NetworkDomain::Regtest,
        NetworkUpgrade::Nu7,
        previous,
    )?;
    for index in 0..suites.len() {
        context.verify_input(index)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
