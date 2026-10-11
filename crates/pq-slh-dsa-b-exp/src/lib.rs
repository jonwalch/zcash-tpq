//! Experimental SLH-DSA-B-128s transparent authorization.
//!
//! Implements the canonical policy and authorization codec, trusted-context
//! message derivation, reservation-before-verification facade, and public
//! partial assembly for `slh-dsa-b-128s-exp-v1`. The caller authenticates ordered
//! spent outputs. This crate has no signer, randomness or runtime fixture tool.
//! See the repository's `docs/slh-dsa-b128s/protocol.md` for the byte contract.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod codec;
pub mod contract;
pub mod profile;
mod rejection;
mod signing_context;
#[cfg(feature = "test-observer")]
#[doc(hidden)]
pub mod test_observer;
pub mod verifier;

pub use codec::{template_commitment, Authorization, Policy, Record};
pub use rejection::Rejection;
pub use signing_context::InputSigningContext;
pub use verifier::{
    input_authorization, verify_signature, ReservedInput, SignatureCheck, TransactionContext,
};
