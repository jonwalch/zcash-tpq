//! Experimental, fixed-profile SLH-DSA-B-128s verification.
//!
//! This BLAKE3 construction is not a FIPS 205 profile. The verification algorithms
//! are adapted from the pinned PQC Suite B source listed in `PROVENANCE.json`.
//! Only the external Pure interface is exposed; it adds the context framing once.

#![forbid(unsafe_code)]

mod address;
mod hash;
mod hypertree;
mod util;

use std::fmt;

/// Encoded public key length, in bytes.
pub const PUBLIC_KEY_BYTES: usize = 32;
/// Encoded signature length, in bytes.
pub const SIGNATURE_BYTES: usize = 7856;
/// Maximum unframed message length accepted by this bounded interface.
pub const MAX_MESSAGE_BYTES: usize = 65536;
/// Maximum context length accepted by the external Pure interface.
pub const MAX_CONTEXT_BYTES: usize = 255;

pub(crate) const N: usize = 16;
pub(crate) const K: usize = 14;
pub(crate) const A: usize = 12;
pub(crate) const D: usize = 7;
pub(crate) const H_PRIME: usize = 9;
pub(crate) const WOTS_LEN: usize = 35;
pub(crate) const WOTS_BYTES: usize = WOTS_LEN * N;
pub(crate) const FORS_BYTES: usize = K * (A + 1) * N;
pub(crate) const XMSS_BYTES: usize = WOTS_BYTES + H_PRIME * N;
pub(crate) type Node = [u8; N];

/// A bounded-input error or a cryptographically invalid signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    /// The public key is not exactly 32 bytes.
    PublicKeyLength,
    /// The signature is not exactly 7,856 bytes.
    SignatureLength,
    /// The message exceeds 65,536 bytes.
    MessageTooLong,
    /// The context exceeds 255 bytes.
    ContextTooLong,
    /// The recovered root differs from the public key's root.
    InvalidSignature,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PublicKeyLength => "SLH public key must be exactly 32 bytes",
            Self::SignatureLength => "SLH signature must be exactly 7856 bytes",
            Self::MessageTooLong => "SLH message exceeds 65536 bytes",
            Self::ContextTooLong => "SLH context exceeds 255 bytes",
            Self::InvalidSignature => "invalid SLH signature",
        })
    }
}

impl std::error::Error for VerifyError {}

/// Verify an external Pure signature, adding `[0, context.len()] || context`
/// before `message` exactly once.
///
/// All input lengths are checked before hashing. Signature sections are borrowed;
/// no complete signature is copied or allocated by verification.
///
/// # Errors
/// Returns a length error for an out-of-bounds input, or `InvalidSignature` if the
/// recovered root does not match the public key. Length errors take precedence in
/// public key, signature, message, context order.
pub fn verify(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<(), VerifyError> {
    let public_key: &[u8; PUBLIC_KEY_BYTES] = public_key
        .try_into()
        .map_err(|_| VerifyError::PublicKeyLength)?;
    let signature: &[u8; SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| VerifyError::SignatureLength)?;
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(VerifyError::MessageTooLong);
    }
    let context_len = u8::try_from(context.len()).map_err(|_| VerifyError::ContextTooLong)?;

    let pk_seed = util::node(&public_key[..N]);
    let pk_root = util::node(&public_key[N..]);
    let (randomizer, rest) = signature.split_at(N);
    let (fors_signature, ht_signature) = rest.split_at(FORS_BYTES);
    let digest = hash::h_msg(
        randomizer,
        &pk_seed,
        &pk_root,
        &[&[0, context_len], context, message],
    );
    let (md, idx_tree, idx_leaf) = util::split_digest(&digest);
    let fors_pk = hypertree::fors_pk_from_sig(fors_signature, md, &pk_seed, idx_tree, idx_leaf);
    let root = hypertree::ht_root(&fors_pk, ht_signature, &pk_seed, idx_tree, idx_leaf);
    if root == pk_root {
        Ok(())
    } else {
        Err(VerifyError::InvalidSignature)
    }
}
