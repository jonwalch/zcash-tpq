//! Experimental SLH-DSA-B-128s wallet signing, separate from node verification.
//!
//! This fixed BLAKE3 construction is not a FIPS 205 profile. The source mapping
//! and clearing limitations are in this crate's `README.md` and `PROVENANCE.json`.
//! Operational signing uses fresh OS entropy and always verifies before release.

#![forbid(unsafe_code)]

mod address;
mod hash;
mod recovery;
mod signing;
mod util;

use rand_core::{CryptoRngCore, OsRng};
use zeroize::Zeroizing;

pub use zakura_pq_slh_dsa_b_verify::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES};

/// Seed bytes in the order `SK.seed || SK.prf || PK.seed`.
pub const SEED_BYTES: usize = 48;
/// Exact external transaction-message length; the signer adds Pure framing.
pub const MESSAGE_BYTES: usize = 101;

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

/// Operational failure; no signature is returned in either case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignError {
    /// A fresh sixteen-byte OS entropy request failed.
    Entropy,
    /// Mandatory verification rejected the unpublished signature.
    Verification,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Entropy => "SLH signing entropy unavailable",
            Self::Verification => "SLH local signature verification failed",
        })
    }
}

impl std::error::Error for SignError {}

/// Owned seed material and its public key. There is no secret encoding API.
///
/// The owned seed clears on drop. Compiler copies, registers and backend
/// temporaries are not comprehensively erased; see the crate's clearing review.
///
/// ```compile_fail
/// use zakura_pq_slh_dsa_b_sign::SigningKey;
/// fn duplicate(key: &SigningKey) -> SigningKey { key.clone() }
/// ```
/// ```compile_fail
/// use zakura_pq_slh_dsa_b_sign::SigningKey;
/// fn log_secret(key: &SigningKey) { let _ = format!("{key:?}"); }
/// ```
pub struct SigningKey {
    seed: Zeroizing<[u8; SEED_BYTES]>,
    public_key: [u8; PUBLIC_KEY_BYTES],
}

impl SigningKey {
    /// Derive a key from owned wallet-derived seed material without cloning it.
    /// This serial operation computes the complete public root; it uses no cache.
    pub fn from_seed(seed: Zeroizing<[u8; SEED_BYTES]>) -> Self {
        let (sk_seed, _, pk_seed) = seeds(&seed);
        let address = address::WotsHash {
            layer: u32::try_from(D - 1).expect("hypertree has 7 layers"),
            ..address::WotsHash::default()
        };
        let root = signing::xmss_node(
            sk_seed,
            0,
            u32::try_from(H_PRIME).expect("XMSS height is 9"),
            pk_seed,
            &address,
        );
        let mut public_key = [0; PUBLIC_KEY_BYTES];
        public_key[..N].copy_from_slice(pk_seed);
        public_key[N..].copy_from_slice(&root);
        Self { seed, public_key }
    }

    /// Public seed and complete public root, encoded in the frozen order.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.public_key
    }

    /// Sign the externally framed transaction message with empty context.
    ///
    /// The caller must authenticate and approve the transaction before invoking
    /// this primitive. No supplied digest is reconstructed or trusted here.
    /// A fresh fallible sixteen-byte entropy request is made on every call.
    /// Pure framing is added once and the real verifier must succeed before any
    /// signature bytes are released. There is no deterministic fallback.
    pub fn sign(
        &self,
        message: &[u8; MESSAGE_BYTES],
    ) -> Result<Box<[u8; SIGNATURE_BYTES]>, SignError> {
        self.sign_with_rng(message, &mut OsRng)
    }

    fn sign_with_rng(
        &self,
        message: &[u8; MESSAGE_BYTES],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Box<[u8; SIGNATURE_BYTES]>, SignError> {
        let mut random = Zeroizing::new([0; N]);
        rng.try_fill_bytes(random.as_mut())
            .map_err(|_| SignError::Entropy)?;
        let signature = self.sign_unpublished(message, &random);
        zakura_pq_slh_dsa_b_verify::verify(&self.public_key, &signature, message, &[])
            .map_err(|_| SignError::Verification)?;
        Ok(release_verified(signature))
    }

    fn sign_unpublished(&self, message: &[u8; MESSAGE_BYTES], random: &Node) -> Zeroizing<Vec<u8>> {
        let (sk_seed, sk_prf, pk_seed) = seeds(&self.seed);
        let root = self.public_key[N..]
            .try_into()
            .expect("public root has exactly 16 bytes");
        let randomizer = hash::prf_msg(sk_prf, random, message);
        let digest = hash::h_msg(&randomizer, pk_seed, root, message);
        let (md, tree, leaf) = util::split_digest(&digest);
        let mut signature = Zeroizing::new(vec![0; SIGNATURE_BYTES]);
        signature[..N].copy_from_slice(&randomizer);
        let (fors, ht) = signature[N..].split_at_mut(FORS_BYTES);
        signing::fors_sign(md, sk_seed, pk_seed, tree, leaf, fors);
        let fors_pk = recovery::fors_pk_from_sig(fors, md, pk_seed, tree, leaf);
        signing::ht_sign(&fors_pk, sk_seed, pk_seed, tree, leaf, ht);
        signature
    }
}

fn release_verified(mut signature: Zeroizing<Vec<u8>>) -> Box<[u8; SIGNATURE_BYTES]> {
    // Called only after verification. Move the allocation and leave the clearing
    // owner empty. Verification failures instead clear the complete buffer.
    std::mem::take(&mut *signature)
        .into_boxed_slice()
        .try_into()
        .expect("the fixed signature allocation has exactly 7856 bytes")
}

fn seeds(seed: &[u8; SEED_BYTES]) -> (&Node, &Node, &Node) {
    let [sk_seed, sk_prf, pk_seed] = seed.as_chunks::<N>().0 else {
        unreachable!("48-byte seeds contain exactly three 16-byte components")
    };
    (sk_seed, sk_prf, pk_seed)
}

#[cfg(test)]
mod tests;
