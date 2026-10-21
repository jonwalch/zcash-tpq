//! Account-zero HKDF layout retained from the existing wallet, with 48 output
//! bytes for the three SLH seed components. No inventory or approval is implied.

use hkdf::Hkdf;
use rand_core::{CryptoRngCore, OsRng};
use sha2::Sha256;
use zeroize::Zeroizing;

use zakura_pq_slh_dsa_b_sign::{SigningKey, SEED_BYTES};

/// The account-zero derivation branches specified by wallet version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    /// Receiving coordinates, encoded as zero.
    Receive = 0,
    /// Change coordinates, encoded as one.
    Change = 1,
}

/// A fixed Regtest, suite-f7, account-zero coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyPath {
    /// Receive or change branch.
    pub role: Role,
    /// Full unsigned 32-bit coordinate; callers must never wrap allocation.
    pub index: u32,
}

/// OS entropy failure during root creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootEntropyError;

impl std::fmt::Display for RootEntropyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wallet root entropy unavailable")
    }
}

impl std::error::Error for RootEntropyError {}

/// Owned root for the initial wallet key checkpoint, with no export, clone,
/// debug or serialization API. This is not an enrolled or backed-up wallet.
pub struct Root {
    bytes: Zeroizing<[u8; 32]>,
}

impl Root {
    /// Draw a fresh 32-byte root through fallible OS entropy.
    pub fn generate() -> Result<Self, RootEntropyError> {
        Self::generate_with_rng(&mut OsRng)
    }

    fn generate_with_rng(rng: &mut impl CryptoRngCore) -> Result<Self, RootEntropyError> {
        let mut bytes = Zeroizing::new([0; 32]);
        rng.try_fill_bytes(bytes.as_mut())
            .map_err(|_| RootEntropyError)?;
        Ok(Self { bytes })
    }

    /// Derive an uncached key. This supplies no enrollment or authority to spend;
    /// the later wallet approval layer must authenticate context before signing.
    pub fn derive_key(&self, path: KeyPath) -> SigningKey {
        SigningKey::from_seed(self.seed(path))
    }

    fn seed(&self, path: KeyPath) -> Zeroizing<[u8; SEED_BYTES]> {
        derive_seed(&self.bytes, path)
    }
}

pub(crate) fn derive_seed(root: &[u8; 32], path: KeyPath) -> Zeroizing<[u8; SEED_BYTES]> {
    derive_chain_seed(root, path, None)
}

pub(crate) fn derive_chain_seed(
    root: &[u8; 32],
    path: KeyPath,
    chain: Option<crate::Hex<32>>,
) -> Zeroizing<[u8; SEED_BYTES]> {
    // Preserve the existing HKDF/HMAC limitation: the owned output clears,
    // but these pinned implementations do not expose internal-state clearing.
    let hkdf = Hkdf::<Sha256>::new(Some(b"ZcashTransparentPQ/wallet-root/v1\0"), root.as_ref());
    let mut info = if chain.is_some() {
        b"ZcashTransparentPQ/wallet-key/v2\0"
    } else {
        b"ZcashTransparentPQ/wallet-key/v1\0"
    }
    .to_vec();
    if let Some(chain) = chain {
        info.extend([2, 1, 0xf7]);
        info.extend(chain.0);
    } else {
        info.extend([1, 2, 0xf7]);
    }
    info.extend(0u32.to_le_bytes());
    // Role is repr(u8) with only 0 and 1, so this conversion is lossless.
    info.push(path.role as u8);
    info.extend(path.index.to_le_bytes());
    let mut seed = Zeroizing::new([0; SEED_BYTES]);
    hkdf.expand(&info, seed.as_mut())
        .expect("48 bytes is within HKDF-SHA-256's output limit");
    seed
}

#[cfg(test)]
mod tests;
