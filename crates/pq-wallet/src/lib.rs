//! Experimental Regtest SLH wallet: backed enrollment, discovery and approved payments.

#![forbid(unsafe_code)]

/// Whether this build contains the experimental wallet key implementation.
pub const fn supports_experimental_slh_dsa_b128s() -> bool {
    cfg!(feature = "experimental-slh-dsa-b128s")
}

/// Explicit refusal for builds without the experimental wallet feature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExperimentalFeatureDisabled;

impl std::fmt::Display for ExperimentalFeatureDisabled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("experimental SLH wallet support is disabled")
    }
}

impl std::error::Error for ExperimentalFeatureDisabled {}

/// Check support before dispatching an SLH operation.
pub fn require_experimental_slh_dsa_b128s() -> Result<(), ExperimentalFeatureDisabled> {
    if supports_experimental_slh_dsa_b128s() {
        Ok(())
    } else {
        Err(ExperimentalFeatureDisabled)
    }
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
mod keys;
#[cfg(feature = "experimental-slh-dsa-b128s")]
pub use keys::{KeyPath, Role, Root, RootEntropyError};

#[cfg(test)]
mod tests {
    #[cfg(feature = "experimental-slh-dsa-b128s")]
    pub(crate) static BACKUPS: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[test]
    fn disabled_feature_is_explicit() {
        assert_eq!(
            super::require_experimental_slh_dsa_b128s().is_ok(),
            cfg!(feature = "experimental-slh-dsa-b128s")
        );
    }
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
mod backup;
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod journal;
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod receiving;
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod scan;
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod storage;
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod watch;
#[cfg(feature = "experimental-slh-dsa-b128s")]
pub mod payment;

#[cfg(feature = "experimental-slh-dsa-b128s")]
mod canonical;
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod error;
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod manifest;
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod suite;

#[cfg(feature = "experimental-slh-dsa-b128s")]
pub use receiving::Receiver;
#[cfg(feature = "experimental-slh-dsa-b128s")]
pub use scan::{ChainSource, Checkpoint, Coin, NodeContext, Outpoint, ScanStatus};
#[cfg(feature = "experimental-slh-dsa-b128s")]
pub use watch::archive::{
    PaymentDetails, PaymentHistoryEntry, PaymentHistoryPage, PaymentLocation, PaymentObservation,
};
#[cfg(feature = "experimental-slh-dsa-b128s")]
pub use watch::{export_inventory, read_inventory, read_transfer, write_transfer, WatchMode, WatchStore};
#[cfg(feature = "experimental-slh-dsa-b128s")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "experimental-slh-dsa-b128s")]
pub use error::Error;
#[cfg(feature = "experimental-slh-dsa-b128s")]
pub use manifest::{Entry, Hex, Manifest, Origin, Profile, MAX_ENTRIES};
#[cfg(feature = "experimental-slh-dsa-b128s")]
use rand_core::{CryptoRngCore, OsRng};
#[cfg(feature = "experimental-slh-dsa-b128s")]
pub use suite::Suite;
#[cfg(feature = "experimental-slh-dsa-b128s")]
use suite::{InputSigner, SignerPartial, SuitePolicy};
#[cfg(feature = "experimental-slh-dsa-b128s")]
use zakura_pq_slh_dsa_b_exp::{InputSigningContext, Record};
#[cfg(feature = "experimental-slh-dsa-b128s")]
use zakura_pq_slh_dsa_b_sign::{SigningKey, PUBLIC_KEY_BYTES};
#[cfg(feature = "experimental-slh-dsa-b128s")]
use zeroize::Zeroizing;

/// An unlocked root and validated recovery inventory. There is no secret Debug,
/// Clone, serialization, arbitrary-seed import or deterministic signing API.
#[cfg(feature = "experimental-slh-dsa-b128s")]
pub struct Wallet {
    root: Zeroizing<[u8; 32]>,
    manifest: Manifest,
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery<'a> {
    format: &'a str,
    manifest: Manifest,
    root_hex: &'a str,
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
impl Wallet {
    /// Generate a fresh root and independently generated identifiers. The empty
    /// inventory issues no receiver; enrollment requires a durable backup.
    pub fn create(profile: Profile, birthday_height: u32) -> Result<Self, Error> {
        Self::create_in_suite(profile, Suite::SlhDsaB128sExpV1, birthday_height)
    }

    /// Injectable CSPRNG variant. Production callers must supply secure entropy.
    pub fn create_with_rng(
        profile: Profile,
        birthday_height: u32,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, Error> {
        Self::create_in_suite_with_rng(profile, Suite::SlhDsaB128sExpV1, birthday_height, rng)
    }

    /// Create a wallet for the approved experimental SLH profile.
    pub fn create_in_suite(
        profile: Profile,
        suite: Suite,
        birthday_height: u32,
    ) -> Result<Self, Error> {
        Self::create_in_suite_with_rng(profile, suite, birthday_height, &mut OsRng)
    }

    /// Injectable CSPRNG variant of [`Self::create_in_suite`].
    pub fn create_in_suite_with_rng(
        profile: Profile,
        suite: Suite,
        birthday_height: u32,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, Error> {
        profile.validate()?;
        let mut root = Zeroizing::new([0; 32]);
        let mut wallet_id = [0; 16];
        let mut allocator_id = [0; 16];
        rng.try_fill_bytes(root.as_mut())
            .map_err(|_| Error::Entropy)?;
        rng.try_fill_bytes(&mut wallet_id)
            .map_err(|_| Error::Entropy)?;
        rng.try_fill_bytes(&mut allocator_id)
            .map_err(|_| Error::Entropy)?;
        let mut manifest =
            Manifest::empty(profile, birthday_height, Hex(wallet_id), Hex(allocator_id));
        manifest.suite = suite.byte();
        Ok(Self { root, manifest })
    }

    /// The validated public inventory; it cannot be mutated through this view.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The suite of every key and policy in this wallet.
    pub fn suite(&self) -> Suite {
        Suite::from_byte(self.manifest.suite).expect("a wallet holds a validated manifest")
    }

    /// Derive a public key, without reserving a receiver or asserting backup coverage.
    pub fn public_key(&self, path: KeyPath) -> [u8; PUBLIC_KEY_BYTES] {
        *self.key(path).public_key()
    }

    /// Derive the public key in this wallet's suite, retaining the wallet API.
    pub fn public_key_bytes(&self, path: KeyPath) -> Result<Vec<u8>, Error> {
        Ok(self.public_key(path).to_vec())
    }

    /// Low-level signing after independent approval of effects, trusted UTXOs,
    /// activation, fees and durable reservations. This does not approve a proposal.
    /// The context must have been reconstructed with authenticated ordered outputs;
    /// only an existing enrolled local coordinate may sign its matching policy.
    pub fn sign_partial(
        &self,
        context: &InputSigningContext,
        path: KeyPath,
    ) -> Result<Record, Error> {
        if context.network() != zakura_pq_tx_context::NetworkDomain::Regtest
            || context.upgrade() != zakura_chain::parameters::NetworkUpgrade::Nu7
        {
            return Err(Error::UnsupportedContext);
        }
        let policy = SuitePolicy::SlhDsaB128sExpV1(context.policy().clone());
        let index = self.signer_index(path, &policy)?;
        let key = self.key(path);
        if zakura_pq_slh_dsa_b_exp::codec::key_commitment(key.public_key())
            != policy.key_commitments()[usize::from(index)]
        {
            return Err(Error::Policy);
        }
        let record = Record {
            index,
            public_key: *key.public_key(),
            signature: key.sign(context.message())?,
        };
        context.verify_partial(&record)?;
        Ok(record)
    }

    /// Internal suite dispatch; signing entropy is always supplied by the
    /// operational signer, never by a proposal or deterministic wallet fallback.
    pub(crate) fn sign_input(
        &self,
        signer: &InputSigner,
        path: KeyPath,
    ) -> Result<SignerPartial, Error> {
        match signer {
            InputSigner::SlhDsaB128sExpV1(context) => Ok(SignerPartial::SlhDsaB128sExpV1(
                self.sign_partial(context, path)?,
            )),
        }
    }

    fn signer_index(&self, path: KeyPath, policy: &SuitePolicy) -> Result<u8, Error> {
        let entry = self
            .manifest
            .entries
            .iter()
            .find(|entry| {
                // Role is repr(u8), with only the receive/change values 0 and 1.
                entry.role == path.role as u8
                    && entry
                        .local(self.manifest.wallet_id)
                        .is_ok_and(|(_, origin)| origin.index == path.index)
            })
            .ok_or(Error::Policy)?;
        if entry.suite_policy()? != *policy {
            return Err(Error::Policy);
        }
        self.manifest.profile.check_policy(policy)?;
        u8::try_from(entry.local(self.manifest.wallet_id)?.0).map_err(|_| Error::Policy)
    }

    /// Authenticate and reconstruct a package against an independently approved
    /// profile. This cannot establish backup freshness, chain history or balance.
    pub fn decrypt(bytes: &[u8], password: &[u8], profile: &Profile) -> Result<Self, Error> {
        profile.validate()?;
        let plaintext = backup::decrypt(bytes, password)?;
        Self::from_plaintext(&plaintext, profile)
    }

    /// Produce a fresh salt/nonce for every envelope. The returned bytes are not
    /// proof of durable storage; use save_backup before publishing an inventory.
    pub fn encrypt(&self, password: &[u8]) -> Result<Vec<u8>, Error> {
        self.encrypt_with_rng(password, &mut OsRng)
    }
    /// Encrypt with fresh fallible entropy from the supplied CSPRNG.
    pub fn encrypt_with_rng(
        &self,
        password: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        backup::encrypt(self.plaintext()?, password, rng)
    }

    /// Retire covered issuance ranges and rotate the allocator after external
    /// reconciliation of the latest backup and old allocator. Save the new
    /// generation before fresh enrollment. Existing entries remain spendable.
    pub fn retire_for_restore(&mut self) -> Result<(), Error> {
        self.retire_for_restore_with_rng(&mut OsRng)
    }
    /// Retire covered issuance and rotate allocator using fallible supplied entropy.
    pub fn retire_for_restore_with_rng(
        &mut self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), Error> {
        let revision = self
            .manifest
            .revision
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let mut id = [0; 16];
        rng.try_fill_bytes(&mut id).map_err(|_| Error::Entropy)?;
        if Hex(id) == self.manifest.allocator_id {
            return Err(Error::Entropy);
        }
        let mut candidate = self.manifest.clone();
        candidate.allocator_id = Hex(id);
        candidate.revision = revision;
        candidate.retired_receive_end = candidate.receive_end;
        candidate.retired_change_end = candidate.change_end;
        self.manifest.check_update(&candidate)?;
        self.manifest = candidate;
        Ok(())
    }

    fn plaintext(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let root_hex = Zeroizing::new(hex::encode(&self.root[..]));
        canonical::encode(
            &Recovery {
                format: "ZcashTransparentPQ/recovery/v1",
                manifest: self.manifest.clone(),
                root_hex: &root_hex,
            },
            manifest::MAX_PLAINTEXT,
        )
    }
    fn from_plaintext(bytes: &[u8], profile: &Profile) -> Result<Self, Error> {
        let recovery: Recovery<'_> = canonical::decode(bytes, manifest::MAX_PLAINTEXT)?;
        if recovery.format != "ZcashTransparentPQ/recovery/v1" {
            return Err(Error::UnsupportedFormat);
        }
        recovery.manifest.validate()?;
        if recovery.manifest.profile != *profile {
            return Err(Error::UnsupportedContext);
        }
        let mut root = Zeroizing::new([0; 32]);
        manifest::decode_hex(recovery.root_hex, root.as_mut())?;
        let wallet = Self {
            root,
            manifest: recovery.manifest,
        };
        for entry in &wallet.manifest.entries {
            let (slot, origin) = entry.local(wallet.manifest.wallet_id)?;
            let role = match entry.role {
                0 => Role::Receive,
                1 => Role::Change,
                _ => return Err(Error::UnsupportedContext),
            };
            if entry.suite_policy()?.key_commitments()[slot]
                != wallet.key_commitment(KeyPath {
                    role,
                    index: origin.index,
                })?
            {
                return Err(Error::Policy);
            }
        }
        Ok(wallet)
    }
    fn key(&self, path: KeyPath) -> SigningKey {
        SigningKey::from_seed(keys::derive_seed(&self.root, path))
    }

    /// Derive this coordinate's public commitment without allocating or issuing it.
    fn key_commitment(&self, path: KeyPath) -> Result<[u8; 32], Error> {
        Ok(zakura_pq_slh_dsa_b_exp::codec::key_commitment(
            self.key(path).public_key(),
        ))
    }
}

#[cfg(all(test, feature = "experimental-slh-dsa-b128s"))]
mod wallet_tests;
