use crate::{
    canonical,
    suite::{Suite, SuitePolicy},
    Error,
};
use serde::{
    de::{self, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use zakura_pq_slh_dsa_b_exp::Policy;

/// Independent canonical inventory/recovery byte ceiling.
pub const MAX_PLAINTEXT: usize = 8 * 1024 * 1024;
/// Independent inventory entry count ceiling.
pub const MAX_ENTRIES: usize = 4096;
const FORMAT: &str = "ZcashTransparentPQ/inventory/v1";

/// Fixed-length public bytes encoded as lowercase hex, with no normalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Hex<const N: usize>(pub [u8; N]);
impl<const N: usize> Serialize for Hex<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}
impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <&str>::deserialize(deserializer)?;
        let mut bytes = [0; N];
        decode_hex(text, &mut bytes).map_err(|_| de::Error::custom("invalid hex field"))?;
        Ok(Self(bytes))
    }
}

pub(crate) fn decode_hex(text: &str, output: &mut [u8]) -> Result<(), Error> {
    if text.len() != output.len() * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Encoding);
    }
    hex::decode_to_slice(text, output).map_err(|_| Error::Encoding)
}

/// Explicitly approved Regtest configuration; never learned from a backup.
/// The activation height and check limits belong to the separately approved
/// experimental SLH gate; node metadata never approves this profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Independently approved Regtest genesis hash.
    pub genesis_hash: Hex<32>,
    /// Approved per-block signature-check allowance.
    pub max_block_pq_checks: u32,
    /// Approved per-transaction signature-check allowance.
    pub max_tx_pq_checks: u32,
    /// Network byte, fixed to Regtest (2).
    pub network: u8,
    /// Independently approved NU7 activation height.
    pub nu7_activation_height: u32,
    /// Exact lowercase NU7 branch identifier.
    pub nu7_branch_id: String,
    /// Independently approved SLH activation, strictly after NU7.
    pub pq_activation_height: u32,
}
impl Profile {
    /// Validate all frozen context and structural invariants.
    pub fn validate(&self) -> Result<(), Error> {
        if self.network != 2
            || self.nu7_branch_id != "77190ad9"
            || self.pq_activation_height <= self.nu7_activation_height
            || self.max_tx_pq_checks == 0
            || self.max_block_pq_checks < self.max_tx_pq_checks
        {
            return Err(Error::UnsupportedContext);
        }
        Ok(())
    }
    /// Local issuance/signing guard, deliberately separate from decoding old
    /// inventory. A receiver commitment alone does not expose this policy.
    pub(crate) fn check_policy(&self, policy: &SuitePolicy) -> Result<(), Error> {
        let required = u32::from(policy.threshold());
        if required > self.max_tx_pq_checks || required > self.max_block_pq_checks {
            return Err(Error::PolicyLimit {
                required,
                transaction: self.max_tx_pq_checks,
                block: self.max_block_pq_checks,
            });
        }
        Ok(())
    }
    /// Decode bounded canonical JSON and validate its invariants.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let profile: Self = canonical::decode(bytes, 4096)?;
        profile.validate()?;
        Ok(profile)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One participant's public account-zero derivation origin.
pub struct Origin {
    /// Derivation account, fixed to zero.
    pub account: u32,
    /// Full unsigned receive/change derivation index.
    pub index: u32,
    /// Participant identity, independent of secret derivation.
    pub wallet_id: Hex<16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// A complete policy and its ordered participant origins.
pub struct Entry {
    #[serde(deserialize_with = "origins")]
    /// One participant origin per sorted policy commitment.
    pub origins: Vec<Origin>,
    /// Canonical lowercase-hex SLH descriptor.
    pub policy_hex: String,
    /// Derivation role: zero for receive, one for change.
    pub role: u8,
}
impl Entry {
    /// The strict SLH policy committed by this entry.
    pub fn policy(&self) -> Result<Policy, Error> {
        match self.suite_policy()? {
            SuitePolicy::SlhDsaB128sExpV1(policy) => Ok(policy),
        }
    }
    /// The policy in this repository's sole supported suite.
    pub(crate) fn suite_policy(&self) -> Result<SuitePolicy, Error> {
        if self.role > 1 || !(1..=15).contains(&self.origins.len()) {
            return Err(Error::Policy);
        }
        let mut raw = vec![0; 4 + 32 * self.origins.len()];
        decode_hex(&self.policy_hex, &mut raw)?;
        let policy = SuitePolicy::decode(&raw)?;
        let mut participants = BTreeSet::new();
        for origin in &self.origins {
            if origin.account != 0 || !participants.insert(origin.wallet_id) {
                return Err(Error::Policy);
            }
        }
        Ok(policy)
    }
    pub(crate) fn local(&self, wallet: Hex<16>) -> Result<(usize, &Origin), Error> {
        let mut matching = self
            .origins
            .iter()
            .enumerate()
            .filter(|(_, origin)| origin.wallet_id == wallet);
        let found = matching.next().ok_or(Error::Policy)?;
        if matching.next().is_some() {
            return Err(Error::Policy);
        }
        Ok(found)
    }
}

/// Public cumulative inventory. Possession of this object is not authentication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Current sole allocator identity.
    pub allocator_id: Hex<16>,
    /// Earliest required scanning height.
    pub birthday_height: u32,
    /// Exclusive generated change range end.
    pub change_end: u64,
    /// Frozen derivation layout version (1).
    pub derivation_version: u8,
    #[serde(deserialize_with = "entries")]
    /// Cumulative public inventory in local coordinate order.
    pub entries: Vec<Entry>,
    /// Exact inventory envelope identity.
    pub format: String,
    /// Independently approved experimental chain profile.
    pub profile: Profile,
    /// Exclusive generated receive range end.
    pub receive_end: u64,
    /// Exclusive change range retired from fresh issuance.
    pub retired_change_end: u64,
    /// Exclusive receive range retired from fresh issuance.
    pub retired_receive_end: u64,
    /// Monotonically increasing inventory revision.
    pub revision: u32,
    /// Single SLH suite byte (f7).
    pub suite: u8,
    /// Participant identity, independent of secret derivation.
    pub wallet_id: Hex<16>,
}
impl Manifest {
    /// Decode bounded canonical JSON and validate its invariants.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let manifest: Self = canonical::decode(bytes, MAX_PLAINTEXT)?;
        manifest.validate()?;
        Ok(manifest)
    }
    /// Validate and encode exact canonical JSON within the byte cap.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        Ok(canonical::encode(self, MAX_PLAINTEXT)?.to_vec())
    }
    /// Domain-separated hash of the validated canonical inventory.
    pub fn fingerprint(&self) -> Result<Hex<32>, Error> {
        let mut hash = Sha256::new();
        hash.update(b"ZcashTransparentPQ/wallet-inventory/v1\0");
        hash.update(self.to_json()?);
        Ok(Hex(hash.finalize().into()))
    }
    /// Validate all frozen context and structural invariants.
    pub fn validate(&self) -> Result<(), Error> {
        if self.format != FORMAT || self.derivation_version != 1 {
            return Err(Error::UnsupportedFormat);
        }
        let suite = Suite::from_byte(self.suite)?;
        self.profile.validate()?;
        if self.receive_end > (1u64 << 32)
            || self.change_end > (1u64 << 32)
            || self.retired_receive_end > self.receive_end
            || self.retired_change_end > self.change_end
            || self.receive_end + self.change_end > MAX_ENTRIES as u64
            || self.entries.len() as u64 != self.receive_end + self.change_end
        {
            return Err(Error::Limits);
        }
        let expected = (0..self.receive_end)
            .map(|i| (0, i))
            .chain((0..self.change_end).map(|i| (1, i)));
        let mut commitments = BTreeSet::new();
        for (entry, coordinate) in self.entries.iter().zip(expected) {
            let policy = entry.suite_policy()?;
            let (_, origin) = entry.local(self.wallet_id)?;
            if (entry.role, u64::from(origin.index)) != coordinate
                || policy.suite() != suite
                || !commitments.insert(policy.commitment())
            {
                return Err(Error::Policy);
            }
        }
        canonical::encode(self, MAX_PLAINTEXT)?;
        Ok(())
    }
    /// Validate a cumulative update without changing state or authenticating it.
    pub fn check_update(&self, candidate: &Self) -> Result<(), Error> {
        self.validate()?;
        candidate.validate()?;
        if candidate.revision == self.revision {
            return if candidate == self {
                Ok(())
            } else {
                Err(Error::RecoveryIncomplete)
            };
        }
        if candidate.revision < self.revision
            || self.wallet_id != candidate.wallet_id
            || self.profile != candidate.profile
            || candidate.birthday_height > self.birthday_height
            || candidate.receive_end < self.receive_end
            || candidate.change_end < self.change_end
            || candidate.retired_receive_end < self.retired_receive_end
            || candidate.retired_change_end < self.retired_change_end
        {
            return Err(Error::RecoveryIncomplete);
        }
        if candidate.allocator_id != self.allocator_id
            && (candidate.retired_receive_end < self.receive_end
                || candidate.retired_change_end < self.change_end)
        {
            return Err(Error::RecoveryIncomplete);
        }
        let new: BTreeMap<_, _> = candidate
            .entries
            .iter()
            .map(|entry| Ok(((entry.role, entry.local(self.wallet_id)?.1.index), entry)))
            .collect::<Result<_, Error>>()?;
        for entry in &self.entries {
            if new.get(&(entry.role, entry.local(self.wallet_id)?.1.index)) != Some(&entry) {
                return Err(Error::RecoveryIncomplete);
            }
        }
        Ok(())
    }
    pub(crate) fn empty(
        profile: Profile,
        birthday_height: u32,
        wallet_id: Hex<16>,
        allocator_id: Hex<16>,
    ) -> Self {
        Self {
            allocator_id,
            birthday_height,
            change_end: 0,
            derivation_version: 1,
            entries: vec![],
            format: FORMAT.into(),
            profile,
            receive_end: 0,
            retired_change_end: 0,
            retired_receive_end: 0,
            revision: 0,
            suite: Suite::SlhDsaB128sExpV1.byte(),
            wallet_id,
        }
    }
}

pub(crate) fn bounded<'de, D: Deserializer<'de>, T: Deserialize<'de>, const LIMIT: usize>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    struct Items<T, const N: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Items<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "an array of at most {N} items")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut result = Vec::new();
            while let Some(value) = sequence.next_element()? {
                if result.len() == N {
                    return Err(de::Error::custom("array limit"));
                }
                result.push(value);
            }
            Ok(result)
        }
    }
    d.deserialize_seq(Items::<T, LIMIT>(std::marker::PhantomData))
}
fn entries<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Entry>, D::Error> {
    bounded::<D, Entry, MAX_ENTRIES>(d)
}
fn origins<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Origin>, D::Error> {
    bounded::<D, Origin, 15>(d)
}
