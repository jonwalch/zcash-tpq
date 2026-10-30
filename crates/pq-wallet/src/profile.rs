//! Canonical public chain context, independent of wallet keys and signing.

use crate::{canonical, Error};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

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

/// Explicitly approved isolated-chain configuration; never learned from a backup.
/// The activation height and check limits belong to the separately approved
/// experimental SLH gate; node metadata never approves this profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Independently approved TPQ node identity, required only on custom Testnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_fingerprint: Option<Hex<32>>,
    /// Independently approved genesis hash in RPC display order.
    pub genesis_hash: Hex<32>,
    /// Approved per-block signature-check allowance.
    pub max_block_pq_checks: u32,
    /// Approved per-transaction signature-check allowance.
    pub max_tx_pq_checks: u32,
    /// Regtest (2), or custom Testnet (1) with an approved fingerprint.
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
        if !matches!(
            (self.network, self.chain_fingerprint),
            (2, None) | (1, Some(_))
        ) || self.nu7_branch_id != "77190ad9"
            || self.pq_activation_height <= self.nu7_activation_height
            || self.max_tx_pq_checks == 0
            || self.max_block_pq_checks < self.max_tx_pq_checks
        {
            return Err(Error::UnsupportedContext);
        }
        Ok(())
    }
    /// Version of the wallet derivation and chain-bound transports.
    pub fn wallet_version(&self) -> u8 {
        if self.network == 1 {
            2
        } else {
            1
        }
    }
    /// Decode bounded canonical JSON and validate its invariants.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let profile: Self = canonical::decode(bytes, 4096)?;
        profile.validate()?;
        Ok(profile)
    }
}
