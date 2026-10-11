use super::{MAX_INPUTS, MAX_PARTIAL, MAX_PROPOSAL, MAX_TRANSACTION};
use crate::{
    canonical,
    manifest::{bounded, decode_hex},
    suite::{SignerPartial, Suite},
    Checkpoint, Entry, Error, Hex, Outpoint, Profile, Receiver,
};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Cursor};
use zakura_chain::{
    parameters::NetworkUpgrade,
    serialization::{BytesInDisplayOrder, ZcashDeserialize, ZcashSerialize},
    transaction::{LockTime, Transaction},
    transparent::{Input, Output},
};

/// Public proposal input hints, checked against authenticated UTXOs before signing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputRecord {
    /// Enrolled policy and public origin mapping; a proposal does not authenticate ownership.
    pub entry: Entry,
    /// Canonical previous-output bytes, checked against the authenticated node before approval.
    pub spent_output_hex: String,
}

/// Canonical recipient or enrolled change output metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputRecord {
    /// Enrolled policy and public origin mapping; a proposal does not authenticate ownership.
    pub entry: Option<Entry>,
    /// Exact output role: payment or change.
    pub kind: String,
    /// Canonical experimental Regtest receiver.
    pub receiver: String,
}

/// Bounded transparent payment proposal; no field grants trust or signing approval.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    /// Exact versioned transport identity.
    pub format: String,
    /// Ordered input records, bounded to fifteen.
    #[serde(deserialize_with = "inputs")]
    pub inputs: Vec<InputRecord>,
    /// One recipient and optional change record.
    #[serde(deserialize_with = "outputs")]
    pub outputs: Vec<OutputRecord>,
    /// Independently approved Regtest activation and check limits.
    pub profile: Profile,
    /// Trusted checkpoint to which this observation or approval is bound.
    pub tip: Checkpoint,
    /// Canonical unsigned transparent transaction bytes as lowercase hex.
    pub transaction_hex: String,
}
fn inputs<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<InputRecord>, D::Error> {
    bounded::<D, InputRecord, MAX_INPUTS>(d)
}
fn outputs<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<OutputRecord>, D::Error> {
    bounded::<D, OutputRecord, 2>(d)
}

impl Proposal {
    /// Decode strictly bounded canonical JSON without normalization.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let proposal: Self = canonical::decode(bytes, MAX_PROPOSAL)?;
        proposal.transaction()?;
        Ok(proposal)
    }
    /// Validate and encode exact canonical JSON within the transport cap.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.transaction()?;
        Ok(canonical::encode(self, MAX_PROPOSAL)?.to_vec())
    }
    /// Hash the complete validated canonical proposal with its fixed domain.
    pub fn id(&self) -> Result<Hex<32>, Error> {
        super::approval::proposal_id(
            || self.to_json(),
            |domain, canonical| {
                let mut hash = Sha256::new();
                hash.update(domain);
                hash.update(canonical);
                hash.finalize().into()
            },
        )
        .map(Hex)
    }
    /// Structural validation only; this establishes no input provenance.
    pub fn transaction(&self) -> Result<Transaction, Error> {
        if self.format != "ZcashTransparentPQ/proposal/v1" {
            return Err(Error::UnsupportedFormat);
        }
        self.profile.validate()?;
        if self.inputs.is_empty()
            || self.inputs.len() > MAX_INPUTS
            || self.outputs.is_empty()
            || self.outputs.len() > 2
        {
            return Err(Error::Limits);
        }
        let tx = decode_transaction(&decode_variable(&self.transaction_hex, MAX_TRANSACTION)?)?;
        let (inputs, outputs, lock_time, expiry) = match &tx {
            Transaction::V5 {
                network_upgrade: NetworkUpgrade::Nu7,
                inputs,
                outputs,
                lock_time,
                expiry_height,
                sapling_shielded_data: None,
                orchard_shielded_data: None,
            }
            | Transaction::V6 {
                network_upgrade: NetworkUpgrade::Nu7,
                inputs,
                outputs,
                lock_time,
                expiry_height,
                sapling_shielded_data: None,
                orchard_shielded_data: None,
                ironwood_shielded_data: None,
            } => (inputs, outputs, lock_time, expiry_height),
            _ => return Err(Error::UnsupportedContext),
        };
        // This minimum wallet has final sequences and no absolute lock time.
        if *lock_time != LockTime::unlocked() || expiry.0 == 0 {
            return Err(Error::UnsupportedContext);
        }
        if inputs.len() != self.inputs.len() || outputs.len() != self.outputs.len() {
            return Err(Error::ProposalMismatch);
        }
        let mut seen = BTreeSet::new();
        for (input, record) in inputs.iter().zip(&self.inputs) {
            let Input::PrevOut {
                outpoint,
                unlock_script,
                sequence,
            } = input
            else {
                return Err(Error::InputContext);
            };
            if !unlock_script.as_raw_bytes().is_empty()
                || *sequence != u32::MAX
                || !seen.insert(point(*outpoint))
            {
                return Err(Error::InputContext);
            }
            let previous = decode_output(&record.spent_output_hex)?;
            if record.entry.suite_policy()?.lock_script() != previous.lock_script {
                return Err(Error::Policy);
            }
        }
        for (output, record) in outputs.iter().zip(&self.outputs) {
            let receiver = Receiver::parse(&record.receiver)?;
            if output.lock_script.as_raw_bytes() != receiver.script() {
                return Err(Error::ProposalMismatch);
            }
            match (record.kind.as_str(), &record.entry) {
                ("payment", None) => (),
                ("change", Some(entry)) if entry.role == 1 && entry.receiver()? == receiver => (),
                // Explicit policy replacement needs its own approval/recovery flow.
                ("policy_transfer", Some(_)) => return Err(Error::UnsupportedContext),
                _ => return Err(Error::ProposalMismatch),
            }
        }
        if self.outputs[0].kind != "payment"
            || self.outputs.get(1).is_some_and(|r| r.kind != "change")
        {
            return Err(Error::ProposalMismatch);
        }
        Ok(tx)
    }
    pub(crate) fn points(&self) -> Result<Vec<Outpoint>, Error> {
        Ok(self
            .transaction()?
            .inputs()
            .iter()
            .map(|i| match i {
                Input::PrevOut { outpoint, .. } => point(*outpoint),
                _ => unreachable!("proposal validates ordinary inputs"),
            })
            .collect())
    }
    pub(crate) fn expiry(&self) -> Result<u32, Error> {
        self.transaction()?
            .expiry_height()
            .map(|h| h.0)
            .ok_or(Error::UnsupportedContext)
    }
}

/// One cosigner's signature for one input. The format names the suite, which
/// fixes the key and signature lengths.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Partial {
    /// Exact versioned transport identity.
    pub format: String,
    /// Zero-based input position, bounded to fourteen.
    pub input_index: u32,
    /// Digest of the complete canonical proposal.
    pub proposal_id: Hex<32>,
    /// Exactly 32 public-key bytes in lowercase hex.
    pub public_key_hex: String,
    /// Exactly 7,856 signature bytes in lowercase hex.
    pub signature_hex: String,
    /// Zero-based position in the sorted enrolled policy, bounded to fourteen.
    pub signer_index: u8,
}
impl Partial {
    /// Decode strictly bounded canonical JSON without normalization.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let partial: Self = canonical::decode(bytes, MAX_PARTIAL)?;
        partial.authorization()?;
        Ok(partial)
    }
    /// Validate and encode exact canonical JSON within the transport cap.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.authorization()?;
        Ok(canonical::encode(self, MAX_PARTIAL)?.to_vec())
    }
    pub(crate) fn new(id: Hex<32>, input_index: u32, signer: SignerPartial) -> Self {
        Self {
            format: signer.suite().partial_format().into(),
            input_index,
            proposal_id: id,
            public_key_hex: hex::encode(signer.public_key()),
            signature_hex: hex::encode(signer.signature()),
            signer_index: signer.index(),
        }
    }
    pub(crate) fn authorization(&self) -> Result<SignerPartial, Error> {
        let suite = Suite::from_partial_format(&self.format)?;
        if self.input_index >= MAX_INPUTS as u32 || self.signer_index >= 15 {
            return Err(Error::ProposalMismatch);
        }
        let (key_size, signature_size) = suite.key_and_signature_sizes();
        let mut public_key = vec![0; key_size];
        let mut signature = vec![0; signature_size];
        decode_hex(&self.public_key_hex, &mut public_key)?;
        decode_hex(&self.signature_hex, &mut signature)?;
        SignerPartial::from_parts(suite, self.signer_index, &public_key, &signature)
    }
}

pub(crate) fn point(p: zakura_chain::transparent::OutPoint) -> Outpoint {
    Outpoint {
        txid: Hex(p.hash.bytes_in_display_order()),
        index: p.index,
    }
}
pub(crate) fn decode_variable(text: &str, limit: usize) -> Result<Vec<u8>, Error> {
    if text.len() > limit * 2 || !text.len().is_multiple_of(2) {
        return Err(Error::Limits);
    }
    let mut bytes = vec![0; text.len() / 2];
    decode_hex(text, &mut bytes)?;
    Ok(bytes)
}
pub(crate) fn decode_transaction(bytes: &[u8]) -> Result<Transaction, Error> {
    if bytes.len() > MAX_TRANSACTION {
        return Err(Error::Limits);
    }
    let mut reader = Cursor::new(bytes);
    let tx = Transaction::zcash_deserialize(&mut reader).map_err(|_| Error::Encoding)?;
    if reader.position() != bytes.len() as u64
        || tx.zcash_serialize_to_vec().map_err(|_| Error::Encoding)? != bytes
    {
        return Err(Error::Encoding);
    }
    Ok(tx)
}
pub(crate) fn decode_output(text: &str) -> Result<Output, Error> {
    let mut bytes = [0; 44];
    decode_hex(text, &mut bytes)?;
    let output = Output::zcash_deserialize(bytes.as_slice()).map_err(|_| Error::Encoding)?;
    if output
        .zcash_serialize_to_vec()
        .map_err(|_| Error::Encoding)?
        != bytes
    {
        return Err(Error::Encoding);
    }
    Ok(output)
}
