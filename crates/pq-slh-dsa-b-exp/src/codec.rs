//! Canonical policy and authorization encoding for `slh-dsa-b-128s-exp-v1`.

use sha2::{Digest, Sha256};
use zakura_chain::transparent::Script;

use crate::contract::{FORMAT_VERSION, KEY_DOMAIN, POLICY_DOMAIN, SUITE, TEMPLATE_VERSION};
use crate::profile::{PUBLIC_KEY_SIZE, SIGNATURE_SIZE};
use crate::verifier::Rejection;

/// Maximum policy participants under the frozen SLH contract.
pub const MAX_SIGNERS: usize = 15;
/// Parser cap on the complete scriptSig, applied before any record is read.
pub const MAX_AUTHORIZATION_SIZE: usize = 131_072;
/// Exact locking-script bytes: `OP_3 <32-byte commitment> c0`.
pub const LOCK_SCRIPT_SIZE: usize = 35;
const OPCODE: u8 = 0xc0;

/// Commit to one public key under the experimental suite and key domain.
pub fn key_commitment(public_key: &[u8; PUBLIC_KEY_SIZE]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(KEY_DOMAIN);
    hash.update([SUITE]);
    hash.update(public_key);
    hash.finalize().into()
}

/// Recognize the exact 35-byte v1 template and return its opaque commitment.
/// Other templates and every noncanonical spelling are not matched.
pub fn template_commitment(script: &[u8]) -> Option<[u8; 32]> {
    if script.len() != LOCK_SCRIPT_SIZE
        || script[..2] != [TEMPLATE_VERSION, 0x20]
        || script[34] != OPCODE
    {
        return None;
    }
    script[2..34].try_into().ok()
}

/// An m-of-n policy over strictly increasing key commitments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    threshold: u8,
    commitments: Vec<[u8; 32]>,
}

fn valid_threshold(threshold: u8, count: usize) -> bool {
    threshold >= 1 && usize::from(threshold) <= count && count <= MAX_SIGNERS
}

impl Policy {
    /// Sort the commitments; duplicates and invalid thresholds are rejected.
    pub fn new(threshold: u8, mut commitments: Vec<[u8; 32]>) -> Result<Self, Rejection> {
        if !valid_threshold(threshold, commitments.len()) {
            return Err(Rejection::Threshold);
        }
        commitments.sort_unstable();
        if commitments.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Rejection::KeyOrder);
        }
        Ok(Self {
            threshold,
            commitments,
        })
    }

    /// Required signer count.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Participant commitments in policy order.
    pub fn commitments(&self) -> &[[u8; 32]] {
        &self.commitments
    }

    /// `01 || f7 || m || n || commitments`.
    pub fn descriptor(&self) -> Vec<u8> {
        let mut bytes = vec![FORMAT_VERSION, SUITE, self.threshold];
        // `new` and `decode` bound the count to 15, fitting in a byte.
        bytes.push(self.commitments.len() as u8);
        for commitment in &self.commitments {
            bytes.extend_from_slice(commitment);
        }
        bytes
    }

    /// `SHA256(POLICY_DOMAIN || descriptor)`.
    pub fn commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(POLICY_DOMAIN);
        hash.update(self.descriptor());
        hash.finalize().into()
    }

    /// The exact 35-byte locking script for this policy.
    pub fn lock_script(&self) -> Script {
        let mut bytes = vec![TEMPLATE_VERSION, 0x20];
        bytes.extend_from_slice(&self.commitment());
        bytes.push(OPCODE);
        Script::new(&bytes)
    }

    /// Strictly decode a descriptor: version, suite, threshold and strictly
    /// increasing commitments, with no trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Rejection> {
        if bytes.len() < 4 {
            return Err(Rejection::Encoding);
        }
        if bytes[0] != FORMAT_VERSION || bytes[1] != SUITE {
            return Err(Rejection::UnsupportedPolicy);
        }
        let (threshold, count) = (bytes[2], usize::from(bytes[3]));
        if !valid_threshold(threshold, count) {
            return Err(Rejection::Threshold);
        }
        if bytes.len() != 4 + 32 * count {
            return Err(Rejection::Encoding);
        }
        // The exact descriptor length above guarantees an empty remainder.
        let commitments = bytes[4..].as_chunks::<32>().0.to_vec();
        // Strictly increasing; a different order is rejected, never normalized.
        if commitments.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Rejection::KeyOrder);
        }
        Ok(Self {
            threshold,
            commitments,
        })
    }
}

/// One explicit signer: policy position, public key and signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    /// Zero-based position in the policy's sorted commitments.
    pub index: u8,
    /// Fixed 32-byte SLH-DSA-B-128s public key.
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    /// One owned fixed-size signature allocation, moved into reserved checks.
    pub signature: Box<[u8; SIGNATURE_SIZE]>,
}

/// A complete input authorization: m signer records, then the descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authorization {
    /// The revealed policy, committed by the spent output.
    pub policy: Policy,
    /// Exactly m records in strictly increasing index order.
    pub records: Vec<Record>,
}

/// Append a minimal data push: direct, `PUSHDATA1` or `PUSHDATA2`.
///
/// # Panics
/// Panics if `data` exceeds the largest PUSHDATA2 field (65,535 bytes).
pub fn push(bytes: &mut Vec<u8>, data: &[u8]) {
    let length = data.len();
    assert!(length <= usize::from(u16::MAX), "field must fit PUSHDATA2");
    // The bound above makes each length fragment representable in a byte.
    match push_prefix(length) {
        1 => bytes.push(length as u8),
        2 => bytes.extend_from_slice(&[0x4c, length as u8]),
        _ => bytes.extend_from_slice(&[0x4d, (length % 256) as u8, (length / 256) as u8]),
    }
    bytes.extend_from_slice(data);
}

/// Read one minimally framed nonempty push of at most `maximum` bytes.
fn read_push(bytes: &[u8], maximum: usize) -> Option<(&[u8], &[u8])> {
    let (&opcode, rest) = bytes.split_first()?;
    let (length, rest) = match opcode {
        1..=75 => (usize::from(opcode), rest),
        0x4c => {
            let (&length, rest) = rest.split_first()?;
            if length < 76 {
                return None;
            }
            (usize::from(length), rest)
        }
        0x4d => {
            if rest.len() < 2 {
                return None;
            }
            let length = usize::from(rest[0]) + 256 * usize::from(rest[1]);
            if length < 256 {
                return None;
            }
            (length, &rest[2..])
        }
        _ => return None,
    };
    if length > maximum || length > rest.len() {
        return None;
    }
    Some(rest.split_at(length))
}

fn read_index(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let (&opcode, rest) = bytes.split_first()?;
    match opcode {
        0 => Some((0, rest)),
        0x51..=0x5e => Some((opcode - 0x50, rest)),
        _ => None,
    }
}

fn encode_index(index: u8) -> u8 {
    assert!(usize::from(index) < MAX_SIGNERS);
    if index == 0 {
        0
    } else {
        0x50 + index
    }
}

impl Authorization {
    /// Exact scriptSig bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for record in &self.records {
            bytes.push(encode_index(record.index));
            push(&mut bytes, &record.public_key);
            push(&mut bytes, record.signature.as_ref());
        }
        push(&mut bytes, &self.policy.descriptor());
        bytes
    }

    /// Strict, bounded decode. Key commitments are checked by structural binding.
    /// Each signature is copied directly into one heap allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, Rejection> {
        if bytes.len() > MAX_AUTHORIZATION_SIZE {
            return Err(Rejection::AuthorizationSize);
        }
        let mut rest = bytes;
        let mut records = Vec::new();
        while let Some((index, remaining)) = read_index(rest) {
            if records.len() == MAX_SIGNERS {
                return Err(Rejection::SignatureCount);
            }
            let (public_key, remaining) =
                read_push(remaining, PUBLIC_KEY_SIZE).ok_or(Rejection::Encoding)?;
            let (signature, remaining) =
                read_push(remaining, SIGNATURE_SIZE).ok_or(Rejection::Encoding)?;
            records.push(Record {
                index,
                public_key: public_key.try_into().map_err(|_| Rejection::Encoding)?,
                signature: signature
                    .to_vec()
                    .into_boxed_slice()
                    .try_into()
                    .map_err(|_| Rejection::Encoding)?,
            });
            rest = remaining;
        }
        let (descriptor, rest) =
            read_push(rest, 4 + 32 * MAX_SIGNERS).ok_or(Rejection::Encoding)?;
        if !rest.is_empty() {
            return Err(Rejection::Encoding);
        }
        let policy = Policy::decode(descriptor)?;
        if records.len() != usize::from(policy.threshold) {
            return Err(Rejection::SignatureCount);
        }
        let count = policy.commitments.len();
        if records.iter().any(|r| usize::from(r.index) >= count)
            || records
                .windows(2)
                .any(|pair| pair[0].index >= pair[1].index)
        {
            return Err(Rejection::SignerIndex);
        }
        Ok(Self { policy, records })
    }
}

/// Bytes in the minimal push prefix for a fixed policy field.
pub fn push_prefix(length: usize) -> usize {
    match length {
        0..=75 => 1,
        76..=255 => 2,
        _ => 3,
    }
}

/// Exact authorization size for a valid m-of-n policy.
pub fn authorization_size(threshold: usize, participants: usize) -> usize {
    let descriptor = 4 + 32 * participants;
    threshold
        * (1 + push_prefix(PUBLIC_KEY_SIZE)
            + PUBLIC_KEY_SIZE
            + push_prefix(SIGNATURE_SIZE)
            + SIGNATURE_SIZE)
        + push_prefix(descriptor)
        + descriptor
}
