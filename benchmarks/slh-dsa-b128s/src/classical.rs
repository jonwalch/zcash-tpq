//! Matched public P2SH ECDSA controls; no classical wallet or storage claim.
//!
//! The script/signature flow is adapted from this repository's
//! `tests/slh-dsa-b128s/fixtures/host/src/classical.rs` (MIT OR Apache-2.0).
//! These deterministic keys and synthetic outpoints must never receive funds.
use std::sync::Arc;

use ripemd::Ripemd160;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zakura_chain::{
    block::Height,
    parameters::NetworkUpgrade,
    serialization::ZcashSerialize,
    transaction::{zip317, HashType, LockTime, Transaction},
    transparent::{Input, OutPoint, Output, Script},
};
use zakura_pq_test_support::{inputs_mut, install, Spend, TransactionRecipe};

pub struct ClassicalPayment {
    version: u8,
    input_count: usize,
    multisig: bool,
    keys: Vec<SecretKey>,
    public_keys: Vec<PublicKey>,
    redeem: Vec<u8>,
    previous: Arc<Vec<Output>>,
    recipient: Script,
    public_seed: u32,
}

impl ClassicalPayment {
    pub fn new(
        version: u8,
        input_count: usize,
        multisig: bool,
        public_seed: u32,
    ) -> Result<Self, String> {
        if !matches!(version, 5 | 6) || !matches!(input_count, 1 | 2 | 5) {
            return Err("classical control requires v5/v6 and 1, 2 or 5 inputs".into());
        }
        let signing_keys = keys(public_seed, if multisig { 3 } else { 1 });
        let (lock, redeem, public_keys) = scripts(&signing_keys, multisig);
        let (recipient, _, _) = scripts(&keys(0xfeed_0123, 1), false);
        Ok(Self {
            version,
            input_count,
            multisig,
            keys: signing_keys,
            public_keys,
            redeem,
            previous: Arc::new(vec![output(10_000_000, lock)?; input_count]),
            recipient,
            public_seed,
        })
    }

    pub fn assemble(&self) -> Result<Transaction, String> {
        // A compressed low-S P2SH single input uses <=150 bytes; a 2-of-3
        // input uses >150 and <=300. These bounded 1/2/5-input cases therefore
        // have a fixed ZIP-317 action count despite variable DER lengths.
        let actions = (self.input_count * if self.multisig { 2 } else { 1 }).max(2);
        let fee = u64::try_from(actions).map_err(|e| e.to_string())? * zip317::MARGINAL_FEE;
        let total = u64::try_from(self.input_count).map_err(|e| e.to_string())? * 10_000_000;
        let spends = (0..self.input_count)
            .map(|index| {
                let mut bytes = b"Zakura/TPQ-payment-bench/classical/outpoint/v1\0".to_vec();
                bytes.extend(self.public_seed.to_le_bytes());
                bytes.extend(
                    u32::try_from(index)
                        .expect("at most five inputs")
                        .to_le_bytes(),
                );
                Spend {
                    outpoint: OutPoint {
                        hash: <[u8; 32]>::from(Sha256::digest(bytes)).into(),
                        index: u32::try_from(index).expect("at most five inputs"),
                    },
                    sequence: u32::MAX,
                    previous_output: self.previous[index].clone(),
                }
            })
            .collect();
        Ok(TransactionRecipe {
            version: self.version,
            network_upgrade: NetworkUpgrade::Nu7,
            lock_time: LockTime::Height(Height(0)),
            expiry_height: Height(130),
            spends,
            outputs: vec![
                output(total - 5_000_000, self.recipient.clone())?,
                output(5_000_000 - fee, self.previous[0].lock_script.clone())?,
            ],
        }
        .build()
        .0)
    }

    pub fn sign(&self, tx: &mut Transaction) -> Result<(), String> {
        let digests = self.digests(tx)?;
        let secp = Secp256k1::new();
        for (index, digest) in digests.into_iter().enumerate() {
            let message = Message::from_digest(digest);
            let mut script = Vec::new();
            if self.multisig {
                script.push(0); // CHECKMULTISIG historical dummy.
            }
            for (key, public_key) in self
                .keys
                .iter()
                .zip(&self.public_keys)
                .take(self.threshold())
            {
                let signature = secp.sign_ecdsa(&message, key);
                // Match SLH's release contract: do not release an unchecked
                // signature. Full transaction verification remains separate.
                secp.verify_ecdsa(&message, &signature, public_key)
                    .map_err(|e| e.to_string())?;
                let mut encoded = signature.serialize_der().to_vec();
                encoded.push(1); // SIGHASH_ALL, committed from actual tx fields.
                push(&encoded, &mut script)?;
            }
            push(&self.redeem, &mut script)?;
            install(tx, index, Script::new(&script));
        }
        Ok(())
    }

    pub fn verify(&self, tx: &Transaction) -> Result<(), String> {
        let mut effects = tx.clone();
        for input in inputs_mut(&mut effects) {
            let Input::PrevOut { unlock_script, .. } = input else {
                return Err("unexpected classical coinbase input".into());
            };
            *unlock_script = Script::new(&[]);
        }
        if effects != self.assemble()? {
            return Err("classical payment effects changed".into());
        }
        let digests = self.digests(tx)?;
        let secp = Secp256k1::verification_only();
        for (input, digest) in tx.inputs().iter().zip(digests) {
            let Input::PrevOut { unlock_script, .. } = input else {
                return Err("unexpected classical coinbase input".into());
            };
            let raw = unlock_script.as_raw_bytes();
            let mut cursor = usize::from(self.multisig);
            if self.multisig && raw.first() != Some(&0) {
                return Err("classical multisig dummy must be zero".into());
            }
            for public_key in self.public_keys.iter().take(self.threshold()) {
                let encoded = take_push(raw, &mut cursor)?;
                if encoded.last() != Some(&1) {
                    return Err("classical signature must use SIGHASH_ALL".into());
                }
                let signature = Signature::from_der(&encoded[..encoded.len() - 1])
                    .map_err(|e| e.to_string())?;
                if signature.serialize_der().as_ref() != &encoded[..encoded.len() - 1] {
                    return Err("noncanonical classical DER".into());
                }
                let mut normalized = signature;
                normalized.normalize_s();
                if normalized != signature {
                    return Err("classical signature must use low S".into());
                }
                secp.verify_ecdsa(&Message::from_digest(digest), &signature, public_key)
                    .map_err(|e| e.to_string())?;
            }
            if take_push(raw, &mut cursor)? != self.redeem || cursor != raw.len() {
                return Err("classical redeem script or trailing bytes changed".into());
            }
        }
        let actual_fee = u64::from(zip317::conventional_fee(tx));
        let total = self
            .previous
            .iter()
            .map(|p| u64::from(p.value))
            .sum::<u64>();
        let outputs = tx.outputs().iter().map(|p| u64::from(p.value)).sum::<u64>();
        if total - outputs != actual_fee {
            return Err("classical fee does not match actual serialized action count".into());
        }
        Ok(())
    }

    pub fn evidence(&self, tx: &Transaction) -> Result<Value, String> {
        self.verify(tx)?;
        Ok(json!({
            "schema_version": 1,
            "algorithm": "ecdsa-secp256k1",
            "version": self.version,
            "policy": if self.multisig { "multisig" } else { "single" },
            "input_count": self.input_count,
            "offline_fixture": true,
            "trusted_utxos": false,
            "node_acceptance": false,
            "transaction_hex": hex::encode(tx.zcash_serialize_to_vec().map_err(|e| e.to_string())?),
            "unsigned_transaction_hex": hex::encode(self.assemble()?.zcash_serialize_to_vec().map_err(|e| e.to_string())?),
            "previous_outputs_hex": self.previous.iter().map(|p| p.zcash_serialize_to_vec().map(hex::encode).map_err(|e| e.to_string())).collect::<Result<Vec<_>, _>>()?,
            "messages": self.digests(tx)?.iter().enumerate().map(|(index, digest)| json!({"input_index": index,"message_hex": hex::encode(digest)})).collect::<Vec<_>>(),
            "wallet": {
                "durable_write_available": false,
                "reason": "matched transaction construction/sign/verify control; no equivalent classical wallet persistence implementation",
            },
        }))
    }

    fn threshold(&self) -> usize {
        if self.multisig {
            2
        } else {
            1
        }
    }

    fn digests(&self, tx: &Transaction) -> Result<Vec<[u8; 32]>, String> {
        if tx.inputs().len() != self.input_count {
            return Err("classical input count changed".into());
        }
        let hasher = tx
            .sighasher(NetworkUpgrade::Nu7, self.previous.clone())
            .map_err(|e| e.to_string())?;
        Ok((0..self.input_count)
            .map(|i| {
                hasher
                    .sighash(HashType::ALL, Some((i, self.redeem.clone())))
                    .0
            })
            .collect())
    }
}

fn keys(seed: u32, count: usize) -> Vec<SecretKey> {
    (0..count)
        .map(|index| {
            // Construct a nonzero scalar below 2^128, hence below secp256k1's
            // group order. Public synthetic derivation, never wallet entropy.
            let mut raw = [0; 32];
            raw[24..28].copy_from_slice(&seed.to_le_bytes());
            raw[31] = u8::try_from(index + 1).expect("at most three public fixture keys");
            SecretKey::from_slice(&raw).expect("public fixture scalar is nonzero and below order")
        })
        .collect()
}

fn scripts(keys: &[SecretKey], multisig: bool) -> (Script, Vec<u8>, Vec<PublicKey>) {
    let secp = Secp256k1::new();
    // Retain the public inventory created here so signing self-checks and
    // verification never regenerate public keys inside their stage timers.
    let public_keys = keys
        .iter()
        .map(|key| PublicKey::from_secret_key(&secp, key))
        .collect::<Vec<_>>();
    let mut redeem = Vec::new();
    if multisig {
        redeem.push(0x52);
    }
    for key in &public_keys {
        redeem.push(33);
        redeem.extend(key.serialize());
    }
    redeem.extend(if multisig {
        &[0x53, 0xae][..]
    } else {
        &[0xac][..]
    });
    let mut lock = vec![0xa9, 20];
    lock.extend(Ripemd160::digest(Sha256::digest(&redeem)));
    lock.push(0x87);
    (Script::new(&lock), redeem, public_keys)
}

fn output(value: u64, lock_script: Script) -> Result<Output, String> {
    Ok(Output {
        value: value
            .try_into()
            .map_err(|e: zakura_chain::amount::Error| e.to_string())?,
        lock_script,
    })
}

fn push(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > 255 {
        return Err("classical control push bound".into());
    }
    if bytes.len() > 75 {
        out.push(0x4c);
    }
    out.push(u8::try_from(bytes.len()).expect("bounded push"));
    out.extend(bytes);
    Ok(())
}

fn take_push<'a>(raw: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], String> {
    let opcode = *raw.get(*cursor).ok_or("truncated classical push")?;
    *cursor += 1;
    let length = match opcode {
        1..=75 => usize::from(opcode),
        0x4c => {
            let length = usize::from(*raw.get(*cursor).ok_or("truncated PUSHDATA1")?);
            *cursor += 1;
            if length < 76 {
                return Err("nonminimal PUSHDATA1".into());
            }
            length
        }
        _ => return Err("unexpected classical push opcode".into()),
    };
    let end = cursor
        .checked_add(length)
        .ok_or("classical push overflow")?;
    let result = raw
        .get(*cursor..end)
        .ok_or("truncated classical push body")?;
    *cursor = end;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_pq_test_support::outputs_mut;

    #[test]
    fn controls_cover_versions_counts_and_real_quorums() {
        for version in [5, 6] {
            for count in [1, 2, 5] {
                for multi in [false, true] {
                    let fixture = ClassicalPayment::new(version, count, multi, 7).unwrap();
                    let mut tx = fixture.assemble().unwrap();
                    fixture.sign(&mut tx).unwrap();
                    fixture.verify(&tx).unwrap();
                    let evidence = fixture.evidence(&tx).unwrap();
                    assert_eq!(evidence["messages"].as_array().unwrap().len(), count);
                    assert_eq!(evidence["node_acceptance"], false);
                    let mut changed = tx.clone();
                    outputs_mut(&mut changed)[0].value = 1u64.try_into().unwrap();
                    assert!(fixture.verify(&changed).is_err());
                    let Input::PrevOut { unlock_script, .. } = &mut inputs_mut(&mut tx)[0] else {
                        unreachable!("fixture always has prevouts")
                    };
                    let mut raw = unlock_script.as_raw_bytes().to_vec();
                    raw[usize::from(multi) + 5] ^= 1;
                    *unlock_script = Script::new(&raw);
                    assert!(fixture.verify(&tx).is_err());
                }
            }
        }
    }

    #[test]
    fn verification_checks_signatures_without_secret_keys() {
        for multisig in [false, true] {
            let mut fixture = ClassicalPayment::new(6, 5, multisig, 7).unwrap();
            let mut tx = fixture.assemble().unwrap();
            fixture.sign(&mut tx).unwrap();
            fixture.keys.clear();
            fixture.verify(&tx).unwrap();

            let Input::PrevOut { unlock_script, .. } = &mut inputs_mut(&mut tx)[0] else {
                unreachable!("fixture always has prevouts")
            };
            let mut raw = unlock_script.as_raw_bytes().to_vec();
            // Change an interior R byte while preserving DER and script framing.
            raw[usize::from(multisig) + 6] ^= 1;
            let mut cursor = usize::from(multisig);
            let encoded = take_push(&raw, &mut cursor).unwrap();
            Signature::from_der(&encoded[..encoded.len() - 1]).unwrap();
            *unlock_script = Script::new(&raw);
            assert!(fixture.verify(&tx).is_err());
        }
    }

    #[test]
    fn bounds_and_minimal_pushes_fail_closed() {
        assert!(ClassicalPayment::new(4, 1, false, 0).is_err());
        assert!(ClassicalPayment::new(5, 0, false, 0).is_err());
        assert!(ClassicalPayment::new(5, 3, false, 0).is_err());
        for malformed in [&[0x4c, 1, 0][..], &[1][..], &[0x4d, 1, 0][..], &[0][..]] {
            assert!(take_push(malformed, &mut 0).is_err());
        }
    }
}
