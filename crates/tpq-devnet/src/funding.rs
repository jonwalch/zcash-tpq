//! One-input real-key classical-to-SLH funding. No PQ secret is accepted here.
//!
//! SIGHASH_ALL and DER construction follow the pinned fixture adapter's
//! classical.rs. Unlike that public P2SH fixture, this signs the generator's
//! random P2PKH key and authenticates the seed outpoint through a trusted node.
use crate::{
    bootstrap::{stable, Tip},
    require,
    rpc::Rpc,
    storage, Chain, Result,
};
use ripemd::Ripemd160;
use secp256k1::{Message, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{io::Cursor, path::Path, sync::Arc};
use zakura_chain::{
    block::Height,
    parameters::{NetworkKind, NetworkUpgrade},
    serialization::{ZcashDeserialize, ZcashSerialize},
    transaction::{HashType, LockTime, Transaction},
    transparent::{Address, Input, OutPoint, Output, Script},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Funder {
    schema: u8,
    chain_fingerprint: String,
    secret_key_hex: String,
}

/// Review is public transaction material; it is not a private-key backup.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub schema: u8,
    pub chain_fingerprint: String,
    pub observed_tip: String,
    pub observed_height: u32,
    pub source_txid: String,
    pub source_index: u32,
    pub destination_script_hex: String,
    pub amount_zat: u64,
    pub fee_zat: u64,
    pub change_zat: u64,
    pub expiry_height: u32,
    pub transaction_hex: String,
    pub transaction_sha256: String,
    pub txid: String,
}

fn source(chain: &Chain) -> Result<(OutPoint, Output)> {
    let blocks = chain.validate()?;
    let parent = &blocks
        .get(1)
        .ok_or("missing seed funding block")?
        .transactions[0];
    require(
        parent.is_coinbase() && parent.outputs().len() == 1,
        "expected one seed coinbase output",
    )?;
    Ok((
        OutPoint {
            hash: parent.hash(),
            index: 0,
        },
        parent.outputs()[0].clone(),
    ))
}

fn key_script(key: &SecretKey) -> Script {
    let public = PublicKey::from_secret_key(key).serialize();
    let hash: [u8; 20] = Ripemd160::digest(Sha256::digest(public)).into();
    Address::from_pub_key_hash(NetworkKind::Testnet, hash).script()
}

fn authenticate(
    rpc: &mut impl Rpc,
    chain: &Chain,
    point: &OutPoint,
    previous: &Output,
) -> Result<Tip> {
    let tip = stable(rpc, chain)?;
    let height = tip.height.ok_or("node has no tip")?;
    // Source is the exact saved coinbase at height 1. Keep maturity 100.
    require(
        height
            .checked_add(1)
            .and_then(|candidate| candidate.checked_sub(1))
            .is_some_and(|age| age >= 100),
        "immature seed coinbase",
    )?;
    require(
        height
            >= chain
                .rules
                .experimental_slh_dsa_b128s_activation_height
                .saturating_sub(1),
        "SLH not active for next block",
    )?;
    require(
        rpc.call("getblockhash", json!([0]))? == chain.rules.genesis_hash
            && rpc.call("getblockhash", json!([1]))?
                == crate::decode_block(&chain.blocks[1])?.hash().to_string(),
        "trusted node has a different source chain",
    )?;
    let utxo = rpc.call(
        "gettxout",
        json!([point.hash.to_string(), point.index, true]),
    )?;
    require(
        !utxo.is_null(),
        "seed outpoint already spent or unavailable",
    )?;
    require(
        utxo["coinbase"] == true
            && utxo["bestblock"].as_str() == tip.hash.as_deref()
            && utxo["confirmations"].as_u64() == Some(u64::from(height))
            && utxo["scriptPubKey"]["hex"].as_str()
                == Some(hex::encode(previous.lock_script.as_raw_bytes()).as_str()),
        "trusted source ownership/height mismatch",
    )?;
    // The canonical saved block gives the integer amount; require RPC agreement.
    require(
        decimal_zat(&utxo["value"].to_string())? == u64::from(previous.value),
        "trusted source amount mismatch",
    )?;
    require(
        stable(rpc, chain)? == tip,
        "tip changed while authenticating funding source",
    )?;
    Ok(tip)
}

fn decimal_zat(value: &str) -> Result<u64> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    require(
        !whole.is_empty()
            && whole.bytes().all(|c| c.is_ascii_digit())
            && fraction.len() <= 8
            && fraction.bytes().all(|c| c.is_ascii_digit()),
        "non-exact RPC coin value",
    )?;
    whole
        .parse::<u64>()?
        .checked_mul(100_000_000)
        .and_then(|whole| {
            fraction
                .parse::<u64>()
                .unwrap_or(0)
                .checked_mul(10u64.pow(u32::try_from(8 - fraction.len()).ok()?))
                .and_then(|fraction| whole.checked_add(fraction))
        })
        .ok_or_else(|| "RPC amount overflow".into())
}

fn amounts(value: u64, amount: u64, fee: u64) -> Result<u64> {
    require(
        amount >= 2403 && (10_000..=1_000_000).contains(&fee),
        "destination dust or fee outside explicit tool bounds",
    )?;
    let change = value
        .checked_sub(amount.checked_add(fee).ok_or("amount plus fee overflow")?)
        .ok_or("insufficient source value")?;
    require(change >= 2403, "change below tool dust floor")?;
    Ok(change)
}

fn sign(
    key: &SecretKey,
    point: OutPoint,
    previous: Output,
    destination: Vec<u8>,
    amount: u64,
    fee: u64,
    height: u32,
) -> Result<(Transaction, u64)> {
    require(
        previous.lock_script == key_script(key),
        "private key does not own seed outpoint",
    )?;
    require(height >= 100, "immature seed coinbase")?;
    require(
        destination.len() == 35 && destination[..2] == [0x53, 0x20] && destination[34] == 0xc0,
        "destination must be exact native SLH locking script",
    )?;
    let change = amounts(u64::from(previous.value), amount, fee)?;
    let expiry_height = Height(height.checked_add(20).ok_or("expiry overflow")?);
    let mut transaction = Transaction::V5 {
        network_upgrade: NetworkUpgrade::Nu7,
        lock_time: LockTime::Height(Height(height)),
        expiry_height,
        inputs: vec![Input::PrevOut {
            outpoint: point,
            unlock_script: Script::new(&[]),
            sequence: 0xffff_fffe,
        }],
        outputs: vec![
            Output::new(amount.try_into()?, Script::new(&destination)),
            Output::new(change.try_into()?, previous.lock_script.clone()),
        ],
        sapling_shielded_data: None,
        orchard_shielded_data: None,
    };
    let digest = transaction
        .sighasher(NetworkUpgrade::Nu7, Arc::new(vec![previous.clone()]))?
        .sighash(
            HashType::ALL,
            Some((0, previous.lock_script.as_raw_bytes().to_vec())),
        )
        .0;
    let signature = secp256k1::ecdsa::sign(Message::from_digest(digest), key);
    let mut encoded = signature.serialize_der().to_vec();
    encoded.push(1);
    let mut unlock = vec![u8::try_from(encoded.len())?];
    unlock.extend(encoded);
    unlock.push(33);
    unlock.extend(PublicKey::from_secret_key(key).serialize());
    let Transaction::V5 { inputs, .. } = &mut transaction else {
        return Err("funding transaction format changed".into());
    };
    inputs[0] = Input::PrevOut {
        outpoint: point,
        unlock_script: Script::new(&unlock),
        sequence: 0xffff_fffe,
    };
    verify_signature(&transaction, &previous)?;
    Ok((transaction, change))
}

fn verify_signature(transaction: &Transaction, previous: &Output) -> Result<()> {
    let Input::PrevOut { unlock_script, .. } = &transaction.inputs()[0] else {
        return Err("not a prevout".into());
    };
    let bytes = unlock_script.as_raw_bytes();
    let length = usize::from(*bytes.first().ok_or("missing signature")?);
    require(
        (9..=73).contains(&length)
            && bytes.len() == length + 35
            && bytes[length] == 1
            && bytes[length + 1] == 33,
        "invalid P2PKH authorization",
    )?;
    let public = PublicKey::from_slice(&bytes[length + 2..])?;
    let hash: [u8; 20] = Ripemd160::digest(Sha256::digest(public.serialize())).into();
    require(
        previous.lock_script == Address::from_pub_key_hash(NetworkKind::Testnet, hash).script(),
        "wrong funding signer",
    )?;
    let signature = secp256k1::ecdsa::Signature::from_der(&bytes[1..length])?;
    let digest = transaction
        .sighasher(NetworkUpgrade::Nu7, Arc::new(vec![previous.clone()]))?
        .sighash(
            HashType::ALL,
            Some((0, previous.lock_script.as_raw_bytes().to_vec())),
        )
        .0;
    secp256k1::ecdsa::verify(&signature, Message::from_digest(digest), &public)?;
    Ok(())
}

/// Authenticate, sign and save before any submission. Explicit approval is a
/// separate command bound to the returned SHA-256 of the signed bytes.
pub fn draft(
    rpc: &mut impl Rpc,
    chain: &Chain,
    key_path: &Path,
    review_path: &Path,
    destination: Vec<u8>,
    amount: u64,
    fee: u64,
) -> Result<Review> {
    let funder: Funder = serde_json::from_slice(&storage::read_private(key_path, 4096)?)?;
    require(
        funder.schema == 1 && funder.chain_fingerprint == chain.chain_fingerprint,
        "private funder belongs to another chain",
    )?;
    let secret: [u8; 32] = hex::decode(&funder.secret_key_hex)?
        .try_into()
        .map_err(|_| "private scalar length")?;
    let key = SecretKey::from_secret_bytes(secret)?;
    let (point, previous) = source(chain)?;
    require(previous.lock_script == key_script(&key), "wrong seed owner")?;
    let tip = authenticate(rpc, chain, &point, &previous)?;
    let height = tip.height.ok_or("missing tip")?;
    let (transaction, change) = sign(
        &key,
        point,
        previous,
        destination.clone(),
        amount,
        fee,
        height,
    )?;
    let bytes = transaction.zcash_serialize_to_vec()?;
    let review = Review {
        schema: 1,
        chain_fingerprint: chain.chain_fingerprint.clone(),
        observed_tip: tip.hash.ok_or("missing tip hash")?,
        observed_height: height,
        source_txid: point.hash.to_string(),
        source_index: point.index,
        destination_script_hex: hex::encode(destination),
        amount_zat: amount,
        fee_zat: fee,
        change_zat: change,
        expiry_height: height.checked_add(20).ok_or("expiry overflow")?,
        transaction_hex: hex::encode(&bytes),
        transaction_sha256: hex::encode(Sha256::digest(&bytes)),
        txid: transaction.hash().to_string(),
    };
    storage::write_new(review_path, &serde_json::to_vec_pretty(&review)?)?;
    Ok(review)
}

impl Review {
    pub fn load(path: &Path) -> Result<Self> {
        Ok(serde_json::from_slice(&storage::read_bounded(
            path,
            32 * 1024,
        )?)?)
    }

    fn validate(&self, chain: &Chain, approval: &str) -> Result<Transaction> {
        require(
            self.schema == 1
                && self.chain_fingerprint == chain.chain_fingerprint
                && self.transaction_sha256 == approval
                && self.transaction_hex.len() <= 4096,
            "review identity/approval mismatch",
        )?;
        let bytes = hex::decode(&self.transaction_hex)?;
        require(
            hex::encode(Sha256::digest(&bytes)) == approval,
            "saved bytes changed",
        )?;
        let mut cursor = Cursor::new(&bytes);
        let tx = Transaction::zcash_deserialize(&mut cursor)?;
        require(
            cursor.position() == u64::try_from(bytes.len())?
                && tx.zcash_serialize_to_vec()? == bytes,
            "noncanonical saved transaction",
        )?;
        let (point, previous) = source(chain)?;
        require(
            self.source_txid == point.hash.to_string()
                && self.source_index == point.index
                && self.txid == tx.hash().to_string(),
            "saved outpoint/txid mismatch",
        )?;
        let Transaction::V5 {
            network_upgrade,
            inputs,
            outputs,
            lock_time,
            expiry_height,
            sapling_shielded_data: None,
            orchard_shielded_data: None,
        } = &tx
        else {
            return Err("unsupported saved funding transaction".into());
        };
        require(
            *network_upgrade == NetworkUpgrade::Nu7
                && inputs.len() == 1
                && outputs.len() == 2
                && *lock_time == LockTime::Height(Height(self.observed_height))
                && expiry_height.0 == self.expiry_height
                && self.observed_height.checked_add(20) == Some(self.expiry_height),
            "saved transaction shape mismatch",
        )?;
        require(
            matches!(&inputs[0], Input::PrevOut {outpoint, sequence: 0xffff_fffe, ..} if *outpoint == point),
            "saved source mismatch",
        )?;
        let destination = hex::decode(&self.destination_script_hex)?;
        require(
            destination.len() == 35 && destination[..2] == [0x53, 0x20] && destination[34] == 0xc0,
            "saved destination is not SLH",
        )?;
        require(
            outputs[0].lock_script.as_raw_bytes() == destination
                && u64::from(outputs[0].value) == self.amount_zat
                && outputs[1].lock_script == previous.lock_script
                && u64::from(outputs[1].value) == self.change_zat
                && amounts(u64::from(previous.value), self.amount_zat, self.fee_zat)?
                    == self.change_zat,
            "saved payment arithmetic mismatch",
        )?;
        verify_signature(&tx, &previous)?;
        Ok(tx)
    }
}

fn known(rpc: &mut impl Rpc, review: &Review) -> Result<bool> {
    match rpc.call("getrawtransaction", json!([review.txid, 0])) {
        Ok(bytes) => {
            require(
                bytes.as_str() == Some(review.transaction_hex.as_str()),
                "node returned conflicting transaction bytes",
            )?;
            Ok(true)
        }
        Err(_) => Ok(false), // No conclusion about absence: authenticate the UTXO next.
    }
}

/// Submit exactly saved bytes. Explicit re-invocation retries only those bytes.
/// A successful return means node-known, not mined or final.
pub fn submit(
    rpc: &mut impl Rpc,
    chain: &Chain,
    review: &Review,
    approval: &str,
) -> Result<String> {
    review.validate(chain, approval)?;
    stable(rpc, chain)?;
    if known(rpc, review)? {
        return Ok(review.txid.clone());
    }
    let (point, previous) = source(chain)?;
    let tip = authenticate(rpc, chain, &point, &previous)?;
    require(
        tip.height.ok_or("missing tip")? < review.expiry_height,
        "saved funding expired; do not regenerate an unresolved payment",
    )?;
    let result = rpc.call("sendrawtransaction", json!([review.transaction_hex]));
    if let Ok(txid) = result {
        require(
            txid.as_str() == Some(review.txid.as_str()),
            "submission returned wrong txid",
        )?;
        return Ok(review.txid.clone());
    }
    if known(rpc, review)? {
        return Ok(review.txid.clone());
    }
    Err("submission outcome unknown or rejected; retain saved bytes and reconcile before exact-byte retry".into())
}
