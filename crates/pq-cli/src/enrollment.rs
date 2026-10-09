//! Public key exchange feeds the existing cumulative inventory/enrollment contract.
use crate::{password::password, payments::id};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{self, Write},
    ops::RangeInclusive,
    path::Path,
};
use zakura_pq_slh_dsa_b_exp::{codec::key_commitment, Policy};
use zakura_pq_wallet::{
    read_inventory, read_transfer, write_transfer, Entry, Hex, KeyPath, Manifest, Origin, Profile,
    Role, Wallet,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const FORMAT: &str = "ZcashTransparentPQ/experimental/slh-dsa-b-128s/key-exchange/v1";
const MAX_KEY: usize = 4096;
pub const USAGE: &str = "Public cosigner enrollment (authenticate every exchange fingerprint):\n\
  pq-wallet key-export <profile> <backup> <receive|change> <index> <new-key-file>\n\
  pq-wallet enroll-prepare <profile> <inventory> <receive|change> <threshold> <new-inventory> <key-file> <key-fingerprint> [<key-file> <key-fingerprint> ...]\n\
Supply one through fifteen independently authenticated public keys. The command\n\
adds one receive/change policy to the existing inventory; it never issues it.\n\
Each cosigner prepares its own cumulative inventory, reviews every participant,\n\
threshold, origin, suite and profile, then enrolls its fingerprint with enroll.\n\
Keep the new covering backup before exporting or issuing the enrolled receiver.\n";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyExchange {
    format: String,
    index: u32,
    profile: Profile,
    public_key_hex: Hex<32>,
    role: u8,
    suite: u8,
    wallet_id: Hex<16>,
}
impl KeyExchange {
    fn to_json(&self) -> Result<Vec<u8>> {
        self.profile.validate()?;
        if self.format != FORMAT || self.role > 1 || self.suite != 0xf7 {
            return Err("unsupported public key exchange".into());
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_KEY {
            return Err("public key exchange exceeds limit".into());
        }
        Ok(bytes)
    }
    fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_KEY {
            return Err("public key exchange exceeds limit".into());
        }
        let value: Self = serde_json::from_slice(bytes)?;
        if value.to_json()? != bytes {
            return Err("public key exchange must be canonical JSON".into());
        }
        Ok(value)
    }
    fn fingerprint(&self) -> Result<Hex<32>> {
        let mut hash = Sha256::new();
        hash.update(b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/key-exchange/v1\0");
        hash.update(self.to_json()?);
        Ok(Hex(hash.finalize().into()))
    }
}
pub fn expected(command: &str) -> Option<RangeInclusive<usize>> {
    match command {
        "key-export" => Some(6..=6),
        "enroll-prepare" => Some(8..=36),
        _ => None,
    }
}
fn role(text: &str) -> Result<Role> {
    match text {
        "receive" => Ok(Role::Receive),
        "change" => Ok(Role::Change),
        _ => Err("expected receive or change".into()),
    }
}
pub fn validate_arguments(args: &[String]) -> Result<()> {
    if args[0] == "enroll-prepare" {
        if !args.len().is_multiple_of(2) {
            return Err(
                "provide one key file and authenticated fingerprint per participant".into(),
            );
        }
        role(&args[3])?;
        let threshold: u8 = args[4].parse()?;
        let participants = (args.len() - 6) / 2;
        if threshold == 0 || usize::from(threshold) > participants || participants > 15 {
            return Err("expected 1 <= threshold <= participants <= 15".into());
        }
        for pair in args[6..].chunks_exact(2) {
            id(&pair[1])?;
        }
    } else if args[0] == "key-export" {
        role(&args[3])?;
        args[4].parse::<u32>()?;
    }
    Ok(())
}
fn append_policy(
    mut manifest: Manifest,
    profile: &Profile,
    role: Role,
    threshold: u8,
    keys: Vec<KeyExchange>,
) -> Result<Manifest> {
    if &manifest.profile != profile || manifest.suite != 0xf7 {
        return Err("inventory does not match the approved SLH profile".into());
    }
    let index = match role {
        Role::Receive => manifest.receive_end,
        Role::Change => manifest.change_end,
    };
    let mut participants = BTreeSet::new();
    let mut ordered = Vec::new();
    for key in keys {
        if key.profile != *profile
            || key.suite != manifest.suite
            || key.role != role as u8
            || !participants.insert(key.wallet_id)
        {
            return Err("cosigner profile, role, suite or participant mismatch".into());
        }
        if key.wallet_id == manifest.wallet_id && u64::from(key.index) != index {
            return Err("local key must use the next cumulative inventory index".into());
        }
        ordered.push((
            key_commitment(&key.public_key_hex.0),
            Origin {
                account: 0,
                index: key.index,
                wallet_id: key.wallet_id,
            },
        ));
    }
    if !participants.contains(&manifest.wallet_id) {
        return Err("policy must contain the local wallet".into());
    }
    if u32::from(threshold) > profile.max_tx_pq_checks
        || u32::from(threshold) > profile.max_block_pq_checks
    {
        return Err("policy exceeds the independently approved check limits".into());
    }
    ordered.sort_by_key(|(commitment, _)| *commitment);
    let policy = Policy::new(
        threshold,
        ordered.iter().map(|(commitment, _)| *commitment).collect(),
    )
    .map_err(|_| "invalid or duplicate cosigner keys")?;
    manifest.entries.push(Entry {
        origins: ordered.into_iter().map(|(_, origin)| origin).collect(),
        policy_hex: hex::encode(policy.descriptor()),
        role: role as u8,
    });
    match role {
        Role::Receive => {
            manifest.receive_end = manifest
                .receive_end
                .checked_add(1)
                .ok_or("receive range exhausted")?
        }
        Role::Change => {
            manifest.change_end = manifest
                .change_end
                .checked_add(1)
                .ok_or("change range exhausted")?
        }
    }
    manifest.revision = manifest
        .revision
        .checked_add(1)
        .ok_or("inventory revision exhausted")?;
    let wallet_id = manifest.wallet_id;
    manifest.entries.sort_by_key(|entry| {
        (
            entry.role,
            entry
                .origins
                .iter()
                .find(|origin| origin.wallet_id == wallet_id)
                .map(|origin| origin.index),
        )
    });
    manifest.validate()?;
    Ok(manifest)
}
pub fn run(args: &[String], profile: Profile) -> Result<()> {
    if args[0] == "key-export" {
        let password = password("Backup password: ")?;
        let wallet = Wallet::load_backup(Path::new(&args[2]), password.as_bytes(), &profile)?;
        let path = KeyPath {
            role: role(&args[3])?,
            index: args[4].parse()?,
        };
        let exchange = KeyExchange {
            format: FORMAT.into(),
            index: path.index,
            profile,
            public_key_hex: Hex(wallet.public_key(path)),
            role: path.role as u8,
            suite: wallet.suite().byte(),
            wallet_id: wallet.manifest().wallet_id,
        };
        write_transfer(Path::new(&args[5]), &exchange.to_json()?)?;
        serde_json::to_writer(
            io::stdout(),
            &serde_json::json!({"exchange":exchange, "fingerprint":exchange.fingerprint()?}),
        )?;
    } else {
        let manifest = Manifest::from_json(&read_inventory(Path::new(&args[2]))?)?;
        let mut keys = Vec::new();
        for pair in args[6..].chunks_exact(2) {
            let key = KeyExchange::from_json(&read_transfer(Path::new(&pair[0]), MAX_KEY)?)?;
            if key.fingerprint()? != id(&pair[1])? {
                return Err("public key pairing fingerprint mismatch".into());
            }
            keys.push(key);
        }
        let candidate = append_policy(
            manifest.clone(),
            &profile,
            role(&args[3])?,
            args[4].parse()?,
            keys,
        )?;
        manifest.check_update(&candidate)?;
        write_transfer(Path::new(&args[5]), &candidate.to_json()?)?;
        serde_json::to_writer(
            io::stdout(),
            &serde_json::json!({"inventory":candidate, "fingerprint":candidate.fingerprint()?, "threshold":args[4].parse::<u8>()?}),
        )?;
    }
    writeln!(io::stdout())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn empty() -> Manifest {
        let corpus: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
        ))
        .unwrap();
        let mut manifest =
            Manifest::from_json(corpus["inventory_json"].as_str().unwrap().as_bytes()).unwrap();
        manifest.entries.clear();
        manifest.receive_end = 0;
        manifest.change_end = 0;
        manifest.retired_receive_end = 0;
        manifest.retired_change_end = 0;
        manifest.validate().unwrap();
        manifest
    }
    fn keys(manifest: &Manifest, n: u8) -> Vec<KeyExchange> {
        (0..n)
            .map(|i| KeyExchange {
                format: FORMAT.into(),
                index: 0,
                profile: manifest.profile.clone(),
                public_key_hex: Hex([i; 32]),
                role: 0,
                suite: 0xf7,
                wallet_id: if i == 0 {
                    manifest.wallet_id
                } else {
                    Hex([i; 16])
                },
            })
            .collect()
    }
    #[test]
    fn canonical_key_exchange_binds_profile_origin_identity_and_suite() {
        let manifest = empty();
        let key = keys(&manifest, 1).pop().unwrap();
        let raw = key.to_json().unwrap();
        assert_eq!(KeyExchange::from_json(&raw).unwrap(), key);
        assert!(KeyExchange::from_json(&[raw.as_slice(), b"\n"].concat()).is_err());
        assert!(KeyExchange::from_json(&vec![b' '; MAX_KEY + 1]).is_err());
        let original = key.fingerprint().unwrap();
        for mut changed in [key.clone(), key.clone(), key.clone(), key.clone()]
            .into_iter()
            .enumerate()
        {
            match changed.0 {
                0 => changed.1.index = 1,
                1 => changed.1.role = 1,
                2 => changed.1.wallet_id = Hex([99; 16]),
                _ => changed.1.profile.max_block_pq_checks += 1,
            }
            assert_ne!(changed.1.fingerprint().unwrap(), original);
        }
        let mut other = key.clone();
        other.suite = 1;
        assert!(other.to_json().is_err());
        let value = String::from_utf8(raw)
            .unwrap()
            .replace("\"suite\":247", "\"suite\":247,\"suite\":247");
        assert!(KeyExchange::from_json(value.as_bytes()).is_err());
    }
    #[test]
    fn all_120_cosigner_policies_reuse_sorted_native_descriptors_and_cumulative_enrollment() {
        let base = empty();
        for n in 1..=15 {
            for m in 1..=n {
                let keys = keys(&base, n);
                let mut reversed = keys.clone();
                reversed.reverse();
                let candidate =
                    append_policy(base.clone(), &base.profile, Role::Receive, m, keys).unwrap();
                assert_eq!(
                    candidate,
                    append_policy(base.clone(), &base.profile, Role::Receive, m, reversed).unwrap()
                );
                base.check_update(&candidate).unwrap();
                assert_eq!(candidate.entries[0].policy().unwrap().threshold(), m);
                assert_eq!(candidate.entries[0].origins.len(), usize::from(n));
                assert_eq!(candidate.entries[0].receiver().unwrap().encode().len(), 69);
                assert_eq!(candidate.receive_end, 1);
            }
        }
        let mut duplicate = keys(&base, 2);
        duplicate[1].wallet_id = duplicate[0].wallet_id;
        assert!(append_policy(base.clone(), &base.profile, Role::Receive, 1, duplicate).is_err());
        let mut wrong = keys(&base, 1);
        wrong[0].index = 1;
        assert!(append_policy(base.clone(), &base.profile, Role::Receive, 1, wrong).is_err());
        let mut wrong = keys(&base, 1);
        wrong[0].profile.max_block_pq_checks += 1;
        assert!(append_policy(base.clone(), &base.profile, Role::Receive, 1, wrong).is_err());
        assert!(append_policy(
            base.clone(),
            &base.profile,
            Role::Receive,
            1,
            keys(&base, 16)
        )
        .is_err());
    }
}
