use crate::{
    suite::{Suite, SuitePolicy},
    Entry, Error, Hex, KeyPath, Manifest, Origin, Role, Wallet, MAX_ENTRIES,
};
use bech32::{primitives::decode::CheckedHrpstring, Bech32m, Hrp};
use std::path::Path;

/// Exact experimental receiver. Parsing never selects a legacy fallback.
/// Regtest retains v1; custom Testnet uses chain-bound v2 transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receiver {
    suite: Suite,
    commitment: Hex<32>,
    chain: Option<Hex<32>>,
}

impl Receiver {
    /// Construct a receiver for the explicit suite and public policy commitment.
    pub fn new(suite: Suite, commitment: Hex<32>) -> Self {
        Self {
            suite,
            commitment,
            chain: None,
        }
    }

    /// Construct transport bound to an independently approved chain profile.
    pub fn for_profile(
        suite: Suite,
        commitment: Hex<32>,
        profile: &crate::Profile,
    ) -> Result<Self, Error> {
        profile.validate()?;
        Ok(Self {
            suite,
            commitment,
            chain: profile.chain_fingerprint,
        })
    }

    /// Reject transport from any other wallet network or custom chain.
    pub fn check_profile(&self, profile: &crate::Profile) -> Result<(), Error> {
        profile.validate()?;
        if self.chain != profile.chain_fingerprint {
            return Err(Error::UnsupportedContext);
        }
        Ok(())
    }

    /// The sole supported experimental suite.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The public policy commitment.
    pub fn commitment(&self) -> Hex<32> {
        self.commitment
    }

    /// Parse exact lowercase Bech32m transport without normalization.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let custom = text.starts_with("tpqtest1");
        if (if custom {
            text.len() != 122
        } else {
            text.len() != 69 || !text.starts_with("tpqreg1")
        }) || text.bytes().any(|b| b.is_ascii_uppercase())
        {
            return Err(Error::Encoding);
        }
        let decoded = CheckedHrpstring::new::<Bech32m>(text).map_err(|_| Error::Encoding)?;
        let payload: Vec<_> = decoded.byte_iter().collect();
        if payload.len() != if custom { 67 } else { 35 }
            || payload[..2] != if custom { [2, 1] } else { [1, 2] }
        {
            return Err(Error::UnsupportedFormat);
        }
        let receiver = Self {
            suite: Suite::from_byte(payload[2])?,
            chain: if custom {
                Some(Hex(payload[3..35]
                    .try_into()
                    .map_err(|_| Error::Encoding)?))
            } else {
                None
            },
            commitment: Hex(payload[if custom { 35 } else { 3 }..]
                .try_into()
                .map_err(|_| Error::Encoding)?),
        };
        // v2 has four padding bits. Reject nonzero padding, not just checksums.
        if receiver.encode() != text {
            return Err(Error::Encoding);
        }
        Ok(receiver)
    }

    /// Encode canonical Regtest (69 characters) or custom Testnet (122 characters).
    pub fn encode(&self) -> String {
        if let Some(chain) = self.chain {
            let mut bytes = vec![2, 1, self.suite.byte()];
            bytes.extend(chain.0);
            bytes.extend(self.commitment.0);
            return bech32::encode::<Bech32m>(Hrp::parse("tpqtest").expect("fixed HRP"), &bytes)
                .expect("bounded receiver");
        }
        let mut bytes = [0u8; 35];
        bytes[..3].copy_from_slice(&[1, 2, self.suite.byte()]);
        bytes[3..].copy_from_slice(&self.commitment.0);
        bech32::encode::<Bech32m>(Hrp::parse("tpqreg").expect("fixed HRP"), &bytes)
            .expect("fixed-length receiver")
    }

    /// The suite's exact output template, `53 20 <commitment> c0`.
    pub fn script(&self) -> [u8; 35] {
        let mut bytes = [0u8; 35];
        bytes[..2].copy_from_slice(&[self.suite.template_version(), 0x20]);
        bytes[2..34].copy_from_slice(&self.commitment.0);
        bytes[34] = 0xc0;
        bytes
    }
}

impl Entry {
    /// Encode a policy with the approved wallet chain identity.
    pub fn receiver_for(&self, profile: &crate::Profile) -> Result<Receiver, Error> {
        let policy = self.suite_policy()?;
        Receiver::for_profile(policy.suite(), Hex(policy.commitment()), profile)
    }

    /// Encode this complete policy as its public receiver.
    pub fn receiver(&self) -> Result<Receiver, Error> {
        let policy = self.suite_policy()?;
        Ok(Receiver::new(policy.suite(), Hex(policy.commitment())))
    }
}

impl Wallet {
    /// Extend both account-zero ranges with fresh 1-of-1 policies. No receiver
    /// becomes available until the entire candidate backup has been verified,
    /// published under a new filename and synced. Keep an external recovery copy.
    pub fn extend_single_backup(
        &mut self,
        receive: u32,
        change: u32,
        path: &Path,
        password: &[u8],
    ) -> Result<(), Error> {
        let total = self.manifest.receive_end
            + self.manifest.change_end
            + u64::from(receive)
            + u64::from(change);
        if total > MAX_ENTRIES as u64 || receive == 0 && change == 0 {
            return Err(Error::Limits);
        }
        let mut candidate = self.manifest.clone();
        candidate.revision = candidate.revision.checked_add(1).ok_or(Error::Exhausted)?;
        for (role, start, count) in [
            (Role::Receive, candidate.receive_end, receive),
            (Role::Change, candidate.change_end, change),
        ] {
            for index in start..start + u64::from(count) {
                let index = u32::try_from(index).map_err(|_| Error::Exhausted)?;
                let policy = SuitePolicy::new(
                    self.suite(),
                    1,
                    vec![self.key_commitment(KeyPath { role, index })?],
                )?;
                candidate.entries.push(Entry {
                    origins: vec![Origin {
                        account: 0,
                        index,
                        wallet_id: candidate.wallet_id,
                    }],
                    policy_hex: hex::encode(policy.encode()),
                    role: role as u8,
                });
            }
        }
        candidate.receive_end += u64::from(receive);
        candidate.change_end += u64::from(change);
        candidate.entries.sort_by_key(|entry| {
            (
                entry.role,
                entry
                    .local(candidate.wallet_id)
                    .expect("validated local entry")
                    .1
                    .index,
            )
        });
        self.enroll_backup(candidate.clone(), candidate.fingerprint()?, path, password)
    }

    /// Install an independently approved cumulative inventory, including 2-of-3
    /// policies. Every local commitment is reconstructed from this wallet root.
    /// Each other cosigner must separately approve and back up their own copy.
    pub fn enroll_backup(
        &mut self,
        candidate: Manifest,
        approved_fingerprint: Hex<32>,
        path: &Path,
        password: &[u8],
    ) -> Result<(), Error> {
        if candidate.fingerprint()? != approved_fingerprint {
            return Err(Error::Pairing);
        }
        self.manifest.check_update(&candidate)?;
        if candidate != self.manifest
            && self.manifest.revision.checked_add(1) != Some(candidate.revision)
        {
            return Err(Error::RecoveryIncomplete);
        }
        // A separate candidate owns its clearing root buffer. Publication failure
        // leaves the caller's accepted manifest unchanged, even after rename.
        let wallet = Self {
            root: self.root.clone(),
            manifest: candidate,
        };
        for entry in &wallet.manifest.entries {
            let (slot, origin) = entry.local(wallet.manifest.wallet_id)?;
            let role = if entry.role == 0 {
                Role::Receive
            } else {
                Role::Change
            };
            let policy = entry.suite_policy()?;
            let previous_end = match role {
                Role::Receive => self.manifest.receive_end,
                Role::Change => self.manifest.change_end,
            };
            if u64::from(origin.index) >= previous_end {
                wallet.manifest.profile.check_policy(&policy)?;
            }
            if policy.key_commitments()[slot]
                != wallet.key_commitment(KeyPath {
                    role,
                    index: origin.index,
                })?
            {
                return Err(Error::Policy);
            }
        }
        wallet.save_backup(path, password)?;
        self.manifest = wallet.manifest.clone();
        Ok(())
    }
}
