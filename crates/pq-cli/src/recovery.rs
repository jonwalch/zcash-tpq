//! Thin command adapters for the wallet's two explicit recovery modes.
use crate::{password::password, payments::id};
use std::{
    io::{self, Write},
    ops::RangeInclusive,
    path::Path,
};
use zakura_pq_wallet::{
    recovery::{self, SnapshotTrust},
    Profile, WatchStore,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub const USAGE: &str = "Encrypted inventory and coherent operational recovery:\n\
  pq-wallet restore <profile> <backup> <approved-inventory-fingerprint> <new-directory>\n\
  pq-wallet snapshot-save <profile> <backup> <store> <new-directory>\n\
  pq-wallet snapshot-restore <profile> <snapshot-directory> <new-directory> unknown\n\
  pq-wallet snapshot-restore <profile> <snapshot-directory> <new-directory> known <trusted-receipt-fingerprint> --retired-old-allocators\n\
Inventory restore and unknown authority restore remain monitor-only. Known mode\n\
asserts independently trusted latest receipt/authority and stopped old allocators;\n\
hashing the receipt in an untrusted snapshot cannot establish completeness.\n\
Retain snapshot receipts through a protected independent channel. Restores retain\n\
old artifacts, rotate allocation, and require trusted-node reconciliation. The new\n\
backup-restored.tpq uses the entered backup password; rekey makes a new password.\n";
pub fn expected(command: &str) -> Option<RangeInclusive<usize>> {
    match command {
        "restore" | "snapshot-save" => Some(5..=5),
        "snapshot-restore" => Some(5..=7),
        _ => None,
    }
}
fn trust(args: &[String]) -> Result<SnapshotTrust> {
    match (args[4].as_str(), args.len()) {
        ("unknown", 5) => Ok(SnapshotTrust::Unknown),
        ("known", 7) if args[6] == "--retired-old-allocators" => {
            Ok(SnapshotTrust::KnownAuthority {
                trusted_receipt: id(&args[5])?,
            })
        }
        _ => Err(
            "use unknown, or known <independently-trusted-receipt> --retired-old-allocators".into(),
        ),
    }
}
pub fn validate_arguments(args: &[String]) -> Result<()> {
    match args[0].as_str() {
        "restore" => {
            id(&args[3])?;
        }
        "snapshot-restore" => {
            trust(args)?;
        }
        _ => (),
    }
    Ok(())
}
pub fn run(args: &[String], profile: Profile) -> Result<()> {
    let password = password("Backup password: ")?;
    if args[0] == "snapshot-save" {
        let mut store = WatchStore::open(Path::new(&args[3]), &profile)?;
        let receipt = store.save_operational_snapshot(
            Path::new(&args[2]),
            password.as_bytes(),
            Path::new(&args[4]),
        )?;
        serde_json::to_writer(
            io::stdout(),
            &serde_json::json!({"receipt":receipt, "receipt_fingerprint":receipt.fingerprint()?}),
        )?;
    } else {
        let restored = if args[0] == "restore" {
            recovery::restore_inventory(
                Path::new(&args[2]),
                password.as_bytes(),
                &profile,
                id(&args[3])?,
                Path::new(&args[4]),
            )?
        } else {
            recovery::restore_operational_snapshot(
                Path::new(&args[2]),
                password.as_bytes(),
                &profile,
                trust(args)?,
                Path::new(&args[3]),
            )?
        };
        serde_json::to_writer(
            io::stdout(),
            &serde_json::json!({"authority":if matches!(restored.authority, SnapshotTrust::Unknown) {"unknown"} else {"known"}, "inventory_fingerprint":restored.wallet.manifest().fingerprint()?, "mode":restored.watch.mode(), "scan":restored.watch.status()?}),
        )?;
    }
    writeln!(io::stdout())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_authority_requires_independent_receipt_and_explicit_retirement() {
        let mut args: Vec<String> = [
            "snapshot-restore",
            "profile",
            "source",
            "destination",
            "unknown",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(trust(&args).unwrap(), SnapshotTrust::Unknown);
        args[4] = "known".into();
        assert!(trust(&args).is_err());
        args.push("11".repeat(32));
        assert!(trust(&args).is_err());
        args.push("--retired-old-allocators".into());
        assert_eq!(
            trust(&args).unwrap(),
            SnapshotTrust::KnownAuthority {
                trusted_receipt: zakura_pq_wallet::Hex([0x11; 32])
            }
        );
        args[6] = "--empty-mempool".into();
        assert!(trust(&args).is_err());
        args[4] = "unknown".into();
        assert!(trust(&args).is_err());
    }
}
