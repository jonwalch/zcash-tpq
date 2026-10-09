//! Experimental Regtest wallet keys, discovery and explicitly approved payments.
#![forbid(unsafe_code)]
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod discovery;
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod enrollment;
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod history;
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod password;
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod payments;
#[cfg(feature = "experimental-slh-dsa-b128s")]
mod recovery;

#[cfg(feature = "experimental-slh-dsa-b128s")]
use password::password;
use std::io::{self, Write};
#[cfg(feature = "experimental-slh-dsa-b128s")]
use std::{fs, io::Read, path::Path};
#[cfg(feature = "experimental-slh-dsa-b128s")]
use zakura_pq_wallet::{KeyPath, Profile, Role, Wallet};
#[cfg(feature = "experimental-slh-dsa-b128s")]
use zeroize::Zeroizing;

#[cfg(feature = "experimental-slh-dsa-b128s")]
const USAGE: &str = "Experimental Regtest PQ wallet keys and backups\n\
Usage:\n\
  pq-wallet create-slh-exp <trusted-profile.json> <new-backup-file> <birthday-height>\n\
  pq-wallet inspect <trusted-profile.json> <backup-file>\n\
  pq-wallet pubkey <trusted-profile.json> <backup-file> <receive|change> <index>\n\
  pq-wallet rekey <trusted-profile.json> <backup-file> <new-backup-file>\n\
Passwords are read from the controlling terminal with echo disabled.\n\
Use a strong unique password from a password manager. Keep a verified recovery\n\
copy outside the working database. Restore retires covered issuance ranges;\n\
reconcile the latest manifest and retire the old allocator first.\n\
";

#[cfg(feature = "experimental-slh-dsa-b128s")]
fn new_password() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let first = password("New backup password: ")?;
    let repeated = password("Repeat new password: ")?;
    if *first != *repeated {
        return Err("password confirmation did not match".into());
    }
    Ok(first)
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let Some(command) = args.first().map(String::as_str) else {
        io::stdout().write_all(USAGE.as_bytes())?;
        io::stdout().write_all(enrollment::USAGE.as_bytes())?;
        io::stdout().write_all(recovery::USAGE.as_bytes())?;
        io::stdout().write_all(discovery::USAGE.as_bytes())?;
        io::stdout().write_all(payments::USAGE.as_bytes())?;
        io::stdout().write_all(history::USAGE.as_bytes())?;
        return Ok(());
    };
    if matches!(command, "--help" | "-h") {
        io::stdout().write_all(USAGE.as_bytes())?;
        io::stdout().write_all(enrollment::USAGE.as_bytes())?;
        io::stdout().write_all(recovery::USAGE.as_bytes())?;
        io::stdout().write_all(discovery::USAGE.as_bytes())?;
        io::stdout().write_all(payments::USAGE.as_bytes())?;
        io::stdout().write_all(history::USAGE.as_bytes())?;
        return Ok(());
    }
    let expected = expected(command).ok_or("unknown command; use --help")?;
    if !expected.contains(&args.len()) {
        return Err("incorrect arguments; use --help".into());
    }
    recovery::validate_arguments(args)?;
    enrollment::validate_arguments(args)?;
    let mut bytes = Vec::new();
    fs::File::open(&args[1])?
        .take(4097)
        .read_to_end(&mut bytes)?;
    let profile = Profile::from_json(&bytes)?;
    if recovery::expected(command).is_some() {
        return recovery::run(args, profile);
    }
    if enrollment::expected(command).is_some() {
        return enrollment::run(args, profile);
    }
    if history::expected(command).is_some() {
        return history::run(args, profile);
    }
    if payments::expected(command).is_some() {
        return payments::run(args, profile);
    }
    if discovery::expected(command).is_some() {
        return discovery::run(args, profile);
    }
    let path = Path::new(&args[2]);
    if command == "create-slh-exp" {
        let birthday = args[3].parse::<u32>()?;
        let password = new_password()?;
        let wallet = Wallet::create(profile, birthday)?;
        wallet.save_backup(path, password.as_bytes())?;
        writeln!(
            io::stdout(),
            "Created verified backup with empty inventory. No receivers issued."
        )?;
    } else {
        let old_password = password("Backup password: ")?;
        let wallet = Wallet::load_backup(path, old_password.as_bytes(), &profile)?;
        match command {
            "inspect" => {
                io::stdout().write_all(&wallet.manifest().to_json()?)?;
                writeln!(io::stdout(), "\nAuthenticated inventory; freshness and chain history require reconciliation.")?;
            }
            "pubkey" => {
                let role = match args[3].as_str() {
                    "receive" => Role::Receive,
                    "change" => Role::Change,
                    _ => return Err("expected receive or change".into()),
                };
                let index = args[4].parse::<u32>()?;
                serde_json::to_writer(
                    io::stdout(),
                    &serde_json::json!({
                        "index": index, "public_key_hex": hex::encode(wallet.public_key_bytes(KeyPath { role, index })?),
                        "role": role as u8, "wallet_id": wallet.manifest().wallet_id,
                    }),
                )?;
                writeln!(io::stdout())?;
            }
            "rekey" => {
                let password = new_password()?;
                wallet.save_backup(Path::new(&args[3]), password.as_bytes())?;
                writeln!(
                    io::stdout(),
                    "Created verified backup generation. Previous backup retained."
                )?;
            }
            _ => unreachable!("command checked before reading credentials"),
        }
    }
    Ok(())
}

#[cfg(feature = "experimental-slh-dsa-b128s")]
fn expected(command: &str) -> Option<std::ops::RangeInclusive<usize>> {
    match command {
        "create-slh-exp" | "rekey" => Some(4..=4),
        "inspect" => Some(3..=3),
        "pubkey" => Some(5..=5),
        _ => discovery::expected(command)
            .or_else(|| payments::expected(command))
            .map(|n| n..=n)
            .or_else(|| history::expected(command))
            .or_else(|| enrollment::expected(command))
            .or_else(|| recovery::expected(command)),
    }
}

#[cfg(not(feature = "experimental-slh-dsa-b128s"))]
fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        writeln!(io::stdout(), "Experimental SLH wallet support is disabled. Build with experimental-slh-dsa-b128s to enable Regtest commands.")?;
        return Ok(());
    }
    Err("experimental SLH wallet support is disabled".into())
}

fn main() -> std::process::ExitCode {
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // Display only deliberately sanitized wallet errors, not their sources.
            let _ = writeln!(io::stderr(), "{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "experimental-slh-dsa-b128s"))]
    #[test]
    fn feature_off_refuses_every_operation_before_files_or_credentials() {
        for command in [
            "create-slh-exp",
            "sign",
            "snapshot-restore",
            "key-export",
            "create",
            "create-sqisign-exp",
        ] {
            let error = run(&[command.into(), "unreadable-profile".into()]).unwrap_err();
            assert_eq!(
                error.to_string(),
                "experimental SLH wallet support is disabled"
            );
        }
    }
    #[cfg(feature = "experimental-slh-dsa-b128s")]
    #[test]
    fn every_command_family_is_bounded_before_reading_files_or_credentials() {
        for command in [
            "create-slh-exp",
            "inspect",
            "pubkey",
            "rekey",
            "restore",
            "extend",
            "enroll",
            "export",
            "watch-create",
            "watch-import",
            "receive",
            "sync",
            "status",
            "propose",
            "propose-preview",
            "review",
            "change-approve",
            "sign",
            "assemble",
            "submit",
            "payment-archive",
            "payment-resume",
            "refresh-propose",
            "refresh-review",
            "refresh-approve",
            "payments",
            "payment-export",
            "payment-history",
            "payment-history-export",
            "key-export",
            "enroll-prepare",
            "snapshot-save",
            "snapshot-restore",
        ] {
            let range = expected(command).expect("every documented operation is dispatched");
            for n in [range.start() - 1, range.end() + 1] {
                let mut args = vec!["not-a-file".into(); n];
                args[0] = command.into();
                assert_eq!(
                    run(&args).unwrap_err().to_string(),
                    "incorrect arguments; use --help",
                    "{command}"
                );
            }
        }
        for command in ["create", "create-sqisign-exp", "create-mldsa", "unknown"] {
            assert!(expected(command).is_none());
            assert_eq!(
                run(&[command.into()]).unwrap_err().to_string(),
                "unknown command; use --help"
            );
        }
    }
}
