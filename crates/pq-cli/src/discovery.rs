use crate::password::password;
use std::{
    io::{self, Write},
    path::Path,
};
use zakura_pq_wallet::{
    export_inventory, read_inventory, Hex, Manifest, Profile, Wallet, WatchMode, WatchStore,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub const USAGE: &str = "Receiving and discovery (experimental Regtest):\n\
  pq-wallet extend <profile> <backup> <new-backup> <receive-count> <change-count>\n\
  pq-wallet enroll <profile> <backup> <approved-inventory> <fingerprint> <new-backup>\n\
  pq-wallet export <profile> <backup> <new-inventory-file>\n\
  pq-wallet watch-create <profile> <inventory> <fingerprint> <new-directory> <monitor|allocator>\n\
  pq-wallet watch-import <profile> <directory> <inventory> <fingerprint>\n\
  pq-wallet receive <profile> <directory>\n\
  pq-wallet sync <profile> <directory> <loopback-ip:rpc-port> <max-blocks>\n\
  pq-wallet status <profile> <directory>\n\
Back up the complete inventory outside the disposable watch directory before\n\
exporting or issuing. Verify pairing fingerprints through an authenticated\n\
channel. Only one allocator may use an inventory; never clone an allocator.\n\
Status is cached confirmed history, not current spendability. Sync uses a trusted\n\
local node; its PQ rules must independently match the approved profile.\n";

pub fn expected(command: &str) -> Option<usize> {
    match command {
        "extend" | "enroll" | "watch-create" => Some(6),
        "watch-import" | "sync" => Some(5),
        "export" => Some(4),
        "receive" | "status" => Some(3),
        _ => None,
    }
}
fn fingerprint(text: &str) -> Result<Hex<32>> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected a 64-character lowercase pairing fingerprint".into());
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes)?;
    Ok(Hex(bytes))
}
pub fn run(args: &[String], profile: Profile) -> Result<()> {
    match args[0].as_str() {
        "extend" | "enroll" | "export" => {
            let password = password("Backup password: ")?;
            let mut wallet =
                Wallet::load_backup(Path::new(&args[2]), password.as_bytes(), &profile)?;
            match args[0].as_str() {
                "extend" => wallet.extend_single_backup(
                    args[4].parse()?,
                    args[5].parse()?,
                    Path::new(&args[3]),
                    password.as_bytes(),
                )?,
                "enroll" => wallet.enroll_backup(
                    Manifest::from_json(&read_inventory(Path::new(&args[3]))?)?,
                    fingerprint(&args[4])?,
                    Path::new(&args[5]),
                    password.as_bytes(),
                )?,
                _ => export_inventory(wallet.manifest(), Path::new(&args[3]))?,
            }
            let fingerprint = hex::encode(wallet.manifest().fingerprint()?.0);
            crate::output(
                serde_json::json!({"inventory_fingerprint":fingerprint}),
                &format!("Inventory fingerprint: {fingerprint}"),
            )?;
            if !crate::machine() {
                writeln!(io::stdout(), "Keep a verified external backup before transferring this inventory or issuing receivers.")?;
            }
        }
        "watch-create" => {
            let mode = match args[5].as_str() {
                "monitor" => WatchMode::Monitor,
                "allocator" => WatchMode::Allocator,
                _ => return Err("expected monitor or allocator".into()),
            };
            let store = WatchStore::create(
                Path::new(&args[4]),
                &read_inventory(Path::new(&args[2]))?,
                fingerprint(&args[3])?,
                &profile,
                mode,
            )?;
            show(&store)?;
        }
        command => {
            let mut store = WatchStore::open(Path::new(&args[2]), &profile)?;
            match command {
                "watch-import" => store.import(
                    &read_inventory(Path::new(&args[3]))?,
                    fingerprint(&args[4])?,
                )?,
                "receive" => {
                    let receiver = store.receive()?.encode();
                    crate::output(serde_json::json!({"receiver":receiver}), &receiver)?;
                    return Ok(());
                }
                "sync" => {
                    store.sync(&mut crate::rpc(&args[3], &profile)?, args[4].parse()?)?;
                }
                "status" => (),
                _ => return Err("unknown discovery command".into()),
            }
            show(&store)?;
        }
    }
    Ok(())
}
fn show(store: &WatchStore) -> Result<()> {
    serde_json::to_writer(
        io::stdout(),
        &serde_json::json!({
            "inventory_fingerprint": hex::encode(store.manifest().fingerprint()?.0),
            "mode": store.mode(), "receive_next": store.receive_next(), "scan": store.status()?,
        }),
    )?;
    writeln!(io::stdout())?;
    Ok(())
}
