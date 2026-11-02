//! Dedicated public-input process. Build without default features.
use std::io::{Read, Write};
use zakura_tpq_devnet::{adapter, Result};

fn run() -> Result<()> {
    if cfg!(feature = "wallet") {
        return Err("host adapter requires --no-default-features --features adapter".into());
    }
    if std::env::args().skip(1).collect::<Vec<_>>() != ["--zdn-public-chain-adapter-v1"] {
        return Err("fixed adapter protocol argument required".into());
    }
    let mut request = Vec::new();
    std::io::stdin()
        .take(u64::try_from(adapter::MAX_JSON)? + 1)
        .read_to_end(&mut request)?;
    let output = adapter::respond(&request, || {
        let path = std::path::Path::new("seed-blocks.bin");
        if !std::fs::symlink_metadata(path)?.file_type().is_file() {
            return Err("raw slot must be regular".into());
        }
        zakura_tpq_devnet::storage::read_bounded(path, adapter::MAX_BUNDLE)
    })?;
    std::io::stdout().write_all(&output)?;
    Ok(())
}
fn main() {
    if run().is_err() {
        // Never forward public-input parser diagnostics or file contents.
        eprintln!("public chain adapter: invalid-public-input");
        std::process::exit(1);
    }
}
