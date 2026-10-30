//! Fixed-slot public export. Never starts or executes the supplied host artifact.
use std::path::Path;
use zakura_tpq_devnet::{
    adapter::{self, Pin},
    storage, Result,
};

fn regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    if !path.is_absolute() || !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("public input requires an absolute regular non-symlink file".into());
    }
    storage::read_bounded(path, limit)
}
fn run() -> Result<()> {
    if cfg!(feature = "wallet") {
        return Err("public importer requires --no-default-features --features adapter".into());
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 7 {
        return Err("usage: zdn-tpq-import ABS_CHAIN_JSON ABS_WALLET_PROFILE_JSON ABS_HOST_ADAPTER EXECUTABLE_SHA256 SELECTION_SHA256 SOURCE_REVISION ABS_NEW_PUBLIC_DIR".into());
    }
    let hash = |v: &str, n| {
        v.len() == n
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if !hash(&args[3], 64)
        || !hash(&args[4], 64)
        || !hash(&args[5], 40)
        || !Path::new(&args[6]).is_absolute()
    {
        return Err("invalid public pin or destination".into());
    }
    let chain = regular(Path::new(&args[0]), zakura_tpq_devnet::MAX_FILE)?;
    let profile = regular(Path::new(&args[1]), 2 * 1024 * 1024)?;
    let host = regular(Path::new(&args[2]), 128 * 1024 * 1024)?;
    let host_pin = Pin::of(&host);
    if host.is_empty() || host_pin.sha256 != args[3] {
        return Err("host adapter pin mismatch".into());
    }
    let (input, bundle, compiled) = adapter::import_public(&chain, &profile)?;
    let descriptor = serde_json::to_vec(&input.descriptor)?;
    let compiled = serde_json::to_vec(&compiled)?;
    let package = serde_json::to_vec(&serde_json::json!({
        "schema":"zdn-external-package/v1","sourceUrl":"https://github.com/jonwalch/zcash-tpq","sourceRevision":args[5],"license":"MIT OR Apache-2.0","hostPlatform":"linux/amd64",
        "hostAdapter":{"adapterId":adapter::ADAPTER_ID,"adapterVersion":adapter::VERSION,"preparedInputSchema":adapter::SCHEMA,"adapterSelectionSha256":args[4],"executableSha256":host_pin.sha256,"executableBytes":host_pin.bytes},
        "preparedChainSource":Pin::of(&chain),"preparedProfileSource":Pin::of(&profile),
        "descriptor":Pin::of(&descriptor),"nativeRules":Pin::of(input.native_rules_json.as_bytes()),"seedBundle":Pin::of(&bundle),"walletProfile":Pin::of(&profile),"compiledResult":Pin::of(&compiled)
    }))?;
    // Finish all semantic/pin checks before creating the destination. A failed
    // create-new export is never reused as a completed import; choose a new path.
    let output = Path::new(&args[6]);
    storage::create_private_dir(output)?;
    for (name, bytes) in [
        ("descriptor.json", descriptor.as_slice()),
        ("native-rules.json", input.native_rules_json.as_bytes()),
        ("wallet-profile.json", profile.as_slice()),
        ("seed-blocks.bin", bundle.as_slice()),
        ("host-adapter", host.as_slice()),
        ("compiled.json", compiled.as_slice()),
        ("package.json", package.as_slice()),
    ] {
        storage::write_new(&output.join(name), bytes)?;
    }
    println!(
        "{}",
        serde_json::to_string(
            &serde_json::json!({"schema":"zdn-tpq-import/v1","package":Pin::of(&package),"nativeFingerprint":input.descriptor.native_fingerprint})
        )?
    );
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("public chain import failed; inputs require explicit public paths/pins and a new destination; run zdn-tpq-import with CHAIN PROFILE HOST_ADAPTER EXECUTABLE_SHA256 SELECTION_SHA256 SOURCE_REVISION NEW_DIR");
        std::process::exit(1);
    }
}
