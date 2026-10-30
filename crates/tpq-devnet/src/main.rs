use std::{net::SocketAddr, path::Path};
use zakura_tpq_devnet::{bootstrap, funding, prepare, rpc::HttpRpc, Chain, Result};

const USAGE: &str = "usage: tpq-devnet prepare PUBLIC_DIR PRIVATE_DIR NAME | bootstrap CHAIN SOCKET COOKIE --producers-stopped | fund-draft CHAIN SOCKET (COOKIE | --trusted-local-gateway) FUNDER REVIEW TPQTEST_RECEIVER AMOUNT_ZAT FEE_ZAT | fund-submit CHAIN SOCKET (COOKIE | --trusted-local-gateway) REVIEW APPROVED_TRANSACTION_SHA256
SOCKET must be numeric loopback with a nonzero port (no URLs, DNS or proxies).
COOKIE is a private cookie file, reopened each request. --trusted-local-gateway
instead explicitly trusts an established local gateway (zdn connect) and sends
no node credentials. COOKIE and --trusted-local-gateway are mutually exclusive.
Bootstrap requires direct authenticated cookie mode; gateways cannot submit blocks.
All modes still validate the independently approved chain/profile identity.";

fn transport(socket: &str, mode: &str) -> Result<HttpRpc> {
    let address = socket.parse::<SocketAddr>()?;
    if mode == "--trusted-local-gateway" {
        HttpRpc::trusted_local_gateway(address)
    } else {
        if mode.starts_with("--") {
            return Err("expected a private cookie path or --trusted-local-gateway".into());
        }
        HttpRpc::new(address, Path::new(mode))
    }
}

fn run(args: &[String]) -> Result<()> {
    // Mode occupies the existing cookie position, never an additional option.
    // Validate misuse before loading chain/key/review files or opening sockets.
    if args.iter().any(|arg| arg == "--trusted-local-gateway")
        && (args.get(3).map(String::as_str) != Some("--trusted-local-gateway")
            || !matches!(
                args.first().map(String::as_str),
                Some("fund-draft" | "fund-submit")
            )
            || args
                .iter()
                .filter(|arg| *arg == "--trusted-local-gateway")
                .count()
                != 1)
    {
        return Err("--trusted-local-gateway replaces COOKIE for funding only; bootstrap requires direct cookie mode".into());
    }
    match args.first().map(String::as_str) {
        Some("--help" | "-h") if args.len() == 1 => println!("{USAGE}"),
        Some("prepare") if args.len() == 4 => {
            let chain = prepare(Path::new(&args[1]), Path::new(&args[2]), args[3].clone())?;
            println!("{}", chain.chain_fingerprint);
        }
        Some("bootstrap") if args.len() == 5 && args[4] == "--producers-stopped" => {
            let mut rpc = transport(&args[2], &args[3])?;
            let chain = Chain::load(Path::new(&args[1]))?;
            bootstrap::bootstrap(&mut rpc, &chain, true)?;
            println!("saved checkpoint range loaded");
        }
        Some("fund-draft") if args.len() == 9 => {
            let mut rpc = transport(&args[2], &args[3])?;
            let chain = Chain::load(Path::new(&args[1]))?;
            let review = funding::draft(
                &mut rpc,
                &chain,
                Path::new(&args[4]),
                Path::new(&args[5]),
                &args[6],
                args[7].parse()?,
                args[8].parse()?,
            )?;
            println!("{}", serde_json::to_string_pretty(&review)?);
        }
        Some("fund-submit") if args.len() == 6 => {
            let mut rpc = transport(&args[2], &args[3])?;
            let chain = Chain::load(Path::new(&args[1]))?;
            let review = funding::Review::load(Path::new(&args[4]))?;
            println!("{}", funding::submit(&mut rpc, &chain, &review, &args[5])?);
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        // Never display server bodies, private JSON parse contexts, or key data.
        eprintln!("tpq-devnet failed: {error}");
        std::process::exit(1);
    }
}
