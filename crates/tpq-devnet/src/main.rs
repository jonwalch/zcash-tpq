use std::{net::SocketAddr, path::Path};
use zakura_tpq_devnet::{bootstrap, funding, prepare, rpc::HttpRpc, Chain, Result};

fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("prepare") if args.len() == 4 => {
            let chain = prepare(Path::new(&args[1]), Path::new(&args[2]), args[3].clone())?;
            println!("{}", chain.chain_fingerprint);
        },
        Some("bootstrap") if args.len() == 5 && args[4] == "--producers-stopped" => {
            let chain = Chain::load(Path::new(&args[1]))?;
            let mut rpc = HttpRpc::new(args[2].parse::<SocketAddr>()?, Path::new(&args[3]))?;
            bootstrap::bootstrap(&mut rpc, &chain, true)?;
            println!("saved checkpoint range loaded");
        },
        Some("fund-draft") if args.len() == 9 => {
            let chain = Chain::load(Path::new(&args[1]))?;
            let mut rpc = HttpRpc::new(args[2].parse::<SocketAddr>()?, Path::new(&args[3]))?;
            let review = funding::draft(&mut rpc,&chain,Path::new(&args[4]),Path::new(&args[5]),hex::decode(&args[6])?,args[7].parse()?,args[8].parse()?)?;
            println!("{}",serde_json::to_string_pretty(&review)?);
        },
        Some("fund-submit") if args.len() == 6 => {
            let chain = Chain::load(Path::new(&args[1]))?;
            let mut rpc = HttpRpc::new(args[2].parse::<SocketAddr>()?, Path::new(&args[3]))?;
            let review = funding::Review::load(Path::new(&args[4]))?;
            println!("{}",funding::submit(&mut rpc,&chain,&review,&args[5])?);
        },
        _ => return Err("usage: tpq-devnet prepare PUBLIC_DIR PRIVATE_DIR NAME | bootstrap CHAIN SOCKET COOKIE --producers-stopped | fund-draft CHAIN SOCKET COOKIE FUNDER REVIEW SCRIPT_HEX AMOUNT_ZAT FEE_ZAT | fund-submit CHAIN SOCKET COOKIE REVIEW APPROVED_TRANSACTION_SHA256".into()),
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
