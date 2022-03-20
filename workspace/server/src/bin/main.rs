use anyhow::{bail, Result};
use clap::Parser;
use sos3_server::{Server, State};
use sos_core::vault::Vault;
use std::{
    collections::HashMap,
    fs::read_dir,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, RwLock},
};
use uuid::Uuid;

/// Secret storage server.
#[derive(Parser, Debug)]
#[clap(name = "sos3", author, version, about, long_about = None)]
struct Cli {
    /// Bind to host:port.
    #[structopt(short, long, default_value = "127.0.0.1:5053")]
    bind: String,

    /// Directory to load vaults from.
    #[structopt(parse(from_os_str))]
    dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let vaults = read_vaults(&args.dir)?;
    let state = Arc::new(RwLock::new(State { vaults }));
    let addr = SocketAddr::from_str(&args.bind)?;
    Server::start(addr, state).await;
    Ok(())
}

/// Read vaults into memory.
fn read_vaults(dir: &PathBuf) -> Result<HashMap<Uuid, Vault>> {
    if !dir.is_dir() {
        bail!("not a directory {}", dir.display());
    }

    let mut vaults = Vec::new();
    for entry in read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(ext) = path.extension() {
            if ext == Vault::extension() {
                let vault = Vault::read_file(path)?;
                vaults.push(vault);
            }
        }
    }

    if vaults.is_empty() {
        bail!("no vaults found");
    }

    Ok(vaults
        .into_iter()
        .map(|v| (v.id().clone(), v))
        .collect::<_>())
}
