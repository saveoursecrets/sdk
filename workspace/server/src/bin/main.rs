use anyhow::Result;
use clap::Parser;
use sos3_server::{FileSystemBackend, Server, State};
use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync::RwLock;

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

    let mut backend = FileSystemBackend::new(args.dir.clone());
    backend.read_dir()?;

    let state = Arc::new(RwLock::new(State {
        backend: Box::new(backend),
    }));

    let addr = SocketAddr::from_str(&args.bind)?;
    Server::start(addr, state).await;
    Ok(())
}
