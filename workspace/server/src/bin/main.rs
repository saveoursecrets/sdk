use clap::Parser;
use sos3_server::{FileSystemBackend, Server, State, ServerConfig, Result};
use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync::RwLock;

/// Secret storage server.
#[derive(Parser, Debug)]
#[clap(name = "sos3", author, version, about, long_about = None)]
struct Cli {
    /// Serve the built in GUI.
    #[structopt(short, long)]
    gui: bool,

    /// Bind to host:port.
    #[structopt(short, long, default_value = "127.0.0.1:5053")]
    bind: String,

    /// Config file to load.
    #[structopt(short, long, parse(from_os_str))]
    config: PathBuf,

    /// Directory to load vaults from.
    #[structopt(parse(from_os_str))]
    dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    let name = env!("CARGO_PKG_NAME").to_string();
    let version = env!("CARGO_PKG_VERSION").to_string();

    let config = ServerConfig::load(&args.config)?;

    let mut backend = FileSystemBackend::new(args.dir.clone());
    backend.read_dir()?;

    let state = Arc::new(RwLock::new(State {
        name,
        version,
        gui: args.gui,
        config,
        backend: Box::new(backend),
    }));

    let addr = SocketAddr::from_str(&args.bind)?;
    Server::start(addr, state).await;
    Ok(())
}
