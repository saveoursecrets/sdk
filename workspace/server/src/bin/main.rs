use anyhow::Result;
use std::sync::{Arc, RwLock};
use std::net::SocketAddr;
use std::str::FromStr;
use sos3_server::{Server, State};
use clap::Parser;

/// Secret storage server.
#[derive(Parser, Debug)]
#[clap(name = "sos3", author, version, about, long_about = None)]
struct Cli {
    /// Bind to host:port.
    #[structopt(short, long, default_value = "127.0.0.1:5053")]
    bind: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let state = Arc::new(RwLock::new(State {}));
    let addr = SocketAddr::from_str(&args.bind)?;
    Server::start(addr, state).await;
    Ok(())
}

