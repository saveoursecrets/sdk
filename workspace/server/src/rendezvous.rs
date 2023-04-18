use clap::Parser;

use sos_node::peer::{libp2p::identity::Keypair, rendezvous::Server, Result};
use std::{net::SocketAddr, str::FromStr};

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Rendezvous server for peer discovery.
#[derive(Parser, Debug)]
#[clap(name = "sos-rendezvous", author, version, about, long_about = None)]
struct Cli {
    /// Hex encoded 32 byte Ed25519 secret key.
    #[clap(short, long, env, hide_env_values = true)]
    identity: Option<String>,

    /// Bind address.
    #[clap(short, long, default_value = "0.0.0.0:3505")]
    bind: String,
}

async fn run() -> Result<()> {
    let args = Cli::parse();

    //let name = env!("CARGO_PKG_NAME").to_string();
    //let version = env!("CARGO_PKG_VERSION").to_string();

    let identity = if let Some(identity) = args.identity {
        let private_key = hex::decode(identity)?;
        Keypair::ed25519_from_bytes(private_key)?
    } else {
        Keypair::generate_ed25519()
    };

    let addr = SocketAddr::from_str(&args.bind)?;
    let server = Server::new(identity, addr);
    server.run().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| {
                "sos_node::peer::rendezvous=info,sos_server=info".into()
            }),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    match run().await {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("{}", e);
        }
    }
    Ok(())
}
