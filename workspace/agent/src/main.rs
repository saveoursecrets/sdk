use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sos_agent::{listen, spawn, Result, ENV};

/// Key agent service.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {}

async fn run() -> Result<()> {
    let _ = Cli::parse();
    let socket = std::env::var(ENV).ok();
    if let Some(socket_path) = socket {
        listen(socket_path).await?;
    } else {
        spawn()?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "sos_agent=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = run().await {
        tracing::error!("{}", e);
    }
    Ok(())
}
