#[cfg(not(target_arch = "wasm32"))]
use sos::{Result, TARGET};

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "sos=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = sos::cli::sos::run().await {
        tracing::error!(target: TARGET, "{}", e);
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn main() {}
