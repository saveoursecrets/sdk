#[cfg(not(target_arch = "wasm32"))]
use sos::{Result, TARGET};

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(all(not(debug_assertions), feature = "keyring"))]
    {
        let native_keyring = sos_sdk::get_native_keyring();
        let mut keyring = native_keyring.lock().await;
        keyring.set_enabled(true);
    }

    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "sos=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = sos::cli::run().await {
        tracing::error!(target: TARGET, "{}", e);
    }

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn main() {}
