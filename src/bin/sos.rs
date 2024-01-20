#[cfg(not(target_arch = "wasm32"))]
use sos::{Result, TARGET, USER};

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> Result<()> {
    use sos_net::sdk::account::Account;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "sos=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = sos::cli::sos::run().await {
        if !e.is_interrupted() {
            tracing::error!(target: TARGET, "{}", e);
        }
        
        if let Some(user) = USER.get() {
            let mut owner = user.write().await;
            if let Err(e) = owner.sign_out().await {
                tracing::warn!(error = ?e, "sign out");
            }
        }

        std::process::exit(1);
    }

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn main() {}
