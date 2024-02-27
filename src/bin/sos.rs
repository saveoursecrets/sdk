#[cfg(not(target_arch = "wasm32"))]
use sos::{Result, TARGET, USER};

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> Result<()> {
    use kdam::term;
    use sos_net::sdk::{account::Account, logs::Logger};

    let logger: Logger = Default::default();
    logger.init_subscriber(None)?;

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

        let _ = term::show_cursor();
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn main() {}
