#[cfg(not(target_arch = "wasm32"))]
use sos::{Result, USER};
use sos_cli_helpers::messages::{fail, warn};

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> Result<()> {
    use kdam::term;
    use sos_net::sdk::{account::Account, logs::Logger};

    let logger: Logger = Default::default();
    logger.init_subscriber(None)?;

    if let Err(e) = sos::cli::sos::run().await {
        if !e.is_interrupted() {
            fail(e.to_string());
        }

        if let Some(user) = USER.get() {
            let mut owner = user.write().await;
            if let Err(e) = owner.sign_out().await {
                warn(format!("sign out {e}"));
            }
        }

        let _ = term::show_cursor();
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn main() {}
