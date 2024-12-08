use sos_ipc::native_bridge::server::{
    NativeBridgeOptions, NativeBridgeServer,
};
use sos_sdk::prelude::{LocalAccount, LocalAccountSwitcher};
use std::sync::Arc;
use tokio::sync::RwLock;

#[macro_export]
#[allow(missing_fragment_specifier)]
macro_rules! println {
    ($($any:tt)*) => {
        compile_error!("println! macro is forbidden, use eprintln! instead");
    };
}

/// Executable used to test the native bridge.
#[doc(hidden)]
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().into_iter().collect::<Vec<_>>();

    let extension_id = args.pop().unwrap_or_else(String::new).to_string();
    let data_dir = None;

    let mut accounts = LocalAccountSwitcher::new();
    accounts
        .load_accounts(
            |identity| {
                let app_dir = data_dir.clone();
                Box::pin(async move {
                    Ok(LocalAccount::new_unauthenticated(
                        *identity.address(),
                        app_dir,
                    )
                    .await?)
                })
            },
            data_dir.clone(),
        )
        .await?;
    let accounts = Arc::new(RwLock::new(accounts));

    let options = NativeBridgeOptions::new(extension_id);
    let server = NativeBridgeServer::new(options, accounts).await?;
    server.listen().await;
    Ok(())
}
