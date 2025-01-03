use sos_ipc::{
    extension_helper::server::{
        ExtensionHelperOptions, ExtensionHelperServer,
    },
    ServiceAppInfo,
};
use sos_sdk::prelude::{
    AccountSwitcherOptions, LocalAccount, LocalAccountSwitcher, Paths,
};
use std::{path::PathBuf, sync::Arc};
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

    // Callers must pass a data directory so that each
    // test is isolated
    let data_dir = args.pop().map(PathBuf::from);
    // Extension identifier is a mock value but mimics the argument
    // that browser's will pass
    let extension_id = args.pop().unwrap_or_else(String::new).to_string();

    // Load any accounts on disc
    let paths = Paths::new_global(data_dir.as_ref().unwrap());
    let options = AccountSwitcherOptions {
        paths: Some(paths),
        ..Default::default()
    };
    let mut accounts = LocalAccountSwitcher::new_with_options(options);
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

    // Start the server
    let info = ServiceAppInfo {
        name: "test_extension_helper".to_string(),
        version: "0.0.0".to_string(),
    };
    let accounts = Arc::new(RwLock::new(accounts));
    let options = ExtensionHelperOptions::new(extension_id, info);
    let server = ExtensionHelperServer::new(options, accounts).await?;
    server.listen().await;
    Ok(())
}
