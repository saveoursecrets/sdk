use sos_account::{
    AccountSwitcherOptions, LocalAccount, LocalAccountSwitcher,
};
use sos_backend::BackendTarget;
use sos_ipc::{
    extension_helper::server::{
        ExtensionHelperOptions, ExtensionHelperServer,
    },
    ServiceAppInfo,
};
use sos_sdk::prelude::Paths;
use sos_test_utils::make_client_backend;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

#[macro_export]
macro_rules! println {
    ($($any:tt)*) => {
        compile_error!("println! macro is forbidden, use eprintln! instead");
    };
}

/// Executable used to test the native bridge.
#[doc(hidden)]
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().collect::<Vec<_>>();

    // Callers must pass a data directory so that each
    // test is isolated
    let data_dir = args.pop().map(PathBuf::from);
    // Extension identifier is a mock value but mimics the argument
    // that browser's will pass
    let extension_id = args.pop().unwrap_or_else(String::new).to_string();

    // Load any accounts on disc
    let paths = Paths::new_client(data_dir.as_ref().unwrap());
    let options = AccountSwitcherOptions {
        paths: Some(paths),
        ..Default::default()
    };
    let mut accounts = LocalAccountSwitcher::new_with_options(options);
    let target = BackendTarget::FileSystem(Paths::new_client(
        data_dir.as_ref().unwrap(),
    ));
    accounts
        .load_accounts(
            |identity| {
                let app_dir = data_dir.clone();
                Box::pin(async move {
                    let paths = Paths::new_client(app_dir.as_ref().unwrap())
                        .with_account_id(identity.account_id());
                    let target = make_client_backend(&paths).await.unwrap();
                    LocalAccount::new_unauthenticated(
                        *identity.account_id(),
                        target,
                    )
                    .await
                })
            },
            target,
        )
        .await?;

    // Start the server
    let info = ServiceAppInfo {
        name: "test_extension_helper".to_string(),
        version: "0.0.0".to_string(),
    };
    let accounts = Arc::new(RwLock::new(accounts));
    let options = ExtensionHelperOptions::new(extension_id, info);
    let server =
        ExtensionHelperServer::new(options, accounts, |_| {}).await?;
    server.listen().await;
    Ok(())
}
