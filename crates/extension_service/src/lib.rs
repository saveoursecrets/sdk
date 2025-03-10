use sos_account::AccountSwitcherOptions;
use sos_backend::{BackendTarget, InferOptions};
use sos_core::Paths;
use sos_ipc::{
    extension_helper::server::{
        ExtensionHelperOptions, ExtensionHelperServer,
    },
    ServiceAppInfo,
};
use sos_net::{
    NetworkAccount, NetworkAccountOptions, NetworkAccountSwitcher,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use xclipboard::Clipboard;

/// Entrypoint for an executable used to bridge JSON requests
/// from browser extensions using the native messaging API
/// to an in-memory extension helper web service.
pub async fn run() -> anyhow::Result<()> {
    let mut args = std::env::args().into_iter().collect::<Vec<_>>();

    // Firefox passes two arguments, the last is the
    // extension id (from Firefox 55) and Chrome passes
    // a single argument on Mac and Linux. But on windows
    // Chrome also passes a native window handle so we
    // pop that first.
    #[cfg(windows)]
    args.pop();

    let extension_id = args.pop().unwrap_or_else(String::new).to_string();

    let mut accounts =
        NetworkAccountSwitcher::new_with_options(AccountSwitcherOptions {
            clipboard: Some(Clipboard::new_timeout(90)?),
            ..Default::default()
        });

    accounts
        .load_accounts(
            |identity| {
                Box::pin(async move {
                    let paths = Paths::new_client(Paths::data_dir()?)
                        .with_account_id(identity.account_id());
                    let target =
                        BackendTarget::infer(paths, InferOptions::default())
                            .await?;
                    Ok(NetworkAccount::new_unauthenticated(
                        *identity.account_id(),
                        target,
                        NetworkAccountOptions::default(),
                    )
                    .await?)
                })
            },
            None,
        )
        .await?;

    let info = ServiceAppInfo {
        name: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let accounts = Arc::new(RwLock::new(accounts));
    let options = ExtensionHelperOptions::new(extension_id, info);
    let server = ExtensionHelperServer::new(options, accounts).await?;
    server.listen().await;
    Ok(())
}
