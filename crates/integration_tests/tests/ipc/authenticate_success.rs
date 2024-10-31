use anyhow::Result;
use sos_ipc::{
    AppIntegration, AuthenticateOutcome, Error,
    LocalAccountAuthenticateCommand, LocalAccountIpcService,
    LocalAccountSocketServer, SocketClient,
};
use sos_net::sdk::{
    crypto::AccessKey,
    prelude::{
        generate_passphrase, Account, LocalAccount, LocalAccountSwitcher,
    },
    Paths,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;

use crate::test_utils::setup;

#[tokio::test]
async fn integration_ipc_authenticate_success() -> Result<()> {
    const TEST_ID: &str = "ipc_authenticate_success";
    // crate::test_utils::init_tracing();
    //

    let socket_name = format!("{}.sock", TEST_ID);

    // Must clean up the tmp file on MacOS
    #[cfg(target_os = "macos")]
    {
        let socket_path =
            std::path::PathBuf::from(format!("/tmp/{}", socket_name));
        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }
    }

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    Paths::scaffold(Some(data_dir.clone())).await?;
    let paths = Paths::new_global(data_dir.clone());

    let account_name = format!("{}_authenticated", TEST_ID);
    let (password, _) = generate_passphrase()?;

    // Create an account and authenticate
    let mut auth_account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
    )
    .await?;
    let key: AccessKey = password.into();
    auth_account.sign_in(&key).await?;

    // Create an account and don't authenticate
    let account_name = format!("{}_unauthenticated", TEST_ID);
    let (unauth_password, _) = generate_passphrase()?;
    let unauth_account = LocalAccount::new_account(
        account_name.clone(),
        unauth_password.clone(),
        Some(data_dir.clone()),
    )
    .await?;

    let unauth_address = unauth_account.address().clone();

    // Add the accounts
    let mut accounts = LocalAccountSwitcher::new_with_options(Some(paths));
    accounts.add_account(auth_account);
    accounts.add_account(unauth_account);

    let ipc_accounts = Arc::new(RwLock::new(accounts));
    let assert_accounts = ipc_accounts.clone();
    let auth_key: AccessKey = unauth_password.into();

    let (auth_tx, mut auth_rx) =
        tokio::sync::mpsc::channel::<LocalAccountAuthenticateCommand>(16);

    tokio::task::spawn(async move {
        while let Some(command) = auth_rx.recv().await {
            let mut accounts = command.accounts.write().await;
            if let Some(account) = accounts
                .iter_mut()
                .find(|a| a.address() == &command.address)
            {
                account.sign_in(&auth_key).await.unwrap();
                command.result.send(AuthenticateOutcome::Success).unwrap();
            } else {
                command.result.send(AuthenticateOutcome::NotFound).unwrap();
            }
        }
    });

    // Start the IPC service
    let delegate = LocalAccountIpcService::new_delegate(auth_tx);
    let service = Arc::new(RwLock::new(LocalAccountIpcService::new(
        ipc_accounts,
        delegate,
    )));

    let server_socket_name = socket_name.clone();
    tokio::task::spawn(async move {
        LocalAccountSocketServer::listen(&server_socket_name, service)
            .await?;
        Ok::<(), Error>(())
    });

    tokio::time::sleep(Duration::from_millis(250)).await;

    let mut client = SocketClient::connect(&socket_name).await?;
    let outcome = client.authenticate(unauth_address).await?;

    println!("{:#?}", outcome);

    let accounts = assert_accounts.write().await;
    let mut it = accounts.iter();
    let first_account = it.next().unwrap();
    let second_account = it.next().unwrap();

    assert!(first_account.is_authenticated().await);
    assert!(second_account.is_authenticated().await);

    Ok(())
}
