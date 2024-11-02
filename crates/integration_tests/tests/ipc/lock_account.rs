use anyhow::Result;
use sos_ipc::{
    remove_socket_file, AppIntegration, CommandOutcome, Error,
    LocalAccountIpcService, LocalAccountServiceDelegate,
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
async fn integration_ipc_lock_account() -> Result<()> {
    const TEST_ID: &str = "ipc_lock_account";
    // crate::test_utils::init_tracing();
    //

    let socket_name = format!("{}.sock", TEST_ID);

    // Must clean up the tmp file on MacOS
    remove_socket_file(&socket_name);

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

    let auth_address = auth_account.address().clone();

    // Add the accounts
    let mut accounts = LocalAccountSwitcher::new_with_options(Some(paths));
    accounts.add_account(auth_account);

    let ipc_accounts = Arc::new(RwLock::new(accounts));
    let assert_accounts = ipc_accounts.clone();

    let (delegate, commands) = LocalAccountServiceDelegate::new(16);
    let mut lock_rx = commands.lock;

    tokio::task::spawn(async move {
        while let Some(command) = lock_rx.recv().await {
            let mut accounts = command.accounts.write().await;

            let account = accounts
                .iter_mut()
                .find(|a| a.address() == &command.address)
                .unwrap();
            account.sign_out().await.unwrap();
            command.result.send(CommandOutcome::Success).unwrap();
        }
    });

    // Start the IPC service
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
    let outcome = client.lock(auth_address).await?;
    assert_eq!(CommandOutcome::Success, outcome);

    let accounts = assert_accounts.write().await;
    let mut it = accounts.iter();
    let account = it.next().unwrap();
    assert!(!account.is_authenticated().await);

    Ok(())
}
