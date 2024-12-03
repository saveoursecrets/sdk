use anyhow::Result;
use sos_ipc::{
    local_account_delegate, remove_socket_file, AppIntegration, Command,
    CommandOptions, CommandOutcome, Error, LocalAccountIpcService,
    LocalAccountSocketServer, SocketClient,
};
use sos_net::sdk::{
    crypto::AccessKey,
    prelude::{
        generate_passphrase, Account, LocalAccount, LocalAccountSwitcher,
    },
    Paths,
};
use sos_test_utils::teardown;
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

    let (delegate, mut commands) = local_account_delegate(16);

    tokio::task::spawn(async move {
        while let Some(command) = commands.recv().await {
            let Command { accounts, options } = command;
            if let CommandOptions::Authenticate { address, result } = options
            {
                let mut accounts = accounts.write().await;
                let account = accounts
                    .iter_mut()
                    .find(|a| a.address() == &address)
                    .unwrap();
                account.sign_in(&auth_key).await.unwrap();
                result.send(CommandOutcome::Success).unwrap();
            }
        }
    });

    // Start the IPC service
    let service = Arc::new(RwLock::new(LocalAccountIpcService::new(
        ipc_accounts,
        delegate,
        Default::default(),
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
    assert_eq!(CommandOutcome::Success, outcome);

    let accounts = assert_accounts.write().await;
    let mut it = accounts.iter();
    let first_account = it.next().unwrap();
    let second_account = it.next().unwrap();

    assert!(first_account.is_authenticated().await);
    assert!(second_account.is_authenticated().await);

    teardown(TEST_ID).await;

    Ok(())
}
