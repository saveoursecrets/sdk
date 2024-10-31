use anyhow::Result;
use sos_ipc::{
    Error, LocalAccountIpcService, LocalAccountSocketServer, SocketClient,
};
use sos_net::sdk::{
    crypto::AccessKey,
    prelude::{
        generate_passphrase, Account, AppIntegration, LocalAccount,
        LocalAccountSwitcher,
    },
    Paths,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

use crate::test_utils::setup;

#[tokio::test]
async fn integration_ipc_list_accounts() -> Result<()> {
    const TEST_ID: &str = "ipc_list_accounts";
    //crate::test_utils::init_tracing();
    //

    let socket_name = format!("{}.sock", TEST_ID);

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
    let (password, _) = generate_passphrase()?;
    let unauth_account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
    )
    .await?;

    let auth_address = auth_account.address().clone();
    let unauth_address = unauth_account.address().clone();

    // Add the accounts
    let mut accounts = LocalAccountSwitcher::new_with_options(Some(paths));
    accounts.add_account(auth_account);
    accounts.add_account(unauth_account);

    // Start the IPC service
    let service = Arc::new(Mutex::new(LocalAccountIpcService::new(accounts)));

    let server_socket_name = socket_name.clone();
    tokio::task::spawn(async move {
        LocalAccountSocketServer::listen(&server_socket_name, service)
            .await?;
        Ok::<(), Error>(())
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create a client and list accounts
    let mut client = SocketClient::connect(&socket_name).await?;
    let accounts = client.list_accounts().await?;
    assert_eq!(2, accounts.len());

    let authenticated = accounts
        .iter()
        .filter(|(a, _)| a.address() == &auth_address)
        .map(|(_, v)| *v)
        .collect::<Vec<_>>();
    let authenticated = authenticated.first().unwrap();
    assert!(*authenticated);

    let authenticated = accounts
        .iter()
        .filter(|(a, _)| a.address() == &unauth_address)
        .map(|(_, v)| *v)
        .collect::<Vec<_>>();
    let authenticated = authenticated.first().unwrap();
    assert!(!*authenticated);

    Ok(())
}
