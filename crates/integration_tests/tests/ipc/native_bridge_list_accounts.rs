use anyhow::Result;
use http::StatusCode;
use sos_ipc::{
    local_transport::{HttpMessage, LocalRequest},
    native_bridge::client::NativeBridgeClient,
    remove_socket_file,
    server::LocalSocketServer,
    Error,
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

const TEST_ID: &str = "ipc_native_bridge_list_accounts";
const SOCKET_NAME: &str = "ipc_native_bridge_list_accounts.sock";

/// Test listing accounts via the native bridge.
#[tokio::test]
async fn integration_ipc_native_bridge_list_accounts() -> Result<()> {
    // crate::test_utils::init_tracing();
    //
    //
    remove_socket_file(SOCKET_NAME);

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

    // Add the accounts
    let mut accounts = LocalAccountSwitcher::from(paths);
    accounts.add_account(auth_account);
    accounts.add_account(unauth_account);

    let ipc_accounts = Arc::new(RwLock::new(accounts));

    let server_socket_name = SOCKET_NAME.to_string();
    tokio::task::spawn(async move {
        LocalSocketServer::listen(
            &server_socket_name,
            ipc_accounts,
            Default::default(),
        )
        .await?;
        Ok::<(), Error>(())
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut request = LocalRequest::get("/accounts".parse().unwrap());
    request.set_request_id(1);

    let (command, arguments) = super::native_bridge_cmd();
    let mut client = NativeBridgeClient::new(command, arguments).await?;
    let response = client.send(request).await?;
    assert_eq!(StatusCode::OK, response.status().unwrap());

    client.kill().await?;
    teardown(TEST_ID).await;

    Ok(())
}
