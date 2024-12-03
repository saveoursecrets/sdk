use anyhow::Result;
use sos_ipc::{
    local_account_delegate, remove_socket_file, Error,
    LocalAccountIpcService, LocalAccountSocketServer,
};
use sos_net::{
    protocol::{
        integration::{LinkedAccount, LocalClient, LocalIntegration},
        Origin, RemoteSync,
    },
    sdk::{
        crypto::AccessKey,
        prelude::{
            generate_passphrase, Account, LocalAccount, LocalAccountSwitcher,
        },
        Paths,
    },
};
use sos_test_utils::teardown;
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, RwLock};

use crate::{test_utils::setup, TestLocalTransport};

/// Test for syncing between apps installed on the same
/// device via the IPC communication channel.
#[tokio::test]
async fn integration_ipc_local_sync() -> Result<()> {
    const TEST_ID: &str = "ipc_local_sync";
    // crate::test_utils::init_tracing();
    //

    let socket_name = format!("{}.sock", TEST_ID);

    // Must clean up the tmp file on MacOS
    remove_socket_file(&socket_name);

    let mut dirs = setup(TEST_ID, 2).await?;
    let data_dir = dirs.clients.remove(0);
    let linked_data_dir = dirs.clients.remove(0);

    Paths::scaffold(Some(data_dir.clone())).await?;
    Paths::scaffold(Some(linked_data_dir.clone())).await?;
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

    let address = auth_account.address().clone();

    // Add the accounts
    let mut accounts = LocalAccountSwitcher::new_with_options(Some(paths));
    accounts.add_account(auth_account);

    // Start the IPC service
    let (delegate, _commands) = local_account_delegate(16);
    let service = Arc::new(RwLock::new(LocalAccountIpcService::new(
        Arc::new(RwLock::new(accounts)),
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

    // Integration mananges the accounts on the linked app
    let integration = LocalIntegration::new();

    // Test transport creates a IPC socket client for communication
    let transport = TestLocalTransport::new(socket_name.clone()).await?;

    // Prepare the local client using our test transport
    let origin = Origin::new(
        socket_name.to_string(),
        format!("sos+ipc://{}", socket_name).parse()?,
    );
    let local_client =
        LocalClient::new(origin, Arc::new(Mutex::new(Box::new(transport))));

    // Prepare the linked account and add to the integration
    let linked_account = LinkedAccount::new_unauthenticated(
        address,
        local_client,
        Some(linked_data_dir),
    )
    .await?;
    let accounts = integration.accounts();
    let mut accounts = accounts.write().await;
    accounts.add_account(linked_account);
    accounts.switch_account(&address);

    let account = accounts.selected_account().unwrap();

    // Sync the data from the other app
    account.sync().await;

    // teardown(TEST_ID).await;

    Ok(())
}
