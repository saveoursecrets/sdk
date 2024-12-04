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
            generate_passphrase, Account, Identity, LocalAccount,
            LocalAccountSwitcher, SecretChange,
        },
        Paths,
    },
};
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, RwLock};

use crate::{
    test_utils::{mock, setup, teardown},
    TestLocalTransport,
};

/// Test for syncing between apps installed on the same
/// device via the IPC communication channel.
#[ignore]
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

    let (password, _) = generate_passphrase()?;

    // Create an account and authenticate
    let mut local_account = LocalAccount::new_account(
        TEST_ID.to_string(),
        password.clone(),
        Some(data_dir.clone()),
    )
    .await?;
    let key: AccessKey = password.into();
    local_account.sign_in(&key).await?;

    let address = local_account.address().clone();

    // Add the accounts
    let mut local_accounts =
        LocalAccountSwitcher::new_with_options(Some(paths));
    local_accounts.add_account(local_account);
    local_accounts.switch_account(&address);
    let local_accounts = Arc::new(RwLock::new(local_accounts));

    // Start the IPC service
    let (delegate, _commands) = local_account_delegate(16);
    let service = Arc::new(RwLock::new(LocalAccountIpcService::new(
        local_accounts.clone(),
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

    let linked_account = accounts.selected_account_mut().unwrap();

    // Initial sync fetches the data from the other app
    let sync_result = linked_account.sync().await;
    assert!(sync_result.result.is_ok());

    // Make sure the account is recognized on disc
    let accounts_list =
        Identity::list_accounts(Some(&linked_account.paths())).await?;
    assert_eq!(1, accounts_list.len());

    // Should be able to sign in to the linked account
    linked_account.sign_in(&key).await?;

    // Create secret in the linked account
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange { id, .. } = linked_account
        .create_secret(meta, secret, Default::default())
        .await?;

    // Read from the linked account
    let (linked_secret_data, _) =
        linked_account.read_secret(&id, Default::default()).await?;

    // Secret is immediately available on the local account
    let local_secret_data = {
        let accounts = local_accounts.read().await;
        let local_account = accounts.selected_account().unwrap();
        let (data, _) =
            local_account.read_secret(&id, Default::default()).await?;
        assert_eq!(&id, data.id());
        assert_eq!("note", data.meta().label());
        data
    };

    // Secrets must be identical
    assert_eq!(linked_secret_data, local_secret_data);

    teardown(TEST_ID).await;

    Ok(())
}
