use anyhow::Result;
use async_trait::async_trait;
use sos_ipc::integration::{LinkedAccount, LocalIntegration};
use sos_ipc::local_transport::{LocalRequest, LocalResponse, LocalTransport};
use sos_net::{
    protocol::RemoteSync,
    sdk::{
        crypto::AccessKey,
        prelude::{generate_passphrase, Account, Identity, SecretChange},
        Paths,
    },
    NetworkAccount, NetworkAccountSwitcher,
};
use sos_sdk::prelude::AccountSwitcherOptions;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::test_utils::{mock, setup, spawn, teardown};

/// Local transport for the test specs.
pub struct TestLocalTransport;

#[async_trait]
impl LocalTransport for TestLocalTransport {
    async fn call(&mut self, request: LocalRequest) -> LocalResponse {
        /*
        let mut client =
            LocalSocketClient::connect(&self.socket_name).await.unwrap();
        let Ok(response) = client.send(request).await else {
            panic!("unable to send request");
        };
        response
        */
        println!("{:#?}", request);
        todo!();
    }
}

/// Test for syncing between a linked account and another
/// account.
#[tokio::test]
async fn integration_ipc_linked_account() -> Result<()> {
    const TEST_ID: &str = "ipc_linked_account";
    // crate::test_utils::init_tracing();
    //

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let origin = server.origin.clone();
    let url = server.origin.url().clone();

    println!("url: {:#?}", url);

    let mut dirs = setup(TEST_ID, 2).await?;
    let data_dir = dirs.clients.remove(0);
    let linked_data_dir = dirs.clients.remove(0);

    Paths::scaffold(Some(data_dir.clone())).await?;
    Paths::scaffold(Some(linked_data_dir.clone())).await?;
    let paths = Paths::new_global(data_dir.clone());

    let (password, _) = generate_passphrase()?;

    // Create an account and authenticate
    let mut local_account = NetworkAccount::new_account(
        TEST_ID.to_string(),
        password.clone(),
        Some(data_dir.clone()),
        Default::default(),
    )
    .await?;
    let key: AccessKey = password.into();
    local_account.sign_in(&key).await?;

    let address = local_account.address().clone();

    // Add the accounts
    let options = AccountSwitcherOptions {
        paths: Some(paths),
        ..Default::default()
    };
    let mut local_accounts =
        NetworkAccountSwitcher::new_with_options(options);
    local_accounts.add_account(local_account);
    local_accounts.switch_account(&address);
    let local_accounts = Arc::new(RwLock::new(local_accounts));

    let ipc_accounts = local_accounts.clone();

    /*
    let server_socket_name = socket_name.clone();
    tokio::task::spawn(async move {
        LocalSocketServer::listen(
            &server_socket_name,
            ipc_accounts,
            Default::default(),
        )
        .await?;
        Ok::<(), Error>(())
    });

    tokio::time::sleep(Duration::from_millis(250)).await;
    */

    // Test transport creates a IPC socket client for communication
    let transport = TestLocalTransport;

    // Integration mananges the accounts on the linked app
    let integration = LocalIntegration::new(origin, Box::new(transport));

    // Prepare the local client using our test transport
    let local_client = integration.client().clone();

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
    // println!("{:#?}", sync_result);
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
