use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use futures::stream::StreamExt;
use std::{
    sync::{Arc, RwLock},
    time::Duration,
};
use url::Url;

use sos_net::client::{
    net::{
        changes::{changes, connect},
        RequestClient,
    },
    provider::StorageProvider,
};
use sos_sdk::{
    commit::CommitRelationship,
    constants::DEFAULT_VAULT_NAME,
    events::{ChangeEvent, ChangeNotification},
    storage::AppPaths,
    vault::VaultRef,
};
use tokio::sync::Mutex;

#[tokio::test]
#[serial]
async fn integration_simple_session() -> Result<()> {
    let dirs = setup(1).await?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    let (address, credentials, mut node_cache, signer) =
        signup(&dirs, 0).await?;
    let AccountCredentials { summary, .. } = credentials;
    let login_vault_id = *summary.id();

    let notifications: Arc<RwLock<Vec<ChangeNotification>>> =
        Arc::new(RwLock::new(Vec::new()));
    let changed = Arc::clone(&notifications);

    // Spawn a task to handle change notifications
    let ws_url = server_url.clone();
    tokio::task::spawn(async move {
        // Create the websocket connection
        let (stream, session) = connect(ws_url, signer).await?;

        // Wrap the stream to read change notifications
        let mut stream = changes(stream, Arc::new(Mutex::new(session)));

        while let Some(notification) = stream.next().await {
            let notification = notification?.await?;

            // Store change notifications so we can
            // assert at the end
            let mut writer = changed.write().unwrap();
            //println!("{:#?}", notification);
            writer.push(notification);
        }

        Ok::<(), anyhow::Error>(())
    });

    // Give the websocket client some time to connect
    tokio::time::sleep(Duration::from_millis(250)).await;

    let _ = AppPaths::data_dir()?;

    //assert_eq!(address, node_cache.address()?);

    // Check the /api route
    let server_info = RequestClient::server_info(server_url.clone()).await?;
    assert!(server_info.status().is_success());

    // Trigger server code path for the / URL
    home(&server_url).await?;

    // Create a new vault
    let new_vault_name = String::from("My Vault");
    let (_, new_passphrase, _) = node_cache
        .create_vault(new_vault_name.clone(), None)
        .await?;

    // Check our new vault is found in the local cache
    let vault_ref = VaultRef::Name(new_vault_name.clone());
    let new_vault_summary =
        node_cache.state().find_vault(&vault_ref).unwrap().clone();
    assert_eq!(&new_vault_name, new_vault_summary.name());

    // Need this for some assertions later
    let new_vault_id = *new_vault_summary.id();

    // Trigger code path for finding by id
    let id_ref = VaultRef::Id(*new_vault_summary.id());
    let new_vault_summary_by_id =
        node_cache.state().find_vault(&id_ref).unwrap().clone();
    assert_eq!(new_vault_summary_by_id, new_vault_summary);

    // Load vaults list
    let cached_vaults = node_cache.vaults().to_vec();
    let vaults = node_cache.load_vaults().await?;
    assert_eq!(2, vaults.len());
    assert_eq!(&cached_vaults, &vaults);

    // Remove the default vault
    let default_ref = VaultRef::Name(DEFAULT_VAULT_NAME.to_owned());
    let default_vault_summary =
        node_cache.state().find_vault(&default_ref).unwrap().clone();
    node_cache.remove_vault(&default_vault_summary).await?;
    let vaults = node_cache.load_vaults().await?;
    assert_eq!(1, vaults.len());
    assert_eq!(1, node_cache.vaults().len());

    // Use the new vault
    node_cache
        .open_vault(&new_vault_summary, new_passphrase, None)
        .await?;

    // Create some secrets
    let notes = create_secrets(&mut node_cache, &new_vault_summary).await?;

    // Ensure we have a commit tree
    assert!(node_cache.commit_tree(&new_vault_summary).is_some());

    // Check the event log history has the right length
    let history = node_cache.history(&new_vault_summary).await?;
    assert_eq!(4, history.len());

    // Check the vault status
    let (status, _) = node_cache.status(&new_vault_summary).await?;
    let equals = matches!(status, CommitRelationship::Equal(_));
    assert!(equals);

    // Delete a secret
    let delete_secret_id = notes.get(0).unwrap().0;
    delete_secret(&mut node_cache, &new_vault_summary, &delete_secret_id)
        .await?;

    // Check our new list of secrets has the right length
    let keeper = node_cache.current().unwrap();
    let index = keeper.index();
    let index_reader = index.read().await;
    let meta = index_reader.values();
    assert_eq!(2, meta.len());
    drop(index_reader);

    // Set the vault name
    node_cache
        .set_vault_name(&new_vault_summary, DEFAULT_VAULT_NAME)
        .await?;

    // Try to pull whilst up to date
    let _ = node_cache.pull(&new_vault_summary, false).await?;
    // Now force a pull
    let _ = node_cache.pull(&new_vault_summary, true).await?;

    // Try to push whilst up to date
    let _ = node_cache.push(&new_vault_summary, false).await?;
    // Now force a push
    let _ = node_cache.push(&new_vault_summary, true).await?;

    // Verify local event log ingegrity
    node_cache.verify(&new_vault_summary).await?;

    // Close the vault
    node_cache.close_vault();

    /* CHANGE NOTIFICATIONS */

    // Assert on all the change notifications
    let mut changes = notifications.write().unwrap();
    assert_eq!(5, changes.len());

    // Created a new vault
    let create_vault = changes.remove(0);
    assert_eq!(&address, create_vault.address());
    assert_eq!(&new_vault_id, create_vault.vault_id());
    assert_eq!(1, create_vault.changes().len());
    assert_eq!(
        &ChangeEvent::CreateVault(new_vault_summary),
        create_vault.changes().get(0).unwrap()
    );

    // Deleted the login vault
    let delete_vault = changes.remove(0);
    assert_eq!(&address, delete_vault.address());
    assert_eq!(&login_vault_id, delete_vault.vault_id());
    assert_eq!(1, delete_vault.changes().len());
    assert_eq!(
        &ChangeEvent::DeleteVault,
        delete_vault.changes().get(0).unwrap()
    );

    // Created 3 secrets
    let create_secrets = changes.remove(0);
    assert_eq!(&address, create_secrets.address());
    assert_eq!(&new_vault_id, create_secrets.vault_id());
    assert_eq!(3, create_secrets.changes().len());

    // Deleted a secret
    let delete_secret = changes.remove(0);
    assert_eq!(&address, delete_secret.address());
    assert_eq!(&new_vault_id, delete_secret.vault_id());
    assert_eq!(1, delete_secret.changes().len());
    assert_eq!(
        &ChangeEvent::DeleteSecret(delete_secret_id),
        delete_secret.changes().get(0).unwrap()
    );

    // Set vault name
    let set_vault_name = changes.remove(0);
    assert_eq!(&address, set_vault_name.address());
    assert_eq!(&new_vault_id, set_vault_name.vault_id());
    assert_eq!(1, set_vault_name.changes().len());
    assert_eq!(
        &ChangeEvent::SetVaultName(String::from(DEFAULT_VAULT_NAME)),
        set_vault_name.changes().get(0).unwrap()
    );

    Ok(())
}

async fn home(server: &Url) -> Result<()> {
    let url = server.clone();
    let response = RequestClient::get(url).await?;
    assert!(response.status().is_success());
    Ok(())
}
