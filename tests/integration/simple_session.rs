use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use futures::stream::StreamExt;
use reqwest_eventsource::Event;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

use sos_core::{
    constants::DEFAULT_VAULT_NAME,
    events::{ChangeEvent, ChangeNotification},
    secret::SecretRef,
};
use sos_node::{
    Client, ClientCache, ClientCredentials, FileCache, SyncStatus,
};

#[tokio::test]
#[serial]
async fn integration_simple_session() -> Result<()> {
    let dirs = setup(1)?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    let (address, credentials, mut file_cache) = signup(&dirs, 0).await?;
    let ClientCredentials { summary, .. } = credentials;
    let login_vault_id = *summary.id();

    let (tx, mut rx) = mpsc::channel(1);

    let mut es = file_cache.client().changes().await?;
    let notifications: Arc<RwLock<Vec<ChangeNotification>>> =
        Arc::new(RwLock::new(Vec::new()));
    let changed = Arc::clone(&notifications);

    tokio::task::spawn(async move {
        while let Some(event) = es.next().await {
            match event {
                Ok(Event::Open) => tx
                    .send(())
                    .await
                    .expect("failed to send changes feed open message"),
                Ok(Event::Message(message)) => {
                    let notification: ChangeNotification =
                        serde_json::from_str(&message.data)?;

                    // Store change notifications so we can
                    // assert at the end
                    let mut writer = changed.write().unwrap();
                    //println!("{:#?}", notification);
                    writer.push(notification);
                }
                Err(e) => {
                    es.close();
                    return Err(e.into());
                }
            }
        }

        Ok::<(), sos_client::Error>(())
    });

    // Wait for the changes feed to connect before
    // we start to make changes
    let _ = rx
        .recv()
        .await
        .expect("failed to receive changes feed open message");

    let _ = FileCache::cache_dir()?;

    assert_eq!(&server_url, file_cache.server());
    assert_eq!(address, file_cache.address()?);

    // Check the /api route
    let server_info = file_cache.client().server_info().await?;
    assert!(server_info.status().is_success());

    // Trigger server code path for the / URL
    home(file_cache.client()).await?;

    // Trigger server code path for the /gui assets
    gui(file_cache.client()).await?;

    // Create a new vault
    let new_vault_name = String::from("My Vault");
    let (new_passphrase, _) =
        file_cache.create_vault(new_vault_name.clone()).await?;

    // Check our new vault is found in the local cache
    let vault_ref = SecretRef::Name(new_vault_name.clone());
    let new_vault_summary =
        file_cache.find_vault(&vault_ref).unwrap().clone();
    assert_eq!(&new_vault_name, new_vault_summary.name());

    // Need this for some assertions later
    let new_vault_id = *new_vault_summary.id();

    // Trigger code path for finding by id
    let id_ref = SecretRef::Id(*new_vault_summary.id());
    let new_vault_summary_by_id =
        file_cache.find_vault(&id_ref).unwrap().clone();
    assert_eq!(new_vault_summary_by_id, new_vault_summary);

    // Load vaults list
    let cached_vaults = file_cache.vaults().to_vec();
    let vaults = file_cache.load_vaults().await?;
    assert_eq!(2, vaults.len());
    assert_eq!(&cached_vaults, &vaults);

    // Remove the default vault
    let default_ref = SecretRef::Name(DEFAULT_VAULT_NAME.to_owned());
    let default_vault_summary =
        file_cache.find_vault(&default_ref).unwrap().clone();
    file_cache.remove_vault(&default_vault_summary).await?;
    let vaults = file_cache.load_vaults().await?;
    assert_eq!(1, vaults.len());
    assert_eq!(1, file_cache.vaults().len());

    // Use the new vault
    file_cache
        .open_vault(&new_vault_summary, &new_passphrase)
        .await?;

    // Create some secrets
    let notes = create_secrets(&mut file_cache, &new_vault_summary).await?;

    // Ensure we have a commit tree
    assert!(file_cache.wal_tree(&new_vault_summary).is_some());

    // Check the WAL history has the right length
    let history = file_cache.history(&new_vault_summary)?;
    assert_eq!(4, history.len());

    // Check the vault status
    let (status, _) = file_cache.vault_status(&new_vault_summary).await?;
    let equals = if let SyncStatus::Equal(_) = status {
        true
    } else {
        false
    };
    assert!(equals);

    // Delete a secret
    let delete_secret_id = notes.get(0).unwrap().0;
    delete_secret(&mut file_cache, &new_vault_summary, &delete_secret_id)
        .await?;

    // Check our new list of secrets has the right length
    let keeper = file_cache.current().unwrap();
    let meta = keeper.meta_data()?;
    assert_eq!(2, meta.len());
    drop(keeper);

    // Set the vault name
    file_cache
        .set_vault_name(&new_vault_summary, DEFAULT_VAULT_NAME)
        .await?;

    // Take a snapshot - need to do these assertions before pull/push
    let (_snapshot, created) =
        file_cache.take_snapshot(&new_vault_summary)?;
    assert!(created);
    let snapshots = file_cache.snapshots().list(new_vault_summary.id())?;
    assert!(!snapshots.is_empty());

    // Try to pull whilst up to date
    let _ = file_cache.pull(&new_vault_summary, false).await?;
    // Now force a pull
    let _ = file_cache.pull(&new_vault_summary, true).await?;

    // Try to push whilst up to date
    let _ = file_cache.push(&new_vault_summary, false).await?;
    // Now force a push
    let _ = file_cache.push(&new_vault_summary, true).await?;

    // Verify local WAL ingegrity
    file_cache.verify(&new_vault_summary)?;

    // Close the vault
    file_cache.close_vault();

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
        &ChangeEvent::CreateVault,
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

async fn home(client: &Client) -> Result<()> {
    let url = client.server().clone();
    let response = client.get(url).await?;
    assert!(response.status().is_success());
    Ok(())
}

async fn gui(client: &Client) -> Result<()> {
    let url = client.server().join("gui")?;
    let response = client.get(url).await?;
    assert!(response.status().is_success());
    Ok(())
}
