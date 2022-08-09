use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use futures::stream::StreamExt;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use url::Url;

use secrecy::ExposeSecret;
use sos_core::{
    constants::DEFAULT_VAULT_NAME,
    events::{ChangeEvent, ChangeNotification},
    secret::SecretRef,
};
use sos_node::{
    cache_dir,
    client::{
        account::AccountCredentials,
        net::{changes::ChangeStreamEvent, RequestClient},
    },
    sync::SyncStatus,
};

#[tokio::test]
#[serial]
async fn integration_simple_session() -> Result<()> {
    let dirs = setup(1)?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    let (address, credentials, mut node_cache, signer) =
        signup(&dirs, 0).await?;
    let AccountCredentials { summary, .. } = credentials;
    let login_vault_id = *summary.id();

    let (tx, mut rx) = mpsc::channel(1);

    let mut es = RequestClient::changes(server_url.clone(), signer).await?;
    let notifications: Arc<RwLock<Vec<ChangeNotification>>> =
        Arc::new(RwLock::new(Vec::new()));
    let changed = Arc::clone(&notifications);

    tokio::task::spawn(async move {
        while let Some(event) = es.next().await {
            let event = event?;
            match event {
                ChangeStreamEvent::Open => tx
                    .send(())
                    .await
                    .expect("failed to send changes feed open message"),
                ChangeStreamEvent::Message(notification) => {
                    // Store change notifications so we can
                    // assert at the end
                    let mut writer = changed.write().unwrap();
                    //println!("{:#?}", notification);
                    writer.push(notification);
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

    let _ = cache_dir().unwrap();

    //assert_eq!(address, node_cache.address()?);

    // Check the /api route
    let server_info = RequestClient::server_info(server_url.clone()).await?;
    assert!(server_info.status().is_success());

    // Trigger server code path for the / URL
    home(&server_url).await?;

    // Trigger server code path for the /gui assets
    gui(&server_url).await?;

    // Create a new vault
    let new_vault_name = String::from("My Vault");
    let (new_passphrase, _) = node_cache
        .create_vault(new_vault_name.clone(), None)
        .await?;

    // Check our new vault is found in the local cache
    let vault_ref = SecretRef::Name(new_vault_name.clone());
    let new_vault_summary =
        node_cache.state().find_vault(&vault_ref).unwrap().clone();
    assert_eq!(&new_vault_name, new_vault_summary.name());

    // Need this for some assertions later
    let new_vault_id = *new_vault_summary.id();

    // Trigger code path for finding by id
    let id_ref = SecretRef::Id(*new_vault_summary.id());
    let new_vault_summary_by_id =
        node_cache.state().find_vault(&id_ref).unwrap().clone();
    assert_eq!(new_vault_summary_by_id, new_vault_summary);

    // Load vaults list
    let cached_vaults = node_cache.vaults().to_vec();
    let vaults = node_cache.load_vaults().await?;
    assert_eq!(2, vaults.len());
    assert_eq!(&cached_vaults, &vaults);

    // Remove the default vault
    let default_ref = SecretRef::Name(DEFAULT_VAULT_NAME.to_owned());
    let default_vault_summary =
        node_cache.state().find_vault(&default_ref).unwrap().clone();
    node_cache.remove_vault(&default_vault_summary).await?;
    let vaults = node_cache.load_vaults().await?;
    assert_eq!(1, vaults.len());
    assert_eq!(1, node_cache.vaults().len());

    // Use the new vault
    node_cache
        .open_vault(&new_vault_summary, new_passphrase.expose_secret())
        .await?;

    // Create some secrets
    let notes = create_secrets(&mut node_cache, &new_vault_summary).await?;

    // Ensure we have a commit tree
    assert!(node_cache.wal_tree(&new_vault_summary).is_some());

    // Check the WAL history has the right length
    let history = node_cache.history(&new_vault_summary)?;
    assert_eq!(4, history.len());

    // Check the vault status
    let (status, _) = node_cache.vault_status(&new_vault_summary).await?;
    let equals = if let SyncStatus::Equal(_) = status {
        true
    } else {
        false
    };
    assert!(equals);

    // Delete a secret
    let delete_secret_id = notes.get(0).unwrap().0;
    delete_secret(&mut node_cache, &new_vault_summary, &delete_secret_id)
        .await?;

    // Check our new list of secrets has the right length
    let keeper = node_cache.current().unwrap();
    let meta = keeper.meta_data()?;
    assert_eq!(2, meta.len());
    drop(keeper);

    // Set the vault name
    node_cache
        .set_vault_name(&new_vault_summary, DEFAULT_VAULT_NAME)
        .await?;

    // Take a snapshot - need to do these assertions before pull/push
    let (_snapshot, created) =
        node_cache.take_snapshot(&new_vault_summary)?;
    assert!(created);
    let snapshots = node_cache
        .snapshots()
        .unwrap()
        .list(new_vault_summary.id())?;
    assert!(!snapshots.is_empty());

    // Try to pull whilst up to date
    let _ = node_cache.pull(&new_vault_summary, false).await?;
    // Now force a pull
    let _ = node_cache.pull(&new_vault_summary, true).await?;

    // Try to push whilst up to date
    let _ = node_cache.push(&new_vault_summary, false).await?;
    // Now force a push
    let _ = node_cache.push(&new_vault_summary, true).await?;

    // Verify local WAL ingegrity
    node_cache.verify(&new_vault_summary)?;

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

async fn home(server: &Url) -> Result<()> {
    let url = server.clone();
    let response = RequestClient::get(url).await?;
    assert!(response.status().is_success());
    Ok(())
}

async fn gui(server: &Url) -> Result<()> {
    let url = server.join("gui")?;
    let response = RequestClient::get(url).await?;
    assert!(response.status().is_success());
    Ok(())
}
