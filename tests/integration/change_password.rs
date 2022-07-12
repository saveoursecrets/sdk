use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use futures::stream::StreamExt;
use reqwest_eventsource::Event;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

use sos_client::{
    Client, ClientCache, ClientCredentials, FileCache, SyncStatus,
};
use sos_core::{
    constants::DEFAULT_VAULT_NAME,
    events::{ChangeEvent, ChangeNotification},
    generate_passphrase,
    secret::SecretRef,
    ChangePassword,
};

#[tokio::test]
#[serial]
async fn integration_change_password() -> Result<()> {
    let dirs = setup(1)?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    let (address, credentials, mut file_cache) = signup(&dirs, 0).await?;
    let ClientCredentials {
        summary,
        encryption_passphrase,
        ..
    } = credentials;

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

    // Use the new vault
    file_cache
        .open_vault(&summary, &encryption_passphrase)
        .await?;

    // Create some secrets
    let notes = create_secrets(&mut file_cache, &summary).await?;

    // Check our new list of secrets has the right length
    let keeper = file_cache.current().unwrap();
    let meta = keeper.meta_data()?;
    assert_eq!(3, meta.len());
    drop(keeper);

    let keeper = file_cache.current_mut().unwrap();
    let (new_passphrase, _) = generate_passphrase()?;

    // Get a new vault for the new passphrase
    let (mut new_passphrase, new_vault, wal_events) = ChangePassword::new(
        keeper.vault_mut(),
        encryption_passphrase,
        new_passphrase,
    )
    .build()?;
    file_cache
        .update_vault(&summary, &new_vault, wal_events)
        .await?;

    // Close the vault
    file_cache.close_vault();

    /* CHANGE NOTIFICATIONS */

    // Assert on all the change notifications
    let mut changes = notifications.write().unwrap();

    /*
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
    */

    Ok(())
}
