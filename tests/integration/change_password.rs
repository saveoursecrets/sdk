use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use futures::stream::StreamExt;
use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use sos_net::client::{
    net::changes::{changes, connect},
    provider::StorageProvider,
};
use sos_sdk::{
    events::{ChangeEvent, ChangeNotification},
    passwd::diceware::generate_passphrase,
};
use tokio::sync::Mutex;

#[tokio::test]
#[serial]
async fn integration_change_password() -> Result<()> {
    let dirs = setup(1).await?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    let (address, credentials, mut node_cache, signer, keypair) =
        signup(&dirs, 0).await?;
    let AccountCredentials {
        summary,
        encryption_passphrase,
        ..
    } = credentials;

    let notifications: Arc<RwLock<Vec<ChangeNotification>>> =
        Arc::new(RwLock::new(Vec::new()));
    let changed = Arc::clone(&notifications);

    // Spawn a task to handle change notifications
    tokio::task::spawn(async move {
        // Create the websocket connection
        let (stream, session) =
            connect(server_url, server_public_key()?, signer, keypair)
                .await?;

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

    // Use the new vault
    node_cache
        .open_vault(&summary, encryption_passphrase.clone().into(), None)
        .await?;

    // Create some secrets
    let _notes = create_secrets(&mut node_cache, &summary).await?;

    // Check our new list of secrets has the right length
    let keeper = node_cache.current().unwrap();

    let index = keeper.index();
    let index_reader = index.read().await;
    let meta = index_reader.values();
    assert_eq!(3, meta.len());
    drop(index_reader);

    let keeper = node_cache.current_mut().unwrap();
    let (new_passphrase, _) = generate_passphrase()?;

    let vault = keeper.vault().clone();

    node_cache
        .change_password(
            &vault,
            encryption_passphrase.into(),
            new_passphrase.into(),
        )
        .await?;

    // Close the vault
    node_cache.close_vault();

    /* CHANGE NOTIFICATIONS */

    // Delay a little to ensure all the change notifications
    // have been received
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Assert on all the change notifications
    let mut changes = notifications.write().unwrap();
    assert_eq!(2, changes.len());

    // Ignore the create secrets change event as it
    // does not interest us for these assertions
    let _create_secrets = changes.remove(0);

    // Updated vault event when we changed the password
    let update_vault = changes.remove(0);
    assert_eq!(&address, update_vault.address());
    assert_eq!(summary.id(), update_vault.vault_id());
    assert_eq!(1, update_vault.changes().len());
    assert_eq!(
        &ChangeEvent::UpdateVault,
        update_vault.changes().get(0).unwrap()
    );
    Ok(())
}
