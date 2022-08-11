use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use futures::stream::StreamExt;
use std::{
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::sync::mpsc;

use secrecy::ExposeSecret;
use sos_core::{
    events::{ChangeEvent, ChangeNotification},
    generate_passphrase,
};
use sos_node::client::{
    account::AccountCredentials,
    net::{changes::ChangeStreamEvent, RequestClient},
};

#[tokio::test]
#[serial]
async fn integration_change_password() -> Result<()> {
    let dirs = setup(1)?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    let (address, credentials, mut node_cache, signer) =
        signup(&dirs, 0).await?;
    let AccountCredentials {
        summary,
        encryption_passphrase,
        ..
    } = credentials;

    let (tx, mut rx) = mpsc::channel(1);

    let mut es = RequestClient::changes(server_url, signer).await?;
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

    // Use the new vault
    node_cache
        .open_vault(&summary, encryption_passphrase.expose_secret())
        .await?;

    // Create some secrets
    let _notes = create_secrets(&mut node_cache, &summary).await?;

    // Check our new list of secrets has the right length
    let keeper = node_cache.current().unwrap();
    let meta = keeper.index().values();
    assert_eq!(3, meta.len());
    drop(keeper);

    let keeper = node_cache.current_mut().unwrap();
    let (new_passphrase, _) = generate_passphrase()?;

    let vault = keeper.vault().clone();
    drop(keeper);

    node_cache
        .change_password(&vault, encryption_passphrase, new_passphrase)
        .await?;

    // Close the vault
    node_cache.close_vault();

    /* CHANGE NOTIFICATIONS */

    // Delay a little to ensure all the change notifications
    // have been received
    tokio::time::sleep(Duration::from_millis(100)).await;

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
